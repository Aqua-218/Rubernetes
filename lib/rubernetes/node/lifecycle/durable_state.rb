# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # The node-side state that survives an agent restart: restoring it,
      # and persisting it with group commit and per-record JSON caching.
      module DurableState
        private

        def restore_state!
          return unless @state_store

          payload = Helpers.string_keys(@state_store.load || {})
          raise LifecycleError, "lifecycle state snapshot must be a JSON object" unless payload.is_a?(Hash)

          schema = Helpers.key(payload, "schema", nil)
          raise LifecycleError, "unsupported lifecycle state schema #{schema.inspect}" if schema && schema.to_s != "rubernetes.node.lifecycle.v1"

          Array(Helpers.key(payload, "records", [])).each do |value|
            record = restore_record(value)
            @records[record.fetch(:uid)] = record
          end
          Helpers.key(payload, "finished", {}).to_h.each { |uid, phase| @finished[uid.to_s] = phase.to_s }
          @probes.restore(Helpers.key(payload, "probes", {}))
          @restarts.restore(Helpers.key(payload, "restarts", []))
        rescue StandardError => error
          raise LifecycleError, "lifecycle state restore failed: #{Helpers.failure_message(error)}"
        end

        def restore_record(value)
          hash = Helpers.string_keys(value || {})
          uid = String(Helpers.key(hash, "uid", ""))
          raise LifecycleError, "persisted lifecycle record has no uid" if uid.empty?

          state = String(Helpers.key(hash, "state", "StateUnknown"))
          allowed = RUNTIME_STATES + %w[Failed Unknown]
          raise LifecycleError, "persisted lifecycle record has invalid state #{state.inspect}" unless allowed.include?(state)

          containers = Array(Helpers.key(hash, "containers", [])).map do |entry|
            item = Helpers.string_keys(entry || {})
            {
              id: String(Helpers.key(item, "id", "")),
              name: String(Helpers.key(item, "name", "")),
              spec: Helpers.immutable(Helpers.key(item, "spec", {})),
              category: String(Helpers.key(item, "category", "app")),
              started: !!Helpers.key(item, "started", false),
              status: Helpers.string_keys(Helpers.key(item, "status", {}))
            }
          end
          {
            uid: uid,
            pod: Helpers.immutable(Helpers.key(hash, "pod", {})),
            request_id: Helpers.key(hash, "request_id", uid),
            state: state,
            phase: String(Helpers.key(hash, "phase", "Unknown")),
            status: Helpers.string_keys(Helpers.key(hash, "status", {})),
            volume: Helpers.key(hash, "volume", nil),
            sandbox_id: Helpers.key(hash, "sandbox_id", nil),
            sandbox_context: Helpers.key(hash, "sandbox_context", nil),
            network: Helpers.key(hash, "network", nil),
            images: Array(Helpers.key(hash, "images", [])),
            image_by_container: Helpers.string_keys(Helpers.key(hash, "image_by_container", {})),
            containers: containers,
            events: Array(Helpers.key(hash, "events", [])),
            resources: Array(Helpers.key(hash, "resources", [])),
            cleanup_errors: Array(Helpers.key(hash, "cleanup_errors", [])),
            cleanup_completed: Helpers.string_keys(Helpers.key(hash, "cleanup_completed", {})),
            error: Helpers.key(hash, "error", nil),
            started_at: Helpers.key(hash, "started_at", nil),
            reason: Helpers.key(hash, "reason", nil),
            # The attachable volumes reported in use for this Pod (volumesInUse
            # survives a restart, as the desired state does).
            attachable_volumes: Helpers.key(hash, "attachable_volumes", nil)
          }
        end

        # A Pod that finished cleanup ("Removed") carries no recovery obligation:
        # its resources were released and @finished holds the terminal phase.
        # Persisting every one of them rewrote the whole state file on EVERY
        # state transition -- 250 dead records / 10.3 MB on a conformance node,
        # and a Pod start makes ~8 transitions, so ~80 MB of JSON churn per Pod.
        # A bounded window of recent removals is kept so a restart can still
        # reason about what just went away.
        PERSISTED_REMOVED_RECORDS = 16

        def persistable_records
          live = []
          removed = []
          @records.each_value do |record|
            (record[:state].to_s == "Removed" ? removed : live) << record
          end
          (live + removed.last(PERSISTED_REMOVED_RECORDS)).map { |record| serializable_record(record) }
        end

        # The persisted records as JSON text, each re-encoded only when it
        # changed (Hash#hash of the live record, computed in C).  Converting
        # every live record on every transition was half of a busy node agent's
        # CPU: with 30 Pods starting, each of their ~15 transitions re-walked
        # all 30 records, and Pod start latency grew from 1 s to 15 s as the
        # agent's single interpreter lock saturated.
        def persistable_record_json
          live = []
          removed = []
          @records.each_value do |record|
            (record[:state].to_s == "Removed" ? removed : live) << record
          end
          cache = (@record_json_cache ||= {})
          dirty = (@dirty_records ||= {}.compare_by_identity)
          now = monotonic_clock.call
          # Every lifecycle change goes through #event or #update_status, which
          # mark the record; only marked records are encoded again.  A sweep
          # that fingerprints every record catches anything changed without a
          # mark within FULL_CHECK_SECONDS.
          full_check = @last_full_record_check.nil? || now - @last_full_record_check >= FULL_CHECK_SECONDS
          @last_full_record_check = now if full_check
          kept = {}
          encoded = (live + removed.last(PERSISTED_REMOVED_RECORDS)).map do |record|
            key = record[:uid] || record.object_id
            cached = cache[key]
            if cached && !dirty.key?(record) && !full_check
              kept[key] = cached
              next cached.last
            end
            fingerprint = record_fingerprint(record)
            json = if cached && cached.first == fingerprint
                     cached.last
                   else
                     JSON.generate(serializable_record(record))
                   end
            kept[key] = [fingerprint, json]
            json
          end
          dirty.clear
          @record_json_cache = kept
          encoded
        end

        FULL_CHECK_SECONDS = 2.0

        def mark_dirty(record)
          (@dirty_records ||= {}.compare_by_identity)[record] = true if record.is_a?(Hash)
        end

        # What decides whether a record must be encoded again.  A deeply frozen
        # part (the Pod object from the informer, container specs) cannot
        # change, so its identity stands in for its content; everything else is
        # hashed.  Hashing the whole record, frozen Pod included, was an eighth
        # of a busy agent's CPU.  (object_id is never reused in Ruby 3.4.)
        def record_fingerprint(record)
          record.map { |key, value| [key, part_fingerprint(value, 0)] }.hash
        end

        def part_fingerprint(value, depth)
          case value
          when Hash, Array
            return value.object_id if frozen_part?(value)
            return value.hash if depth >= 2

            if value.is_a?(Hash)
              value.map { |key, child| [key, part_fingerprint(child, depth + 1)] }
            else
              value.map { |child| part_fingerprint(child, depth + 1) }
            end
          else
            value.hash
          end
        end

        def frozen_part?(value)
          return false unless value.frozen?

          Helpers.deep_frozen?(value) || (defined?(Watch::Support::DEEP_FROZEN) && Watch::Support::DEEP_FROZEN.key?(value))
        end

        # Group commit: every call is numbered, and a writer persists the state
        # as it is once it holds the lock, which covers every call numbered
        # before that point.  A call whose number such a write already covers
        # returns without writing -- its change is on disk.  Each write
        # serializes every live record (~1 MB with fifteen 50-volume Pods), and
        # concurrent Pod workers used to write it once per transition each.
        def persist_state!
          return true unless @state_store

          ticket = @persist_counter_mutex.synchronize { @persist_requested += 1 }
          @persist_mutex.synchronize do
            return true if @persist_completed >= ticket

            covered = @persist_counter_mutex.synchronize { @persist_requested }
            # A store that takes the whole document as text is handed the
            # cached per-record JSON; any other is handed the snapshot.
            if state_store_supports?(:save_body)
              @state_store.save_body(state_document_json)
            else
              @state_store.save(state_snapshot)
            end
            @persist_completed = covered
          end
          true
        rescue StandardError => error
          raise LifecycleError, "lifecycle state persist failed: #{Helpers.failure_message(error)}"
        end

        def state_document_json
          records = @mutex.synchronize { persistable_record_json }
          finished = @mutex.synchronize { finished_phases }
          body = +%({"schema":"rubernetes.node.lifecycle.v1","records":[)
          body << records.join(",") << "],"
          body << %("probes":) << JSON.generate(@probes.snapshot) << ","
          body << %("restarts":) << JSON.generate(@restarts.snapshot) << ","
          body << %("finished":) << JSON.generate(finished) << "}\n"
        end

        def state_snapshot
          {
            "schema" => "rubernetes.node.lifecycle.v1",
            "records" => @mutex.synchronize { persistable_records },
            "probes" => @probes.snapshot,
            "restarts" => @restarts.snapshot,
            "finished" => @mutex.synchronize { finished_phases }
          }
        end

        # The tombstones as persisted: the phase alone, not the record kept
        # with it in memory.
        def finished_phases
          @finished.transform_values { |value| value.is_a?(Hash) ? value["phase"] : value }
        end

        def serializable_record(record)
          json_safe(record)
        end

        def json_safe(value)
          return json_safe_uncached(value) unless Helpers.deep_frozen?(value)

          cache = (@conversion_cache ||= ConversionCache.new)
          cache.fetch(value) || cache.store(value, Helpers.deep_freeze(json_safe_uncached(value)))
        end

        def json_safe_uncached(value)
          case value
          when Hash
            value.each_with_object({}) { |(key, child), result| result[key.to_s] = json_safe(child) }
          when Array
            value.map { |child| json_safe(child) }
          when Time
            value.utc.iso8601(6)
          else
            if value.nil? || value == true || value == false || value.is_a?(Numeric) || value.is_a?(String)
              value
            elsif hash_convertible?(value)
              json_safe(value.to_h)
            else
              value.to_s
            end
          end
        end
      end
    end
  end
end
