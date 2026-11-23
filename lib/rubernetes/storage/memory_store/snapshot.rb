# frozen_string_literal: true

module Rubernetes
  module Storage
    # Whole-state export and import for replication snapshots.
    class MemoryStore
      # Complete durable state for replication snapshots: revision counters,
      # per-key version history, mutation history and request memory.  Watchers
      # are connection state and are not exported.
      # A write_pause identifies the migration and blocks later commits before
      # releasing the snapshot lock.
      def export_state(write_pause: nil)
        @monitor.synchronize do
          raise Unavailable, "datastore writes are already paused for migration" if write_pause && @write_pause

          state = {
            "schema_version" => 1,
            "revision" => @revision,
            "compacted_revision" => @compacted_revision,
            "resource_revisions" => @resource_revisions.sort.to_h,
            "known_keys" => sorted_keys_locked.dup,
            "versions" => sorted_keys_locked.to_h do |key|
                            [key, versions_for(key).map { |(revision, object)| [revision, object] }]
                          end,
            "history" => @history.map do |mutation|
              {"type" => mutation.type.to_s, "key" => mutation.key, "revision" => mutation.revision,
               "object" => mutation.object, "old_object" => mutation.old_object, "timestamp" => mutation.timestamp}
            end,
            "requests" => @requests.keys.sort.each_with_object({}) do |uid, output|
              stored = @requests[uid]
              output[uid] = {"fingerprint" => stored.fingerprint, "operation" => stored.operation.to_s,
                             "key" => stored.key, "revision" => stored.revision, "result" => stored.result}
            end
          }
          @write_pause = write_pause if write_pause
          state
        end
      end

      def resume_writes!(write_pause:)
        @monitor.synchronize do
          @write_pause = nil if @write_pause == write_pause
        end
      end

      # Replace the complete state with an exported document.  Only valid on a
      # store that has not been mutated; a replica restores into a fresh
      # instance so the import never mixes generations.
      def import_state(document)
        raise ArgumentError, "state document must be a Hash" unless document.is_a?(Hash)
        raise ArgumentError, "state schema_version must be 1" unless document["schema_version"] == 1

        @monitor.synchronize do
          raise ArgumentError, "import_state requires an unused store" unless @revision.zero? && @live_versions.empty?

          @revision = Integer(document.fetch("revision"))
          @compacted_revision = Integer(document.fetch("compacted_revision"))
          raise ArgumentError, "snapshot known_keys must be an array" unless document.fetch("known_keys").is_a?(Array)

          @sorted_keys = nil
          @live_versions = {}
          @deleted_versions = {}
          # A key space's most recent write can be a compacted deletion.
          # Older snapshots have only the lower bounds from retained versions.
          @resource_revisions = document.fetch("resource_revisions", {}).transform_values do |value|
            revision = Integer(value)
            raise ArgumentError, "key space revision outside snapshot range" unless revision.between?(0, @revision)

            revision
          end
          document.fetch("versions").each do |key, entries|
            list = entries.map do |(revision, object)|
              [Integer(revision), MemoryStoreSupport.immutable_copy(object)]
            end
            # Older writers included empty histories for failed GETs and
            # names whose last deletion was already compacted.
            next if list.empty?

            latest, current = list.last
            bucket = resource_bucket(String(key))
            @resource_revisions[bucket] = [@resource_revisions.fetch(bucket, 0), latest].max if bucket
            next if current.nil? && latest <= @compacted_revision

            index = current ? @live_versions : @deleted_versions
            index[String(key)] = list
          end
          @history = Array(document.fetch("history")).map do |entry|
            Mutation.new(type: entry.fetch("type").to_sym, key: entry.fetch("key"), revision: Integer(entry.fetch("revision")),
                         object: MemoryStoreSupport.immutable_copy(entry["object"]),
                         old_object: MemoryStoreSupport.immutable_copy(entry["old_object"]),
                         timestamp: entry["timestamp"].nil? ? nil : Float(entry["timestamp"]))
          end
          @requests = {}
          requests = document.fetch("requests")
          # Snapshots serialize requests by UID. Rebuild the revision order
          # used for incremental compaction in the longer-window policy.
          requests = requests.sort_by { |_uid, stored| Integer(stored["revision"] || 0) } if @retain_longer_window
          requests.each do |uid, stored|
            @requests[String(uid)] = RequestResult.new(fingerprint: stored.fetch("fingerprint").freeze, operation: stored.fetch("operation").to_sym,
                                                       key: stored.fetch("key").freeze, revision: stored["revision"].nil? ? nil : Integer(stored["revision"]),
                                                       result: MemoryStoreSupport.immutable_copy(stored.fetch("result")))
          end
        end
        self
      end
    end
  end
end
