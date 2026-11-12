# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # The node's per-Pod records: lookup and identity, the bounded event
      # trail, state transitions, and forgetting a Pod once it is gone.
      module Records
        def record(pod_or_uid)
          uid = pod_uid(pod_or_uid)
          @mutex.synchronize { @records[uid] }
        end

        # What the Summary API needs of each running Pod, without the deep copy
        # #records makes of every record (a pass every 10 s for the eviction
        # manager).  The Pod objects are the stored, immutable ones.
        def stats_records
          @mutex.synchronize do
            @records.values.filter_map do |record|
              next unless record[:state].to_s == "Running" && record[:sandbox_id]

              {uid: record[:uid], state: record[:state], sandbox_id: record[:sandbox_id], pod: record[:pod],
               started_at: record[:started_at], volume: record[:volume],
               containers: Array(record[:containers]).map { |entry| {id: entry[:id], name: entry[:name], started_at: entry[:started_at]} }}
            end
          end
        end

        # The runtime containers of a Pod as the CPU manager's reconcile reads
        # them (podStatusProvider): {name:, id:, state: "running"|"exited"|"waiting"}.
        def container_states(pod_uid)
          @mutex.synchronize do
            record = @records[pod_uid.to_s]
            next [] unless record

            Array(record[:containers]).map do |entry|
              status = entry[:status].is_a?(Hash) ? entry[:status] : {}
              state = case status["state"].to_s
                      when "running" then "running"
                      when "terminated", "exited" then "exited"
                      else "waiting"
                      end
              {name: entry[:name].to_s, id: entry[:id].to_s, state: state}
            end
          end
        end

        # The Pods whose records still exist on the node (image GC's in-use set).
        def pods_on_node
          @mutex.synchronize { @records.values.filter_map { |record| record[:pod] unless record[:state].to_s == "Removed" } }
        end

        def records
          @mutex.synchronize do
            @records.transform_values { |value| immutable_record(value) }.freeze
          end
        end

        def state(pod_or_uid)
          record(pod_or_uid)&.fetch(:state, nil)
        end

        # Every record with a running workload, for the agent's relist thread.
        def running_pod_uids
          @mutex.synchronize { @records.select { |_uid, record| record[:state] == "Running" }.keys }
        end

        # Pod IPs the network attached, in family order, for status and env.
        def pod_ips(record)
          network = record[:network]
          return [] unless network.is_a?(Hash)

          ips = Helpers.key(network, "ips", nil)
          ips = [Helpers.key(network, "ip", nil)].compact if ips.nil?
          Array(ips).flatten.map(&:to_s).reject(&:empty?)
        end

        private

        def monotonic_clock
          -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
        end

        def normalize_pod(pod)
          value = if hash_convertible?(pod) && !pod.is_a?(Hash)
                    pod.to_h
                  else
                    pod
                  end
          value ||= {}
          raise ArgumentError, "Pod must be a hash" unless value.is_a?(Hash)
          raise ArgumentError, "Pod metadata.name is required" if Helpers.key(Helpers.key(value, "metadata", {}), "name", "").to_s.empty?
          return value if Helpers.immutable?(value)

          Helpers.immutable(value)
        end

        def pod_uid(pod)
          return pod.to_s unless pod.is_a?(Hash)

          metadata = Helpers.key(pod, "metadata", {})
          uid = Helpers.key(metadata, "uid", nil)
          return uid.to_s unless uid.nil? || uid.to_s.empty?

          namespace = Helpers.key(metadata, "namespace", "default")
          name = Helpers.key(metadata, "name", "")
          "#{namespace}/#{name}"
        end

        def pod_name(pod)
          metadata = Helpers.key(pod, "metadata", {})
          Helpers.key(metadata, "name", pod_uid(pod)).to_s
        end

        def new_record(pod, request_id: nil)
          uid = pod_uid(pod)
          record = {
            uid: uid,
            pod: pod,
            request_id: request_id || uid,
            state: "New",
            phase: "Pending",
            status: {},
            volume: nil,
            sandbox_id: nil,
            sandbox_context: nil,
            network: nil,
            images: [],
            image_by_container: {},
            # spec.volumes[].image references -> the pinned image (digest,
            # unpacked rootfs), and the resolver handles to release with them.
            volume_images: {},
            volume_image_handles: [],
            containers: [],
            events: [],
            resources: [],
            cleanup_errors: [],
            cleanup_completed: {},
            error: nil,
            started_at: nil,
            reason: nil,
            termination_message: nil
          }
          @mutex.synchronize { @records[uid] = record }
          persist_state!
          record
        end

        def immutable_record(record)
          Helpers.deep_freeze(Helpers.deep_copy(record))
        end

        def record_for(uid)
          @mutex.synchronize { @records[uid] }
        end

        def resolve_record(pod_or_uid)
          if pod_or_uid.is_a?(Hash)
            object = normalize_pod(pod_or_uid)
            uid = pod_uid(object)
            [object, uid, record_for(uid)]
          else
            uid = pod_or_uid.to_s
            existing = record_for(uid)
            [existing && existing[:pod], uid, existing]
          end
        end

        def result_for(record)
          Result.new(
            pod_uid: record[:uid], state: record[:state], phase: record[:phase],
            status: Helpers.immutable(record[:status] || {}),
            events: Helpers.immutable(record[:events] || []),
            resources: Helpers.immutable(record[:resources] || []),
            error: record[:error], cleanup_errors: Helpers.immutable(record[:cleanup_errors] || [])
          ).freeze
        end

        def set_state(record, state)
          state = state.to_s
          raise LifecycleError, "unknown lifecycle state #{state.inspect}" unless RUNTIME_STATES.include?(state) || %w[Failed Unknown].include?(state)

          previous = record[:state]
          record[:state] = state
          event(record, "state", from: previous, to: state)
        end

        # How much of a Pod's own history the node keeps.
        #
        # The trail is diagnostic, not durable state, and it is APPENDED TO ON
        # EVERY SYNC: a Pod that is retried -- a crash-looping container, a
        # cleanup that has not finished -- adds entries for as long as it lives.
        # Unbounded, one Pod's record reached tens of kilobytes and the node's
        # resident memory grew into the gigabytes over a single conformance run,
        # which slows every Pod on the node down with it.  The most recent
        # entries are the ones worth having.
        MAX_RECORD_EVENTS = 200

        def event(record, type, payload = {})
          mark_dirty(record)
          entry = {"type" => type.to_s, "state" => record[:state], "at" => Helpers.now(@clock).iso8601(6)}
          entry.merge!(Helpers.string_keys(payload))
          # An entry never changes once recorded.  Frozen, json_safe converts
          # it once and reuses the conversion on every later persist of the
          # record (a record's ~200 entries were re-walked on each transition).
          Helpers.deep_freeze(entry)
          events = record[:events]
          events << entry
          events.shift(events.length - MAX_RECORD_EVENTS) if events.length > MAX_RECORD_EVENTS
          @event_sink.call(record[:uid], entry) if @event_sink
          @metrics_observer&.observe(record, entry)
        end

        # The trail is the only place a Pod start can be broken down after the
        # fact, and "how long did this step take" is the question it is read to
        # answer.  Without it, locating the 21 s in a 27 s start meant diffing
        # the timestamps of whatever unrelated events happened to bracket it.
        def timed(record, type, payload = {})
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = yield
          event(record, type, payload.merge(seconds: (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(3)))
          result
        end

        def forget_pod(uid)
          identifier = uid.to_s
          return if identifier.empty?

          @mutex.synchronize do
            @finished.delete(identifier)
            @start_retries&.delete(identifier)
            @cleanup_retries&.delete(identifier)
          end
          @records.delete(identifier)
          remove_pod_directory(identifier)
          nil
        end

        # The Pod's own directory (etc/hosts, resolv.conf, container files)
        # goes with the record, as kubelet removes /var/lib/kubelet/pods/<uid>
        # once the Pod is gone; left behind, a worker had 316 of them after
        # one round.  The sandbox and every mount under it are gone by now.
        def remove_pod_directory(identifier)
          return unless @pod_root

          directory = File.join(@pod_root, identifier)
          FileUtils.rm_rf(directory) if File.directory?(directory)
        rescue SystemCallError
          # A directory still busy (a mount that outlived the sandbox) stays;
          # the next agent start's stale-state sweep sees it.
          nil
        end

        def deletion_requested?(pod)
          metadata = Helpers.key(pod, "metadata", {})
          !Helpers.key(metadata, "deletionTimestamp", nil).nil?
        end

        def pod_directory(record)
          return nil unless @pod_root

          File.join(@pod_root, record[:uid].to_s)
        end

        def grace_seconds(pod)
          spec = Helpers.key(pod, "spec", {})
          value = Helpers.key(spec, "terminationGracePeriodSeconds", 30)
          Integer(value || 30).clamp(0, 3600)
        rescue ArgumentError, TypeError
          30
        end

        def container_policy(pod, definition)
          Helpers.key(definition, "restartPolicy", Helpers.key(Helpers.key(pod, "spec", {}), "restartPolicy", "Always")).to_s.then do |value|
            value.empty? ? "Always" : value
          end
        end

        def restart_identity(record, entry)
          "#{record.fetch(:uid)}/#{entry.fetch(:name)}"
        end

        # kubelet's convertToAPIContainerStatuses always stamps state.running
        # .startedAt, and carries it onto state.terminated.startedAt when the
        # container exits.  Ours reported `startedAt: null`, which every client
        # that measures container runtime reads as "never started".  The Pod's
        # own startTime is the first container start, which is also what
        # activeDeadlineSeconds counts from.
        def mark_container_started(entry, record)
          started_at = Helpers.now(@clock).iso8601(6)
          entry[:started_at] = started_at
          record[:started_at] ||= started_at
          started_at
        end
      end
    end
  end
end
