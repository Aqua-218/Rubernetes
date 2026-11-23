# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # One sync of a desired Pod against its record: decide between terminate,
      # start, in-place resize, restart, or the upkeep of a Pod that is already
      # running as configured.
      module Reconciliation
        # Reconcile one desired Pod with the local record.  A deletion timestamp
        # is treated as a normal termination, never as an abrupt resource drop.
        def reconcile(pod, action: nil, request_id: nil)
          object = normalize_pod(pod)
          uid = pod_uid(object)
          if action.to_s.upcase == "DELETED" || deletion_requested?(object)
            return terminate(object, request_id: request_id, gone: action.to_s.upcase == "DELETED")
          end

          existing = record(uid)
          acknowledge_generation(object, existing) if existing
          if (eviction = take_eviction_request(uid, existing))
            return evict(object, **eviction)
          end

          # kubelet never re-creates a Pod that has already reached a terminal
          # phase: its containers ran, stopped, and the restart policy does not
          # ask for another attempt.  Starting one again allocates a fresh
          # sandbox and a fresh image staging directory on every sync, so a
          # completed Pod quietly fills the node's disk while the API still
          # reports it as Succeeded.
          return republish_finished(object, existing, uid) if pod_finished?(object, existing, uid)
          return start_unless_backing_off(object, existing, uid, request_id) unless existing && existing.fetch(:state) == "Running"

          # spec.activeDeadlineSeconds is the kubelet's to enforce: a Pod that has
          # been active on the node longer than the deadline is killed and marked
          # Failed/DeadlineExceeded.  The field was validated by the API server
          # and then read by nobody, so the deadline never elapsed.  Conformance:
          # "[sig-node] Pods should allow activeDeadlineSeconds to be updated"
          # (test/e2e/common/node/pods.go).
          if active_deadline_exceeded?(existing, object)
            return terminate(object, request_id: request_id, reason: DEADLINE_EXCEEDED_REASON,
                                     terminal_phase: "Failed",
                                     message: DEADLINE_EXCEEDED_MESSAGE)
          end

          sync_running(object, existing, request_id)
        end

        alias sync reconcile

        # kubelet's status manager records the generation it is acting on at
        # the start of the sync, whatever the sync then does (restart, retry a
        # failed start, nothing).  Without this a spec update that lands while
        # a restart is in flight is acknowledged only when the next sync
        # happens to publish, past the 20 s the e2e allows.
        def acknowledge_generation(object, record)
          # The acknowledgement is published ahead of the sync as a courtesy to
          # clients; when it cannot be, the sync still runs and publishes.
          best_effort do
            current = Helpers.key(Helpers.key(object, "metadata", {}), "generation", nil)
            seen = Helpers.key(Helpers.key(record[:pod] || {}, "metadata", {}), "generation", nil)
            next if current.nil? || current.to_i <= seen.to_i
            # An in-place resize publishes the new generation together with its
            # PodResizeInProgress condition (kubelet allocates the resize in the
            # same sync).  Acknowledging it first told the resize e2e "done" --
            # observedGeneration caught up, no resize condition, Pod ready -- a
            # moment before the condition appeared (round 101, "extended resize
            # with equivalents").
            next if resizing_in_place?(record, object)

            update_status(object, record)
          end
        end

        private

        # The eviction queued for this Pod (see Termination#request_eviction),
        # when the Pod still has something to kill.  The request is consumed
        # either way.
        def take_eviction_request(uid, existing)
          eviction = @mutex.synchronize { @eviction_requests.delete(uid.to_s) }
          return nil unless eviction && existing
          return nil if %w[Stopped Removed].include?(existing[:state].to_s) || existing[:forced_terminal]

          eviction
        end

        def republish_finished(object, existing, uid)
          # The terminal record is the truth even when a stray earlier sync
          # republished the Pod as Running: re-publish it so the API stops
          # disagreeing with a Pod that has already finished.
          terminal = terminal_record(uid, existing)
          if terminal && Helpers.key(Helpers.key(object, "status", {}), "phase", "").to_s != terminal[:phase].to_s
            update_status(object, terminal)
            persist_state!
          end
          terminal ? result_for(terminal) : nil
        end

        # A Pod that is not running is started, unless it is a failed start
        # still waiting out its backoff.
        def start_unless_backing_off(object, existing, uid, request_id)
          # A retried start waits out its backoff (kubelet: the sandbox/
          # container creation backoff) instead of allocating a fresh sandbox
          # on every sync.
          # kubelet keys its restart backoff on the container's hash, so a Pod
          # whose containers were edited starts again immediately instead of
          # waiting out the failed version's backoff.  Without that a Pod
          # whose broken field was just corrected sits in a backoff that grows
          # to minutes -- long past what a client waiting for it will allow.
          if existing && existing[:phase].to_s == "Pending" && existing[:error]
            # Labels and annotations stay out of config_digest so a metadata
            # change never restarts a HEALTHY Pod -- but a Pod stuck in
            # CreateContainerConfigError is exactly the case where the metadata
            # IS the fix: a downward-API env var reading
            # metadata.annotations['x'] cannot expand until the annotation
            # exists.  kubelet retries container creation on the sync that
            # follows the update; waiting out a backoff grown to 30s instead
            # is longer than the client watching the Pod will allow.
            if config_digest(existing.fetch(:pod)) == config_digest(object) &&
               metadata_digest(existing.fetch(:pod)) == metadata_digest(object)
              if start_retry_pending?(uid)
                if mark_image_pull_backoff(existing)
                  update_status(object, existing)
                  persist_state!
                end
                return result_for(existing)
              end
            else
              clear_start_retry(uid)
            end
          end

          start(object, request_id: request_id)
        end

        # The sync of a Pod whose record is Running.
        def sync_running(object, existing, request_id)
          return result_for(existing) if existing[:sidecars_stopping]

          if runtime_sandbox_stopped?(existing)
            lose_sandbox!(object, existing)
            return result_for(existing)
          end

          config_changed = config_digest(existing.fetch(:pod)) != config_digest(object)

          # An ephemeral container is ADDED to a running Pod; upstream starts it
          # in place and never restarts the Pod for it (that is the whole point
          # of the ephemeralcontainers subresource).  Precisely because it must
          # not restart anything, spec.ephemeralContainers is one of
          # RESTART_NEUTRAL_SPEC_FIELDS and is stripped from the config digest --
          # so the digest can never be what tells us one arrived.  Asking it
          # anyway made this branch unreachable and the container stayed in
          # ContainerCreating for ever.  Compare the spec against the containers
          # actually started instead.  Conformance: "[sig-node] Ephemeral
          # Containers will start an ephemeral container in an existing pod" and
          # "... should update the ephemeral containers in an existing pod"
          # (test/e2e/common/node/ephemeral_containers.go).
          if existing[:state] == "Running" && pending_ephemeral_containers?(object, existing)
            start_ephemeral_containers(object, existing)
            unless config_changed
              existing[:pod] = object
              persist_state!
              return result_for(existing)
            end
          end

          # A resize that was waiting (PodResizePending) and has been reverted
          # to what the Pod already runs with: nothing to actuate, the
          # condition goes.
          if !config_changed && existing[:resize_pending] && !PodResize.resources_changed?(existing[:pod], object)
            existing[:resize_pending] = nil
            update_status(object, existing)
          end

          config_changed ? apply_changed_config(object, existing, request_id) : refresh_running(object, existing)
        end

        # In-place resize and image updates preserve the Pod's state and other
        # containers; replacing the sandbox handles the remaining changes.
        def apply_changed_config(object, existing, request_id)
          if existing[:state] == "Running" && resize_only_change?(existing.fetch(:pod), object)
            resize_pod(existing, object)
            persist_state!
            return result_for(existing)
          end
          if existing[:state] == "Running" && (updates = image_only_updates(existing, object))
            return apply_running_image_updates(object, existing, updates)
          end

          # kubelet's status manager acknowledges the new spec generation on
          # the sync that observes it, before the containers are replaced;
          # reporting it only once the restarted Pod is up made
          # observedGeneration lag an image pull ("... pod generation should
          # start at 1 and increment per update" allows 20 s).
          existing[:pod] = object
          update_status(object, existing)
          terminate(existing.fetch(:pod), request_id: request_id)
          start(object, request_id: request_id)
        end

        # Same configuration, newer object: the status the node publishes
        # is derived from the Pod it holds (metadata.generation ->
        # status.observedGeneration, labels for the downward API), so it
        # follows the latest copy.  Holding the copy from the first start
        # left observedGeneration at 1 for ever.
        def refresh_running(object, existing)
          previous_generation = Helpers.key(Helpers.key(existing[:pod] || {}, "metadata", {}), "generation", nil)
          previous_projected = projected_metadata(existing[:pod])
          gates_changed = readiness_gates_changed?(object, existing[:pod])
          existing[:pod] = object
          mark_dirty(existing)
          observe_exits(existing, object)
          return result_for(existing) if existing[:sidecar_shutdown_pending] || pod_finished?(object, existing, existing[:uid])

          refresh_recovered_init_statuses(existing) if existing[:state] == "Running"

          # A new generation is answered with a status carrying its
          # observedGeneration right away (kubelet syncs on the update event;
          # e2e waits 20 s for it), not on the next periodic status pass.
          current_generation = Helpers.key(Helpers.key(object, "metadata", {}), "generation", nil)
          runtime_ips_changed = existing[:state] == "Running" && refresh_runtime_pod_ips(existing)
          update_status(object, existing) if current_generation != previous_generation || gates_changed || runtime_ips_changed
          resume_backoff_restarts(existing, object) if existing[:state] == "Running"
          probe_running_containers(existing, object) if existing[:state] == "Running"
          # Labels and annotations are what downward API volumes project;
          # kubelet re-syncs the Pod on the update event, so a change reaches
          # the files at once instead of on the next periodic volume sync.
          metadata_changed = runtime_ips_changed || projected_metadata(object) != previous_projected
          sync_volumes(existing, object) if existing[:state] == "Running" && (metadata_changed || volume_sync_due?(existing))
          persist_state!
          result_for(existing)
        end

        # A controller's readiness-gate update changes status without
        # changing the Pod generation or any container probe result.
        def readiness_gates_changed?(pod, previous)
          types = Array(pod.dig("spec", "readinessGates")).map { |gate| gate["conditionType"] }
          return false if types.empty?

          readiness_gate_values(pod, types) != readiness_gate_values(previous, types)
        end

        def readiness_gate_values(pod, types)
          Array(pod&.dig("status", "conditions")).filter_map do |condition|
            type = condition["type"]
            [type, condition["status"]] if types.include?(type)
          end.to_h
        end

        # A Pod is finished when a terminal phase was reached and its restart
        # policy does not call for another attempt.  Either the live record or
        # the Pod's own published status is proof: after a completed termination
        # the local record is gone, and only the reported phase remains.
        def pod_finished?(pod, record, uid = nil)
          # Checked before the restart policy: a Pod the kubelet itself failed
          # (activeDeadlineSeconds, eviction) is terminal even with
          # restartPolicy Always -- upstream never restarts a Failed Pod, and
          # restarting one here brought an evicted Pod straight back.
          return true if uid && @mutex.synchronize { @finished.key?(uid.to_s) }
          return true if record && record[:forced_terminal]

          policy = Helpers.key(Helpers.key(pod, "spec", {}), "restartPolicy", "Always").to_s
          return false if policy == "Always"

          phases = []
          phases << record[:phase].to_s if record
          phases << Helpers.key(Helpers.key(pod, "status", {}), "phase", "").to_s
          return true if phases.include?("Succeeded")

          policy == "Never" && phases.include?("Failed")
        end

        # The record that reached the terminal phase, which is not necessarily the
        # one in @records: a stray restart can have replaced it.
        def terminal_record(uid, existing)
          remembered = @mutex.synchronize { @finished[uid.to_s] }
          return existing unless remembered.is_a?(Hash)
          return existing if existing && existing[:phase].to_s == remembered["phase"].to_s

          remembered.fetch("record")
        end

        # Remember a Pod that reached a terminal phase so no later sync starts it
        # again, whatever the reported status says by then.
        def remember_finished(record)
          policy = Helpers.key(Helpers.key(record[:pod] || {}, "spec", {}), "restartPolicy", "Always").to_s
          return if record[:phase].to_s == "Pending"

          phase = record[:phase].to_s
          forced = record[:forced_terminal] && %w[Failed Succeeded].include?(phase)
          return if policy == "Always" && !forced
          return unless forced || phase == "Succeeded" || (policy == "Never" && phase == "Failed")

          # The tombstone exists to stop a later sync from starting this Pod
          # again, and to republish the terminal status; the diagnostic event
          # trail is no part of that.  Copying it too made every finished Pod
          # keep tens of kilobytes alive for the life of the process.
          snapshot = Marshal.load(Marshal.dump(record))
          snapshot[:events] = []
          @mutex.synchronize { @finished[record[:uid].to_s] = {"phase" => phase, "record" => snapshot} }
        end

        DEADLINE_EXCEEDED_REASON = "DeadlineExceeded"
        DEADLINE_EXCEEDED_MESSAGE = "Pod was active on the node longer than the specified deadline"

        # kubelet's podIsActiveDeadlineExceeded: measured from the Pod's start
        # time on THIS node, and only while it is still running.
        def active_deadline_exceeded?(record, pod, now: nil)
          return false unless record.is_a?(Hash)
          return false unless %w[Running Pending].include?(record[:phase].to_s)
          return false if %w[Stopped Removed].include?(record[:state].to_s)

          deadline = Helpers.key(Helpers.key(pod, "spec", {}), "activeDeadlineSeconds", nil)
          return false if deadline.nil?

          seconds = Integer(deadline)
          return false unless seconds.positive?

          started = record[:started_at]
          return false if started.nil?

          started = Time.parse(started.to_s) unless started.is_a?(Time)
          ((now || @clock.call).to_f - started.to_f) >= seconds
        rescue ArgumentError, TypeError, RangeError
          # A deadline that is not a number (the API validates it) or a start
          # time that does not parse: no deadline to enforce.
          false
        end

        # Only the metadata a container's configuration can read back: a label or
        # annotation change matters to a Pod that could not be configured, and to
        # nothing else.
        def metadata_digest(pod)
          metadata = Helpers.key(Helpers.string_keys(pod), "metadata", {})
          Digest::SHA256.hexdigest(JSON.generate(canonical_config_value(
            "labels" => Helpers.key(metadata, "labels", {}),
            "annotations" => Helpers.key(metadata, "annotations", {})
          )))
        end

        def config_digest(pod)
          value = Helpers.string_keys(pod)
          metadata = Helpers.key(value, "metadata", {})
          # Labels and annotations are not part of the digest: kubelet never
          # restarts a Pod for a metadata change (a released ReplicaSet Pod
          # keeps running); projected downward API content is refreshed by
          # the periodic volume sync instead.
          desired_metadata = %w[name namespace uid].each_with_object({}) do |field, result|
            result[field] = metadata[field] if metadata.key?(field)
          end
          # TypeMeta is deliberately not part of the digest: a list item and a
          # watch event describe the same Pod with and without apiVersion/kind,
          # and a digest that flips between them terminates and recreates a
          # healthy Pod on every resync.
          # kubelet restarts containers for a change of the container's own
          # spec (computeHash over the v1.Container), never for scheduling or
          # lifecycle fields the API allows on a running Pod: tolerations,
          # activeDeadlineSeconds, terminationGracePeriodSeconds, priority.
          # Hashing the whole spec killed and recreated a Pod on every such
          # update ("[sig-node] Pods Extended pod generation should start at 1
          # and increment per update" adds a toleration and watched its
          # container die).
          spec = Helpers.key(value, "spec", {})
          spec = spec.reject { |key, _| RESTART_NEUTRAL_SPEC_FIELDS.include?(key.to_s) } if spec.is_a?(Hash)
          # kubelet computePodActions never re-runs an init container that has
          # completed, so a change to one (the e2e swaps its image to pause,
          # which would block for ever) restarts nothing; only restartable init
          # containers (sidecars) are live containers whose hash matters.
          if spec.is_a?(Hash) && spec.key?("initContainers")
            spec = spec.merge("initContainers" => Array(spec["initContainers"]).select do |container|
              restartable_init?(Helpers.string_keys(container))
            end)
          end
          desired = {
            "metadata" => desired_metadata,
            "spec" => spec
          }
          Digest::SHA256.hexdigest(JSON.generate(canonical_config_value(desired)))
        end

        RESTART_NEUTRAL_SPEC_FIELDS = %w[
          tolerations activeDeadlineSeconds terminationGracePeriodSeconds priority priorityClassName
          schedulerName schedulingGates nodeName nodeSelector affinity preemptionPolicy
          readinessGates ephemeralContainers
        ].freeze

        def canonical_config_value(value)
          case value
          when Hash
            value.keys.map(&:to_s).sort.to_h do |key|
              child = value.key?(key) ? value[key] : value[key.to_sym]
              [key, canonical_config_value(child)]
            end
          when Array
            value.map { |child| canonical_config_value(child) }
          else
            value
          end
        end
      end
    end
  end
end
