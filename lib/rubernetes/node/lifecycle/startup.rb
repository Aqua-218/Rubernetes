# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Starts a Pod in the normative order
      # admission -> Volume -> sandbox -> network -> init -> sidecar -> app,
      # and rolls a failed start back so the next sync can retry it.
      module Startup
        # Execute the normative M2 order:
        # admission -> Volume -> sandbox -> network -> init -> sidecar -> app.
        def start(pod, request_id: nil)
          object = normalize_pod(pod)
          uid = pod_uid(object)
          existing = record(uid)
          return result_for(existing) if existing && existing.fetch(:state) == "Running"
          return resume_initialization(object, existing, request_id) if existing && existing[:state] == "WorkloadStopped" && existing[:next_init_index]
          # A sandbox that could not be removed can still hold the block devices open.
          if existing && existing[:state] == "CleanupPending" && existing[:sandbox_id] &&
             !existing.dig(:cleanup_completed, "sandbox:#{existing[:sandbox_id]}")
            return result_for(existing)
          end

          replacing = existing if existing&.fetch(:restarting_after_sandbox_loss, false)
          return result_for(existing) if replacing && existing[:state] == "CleanupPending"
          return result_for(existing) if existing && @mutex.synchronize { @terminating.key?(uid) }

          # A start attempt that follows an earlier one for the same Pod must
          # not leave the earlier attempt's volumes staged.  Stage paths are
          # keyed by Pod uid and volume name, so preparing again would try to
          # mount over a mount that is still there and fail the Pod for good.
          # kubelet keeps one idempotent volume set per Pod; here the previous
          # set is released before a new one is prepared.
          release_stale_volumes(existing) if existing && !replacing
          record = new_record(object, request_id: request_id, replacing: replacing)
          # A retried start builds a fresh record, but the containers in it are
          # the same containers restarting.  Carry what the previous attempt
          # ended with so each one can report its lastState.
          record[:previous_terminations] = terminations_of(existing)
          set_state(record, "New")
          begin
            check_start_cancelled!(record)
            admission_step(object, record)
            with_native_pod_cgroup(object) do
              pin_images(object, record)
              set_state(record, "ImagePinned")
              volume_step(object, record)
              sandbox_step(object, record)
            end
            network_step(object, record)
            publish_workload_start(object, record)
          rescue StartCancelled
            # The queued termination sync owns the stop and resource cleanup.
            result_for(record)
          rescue LifecycleError => error
            fail_record(record, error)
          rescue StandardError => error
            fail_start_as_defect(record, error)
          end
        end

        alias create start
        alias start_pod start
        attr_writer :desired_pod_lookup

        private

        # Admission precedes allocating the Pod cgroup and fetching images.
        def admission_step(object, record)
          admit!(object, record)
          set_state(record, "Validated")
          forget_objects_read_before(object)
          # The Pod is in the desired state of the world from here on: its
          # attachable volumes are reported in use before they are mounted.
          note_attachable_volumes(object, record)
        end

        # See ResourceReader#forget_read_before.  A Pod without a creation time
        # (a static Pod) is treated as created now.
        def forget_objects_read_before(object)
          return unless @resource_reader

          metadata = Helpers.key(object, "metadata", {})
          created = Helpers.key(metadata, "creationTimestamp", nil)
          @resource_reader.forget_read_before(created ? Time.iso8601(created.to_s) : Time.now,
                                              namespace: Helpers.key(metadata, "namespace", "default"))
        end

        # Volume.
        def volume_step(object, record)
          wait_for_volumes_reported_in_use(object, record)
          if record[:volume]
            verify_preserved_volumes(object, record)
          else
            record[:volume] = timed(record, "volume.ready") { prepare_volume(object, record) }
            record[:volume_boot_id] = kernel_boot_id if record[:volume]
          end
          # subPaths are bound when each container's spec is built, i.e. when
          # that container starts (kubelet makeMounts): an emptyDir subPath an
          # init container fills does not exist before then.  The sandbox sees
          # binds made after it exists because the Pod root is a shared mount
          # and the holder's namespace is its slave (PodVolumes
          # #ensure_propagating_root!).
          set_state(record, "WorkspaceAllocated")
        end

        # sandbox (dynamic resources are prepared before it exists).
        def sandbox_step(object, record)
          prepare_dynamic_resources(object, record)
          record[:sandbox_id] = timed(record, "sandbox.ready") { create_sandbox(object, record) }
          raise LifecycleError, "runtime returned an empty sandbox identity" if record[:sandbox_id].to_s.empty?

          record[:sandbox_context] = network_sandbox_context(record)
          record[:resources] << {"kind" => "sandbox", "id" => record[:sandbox_id].to_s}
          set_state(record, "IsolationCreated")
        end

        # network, then what needs the Pod's address: sysctls and Pod files.
        def network_step(object, record)
          record[:network] = timed(record, "network.ready") { connect_network(object, record) }
          record[:resources] << {"kind" => "network", "id" => record[:network].to_s} unless record[:network].nil?
          apply_sysctls(object, record)
          prepare_pod_files(object, record)
          set_state(record, "ResourcesAttached")
          set_state(record, "WorkloadStopped")
        end

        # init -> sidecar -> app.
        def workload_step(object, record)
          began = record[:initialization_began] ||= Process.clock_gettime(Process::CLOCK_MONOTONIC)
          case start_init_containers(object, record)
          when :pending then return
          when :failed then return settle_failed_init(record)
          end

          object = adopt_init_image_updates(record)
          unless object
            record[:next_init_index] = Array(record.dig(:pod, "spec", "initContainers")).length
            return
          end

          record.delete(:initialization_began)
          event(record, "init.ready", seconds: (Process.clock_gettime(Process::CLOCK_MONOTONIC) - began).round(3))
          timed(record, "app.ready") { start_application_containers(object, record) }
          set_state(record, "Running")
          record[:phase] = "Running"
          # A reason from an earlier attempt (FailedMount, ContainerCreating)
          # describes a state the Pod has left; carrying it into a running
          # Pod's status makes `kubectl get pods` report the old failure as
          # the Pod's STATUS forever.
          record[:reason] = nil
          record[:error] = nil
        end

        # A terminal init exit is an ordinary workload failure. Keep its
        # runtime logs available while the Pod exists, as for application exits.
        def settle_failed_init(record)
          stop_sidecars(record)
          record.delete(:initialization_began)
          record[:phase] = "Failed"
          record[:forced_terminal] = true
        end

        def publish_workload_start(object, record)
          workload_step(object, record)
          record.delete(:restarting_after_sandbox_loss) if record[:state] == "Running" || record[:forced_terminal]
          clear_start_retry(record[:uid]) unless record[:image_update_retry_key]
          update_status(record[:pod], record) unless record[:image_update_retry_key]
          persist_state!
          result_for(record)
        end

        # An unstarted sidecar's next probe must not block its Pod worker:
        # deletion and changed manifests still have to reach reconciliation.
        def resume_initialization(object, record, request_id)
          check_start_cancelled!(record)
          if active_deadline_exceeded?(record, object)
            return terminate(object, request_id: request_id, reason: DEADLINE_EXCEEDED_REASON,
                                     terminal_phase: "Failed", message: DEADLINE_EXCEEDED_MESSAGE)
          end
          if config_digest(record.fetch(:pod)) != config_digest(object)
            updates = image_only_updates(record, object, during_init: true)
            return apply_changed_config(object, record, request_id) unless updates
            return result_for(record) unless apply_init_image_updates(object, record, updates)
          end

          record[:pod] = object
          observe_exits(record, object)
          return result_for(record) unless record[:state] == "WorkloadStopped"

          resume_backoff_restarts(record, object)
          return result_for(record) unless record[:state] == "WorkloadStopped"

          probe_initialized_sidecars(object, record)
          sync_volumes(record, object) if volume_sync_due?(record)
          publish_workload_start(object, record)
        rescue StartCancelled
          result_for(record)
        rescue LifecycleError => error
          fail_record(record, error)
        rescue StandardError => error
          fail_start_as_defect(record, error)
        end

        # An unexpected exception here is a kubelet defect, not a Pod
        # condition: keep its origin (kubelet logs the stack) so the failure
        # can be diagnosed from the agent log instead of only "Pod start failed".
        def fail_start_as_defect(record, error)
          frames = Array(error.backtrace).first(6).map { |frame| frame.to_s.sub(%r{\A.*/lib/rubernetes/}, "") }
          event(record, "pod.start_error", error: Helpers.failure_message(error),
                                           message: "#{Helpers.failure_message(error)} at #{frames.join(" <- ")}")
          fail_record(record, LifecycleError.new("Pod start failed: #{Helpers.failure_message(error)}"))
        end

        # kubelet's volume manager and sandbox creation retry quickly (the
        # reconciler loop is sub-second with exponential backoff on repeated
        # failure); the slow 10s..5m curve belongs to CrashLoopBackOff only.
        START_BACKOFF_INITIAL_SECONDS = 1.0
        START_BACKOFF_MAX_SECONDS = 30.0

        def fail_record(record, error, preserve_phase: false)
          record[:error] = error.message
          retryable = !preserve_phase && !TERMINAL_START_REASONS.include?(record[:reason].to_s)
          record.delete(:restarting_after_sandbox_loss) unless retryable
          failure_type = case record[:reason].to_s
                         when "FailedMount" then "volume.failed"
                         when "FailedCreatePodSandBox" then "sandbox.failed"
                         when "PodAdmissionFailed" then "pod.admission_failed"
                         else "pod.failed"
                         end
          # A DRA preparation failure has already been reported as
          # FailedPrepareDynamicResources.
          unless error.is_a?(DynamicResourcesError)
            event(record, failure_type, message: record[:admission_message] || error.message,
                                        reason: (record[:admission_reason] || record[:reason]).to_s)
          end
          record[:phase] = "Failed" unless preserve_phase || retryable
          if retryable
            record[:phase] = "Pending"
            record[:reason] ||= "ContainerCreating"
            retry_schedule = schedule_start_retry(record[:uid])
            mark_image_pull_backoff(record) if retry_schedule.fetch(:count) > 1
          end
          set_state(record, "RollingBack") unless %w[RollingBack Stopped Removed].include?(record[:state])
          stop_confirmed = true
          begin
            stop_containers(record)
            clear_cleanup_error(record, "stop")
          rescue StandardError => stop_error
            stop_confirmed = false
            record_cleanup_error(record, "stop", "workload stop failed: #{Helpers.failure_message(stop_error)}")
          end
          unless stop_confirmed
            # Never remove a container, network, sandbox, image, or volume while
            # a started workload lacks a confirmed terminal state. Keep all
            # ownership durable so the next reconciliation can retry stopping
            # before entering reverse-order cleanup.
            set_state(record, "CleanupPending")
            record[:phase] = "Unknown"
            update_status(record[:pod], record)
            persist_state!
            return result_for(record)
          end
          cleanup_resources(record)
          if record[:pending_terminal_phase]
            settle_terminated_record(record, record[:pending_terminal_phase], deleting: deletion_requested?(record[:pod]))
            return publish_termination(record[:pod], record[:uid], record, gone: record[:config_removed])
          end
          set_state(record, "Stopped") unless record[:state] == "Stopped"
          if record[:cleanup_errors].empty?
            set_state(record, "Removed")
          else
            set_state(record, "CleanupPending")
          end
          record[:resources] = [] if record[:cleanup_errors].empty?
          update_status(record[:pod], record)
          forget_terminated_probe_and_restart_state(record)
          persist_state!
          result_for(record)
        end

        def schedule_start_retry(uid)
          if (record = @records[uid])
            event(record, "container.backoff", message: "Back-off restarting failed container in pod #{pod_name(record[:pod])}")
          end
          @start_retries ||= {}
          attempt = @start_retries[uid.to_s] || {count: 0}
          count = attempt[:count] + 1
          delay = [START_BACKOFF_INITIAL_SECONDS * (2**(count - 1)), START_BACKOFF_MAX_SECONDS].min
          @start_retries[uid.to_s] = {count: count, next_at: monotonic_clock.call + delay}
        end

        def start_retry_pending?(uid)
          attempt = (@start_retries ||= {})[uid.to_s]
          return false unless attempt

          monotonic_clock.call < attempt[:next_at]
        end

        def clear_start_retry(uid)
          (@start_retries ||= {}).delete(uid.to_s)
        end

        # True while this Pod is waiting to be started again after a failed
        # attempt, whether or not its backoff has elapsed.
        def start_retry_scheduled?(uid)
          (@start_retries ||= {}).key?(uid.to_s)
        end
      end
    end
  end
end
