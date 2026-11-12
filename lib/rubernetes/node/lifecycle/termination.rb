# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Terminates a Pod in the observable Kubernetes order (preStop hooks,
      # stop within the grace period, reverse-order cleanup, terminal phase)
      # and carries out evictions.
      module Termination
        # Terminate in the observable Kubernetes order and release resources in
        # reverse acquisition order.  Cleanup errors are retained alongside the
        # original failure instead of replacing it.
        def terminate(pod_or_uid, request_id: nil, reason: "PodTerminating", terminal_phase: nil, message: nil, gone: false)
          object, uid, record = resolve_record(pod_or_uid)
          # One terminate per Pod at a time; a concurrent caller waits for the
          # running one and gets its outcome.
          first = @mutex.synchronize do
            if @terminating.key?(uid.to_s)
              @terminating_done.wait(@mutex) while @terminating.key?(uid.to_s)
              false
            else
              @terminating[uid.to_s] = true
              true
            end
          end
          unless first
            _object, _uid, current = resolve_record(pod_or_uid)
            return current ? result_for(current) : nil
          end
          begin
            terminate_once(object, uid, record, request_id: request_id, reason: reason, terminal_phase: terminal_phase,
                                                message: message, gone: gone)
          ensure
            @mutex.synchronize do
              @terminating.delete(uid.to_s)
              @terminating_done.broadcast
            end
          end
        end

        def terminate_once(object, uid, record, request_id:, reason:, terminal_phase:, message:, gone:)
          unless record
            # A Pod this node never started still has to be confirmed gone.  The
            # API server sets a deletionTimestamp and waits for the kubelet
            # whatever state the Pod reached, so one that was scheduled here and
            # never ran -- admission refused it, the namespace went away first --
            # has nothing to clean up and everything to confirm.  Returning
            # without a word left it Terminating in the API for ever.
            complete_graceful_deletion(object, {cleanup_errors: [], events: [], state: "Removed", uid: uid}) if object
            return nil
          end

          begin_termination(object, uid, record, reason: reason, message: message, gone: gone)
          stop_within_grace(object, record)
          cleanup_resources(record)
          settle_terminated_record(record, terminal_phase)
          publish_termination(object, uid, record, gone: gone)
        rescue StandardError => error
          record ||= new_record(object || {"metadata" => {"uid" => uid}}, request_id: request_id)
          fail_record(record, LifecycleError.new("Pod termination failed: #{Helpers.failure_message(error)}"), preserve_phase: true)
        end

        alias stop terminate
        alias delete terminate
        alias stop_pod terminate
        alias delete_pod terminate

        EVICTED_REASON = "Evicted"

        # Queue an eviction for the Pod's next sync (see #evict).
        def request_eviction(uid, message:, grace_period_seconds: nil, condition: nil, reason: EVICTED_REASON)
          @mutex.synchronize do
            @eviction_requests[uid.to_s] = {message: message, grace_period_seconds: grace_period_seconds, condition: condition,
                                            reason: reason}
          end
          true
        end

        # The eviction manager's killPodFunc (evict=true): stop the Pod within
        # +grace_period_seconds+ and report it Failed/Evicted with +message+
        # and the DisruptionTarget +condition+ (TerminationByKubelet).
        # The node shutdown manager kills the same way with reason Terminated.
        def evict(pod_or_uid, message:, grace_period_seconds: nil, condition: nil, reason: EVICTED_REASON)
          object, _uid, record = resolve_record(pod_or_uid)
          return nil unless record

          record[:grace_override] = Integer(grace_period_seconds) unless grace_period_seconds.nil?
          if condition
            record[:disruption_condition] = Helpers.string_keys(condition).merge(
              "lastTransitionTime" => Helpers.now(@clock).iso8601(6)
            )
          end
          terminate(object || record[:pod], reason: reason, terminal_phase: "Failed", message: message)
        end

        private

        def begin_termination(object, uid, record, reason:, message:, gone:)
          record[:phase] = "Running" if record[:phase].to_s.empty?
          record[:reason] = reason.to_s
          record[:termination_message] = message if message
          # HandlePodRemoves: a Pod whose API object is gone leaves the pod
          # manager at once, so admission stops counting it even while its
          # containers are still being killed.  Counting it refused the Pods a
          # preemption made room for ("Node didn't have enough resource").
          @mutex.synchronize { record[:config_removed] = true } if gone
          remove_endpoints(object, uid)
          set_state(record, "Stopping") unless %w[Stopped Removed].include?(record[:state])
        end

        # preStop hooks, then the stop itself, both inside the grace period.
        def stop_within_grace(object, record)
          kill_grace = kill_grace_seconds(record, object)
          hooks_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            run_pre_stop_hooks(object, record, budget: kill_grace)
          rescue StandardError => error
            # A preStop hook that fails does not stop the kill.  kubelet records
            # a FailedPreStopHook event and carries on
            # (pkg/kubelet/kuberuntime/kuberuntime_container.go killContainer:
            # "if the pre-stop hook fails, we still want to kill the container"),
            # because the container has to go either way.  Counting it as a
            # cleanup error instead left the Pod in CleanupPending, so the node
            # never issued its final delete and the Pod stayed Terminating in the
            # API for ever -- a failed hook made the Pod immortal.
            event(record, "container.failed_prestop", reason: "FailedPreStopHook",
                                                      message: "PreStopHook failed: #{Helpers.failure_message(error)}")
          end
          # killContainer: the preStop hook spends the grace period; what is
          # left, at least the minimum, is the stop's -- unless an eviction
          # overrides it, which applies last.
          spent = Process.clock_gettime(Process::CLOCK_MONOTONIC) - hooks_started
          stop_grace = [(kill_grace - spent).ceil, MINIMUM_GRACE_PERIOD_SECONDS].max
          stop_grace = Integer(record[:grace_override]) unless record[:grace_override].nil?
          stop_containers(record, grace: stop_grace)
          clear_cleanup_error(record, "stop")
          set_state(record, "Stopped") unless record[:state] == "Stopped"
        end

        # The state and phase the record ends in once cleanup has run.
        def settle_terminated_record(record, forced_phase)
          if record[:cleanup_errors].empty?
            set_state(record, "Removed")
          else
            # A failed release is durable work, not a successful stop.  Keep the
            # record and owned resources so the next reconciliation can retry
            # cleanup after the workload has been confirmed stopped.
            set_state(record, "CleanupPending") unless record[:state] == "CleanupPending"
          end
          # kubelet getPhase for a terminal Pod: Succeeded only when every
          # container stopped with exit 0, otherwise Failed.
          if record[:cleanup_errors].empty?
            # A forced terminal phase wins over the exit-code rule: a Pod killed
            # for exceeding its deadline is Failed even when its containers were
            # stopped cleanly.
            record[:phase] = forced_phase || terminal_phase(record)
            # A phase the kubelet forced (DeadlineExceeded, Evicted) is final
            # whatever the restart policy says.
            # A forced "Running" (a lost sandbox under Always/OnFailure, which
            # the next sync starts again) is a published phase, not a terminal one.
            record[:forced_terminal] = true if forced_phase && %w[Failed Succeeded].include?(forced_phase.to_s)
          end
          record[:phase] = "Unknown" unless record[:cleanup_errors].empty?
          remember_finished(record)
          record[:resources] = [] if record[:cleanup_errors].empty?
        end

        def publish_termination(object, uid, record, gone:)
          update_status(object, record)
          withdraw_host_ports(record)
          forget_terminated_probe_and_restart_state(record)
          persist_state!
          # A Pod deleted gracefully keeps its API object until the kubelet says
          # the containers are gone; upstream's status manager then issues the
          # final delete with grace 0.  Without it a gracefully deleted Pod is
          # stopped on the node and left in the API for ever, Terminating.
          complete_graceful_deletion(object, record)
          result = result_for(record)
          # The API object is already gone (the informer delivered DELETED):
          # nothing is left to report or restart, so the record goes too.
          # Keeping it -- and its tombstone -- for every Pod the node ever ran
          # made each later Pod start slower (every persist and sync walks the
          # records): ~2,000 per conformance round.
          forget_pod(uid) if gone && record[:cleanup_errors].empty?
          result
        end

        # kuberuntime killContainer: minimumGracePeriodInSeconds.
        MINIMUM_GRACE_PERIOD_SECONDS = 2

        # setTerminationGracePeriod: an eviction's override, else the
        # deletion's (a force delete is 0), else the Pod's
        # terminationGracePeriodSeconds.  The preStop hook runs only when it is
        # above zero, and within it.
        def kill_grace_seconds(record, object)
          grace = record[:grace_override]
          if grace.nil?
            deletion = Helpers.key(Helpers.key(object || {}, "metadata", {}), "deletionGracePeriodSeconds", nil)
            grace = deletion.nil? ? grace_seconds(record[:pod]) : Integer(deletion)
          end
          [Integer(grace), 0].max
        rescue ArgumentError, TypeError
          grace_seconds(record[:pod])
        end

        # A Pod is Succeeded only if its app containers ran and every one of
        # them exited zero.  This used to answer "Succeeded" for a Pod whose
        # containers had NEVER run -- nothing had exited non-zero, so nothing
        # looked failed -- and a Pod whose container cannot be created was
        # reported as completed while its own container status still said
        # Waiting/CreateContainerConfigError.  kubelet keeps that Pod Pending
        # and retries creating the container ("[sig-node] Variable Expansion
        # should verify that a failing subpath expansion can be modified during
        # the lifetime of a container" waits for exactly that Pending).
        def terminal_phase(record)
          app_entries = record[:containers].select { |entry| entry[:category] == "app" }
          ran = app_entries.any? { |entry| entry[:status].is_a?(Hash) }
          unless ran
            return "Failed" if TERMINAL_START_REASONS.include?(record[:reason].to_s)

            return "Pending"
          end
          failed = app_entries.any? do |entry|
            entry[:status].is_a?(Hash) && Integer(entry[:status]["exitCode"] || 0) != 0
          end
          failed ? "Failed" : "Succeeded"
        end

        # The final delete of a Pod the API server marked for deletion.  Only for
        # a Pod that actually carries a deletionTimestamp, and only once its
        # cleanup succeeded: a CleanupPending record still owns resources.
        def complete_graceful_deletion(pod, record)
          return unless @pod_deleter
          return unless deletion_requested?(pod)
          return unless record[:cleanup_errors].empty?

          metadata = Helpers.key(pod, "metadata", {})
          name = Helpers.key(metadata, "name", "").to_s
          namespace = Helpers.key(metadata, "namespace", "").to_s
          return if name.empty?

          @pod_deleter.call(namespace: namespace, name: name, uid: Helpers.key(metadata, "uid", nil))
          event(record, "pod.deleted", name: name)
          # The API object is gone, so there is nothing left to start again and
          # nothing left to report: keeping the record and its tombstone only
          # grows the node's memory for every Pod it ever ran.  kubelet does the
          # same once a Pod is removed (podManager.RemovePod and
          # statusManager.RemoveOrphanedStatuses).
          forget_pod(Helpers.key(metadata, "uid", nil))
        rescue StandardError => error
          # Already gone (the namespace was deleted, or another deleter won):
          # the final delete has nothing left to do, and the record must not
          # outlive it.  Most Pods of a conformance round end this way.
          if error.message.include?("HTTP 404") || (value_reports?(error, :status) && error.status.to_i == 404)
            forget_pod(Helpers.key(Helpers.key(pod, "metadata", {}), "uid", nil))
            return
          end
          # The API can refuse or be unreachable; the next sync retries.
          event(record, "pod.delete_failed", name: Helpers.key(Helpers.key(pod, "metadata", {}), "name", nil),
                                             error: Helpers.failure_message(error))
        end

        # kubelet removes a Pod's probe workers (probeManager.RemovePod) and its
        # restart backoff entries once the Pod is gone.  Ours kept both for every
        # Pod the node had ever run, and both are serialised in full on EVERY
        # state transition of EVERY Pod, under one lock -- 415 KB of dead probe
        # state and 50 KB of dead backoff state per node, rewritten ~8 times per
        # Pod start, which is what serialised Pod starts on a node behind each
        # other.  Called only once cleanup has succeeded, and after the record's
        # final status has been reported from it.
        def forget_terminated_probe_and_restart_state(record)
          return unless record[:cleanup_errors].to_a.empty?
          # A Pod whose start failed is rolled back through this same path and
          # then STARTED AGAIN.  Its restart history is what makes the retries a
          # restart count rather than a series of first attempts, so it must
          # survive the rollback: kubelet keeps the backoff across them, and
          # "[sig-node] InitContainer should not start app containers if init
          # containers fail on a RestartAlways pod" waits for restartCount 3.
          return if start_retry_scheduled?(record[:uid])

          Array(record[:containers]).each do |entry|
            identifier = entry[:id]
            @probes.unregister(identifier) unless identifier.nil?
          end
          @restarts.forget_pod(record[:uid])
        end
      end
    end
  end
end
