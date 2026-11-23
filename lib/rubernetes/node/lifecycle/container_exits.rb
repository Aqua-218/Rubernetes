# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Containers that exited on their own: the PLEG-style relist, a sandbox
      # the runtime lost, and recording an exit with its termination message.
      module ContainerExits
        # PLEG-style relist: notice containers that exited on their own and
        # apply the restart policy to them.  The runtime only learns of an exit
        # when asked, so without this sweep a finished container stays
        # "running" until the next full sync.  Returns the number of exits
        # handled.
        def observe_exits(record_or_uid, pod = nil, now: nil)
          record = record_or_uid.is_a?(Hash) && record_or_uid.key?(:uid) ? record_or_uid : record(record_or_uid)
          return 0 unless record && (record[:state] == "Running" || (record[:state] == "WorkloadStopped" && record[:next_init_index]))

          object = pod ? normalize_pod(pod) : record[:pod]
          return finish_pending_sidecars(object, record) if record[:sidecar_shutdown_pending]

          handled = 0
          record[:containers].dup.each do |entry|
            next unless observe_container?(record, entry)

            container_id = entry[:id]
            status = begin
              invoke(@runtime, :container_status, container_id)
            rescue StandardError => error
              # The runtime no longer knows a container this record started:
              # startup recovery released its sandbox after the agent crashed,
              # or it was removed behind the agent's back.  Swallowing that
              # left the Pod "Running" with a dead process for ever (and exec
              # answering "unknown container").  kubelet's PLEG treats a
              # container missing from the runtime as dead: it is reported
              # Terminated/ContainerStatusUnknown (137) and, when the sandbox
              # itself is gone, the Pod is killed and synced from scratch.
              next unless lost_container_error?(error) && entry[:id] == container_id
              return lose_sandbox!(object, record, error) if sandbox_lost?(record)

              {"state" => "exited", "exit_code" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON,
               "message" => CONTAINER_STATUS_UNKNOWN_MESSAGE}
            end
            status = status.to_h if hash_convertible?(status) && !status.is_a?(Hash)
            next unless status.is_a?(Hash)

            # Every relist (each second) asks every running container; only an
            # exited one needs its whole status converted.
            state = Helpers.key(status, "state", "").to_s
            next unless %w[stopped terminated exited].include?(state)
            return lose_sandbox!(object, record) if runtime_sandbox_stopped?(record)

            status = Helpers.string_keys(status)

            exit_code, signal = exit_details(status)
            exit_code = 128 + Integer(signal) if exit_code.nil? && !signal.nil?
            next if exit_code.nil?

            reason = status["oom_killed"] == true ? "OOMKilled" : Helpers.key(status, "reason", nil)
            begin
              handle_container_exit(object, container_name: entry[:name], container_id: container_id, exit_code: Integer(exit_code), reason: reason, now: now,
                                            message: Helpers.key(status, "message", nil))
            rescue StandardError => error
              # A restart that fails (runtime refused the create, backoff
              # bookkeeping raised) must not abort the whole relist; the next
              # sync retries it and the record says why.
              event(record, "container.restart_failed", name: entry[:name], error: Helpers.failure_message(error))
              record[:error] = "container #{entry[:name].inspect} restart failed: #{Helpers.failure_message(error)}"
              update_status(object, record)
            end
            handled += 1
          end
          handled
        end

        def observe_container?(record, entry)
          return false unless entry[:started] && !record[:sidecars_stopping] && runtime_supports?(:container_status)
          return false if entry[:exit_recorded_for] == entry[:id]

          record[:state] != "WorkloadStopped" || entry[:category] != "init"
        end
        private :observe_container?

        CONTAINER_STATUS_UNKNOWN_REASON = "ContainerStatusUnknown"
        CONTAINER_STATUS_UNKNOWN_MESSAGE = "The container could not be located when the pod was terminated"
        SANDBOX_LOST_REASON = "SandboxLost"

        def lost_container_error?(error)
          Helpers.failure_message(error).match?(/unknown container|no such container|container .* not found/i)
        end

        def sandbox_lost_error?(error)
          Helpers.failure_message(error).include?("unknown sandbox")
        end

        def sandbox_lost?(record)
          return true if runtime_sandbox_stopped?(record)
          return false unless record[:sandbox_id] && runtime_supports?(:sandbox)

          invoke(@runtime, :sandbox, record[:sandbox_id])
          false
        rescue StandardError => error
          Helpers.failure_message(error).include?("unknown sandbox")
        end

        # Marks the Pod in `sandbox_id` for the same treatment as a sandbox
        # the runtime lost: the next sync kills it and the restart policy
        # brings it back in a new sandbox.  For a sandbox that is running but
        # can no longer be trusted (its network attachment could not be
        # confirmed after an agent restart).
        def replace_sandbox(sandbox_id, message:)
          @mutex.synchronize do
            record = @records.values.find { |candidate| candidate[:sandbox_id].to_s == sandbox_id.to_s }
            next false unless record

            record[:sandbox_replacement] = message
            true
          end
        end

        def runtime_sandbox_stopped?(record)
          sandbox = record[:sandbox_id]
          return false unless sandbox && runtime_supports?(:sandbox_state)

          best_effort { @runtime.sandbox_state(sandbox) } == :stopped
        end

        # kubelet SyncPod on a sandbox the runtime lost ("pod sandbox changed"):
        # every container that ran is reported Terminated with
        # ContainerStatusUnknown/137, the Pod is killed, and the restart policy
        # decides what follows -- Always/OnFailure start it again on the next
        # sync (no tombstone), Never ends it Failed.
        def lose_sandbox!(object, record, error = nil)
          first = @mutex.synchronize do
            next false if record[:sandbox_loss_seen] || !@records[record[:uid]].equal?(record)

            record[:sandbox_loss_seen] = true
          end
          return 0 unless first

          event(record, "sandbox.lost", sandbox_id: record[:sandbox_id],
                                        message: error ? Helpers.failure_message(error) : "Pod sandbox is no longer ready")
          finished_at = Helpers.now(@clock).iso8601(6)
          policy = Helpers.key(Helpers.key(object || {}, "spec", {}), "restartPolicy", "Always").to_s
          # The Pod comes back in a new sandbox with the same containers
          # restarting: their count goes on from here (kubelet numbers a
          # container the runtime lost from what it knew of it), so it must
          # outlive this record.
          record[:restarting_after_sandbox_loss] = policy != "Never"
          record[:containers].each do |entry|
            restart_count = entry[:status].fetch("restartCount", 0).to_i
            @restarts.advance_restart_count(restart_identity(record, entry), to: restart_count + 1) if policy != "Never" && entry[:category] != "ephemeral"
            next unless entry[:started]

            @probes.unregister(entry[:id])
            terminated = {"exitCode" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON, "message" => CONTAINER_STATUS_UNKNOWN_MESSAGE,
                          "finishedAt" => finished_at, "containerID" => entry[:id]}
            terminated["startedAt"] = entry[:started_at] if entry[:started_at]
            entry[:started] = false
            entry[:status] = {"state" => "terminated", "exitCode" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON,
                              "terminated" => terminated, "ready" => false, "started" => false, "restartCount" => restart_count}
          end
          phase = policy == "Never" ? "Failed" : sandbox_replacement_phase(record)
          terminate(object || record[:uid], reason: SANDBOX_LOST_REASON, terminal_phase: phase,
                                            message: CONTAINER_STATUS_UNKNOWN_MESSAGE)
          record[:containers].length
        end

        # Regular init must run again in the replacement sandbox. Already
        # initialized Pods without regular init stay Running during restarts.
        def sandbox_replacement_phase(record)
          record[:containers].any? { |entry| entry[:category] == "init" } ? "Pending" : "Running"
        end

        # The exit code and terminating signal a runtime status carries.  The
        # Native runtime keeps them on the process handle; simpler runtimes
        # report them at the top level or under "terminated".
        def exit_details(status)
          candidates = [status, Helpers.key(status, "process", nil), Helpers.key(status, "terminated", nil)].compact
          candidates = candidates.filter_map { |candidate| hash_convertible?(candidate) ? Helpers.string_keys(candidate.to_h) : nil }
          exit_code = nil
          signal = nil
          candidates.each do |candidate|
            if exit_code.nil?
              exit_code = Helpers.key(candidate, "exit_status",
                                      Helpers.key(candidate, "exitCode", Helpers.key(candidate, "exit_code", nil)))
            end
            signal = Helpers.key(candidate, "term_signal", Helpers.key(candidate, "signal", nil)) if signal.nil?
          end
          [exit_code.nil? ? nil : Integer(exit_code), signal.nil? ? nil : Integer(signal)]
        rescue ArgumentError, TypeError
          [nil, nil]
        end

        # Apply restartPolicy to a runtime-reported process exit.  Runtime
        # adapters can call this without knowing how Pod status or backoff is
        # represented internally.
        def handle_container_exit(pod_or_uid, container_name:, container_id: nil, exit_code: 0, reason: nil, now: nil, message: nil)
          object, uid, record = resolve_record(pod_or_uid)
          raise LifecycleError, "Pod #{uid} is not known" unless record

          entry = record[:containers].find { |candidate| candidate[:name] == container_name.to_s }
          raise LifecycleError, "container #{container_name.inspect} is not known in Pod #{uid}" unless entry

          policy = container_policy(object, entry[:spec])
          restart_key = restart_identity(record, entry)
          # The relist thread and a sync worker can both find the same exited
          # container; only the first observation records it.  Both did, the
          # restart counted twice, and "Container Runtime blackbox test ...
          # terminate-cmd-rpof" saw restartCount 2 where one restart happened.
          return @restarts.attempt(restart_key, container_id: entry[:id]) unless claim_exit!(entry, container_id: container_id)

          # kubelet reports Completed for a zero exit and Error otherwise.
          reason = Integer(exit_code).zero? ? "Completed" : "Error" if reason.to_s.empty?
          # The restart count this run had; the next start (or a
          # RestartAllContainers reset) is what moves it on.
          entry[:restart_count_before_exit] = entry[:status].is_a?(Hash) ? entry[:status]["restartCount"].to_i : 0
          restart_all = restart_all_rule?(entry, exit_code)
          rules = Helpers.key(entry[:spec], "restartPolicyRules", nil) unless restart_all
          attempt = @restarts.record_exit(restart_key, exit_code: exit_code, reason: reason, policy: policy, at: now, rules: rules)
          record_terminated(record, entry, exit_code: exit_code, reason: reason, message: message)
          remove_endpoints(object, uid) if entry[:category] == "app" && record[:containers].select do |candidate|
            candidate[:category] == "app"
          end.none? { |candidate| candidate[:started] }
          if restart_all
            restart_all_containers(object, record, [entry])
            persist_state!
            return attempt
          end
          if attempt.restart_pending?
            restart_container(object, record, entry, reason: reason || "Failure", now: now, attempt: attempt)
          else
            finish_pod_without_running_apps(object, record)
          end
          persist_state!
          attempt
        end

        alias container_exited handle_container_exit
        alias on_container_exit handle_container_exit

        # True exactly once per container run: the caller that wins records the
        # exit, every other observer of the same run is told it was recorded.
        def claim_exit!(entry, container_id: nil)
          @exit_mutex ||= Mutex.new
          @exit_mutex.synchronize do
            return false if container_id && container_id != entry[:id]
            return false if exited_already?(entry) || entry[:exit_recorded_for].to_s == entry[:id].to_s

            entry[:exit_recorded_for] = entry[:id]
            true
          end
        end

        def release_exit_claim!(entry)
          @exit_mutex.synchronize { entry.delete(:exit_recorded_for) }
        end

        def exited_already?(entry)
          status = entry[:status]
          status.is_a?(Hash) && status["state"] == "terminated" &&
            status.dig("terminated", "containerID").to_s == entry[:id].to_s
        end

        # kubelet getTerminationMessage: the termination message file (last 4 KiB)
        # or, with FallbackToLogsOnError and a failed exit, the last 80 lines /
        # 2 KiB of the container log.
        TERMINATION_MESSAGE_LIMIT = 4 * 1024
        TERMINATION_LOG_LIMIT = 2 * 1024
        TERMINATION_LOG_LINES = 80

        def termination_message_for(entry, exit_code:, reason:)
          # The message is a courtesy to whoever reads the status: a message
          # file that cannot be read never stands in the way of recording the
          # exit itself.
          best_effort { read_termination_message(entry, exit_code: exit_code, reason: reason) }
        end

        def tail_container_log(container_id)
          output = invoke(@runtime, :logs, container_id, follow: false, tail: TERMINATION_LOG_LINES)
          text = if value_reports?(output, :read)
                   output.read.to_s
                 else
                   (value_reports?(output, :each) && !output.is_a?(String) ? output.to_a.join : output.to_s)
                 end
          text = text.dup.force_encoding(Encoding::UTF_8).scrub
          text = text.lines.last(TERMINATION_LOG_LINES).join
          text.byteslice(-TERMINATION_LOG_LIMIT, TERMINATION_LOG_LIMIT) || text
        rescue StandardError
          # No log to fall back to (the runtime keeps none for this container,
          # or cannot read it): the termination message stays empty.
          ""
        end

        private

        # The exited container's status: Terminated, with its termination
        # message, and no longer probed.
        def record_terminated(record, entry, exit_code:, reason:, message:)
          @probes.unregister(entry[:id])
          entry[:started] = false
          finished_at = Helpers.now(@clock).iso8601(6)
          terminated = {"exitCode" => Integer(exit_code), "reason" => reason.to_s, "finishedAt" => finished_at}
          terminated["startedAt"] = entry[:started_at] if entry[:started_at]
          terminated["containerID"] = entry[:id]
          message ||= termination_message_for(entry, exit_code: Integer(exit_code), reason: reason)
          terminated["message"] = message unless message.nil? || message.empty?
          entry[:status] = {
            "state" => "terminated", "exitCode" => Integer(exit_code), "reason" => reason.to_s,
            "terminated" => terminated,
            "ready" => false, "started" => false, "restartCount" => entry[:restart_count_before_exit]
          }
          entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
          event(record, "container.exited", name: entry[:name], container_id: entry[:id], exit_code: Integer(exit_code), reason: reason.to_s)
        end

        # kubelet getPhase: the Pod stays Running while any container still
        # runs; only when every app container stopped (and none restarts)
        # does it reach Succeeded/Failed.
        def finish_pod_without_running_apps(object, record)
          app_entries = record[:containers].select { |candidate| candidate[:category] == "app" }
          return if app_entries.none? { |candidate| candidate[:started] || candidate[:restart_pending] } && !finish_sidecars(record)

          update_status(object, record)
        end

        def finish_pending_sidecars(object, record)
          finish_pod_without_running_apps(object, record)
          persist_state!
          0
        end

        def finish_sidecars(record)
          claimed = @mutex.synchronize do
            next false if record[:sidecars_stopping] || @terminating.key?(record[:uid].to_s)

            record[:sidecars_stopping] = true
            record[:sidecar_shutdown_pending] = true
          end
          return false unless claimed

          begin
            stop_sidecars(record)
            record[:phase] = terminal_phase(record)
            record.delete(:sidecar_shutdown_pending)
            true
          rescue LifecycleError => error
            event(record, "pod.stop_failed", message: Helpers.failure_message(error))
            schedule_wakeup(record[:uid], 1)
            false
          ensure
            @mutex.synchronize do
              record.delete(:sidecars_stopping)
              @terminating_done.broadcast
            end
          end
        end

        def read_termination_message(entry, exit_code:, reason:)
          spec = entry[:spec] || {}
          settings = Helpers.key(spec, "termination_message", nil)
          return nil unless settings.is_a?(Hash)

          host_path = Helpers.key(settings, "host_path", nil)
          message = ""
          if host_path && File.file?(host_path)
            size = File.size(host_path)
            message = File.open(host_path, "rb") do |file|
              file.seek([size - TERMINATION_MESSAGE_LIMIT, 0].max)
              file.read.to_s
            end
            message = message.dup.force_encoding(Encoding::UTF_8).scrub
          end
          failed = !Integer(exit_code).zero? || reason.to_s == "OOMKilled"
          message = tail_container_log(entry[:id]) if message.empty? && failed && Helpers.key(settings, "policy", "File").to_s == "FallbackToLogsOnError"
          message.empty? ? nil : message
        end
      end
    end
  end
end
