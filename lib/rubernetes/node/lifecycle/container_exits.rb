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
          return 0 unless record && record[:state] == "Running"

          object = pod ? normalize_pod(pod) : record[:pod]
          handled = 0
          record[:containers].dup.each do |entry|
            next unless entry[:started]
            next unless runtime_supports?(:container_status)

            status = begin
              invoke(@runtime, :container_status, entry[:id])
            rescue StandardError => error
              # The runtime no longer knows a container this record started:
              # startup recovery released its sandbox after the agent crashed,
              # or it was removed behind the agent's back.  Swallowing that
              # left the Pod "Running" with a dead process for ever (and exec
              # answering "unknown container").  kubelet's PLEG treats a
              # container missing from the runtime as dead: it is reported
              # Terminated/ContainerStatusUnknown (137) and, when the sandbox
              # itself is gone, the Pod is killed and synced from scratch.
              next unless lost_container_error?(error)
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

            status = Helpers.string_keys(status)

            exit_code, signal = exit_details(status)
            exit_code = 128 + Integer(signal) if exit_code.nil? && !signal.nil?
            next if exit_code.nil?

            reason = status["oom_killed"] == true ? "OOMKilled" : Helpers.key(status, "reason", nil)
            begin
              handle_container_exit(object, container_name: entry[:name], exit_code: Integer(exit_code), reason: reason, now: now,
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

        CONTAINER_STATUS_UNKNOWN_REASON = "ContainerStatusUnknown"
        CONTAINER_STATUS_UNKNOWN_MESSAGE = "The container could not be located when the pod was terminated"

        def lost_container_error?(error)
          Helpers.failure_message(error).match?(/unknown container|no such container|container .* not found/i)
        end

        def sandbox_lost_error?(error)
          Helpers.failure_message(error).include?("unknown sandbox")
        end

        def sandbox_lost?(record)
          return false unless record[:sandbox_id] && runtime_supports?(:sandbox)

          invoke(@runtime, :sandbox, record[:sandbox_id])
          false
        rescue StandardError => error
          Helpers.failure_message(error).include?("unknown sandbox")
        end

        # kubelet SyncPod on a sandbox the runtime lost ("pod sandbox changed"):
        # every container that ran is reported Terminated with
        # ContainerStatusUnknown/137, the Pod is killed, and the restart policy
        # decides what follows -- Always/OnFailure start it again on the next
        # sync (no tombstone), Never ends it Failed.
        def lose_sandbox!(object, record, error)
          event(record, "sandbox.lost", sandbox_id: record[:sandbox_id], message: Helpers.failure_message(error))
          finished_at = Helpers.now(@clock).iso8601(6)
          record[:containers].each do |entry|
            next unless entry[:started]

            @probes.unregister(entry[:id])
            restart_count = entry[:status].is_a?(Hash) ? entry[:status]["restartCount"].to_i : 0
            terminated = {"exitCode" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON, "message" => CONTAINER_STATUS_UNKNOWN_MESSAGE,
                          "finishedAt" => finished_at, "containerID" => entry[:id]}
            terminated["startedAt"] = entry[:started_at] if entry[:started_at]
            entry[:started] = false
            entry[:status] = {"state" => "terminated", "exitCode" => 137, "reason" => CONTAINER_STATUS_UNKNOWN_REASON,
                              "terminated" => terminated, "ready" => false, "started" => false, "restartCount" => restart_count}
          end
          # kubelet getPhase: every container stopped under Always (or a failed
          # one under OnFailure) is still a Running Pod -- it is being
          # restarted; only Never ends Failed.
          policy = Helpers.key(Helpers.key(object || {}, "spec", {}), "restartPolicy", "Always").to_s
          terminate(object || record[:uid], reason: "SandboxLost", terminal_phase: policy == "Never" ? "Failed" : "Running",
                                            message: CONTAINER_STATUS_UNKNOWN_MESSAGE)
          record[:containers].length
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
        def handle_container_exit(pod_or_uid, container_name:, exit_code: 0, reason: nil, now: nil, message: nil)
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
          return @restarts.attempt(restart_key, container_id: entry[:id]) unless claim_exit!(entry)

          # kubelet reports Completed for a zero exit and Error otherwise.
          reason = Integer(exit_code).zero? ? "Completed" : "Error" if reason.to_s.empty?
          # The restart count this run had; the next start (or a
          # RestartAllContainers reset) is what moves it on.
          entry[:restart_count_before_exit] = entry[:status].is_a?(Hash) ? entry[:status]["restartCount"].to_i : 0
          attempt = @restarts.record_exit(restart_key, exit_code: exit_code, reason: reason, policy: policy, at: now)
          record_terminated(record, entry, exit_code: exit_code, reason: reason, message: message)
          remove_endpoints(object, uid) if entry[:category] == "app" && record[:containers].select do |candidate|
            candidate[:category] == "app"
          end.none? { |candidate| candidate[:started] }
          if restart_all_rule?(entry, exit_code)
            restart_all_containers(object, record, [entry])
            persist_state!
            return attempt
          end
          should_restart = @restarts.should_restart?(policy: policy, exit_code: exit_code, reason: reason,
                                                     rules: Helpers.key(entry[:spec], "restartPolicyRules", nil))
          if should_restart
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
        def claim_exit!(entry)
          @exit_mutex ||= Mutex.new
          @exit_mutex.synchronize do
            return false if exited_already?(entry) || entry[:exit_recorded_for].to_s == entry[:id].to_s

            entry[:exit_recorded_for] = entry[:id]
            true
          end
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
          if app_entries.none? { |candidate| candidate[:started] }
            record[:phase] = terminal_phase(record)
            # Sidecars (restartable init containers) are stopped once the
            # last app container is gone, as kubelet does.
            stop_sidecars(record)
          end
          update_status(object, record)
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
