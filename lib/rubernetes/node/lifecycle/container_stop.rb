# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Stopping containers: TERM, the grace period, KILL, and the confirmed
      # terminated state each stopped container reports.
      module ContainerStop
        private

        def stop_containers(record, grace: nil)
          grace ||= record[:grace_override] || grace_seconds(record[:pod])
          record[:containers].reverse_each do |entry|
            stop_entry(record, entry, grace) if entry[:started]
          end
        end

        def stop_entry(record, entry, grace)
          event(record, "container.term", name: entry[:name], container_id: entry[:id])
          event(record, "container.killing", name: entry[:name], container_id: entry[:id], reason: "Killing",
                                             message: "Stopping container #{entry[:name]}")
          (@stop_details ||= {}).delete(entry[:id])
          stopped = stop_one(entry[:id], grace)
          raise LifecycleError, "container #{entry[:name].inspect} did not reach a confirmed stopped state" unless stopped

          @probes.unregister(entry[:id])
          entry[:started] = false
          terminated = stopped_termination(entry)
          entry[:status] = {"state" => "terminated", "exitCode" => terminated.fetch("exitCode"), "reason" => terminated.fetch("reason"),
                            "terminated" => terminated, "ready" => false, "started" => false,
                            "restartCount" => entry[:status]["restartCount"].to_i}
        end

        # Each container runs preStop and stops independently against the
        # same deadline. Sidecars also wait for the app containers and the
        # next sidecar to stop, for as long as that deadline allows.
        def stop_with_sidecar_order(record, entries, grace, minimum_grace: Termination::MINIMUM_GRACE_PERIOD_SECONDS)
          sidecars, others = entries.select { |entry| entry[:started] }.partition { |entry| entry[:category] == "sidecar" }
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + grace
          threads = []
          main = others.reverse_each.filter_map do |entry|
            thread = launch_stop(record, entry, deadline, minimum_grace, [])
            threads << thread
            thread if entry[:category] == "app"
          end
          previous = nil
          sidecars.reverse_each do |entry|
            prerequisites = previous ? main + [previous] : main
            previous = launch_stop(record, entry, deadline, minimum_grace, prerequisites)
            threads << previous
          end
          error = threads.filter_map(&:value).first
          raise error if error
        end

        def launch_stop(record, entry, deadline, minimum_grace, prerequisites)
          Thread.new do
            run_termination_hook(record, entry, deadline)
            wait_for_stop_prerequisites(prerequisites, deadline)
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            grace = [remaining.ceil, minimum_grace].max
            stop_entry(record, entry, grace)
            nil
          rescue StandardError => error
            error
          end
        end

        def wait_for_stop_prerequisites(prerequisites, deadline)
          prerequisites.each do |thread|
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break unless remaining.positive? && thread.join(remaining)
            next unless thread.value

            # An error did not confirm the predecessor's exit. Keep the
            # sidecar available until the shared deadline in that case.
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            sleep(remaining) if remaining.positive?
            break
          end
        end

        def run_termination_hook(record, entry, deadline)
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          run_pre_stop_hooks(record[:pod], record, budget: remaining, entries: [entry])
        rescue StandardError => error
          event(record, "container.failed_prestop", name: entry[:name], reason: "FailedPreStopHook",
                                                    message: "PreStopHook failed: #{Helpers.failure_message(error)}")
        end

        # The termination the runtime reports after a stop: a SIGKILL after the
        # grace period exits 137 (Error); otherwise the runtime status (exit
        # code, reason, termination message) is used when it is available.
        def stopped_termination(entry)
          container_id = entry[:id]
          details = (@stop_details ||= {})[container_id] || {}
          status = status_after_stop(container_id)
          terminated = Helpers.key(status, "terminated", status)
          terminated = Helpers.string_keys(terminated.is_a?(Hash) ? terminated : {})
          exit_code, signal = exit_details(status)
          exit_code = 128 + signal if exit_code.nil? && signal
          exit_code = details[:killed] ? 137 : 0 if exit_code.nil?
          exit_code = Integer(exit_code)
          reason = Helpers.key(terminated, "reason", nil)
          reason = "OOMKilled" if status["oom_killed"] == true
          reason = exit_code.zero? ? "Completed" : "Error" if reason.nil? || reason.to_s.empty?
          started_at = terminated["startedAt"] || entry[:started_at]
          finished_at = terminated["finishedAt"] || Helpers.now(@clock).iso8601(6)
          result = {"exitCode" => exit_code, "reason" => reason.to_s, "finishedAt" => finished_at, "containerID" => container_id}
          result["startedAt"] = started_at if started_at
          message = Helpers.key(terminated, "message", nil)
          message = termination_message_for(entry, exit_code: exit_code, reason: reason) if message.nil? || message.to_s.empty?
          result["message"] = message.to_s unless message.nil? || message.to_s.empty?
          result
        end

        # What the runtime reports about a container that was just stopped; {}
        # when it has no status call or no longer knows the container.
        def status_after_stop(container_id)
          return {} unless runtime_supports?(:container_status)

          value = best_effort { invoke(@runtime, :container_status, container_id) }
          value = value.to_h if hash_convertible?(value) && !value.is_a?(Hash)
          value.is_a?(Hash) ? Helpers.string_keys(value) : {}
        end

        # +release_process+: false keeps the exited process handle so the
        # container's log stays readable (a container waiting out its restart
        # backoff); the handle goes with the container itself.
        def stop_one(container_id, grace, release_process: true)
          # Only the narrow runtime doubles take a bare signal; the runtime
          # backends deliver TERM themselves in stop_container.
          send_signal(container_id, "TERM") if runtime_supports?(:signal)
          result = begin
            options = {timeout: grace}
            options[:release_process] = release_process if accepts_keyword?(@runtime, :stop_container, :release_process)
            invoke(@runtime, :stop_container, container_id, **options)
          rescue StandardError => error
            raise if cri_unavailable?(error)

            # A container the runtime no longer knows (the host
            # rebooted, or recovery released its sandbox) has nothing
            # left to stop.  Waiting out the grace period for it kept
            # a restarted node NotReady for the sum of its Pods'
            # grace periods; kubelet reports such a container
            # terminated (137) and moves on.
            if lost_container_error?(error)
              (@stop_details ||= {})[container_id] = {killed: true}
              return true
            end

            false
          end
          running = if result.is_a?(Hash)
                      Helpers.key(result, "running", false)
                    elsif result == false
                      true
                    end
          if running
            @sleeper.call(grace) if grace.positive?
            (@stop_details ||= {})[container_id] = {killed: true}
            kill_result = kill_container(container_id)
            return true if kill_result != false && !runtime_supports?(:container_status)

            result = invoke(@runtime, :stop_container, container_id, timeout: grace)
            # Minimal injected runtimes often model SIGKILL as the terminal
            # confirmation and intentionally keep stop_container returning
            # `running`. Native runtimes expose container_status/wait and take
            # the stricter path below.
            return true if result == false && kill_result != false && !runtime_supports?(:container_status)
          end
          return false if result.nil? || result == false

          confirm_stopped(container_id, result)
        end

        def cri_unavailable?(error)
          defined?(Runtime::CRI::Client::Error) && error.is_a?(Runtime::CRI::Client::Error) &&
            error.code == Runtime::CRI::Client::UNAVAILABLE
        end

        def confirm_stopped(container_id, result)
          if result.is_a?(Hash)
            running = Helpers.key(result, "running", nil)
            return false if running == true

            state = Helpers.key(result, "state", nil)
            return false if %w[running created].include?(state.to_s)

            exit_code = Helpers.key(result, "exitCode", Helpers.key(result, "exit_code", :unknown))
            return false if exit_code.nil?
          end
          if runtime_supports?(:container_status)
            status = invoke(@runtime, :container_status, container_id)
            status = status.to_h if hash_convertible?(status)
            return false if status.is_a?(Hash) && %w[running created].include?(Helpers.key(status, "state", "").to_s)
          end
          true
        rescue StandardError
          # Native stop_container returns only after its process wait/pidfd
          # confirmation. Generic adapters may not expose container_status, so
          # retain their successful stop result as the confirmation boundary.
          result == true
        end

        def kill_container(container_id)
          if runtime_supports?(:kill_container)
            invoke(@runtime, :kill_container, container_id, signal: "KILL")
          elsif runtime_supports?(:signal)
            send_signal(container_id, "KILL")
          end
        end

        def send_signal(container_id, signal)
          @runtime.signal(container_id, signal)
        rescue ArgumentError => error
          raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

          @runtime.signal(container_id, signal: signal)
        end
      end
    end
  end
end
