# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Container lifecycle hooks: postStart and preStop handlers (exec,
      # httpGet, tcpSocket, sleep) run through the runtime.
      module Hooks
        private

        def run_post_start_hook(entry, record)
          handler = Helpers.key(Helpers.key(entry[:spec], "lifecycle", {}), "postStart", nil)
          return if handler.nil?

          event(record, "postStart", name: entry[:name])
          execute_hook(entry[:id], handler, record: record)
        end

        # executePreStopHook runs within the grace period: a hook still running
        # when it ends is abandoned and the container killed.
        def run_pre_stop_hooks(_pod, record, budget: nil)
          return if budget && !budget.positive?

          deadline = budget && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + budget)
          record[:containers].reverse_each do |entry|
            handler = Helpers.key(Helpers.key(entry[:spec], "lifecycle", {}), "preStop", nil)
            next if handler.nil? || !entry[:started]

            remaining = deadline ? deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC) : HOOK_TIMEOUT_SECONDS
            break unless remaining.positive?

            event(record, "preStop", name: entry[:name])
            execute_hook(entry[:id], handler, timeout: deadline ? remaining : HOOK_TIMEOUT_SECONDS, record: record,
                                              grace_bounded: !deadline.nil?)
          end
        end

        HOOK_TIMEOUT_SECONDS = 30.0

        def wait_for_exec(result, timeout:)
          status = if value_reports?(result, :fetch) && value_reports?(result, :key?) && result.key?(:status)
                     result[:status]
                   elsif value_reports?(result, :status)
                     result.status
                   end
          drain = Thread.new do
            %i[stdout stderr].each do |name|
              stream = value_reports?(result, :key?) && result.key?(name) ? result[name] : nil
              next unless value_reports?(stream, :read)

              # Drained so the hook's process is never blocked on a full pipe;
              # a stream that closes under the reader has nothing left to drain.
              best_effort { loop { break if stream.read(65_536).nil? } }
            end
          end
          if value_reports?(status, :pop)
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout)
            loop do
              value = status.pop(true)
              return value
            rescue ThreadError
              break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

              sleep 0.05
            end
          else
            drain.join(timeout)
          end
          nil
        ensure
          drain&.join(1)
        end

        def execute_hook(container_id, handler, timeout: HOOK_TIMEOUT_SECONDS, record: nil, grace_bounded: false)
          definition = Helpers.string_keys(handler)
          if (exec = Helpers.key(definition, "exec", nil))
            command = Array(Helpers.key(exec, "command", []))
            raise LifecycleError, "lifecycle exec command must not be empty" if command.empty?

            # kubelet runs the hook synchronously and only then stops the
            # container; returning with the stream open let the container be
            # killed while the hook's command was still running.
            wait_for_exec(invoke(@runtime, :exec, container_id, command, tty: false), timeout: timeout)
          elsif (http = Helpers.key(definition, "httpGet", nil))
            raise LifecycleError, "runtime does not implement lifecycle HTTP hook" unless runtime_supports?(:http_get)

            # A lifecycle hook is not a probe: it gets the hook timeout, not the
            # one-second default a readiness check is happy with.  A postStart or
            # preStop hook calls another Pod over the network, and under load one
            # second is not enough to reach it -- and a hook that "fails" on a
            # timeout is a hook the workload never received.
            http_hook(container_id, Helpers.string_keys(http), [timeout, HOOK_TIMEOUT_SECONDS].min, record)
          elsif (tcp = Helpers.key(definition, "tcpSocket", nil))
            raise LifecycleError, "runtime does not implement lifecycle TCP hook" unless runtime_supports?(:tcp_socket)

            invoke(@runtime, :tcp_socket, container_id, tcp, timeout: [timeout, HOOK_TIMEOUT_SECONDS].min)
          elsif (sleep_action = Helpers.key(definition, "sleep", nil))
            wanted = Integer(Helpers.key(sleep_action, "seconds", 0) || 0)
            seconds = [wanted, timeout].min
            @sleeper.call(seconds) if seconds.positive?
            # runSleepHandler: the grace period ended first.
            if grace_bounded && wanted > timeout
              event(record, "hook.sleep_terminated") if record
              raise LifecycleError, "container terminated before sleep hook finished"
            end
          else
            raise LifecycleError, "lifecycle hook must define exec, httpGet, tcpSocket, or sleep"
          end
        end

        # runHTTPHandler: an HTTPS hook answered in plain HTTP is retried over
        # HTTP without the Authorization header, and the fallback reported
        # (LifecycleHTTPFallback, kubelet_lifecycle_handler_http_fallbacks_total).
        HTTP_RESPONSE_TO_HTTPS = /server gave HTTP response to HTTPS client|wrong version number|packet length too long|record layer failure/i

        def http_hook(container_id, http, timeout, record)
          invoke(@runtime, :http_get, container_id, http, timeout: timeout)
        rescue StandardError => error
          raise unless Helpers.key(http, "scheme", "").to_s.casecmp("HTTPS").zero? && error.message.match?(HTTP_RESPONSE_TO_HTTPS)

          plain = http.merge("scheme" => "HTTP")
          plain["httpHeaders"] = Array(http["httpHeaders"]).reject do |header|
            header.is_a?(Hash) && header["name"].to_s.casecmp("Authorization").zero?
          end
          result = invoke(@runtime, :http_get, container_id, plain, timeout: timeout)
          host = Helpers.join_host_port(Helpers.key(http, "host", nil) || record_pod_ip(record) || "127.0.0.1", Helpers.key(http, "port", 80))
          event(record, "hook.http_fallback", host: host) if record
          result
        end

        def record_pod_ip(record)
          record ? pod_ips(record).first : nil
        end
      end
    end
  end
end
