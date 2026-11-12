# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Reaching into a running container from outside: exec, attach,
      # port-forward, probes, sysctls and logs.  Each goes through the
      # connector that owns namespace entry (or the supervisor's own streams)
      # and fails as a missing capability when none is wired -- never through
      # a host-side fallback.
      module Connectors
        # Execute a new process only through an adapter that explicitly owns the
        # namespace/cgroup entry operation.  The Native backend cannot safely
        # infer that operation from a host PID, so an absent adapter is a hard
        # capability failure rather than a host-side fallback.
        def exec(value, command, tty: false, **options)
          sandbox, container = find_container(value)
          raise InvalidState, "exec requires a running container" unless container.state == :running

          command = validate_command!(command)
          adapter = @adapters[:exec]
          raise CapabilityError, "exec adapter is not configured" unless adapter

          result = invoke(adapter, :exec, sandbox: sandbox, container: container, command: command, tty: tty, **options)
          validate_duplex_result!(result, operation: :exec, options: options)
          result
        end

        # Attach exposes only the already-running process streams.  This default
        # is valid for a process supervisor that returned real streams; pure
        # fake processes have no stream and therefore fail closed.
        def attach(value, tty: false, **options)
          sandbox, container = find_container(value)
          raise InvalidState, "attach requires a running container" unless container.state == :running

          result = if (adapter = @adapters[:attach])
                     invoke(adapter, :attach, sandbox: sandbox, container: container, tty: tty, **options)
                   else
                     attach_process_streams(container, tty: tty, **options)
                   end
          validate_duplex_result!(result, operation: :attach, options: options)
          result
        end

        # Port-forward requires a connector because the runtime owns the target
        # network namespace.  It never falls back to a host socket.
        def port_forward(value, ports, timeout: 30.0, stream: nil, **)
          sandbox, container = find_container(value)
          raise InvalidState, "port-forward requires a running container" unless container.state == :running

          normalized_ports = normalize_ports(ports)
          timeout = normalize_timeout(timeout)
          adapter = @adapters[:port_forward]
          raise CapabilityError, "port-forward connector is not configured" unless adapter

          result = invoke(adapter, :port_forward, sandbox: sandbox, container: container,
                                                  ports: normalized_ports, timeout: timeout, stream: stream, **)
          validate_duplex_result!(result, operation: :port_forward, options: {stdin: true, stdout: true})
          result
        end

        # spec.securityContext.sysctls: written inside the sandbox's network
        # and IPC namespaces by the connector, which owns namespace entry.
        def apply_sysctls(value, sysctls)
          sandbox = sandbox(value)
          entries = Array(sysctls).map { |entry| normalize_hash(entry) }.reject { |entry| entry["name"].to_s.empty? }
          return [] if entries.empty?

          adapter = @adapters[:sysctl] || @adapters[:http_probe]
          raise CapabilityError, "sysctl adapter is not configured" unless connector_performs?(adapter, :apply_sysctls)

          invoke(adapter, :apply_sysctls, sandbox: sandbox, sysctls: entries)
        end

        # Probe effects are explicit runtime capabilities.  ProbeManager may use
        # these methods when no external client was injected, but an unavailable
        # connector remains an observable failure.
        def http_get(value, definition, timeout: 1.0, **)
          sandbox, container = find_container(value)
          raise InvalidState, "HTTP probe requires a running container" unless container.state == :running

          adapter = @adapters[:http_probe]
          raise CapabilityError, "HTTP probe connector is not configured" unless adapter

          invoke(adapter, :http_get, sandbox: sandbox, container: container,
                                     definition: normalize_hash(definition), timeout: normalize_timeout(timeout), **)
        end

        # gRPC health probes join the Pod's network namespace through the same
        # connector as HTTP probes; the agent's own namespace cannot reach a
        # Pod's loopback (or, on this host, its IP at all).
        def grpc_check(value, definition, timeout: 1.0, **)
          sandbox, container = find_container(value)
          raise InvalidState, "gRPC probe requires a running container" unless container.state == :running

          adapter = @adapters[:http_probe]
          raise CapabilityError, "gRPC probe connector is not configured" unless connector_performs?(adapter, :grpc_check)

          invoke(adapter, :grpc_check, sandbox: sandbox, container: container,
                                       definition: normalize_hash(definition), timeout: normalize_timeout(timeout), **)
        end

        def tcp_socket(value, definition, timeout: 1.0, **)
          sandbox, container = find_container(value)
          raise InvalidState, "TCP probe requires a running container" unless container.state == :running

          adapter = @adapters[:tcp_probe]
          raise CapabilityError, "TCP probe connector is not configured" unless adapter

          invoke(adapter, :tcp_socket, sandbox: sandbox, container: container,
                                       definition: normalize_hash(definition), timeout: normalize_timeout(timeout), **)
        end

        # A container's log is BOTH streams: the Pod log API has no way to ask
        # for only one, and kubelet returns whatever the container wrote to
        # either (the CRI tags each line with its stream and ReadLogs returns
        # them all).  Serving stdout alone hid every diagnostic a workload
        # writes to stderr.
        def logs(value, follow: false, since: nil, tail: nil, stream: :all, timestamps: false)
          sandbox, container = find_container(value)
          # A container that ran and exited (a restart being backed off, the
          # querier of the DNS specs whose loop has finished) keeps its log with
          # the supervisor under its process id even after the handle was
          # released; kubelet serves that log until the container is removed.
          handle = container.process || (container.state == :stopped ? "process-#{sandbox.id}-#{container.id}" : nil)
          raise InvalidState, "logs require a started container" unless handle

          @process_supervisor.logs(handle, follow: follow, since: since, tail: tail, stream: stream,
                                           timestamps: timestamps)
        end

        private

        # Attach joins a running container's streams the way the CRI shim does:
        # output is the container's log from the moment of attaching (the
        # supervisor's pipe is owned by the logger; a second reader on it would
        # steal bytes from `kubectl logs`), input is the process's stdin pipe.
        def attach_process_streams(container, tty:, stdin: false, stdout: true, stderr: false, **_options)
          process = container.process
          raise CapabilityError, "container process does not expose attach streams" unless process

          input = stream_requested?(stdin) ? borrow_process_stream(process.stdin) : nil
          output = stream_requested?(stdout) ? follow_log_stream(process, :stdout) : nil
          error = !tty && stream_requested?(stderr) ? follow_log_stream(process, :stderr) : nil
          raise CapabilityError, "container process stdin stream is unavailable" if stream_requested?(stdin) && input.nil?
          raise CapabilityError, "container process stdout stream is unavailable" if stream_requested?(stdout) && output.nil?
          raise CapabilityError, "container process stderr stream is unavailable" if stream_requested?(stderr) && !tty && error.nil?

          {stdin: input, stdout: output, stderr: error}.freeze
        end

        # nil when the process's log cannot be followed (its handle was closed
        # under the attach, the log file is gone): the caller reports the
        # stream as unavailable.
        def follow_log_stream(process, stream)
          # Only new output: the log so far belongs to `logs`, not `attach`.
          existing = @process_supervisor.logs(process, follow: false, stream: stream)
          since = existing.is_a?(String) ? existing.bytesize : nil
          @process_supervisor.logs(process, follow: true, since: since, stream: stream)
        rescue *PROCESS_ERRORS
          nil
        end

        def borrow_process_stream(stream)
          stream && BorrowedProcessStream.new(stream)
        end

        def validate_duplex_result!(result, operation:, options: {})
          stdin_required = stream_requested?(options[:stdin])
          stdout_required = stream_requested?(options.fetch(:stdout, true))
          stderr_required = stream_requested?(options[:stderr]) && !options[:tty]
          return result if byte_source?(result) && byte_sink?(result)

          if mapping?(result)
            value = result.to_h
            input = value[:stdin] || value["stdin"] || value[:input] || value["input"]
            output = value[:stdout] || value["stdout"] || value[:output] || value["output"]
            error = value[:stderr] || value["stderr"] || value[:error] || value["error"]
            raise CapabilityError, "#{operation} adapter returned no stdin stream" if stdin_required && input.nil?
            raise CapabilityError, "#{operation} adapter returned no stdout stream" if stdout_required && output.nil?
            raise CapabilityError, "#{operation} adapter returned no stderr stream" if stderr_required && error.nil?

            return result
          end

          return result if stdout_required && result.is_a?(String)
          return result if !stdin_required && !stdout_required && !stderr_required && !result.nil?

          raise CapabilityError, "#{operation} adapter returned no usable byte stream"
        end

        def stream_requested?(value)
          value == true || byte_source?(value) || byte_sink?(value)
        end

        def normalize_ports(value)
          values = value.is_a?(Array) ? value : [value]
          raise ConfigurationError, "port-forward requires at least one port" if values.empty?
          raise ConfigurationError, "port-forward accepts at most 128 ports" if values.length > 128

          normalized = values.flat_map do |port|
            if port.is_a?(Range)
              first = normalize_port(port.begin)
              last = normalize_port(port.end) - (port.exclude_end? ? 1 : 0)
              raise ConfigurationError, "port-forward range must be ascending" if last < first
              raise ConfigurationError, "port-forward range is too large" if last - first + 1 > 128

              (first..last).to_a
            else
              [normalize_port(port)]
            end
          end
          raise ConfigurationError, "port-forward port list must not be empty" if normalized.empty?

          normalized.freeze
        end

        def normalize_port(value)
          value = value.to_s.split(":", 2).last if value.is_a?(String) && value.include?(":")
          port = Integer(value)
          raise ConfigurationError, "port-forward ports must be between 1 and 65535" unless port.between?(1, 65_535)

          port
        rescue ArgumentError, TypeError => error
          raise ConfigurationError, "port-forward port must be an integer: #{error.message}"
        end

        def normalize_timeout(value)
          timeout = Float(value)
          raise ConfigurationError, "timeout must be non-negative" if timeout.negative?

          timeout
        rescue ArgumentError, TypeError => error
          raise ConfigurationError, "timeout must be a non-negative number: #{error.message}"
        end
      end
    end
  end
end
