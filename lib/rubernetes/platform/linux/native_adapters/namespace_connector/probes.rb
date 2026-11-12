# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Probes run from inside the Pod's network namespace.
        class NamespaceConnector
          # HTTP GET inside the Pod network namespace.  The request is a plain
          # HTTP/1.1 exchange on a blocking socket with an IO.select deadline;
          # no Timeout thread is created in the namespace helper child.
          def http_get(sandbox:, container:, definition:, timeout: 1.0, **_options)
            raise EffectError, "HTTP probe requires a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            host = String(definition["host"] || "127.0.0.1")
            port = Integer(definition["port"] || 80)
            path = String(definition["path"] || "/")
            path = "/#{path}" unless path.start_with?("/")
            headers = Array(definition["httpHeaders"]).each_with_object({}) do |header, result|
              item = header.to_h.transform_keys(&:to_s)
              result[String(item["name"])] = String(item["value"]) unless item["name"].to_s.empty?
            end
            # v1.HTTPGetAction.scheme selects HTTP or HTTPS.  kubelet's HTTPS
            # prober does not verify the server certificate -- the endpoint is
            # the container's own, and a Pod that serves its readiness over
            # TLS (every admission webhook does) is never ready without this.
            tls = String(definition["scheme"] || definition[:scheme]).casecmp("HTTPS").zero?
            deadline = Float(timeout)
            result = @namespace_adapter.within_namespaces(handle, only: [:network], timeout: deadline + 5.0) do
              NamespaceConnector.blocking_http_get(host, port, path, headers, deadline, tls: tls)
            end
            {"status" => Integer(result.fetch("status")), "success" => Integer(result.fetch("status")).between?(200, 399),
             "message" => "HTTP #{result.fetch("status")}", "body_bytes" => Integer(result.fetch("body_bytes"))}.freeze
          end

          def grpc_check(sandbox:, container:, definition:, timeout: 1.0, **_options)
            raise EffectError, "gRPC probe requires a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            host = String(definition["host"] || "127.0.0.1")
            port = Integer(definition["port"] || 0)
            raise EffectError, "gRPC probe port is required" unless port.positive?

            service = String(definition["service"] || "")
            deadline = Float(timeout)
            # The helper is a fresh fork, so the grpc gem is loaded and
            # initialised there and never in the agent itself.
            result = @namespace_adapter.within_namespaces(handle, only: [:network], timeout: deadline + 5.0) do
              NamespaceConnector.blocking_grpc_check(host, port, service, deadline)
            end
            {"success" => result.fetch("success") == true, "message" => String(result.fetch("message"))}.freeze
          end

          # net.JoinHostPort: an IPv6 literal is bracketed.
          def self.host_port(host, port)
            host = host.to_s
            host = "[#{host}]" if host.include?(":") && !host.start_with?("[")
            "#{host}:#{port}"
          end

          def self.blocking_grpc_check(host, port, service, timeout)
            require "grpc"
            require "grpc/health/v1/health_services_pb"
            stub = ::Grpc::Health::V1::Health::Stub.new(host_port(host, port), :this_channel_is_insecure, timeout: timeout)
            request = ::Grpc::Health::V1::HealthCheckRequest.new(service: service.to_s)
            response = stub.check(request, deadline: Time.now + timeout)
            status = response.status.to_s
            {"success" => status == "SERVING", "message" => "gRPC health check status: #{status}"}
          rescue ::GRPC::DeadlineExceeded
            {"success" => false, "message" => "gRPC probe timed out after #{timeout}s"}
          rescue ::GRPC::BadStatus => error
            {"success" => false, "message" => "gRPC probe failed: #{error.message}"}
          rescue LoadError => error
            {"success" => false, "message" => "gRPC probe unavailable: #{error.message}"}
          end

          def tcp_socket(sandbox:, container:, definition:, timeout: 1.0, **_options)
            raise EffectError, "TCP probe requires a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            host = String(definition["host"] || "127.0.0.1")
            port = Integer(definition["port"])
            deadline = Float(timeout)
            result = @namespace_adapter.within_namespaces(handle, only: [:network], timeout: deadline + 5.0) do
              NamespaceConnector.blocking_tcp_connect(host, port, deadline)
            end
            {"success" => result.fetch("connected") == true, "message" => result.fetch("message")}.freeze
          end

          def self.blocking_tcp_connect(host, port, timeout)
            # The socket family follows the address: an IPv6 Pod IP needs an
            # AF_INET6 socket (AF_INET refused every IPv6 probe with EAFNOSUPPORT).
            info = Addrinfo.ip(host.to_s.delete_prefix("[").delete_suffix("]"))
            address = Socket.sockaddr_in(Integer(port), info.ip_address)
            socket = Socket.new(info.afamily, Socket::SOCK_STREAM, 0)
            begin
              socket.connect_nonblock(address, exception: false)
              ready = socket.wait_writable(timeout)
              return {"connected" => false, "message" => "connect timed out"} unless ready

              error = socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int
              return {"connected" => false, "message" => SystemCallError.new(error).message} unless error.zero?

              {"connected" => true, "message" => "connected"}
            ensure
              socket.close
            end
          rescue SystemCallError => error
            {"connected" => false, "message" => error.message}
          end

          def self.blocking_http_get(host, port, path, headers, timeout, tls: false)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            remaining = -> { timeout - (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) }
            connect = blocking_tcp_connect(host, port, timeout)
            raise EffectError, "HTTP probe connect failed: #{connect.fetch("message")}" unless connect.fetch("connected")

            transport = TCPSocket.new(host.to_s.delete_prefix("[").delete_suffix("]"), Integer(port))
            socket = tls ? start_probe_tls(transport, host) : transport
            begin
              request = ["GET #{path} HTTP/1.1", "Host: #{host_port(host, port)}", "User-Agent: rubernetes-probe/1", "Connection: close"]
              headers.each { |name, value| request << "#{name}: #{value}" }
              socket.write(request.join("\r\n") + "\r\n\r\n")
              buffer = "".b
              loop do
                wait = remaining.call
                raise EffectError, "HTTP probe timed out" if wait <= 0
                break unless socket.wait_readable(wait)

                begin
                  chunk = socket.read_nonblock(16 * 1024, exception: false)
                rescue EOFError
                  break
                end
                break if chunk.nil?
                next if chunk == :wait_readable

                buffer << chunk
                break if buffer.bytesize > 1024 * 1024
                break if buffer.include?("\r\n\r\n".b) && buffer.start_with?("HTTP/".b) && buffer.bytesize >= 12
              end
              status = buffer[%r{\AHTTP/1\.[01] (\d{3})}, 1]
              raise EffectError, "HTTP probe received no status line" unless status

              {"status" => Integer(status), "body_bytes" => buffer.bytesize}
            ensure
              socket.close
              transport.close unless transport.closed?
            end
          end

          # kubelet's HTTPS prober sets InsecureSkipVerify: the probe targets
          # the container's own endpoint, whose certificate is routinely
          # self-signed and issued for a name the probe does not use.
          def self.start_probe_tls(transport, host)
            context = OpenSSL::SSL::SSLContext.new
            context.verify_mode = OpenSSL::SSL::VERIFY_NONE
            ssl = OpenSSL::SSL::SSLSocket.new(transport, context)
            # SNI carries a name, never an IP literal (Go's tls sends none for one).
            name = host.to_s.delete_prefix("[").delete_suffix("]")
            ssl.hostname = name unless name.empty? || name.match?(/\A[\d.]+\z/) || name.include?(":")
            ssl.sync_close = false
            ssl.connect
            ssl
          end
        end
      end
    end
  end
end
