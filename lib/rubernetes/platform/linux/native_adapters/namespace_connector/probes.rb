# frozen_string_literal: true

require "net/http"
require_relative "../../../../http_probe_headers"
require_relative "../../../../http_probe_response"
require_relative "../../../../grpc_health_probe"

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Probes run from inside the Pod's network namespace.
        class NamespaceConnector
          HTTP_REDIRECTS = HTTPProbeResponse::REDIRECT_CODES
          HTTP_REDIRECT_LIMIT = HTTPProbeResponse::REDIRECT_LIMIT
          HTTP_BODY_LIMIT = HTTPProbeResponse::BODY_LIMIT
          HTTP_RESPONSE_LIMIT = 1024 * 1024

          # Net::HTTPResponse parses the framing while the underlying IO
          # limits header and body reads from an untrusted probe endpoint.
          class ProbeSocket
            def initialize(socket, deadline)
              @socket = socket
              @deadline = deadline
              @remaining_bytes = HTTP_RESPONSE_LIMIT
            end

            def read_nonblock(length, ...)
              NamespaceConnector.probe_http_remaining(@deadline)
              raise EffectError, "HTTP probe response is too large" if @remaining_bytes.zero?

              chunk = @socket.read_nonblock([length, @remaining_bytes].min, ...)
              @remaining_bytes -= chunk.bytesize if chunk.is_a?(String)
              chunk
            end

            def write_nonblock(...)
              NamespaceConnector.probe_http_remaining(@deadline)
              @socket.write_nonblock(...)
            end

            # Net::BufferedIO waits through to_io. Recheck the shared deadline
            # before every wait, even when a partial response arrived earlier.
            def to_io = self

            def wait_readable(timeout)
              @socket.to_io.wait_readable([timeout, NamespaceConnector.probe_http_remaining(@deadline)].min)
            end

            def wait_writable(timeout)
              @socket.to_io.wait_writable([timeout, NamespaceConnector.probe_http_remaining(@deadline)].min)
            end

            def closed? = @socket.closed?
          end

          # HTTP GET inside the Pod network namespace. Buffered socket IO
          # enforces timeouts without a Timeout thread in the helper child.
          def http_get(sandbox:, container:, definition:, timeout: 1.0, **_options)
            raise EffectError, "HTTP probe requires a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            host = String(definition["host"] || "127.0.0.1")
            port = Integer(definition["port"] || 80)
            path = String(definition["path"] || "/")
            path = "/#{path}" unless path.start_with?("/")
            headers = HTTPProbeHeaders.from_action(definition["httpHeaders"])
            # v1.HTTPGetAction.scheme selects HTTP or HTTPS.  kubelet's HTTPS
            # prober does not verify the server certificate -- the endpoint is
            # the container's own, and a Pod that serves its readiness over
            # TLS (every admission webhook does) is never ready without this.
            tls = String(definition["scheme"] || definition[:scheme]).casecmp("HTTPS").zero?
            deadline = Float(timeout)
            @namespace_adapter.within_namespaces(handle, only: [:network], timeout: deadline + 5.0) do
              NamespaceConnector.blocking_http_get(host, port, path, headers, deadline, tls: tls)
            end.freeze
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
            GRPCHealthProbe.check(host_port(host, port), service, timeout)
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
            scheme = tls ? "https" : "http"
            uri = URI("#{scheme}://#{host_port(host, port)}#{path}")
            origin = uri.hostname
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            HTTP_REDIRECT_LIMIT.times do |hop|
              response = probe_http_exchange(uri, headers, deadline)
              target = response.delete("location")
              return response unless target && !target.empty? && HTTP_REDIRECTS.include?(response.fetch("status"))

              uri = uri.merge(target)
              return response unless uri.hostname == origin

              headers = HTTPProbeHeaders.redirected(headers, target)
              raise EffectError, "stopped after #{HTTP_REDIRECT_LIMIT} redirects" if hop + 1 == HTTP_REDIRECT_LIMIT
              raise EffectError, "HTTP probe redirect requires HTTP or HTTPS" unless %w[http https].include?(uri.scheme)
            end
          end

          def self.probe_http_exchange(uri, headers, deadline)
            host = uri.hostname
            transport = connect_probe_http(host, uri.port, deadline)
            socket = uri.scheme == "https" ? start_probe_tls(transport, host, deadline) : transport
            fields = HTTPProbeHeaders.for_request(headers, host_port(host, uri.port))
            fields["Connection"] ||= ["close"]
            request = ["GET #{uri.request_uri} HTTP/1.1"]
            fields.each { |name, values| values.each { |value| request << "#{name}: #{value}" } }
            remaining = probe_http_remaining(deadline)
            io = Net::BufferedIO.new(ProbeSocket.new(socket, deadline), read_timeout: remaining, write_timeout: remaining)
            io.write(request.join("\r\n") + "\r\n\r\n")
            response = Net::HTTPResponse.read_new(io)
            response = Net::HTTPResponse.read_new(io) while response.is_a?(Net::HTTPInformation) && response.code != "101"
            probe_http_remaining(deadline)
            probe_http_result(response, io, deadline)
          ensure
            socket&.close
            transport&.close unless transport&.closed?
          end

          def self.connect_probe_http(host, port, deadline)
            addresses = Addrinfo.getaddrinfo(host, port, nil, :STREAM, timeout: probe_http_remaining(deadline))
            last_error = nil
            addresses.each do |address|
              return address.connect(timeout: probe_http_remaining(deadline))
            rescue SystemCallError => error
              last_error = error
            end
            raise EffectError, "HTTP probe connect failed: #{last_error&.message || "no address"}"
          end

          def self.probe_http_result(response, io, deadline)
            HTTPProbeResponse.capture do |consume|
              response.reading_body(io, true) do
                consume.call(response) { io.read_timeout = probe_http_remaining(deadline) }
              end
            end
          end

          def self.probe_http_remaining(deadline)
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise EffectError, "HTTP probe timed out" unless remaining.positive?

            remaining
          end

          # kubelet's HTTPS prober sets InsecureSkipVerify: the probe targets
          # the container's own endpoint, whose certificate is routinely
          # self-signed and issued for a name the probe does not use.
          def self.start_probe_tls(transport, host, deadline)
            context = OpenSSL::SSL::SSLContext.new
            context.verify_mode = OpenSSL::SSL::VERIFY_NONE
            ssl = OpenSSL::SSL::SSLSocket.new(transport, context)
            # SNI carries a name, never an IP literal (Go's tls sends none for one).
            name = host.to_s.delete_prefix("[").delete_suffix("]")
            ssl.hostname = name unless name.empty? || name.match?(/\A[\d.]+\z/) || name.include?(":")
            ssl.sync_close = false
            loop do
              remaining = probe_http_remaining(deadline)
              case ssl.connect_nonblock(exception: false)
              when :wait_readable then transport.wait_readable(remaining)
              when :wait_writable then transport.wait_writable(remaining)
              else return ssl
              end
            end
          end
        end
      end
    end
  end
end
