# frozen_string_literal: true

require "net/http"
require "openssl"
require "socket"
require "timeout"
require "uri"

module Rubernetes
  module Node
    # Probe connectors that reach the Pod from the node, the way the kubelet
    # prober does: an HTTP GET, a TCP connect, or a gRPC health check against
    # the Pod IP.  Each returns a Hash ProbeManager#probe_success? understands.
    module ProbeConnectors
      # kubelet: pkg/probe/http — redirects are followed (at most 10), a 3xx
      # to a different host is treated as success with a warning, and the
      # body is capped at 10 KiB for the message.
      class HTTP
        MAX_REDIRECTS = 10
        MAX_BODY_BYTES = 10 * 1024
        USER_AGENT = "kube-probe/1.36"

        def get(uri, headers: {}, timeout: 1.0, **_options)
          target = uri.is_a?(URI) ? uri : URI(uri.to_s)
          redirects = 0
          loop do
            response = request(target, headers, timeout)
            code = response.code.to_i
            if code.between?(300, 399) && response["location"] && redirects < MAX_REDIRECTS
              location = URI.join(target.to_s, response["location"])
              return {"status" => 200, "success" => true, "message" => "probe redirected to #{location}"} if location.host != target.host

              target = location
              redirects += 1
              next
            end
            body = response.body.to_s.byteslice(0, MAX_BODY_BYTES)
            return {"status" => code, "success" => code.between?(200, 399), "message" => "HTTP probe #{code}: #{body}".strip}
          end
        rescue Timeout::Error, Net::OpenTimeout, Net::ReadTimeout
          {"status" => 0, "success" => false, "message" => "HTTP probe timed out after #{timeout}s"}
        rescue SystemCallError, IOError, OpenSSL::SSL::SSLError, SocketError => error
          {"status" => 0, "success" => false, "message" => "HTTP probe failed: #{error.message}"}
        end

        private

        def request(uri, headers, timeout)
          http = Net::HTTP.new(uri.host, uri.port)
          http.open_timeout = timeout
          http.read_timeout = timeout
          http.write_timeout = timeout if http.respond_to?(:write_timeout=)
          if uri.scheme == "https"
            http.use_ssl = true
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          end
          get = Net::HTTP::Get.new(uri.request_uri.empty? ? "/" : uri.request_uri)
          get["User-Agent"] = USER_AGENT
          get["Accept"] = "*/*"
          headers.each { |name, value| get[name.to_s] = value.to_s }
          http.start { |session| session.request(get) }
        end
      end

      class TCP
        def connect(host, port, timeout: 1.0, **_options)
          socket = Socket.tcp(host.to_s, Integer(port), connect_timeout: timeout)
          socket.close
          {"success" => true, "message" => "TCP probe connected to #{Helpers.join_host_port(host, port)}"}
        rescue Errno::ETIMEDOUT, Timeout::Error
          {"success" => false, "message" => "TCP probe timed out after #{timeout}s"}
        rescue SystemCallError, SocketError => error
          {"success" => false, "message" => "TCP probe failed: #{error.message}"}
        end
      end

      # grpc.health.v1.Health/Check, as kubelet's grpc prober (only SERVING
      # counts as success; UNIMPLEMENTED and errors fail the probe).
      class GRPC
        def check(host, port, service: nil, timeout: 1.0, **_options)
          require "grpc"
          require "grpc/health/v1/health_services_pb"
          # probe/grpc: net.JoinHostPort(host, port) as the target.
          stub = ::Grpc::Health::V1::Health::Stub.new(Helpers.join_host_port(host, port), :this_channel_is_insecure, timeout: timeout)
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
      end
    end
  end
end
