# frozen_string_literal: true

require "net/http"
require "openssl"
require "socket"
require "timeout"
require "uri"
require_relative "../http_probe_headers"
require_relative "../http_probe_response"
require_relative "../grpc_health_probe"
require_relative "status"

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
        MAX_REDIRECTS = HTTPProbeResponse::REDIRECT_LIMIT
        MAX_BODY_BYTES = HTTPProbeResponse::BODY_LIMIT
        USER_AGENT = HTTPProbeHeaders::USER_AGENT

        # Net::HTTP normally joins repeated values with a comma. A kubelet
        # probe writes each value on its own line.
        class Get < Net::HTTP::Get
          def each_capitalized
            return enum_for(__method__) unless block_given?

            super { |name, _joined| get_fields(name).each { |value| yield name, value } }
          end
        end

        def get(uri, headers: {}, timeout: 1.0, **_options)
          target = uri.is_a?(URI) ? uri : URI(uri.to_s)
          MAX_REDIRECTS.times do
            result = request(target, headers, timeout)
            location = result.delete("location")
            return result unless HTTPProbeResponse::REDIRECT_CODES.include?(result.fetch("status")) && !location.to_s.empty?

            redirected = target.merge(location)
            return result unless redirected.hostname == target.hostname

            headers = HTTPProbeHeaders.redirected(headers, location)
            target = redirected
          end
          {"status" => 0, "success" => false, "message" => "stopped after #{MAX_REDIRECTS} redirects"}
        rescue Timeout::Error
          {"status" => 0, "success" => false, "message" => "HTTP probe timed out after #{timeout}s"}
        rescue SystemCallError, IOError, OpenSSL::SSL::SSLError, SocketError => error
          {"status" => 0, "success" => false, "message" => "HTTP probe failed: #{error.message}"}
        end

        private

        def request(uri, headers, timeout)
          http = Net::HTTP.new(uri.hostname, uri.port, nil)
          http.open_timeout = timeout
          http.read_timeout = timeout
          http.write_timeout = timeout if http.respond_to?(:write_timeout=)
          if uri.scheme == "https"
            http.use_ssl = true
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          end
          get = Get.new(uri.request_uri.empty? ? "/" : uri.request_uri)
          get.delete("User-Agent")
          get.delete("Accept")
          get.delete("Accept-Encoding")
          get["Connection"] = "close"
          authority = Helpers.join_host_port(uri.hostname, uri.port)
          HTTPProbeHeaders.for_request(headers, authority).each { |name, values| get[name] = values }
          http.ignore_eof = false
          http.start { |session| HTTPProbeResponse.capture { |consume| session.request(get, &consume) } }
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
          GRPCHealthProbe.check(Helpers.join_host_port(host, port), service, timeout)
        end
      end
    end
  end
end
