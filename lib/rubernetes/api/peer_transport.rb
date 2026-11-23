# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "uri"
require_relative "../security/egress"
require_relative "request"
require_relative "response"

module Rubernetes
  module API
    # Peer TLS uses the same DNS SAN on all API servers, even when dialing
    # their individually advertised IP addresses.
    class PeerTransport
      SERVER_NAME = "kubernetes.default.svc"
      PROXIED_HEADER = "x-kubernetes-peer-proxied"
      DISCOVERY_ACCEPT = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList"
      DISCOVERY_USER = {"username" => "system:apiserver", "uid" => "system:apiserver", "groups" => ["system:authenticated"]}.freeze
      TIMEOUT = 5
      REQUEST_TIMEOUT = 60
      # Forward Kubernetes representation, concurrency and upgrade headers.
      # Request-header authentication may be customized at the destination,
      # so arbitrary caller headers must not accompany our proxy certificate.
      REQUEST_HEADERS = %w[accept content-type content-encoding if-match if-none-match if-modified-since
                           if-unmodified-since user-agent audit-id upgrade sec-websocket-key sec-websocket-version
                           sec-websocket-protocol sec-websocket-extensions x-stream-protocol-version].freeze
      HOP_HEADERS = %w[connection content-length keep-alive proxy-authenticate proxy-authorization
                       te trailer transfer-encoding upgrade].freeze
      ERRORS = [IOError, EOFError, SystemCallError, SocketError, Net::ProtocolError, Net::OpenTimeout,
                Net::ReadTimeout, Net::WriteTimeout, OpenSSL::SSL::SSLError, Security::Egress::DialError].freeze

      def initialize(ca_file:, certificate:, key:)
        @store = OpenSSL::X509::Store.new
        @store.add_file(ca_file)
        @certificate = certificate
        @key = key
      end

      def discovery(endpoint, path)
        request = Request.new(path: path, headers: {"accept" => "#{DISCOVERY_ACCEPT};profile=nopeer,#{DISCOVERY_ACCEPT},application/json"})
        response = forward(endpoint, request, DISCOVERY_USER, timeout: TIMEOUT)
        yield response.status if block_given?
        raise IOError, "peer discovery returned HTTP #{response.status}" unless response.status == 200

        document = JSON.parse(response.body)
        unless document.is_a?(Hash) && document["kind"] == "APIGroupDiscoveryList" &&
               document["apiVersion"] == "apidiscovery.k8s.io/v2" && document["items"].is_a?(Array)
          raise IOError, "peer discovery did not return a v2 APIGroupDiscoveryList"
        end

        document.fetch("items")
      end

      def forward(endpoint, request, identity, timeout: REQUEST_TIMEOUT)
        host = endpoint.host
        port = endpoint.port
        server = URI::HTTPS.build(host: SERVER_NAME, port: port)
        http = Security::Egress.http(server, "controlplane", ipaddr: host)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.verify_hostname = true
        http.cert_store = @store
        http.cert = @certificate
        http.key = @key
        http.open_timeout = TIMEOUT
        http.read_timeout = timeout
        http.write_timeout = TIMEOUT
        http.max_retries = 0
        headers = proxy_headers(request, identity)
        target = request.raw_path
        raise ArgumentError, "invalid peer proxy request target" unless target.match?(%r{\A/[^\x00-\x20\x7f]*\z})

        query = URI.encode_www_form(request.query)
        target = "#{target}?#{query}" unless query.empty?
        body = request.body
        body = JSON.generate(body) unless body.nil? || body.is_a?(String)
        body = nil if body == ""
        return upgrade(endpoint, request, target, headers, body, timeout: timeout) if upgrade_protocol(request)

        outbound = Net::HTTPGenericRequest.new(request.method, !body.nil?, request.method != "HEAD", target, {"accept-encoding" => "identity"})
          .extend(Request::RepeatedHeaderLines)
        headers.each { |name, values| values.each { |value| outbound.add_field(name, value) } }
        unless body.nil?
          outbound["content-type"] ||= "application/json"
          outbound.body = body
        end
        if stream_request?(request)
          stream = Stream.new(http, outbound)
          status, response_headers = stream.head
          return Response.new(status: status, headers: response_headers, body: stream, stream: true, unbounded: true)
        end

        response = http.request(outbound)
        Response.new(status: response.code.to_i, headers: self.class.response_headers(response.to_hash), body: response.body)
      end

      def self.response_headers(fields)
        connection = Array(fields["connection"]).flat_map { |value| value.downcase.split(/\s*,\s*/) }
        fields.except(*(HOP_HEADERS + connection)).transform_values { |values| Array(values).join(", ") }
      end

      private

      def proxy_headers(request, identity)
        headers = REQUEST_HEADERS.to_h { |name| [name, request.header_values(name)] }
        headers["audit-id"] = [request.request_id] if request.request_id
        headers["x-remote-user"] = [identity.fetch("username")]
        headers["x-remote-uid"] = [identity["uid"]] unless identity["uid"].to_s.empty?
        headers["x-remote-group"] = Array(identity["groups"])
        identity.fetch("extra", {}).each do |key, values|
          escaped = key.to_s.downcase.b.bytes.map do |byte|
            character = byte.chr
            character.match?(/[a-z0-9!\#$&'*+\-.^_`|~]/) ? character : format("%%%02X", byte)
          end.join
          headers["x-remote-extra-#{escaped}"] = Array(values)
        end
        headers[PROXIED_HEADER] = ["true"]
        headers
      end

      def stream_request?(request)
        %w[true 1].include?(request.query_value("watch").to_s) ||
          %w[true 1].include?(request.query_value("follow").to_s)
      end

      def upgrade_protocol(request)
        connection = request.header("connection").to_s.downcase.split(/\s*,\s*/)
        protocol = request.header("upgrade").to_s
        protocol if connection.include?("upgrade") && !protocol.empty?
      end

      # The standard Ruby client owns the HTTP connection after a 101. Open
      # the upgrade separately so the same verified socket carries the
      # negotiated WebSocket or SPDY session in both directions.
      def upgrade(endpoint, request, target, headers, body, timeout:)
        host = endpoint.host
        port = endpoint.port
        context = OpenSSL::SSL::SSLContext.new
        context.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER, verify_hostname: true, cert_store: @store,
                           cert: @certificate, key: @key)
        tcp = Security::Egress.tcp_socket(host, port, "controlplane", connect_timeout: TIMEOUT)
        socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
        socket.hostname = SERVER_NAME
        socket.sync_close = true
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + TIMEOUT
        io_until(deadline, socket) { socket.connect_nonblock(exception: false) }
        lines = ["#{request.method} #{target} HTTP/1.1", "Host: #{SERVER_NAME}:#{port}", "Connection: Upgrade"]
        lines << "Content-Length: #{body.bytesize}" if body
        headers.each do |name, values|
          values.each do |value|
            raise ArgumentError, "invalid peer proxy header" if value.to_s.match?(/[\r\n\x00]/)

            lines << "#{name}: #{value}"
          end
        end
        payload = "#{lines.join("\r\n")}\r\n\r\n#{body}".b
        until payload.empty?
          written = io_until(deadline, socket) { socket.write_nonblock(payload, exception: false) }
          payload = payload.byteslice(written..)
        end
        buffered = Net::BufferedIO.new(socket, read_timeout: timeout)
        response = Net::HTTPResponse.read_new(buffered)
        status = response.code.to_i
        response_headers = self.class.response_headers(response.to_hash)
        if status != 101
          response.reading_body(buffered, request.method != "HEAD") { response.body }
          return Response.new(status: status, headers: response_headers, body: response.body)
        end
        protocol = response["upgrade"]
        raise IOError, "peer negotiated an unexpected upgrade protocol" unless protocol&.casecmp?(upgrade_protocol(request))

        buffered.read_timeout = nil
        response_headers["upgrade"] = protocol
        relay = UpgradeRelay.new(socket, buffered, protocol)
        Response.new(status: 101, headers: response_headers, upgrade: relay)
      ensure
        unless relay
          socket&.close
          tcp&.close unless tcp&.closed?
        end
      end

      def io_until(deadline, socket)
        loop do
          result = yield
          return result unless %i[wait_readable wait_writable].include?(result)

          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          ready = remaining.positive? && (result == :wait_readable ? socket.wait_readable(remaining) : socket.wait_writable(remaining))
          raise Net::OpenTimeout, "peer upgrade timed out" unless ready
        end
      end

      class UpgradeRelay
        Writer = Data.define(:socket) do
          def <<(bytes)
            socket.write(bytes)
            socket.flush
          end
        end

        attr_reader :protocol

        def initialize(socket, buffered, protocol)
          @socket = socket
          @buffered = buffered
          @protocol = protocol
        end

        def call(downstream, _request)
          uploader = Thread.new do
            loop { @socket.write(downstream.readpartial(16_384)) }
          rescue *ERRORS
            close
          end
          @buffered.read_all(Writer.new(downstream))
        rescue *ERRORS
          nil
        ensure
          close
          uploader&.kill
          uploader&.join
        end

        def close
          @socket.close unless @socket.closed?
        rescue IOError, SystemCallError
          nil
        end
      end

      # Bounded backpressure with ownership of the upstream connection.
      # HTTPServer closes the body when the downstream watcher disconnects.
      class Stream
        def initialize(http, request)
          @header = Queue.new
          @chunks = SizedQueue.new(8)
          @thread = Thread.new do
            http.start do |connection|
              connection.request(request) do |response|
                @header << [response.code.to_i, PeerTransport.response_headers(response.to_hash)]
                connection.read_timeout = nil
                response.read_body { |chunk| @chunks << chunk.b unless chunk.empty? }
              end
            end
          rescue StandardError => error
            @header << error if @header.empty?
            @chunks << error unless @chunks.closed?
          ensure
            @chunks.close
          end
        end

        def head
          result = @header.pop
          raise result if result.is_a?(Exception)

          result
        end

        def each
          return enum_for(:each) unless block_given?

          while (chunk = @chunks.pop)
            raise chunk if chunk.is_a?(Exception)

            yield chunk
          end
        ensure
          close
        end

        def close
          @chunks.close
          @thread.kill
          @thread.join
        end
      end
    end
  end
end
