# frozen_string_literal: true

# openssl before net/http: the TLS accessors are conditionally defined.
require "openssl"
require_relative "../security/egress"
require "net/http"
require "net/https"
require "socket"
require "timeout"
require "uri"

module Rubernetes
  module API
    # Resolves a Pod's node to the streaming endpoint served by that node's
    # agent, so the API server can proxy logs/exec/attach/port-forward the way
    # kube-apiserver proxies to a kubelet.
    #
    # The address comes from the Node object the agent registered
    # (status.addresses plus status.daemonEndpoints.kubeletEndpoint.port), not
    # from configuration: a node that has not advertised an endpoint is
    # reported unavailable rather than guessed at.
    class NodeEndpointResolver
      DEFAULT_PORT = 10_250

      # The API server's client side of the kubelet API: its client
      # certificate, and the CA the kubelet's serving certificate must chain
      # to (without one the kubelet is not verified, as upstream without
      # --kubelet-certificate-authority).
      module KubeletClientTLS
        module_function

        def load(cert_file:, key_file:, ca_file: nil)
          {cert: OpenSSL::X509::Certificate.new(File.read(cert_file)), key: OpenSSL::PKey.read(File.read(key_file)),
           ca_file: ca_file}
        end

        def configure(http, uri, tls)
          http.use_ssl = uri.scheme == "https"
          return http unless http.use_ssl? && tls

          http.cert = tls[:cert]
          http.key = tls[:key]
          if tls[:ca_file]
            http.ca_file = tls[:ca_file]
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          else
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          end
          http
        end

        def context(tls)
          context = OpenSSL::SSL::SSLContext.new
          context.verify_mode = OpenSSL::SSL::VERIFY_NONE
          return context unless tls

          context.cert = tls[:cert]
          context.key = tls[:key]
          if tls[:ca_file]
            context.ca_file = tls[:ca_file]
            context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          end
          context
        end
      end

      # One node's streaming endpoint.  Exposes the same service surface the
      # subresource bridge expects from an in-process node.
      class Endpoint
        def initialize(base_uri, open_timeout: 5, read_timeout: nil, tls: nil)
          @base_uri = base_uri
          @open_timeout = open_timeout
          @read_timeout = read_timeout
          @tls = tls
        end

        def logs(container_id = nil, follow: false, since: nil, tail: nil, stream: nil,
                 request_id: nil, identity: nil, namespace: nil, pod: nil, timestamps: false, limit_bytes: nil, **_options)
          query = {}
          query["follow"] = "true" if follow
          query["timestamps"] = "true" if timestamps
          query["limitBytes"] = limit_bytes.to_s if limit_bytes && !limit_bytes.to_s.empty?
          query["sinceSeconds"] = since if since && since.to_s.match?(/\A\d+\z/)
          query["sinceTime"] = since if since && !since.to_s.match?(/\A\d+\z/)
          query["tailLines"] = tail if tail
          query["stream"] = stream if stream
          query["requestID"] = request_id if request_id

          path = "/containerLogs/#{escape(namespace || "default")}/#{escape(pod.to_s)}/#{escape(container_id.to_s)}"
          get_stream(path, query, follow: follow)
        end

        HOP_HEADERS = %w[connection upgrade sec-websocket-key sec-websocket-version sec-websocket-protocol
                         sec-websocket-extensions x-stream-protocol-version].freeze
        UpgradeResult = Struct.new(:status, :headers, :body, :socket, keyword_init: true) do
          def upgraded? = status == 101
        end

        # Forwards a connection-upgrade request (WebSocket or SPDY/3.1) to
        # the node and returns the node's answer: on 101 the raw socket, now
        # speaking the upgraded protocol, for the API server to splice to the
        # client; otherwise the status and body to relay.  kube-apiserver's
        # UpgradeAwareHandler does exactly this byte-for-byte proxying.
        def dial_upgrade(method:, path:, query:, headers:)
          uri = URI.join(@base_uri, path)
          uri.query = query unless query.nil? || query.empty?
          socket = open_socket(uri)
          request_lines = ["#{method} #{uri.request_uri} HTTP/1.1", "Host: #{uri.host}:#{uri.port}"]
          headers.each { |name, value| Array(value).each { |item| request_lines << "#{name}: #{item}" } }
          request_lines << "Content-Length: 0" unless headers.keys.any? { |name| name.to_s.casecmp("content-length").zero? }
          socket.write(request_lines.join("\r\n") + "\r\n\r\n")
          socket.flush if socket.respond_to?(:flush)
          status, response_headers, leftover = read_response_head(socket)
          if status == 101
            UpgradeResult.new(status: status, headers: response_headers, body: leftover, socket: socket)
          else
            body = read_body(socket, response_headers, leftover)
            socket.close
            UpgradeResult.new(status: status, headers: response_headers, body: body, socket: nil)
          end
        rescue SystemCallError, IOError, Timeout::Error => error
          socket&.close
          raise Status::ServiceUnavailable.new("node streaming endpoint is unreachable: #{error.message}")
        end

        # Which of the client's headers travel to the node: the upgrade
        # negotiation itself plus a request id for correlation.
        def self.upgrade_headers(request)
          result = {}
          HOP_HEADERS.each do |name|
            values = request.headers.respond_to?(:raw_values) ? request.headers.raw_values(name) : Array(request.header(name))
            result[name] = values unless values.empty?
          end
          request_id = request.header("x-request-id")
          result["x-request-id"] = [request_id] if request_id && !request_id.to_s.empty?
          result
        end

        def exec(container_id, command:, namespace: nil, pod: nil)
          query = command.map { |argument| ["command", argument.to_s] }
          path = "/exec/#{escape(namespace || "default")}/#{escape(pod.to_s)}/#{escape(container_id.to_s)}"
          uri = URI.join(@base_uri, path)
          uri.query = URI.encode_www_form(query) unless query.empty?
          http = Security::Egress.http(uri, "cluster")
          KubeletClientTLS.configure(http, uri, @tls)
          http.open_timeout = @open_timeout
          http.read_timeout = 300
          response = http.request(Net::HTTP::Post.new(uri))
          unless response.code.to_i == 200
            raise Status::ServiceUnavailable.new(
              "node exec endpoint returned #{response.code}: #{response.body.to_s[0, 200]}"
            )
          end

          {"stdout" => [response.body.to_s.b]}
        end

        private

        def escape(value)
          URI.encode_www_form_component(value.to_s)
        end

        def open_socket(uri)
          tcp = Security::Egress.tcp_socket(uri.hostname, uri.port, "cluster", connect_timeout: @open_timeout)
          begin
            tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          rescue SystemCallError
            nil # an egress tunnel over a Unix socket
          end
          return tcp unless uri.scheme == "https"

          ssl = OpenSSL::SSL::SSLSocket.new(tcp, KubeletClientTLS.context(@tls))
          ssl.hostname = uri.host unless uri.host.match?(/\A[\d.:\[\]]+\z/)
          ssl.sync_close = true
          ssl.connect
          ssl
        end

        MAX_HEAD_BYTES = 64 * 1024

        def read_response_head(socket)
          buffer = "".b
          until (index = buffer.index("\r\n\r\n"))
            chunk = socket.readpartial(4096)
            buffer << chunk
            raise Status::ServiceUnavailable.new("node streaming endpoint sent an oversized response head") if buffer.bytesize > MAX_HEAD_BYTES
          end
          head = buffer.byteslice(0, index)
          leftover = buffer.byteslice((index + 4)..) || "".b
          lines = head.split("\r\n")
          status_line = lines.shift.to_s
          status = status_line.split(" ", 3)[1].to_i
          headers = Hash.new { |hash, key| hash[key] = [] }
          lines.each do |line|
            name, value = line.split(":", 2)
            next if name.nil? || value.nil?

            headers[name.strip.downcase] << value.strip
          end
          [status, headers, leftover]
        rescue EOFError
          raise Status::ServiceUnavailable.new("node streaming endpoint closed the connection during the upgrade")
        end

        def read_body(socket, headers, leftover)
          length = headers["content-length"].first&.to_i
          body = leftover.dup
          if length
            body << socket.read(length - body.bytesize).to_s while body.bytesize < length
          elsif headers["transfer-encoding"].any? { |value| value.downcase.include?("chunked") }
            body = read_chunked(socket, leftover)
          end
          body
        rescue IOError, SystemCallError
          body || "".b
        end

        MAX_ERROR_BODY_BYTES = 1024 * 1024

        # A chunked body is read chunk by chunk up to its terminating
        # zero-size chunk.  The node answers a refused exec (a missing
        # executable, an unknown container) with a chunked 500 on a
        # keep-alive connection; reading that socket to EOF waited for the
        # node's 30s idle close before the client saw the error.
        def read_chunked(socket, leftover)
          buffer = leftover.dup
          result = "".b
          loop do
            line_end = buffer.index("\r\n")
            if line_end.nil?
              fill_buffer(buffer, socket)
              next
            end

            size = buffer.byteslice(0, line_end).split(";").first.to_s.strip.to_i(16)
            if size.zero?
              # Trailers up to the blank line end the message.
              fill_buffer(buffer, socket) until buffer.index("\r\n\r\n", line_end)
              return result
            end

            result << raw.byteslice(line_end + 2, size).to_s
            offset = line_end + 2 + size + 2
          end
          result
        end

        # A followed log has no end: buffering it returns nothing until the
        # container exits, which every client reads as a stalled request.  The
        # chunks are yielded as the node produces them, and the connection is
        # held open for exactly as long as the consumer reads.
        # A followed log held open by a bare Enumerator has no lifecycle: when
        # the API server's own client goes away the consumer simply stops
        # pulling, the generator suspends INSIDE Net::HTTP, and the connection
        # to the node stays open forever.  The node then sees a peer that is
        # still connected, so its disconnect monitor never fires and its
        # log-follow thread polls at 10Hz for the life of the process.  That
        # leaked ~3 threads per abandoned `kubectl logs -f` on both ends: in
        # the 2026-09-14 K1 run the node agent reached 603 threads / 8.9GB
        # after two hours with five Pods, and the API server 5.1GB.
        #
        # FollowStream gives the stream an owner.  It answers #close, which is
        # what Node::Service::Stream#close_endpoint and the HTTP server's
        # stream close hook already call when the client disconnects; closing
        # it finishes the upstream connection, which unblocks the reader and
        # lets the node observe the EOF it was waiting for.
        class FollowStream
          include Enumerable

          def initialize(uri, open_timeout:, tls: nil)
            @tls = tls
            @uri = uri
            @open_timeout = open_timeout
            @mutex = Mutex.new
            @closed = false
            @http = nil
          end

          def each
            return to_enum(:each) unless block_given?

            http = Security::Egress.http(@uri, "cluster")
            KubeletClientTLS.configure(http, @uri, @tls)
            http.open_timeout = @open_timeout
            # A follow must not be cut off by a read timeout: an idle log is
            # not a broken one.  #close is what ends it.
            http.read_timeout = nil
            @mutex.synchronize do
              raise StreamClosed, "node log stream was closed" if @closed

              @http = http
            end
            begin
              http.start do |connection|
                connection.request(Net::HTTP::Get.new(@uri)) do |response|
                  raise Status::ServiceUnavailable.new("node streaming endpoint returned #{response.code}") unless response.code.to_i == 200

                  response.read_body do |chunk|
                    raise StreamClosed, "node log stream was closed" if closed?

                    yield chunk.b
                  end
                end
              end
            rescue StreamClosed
              nil
            rescue IOError, SystemCallError
              # #close finishes the connection under the reader on purpose;
              # after a close that is the end of the stream, not a failure.
              raise unless closed?

              nil
            ensure
              finish_connection
            end
            self
          end

          def closed?
            @mutex.synchronize { @closed }
          end

          # Ends the follow.  Safe from another thread: finishing the
          # connection makes the in-flight read raise, which is the only way
          # to interrupt Net::HTTP#read_body.
          def close
            @mutex.synchronize do
              return self if @closed

              @closed = true
            end
            finish_connection
            self
          end

          private

          def finish_connection
            http = @mutex.synchronize { @http.tap { @http = nil } }
            return unless http&.started?

            http.finish
          rescue IOError, SystemCallError
            nil
          end
        end

        # Raised inside a FollowStream to unwind the Net::HTTP block once the
        # stream has been closed.
        class StreamClosed < StandardError; end

        def follow_stream(uri)
          FollowStream.new(uri, open_timeout: @open_timeout, tls: @tls)
        end

        def get_stream(path, query, follow: false)
          uri = URI.join(@base_uri, path)
          uri.query = URI.encode_www_form(query) unless query.empty?
          return follow_stream(uri) if follow

          http = Security::Egress.http(uri, "cluster")
          KubeletClientTLS.configure(http, uri, @tls)
          http.open_timeout = @open_timeout
          http.read_timeout = @read_timeout if @read_timeout
          # A one-shot read may be buffered; a follow may not (see below).
          response = http.request(Net::HTTP::Get.new(uri))
          code = response.code.to_i
          unless code == 200
            # A node-side 4xx is the client's answer, not an outage: forwarding
            # it as 503 makes "the container has not started yet" look like a
            # broken cluster.
            body = response.body.to_s.strip
            raise Status::BadRequest.new(body.empty? ? "node rejected the log request" : body) if code == 400
            raise Status::NotFound.new(body.empty? ? "container log is not available" : body) if code == 404

            raise Status::ServiceUnavailable.new(
              "node streaming endpoint returned #{response.code} for #{uri}: #{body[0, 200]}"
            )
          end

          [response.body.to_s.b]
        end
      end

      attr_reader :scheme, :tls

      # +tls+: KubeletClientTLS options (kube-apiserver --kubelet-client-
      # certificate / --kubelet-client-key / --kubelet-certificate-authority);
      # with them the API server dials every kubelet over https.
      def initialize(store:, resource:, scheme: nil, port: DEFAULT_PORT, tls: nil)
        @store = store
        @resource = resource
        @tls = tls
        @scheme = scheme || (tls ? "https" : "http")
        @default_port = port
      end

      # The bridge calls this with the pod and the node name.
      def call(node_name, pod = nil)
        node = fetch_node(node_name)
        return nil unless node

        address = node_address(node)
        return nil unless address

        port = kubelet_endpoint_port(node) || @default_port
        base = "#{@scheme}://#{format_host(address)}:#{port}"
        PodScopedEndpoint.new(Endpoint.new(base, tls: @tls), pod)
      end

      # v1.DaemonEndpoint serialises its port as "Port"; the lowercase form is
      # accepted so a Node written by an older agent still resolves.
      def kubelet_endpoint_port(node)
        endpoint = node.dig("status", "daemonEndpoints", "kubeletEndpoint")
        return nil unless endpoint.is_a?(Hash)

        value = endpoint["Port"] || endpoint[:Port] || endpoint["port"] || endpoint[:port]
        port = value.to_i
        port.positive? ? port : nil
      end

      # Carries the pod's namespace/name into the endpoint call, which the
      # bridge's service contract does not pass along.
      #
      # The bridge asks a node for a *service* first (`node.subresource("log")`
      # or `node.logs` with no arguments) and only then invokes that service, so
      # the two must be separate objects: returning a body from `logs` makes the
      # bridge try to call the body.
      class PodScopedEndpoint
        SUBRESOURCE_ALIASES = {"log" => :logs, "logs" => :logs, "exec" => :exec, "attach" => :attach,
                               "portforward" => :portforward, "port-forward" => :portforward}.freeze

        def initialize(endpoint, pod)
          @endpoint = endpoint
          @pod = pod || {}
        end

        def subresource(name)
          key = SUBRESOURCE_ALIASES[name.to_s]
          raise KeyError, "node endpoint does not serve #{name}" unless key

          case key
          when :exec then ExecSubresource.new(self)
          when :logs then LogSubresource.new(self)
          else UpgradeOnlySubresource.new(name.to_s)
          end
        end

        # The node's own path for a streaming subresource, kubelet style.
        def upgrade_path(operation, container_name: nil)
          namespace = escape(@pod.dig("metadata", "namespace") || "default")
          name = escape(@pod.dig("metadata", "name"))
          case operation.to_s
          when "exec", "attach"
            container = container_name.to_s.empty? ? container_id_for : container_name.to_s
            "/#{operation}/#{namespace}/#{name}/#{escape(container)}"
          when "portforward"
            uid = @pod.dig("metadata", "uid").to_s
            uid.empty? ? "/portForward/#{namespace}/#{name}" : "/portForward/#{namespace}/#{name}/#{escape(uid)}"
          else
            raise ArgumentError, "#{operation} is not an upgradable subresource"
          end
        end

        # Proxies a client's upgrade request to the node.  Returns the node's
        # UpgradeResult; the caller splices the sockets on 101.
        def upgrade_proxy(operation, request, container_name: nil)
          @endpoint.dial_upgrade(
            method: request.method == "GET" ? "GET" : "POST",
            path: upgrade_path(operation, container_name: container_name),
            query: query_string_for(request),
            headers: Endpoint.upgrade_headers(request)
          )
        end

        # The client's query, re-encoded (repeated keys stay repeated so a
        # multi-word `command` survives).
        def query_string_for(request)
          return request.query_string if request.respond_to?(:query_string) && request.query_string

          query = request.respond_to?(:query) ? request.query : nil
          return nil unless query.is_a?(Hash) && !query.empty?

          pairs = query.flat_map { |key, value| Array(value).map { |item| [key.to_s, item.to_s] } }
          URI.encode_www_form(pairs)
        end

        # attach/port-forward exist only as upgraded connections.
        class UpgradeOnlySubresource
          def initialize(name) = @name = name

          def attach(*) = raise(Status::BadRequest.new("Pod #{@name} requires a connection upgrade (WebSocket or SPDY/3.1)"))
          alias port_forward attach
          alias call attach
        end

        def escape(value)
          URI.encode_www_form_component(value.to_s)
        end

        # The service the bridge invokes for a log request.
        class LogSubresource
          def initialize(owner) = @owner = owner

          def logs(container_id = nil, **) = @owner.fetch_logs(container_id, **)
        end

        # The service the bridge invokes for exec.  Result retrieval (every
        # conformance runner copies its report out of the pod this way) is
        # non-interactive, which is what the node serves.
        class ExecSubresource
          def initialize(owner) = @owner = owner

          def exec(container_id = nil, **) = @owner.run_exec(container_id, **)
        end

        # The node endpoint is name-addressed, like the kubelet's: it maps the
        # container *name* to whatever runtime id it is using.  Resolving a
        # runtime id here would require the API server to know the node's
        # internal bookkeeping.
        def container_id_for(pod: nil, container_name: nil, **_options)
          name = container_name.to_s
          return name unless name.empty?

          first = Array((pod || @pod).dig("spec", "containers")).first
          first.is_a?(Hash) ? (first["name"] || first[:name]).to_s : ""
        end

        def run_exec(container_id = nil, command: nil, **_options)
          container_id = container_id_for if container_id.to_s.empty?
          @endpoint.exec(container_id, command: Array(command),
                                       namespace: @pod.dig("metadata", "namespace"),
                                       pod: @pod.dig("metadata", "name"))
        end

        def fetch_logs(container_id = nil, **)
          # An empty container makes the node URL ambiguous ("/containerLogs/
          # ns/pod/"), so fall back to the pod's first container the way
          # `kubectl logs` does for a single-container pod.
          container_id = container_id_for if container_id.to_s.empty?
          @endpoint.logs(container_id,
                         namespace: @pod.dig("metadata", "namespace"),
                         pod: @pod.dig("metadata", "name"),
                         **)
        end
      end

      private

      def fetch_node(node_name)
        result = @store.get(resource: @resource, namespace: :cluster, name: node_name.to_s)
        result.respond_to?(:object) ? result.object : result
      rescue StandardError => error
        # Reporting the node as merely "unavailable" hides why; a routing
        # failure that cannot be explained cannot be fixed from the logs.
        raise Status::ServiceUnavailable.new(
          "node #{node_name.inspect} could not be read for streaming: #{error.class}: #{error.message}"
        )
      end

      # Where the API server dials this node's streaming endpoint.
      #
      # It is NOT always the node's InternalIP.  kubelet serves exec, attach,
      # logs and port-forward behind its own authentication and authorization
      # (--authentication-token-webhook / --authorization-mode=Webhook), which
      # is what lets it listen on a routable address.  An agent that has no
      # authorizer of its own must stay on loopback, and then its node address
      # -- the address its Pods and the rest of the cluster reach it on -- is a
      # different address entirely.  The agent publishes the one the API server
      # should dial; without it, giving a node an honest InternalIP sent every
      # exec and log request to an address nothing was listening on.
      STREAMING_ADDRESS_ANNOTATION = "node.rubernetes.io/streaming-address"

      def node_address(node)
        announced = node.dig("metadata", "annotations", STREAMING_ADDRESS_ANNOTATION)
        return announced.to_s unless announced.to_s.empty?

        addresses = Array(node.dig("status", "addresses"))
        %w[InternalIP ExternalIP Hostname].each do |type|
          entry = addresses.find { |value| value["type"] == type && !value["address"].to_s.empty? }
          return entry["address"] if entry
        end
        nil
      end

      def format_host(address)
        address.to_s.include?(":") ? "[#{address}]" : address.to_s
      end
    end
  end
end
