# frozen_string_literal: true

require "json"
require "openssl"
require "zlib"
require "stringio"
require "socket"
require "time"

require_relative "errors"
require_relative "headers"
require_relative "request"
require_relative "response"
require_relative "http2"

module Rubernetes
  module Transport
    # A small, dependency-free HTTP/1.1 adapter for an in-process handler.
    #
    # The adapter deliberately owns HTTP framing only. Authentication,
    # routing, API semantics, and persistence remain in the handler. A server
    # is started in a background thread by default:
    #
    #   server = Rubernetes::Transport::HTTPServer.new(handler, port: 0)
    #   server.start
    #   puts server.port
    #   server.stop
    #
    # A handler receives a Request and may return Response, a response hash,
    # a Rack-style three-element array, or a JSON-compatible value. An
    # Enumerable response body is streamed with HTTP chunked framing.
    class HTTPServer
      HEADER_SEPARATOR = "\r\n\r\n".b.freeze
      CRLF = "\r\n".b.freeze
      MAX_READ_CHUNK = 16 * 1024
      DEFAULT_MAX_HEADER_BYTES = 64 * 1024
      DEFAULT_MAX_HEADER_COUNT = 100
      DEFAULT_MAX_BODY_BYTES = 3 * 1024 * 1024
      DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
      DEFAULT_READ_TIMEOUT = 30.0
      DEFAULT_WRITE_TIMEOUT = 30.0
      DEFAULT_MAX_REQUESTS_PER_CONNECTION = 100
      DEFAULT_SHUTDOWN_TIMEOUT = 5.0
      DEFAULT_BACKLOG = 128
      # kube-apiserver has no comparable cap; 256 was reached by a three-node
      # cluster's informers plus the conformance client and answered 503.
      DEFAULT_MAX_CONNECTIONS = 8192
      OVERLOAD_RESPONSE = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\nRetry-After: 1\r\n\r\n".b.freeze

      FORBIDDEN_TRAILER_NAMES = %w[
        connection
        content-length
        host
        keep-alive
        proxy-authenticate
        proxy-authorization
        te
        trailer
        transfer-encoding
        upgrade
      ].freeze

      STATUS_REASONS = {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported"
      }.freeze

      attr_reader :host, :configured_port, :handler, :logger, :max_connections
      # Called once per failed TLS handshake (net/http's "TLS handshake error
      # from" log line, which apiserver_tls_handshake_errors_total counts).
      attr_accessor :on_tls_handshake_error

      def initialize(handler = nil, host: "127.0.0.1", port: 0, cert_file: nil, key_file: nil,
                     cert: nil, key: nil, tls: nil, logger: nil, request_class: nil,
                     request_factory: nil, **options, &block)
        host = options.delete(:bind) || options.delete(:listen_host) || host
        port = options.delete(:listen_port) if options.key?(:listen_port)
        cert_file ||= options.delete(:ssl_cert)
        key_file ||= options.delete(:ssl_key)
        cert ||= options.delete(:ssl_certificate)
        key ||= options.delete(:ssl_private_key)
        handler ||= block
        handler ||= options.delete(:handler)
        raise ConfigurationError, "an HTTP handler is required" unless callable_handler?(handler)

        tls_options = tls.is_a?(Hash) ? tls.dup : {}
        @request_client_certificates = options.delete(:request_client_certificates) || tls_options.delete(:request_client_certificates) || false
        @client_ca_certificates = Array(options.delete(:client_ca_certificates) || tls_options.delete(:client_ca_certificates))
        cert_file ||= tls_options.delete(:cert_file) || tls_options.delete(:certificate)
        key_file ||= tls_options.delete(:key_file) || tls_options.delete(:private_key)
        cert ||= tls_options.delete(:cert)
        key ||= tls_options.delete(:key)
        tls_enabled = tls.nil? ? (cert_file || key_file || cert || key) : tls
        if (tls_enabled && !(cert_file || cert)) || (tls_enabled && !(key_file || key))
          raise ConfigurationError, "TLS requires both certificate and private key"
        end
        if (cert_file || cert || key_file || key) && tls == false
          raise ConfigurationError, "TLS certificate and key cannot be used with tls: false"
        end
        raise ConfigurationError, "unknown TLS options: #{tls_options.keys.join(", ")}" unless tls_options.empty?

        @handler = handler
        @static_handler = handler.is_a?(Hash) && response_hash?(handler)
        @host = String(host).dup.freeze
        @configured_port = integer_option(port, "port", min: 0, max: 65_535)
        @cert_file = cert_file
        @key_file = key_file
        @certificate = cert
        @private_key = key
        @tls_enabled = !!tls_enabled
        @logger = logger
        @request_class = request_class
        @request_factory = request_factory
        raise ConfigurationError, "request_factory must respond to call" unless @request_factory.nil? || @request_factory.respond_to?(:call)

        @backlog = integer_option(option(options, :backlog, DEFAULT_BACKLOG), "backlog", min: 1)
        @max_header_bytes = integer_option(option(options, :max_header_bytes, option(options, :header_limit, DEFAULT_MAX_HEADER_BYTES)),
                                           "max_header_bytes", min: 1)
        @max_header_count = integer_option(option(options, :max_header_count, DEFAULT_MAX_HEADER_COUNT), "max_header_count", min: 1)
        @max_body_bytes = integer_option(option(options, :max_body_bytes, option(options, :body_limit, DEFAULT_MAX_BODY_BYTES)),
                                         "max_body_bytes", min: 0)
        @max_response_bytes = integer_option(
          option(options, :max_response_bytes, option(options, :response_limit, DEFAULT_MAX_RESPONSE_BYTES)), "max_response_bytes", min: 0
        )
        @max_response_header_bytes = integer_option(
          option(options, :max_response_header_bytes,
                 option(options, :response_header_limit, [@max_header_bytes, DEFAULT_MAX_HEADER_BYTES].max)), "max_response_header_bytes", min: 1
        )
        common_timeout = options.delete(:timeout)
        @read_timeout = float_option(
          option(options, :read_timeout,
                 option(options, :request_timeout, common_timeout || DEFAULT_READ_TIMEOUT)), "read_timeout", min: 0.001
        )
        @write_timeout = float_option(option(options, :write_timeout, common_timeout || DEFAULT_WRITE_TIMEOUT), "write_timeout", min: 0.001)
        # HTTP/2 over TLS (ALPN h2), on by default like Go servers.
        @http2 = option(options, :http2, true) ? true : false
        @max_requests_per_connection = integer_option(option(options, :max_requests_per_connection, DEFAULT_MAX_REQUESTS_PER_CONNECTION),
                                                      "max_requests_per_connection", min: 1)
        @max_connections = integer_option(
          option(options, :max_connections,
                 option(options, :max_concurrent_connections,
                        option(options, :connection_limit, DEFAULT_MAX_CONNECTIONS))),
          "max_connections",
          min: 1
        )
        @shutdown_timeout = float_option(option(options, :shutdown_timeout, DEFAULT_SHUTDOWN_TIMEOUT), "shutdown_timeout", min: 0.0)
        @default_keep_alive = options.key?(:keep_alive) ? !!options.delete(:keep_alive) : true
        @server_name = String(options.delete(:server_name) || "Rubernetes")
        begin
          Headers.new("Server" => @server_name)
        rescue ArgumentError => error
          raise ConfigurationError, "server_name is not a valid HTTP header value", cause: error
        end
        @server_name.freeze
        @strict_host = options.key?(:require_host) ? !!options.delete(:require_host) : true
        raise ConfigurationError, "unknown HTTP server options: #{options.keys.sort.join(", ")}" unless options.empty?

        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @state = :new
        @listener = nil
        @tcp_listener = nil
        @ssl_context = nil
        @accept_thread = nil
        @clients = {}
        @stream_monitors = {}
      end

      def tls?
        @tls_enabled
      end

      def started?
        @mutex.synchronize { %i[running stopping].include?(@state) }
      end

      alias running? started?

      def stopping?
        @mutex.synchronize { @state == :stopping }
      end

      def stopped?
        @mutex.synchronize { @state == :stopped }
      end

      # Bind the listener and start accepting connections.
      #
      # Passing background: false runs the accept loop on the current thread;
      # this is useful for a dedicated daemon thread or a foreground process.
      def start(background: true)
        @mutex.synchronize do
          raise Error, "HTTP server is already started" if %i[running stopping].include?(@state)
          raise Error, "HTTP server cannot be restarted" if @state == :stopped

          bind_listener
          @state = :running
        end

        if background
          @accept_thread = Thread.new { accept_loop }
          @accept_thread.name = "rubernetes-http-accept" if @accept_thread.respond_to?(:name=)
        else
          accept_loop
        end
        self
      end

      alias start! start

      # Run the listener in the calling thread until stop is requested.
      def run
        start(background: false)
      end

      # The bound port, including an ephemeral port selected by the kernel.
      def port
        socket = @mutex.synchronize { @tcp_listener }
        return nil unless socket

        socket.addr.fetch(1)
      rescue IOError, SystemCallError
        nil
      end

      def address
        socket = @mutex.synchronize { @tcp_listener }
        return nil unless socket

        socket.addr
      rescue IOError, SystemCallError
        nil
      end

      def endpoint
        return nil unless port

        scheme = tls? ? "https" : "http"
        "#{scheme}://#{@host}:#{port}"
      end
      alias url endpoint
      alias uri endpoint
      alias listen_port port

      def listener
        @mutex.synchronize { @listener }
      end

      # Number of accepted connections currently occupying a worker slot.
      def active_connections
        @mutex.synchronize { @clients.length }
      end

      # Number of peer-monitor threads attached to streaming responses.
      # Exposed so an embedding service can verify that watch teardown has
      # completed before releasing the rest of its server-side state.
      def active_stream_monitors
        @mutex.synchronize { @stream_monitors.length }
      end

      # Stop accepting new work and wait for active requests to finish.
      #
      # Graceful shutdown closes idle/remaining sockets after timeout so a
      # watch stream or a handler blocked on external state cannot keep the
      # process alive forever.
      def stop(graceful: true, timeout: @shutdown_timeout)
        timeout = float_option(timeout, "shutdown timeout", min: 0.0)
        current = Thread.current
        clients_to_close = []

        @mutex.synchronize do
          return self if %i[new stopped].include?(@state)

          @state = :stopping
          close_listener
          clients_to_close = @clients.keys unless graceful
        end

        clients_to_close.each { |client| close_socket(client) }

        deadline = monotonic_time + timeout
        @mutex.synchronize do
          while @clients.any? { |_socket, thread| thread != current } && monotonic_time < deadline
            @condition.wait(@mutex, [deadline - monotonic_time, 0.05].max)
          end
          @clients.each_key { |client| close_socket(client) }
        end

        join_thread(@accept_thread, timeout: remaining(deadline), except: current)
        @mutex.synchronize do
          @state = :stopped
          @condition.broadcast
        end
        self
      end

      alias shutdown stop
      alias close stop

      def join(timeout = nil)
        deadline = timeout.nil? ? nil : monotonic_time + float_option(timeout, "join timeout", min: 0.0)
        join_thread(@accept_thread, timeout: remaining(deadline))
        loop do
          threads = @mutex.synchronize { @clients.values.dup }
          threads.each { |thread| join_thread(thread, timeout: remaining(deadline)) }
          break if threads.empty? || (deadline && monotonic_time >= deadline)
        end
        self
      end

      private

      def option(options, name, default)
        options.key?(name) ? options.delete(name) : default
      end

      def callable_handler?(value)
        return true if value.respond_to?(:call)
        return true if value.is_a?(Hash)

        false
      end

      def integer_option(value, name, min:, max: nil)
        number = Integer(value)
        raise ConfigurationError, "#{name} must be at least #{min}" if number < min
        raise ConfigurationError, "#{name} must be at most #{max}" if max && number > max

        number
      rescue ArgumentError, TypeError => error
        raise ConfigurationError, "#{name} must be an integer: #{value.inspect}", cause: error
      end

      def float_option(value, name, min:)
        number = Float(value)
        raise ConfigurationError, "#{name} must be at least #{min}" if number < min
        raise ConfigurationError, "#{name} must be finite" unless number.finite?

        number
      rescue ArgumentError, TypeError => error
        raise ConfigurationError, "#{name} must be a number: #{value.inspect}", cause: error
      end

      def bind_listener
        @tcp_listener = TCPServer.new(@host, @configured_port)
        @tcp_listener.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
        @tcp_listener.listen(@backlog)
        # Keep the underlying TCP listener even for TLS. Wrapping and
        # handshaking each client in its own worker subjects the handshake to
        # the read deadline and prevents one slow TLS peer from blocking
        # accept() for every other peer.
        @ssl_context = @tls_enabled ? build_ssl_context : nil
        @listener = @tcp_listener
      rescue SystemCallError, OpenSSL::OpenSSLError, IOError => error
        close_listener
        raise ConfigurationError, "cannot bind HTTP listener on #{@host}:#{@configured_port}: #{error.message}", cause: error
      end

      KEY_EXCHANGE_GROUPS = "X25519:P-256:P-384:P-521"

      # A rotated serving certificate: connections accepted from now on use
      # it, established ones keep theirs (as kubelet's dynamic certificate
      # provider does).
      def reload_tls!(certificate:, private_key:)
        @certificate = certificate
        @private_key = private_key
        @mutex.synchronize { @ssl_context = build_ssl_context if @tls_enabled }
        self
      end
      public :reload_tls!

      def build_ssl_context
        context = OpenSSL::SSL::SSLContext.new
        context.cert = @certificate || OpenSSL::X509::Certificate.new(File.binread(@cert_file))
        context.key = @private_key || OpenSSL::PKey.read(File.binread(@key_file))
        context.min_version = OpenSSL::SSL::TLS1_2_VERSION if context.respond_to?(:min_version=)
        # Go's crypto/tls (kube-apiserver) negotiates key-exchange groups in
        # server order with X25519 first.  OpenSSL defaults to the client's
        # order, and clients such as busybox 1.36 wget list P-256 first and
        # then send a ClientKeyExchange point OpenSSL 3 rejects ("EC lib",
        # internal_error alert).  Match Go so those clients keep working.
        context.ecdh_curves = KEY_EXCHANGE_GROUPS if context.respond_to?(:ecdh_curves=)
        context.options |= OpenSSL::SSL::OP_CIPHER_SERVER_PREFERENCE
        # ALPN: like any Go server, prefer h2.  Clients that need an HTTP/1.1
        # upgrade (exec, attach, port-forward) offer only http/1.1 or no ALPN.
        if @http2 && context.respond_to?(:alpn_select_cb=)
          context.alpn_select_cb = lambda do |protocols|
            if protocols.include?("h2") then "h2"
            elsif protocols.include?("http/1.1") then "http/1.1"
            else protocols.first
            end
          end
        end
        if @request_client_certificates
          # kube-apiserver's tls.RequestClientCert: ask every client for a
          # certificate but let the handshake succeed without one or with an
          # unverifiable one; the authenticators decide what it is worth.
          context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          context.verify_callback = ->(_preverify_ok, _store_context) { true }
          # OpenSSL refuses to resume a session on a peer-verifying context
          # that has no session id context (SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED,
          # sent as an internal_error alert): every client that resumes TLS
          # sessions -- Ruby's Net::HTTP does -- failed its second connection.
          context.session_id_context = "rubernetes-http-server"
          store = OpenSSL::X509::Store.new
          Array(@client_ca_certificates).each { |certificate| store.add_cert(certificate) }
          context.cert_store = store
          # Advertise the acceptable CAs so clients pick a matching certificate.
          context.client_ca = Array(@client_ca_certificates) unless Array(@client_ca_certificates).empty?
        end
        context
      rescue Errno::ENOENT, Errno::EACCES, OpenSSL::OpenSSLError, ArgumentError => error
        raise ConfigurationError, "cannot configure TLS listener: #{error.message}", cause: error
      end

      def accept_loop
        loop do
          break if stopping?

          client = accept_client
          break unless client

          if stopping?
            close_socket(client)
            break
          end

          unless admit_connection?(client)
            # Refuse before creating a worker so the connection ceiling also
            # bounds thread count. Plain HTTP receives a best-effort 503;
            # incomplete TLS peers are closed without emitting plaintext.
            reject_connection(client)
            next
          end

          start_gate = Queue.new
          begin
            thread = Thread.new(client, start_gate) do |socket, gate|
              gate.pop
              Thread.current.name = "rubernetes-http-client" if Thread.current.respond_to?(:name=)
              handle_client(socket)
            end
          rescue ThreadError => error
            unregister_client(client)
            reject_connection(client)
            log(:warn, "HTTP client worker could not be created", error: error.class.name)
            next
          end
          thread.report_on_exception = false if thread.respond_to?(:report_on_exception=)
          @mutex.synchronize do
            @clients[client] = thread
          end
          start_gate << true
        end
      ensure
        @mutex.synchronize do
          @state = :stopped if @state == :running
          @condition.broadcast
        end
      end

      def accept_client
        listener = @mutex.synchronize { @listener }
        return nil unless listener

        client = listener.accept
        disable_nagle(client)
        client
      rescue IOError, Errno::EBADF, Errno::EINVAL
        return nil if stopping?

        log(:warn, "HTTP listener stopped unexpectedly")
        nil
      rescue OpenSSL::SSL::SSLError, SystemCallError => error
        return nil if stopping?

        log(:warn, "HTTP connection accept failed", error: error.class.name)
        nil
      end

      def register_client(socket)
        @mutex.synchronize { @clients[socket] = Thread.current }
      end

      def admit_connection?(socket)
        @mutex.synchronize do
          return false if @clients.length >= @max_connections

          @clients[socket] = :pending
          true
        end
      end

      def reject_connection(socket)
        @logger&.warn("http.connection_rejected", max_connections: @max_connections) if @logger.respond_to?(:warn)
        socket.write_nonblock(OVERLOAD_RESPONSE, exception: false) unless @tls_enabled
      rescue IOError, SystemCallError
        nil
      ensure
        close_socket(socket)
      end

      def unregister_client(socket)
        @mutex.synchronize do
          @clients.delete(socket)
          @condition.broadcast
        end
      end

      def handle_client(socket)
        register_client(socket) unless @mutex.synchronize { @clients.key?(socket) }
        active_socket = socket
        tls_ready = !@tls_enabled
        if @tls_enabled
          active_socket = establish_tls(socket)
          tls_ready = true
        end
        buffer = +"".b
        request_count = 0
        client_certificate = nil
        client_chain = []
        if @tls_enabled && active_socket.respond_to?(:peer_cert)
          begin
            client_certificate = active_socket.peer_cert
            client_chain = Array(active_socket.peer_cert_chain)
          rescue OpenSSL::SSL::SSLError
            client_certificate = nil
          end
        end

        if @tls_enabled && active_socket.respond_to?(:alpn_protocol) && active_socket.alpn_protocol == "h2"
          return serve_http2(active_socket, socket, client_certificate, client_chain)
        end

        loop do
          request = parse_request(active_socket, buffer, client_certificate: client_certificate, client_chain: client_chain)
          break unless request

          request_count += 1
          response = respond_to_request(request)

          keep_alive = keep_alive_for?(request, request_count) && @default_keep_alive
          begin
            write_response(active_socket, response, request: request, keep_alive: keep_alive)
          rescue ResponseTooLarge => error
            log(:warn, "HTTP response exceeded configured limit", error: error.message)
            write_error(active_socket, ResponseError.new("response exceeds the configured limit"), request: request) unless error.partial?
            keep_alive = false
          end
          break if response.respond_to?(:upgrade?) && response.upgrade?
          break unless keep_alive
        end
      rescue RequestError => error
        write_error(active_socket, error) if tls_ready
      rescue ResponseTimeout, IOError, SystemCallError, OpenSSL::SSL::SSLError
        # A peer closing its socket or a blocked response write is a normal
        # end to a connection. Never append a second error response after a
        # response write has timed out or partially sent.
        nil
      rescue StandardError => error
        log(:error, "HTTP client loop failed", error: error.class.name)
      ensure
        close_socket(active_socket) if active_socket && active_socket != socket
        close_socket(socket)
        unregister_client(socket)
      end

      # The handler's response to one request, or the error response when
      # the handler fails.  HTTP/1.1 and HTTP/2 requests both come here.
      def respond_to_request(request)
        normalize_response(invoke_handler(request))
      rescue StandardError => error
        # A 500 whose only record is an exception class name cannot be
        # diagnosed from a running cluster's logs.  Carry the message and a
        # bounded backtrace: the response body stays generic.
        log(:error, "HTTP handler failed", error: error.class.name, message: error.message,
                                           method: request.respond_to?(:method) ? request.method : nil,
                                           path: request.respond_to?(:path) ? request.path : nil,
                                           backtrace: Array(error.backtrace).first(12))
        error_response(error)
      end

      def serve_http2(tls_socket, socket, client_certificate, client_chain)
        HTTP2::Connection.new(
          tls_socket, server: self, remote_address: remote_address(socket),
                      client_certificate: client_certificate, client_chain: client_chain,
                      idle_timeout: @read_timeout, write_timeout: @write_timeout,
                      max_header_bytes: @max_header_bytes, max_header_count: @max_header_count,
                      max_body_bytes: @max_body_bytes, max_response_bytes: @max_response_bytes,
                      server_name: @server_name
        ).serve
      end

      def establish_tls(socket)
        context = @mutex.synchronize { @ssl_context }
        raise ConfigurationError, "TLS context is not initialized" unless context

        tls_socket = OpenSSL::SSL::SSLSocket.new(socket, context)
        tls_socket.sync_close = true
        deadline = monotonic_time + @read_timeout
        loop do
          result = tls_socket.accept_nonblock(exception: false)
          case result
          when :wait_readable
            wait_for_io(tls_socket, readable: true, deadline: deadline)
          when :wait_writable
            wait_for_io(tls_socket, readable: false, deadline: deadline)
          else
            return tls_socket
          end
        end
      rescue RequestTimeout
        close_socket(tls_socket) if tls_socket
        report_tls_handshake_error
        raise
      rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
        close_socket(tls_socket) if tls_socket
        report_tls_handshake_error
        raise
      end

      def report_tls_handshake_error
        @on_tls_handshake_error&.call
      rescue StandardError
        nil
      end

      def parse_request(socket, buffer, client_certificate: nil, client_chain: [])
        header_block = read_header_block(socket, buffer)
        return nil if header_block.nil?

        lines = header_block.byteslice(0, header_block.bytesize - HEADER_SEPARATOR.bytesize).split(CRLF, -1)
        request_line = lines.shift
        raise BadRequest, "request line is missing" if request_line.nil? || request_line.empty?
        raise BadRequest, "request line contains non-ASCII bytes" unless request_line.ascii_only?

        method, target, version = request_line.split(" ", -1)
        if method.nil? || target.nil? || version.nil? || request_line.split(" ", -1).length != 3
          raise BadRequest, "request line must contain method, target, and HTTP version"
        end
        raise BadRequest, "request method is invalid" unless Headers::TOKEN_PATTERN.match?(method)
        raise BadRequest, "request target contains control bytes" if target.each_byte.any? { |byte| byte < 0x20 || byte == 0x7f }
        raise HTTPVersionNotSupported unless %w[HTTP/1.0 HTTP/1.1].include?(version)

        headers = Headers.new
        raise HeaderTooLarge if lines.length > @max_header_count

        lines.each do |line|
          raise BadRequest, "header line is malformed" if line.empty? || line.start_with?(" ", "\t")

          name, value = line.split(":", 2)
          raise BadRequest, "header line is malformed" if value.nil?
          raise BadRequest, "header name is invalid" unless Headers::TOKEN_PATTERN.match?(name)

          begin
            headers.add(name, value)
          rescue ArgumentError => error
            raise BadRequest, error.message
          end
        end

        validate_host_header!(headers, version)
        expect_continue!(socket, headers)
        body = read_request_body(socket, buffer, headers)
        Request.new(
          method: method,
          target: target,
          headers: headers,
          body: body,
          http_version: version,
          remote_address: remote_address(socket),
          initial_data: buffer,
          client_certificate: client_certificate,
          client_chain: client_chain
        )
      end

      def validate_host_header!(headers, version)
        values = headers.raw_values("host")
        return unless @strict_host && version == "HTTP/1.1"
        raise BadRequest, "HTTP/1.1 requires exactly one Host header" unless values.length == 1
      end

      def expect_continue!(socket, headers)
        values = headers.raw_values("expect")
        return if values.empty?

        tokens = values.flat_map { |value| value.split(",").map { |token| token.strip.downcase } }
        raise RequestError.new("unsupported Expect header", status: 417, code: "ExpectationFailed") unless tokens == ["100-continue"]

        write_all(socket, "HTTP/1.1 100 Continue\r\n\r\n".b, deadline: monotonic_time + @write_timeout)
      end

      def read_request_body(socket, buffer, headers)
        content_lengths = headers.raw_values("content-length")
        transfer_encodings = headers.raw_values("transfer-encoding")
        raise BadRequest, "duplicate Content-Length is not permitted" if content_lengths.length > 1
        raise BadRequest, "Content-Length and Transfer-Encoding cannot be combined" if !content_lengths.empty? && !transfer_encodings.empty?

        if transfer_encodings.empty?
          return "".b if content_lengths.empty?

          length = parse_content_length(content_lengths.first)
          raise PayloadTooLarge if length > @max_body_bytes

          return read_exact(socket, buffer, length)
        end

        encodings = transfer_encodings.flat_map { |value| value.split(",").map { |token| token.strip.downcase } }
        raise NotImplemented unless encodings == ["chunked"]

        read_chunked_body(socket, buffer)
      end

      def parse_content_length(value)
        text = String(value)
        raise BadRequest, "Content-Length must contain only decimal digits" unless text.match?(/\A[0-9]+\z/)

        length = Integer(text, 10)
        raise PayloadTooLarge if length > @max_body_bytes

        length
      rescue ArgumentError, TypeError => error
        raise BadRequest, "Content-Length is invalid: #{error.message}"
      end

      def read_chunked_body(socket, buffer)
        body = +"".b
        loop do
          line = read_line(socket, buffer, @max_header_bytes)
          raise BadRequest, "chunk size line is missing" if line.nil?
          raise BadRequest, "chunk size line is malformed" unless line.ascii_only?

          size = parse_chunk_size(line)
          raise PayloadTooLarge if size > @max_body_bytes - body.bytesize
          break if size.zero? && consume_chunk_trailers(socket, buffer)

          body << read_exact(socket, buffer, size)
          terminator = read_exact(socket, buffer, 2)
          raise BadRequest, "chunk is not terminated by CRLF" unless terminator == CRLF
        end
        body
      end

      def consume_chunk_trailers(socket, buffer)
        trailer_count = 0
        trailer_bytes = 0
        loop do
          line = read_line(socket, buffer, @max_header_bytes)
          raise BadRequest, "chunk trailer is missing" if line.nil?

          trailer_bytes += line.bytesize + CRLF.bytesize
          raise HeaderTooLarge if trailer_bytes > @max_header_bytes
          return true if line.empty?

          trailer_count += 1
          raise HeaderTooLarge if trailer_count > @max_header_count

          name, value = line.split(":", 2)
          raise BadRequest, "chunk trailer is malformed" if value.nil? || !Headers::TOKEN_PATTERN.match?(name)
          raise BadRequest, "forbidden chunk trailer" if FORBIDDEN_TRAILER_NAMES.include?(name.downcase)

          begin
            Headers.new.add(name, value)
          rescue ArgumentError => error
            raise BadRequest, error.message
          end
        end
      end

      # Parse chunk-size and chunk extensions without accepting ambiguous
      # delimiters. Extensions are ignored semantically, but malformed ones
      # must not be allowed to alter where the next chunk begins.
      def parse_chunk_size(line)
        bytes = line.bytes
        index = 0
        index += 1 while index < bytes.length && hex_byte?(bytes[index])
        raise BadRequest, "chunk size is invalid" if index.zero?

        size = Integer(line.byteslice(0, index), 16)
        while index < bytes.length
          index += 1 while index < bytes.length && bws_byte?(bytes[index])
          raise BadRequest, "chunk extension is invalid" unless bytes[index] == 0x3b

          index += 1
          index += 1 while index < bytes.length && bws_byte?(bytes[index])
          name_start = index
          index += 1 while index < bytes.length && token_byte?(bytes[index])
          raise BadRequest, "chunk extension is invalid" if index == name_start

          index += 1 while index < bytes.length && bws_byte?(bytes[index])
          if bytes[index] == 0x3d
            index += 1
            index += 1 while index < bytes.length && bws_byte?(bytes[index])
            raise BadRequest, "chunk extension is invalid" if index >= bytes.length

            if bytes[index] == 0x22
              index = consume_quoted_chunk_extension(bytes, index)
            else
              value_start = index
              index += 1 while index < bytes.length && token_byte?(bytes[index])
              raise BadRequest, "chunk extension is invalid" if index == value_start
            end
          end

          index += 1 while index < bytes.length && bws_byte?(bytes[index])
          raise BadRequest, "chunk extension is invalid" if index < bytes.length && bytes[index] != 0x3b
        end
        size
      rescue ArgumentError => error
        raise BadRequest, "chunk size is invalid: #{error.message}"
      end

      def consume_quoted_chunk_extension(bytes, index)
        index += 1
        closed = false
        escaped = false
        while index < bytes.length
          byte = bytes[index]
          if escaped
            raise BadRequest, "chunk extension is invalid" unless quoted_byte?(byte)

            escaped = false
          elsif byte == 0x5c
            escaped = true
          elsif byte == 0x22
            closed = true
            index += 1
            break
          else
            raise BadRequest, "chunk extension is invalid" unless quoted_byte?(byte)
          end
          index += 1
        end
        raise BadRequest, "chunk extension is invalid" unless closed && !escaped

        index
      end

      def hex_byte?(byte)
        byte.between?(0x30, 0x39) || byte.between?(0x41, 0x46) || byte.between?(0x61, 0x66)
      end

      def token_byte?(byte)
        byte.between?(0x30, 0x39) ||
          byte.between?(0x41, 0x5a) ||
          byte.between?(0x61, 0x7a) ||
          [0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2a, 0x2b, 0x2d, 0x2e, 0x5e, 0x5f, 0x60, 0x7c, 0x7e].include?(byte)
      end

      def bws_byte?(byte)
        [0x20, 0x09].include?(byte)
      end

      def quoted_byte?(byte)
        byte == 0x09 || (byte.between?(0x20, 0x7e) && byte != 0x7f) || byte >= 0x80
      end

      def read_header_block(socket, buffer)
        deadline = monotonic_time + @read_timeout
        loop do
          index = buffer.index(HEADER_SEPARATOR)
          if index
            length = index + HEADER_SEPARATOR.bytesize
            raise HeaderTooLarge if length > @max_header_bytes

            raise BadRequest, "header line break must be CRLF" if invalid_line_break?(buffer.byteslice(0, length), final: true)

            block = buffer.byteslice(0, length)
            buffer.replace(buffer.byteslice(length..)&.dup || +"".b)
            return block
          end
          raise HeaderTooLarge if buffer.bytesize >= @max_header_bytes
          raise BadRequest, "header line break must be CRLF" if invalid_line_break?(buffer)

          chunk = read_from_socket(socket, MAX_READ_CHUNK, deadline: deadline)
          return nil if chunk.nil? && buffer.empty?
          raise BadRequest, "connection ended before request headers" if chunk.nil? && invalid_line_break?(buffer, final: true)
          raise BadRequest, "connection ended before request headers" if chunk.nil?

          buffer << chunk
        end
      end

      def read_line(socket, buffer, limit)
        deadline = monotonic_time + @read_timeout
        loop do
          index = buffer.index(CRLF)
          if index
            length = index + CRLF.bytesize
            raise HeaderTooLarge if length > limit

            line = buffer.byteslice(0, index)
            buffer.replace(buffer.byteslice(length..)&.dup || +"".b)
            return line
          end
          raise HeaderTooLarge if buffer.bytesize >= limit
          raise BadRequest, "line break must be CRLF" if invalid_line_break?(buffer)

          chunk = read_from_socket(socket, MAX_READ_CHUNK, deadline: deadline)
          raise BadRequest, "connection ended before line terminator" if chunk.nil? && invalid_line_break?(buffer, final: true)
          raise BadRequest, "connection ended before line terminator" if chunk.nil?

          buffer << chunk
        end
      end

      def invalid_line_break?(buffer, final: false)
        bytes = buffer.bytes
        bytes.each_with_index do |byte, index|
          if byte == 0x0a
            return true if index.zero? || bytes[index - 1] != 0x0d
          elsif byte == 0x0d
            next_byte = bytes[index + 1]
            return true if next_byte && next_byte != 0x0a
            return true if final && next_byte.nil?
          end
        end
        false
      end

      def read_exact(socket, buffer, length)
        return "".b if length.zero?

        deadline = monotonic_time + @read_timeout
        output = +"".b
        if buffer.bytesize >= length
          output << buffer.byteslice(0, length)
          buffer.replace(buffer.byteslice(length..)&.dup || +"".b)
          return output
        end

        output << buffer
        buffer.clear
        while output.bytesize < length
          chunk = read_from_socket(socket, [MAX_READ_CHUNK, length - output.bytesize].min, deadline: deadline)
          raise BadRequest, "connection ended before request body completed" if chunk.nil?

          output << chunk
        end
        output
      end

      def read_from_socket(socket, length, deadline:)
        loop do
          wait_for_io(socket, readable: true, deadline: deadline)
          data = socket.readpartial(length)
          return data.b
        rescue IO::WaitReadable
          next
        rescue IO::WaitWritable
          wait_for_io(socket, readable: false, deadline: deadline)
        rescue EOFError
          return nil
        end
      end

      def wait_for_io(socket, readable:, deadline:)
        remaining = deadline - monotonic_time
        raise RequestTimeout if remaining <= 0

        readers = readable ? [socket] : nil
        writers = readable ? nil : [socket]
        ready = IO.select(readers, writers, nil, remaining)
        raise RequestTimeout unless ready
      rescue IOError, Errno::EBADF
        raise
      end

      def invoke_handler(request)
        handler_request = request_for_handler(request)
        return @handler if @static_handler

        if @handler.is_a?(Hash)
          route = @handler[request.path] || @handler[request.target] || @handler[:default] || @handler["default"]
          return invoke_callable(route, handler_request, keyword_source: request) if route.respond_to?(:call)
          return route unless route.nil?

          return Response.json(status_payload(404, "NotFound", "route not found"), status: 404)
        end

        invoke_callable(@handler, handler_request, keyword_source: request)
      end

      def request_for_handler(request)
        return @request_factory.call(request) if @request_factory
        return request if @request_class.nil? && !api_server_handler?

        klass = @request_class
        klass ||= Rubernetes::API::Request if defined?(Rubernetes::API::Request) && api_server_handler?
        return request if klass.nil? || klass == Request

        attributes = {
          method: request.method,
          path: request.path,
          # API::Request reads the collection itself, keeping repeated fields.
          headers: klass == Rubernetes::API::Request ? request.headers : request.headers.to_h,
          query: request.query,
          body: request.body
        }
        if klass.instance_method(:initialize).parameters.any? do |kind, name|
          kind == :keyrest || (%i[key keyreq].include?(kind) && name == :client_certificate)
        end
          attributes[:client_certificate] = request.respond_to?(:client_certificate) ? request.client_certificate : nil
          attributes[:client_chain] = request.respond_to?(:client_chain) ? request.client_chain : []
          attributes[:remote_address] = request.remote_address
        end
        klass.new(**attributes)
      rescue ArgumentError, TypeError => error
        raise ResponseError, "cannot construct handler request: #{error.message}", cause: error
      end

      def api_server_handler?
        return false unless defined?(Rubernetes::API::Server)

        return true if @handler.is_a?(Rubernetes::API::Server)
        return @handler.receiver.is_a?(Rubernetes::API::Server) if @handler.is_a?(Method)

        false
      end

      def invoke_callable(callable, request, keyword_source: request)
        return callable.call(request) unless callable.respond_to?(:method)

        parameters = if callable.respond_to?(:parameters)
                       callable.parameters
                     else
                       callable.method(:call).parameters
                     end
        return callable.call if parameters.empty?

        keyword_parameters = parameters.select { |kind, _| %i[key keyreq keyrest].include?(kind) }
        unless keyword_parameters.empty?
          names = request_hash(keyword_source).merge(request: request)
          accepts_keywords = keyword_parameters.any? { |kind, _| kind == :keyrest }
          unless accepts_keywords
            accepted = keyword_parameters.filter_map { |_kind, name| name }.to_h { |name| [name, names[name]] }
            return callable.call(**accepted)
          end

          return callable.call(**names)
        end

        positional = parameters.count { |kind, _| %i[req opt rest].include?(kind) }
        return callable.call(request.method, request.path, request.headers, request.body) if positional >= 4

        callable.call(request)
      end

      def request_hash(request)
        return request.to_h if request.respond_to?(:to_h)

        {
          method: request.method,
          target: request.respond_to?(:target) ? request.target : request.path,
          path: request.path,
          query: request.respond_to?(:query) ? request.query : {},
          headers: request.headers,
          body: request.body
        }
      end

      def normalize_response(value)
        response = case value
                   when Response
                     value
                   when Array
                     if value.length == 3 && value.first.is_a?(Integer)
                       Response.new(status: value[0], headers: value[1] || {}, body: value[2])
                     else
                       Response.new(body: value)
                     end
                   when Hash
                     if response_hash?(value)
                       Response.new(
                         status: response_field(value, :status, :status_code, "statusCode") || 200,
                         headers: response_field(value, :headers) || {},
                         body: response_field(value, :body),
                         stream: response_field(value, :stream),
                         upgrade: response_field(value, :upgrade)
                       )
                     else
                       Response.new(body: value)
                     end
                   when String
                     Response.new(body: value)
                   when nil
                     Response.new(status: 204, body: "")
                   else
                     object_response(value)
                   end

        body = response.body
        headers = response.headers.dup
        if body.is_a?(Hash) || (body.is_a?(Array) && !response.stream?)
          body = JSON.generate(body)
          value.body_encoded(body.bytesize) if value.respond_to?(:body_encoded)
          headers.set("Content-Type", "application/json; charset=utf-8") unless headers.include?("content-type")
          return Response.new(status: response.status, headers: headers, body: body, stream: false,
                              upgrade: response.upgrade, unbounded: response.unbounded?)
        end

        headers.set("Content-Type", "application/json; charset=utf-8") if response.stream? && !headers.include?("content-type")
        Response.new(status: response.status, headers: headers, body: body, stream: response.stream?,
                     upgrade: response.upgrade, unbounded: response.unbounded?)
      rescue JSON::GeneratorError, ResponseError, ArgumentError, TypeError => error
        raise ResponseError, "handler returned an invalid response: #{error.message}", cause: error
      end

      def response_hash?(value)
        keys = value.keys.map(&:to_s)
        keys.include?("status") || keys.include?("status_code") || keys.include?("statusCode") ||
          keys.include?("headers") || keys.include?("body") || keys.include?("stream") || keys.include?("upgrade")
      end

      def response_field(value, *keys)
        keys.each do |key|
          return value[key] if value.key?(key)

          string_key = key.to_s
          return value[string_key] if value.key?(string_key)
        end
        nil
      end

      def object_response(value)
        status = if value.respond_to?(:status)
                   value.status
                 elsif value.respond_to?(:status_code)
                   value.status_code
                 else
                   200
                 end
        headers = value.respond_to?(:headers) ? value.headers : {}
        body = value.respond_to?(:body) ? value.body : value.to_s
        body = value.encoded_body if value.respond_to?(:encoded_body) && value.encoded_body.is_a?(String)
        stream = value.respond_to?(:stream?) ? value.stream? : nil
        upgrade = value.respond_to?(:upgrade) ? value.upgrade : nil
        unbounded = value.respond_to?(:unbounded?) ? value.unbounded? : false
        Response.new(status: status, headers: headers, body: body, stream: stream, upgrade: upgrade,
                     unbounded: unbounded)
      end

      # A response goes out as a head and a body (two TLS records, two
      # segments).  With Nagle's algorithm on, the kernel held the second
      # small segment until the client acknowledged the first, and clients
      # delay that ACK by 40 ms: a 2 ms GET took 45 ms on the wire, every
      # request, on every connection.  kube-apiserver's Go runtime disables
      # Nagle on every accepted socket; so do we.
      def disable_nagle(client)
        io = client.respond_to?(:to_io) ? client.to_io : client
        io.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1) if io.respond_to?(:setsockopt)
      rescue SystemCallError, IOError
        nil
      end

      def write_response(socket, response, request:, keep_alive:)
        return write_upgrade_response(socket, response, request: request) if response.respond_to?(:upgrade?) && response.upgrade?

        headers = response.headers.dup
        body = response.body
        status = response.status
        no_body = response.no_body? || (request && request.method == "HEAD")
        stream = response.stream? && !no_body
        body_bytes = nil

        headers.delete("content-length")
        headers.delete("transfer-encoding")
        headers.delete("connection")
        headers.set("Date", Time.now.utc.httpdate) unless headers.include?("date")
        headers.set("Server", @server_name) unless headers.include?("server")

        if no_body
          body_bytes = body_to_bytes(body) unless response.no_body? || response.stream?
          headers.set("Content-Length", body_bytes.bytesize.to_s) if body_bytes && !response.no_body?
        elsif stream
          raise ResponseTooLarge, "response stream exceeds the configured limit" if @max_response_bytes.zero?

          headers.set("Transfer-Encoding", "chunked")
        else
          body_bytes = body_to_bytes(body)
          raise ResponseTooLarge, "response body exceeds #{@max_response_bytes} bytes" if body_bytes.bytesize > @max_response_bytes

          # kube-apiserver compresses a large response when the client offers
          # gzip (WithCompression); list responses are the reason clients ask
          # for it at all.  A small body is left alone: framing and CPU cost
          # more than the bytes saved.
          if gzip_requested?(request) && body_bytes.bytesize >= GZIP_MIN_BYTES && !headers.include?("content-encoding")
            body_bytes = gzip_bytes(body_bytes)
            headers.set("Content-Encoding", "gzip")
            headers.add("Vary", "Accept-Encoding") unless headers.include?("vary")
          end
          headers.set("Content-Length", body_bytes.bytesize.to_s)
        end

        connection = keep_alive && @default_keep_alive ? "keep-alive" : "close"
        headers.set("Connection", connection)
        status_line = "HTTP/1.1 #{status} #{STATUS_REASONS.fetch(status, "Unknown Status")}\r\n"
        header_data = +status_line
        headers.each do |name, _value|
          headers.raw_values(name).each do |value|
            header_data << "#{name}: #{value}\r\n"
          end
        end
        header_data << CRLF
        if header_data.bytesize > @max_response_header_bytes
          raise ResponseTooLarge,
                "response headers exceed #{@max_response_header_bytes} bytes"
        end

        if !no_body && !stream && body_bytes && !body_bytes.empty? && body_bytes.bytesize <= COALESCED_BODY_BYTES
          # One write for head and body: one TLS record, one segment, and
          # no dependence on the peer's ACK timing at all.
          write_all(socket, header_data.b << body_bytes, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
          return
        end

        write_all(socket, header_data.b, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
        return if no_body

        if stream
          write_stream(socket, body, request: request,
                                     unbounded: response.respond_to?(:unbounded?) && response.unbounded?)
        elsif body_bytes && !body_bytes.empty?
          write_all(socket, body_bytes, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
        end
      end

      # Bodies up to this size are sent in the same write as the head.  A TLS
      # record holds 16 KiB, so a small response then fits one record.
      COALESCED_BODY_BYTES = (16 * 1024) - 1024

      # kube-apiserver's compression threshold (128 KiB is the upstream
      # DefaultCompressionThreshold... it uses 128 * 1024).
      GZIP_MIN_BYTES = 128 * 1024

      def gzip_requested?(request)
        return false unless request.respond_to?(:header)

        request.header("accept-encoding").to_s.downcase.split(",").any? do |value|
          token, _, quality = value.strip.partition(";")
          next false unless ["gzip", "*"].include?(token)

          quality.strip != "q=0"
        end
      end

      def gzip_bytes(bytes)
        buffer = StringIO.new(+"".b)
        writer = Zlib::GzipWriter.new(buffer)
        begin
          writer.write(bytes)
        ensure
          writer.close
        end
        buffer.string
      end

      def write_upgrade_response(socket, response, request:)
        raise ResponseError, "HTTP upgrade responses must use status 101" unless response.status == 101

        headers = response.headers.dup
        headers.delete("content-length")
        headers.delete("transfer-encoding")
        headers.delete("connection")
        headers.set("Date", Time.now.utc.httpdate) unless headers.include?("date")
        headers.set("Server", @server_name) unless headers.include?("server")
        headers.set("Connection", "Upgrade")
        protocol = response.upgrade.respond_to?(:protocol) ? response.upgrade.protocol : headers["upgrade"]
        headers.set("Upgrade", protocol) unless protocol.to_s.empty? || headers.include?("upgrade")
        status_line = "HTTP/1.1 #{response.status} #{STATUS_REASONS.fetch(response.status, "Unknown Status")}\r\n"
        header_data = +status_line
        headers.each do |name, _value|
          headers.raw_values(name).each { |value| header_data << "#{name}: #{value}\r\n" }
        end
        header_data << CRLF
        if header_data.bytesize > @max_response_header_bytes
          raise ResponseTooLarge,
                "response headers exceed #{@max_response_header_bytes} bytes"
        end

        write_all(socket, header_data.b, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
        initial_data = request.respond_to?(:initial_data) ? request.initial_data : ""
        upgrade_socket = initial_data.empty? ? socket : BufferedSocket.new(socket, initial_data)
        response.upgrade.call(upgrade_socket, request)
      end

      def write_stream(socket, body, request:, unbounded: false)
        bytes_written = 0
        # Only an open-ended stream (a watch, a followed log) is watched for the
        # peer going away.  On TLS the probe consumes a byte, and a client that
        # reuses its keep-alive connection right after a bounded response sends
        # its next request while the probe is still running: the request lost
        # its first byte and the server waited for the rest of it (408, stalled
        # DELETEs -- conformance round 98).
        monitor = unbounded ? start_disconnect_monitor(socket, body) : nil
        # A metered stream (API::LongRunningBody) learns each piece's
        # encoded size: apiserver_watch_events_sizes.
        sizes = body.respond_to?(:piece_written)
        each_stream_piece(body) do |piece|
          encoded = encode_stream_piece(piece)
          next if encoded.empty?

          body.piece_written(encoded.bytesize) if sizes
          bytes_written += encoded.bytesize
          if !unbounded && bytes_written > @max_response_bytes
            raise ResponseTooLarge.new("response stream exceeds #{@max_response_bytes} bytes", partial: true)
          end

          frame = "#{encoded.bytesize.to_s(16)}\r\n".b + encoded + CRLF
          write_all(socket, frame, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
        end
        raise IOError, "peer closed during response stream" if stream_peer_disconnected?(monitor)

        write_all(socket, "0\r\n\r\n".b, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
      ensure
        stop_disconnect_monitor(monitor)
        close_stream_body(monitor, body)
      end

      def each_stream_piece(body, &)
        parameters = body.method(:each).parameters
        accepts_timeout = parameters.any? do |kind, name|
          (kind == :key && name == :timeout) || (kind == :keyreq && name == :timeout) || kind == :keyrest
        end
        if accepts_timeout
          body.each(timeout: nil, &)
        else
          body.each(&)
        end
      rescue NameError
        body.each(&)
      end

      # A watch enumerable can block waiting for its next event. A separate
      # lightweight peer monitor lets a client FIN/RST wake that enumerable so
      # its close hook unregisters server-side watcher state promptly.
      def start_disconnect_monitor(socket, body)
        mode = disconnect_monitor_mode(socket)
        return nil unless body.respond_to?(:close) && mode

        mutex = Mutex.new
        state = {stopped: false, closed: false, peer_disconnected: false, mutex: mutex}
        close_body = lambda do |peer_disconnected = false|
          should_close = mutex.synchronize do
            state[:peer_disconnected] ||= peer_disconnected
            next false if state[:closed]

            state[:closed] = true
            true
          end
          body.close if should_close
        rescue StandardError => error
          log(:warn, "HTTP stream close hook failed", error: error.class.name)
          nil
        end
        state[:close_body] = close_body
        start_gate = Queue.new
        thread = Thread.new do
          start_gate.pop
          wait_mode = :wait_readable
          loop do
            break if mutex.synchronize { state[:stopped] }

            readers = wait_mode == :wait_readable ? [socket] : nil
            writers = wait_mode == :wait_writable ? [socket] : nil
            ready = IO.select(readers, writers, nil, 0.1)
            next unless ready

            probe = probe_stream_peer(socket, mode)
            case probe
            when :closed
              close_body.call(true)
              break
            when :wait_writable
              wait_mode = :wait_writable
            when :wait_readable
              wait_mode = :wait_readable
            else
              wait_mode = :wait_readable
              sleep 0.01
            end
          end
        rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
          close_body.call(true)
        rescue NotImplementedError, ArgumentError, TypeError
          # A non-standard wrapper may not support either peer probe. The
          # normal write path still detects disconnects after the next event.
          nil
        rescue StandardError => error
          log(:debug, "HTTP stream disconnect monitor stopped", error: error.class.name)
        ensure
          unregister_stream_monitor(Thread.current)
        end
        thread.report_on_exception = false if thread.respond_to?(:report_on_exception=)
        thread.name = "rubernetes-http-stream-peer" if thread.respond_to?(:name=)
        state[:thread] = thread
        @mutex.synchronize { @stream_monitors[thread] = true }
        start_gate << true
        state
      rescue ThreadError
        nil
      end

      def stop_disconnect_monitor(state)
        return unless state

        thread = state[:thread]
        state[:mutex].synchronize { state[:stopped] = true }
        thread.join(0.2)
        if thread.alive?
          thread.kill
          thread.join(0.2)
        end
      rescue ThreadError
        nil
      ensure
        unregister_stream_monitor(thread) if thread
      end

      def close_stream_body(state, body)
        if state && state[:close_body]
          state[:close_body].call(false)
        elsif body.respond_to?(:close)
          body.close
        end
      rescue StandardError => error
        log(:warn, "HTTP stream close hook failed", error: error.class.name)
      end

      def disconnect_monitor_mode(socket)
        return :peek if socket.respond_to?(:recv_nonblock)
        return :tls_read if socket.is_a?(OpenSSL::SSL::SSLSocket) && socket.respond_to?(:read_nonblock)

        nil
      end

      def probe_stream_peer(socket, mode)
        value = if mode == :peek
                  socket.recv_nonblock(1, Socket::MSG_PEEK, exception: false)
                else
                  socket.read_nonblock(1, exception: false)
                end
        return value if %i[wait_readable wait_writable].include?(value)
        return :closed if value.nil? || value == ""

        # Bytes sent by a client while an unbounded response is in progress
        # cannot form a usable next HTTP request. For TLS they must be consumed
        # to process close_notify, so fail closed on any application byte.
        mode == :tls_read ? :closed : :alive
      rescue IO::WaitReadable
        :wait_readable
      rescue IO::WaitWritable
        :wait_writable
      end

      def stream_peer_disconnected?(state)
        return false unless state

        state[:mutex].synchronize { state[:peer_disconnected] }
      end

      def unregister_stream_monitor(thread)
        return unless thread

        @mutex.synchronize do
          @stream_monitors.delete(thread)
          @condition.broadcast
        end
      end

      def encode_stream_piece(piece)
        return piece.b if piece.is_a?(String)
        return "" if piece.nil?
        return "#{JSON.generate(piece)}\n" if piece.is_a?(Hash) || piece.is_a?(Array)

        if piece.respond_to?(:to_h)
          hash = piece.to_h
          return "#{JSON.generate(hash)}\n" if hash.is_a?(Hash)
        end

        String(piece).b
      rescue JSON::GeneratorError, TypeError => error
        raise ResponseError, "cannot encode response stream item: #{error.message}", cause: error
      end

      def body_to_bytes(body)
        return "".b if body.nil?
        return body.b if body.is_a?(String)
        return JSON.generate(body).b if body.is_a?(Hash) || body.is_a?(Array)

        String(body).b
      rescue JSON::GeneratorError, TypeError => error
        raise ResponseError, "cannot encode response body: #{error.message}", cause: error
      end

      def keep_alive_for?(request, count)
        return false if count >= @max_requests_per_connection

        tokens = request.headers.raw_values("connection").flat_map { |value| value.split(",").map { |token| token.strip.downcase } }
        return false if tokens.include?("close")
        return true if request.http_version == "HTTP/1.1"

        tokens.include?("keep-alive")
      end

      def error_response(error)
        status = if error.respond_to?(:status)
                   Integer(error.status)
                 elsif error.respond_to?(:status_code)
                   Integer(error.status_code)
                 elsif error.respond_to?(:code) && error.code.to_s.match?(/\A[1-5][0-9]{2}\z/)
                   Integer(error.code)
                 else
                   500
                 end
        code = if error.respond_to?(:reason) && !error.reason.nil?
                 error.reason.to_s
               elsif error.respond_to?(:code)
                 error.code.to_s
               else
                 STATUS_REASONS.fetch(status, "InternalError").delete(" ")
               end
        message = if error.is_a?(RequestError) || error.respond_to?(:status) || error.respond_to?(:status_code) || error.respond_to?(:reason)
                    error.message
                  else
                    "the server could not complete the request"
                  end
        Response.json(status_payload(status, code, message), status: status)
      rescue StandardError
        Response.new(status: 500, headers: {"Content-Type" => "application/json"}, body: "{\"status\":\"Failure\"}")
      end

      def write_error(socket, error, request: nil)
        write_response(socket, error_response(error), request: request, keep_alive: false)
      rescue ResponseTooLarge
        write_raw_error(socket)
      rescue ResponseTimeout, IOError, SystemCallError, OpenSSL::SSL::SSLError
        nil
      end

      def write_raw_error(socket)
        body = "{\"status\":\"Failure\",\"code\":500}".b
        response = "HTTP/1.1 500 Internal Server Error\r\n" \
                   "Content-Type: application/json\r\n" \
                   "Content-Length: #{body.bytesize}\r\n" \
                   "Connection: close\r\n\r\n".b
        write_all(socket, response + body, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
      rescue ResponseTimeout, IOError, SystemCallError, OpenSSL::SSL::SSLError
        nil
      end

      def status_payload(status, reason, message)
        {
          kind: "Status",
          apiVersion: "v1",
          metadata: {},
          status: "Failure",
          reason: reason,
          message: message,
          code: status
        }
      end

      def remote_address(socket)
        socket.peeraddr[3]
      rescue IOError, SystemCallError
        nil
      end

      def write_all(socket, data, deadline:, timeout_error: nil)
        offset = 0
        while offset < data.bytesize
          begin
            wait_for_io(socket, readable: false, deadline: deadline)
            written = socket.write_nonblock(data.byteslice(offset..), exception: false)
            case written
            when :wait_writable
              next
            when :wait_readable
              wait_for_io(socket, readable: true, deadline: deadline)
            when Integer
              raise IOError, "socket write returned zero bytes" if written <= 0

              offset += written
            else
              raise IOError, "socket write returned an invalid result"
            end
          rescue IO::WaitWritable
            next
          rescue IO::WaitReadable
            wait_for_io(socket, readable: true, deadline: deadline)
          end
        end
      rescue RequestTimeout => error
        raise(timeout_error || RequestTimeout, error.message, cause: error)
      end

      def close_listener
        [@listener, @tcp_listener].compact.uniq.each { |socket| close_socket(socket) }
        @listener = nil
        @tcp_listener = nil
        @ssl_context = nil
      end

      def close_socket(socket)
        socket.close unless socket.closed?
      rescue IOError, SystemCallError
        nil
      end

      def join_thread(thread, timeout:, except: nil)
        return if thread.nil? || thread == except || !thread.respond_to?(:join)

        thread.join(timeout)
      rescue ThreadError
        nil
      end

      def remaining(deadline)
        return nil unless deadline

        [deadline - monotonic_time, 0.0].max
      end

      def monotonic_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def log(level, message, **fields)
        return unless @logger

        if @logger.respond_to?(level)
          @logger.public_send(level, message, **fields)
        elsif @logger.respond_to?(:call)
          @logger.call(level, message, fields)
        end
      rescue StandardError
        nil
      end

      # Bytes read together with an upgrade request belong to the upgraded
      # protocol, not to a subsequent HTTP request.  The parser keeps those
      # bytes in the connection buffer; this adapter makes them visible to
      # the duplex handler before reading from the socket.
      class BufferedSocket
        def initialize(socket, prefix)
          @socket = socket
          @prefix = String(prefix).b
        end

        def read(length = nil)
          return @socket.read(length) if @prefix.empty?
          return @prefix.tap { @prefix = "".b } if length.nil?

          length = Integer(length)
          return "".b if length.zero?

          prefix = @prefix.byteslice(0, length)
          if prefix.bytesize == length
            @prefix = @prefix.byteslice(length..)&.b || "".b
            prefix
          else
            @prefix = "".b
            suffix = @socket.read(length - prefix.bytesize)
            prefix + suffix.to_s.b
          end
        end

        def readpartial(length, buffer = nil)
          value = read(length)
          raise EOFError if value.nil? || value.empty?

          if buffer
            buffer.replace(value)
            buffer
          else
            value
          end
        end

        def write(data)
          @socket.write(data)
        end

        def write_nonblock(*, **)
          @socket.write_nonblock(*, **)
        end

        def to_io
          @socket.respond_to?(:to_io) ? @socket.to_io : @socket
        end

        def closed?
          @socket.closed?
        end

        def close
          @socket.close
        end
      end
    end

    HTTPServer::Adapter = HTTPServer unless HTTPServer.const_defined?(:Adapter, false)
    HTTPServer::Server = HTTPServer unless HTTPServer.const_defined?(:Server, false)
    HTTPAdapter = HTTPServer unless const_defined?(:HTTPAdapter, false)
    HTTP = HTTPServer unless const_defined?(:HTTP, false)
    Server = HTTPServer unless const_defined?(:Server, false)
  end
end
