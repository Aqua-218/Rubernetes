# frozen_string_literal: true

require "json"
require "ipaddr"
require "net/http"
require "rbconfig"
require "digest"
require "openssl"
require "uri"

require_relative "../cleanup"
require_relative "../version"
require_relative "errors"

module Rubernetes
  module Client
    # Small, injectable Net::HTTP transport for Kubernetes JSON REST requests.
    class HTTPClient
      DEFAULT_OPEN_TIMEOUT = 10
      DEFAULT_READ_TIMEOUT = 60
      DEFAULT_WRITE_TIMEOUT = 60
      MAX_CREDENTIAL_FILE_BYTES = 16 * 1024 * 1024
      MAX_STREAM_ERROR_BODY_BYTES = 1024 * 1024
      SUCCESS_STATUS_RANGE = (200..299)

      StreamSession = Struct.new(:resource, :close_requested, :close_in_progress, :close_succeeded,
                                 :close_error, keyword_init: true)

      Response = Struct.new(:status, :headers, :body, keyword_init: true) do
        def success?
          (200..299).cover?(status)
        end

        def [](name)
          headers[name.to_s.downcase]
        end

        def json
          return nil if body.nil? || body.empty?

          JSON.parse(body)
        rescue JSON::ParserError => error
          raise Client::Error.new("response body is not valid JSON: #{error.message}", cause: error), cause: error
        end
      end

      attr_reader :context, :user_agent

      # The upstream component each executable stands in for, as the command
      # client-go puts first in its User-Agent (and the API server takes as
      # the field manager of a write without fieldManager).
      UPSTREAM_COMMANDS = {
        "rubernetes-agent" => "kubelet",
        "rubernetes-controller-manager" => "kube-controller-manager",
        "rubernetes-scheduler" => "kube-scheduler",
        "rubernetes-proxy" => "kube-proxy",
        "rubernetes-apiserver" => "kube-apiserver",
        "rubectl" => "kubectl"
      }.freeze
      GIT_VERSION = Rubernetes::KUBERNETES_GIT_VERSION
      GIT_COMMIT = ""
      # rest.DefaultKubernetesUserAgent:
      # "<command>/<version> (<os>/<arch>) kubernetes/<commit>".
      def self.default_user_agent(command: $PROGRAM_NAME)
        name = File.basename(command.to_s)
        name = UPSTREAM_COMMANDS.fetch(name, name)
        name = "unknown" if name.empty?
        version = GIT_VERSION.split("-", 2).first
        commit = GIT_COMMIT.empty? ? "unknown" : GIT_COMMIT[0, 7]
        "#{name}/#{version} (#{Rubernetes.go_platform}) kubernetes/#{commit}"
      end

      # The transport dependencies are injectable so callers can use a deterministic fake without
      # opening a socket. Production calls use Net::HTTP by default.
      def initialize(
        context: nil,
        server: nil,
        token: nil,
        namespace: nil,
        ca_file: nil,
        ca_data: nil,
        client_certificate_file: nil,
        client_certificate_data: nil,
        client_key_file: nil,
        client_key_data: nil,
        insecure_skip_tls_verify: false,
        http: nil,
        http_class: Net::HTTP,
        http_factory: nil,
        transport: nil,
        open_timeout: DEFAULT_OPEN_TIMEOUT,
        read_timeout: DEFAULT_READ_TIMEOUT,
        write_timeout: DEFAULT_WRITE_TIMEOUT,
        user_agent: nil,
        max_retries: DEFAULT_MAX_RETRIES,
        retry_sleeper: ->(seconds) { sleep(seconds) }
      )
        @user_agent = (user_agent || self.class.default_user_agent).to_s
        @max_retries = Integer(max_retries)
        @retry_sleeper = retry_sleeper
        @context = context || {
          server: server,
          bearer_token: token,
          namespace: namespace,
          ca_file: ca_file,
          ca_data: ca_data,
          client_certificate_file: client_certificate_file,
          client_certificate_data: client_certificate_data,
          client_key_file: client_key_file,
          client_key_data: client_key_data,
          insecure_skip_tls_verify: insecure_skip_tls_verify
        }
        @http_factory = http_factory || build_factory(http, http_class)
        @transport = transport
        @stream_mutex = Mutex.new
        @stream_condition = ConditionVariable.new
        @active_streams = {}.compare_by_identity
        @pool = {}
        @pool_mutex = Mutex.new
        @closed = false
        @open_timeout = Integer(open_timeout)
        @read_timeout = Integer(read_timeout)
        @write_timeout = Integer(write_timeout)
        validate_timeouts!
        @base_uri = parse_base_uri(context_value(:server))
        validate_bearer_token!
        validate_server_credential_transport!
        RestClientMetrics.transport_created(tls_cache_key) unless @transport
      rescue ArgumentError => error
        raise ConfigurationError.new("HTTP client timeout must be a non-negative integer: #{error.message}", cause: error), cause: error
      end

      # client-go rest.Request: at most ten retries.
      DEFAULT_MAX_RETRIES = 10
      # net.IsConnectionReset / IsProbableEOF / IsHTTP2ConnectionLost: the
      # transport errors a GET is retried after.
      RETRYABLE_TRANSPORT_ERRORS = [Errno::ECONNRESET, Errno::EPIPE, EOFError].freeze

      # Sends one HTTP request and returns a Response. Non-2xx responses are returned so callers
      # can inspect Status details; use request! when an exception is preferable.
      #
      # As client-go's Request.request: a 429 or 5xx answer with an integer
      # Retry-After is sent again after that many seconds, and a GET whose
      # connection was reset or cut short is sent again after one second, up
      # to DEFAULT_MAX_RETRIES times.  Every attempt counts in
      # rest_client_requests_total, every one after the first in
      # rest_client_request_retries_total; the latency covers them all.
      def request(method, path, body: nil, headers: {}, query: nil)
        normalized_method = normalize_method(method)
        uri = build_uri(path, query)
        request_headers = build_headers(headers, body)
        request_body = encode_body(body, request_headers)

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        attempts = 0
        normalized = nil
        begin
          loop do
            retry_attempt = attempts.positive?
            response = begin
              if @transport
                call_transport(normalized_method, uri, request_body, request_headers)
              else
                call_http(normalized_method, uri, request_body, request_headers)
              end
            rescue StandardError => error
              RestClientMetrics.attempt(normalized_method, uri, "<error>", request_body.to_s.bytesize, retry_attempt)
              wait = retryable_error_wait(normalized_method, error, attempts)
              raise if wait.nil?

              attempts += 1
              @retry_sleeper.call(wait)
              next
            end
            normalized = normalize_response(response)
            RestClientMetrics.attempt(normalized_method, uri, normalized.status, request_body.to_s.bytesize, retry_attempt)
            wait = retry_after_wait(normalized, attempts)
            break if wait.nil?

            attempts += 1
            @retry_sleeper.call(wait)
          end
        ensure
          RestClientMetrics.latency(normalized_method, uri, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                                    normalized&.body.to_s.bytesize)
        end
        normalized
      rescue APIError, ConfigurationError, Error
        raise
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout, Net::HTTPBadResponse,
             IOError, SocketError, SystemCallError, OpenSSL::SSL::SSLError => error
        raise TransportError.new("HTTP #{normalized_method} #{uri}: #{error.message}", cause: error), cause: error
      rescue URI::InvalidURIError => error
        raise ConfigurationError.new("invalid Kubernetes API URL: #{error.message}", cause: error), cause: error
      end

      # Streams response body chunks without buffering a long-running Kubernetes watch in
      # memory. The returned response contains status and headers; successful body bytes are
      # delivered only to the block. Error responses are bounded and raised as APIError.
      def stream(method, path, body: nil, headers: {}, query: nil, &block)
        return enum_for(__method__, method, path, body: body, headers: headers, query: query) unless block

        normalized_method = normalize_method(method)
        uri = build_uri(path, query)
        request_headers = build_headers(headers, body)
        request_body = encode_body(body, request_headers)

        if @transport
          session = register_stream(@transport)
          begin
            response = normalize_response(call_transport(normalized_method, uri, request_body, request_headers))
            raise_for_status!(response, normalized_method, path) unless response.success?
            each_stream_body_chunk(response.body, &block)
            Response.new(status: response.status, headers: response.headers, body: "")
          ensure
            unregister_stream(session)
          end
        else
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          first = true
          counted = lambda do |code|
            next unless first

            first = false
            RestClientMetrics.record(normalized_method, uri, code, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                                     request_body.to_s.bytesize, nil)
          end
          begin
            call_http_stream(normalized_method, uri, request_body, request_headers) do |chunk|
              counted.call(200)
              yield(chunk)
            end
          rescue APIError => error
            counted.call(error.status)
            raise
          rescue StandardError
            counted.call("<error>")
            raise
          ensure
            counted.call(200)
          end
        end
      rescue APIError, ConfigurationError, Error
        raise
      rescue Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout, Net::HTTPBadResponse,
             IOError, SocketError, SystemCallError, OpenSSL::SSL::SSLError => error
        raise TransportError.new("HTTP #{normalized_method} #{uri}: #{error.message}", cause: error), cause: error
      rescue URI::InvalidURIError => error
        raise ConfigurationError.new("invalid Kubernetes API URL: #{error.message}", cause: error), cause: error
      end

      # tlsConfigKey: what the TLS transport is keyed by (loadTLSFiles reads
      # the files first); the server is not part of it.
      def tls_cache_key
        read = lambda { |path|
          if path
            begin
              File.binread(path)
            rescue StandardError
              path.to_s
            end
          end
        }
        [context_value(:ca_data) || context_value(:certificate_authority_data) ||
          read.call(context_value(:ca_file) || context_value(:certificate_authority_file)),
         context_value(:client_certificate_data) || read.call(context_value(:client_certificate_file)),
         context_value(:client_key_data) || read.call(context_value(:client_key_file)),
         context_value(:insecure_skip_tls_verify) == true].hash
      end
      private :tls_cache_key

      # checkWait: 429 or any 5xx with an integer Retry-After.
      def retry_after_wait(response, attempts)
        return nil if attempts >= @max_retries
        return nil unless response.status == 429 || response.status >= 500

        value = response.headers.find { |name, _| name.to_s.casecmp("retry-after").zero? }&.last
        value = value.first if value.is_a?(Array)
        return nil unless value.to_s.match?(/\A-?\d+\z/)

        [Integer(value.to_s), 0].max
      end

      # isErrRetryableFunc: only a GET, only after a reset or cut-short
      # connection, with retryAfterResponse's one second.
      def retryable_error_wait(method, error, attempts)
        return nil if attempts >= @max_retries || method != "GET"
        return nil unless RETRYABLE_TRANSPORT_ERRORS.any? { |kind| error.is_a?(kind) } ||
                          error.message.to_s.match?(/connection reset by peer|use of closed network connection|http2: client connection lost/i)

        1
      end

      # Sends one request and raises APIError for a non-2xx response.
      def request!(method, path, body: nil, headers: {}, query: nil)
        response = request(method, path, body: body, headers: headers, query: query)
        raise_for_status!(response, method, path) unless response.success?

        response
      end

      # client-go transport.UpdateTransport's closeAllConns after a client
      # certificate rotation: pooled keep-alive sessions are abandoned (the
      # next request handshakes again, presenting the new certificate) and
      # active streams are interrupted so their watchers reconnect.  Unlike
      # #close the client stays usable.
      def reset_connections!
        sessions = @stream_mutex.synchronize do
          @connection_generation = connection_generation + 1
          @active_streams.values.dup
        end
        drain_pool!
        errors = []
        sessions.each do |session|
          errors.concat(close_stream_session(session))
        rescue StandardError => error
          errors << error
        end
        errors
      end

      def connection_generation
        @connection_generation || 0
      end

      # Interrupts every active streaming request. A Net::HTTP read can block
      # forever when read_timeout is zero, so shutdown closes the session's
      # socket rather than relying on a timeout. The caller that owns the
      # streaming thread remains responsible for joining it.
      def close
        drain_pool!
        sessions, transport = @stream_mutex.synchronize do
          @closed = true
          current = @active_streams.values.dup
          tracked_transport = current.any? { |session| session.resource.equal?(@transport) }
          [current, tracked_transport ? nil : @transport]
        end

        errors = []
        closed_resources = {}
        sessions.each do |session|
          resource_key = session.resource.object_id
          if closed_resources.key?(resource_key)
            close_result = closed_resources.fetch(resource_key)
            set_stream_close_result(session, close_result)
            next
          end

          begin
            close_result = close_stream_session(session)
            closed_resources[resource_key] = close_result
            errors.concat(close_result)
          rescue StandardError => error
            closed_resources[resource_key] = [error]
            errors << error
          end
        end
        if transport.respond_to?(:close)
          begin
            errors.concat(close_resource(transport))
          rescue StandardError => error
            errors << error
          end
        end
        aggregate = Rubernetes::Cleanup.aggregate(errors, operation: "HTTP client close")
        raise aggregate if aggregate

        self
      end

      # Converts a failed response into a Kubernetes-shaped APIError without exposing credentials.
      def raise_for_status!(response, method = nil, path = nil)
        return response if response.success?

        status_object = parse_status(response.body)
        detail = status_object.is_a?(Hash) ? status_object["message"] : nil
        detail = detail.to_s unless detail.nil?
        detail = redact_bearer_token(detail) unless detail.nil?
        operation = [method, path].compact.join(" ")
        message = "Kubernetes API request#{" #{operation}" unless operation.empty?} failed with HTTP #{response.status}"
        message = "#{message}: #{detail}" unless detail.nil? || detail.empty?
        raise APIError.new(message, response: response, status_object: status_object)
      end

      private

      def build_factory(http, http_class)
        return ->(_uri) { http } if http
        return ->(uri) { http_class.new(uri.hostname, uri.port) } if http_class

        raise ArgumentError, "http_class or http must be provided"
      end

      def validate_timeouts!
        [@open_timeout, @read_timeout, @write_timeout].each do |timeout|
          raise ArgumentError, "timeout must be non-negative" if timeout.negative?
        end
      end

      def validate_bearer_token!
        token = context_value(:bearer_token) || context_value(:token)
        return if token.nil?
        raise ConfigurationError, "Kubernetes bearer token must be a non-empty string" unless token.is_a?(String) && !token.empty?
        return if token.b.match?(/\A[!-~]+\z/n)

        raise ConfigurationError, "Kubernetes bearer token must contain only printable ASCII without whitespace"
      end

      def redact_bearer_token(value)
        token = context_value(:bearer_token) || context_value(:token)
        return value.to_s if token.nil? || token.to_s.empty?

        value.to_s.b.gsub(token.to_s.b, "[REDACTED]".b).force_encoding(value.to_s.encoding)
      end

      def validate_server_credential_transport!
        token = context_value(:bearer_token) || context_value(:token)
        return if token.nil? || @base_uri.scheme == "https" || loopback_host?(@base_uri.host)

        raise ConfigurationError, "Kubernetes bearer tokens require https for non-loopback API servers"
      end

      def loopback_host?(host)
        normalized = host.to_s.delete_prefix("[").delete_suffix("]")
        return true if normalized.casecmp?("localhost")

        IPAddr.new(normalized).loopback?
      rescue IPAddr::InvalidAddressError
        false
      end

      def context_value(key)
        if @context.respond_to?(key)
          @context.public_send(key)
        elsif @context.is_a?(Hash)
          @context[key] || @context[key.to_s]
        end
      end

      def parse_base_uri(server)
        raise ConfigurationError, "Kubernetes API server is required" unless server.is_a?(String) && !server.empty?

        uri = URI.parse(server)
        unless %w[http https].include?(uri.scheme) && uri.host && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
          raise ConfigurationError, "Kubernetes API server must be an http(s) URL without embedded credentials"
        end

        uri
      rescue URI::InvalidURIError => error
        raise ConfigurationError.new("Kubernetes API server is not a valid URL", cause: error), cause: error
      end

      def normalize_method(method)
        normalized = method.to_s.upcase
        raise UsageError, "HTTP method must contain only ASCII token characters" unless normalized.match?(/\A[A-Z][A-Z0-9-]*\z/)

        normalized
      end

      def build_uri(path, query)
        path_value = path.to_s
        raise UsageError, "REST path must be a non-empty relative API path" if path_value.empty?
        raise UsageError, "REST path must not contain control characters" if path_value.match?(/[\x00-\x1f\x7f]/)
        raise UsageError, "REST path must not contain backslashes" if path_value.include?("\\")
        if path_value.match?(%r{\A(?:[a-z][a-z0-9+.-]*:)?//}i) || path_value.match?(/\A[a-z][a-z0-9+.-]*:/i)
          raise UsageError, "REST path must not contain an absolute URL"
        end

        path_uri = URI.parse(path_value.start_with?("/") ? path_value : "/#{path_value}")
        raise UsageError, "REST path must not contain a fragment" if path_uri.fragment

        base_path = @base_uri.path.to_s
        base_path = "" if base_path == "/"
        joined_path = "#{base_path}/#{path_uri.path}".squeeze("/")
        joined_path = "/" if joined_path.empty?
        query_values = merge_query_values(path_uri.query, query)
        query_string = query_values.empty? ? nil : query_values.join("&")

        uri_class = @base_uri.scheme == "https" ? URI::HTTPS : URI::HTTP
        uri_class.build(
          scheme: @base_uri.scheme,
          userinfo: nil,
          host: @base_uri.host,
          port: @base_uri.port,
          path: joined_path,
          query: query_string,
          fragment: nil
        )
      rescue URI::InvalidURIError => error
        raise ConfigurationError.new("invalid REST path #{path_value.inspect}: #{error.message}", cause: error), cause: error
      end

      def encode_query(query)
        return nil if query.nil?

        if query.is_a?(String)
          raise UsageError, "REST query must not contain control characters" if query.match?(/[\x00-\x1f\x7f]/)

          return query
        end
        raise UsageError, "REST query must be a mapping or encoded query string" unless query.respond_to?(:to_hash)

        URI.encode_www_form(query.to_hash.flat_map do |key, value|
          value.is_a?(Array) ? value.map { |item| [key, item] } : [[key, value]]
        end)
      end

      # Explicit query options are authoritative over query parameters embedded in a raw path.
      # This matters for security-sensitive options such as watch=true: a path supplied as
      # "...?watch=false" must not be able to override the client-enforced value.
      def merge_query_values(path_query, query)
        encoded_query = encode_query(query)
        return [path_query].compact.reject(&:empty?) if encoded_query.nil?
        return [encoded_query, path_query].compact.reject(&:empty?) unless query.respond_to?(:to_hash)

        explicit_names = query.to_hash.keys.map(&:to_s)
        path_pairs = URI.decode_www_form(path_query.to_s).reject do |name, _value|
          explicit_names.include?(name)
        end
        values = []
        values << URI.encode_www_form(path_pairs) unless path_pairs.empty?
        values << encoded_query unless encoded_query.empty?
        values
      rescue ArgumentError => error
        raise UsageError.new("REST path query is not valid form encoding: #{error.message}", cause: error), cause: error
      end

      def build_headers(headers, body)
        raise UsageError, "HTTP headers must be a mapping" unless headers.respond_to?(:to_hash)

        result = {}
        headers.to_hash.each do |key, value|
          name = key.to_s
          header_value = value.to_s
          raise UsageError, "HTTP header names must use ASCII token characters" unless name.match?(/\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/)
          raise UsageError, "HTTP headers must not contain control characters" if header_value.match?(/[\x00-\x1f\x7f]/)

          result[name] = header_value
        end
        result["Accept"] = "application/json" unless result.keys.any? { |key| key.casecmp?("Accept") }
        result["User-Agent"] = @user_agent unless @user_agent.empty? || result.keys.any? { |key| key.casecmp?("User-Agent") }
        result["Content-Type"] = "application/json" if body && result.keys.none? { |key| key.casecmp?("Content-Type") }
        unless result.keys.any? { |key| key.casecmp?("Authorization") }
          token = context_value(:bearer_token) || context_value(:token)
          result["Authorization"] = "Bearer #{token}" if token && !token.to_s.empty?
        end
        result
      end

      def encode_body(body, _headers)
        return nil if body.nil?
        return body if body.is_a?(String)

        JSON.generate(body)
      rescue JSON::GeneratorError => error
        raise UsageError.new("request body cannot be encoded as JSON: #{error.message}", cause: error), cause: error
      end

      def call_transport(method, uri, body, headers)
        result = @transport.call(method, uri, body: body, headers: headers, context: @context)
        return result if result.is_a?(Response)

        result
      rescue ArgumentError => error
        raise TransportError.new("injected HTTP transport rejected request: #{error.message}", cause: error), cause: error
      end

      # One TLS connection per API call cost every controller write a full
      # handshake -- on both ends; the API server spent its CPU on RSA for
      # clients that then sent one request and hung up.  A ReplicationController
      # needed 19 s to create 100 Pods that the server itself handles in about
      # 30 ms each.  Plain requests now reuse a started Net::HTTP per thread
      # and server (the API server keeps connections alive); a connection the
      # server closed in the meantime is dropped and the request retried once.
      # Streams keep their own connection, as before, and an injected adapter
      # (tests) is used exactly as given.
      SESSIONS_KEY = :rubernetes_http_sessions
      # Below the API server's 30 s idle read timeout, so Net::HTTP reopens a
      # connection that sat idle longer instead of writing into one the
      # server has already closed.
      KEEP_ALIVE_TIMEOUT_SECONDS = 20
      CONNECTION_ERRORS = [IOError, EOFError, Errno::ECONNRESET, Errno::EPIPE, Errno::ECONNREFUSED,
                           Net::HTTPBadResponse, OpenSSL::SSL::SSLError].freeze

      def call_http(method, uri, body, headers)
        http = @http_factory.call(uri)
        request = build_request(method, uri, body, headers)
        return persistent_request(http, uri, request) if http.is_a?(Net::HTTP) && !http.started?

        configure_http(http, uri)
        if http.respond_to?(:request)
          http.request(request)
        elsif http.respond_to?(:start)
          http.start { |session| session.request(request) }
        else
          raise TransportError, "HTTP adapter must respond to start or request"
        end
      end

      # Connections are pooled per client and server, shared by every thread:
      # the earlier per-thread sessions gave each Pod worker thread (one per
      # Pod, retired when idle) its own TLS handshake, so a node paid one
      # handshake per Pod for the ServiceAccount token request alone.  A
      # request checks an idle connection out (or starts one -- never waits),
      # uses it alone, and checks it back in only when its response was fully
      # read; a connection the server closed is replaced and the request
      # retried once, and a connection from an earlier generation (certificate
      # rotation) is finished instead of reused.
      POOL_MAX_IDLE_PER_SERVER = 8

      def persistent_request(fresh, uri, request)
        generation = connection_generation
        key = "#{generation}|#{uri.scheme}://#{uri.hostname}:#{uri.port}"
        session = checkout_connection(key, generation) || start_session(fresh, uri)
        response = nil
        begin
          response = session.request(request)
        rescue *CONNECTION_ERRORS
          finish_connection(session)
          session = start_session(@http_factory.call(uri), uri)
          begin
            response = session.request(request)
          rescue StandardError
            finish_connection(session)
            raise
          end
        rescue StandardError
          finish_connection(session)
          raise
        end
        checkin_connection(key, generation, session, response)
        response
      end

      def checkout_connection(key, generation)
        @pool_mutex.synchronize do
          # Idle connections of an earlier generation are finished, not reused.
          stale = @pool.keys.reject { |existing| existing.start_with?("#{generation}|") }
          stale.each { |existing| @pool.delete(existing).each { |old| finish_connection(old) } }
          idle = @pool[key]
          while idle && !idle.empty?
            candidate = idle.pop
            return candidate if candidate.started?
          end
          nil
        end
      end

      def checkin_connection(key, generation, session, response)
        clean = session.started? && response_fully_read?(response) && generation == connection_generation && !@closed
        return finish_connection(session) unless clean

        @pool_mutex.synchronize do
          idle = (@pool[key] ||= [])
          if idle.length >= POOL_MAX_IDLE_PER_SERVER
            finish_connection(session)
          else
            idle << session
          end
        end
      end

      # Net::HTTP#request without a block reads the whole body before it
      # returns; a response still holding an open body would leave bytes on
      # the connection for the next request.
      def response_fully_read?(response)
        return true unless response.respond_to?(:instance_variable_get)

        read = response.instance_variable_get(:@read)
        read.nil? || read == true
      end

      def finish_connection(session)
        session.finish if session.respond_to?(:started?) && session.started?
      rescue StandardError
        nil
      end

      def drain_pool!
        idle = @pool_mutex.synchronize do
          all = @pool.values.flatten
          @pool.clear
          all
        end
        idle.each { |session| finish_connection(session) }
      end

      def start_session(http, uri)
        configure_http(http, uri)
        http.keep_alive_timeout = KEEP_ALIVE_TIMEOUT_SECONDS if http.respond_to?(:keep_alive_timeout=)
        resolve_address(http, uri)
        http.start
        http
      end

      # client-go's DNS resolution hook (rest_client_dns_resolution_duration_seconds):
      # the name is resolved here, timed, and the connection opened to the
      # address found, so the resolution is measured once per new session
      # and never repeated inside the connect.
      def resolve_address(http, uri)
        return unless http.respond_to?(:ipaddr=) && uri.hostname
        return if http.respond_to?(:ipaddr) && http.ipaddr

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        addresses = Addrinfo.getaddrinfo(uri.hostname, uri.port, nil, :STREAM)
        seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        RestClientMetrics.dns_resolution(uri, seconds)
        address = addresses.find(&:ipv4?) || addresses.first
        http.ipaddr = address.ip_address if address
      rescue SocketError, SystemCallError
        # Resolution failed: the connect reports it with the usual error.
        nil
      end

      def call_http_stream(method, uri, body, headers, &)
        http = nil
        session = nil
        http, session = open_http_stream(uri)
        ensure_open_stream!(session)
        configure_http(http, uri)
        request = build_request(method, uri, body, headers)
        streamed_response = nil
        yielded_response = false
        consume = lambda do |raw_response|
          yielded_response = true
          streamed_response = consume_http_stream(raw_response, method, uri.request_uri, &)
        end

        raw_response = if http.respond_to?(:request)
                         http.request(request, &consume)
                       elsif http.respond_to?(:start)
                         http.start { |session| session.request(request, &consume) }
                       else
                         raise TransportError, "HTTP adapter must respond to start or request"
                       end
        return streamed_response if yielded_response

        consume_http_stream(raw_response, method, uri.request_uri, &)
      ensure
        unregister_stream(session) if session
      end

      def register_stream(resource)
        session = StreamSession.new(resource: resource, close_requested: false, close_in_progress: false,
                                    close_succeeded: false, close_error: nil)
        @stream_mutex.synchronize do
          raise TransportError, "HTTP client is closed" if @closed

          @active_streams[session] = session
        end
        session
      end

      # Construct and register a Net::HTTP stream while holding the lifecycle
      # mutex. This closes the factory/close TOCTOU window: a concurrent close
      # cannot snapshot an empty registry and return while a new socket is
      # still being initialized.
      def open_http_stream(uri)
        @stream_mutex.synchronize do
          raise TransportError, "HTTP client is closed" if @closed

          resource = @http_factory.call(uri)
          session = StreamSession.new(resource: resource, close_requested: false, close_in_progress: false,
                                      close_succeeded: false, close_error: nil)
          @active_streams[session] = session
          [resource, session]
        end
      end

      def unregister_stream(session)
        @stream_mutex.synchronize { @active_streams.delete(session) }
      end

      def ensure_open_stream!(session)
        closed = @stream_mutex.synchronize { session.close_requested }
        raise TransportError, "HTTP client was closed while opening a stream" if closed
      end

      def close_stream_session(session)
        @stream_mutex.synchronize do
          return [] if session.close_succeeded

          if session.close_in_progress
            @stream_condition.wait(@stream_mutex) while session.close_in_progress
            return [] if session.close_succeeded
          end

          session.close_requested = true
          session.close_in_progress = true
        end

        errors = close_resource(session.resource)
        @stream_mutex.synchronize do
          session.close_in_progress = false
          session.close_succeeded = errors.empty?
          session.close_error = errors.empty? ? nil : errors.first
          @stream_condition.broadcast
        end
        errors
      end

      def set_stream_close_result(session, errors)
        @stream_mutex.synchronize do
          session.close_requested = true
          session.close_in_progress = false
          session.close_succeeded = errors.empty?
          session.close_error = errors.empty? ? nil : errors.first
          @stream_condition.broadcast
        end
      end

      def close_resource(resource)
        return [] unless resource

        errors = []
        started = begin
          resource.respond_to?(:started?) ? resource.started? : nil
        rescue StandardError => error
          errors << error
          nil
        end
        finish_attempted = resource.respond_to?(:finish) && (started.nil? || started)
        if finish_attempted
          begin
            resource.finish
          rescue StandardError => error
            errors << error
          end
        end
        if resource.respond_to?(:close) && (!finish_attempted || errors.any?)
          begin
            resource.close
          rescue StandardError => error
            errors << error
          end
        end

        socket = resource_socket(resource)
        if socket && socket.respond_to?(:close) && (!socket.respond_to?(:closed?) || !socket.closed?)
          begin
            socket.close
          rescue StandardError => error
            errors << error
          end
        end
        errors
      end

      def resource_socket(resource)
        return resource.socket if resource.respond_to?(:socket)
        return unless resource.instance_variable_defined?(:@socket)

        resource.instance_variable_get(:@socket)
      rescue StandardError
        nil
      end

      def consume_http_stream(raw_response, method, path, &)
        status = response_status(raw_response)
        headers = response_headers(raw_response)
        response = Response.new(status: status, headers: headers.freeze, body: "")
        unless response.success?
          error_body = +""
          each_raw_response_chunk(raw_response) do |chunk|
            error_body << chunk
            raise TransportError, "HTTP error response exceeds #{MAX_STREAM_ERROR_BODY_BYTES} bytes" if error_body.bytesize > MAX_STREAM_ERROR_BODY_BYTES
          end
          response.body = error_body
          raise_for_status!(response, method, path)
        end

        each_raw_response_chunk(raw_response, &)
        response
      end

      def each_raw_response_chunk(raw_response, &)
        if raw_response.respond_to?(:read_body)
          raw_response.read_body { |chunk| yield(String(chunk)) }
        else
          body = raw_response.respond_to?(:body) ? raw_response.body : ""
          each_stream_body_chunk(body, &)
        end
      end

      def each_stream_body_chunk(body)
        return if body.nil? || body == ""

        if body.is_a?(String)
          yield body
        elsif body.respond_to?(:each)
          body.each { |chunk| yield String(chunk) }
        else
          yield String(body)
        end
      end

      def watch_timeout_seconds(uri)
        query = uri.respond_to?(:query) ? uri.query.to_s : ""
        return nil unless query.match?(/(?:\A|&)watch=(?:true|1)(?:&|\z)/)

        match = query.match(/(?:\A|&)timeoutSeconds=(\d+)(?:&|\z)/)
        match ? Integer(match[1]) : nil
      end

      def configure_http(http, uri)
        return http unless http.respond_to?(:use_ssl=)

        http.use_ssl = uri.scheme == "https"
        if http.respond_to?(:open_timeout=)
          http.open_timeout = @open_timeout
          if http.respond_to?(:read_timeout=)
            # Net::HTTP 3.4 treats zero as an immediate timeout. The client
            # contract uses zero to mean an unbounded read, so pass nil to
            # Net::HTTP's BufferedIO instead of the literal zero.
            http.read_timeout = @read_timeout.zero? ? nil : @read_timeout
            # A watch stream stays silent for as long as the cluster does; its
            # read timeout must outlive the server-side timeoutSeconds or an
            # idle watch is torn down and re-listed every read_timeout.
            watch_timeout = watch_timeout_seconds(uri)
            http.read_timeout = [http.read_timeout.to_i, watch_timeout + 60].max if watch_timeout
          end
          http.write_timeout = @write_timeout if http.respond_to?(:write_timeout=)
        end
        ssl_enabled = http.respond_to?(:use_ssl?) ? http.use_ssl? : uri.scheme == "https"
        ca_file = context_value(:ca_file) || context_value(:certificate_authority_file)
        ca_data = context_value(:ca_data) || context_value(:certificate_authority_data)
        client_certificate = context_value(:client_certificate_data) || context_value(:client_certificate_file)
        client_key = context_value(:client_key_data) || context_value(:client_key_file)
        insecure_value = context_value(:insecure_skip_tls_verify)
        unless insecure_value.nil? || insecure_value == true || insecure_value == false
          raise ConfigurationError, "insecure TLS verification setting must be a boolean"
        end

        unless ssl_enabled
          if insecure_value == true || ca_file || ca_data || client_certificate || client_key
            raise ConfigurationError, "TLS credentials and options require an https Kubernetes API server"
          end

          return http
        end

        insecure = insecure_value == true
        raise ConfigurationError, "certificate authority data cannot be combined with insecure TLS verification" if insecure && (ca_data || ca_file)

        http.verify_mode = insecure ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER if http.respond_to?(:verify_mode=)
        if ca_data
          configure_ca_store(http, ca_data)
        elsif ca_file
          configure_ca_store(http, read_credential_file(ca_file, "certificate authority"))
        end
        configure_client_certificate(http)
        http
      rescue OpenSSL::OpenSSLError, ArgumentError, TypeError, Errno::ENOENT, Errno::EACCES, Errno::EISDIR, Errno::ELOOP => error
        raise ConfigurationError.new("cannot configure Kubernetes TLS credentials: #{error.message}", cause: error), cause: error
      end

      def configure_ca_store(http, ca_data)
        store = tls_cache(:ca_store, ca_data) do
          value = OpenSSL::X509::Store.new
          certificates = OpenSSL::X509::Certificate.load(ca_data)
          raise ConfigurationError, "certificate authority data contains no certificates" if certificates.empty?

          certificates.each { |certificate| value.add_cert(certificate) }
          value
        end
        http.cert_store = store if http.respond_to?(:cert_store=)
      end

      def configure_client_certificate(http)
        certificate = context_value(:client_certificate_data)
        certificate = read_credential_file(context_value(:client_certificate_file), "client certificate") if certificate.nil?
        key = context_value(:client_key_data)
        key = read_credential_file(context_value(:client_key_file), "client key", sensitive: true) if key.nil?
        return if certificate.nil? && key.nil?
        raise ConfigurationError, "client certificate and client key must be supplied together" if certificate.nil? || key.nil?

        pair = tls_cache(:client_pair, [certificate, key]) do
          parsed_certificate = OpenSSL::X509::Certificate.new(certificate)
          parsed_key = OpenSSL::PKey.read(key)
          unless parsed_certificate.check_private_key(parsed_key)
            raise ConfigurationError, "client certificate does not match client private key"
          end

          [parsed_certificate, parsed_key]
        end
        http.cert = pair[0] if http.respond_to?(:cert=)
        http.key = pair[1] if http.respond_to?(:key=)
      end

      # Parsing an X.509 certificate and a private key, and proving they match,
      # costs real CPU -- doing it on every API request turns a control loop
      # into a key-parsing benchmark.  The result is memoised against the
      # exact bytes it was derived from, so rotated credentials are still
      # picked up the moment their content changes.
      def tls_cache(slot, material)
        @tls_cache ||= {}
        digest = Digest::SHA256.hexdigest(Array(material).join("\x00"))
        cached = @tls_cache[slot]
        return cached[:value] if cached && cached[:digest] == digest

        value = yield
        @tls_cache[slot] = {digest: digest, value: value}
        value
      end

      # Credential files are re-read only when they change on disk; the
      # symlink audit and the permission checks run on that same path.
      def read_credential_file(path, label, sensitive: false)
        return nil if path.nil?

        stat = begin
          File.stat(path)
        rescue SystemCallError
          nil
        end
        token = stat && [stat.ino, stat.size, stat.mtime.to_f, stat.mode]
        @credential_files ||= {}
        cached = @credential_files[path]
        return cached[:content] if cached && token && cached[:token] == token

        content = read_file(path, label, sensitive: sensitive)
        @credential_files[path] = {token: token, content: content} if token
        content
      end

      def read_file(path, label, sensitive: false)
        return nil if path.nil?

        reject_symlink_components(path, label)

        flags = File::RDONLY
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        File.open(path, flags) do |file|
          file.binmode
          stat = file.stat
          raise ConfigurationError, "#{label} file must be a regular file: #{path}" unless stat.file?
          raise ConfigurationError, "#{label} file has no read permission: #{path}" if stat.mode.nobits?(0o444)
          if sensitive && stat.mode.anybits?(0o077)
            raise ConfigurationError, "#{label} file must not grant permissions to group or other users: #{path}"
          end

          content = file.read(MAX_CREDENTIAL_FILE_BYTES + 1)
          if content.bytesize > MAX_CREDENTIAL_FILE_BYTES
            raise ConfigurationError,
                  "#{label} file exceeds #{MAX_CREDENTIAL_FILE_BYTES} bytes: #{path}"
          end
          raise ConfigurationError, "#{label} file is empty: #{path}" if content.empty?

          content
        end
      rescue ConfigurationError
        raise
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR, Errno::ELOOP => error
        raise ConfigurationError.new("cannot read #{label} file #{path}: #{error.message}", cause: error), cause: error
      end

      def reject_symlink_components(path, label)
        current = File::SEPARATOR
        File.expand_path(path).split(File::SEPARATOR).each do |component|
          next if component.empty?

          current = File.join(current, component)
          raise ConfigurationError, "#{label} file must not contain symlinks: #{path}" if File.symlink?(current)
        end
      end

      def build_request(method, uri, body, headers)
        request_class = net_http_request_class(method)
        request = if request_class
                    request_class.new(uri.request_uri, headers)
                  else
                    Net::HTTPGenericRequest.new(method, !body.nil?, true, uri.request_uri, headers)
                  end
        request.body = body if body
        request
      end

      def net_http_request_class(method)
        return Net::HTTP::Get if method == "GET"
        return Net::HTTP::Post if method == "POST"
        return Net::HTTP::Put if method == "PUT"
        return Net::HTTP::Patch if method == "PATCH"
        return Net::HTTP::Delete if method == "DELETE"
        return Net::HTTP::Head if method == "HEAD"
        return Net::HTTP::Options if method == "OPTIONS"

        nil
      end

      def normalize_response(response)
        return response if response.is_a?(Response)

        status = response_status(response)
        headers = response_headers(response)
        raw_body = response.respond_to?(:body) ? response.body : ""
        body = raw_body.is_a?(String) ? raw_body : JSON.generate(raw_body)
        Response.new(status: status, headers: headers.freeze, body: body)
      end

      def response_status(response)
        status = if response.respond_to?(:code)
                   response.code.to_i
                 elsif response.respond_to?(:status)
                   response.status.to_i
                 end
        raise TransportError, "HTTP adapter returned a response without a numeric status" unless status && status.positive?

        status
      end

      def response_headers(response)
        if response.respond_to?(:each_header)
          collected_headers = {}
          response.each_header { |name, value| collected_headers[name.to_s.downcase] = value.to_s }
          collected_headers
        elsif response.respond_to?(:headers)
          response.headers.to_h { |name, value| [name.to_s.downcase, value.to_s] }
        else
          {}
        end
      end

      def parse_status(body)
        object = JSON.parse(body.to_s)
        object.is_a?(Hash) && object["kind"] == "Status" ? object : nil
      rescue JSON::ParserError
        nil
      end
    end

    RESTClient = HTTPClient
    REST = HTTPClient
  end
end

module Rubernetes
  module Client
    # client-go's rest_client metrics (tools/metrics, registered by
    # component-base/metrics/prometheus/restclient): requests by code, host
    # and method; latency and body sizes by host and verb.
    module RestClientMetrics
      LATENCY_BUCKETS = [0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0].freeze
      SIZE_BUCKETS = [64, 256, 512, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304, 16_777_216].freeze

      module_function

      def registry
        return nil unless defined?(Rubernetes::Observability::Metrics)

        @registry ||= Rubernetes::Observability::Metrics.global.tap do |metrics|
          metrics.register("rest_client_requests_total", type: :counter,
                                                         help: "Number of HTTP requests, partitioned by status code, method, and host.")
          metrics.register("rest_client_request_duration_seconds", type: :histogram, buckets: LATENCY_BUCKETS,
                                                                   help: "Request latency in seconds. Broken down by verb, and host.")
          metrics.register("rest_client_request_size_bytes", type: :histogram, buckets: SIZE_BUCKETS,
                                                             help: "Request size in bytes. Broken down by verb and host.")
          metrics.register("rest_client_response_size_bytes", type: :histogram, buckets: SIZE_BUCKETS,
                                                              help: "Response size in bytes. Broken down by verb and host.")
          metrics.register("rest_client_request_retries_total", type: :counter,
                                                                help: "Number of request retries, partitioned by status code, verb, and host.")
          metrics.register("rest_client_transport_create_calls_total", type: :counter,
                                                                       help: "Number of calls to get a new transport, partitioned by the result of the operation hit: obtained from the cache, miss: created and added to the cache, uncacheable: created and not cached")
          metrics.register("rest_client_transport_cache_entries", type: :gauge, help: "Number of transport entries in the internal cache.")
        end
      end

      # rest_client_dns_resolution_duration_seconds{host}: one name lookup
      # before a new connection.
      def dns_resolution(uri, seconds)
        metrics = registry
        return unless metrics

        name = "rest_client_dns_resolution_duration_seconds"
        metrics.register(name, type: :histogram) unless metrics.registered?(name)
        metrics.observe(name, seconds, {"host" => host_of(uri)})
      rescue StandardError
        nil
      end

      def record(method, uri, code, seconds, request_size, response_size)
        attempt(method, uri, code, request_size, false)
        latency(method, uri, seconds, response_size)
      end

      # One attempt: rest_client_requests_total and the request size, and
      # rest_client_request_retries_total when it is not the first.
      def attempt(method, uri, code, request_size, retried)
        metrics = registry
        return unless metrics

        host = host_of(uri)
        verb = method.to_s.upcase
        metrics.increment("rest_client_requests_total", {"code" => code.to_s, "host" => host, "method" => verb})
        metrics.increment("rest_client_request_retries_total", {"code" => code.to_s, "host" => host, "verb" => verb}) if retried
        metrics.observe("rest_client_request_size_bytes", request_size.to_i, {"host" => host, "verb" => verb})
      rescue StandardError
        nil
      end

      # The whole request: rest_client_request_duration_seconds, and the
      # final response's size.
      def latency(method, uri, seconds, response_size)
        metrics = registry
        return unless metrics

        host = host_of(uri)
        verb = method.to_s.upcase
        metrics.observe("rest_client_request_duration_seconds", seconds, {"host" => host, "verb" => verb})
        metrics.observe("rest_client_response_size_bytes", response_size.to_i, {"host" => host, "verb" => verb}) if response_size
      rescue StandardError
        nil
      end

      def host_of(uri) = uri.respond_to?(:host) && uri.host ? "#{uri.host}:#{uri.port}" : ""

      # tlsTransportCache.get: rest_client_transport_create_calls_total
      # ("miss" for a new TLS configuration, "hit" for a known one) and
      # rest_client_transport_cache_entries.
      def transport_created(key)
        metrics = registry
        return unless metrics

        @transport_keys_mutex ||= Mutex.new
        result, size = @transport_keys_mutex.synchronize do
          @transport_keys ||= Set.new
          hit = !@transport_keys.add?(key)
          [hit ? "hit" : "miss", @transport_keys.size]
        end
        metrics.increment("rest_client_transport_create_calls_total", {"result" => result})
        metrics.set("rest_client_transport_cache_entries", size)
      rescue StandardError
        nil
      end
    end
  end
end
