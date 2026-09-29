# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
require "tempfile"
require "timeout"
require "uri"

require_relative "digest"
require_relative "errors"
require_relative "manifest"
require_relative "media_types"
require_relative "reference"
require_relative "strict_json"

module Rubernetes
  module Image
    # Small response value used by both the stdlib transport and injected test transports.
    class RegistryResponse
      attr_reader :status, :headers, :body

      def initialize(status:, headers: {}, body: "")
        @status = Integer(status)
        @headers = headers.each_with_object({}) { |(key, value), result| result[key.to_s.downcase] = value.to_s }.freeze
        @body = body.nil? ? "".b : body.to_s.b
        freeze
      rescue ArgumentError, TypeError => error
        raise RegistryError.new("registry transport returned an invalid response: #{error.message}", cause: error), cause: error
      end

      def success?
        (200..299).cover?(status)
      end

      def [](name)
        headers[name.to_s.downcase]
      end
    end

    # Production HTTPS transport. It intentionally has no redirect handling: a
    # registry or token endpoint must be explicitly trusted and remain HTTPS.
    class NetHTTPTransport
      DEFAULT_OPEN_TIMEOUT = 10
      DEFAULT_READ_TIMEOUT = 60
      DEFAULT_WRITE_TIMEOUT = 60
      DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024 * 1024
      CHUNK_BYTES = 1024 * 1024

      def initialize(
        http_class: Net::HTTP,
        open_timeout: DEFAULT_OPEN_TIMEOUT,
        read_timeout: DEFAULT_READ_TIMEOUT,
        write_timeout: DEFAULT_WRITE_TIMEOUT,
        ca_file: nil,
        ca_data: nil
      )
        @http_class = http_class
        @open_timeout = Integer(open_timeout)
        @read_timeout = Integer(read_timeout)
        @write_timeout = Integer(write_timeout)
        @ca_file = ca_file
        @ca_data = ca_data
        raise RegistryError, "registry transport timeout must be non-negative" if [@open_timeout, @read_timeout, @write_timeout].any?(&:negative?)
      rescue ArgumentError, TypeError => error
        raise RegistryError.new("invalid registry transport configuration: #{error.message}", cause: error), cause: error
      end

      def request(method:, uri:, headers: {}, body: nil, sink: nil, max_bytes: DEFAULT_MAX_RESPONSE_BYTES)
        uri = URI.parse(uri.to_s)
        validate_uri!(uri)
        request_class = Net::HTTP.const_get(method.to_s.upcase.capitalize)
        request = request_class.new(uri)
        headers.each { |key, value| request[key.to_s] = value.to_s }
        request.body = body unless body.nil?
        response_body = String.new(encoding: Encoding::BINARY)
        streamed_bytes = 0
        # Net::HTTP#request returns the Net::HTTPResponse, not the block
        # value; capture the normalized response explicitly.
        captured = nil
        build_http(uri).request(request) do |http_response|
          http_response.read_body do |chunk|
            if sink
              chunk = chunk.to_s.b
              streamed_bytes += chunk.bytesize
              raise LimitError, "registry response exceeds the configured byte limit" if streamed_bytes > Integer(max_bytes)
              if sink.respond_to?(:call)
                sink.call(chunk)
              elsif sink.respond_to?(:write)
                sink.write(chunk)
              else
                raise RegistryError, "registry stream sink must implement call or write"
              end
            else
              response_body << chunk.to_s.b
              raise LimitError, "registry response exceeds the configured byte limit" if response_body.bytesize > Integer(max_bytes)
            end
          end
          captured = RegistryResponse.new(status: http_response.code, headers: response_headers(http_response), body: response_body)
        end
        captured || RegistryResponse.new(status: 599, headers: {}, body: response_body)
      rescue URI::InvalidURIError, SocketError, SystemCallError, IOError, EOFError, Timeout::Error,
             OpenSSL::SSL::SSLError => error
        raise RegistryError.new("registry HTTPS request failed: #{error.message}", cause: error), cause: error
      rescue NameError => error
        raise RegistryError.new("unsupported registry HTTP method: #{method.inspect}", cause: error), cause: error
      end

      def stream(method:, uri:, headers: {}, body: nil, max_bytes: DEFAULT_MAX_RESPONSE_BYTES)
        request(method: method, uri: uri, headers: headers, body: body, sink: ->(chunk) { yield chunk }, max_bytes: max_bytes)
      end

      private

      def build_http(uri)
        http = @http_class.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        if @ca_file
          http.ca_file = @ca_file
        elsif @ca_data
          store = OpenSSL::X509::Store.new
          store.set_default_paths
          certificate = OpenSSL::X509::Certificate.new(@ca_data)
          store.add_cert(certificate)
          http.cert_store = store
        end
        http.open_timeout = @open_timeout
        http.read_timeout = @read_timeout
        http.write_timeout = @write_timeout if http.respond_to?(:write_timeout=)
        http
      end

      def validate_uri!(uri)
        raise RegistryError, "registry transport requires an HTTPS URI" unless uri.scheme == "https"
        raise RegistryError, "registry transport URI must include a host" if uri.host.to_s.empty?
        raise RegistryError, "registry transport URI must not contain userinfo" if uri.userinfo
      end

      def response_headers(response)
        response.each_header.each_with_object({}) do |(key, value), headers|
          headers[key.to_s.downcase] = value.to_s
        end
      end
    end

    # OCI Distribution client with injectable transport and challenge-based auth.
    class RegistryClient
      DOCKER_HUB_ALIASES = %w[docker.io index.docker.io registry.hub.docker.com].freeze
      DOCKER_HUB_ENDPOINT = "registry-1.docker.io"
      WELL_KNOWN_TOKEN_REALMS = {"registry-1.docker.io" => %w[auth.docker.io]}.freeze

      DEFAULT_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
      DEFAULT_MAX_BLOB_BYTES = 20 * 1024 * 1024 * 1024
      DEFAULT_MAX_CONFIG_BYTES = 8 * 1024 * 1024
      TOKEN_CLOCK_SKEW = 30

      attr_reader :reference, :endpoint, :transport

      def initialize(
        reference = nil,
        endpoint: nil,
        registry: nil,
        transport: nil,
        username: nil,
        password: nil,
        basic_auth: nil,
        bearer_token: nil,
        token: nil,
        token_realm_allowlist: nil,
        allowed_token_realms: nil,
        allow_insecure: false,
        ca_file: nil,
        ca_data: nil,
        http_class: Net::HTTP,
        open_timeout: NetHTTPTransport::DEFAULT_OPEN_TIMEOUT,
        read_timeout: NetHTTPTransport::DEFAULT_READ_TIMEOUT,
        write_timeout: NetHTTPTransport::DEFAULT_WRITE_TIMEOUT,
        max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
        max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
        **extra_options
      )
        reference ||= extra_options.delete(:image) || extra_options.delete(:reference)
        unless extra_options.empty?
          raise RegistryError, "unknown registry client options: #{extra_options.keys.join(', ')}"
        end
        @reference = reference && Reference.parse(reference)
        registry_value = registry || (@reference && @reference.registry)
        # Docker Hub references normalise to "docker.io", whose host serves a web
        # page, not the v2 API; the distribution endpoint is registry-1.docker.io
        # (the same mapping containerd and the docker CLI apply).
        registry_value = DOCKER_HUB_ENDPOINT if DOCKER_HUB_ALIASES.include?(registry_value.to_s.downcase)
        endpoint_value = endpoint || if registry_value.to_s.match?(%r{\Ahttps?://})
                                     registry_value
                                   elsif registry_value
                                     "https://#{registry_value}"
                                   end
        raise RegistryError, "registry endpoint is required" if endpoint_value.to_s.empty?
        @endpoint = parse_endpoint(endpoint_value, allow_insecure: allow_insecure)
        @allow_insecure = !!allow_insecure
        @transport = transport || NetHTTPTransport.new(
          http_class: http_class,
          ca_file: ca_file,
          ca_data: ca_data,
          open_timeout: open_timeout,
          read_timeout: read_timeout,
          write_timeout: write_timeout
        )
        username, password = normalize_basic_auth(basic_auth, username, password)
        @username = username
        @password = password
        @bearer_token = bearer_token || token
        if token_realm_allowlist && allowed_token_realms
          raise RegistryError, "token_realm_allowlist and allowed_token_realms are mutually exclusive"
        end
        @token_realm_allowlist = normalize_token_realm_allowlist(token_realm_allowlist || allowed_token_realms)
        validate_credentials!
        @max_manifest_bytes = Integer(max_manifest_bytes)
        @max_blob_bytes = Integer(max_blob_bytes)
        raise RegistryError, "registry response limits must be positive" unless @max_manifest_bytes.positive? && @max_blob_bytes.positive?
        @token_cache = {}
      rescue ArgumentError, TypeError => error
        raise RegistryError.new("invalid registry client configuration: #{error.message}", cause: error), cause: error
      end

      def manifest(ref = nil, platform: nil, os: nil, architecture: nil, arch: nil, variant: nil)
        image_reference = normalize_reference(ref)
        document = fetch_document(image_reference, image_reference.locator)
        index_digest = nil
        while document.is_a?(Index)
          index_digest = document.digest
          descriptor = document.select(platform, os: os, architecture: architecture, arch: arch, variant: variant)
          image_reference = image_reference.with_digest(descriptor.digest)
          document = fetch_document(image_reference, descriptor.digest.to_s, expected_digest: descriptor.digest, expected_size: descriptor.size, index_digest: index_digest)
        end
        document
      end
      alias resolve_manifest manifest
      alias get_manifest manifest
      alias resolve resolve_manifest

      def fetch_config(ref = nil, manifest: nil)
        image_manifest = manifest || self.manifest(ref)
        image_reference = normalize_reference(ref)
        descriptor = image_manifest.config
        raise LimitError, "image config exceeds the configured byte limit" if descriptor.size > DEFAULT_MAX_CONFIG_BYTES

        temporary = fetch_blob_to_temp(image_reference, descriptor)
        begin
          temporary.rewind
          bytes = temporary.read(DEFAULT_MAX_CONFIG_BYTES + 1).to_s.b
          raise LimitError, "image config exceeds the configured byte limit" if bytes.bytesize > DEFAULT_MAX_CONFIG_BYTES

          bytes
        ensure
          temporary.close!
        end
      end

      def fetch_blob(ref_or_digest, digest = nil, expected_size: nil, media_type: nil, io: nil)
        image_reference, blob_digest = normalize_blob_arguments(ref_or_digest, digest)
        validate_blob_media_type!(media_type)
        if expected_size && Integer(expected_size) > @max_blob_bytes
          raise LimitError, "registry blob exceeds the configured byte limit"
        end
        if io && !io.respond_to?(:write)
          raise RegistryError, "registry blob destination must implement write"
        end
        path = "/v2/#{image_reference.repository}/blobs/#{blob_digest}"
        if io
          raise RegistryError, "registry blob transport must implement streaming" unless @transport.respond_to?(:stream)

          digest_state = ::Digest::SHA256.new
          bytes = 0
          temporary = Tempfile.new(["rubernetes-blob", ".part"])
          temporary.binmode
          begin
            response = stream_request(
              "GET",
              path,
              accept: media_type || "application/octet-stream",
              scope: "repository:#{image_reference.repository}:pull",
              max_bytes: @max_blob_bytes,
              on_retry: lambda {
                temporary.truncate(0)
                temporary.rewind
                digest_state = ::Digest::SHA256.new
                bytes = 0
              }
            ) do |chunk|
              chunk = chunk.to_s.b
              bytes += chunk.bytesize
              raise LimitError, "registry blob exceeds the configured byte limit" if bytes > @max_blob_bytes
              digest_state.update(chunk)
              temporary.write(chunk)
            end
            ensure_success!(response, "GET #{path}")
            if expected_size && bytes != Integer(expected_size)
              raise RegistryError, "registry blob size does not match the descriptor"
            end
            verify_stream_digest!(digest_state, blob_digest, response["docker-content-digest"])
            validate_response_media_type!(media_type, response["content-type"])
            temporary.flush
            temporary.rewind
            IO.copy_stream(temporary, io)
            return bytes
          ensure
            temporary.close!
          end
        end
        response = request("GET", path, accept: media_type || "application/octet-stream", scope: "repository:#{image_reference.repository}:pull", max_bytes: @max_blob_bytes)
        ensure_success!(response, "GET #{path}")
        body = response.body
        if expected_size && body.bytesize != Integer(expected_size)
          raise RegistryError, "registry blob size does not match the descriptor"
        end
        verify_response_digest!(body, blob_digest, response["docker-content-digest"])
        validate_response_media_type!(media_type, response["content-type"])
        if io
          io.write(body)
          body.bytesize
        else
          body
        end
      rescue ArgumentError, TypeError => error
        raise RegistryError.new("invalid registry blob size: #{error.message}", cause: error), cause: error
      end
      alias get_blob fetch_blob

      def pull(ref = nil, platform: nil, os: nil, architecture: nil, arch: nil, variant: nil, store: nil)
        image_reference = normalize_reference(ref)
        image_manifest = manifest(image_reference, platform: platform, os: os, architecture: architecture, arch: arch, variant: variant)
        pinned_reference = image_reference.with_digest(image_manifest.digest)
        config, config_path = fetch_pull_config(pinned_reference, image_manifest.config, store)
        layers = image_manifest.layers.map do |descriptor|
          if store
            temporary = fetch_blob_to_temp(pinned_reference, descriptor)
            begin
              temporary.rewind
              path = store.put(descriptor.digest, io: temporary, size: descriptor.size, media_type: descriptor.media_type)
              {descriptor: descriptor, bytes: nil, path: path}.freeze
            ensure
              temporary.close!
            end
          else
            bytes = fetch_blob(pinned_reference, descriptor.digest, expected_size: descriptor.size, media_type: descriptor.media_type)
            {descriptor: descriptor, bytes: bytes, path: nil}.freeze
          end
        end.freeze
        Image.new(reference: pinned_reference, manifest: image_manifest, config: config, config_path: config_path, layers: layers)
      end

      # Returns a bearer token obtained from a Distribution WWW-Authenticate challenge.
      # Credentials are sent only to the registry origin or an explicitly
      # configured token_realm_allowlist origin. The token response is cached
      # only until its advertised expiry.
      def token_for(realm:, service: nil, scope: nil)
        uri = URI.parse(realm.to_s)
        validate_auth_uri!(uri)
        key = [uri.to_s, service.to_s, scope.to_s].freeze
        cached = @token_cache[key]
        return cached[:token] if cached && cached[:expires_at] > monotonic_time + TOKEN_CLOCK_SKEW

        query = URI.decode_www_form(uri.query.to_s)
        query << ["service", service] if service && !service.to_s.empty?
        query << ["scope", scope] if scope && !scope.to_s.empty?
        uri.query = URI.encode_www_form(query) unless query.empty?
        headers = {"Accept" => "application/json"}
        headers["Authorization"] = basic_authorization if basic_configured?
        response = call_transport("GET", uri, headers: headers, body: nil, max_bytes: 2 * 1024 * 1024)
        unless response.success?
          raise AuthenticationError, "registry token endpoint returned HTTP #{response.status}"
        end
        payload = parse_json_response(response, "registry token response")
        raise AuthenticationError, "registry token response must be a JSON object" unless payload.is_a?(Hash)
        token = payload["token"] || payload["access_token"]
        raise AuthenticationError, "registry token response did not contain a token" unless token.is_a?(String) && !token.empty? && !token.match?(/[\x00-\x20\x7f]/)
        expires_in = payload["expires_in"]
        expires_at = expires_in.is_a?(Numeric) && expires_in.positive? ? monotonic_time + expires_in.to_f : Float::INFINITY
        @token_cache[key] = {token: token, expires_at: expires_at}.freeze
        token
      rescue URI::InvalidURIError => error
        raise AuthenticationError.new("registry token realm is invalid: #{error.message}", cause: error), cause: error
      end

      private

      def normalize_reference(value)
        return reference if value.nil? && reference
        raise ReferenceError, "registry client requires an image reference" if value.nil?

        Reference.parse(value)
      end

      def normalize_blob_arguments(ref_or_digest, digest)
        if digest
          [normalize_reference(ref_or_digest), Digest.parse(digest)]
        elsif ref_or_digest.is_a?(Digest)
          [normalize_reference(nil), ref_or_digest]
        else
          image_reference = normalize_reference(nil)
          [image_reference, Digest.parse(ref_or_digest)]
        end
      rescue DigestError => error
        raise RegistryError.new(error.message, cause: error), cause: error
      end

      def fetch_pull_config(reference, descriptor, store)
        raise LimitError, "image config exceeds the configured byte limit" if descriptor.size > DEFAULT_MAX_CONFIG_BYTES

        temporary = fetch_blob_to_temp(reference, descriptor)
        begin
          config_path = nil
          if store
            temporary.rewind
            config_path = store.put(descriptor.digest, io: temporary, size: descriptor.size, media_type: descriptor.media_type)
          end
          temporary.rewind
          config = temporary.read(DEFAULT_MAX_CONFIG_BYTES + 1).to_s.b
          raise LimitError, "image config exceeds the configured byte limit" if config.bytesize > DEFAULT_MAX_CONFIG_BYTES
          [config, config_path]
        ensure
          temporary.close!
        end
      end

      def fetch_blob_to_temp(reference, descriptor)
        temporary = Tempfile.new(["rubernetes-blob", ".part"])
        temporary.binmode
        fetch_blob(
          reference,
          descriptor.digest,
          expected_size: descriptor.size,
          media_type: descriptor.media_type,
          io: temporary
        )
        temporary.flush
        temporary.rewind
        temporary
      rescue StandardError
        temporary.close! if defined?(temporary) && temporary
        raise
      end

      def validate_blob_media_type!(media_type)
        return if media_type.nil? || media_type.to_s.empty? || media_type.to_s.split(";", 2).first.strip == "application/octet-stream"
        normalized = media_type.to_s.split(";", 2).first.strip
        return if MediaTypes.layer?(normalized) || MediaTypes.config?(normalized) || MediaTypes.manifest?(normalized) || MediaTypes.index?(normalized)

        raise UnsupportedMediaType, "unsupported registry blob media type: #{normalized}"
      end

      def validate_response_media_type!(expected, actual)
        return if expected.nil? || actual.nil? || actual.to_s.empty?
        expected_type = expected.to_s.split(";", 2).first.strip
        actual_type = actual.to_s.split(";", 2).first.strip
        return if actual_type == "application/octet-stream" || actual_type == expected_type
        return unless MediaTypes.layer?(actual_type) || MediaTypes.config?(actual_type) || MediaTypes.manifest?(actual_type) || MediaTypes.index?(actual_type)

        raise RegistryError, "registry response media type does not match the descriptor"
      end

      def fetch_document(image_reference, locator, expected_digest: nil, expected_size: nil, index_digest: nil)
        path = "/v2/#{image_reference.repository}/manifests/#{locator}"
        accept = (MediaTypes::MANIFEST_TYPES + MediaTypes::INDEX_TYPES).join(", ")
        response = request("GET", path, accept: accept, scope: "repository:#{image_reference.repository}:pull", max_bytes: @max_manifest_bytes)
        ensure_success!(response, "GET #{path}")
        verify_response_digest!(response.body, expected_digest || (image_reference.digest if image_reference.digest), response["docker-content-digest"])
        ManifestDocument.parse(response.body, expected_digest: expected_digest || (image_reference.digest if image_reference.digest), expected_size: expected_size, max_bytes: @max_manifest_bytes, index_digest: index_digest)
      rescue JSON::ParserError, ManifestError, DigestError, DigestMismatch, LimitError
        raise
      rescue Error
        raise
      rescue StandardError => error
        raise RegistryError.new("cannot parse registry manifest: #{error.message}", cause: error), cause: error
      end

      def request(method, path, accept:, scope:, body: nil, max_bytes: @max_manifest_bytes)
        headers = {"Accept" => accept}
        headers["Authorization"] = "Bearer #{@bearer_token}" if @bearer_token
        response = follow_redirects(method, build_uri(path), headers: headers, body: body, max_bytes: max_bytes)
        return response unless response.status == 401

        challenge = parse_authenticate(response["www-authenticate"])
        if challenge && challenge[:scheme] == "bearer"
          token = token_for(realm: challenge[:realm], service: challenge[:service], scope: challenge[:scope] || scope)
          headers["Authorization"] = "Bearer #{token}"
          response = follow_redirects(method, build_uri(path), headers: headers, body: body, max_bytes: max_bytes)
        elsif challenge && challenge[:scheme] == "basic" && basic_configured?
          headers["Authorization"] = basic_authorization
          response = follow_redirects(method, build_uri(path), headers: headers, body: body, max_bytes: max_bytes)
        end
        if response.status == 401
          raise AuthenticationError, "registry authentication failed"
        end
        response
      end

      def stream_request(method, path, accept:, scope:, body: nil, max_bytes: @max_blob_bytes, on_retry: nil, &sink)
        unless @transport.respond_to?(:stream)
          raise RegistryError, "registry blob transport must implement streaming"
        end
        headers = {"Accept" => accept}
        headers["Authorization"] = "Bearer #{@bearer_token}" if @bearer_token
        response = follow_redirects(method, build_uri(path), headers: headers, body: body, max_bytes: max_bytes,
                                    stream: true, on_redirect: on_retry, &sink)
        return response unless response.status == 401

        challenge = parse_authenticate(response["www-authenticate"])
        if challenge && challenge[:scheme] == "bearer"
          token = token_for(realm: challenge[:realm], service: challenge[:service], scope: challenge[:scope] || scope)
          on_retry&.call
          headers["Authorization"] = "Bearer #{token}"
          response = follow_redirects(method, build_uri(path), headers: headers, body: body, max_bytes: max_bytes,
                                      stream: true, on_redirect: on_retry, &sink)
        elsif challenge && challenge[:scheme] == "basic" && basic_configured?
          on_retry&.call
          headers["Authorization"] = basic_authorization
          response = follow_redirects(method, build_uri(path), headers: headers, body: body, max_bytes: max_bytes,
                                      stream: true, on_redirect: on_retry, &sink)
        end
        raise AuthenticationError, "registry authentication failed" if response.status == 401

        response
      end

      # OCI Distribution allows 3xx redirects for content downloads (blobs,
      # and registry.k8s.io also redirects manifests).  Redirects are
      # followed only for GET/HEAD, only to HTTPS, at most MAX_REDIRECTS
      # times, and credentials are never forwarded to a different origin.
      # The content digest is verified by the caller regardless of origin.
      MAX_REDIRECTS = 5
      REDIRECT_STATUSES = [301, 302, 303, 307, 308].freeze

      def follow_redirects(method, uri, headers:, body:, max_bytes:, stream: false, on_redirect: nil, &sink)
        current = uri
        current_headers = headers
        hops = 0
        loop do
          response = if stream
                       call_transport_stream(method, current, headers: current_headers, body: body, max_bytes: max_bytes, &sink)
                     else
                       call_transport(method, current, headers: current_headers, body: body, max_bytes: max_bytes)
                     end
          return response unless REDIRECT_STATUSES.include?(response.status) && %w[GET HEAD].include?(String(method).upcase)

          # A streamed redirect has already delivered its (non-content) body
          # to the sink; the caller resets its digest/temporary state here.
          on_redirect&.call
          hops += 1
          raise RegistryError, "registry redirect limit exceeded" if hops > MAX_REDIRECTS
          location = response["location"].to_s
          raise RegistryError, "registry redirect without Location" if location.empty?
          target = URI.join(current.to_s, location)
          raise RegistryError, "registry redirect to a non-HTTPS location" unless target.scheme == "https" || (@allow_insecure && target.scheme == "http")
          raise RegistryError, "registry redirect with userinfo" if target.userinfo
          current_headers = same_origin?(target) && same_origin?(current) ? current_headers : current_headers.reject { |name, _| name.to_s.casecmp?("authorization") }
          current = target
        end
      end

      def call_transport(method, uri, headers:, body:, max_bytes:)
        response = if @transport.respond_to?(:request)
                     invoke_request(method, uri, headers: headers.dup, body: body, max_bytes: max_bytes)
                   elsif @transport.respond_to?(:call)
                     @transport.call(method: method, uri: uri, headers: headers.dup, body: body)
                   else
                     raise RegistryError, "registry transport must implement request or call"
                   end
        normalize_response(response)
      rescue Error
        raise
      rescue StandardError => error
        raise RegistryError.new("registry transport failed: #{error.message}", cause: error), cause: error
      end

      def call_transport_stream(method, uri, headers:, body:, max_bytes:, &block)
        response = if @transport.respond_to?(:stream)
                     invoke_stream(method, uri, headers: headers.dup, body: body, max_bytes: max_bytes, &block)
                   else
                     call_transport(method, uri, headers: headers, body: body, max_bytes: max_bytes)
                   end
        normalize_response(response)
      rescue Error
        raise
      rescue StandardError => error
        raise RegistryError.new("registry stream transport failed: #{error.message}", cause: error), cause: error
      end

      def invoke_stream(method, uri, headers:, body:, max_bytes:)
        parameters = @transport.method(:stream).parameters
        keyword = parameters.any? { |kind, name| [:key, :keyreq, :keyrest].include?(kind) && name == :method }
        if keyword
          arguments = transport_keyword_arguments(parameters, method: method, uri: uri, headers: headers, body: body, max_bytes: max_bytes)
          @transport.stream(**arguments) { |chunk| yield chunk }
        else
          @transport.stream(method, uri, headers: headers, body: body) { |chunk| yield chunk }
        end
      end

      def invoke_request(method, uri, headers:, body:, max_bytes:)
        parameters = @transport.method(:request).parameters
        keyword = parameters.any? { |kind, name| [:key, :keyreq, :keyrest].include?(kind) && name == :method }
        if keyword
          arguments = transport_keyword_arguments(parameters, method: method, uri: uri, headers: headers, body: body, max_bytes: max_bytes)
          @transport.request(**arguments)
        else
          @transport.request(method, uri, headers: headers, body: body)
        end
      end

      def transport_keyword_arguments(parameters, method:, uri:, headers:, body:, max_bytes:)
        keyrest = parameters.any? { |kind, _name| kind == :keyrest }
        allowed = parameters.filter_map { |kind, name| name if [:key, :keyreq].include?(kind) }
        arguments = {}
        arguments[:method] = method if keyrest || allowed.include?(:method)
        if keyrest || allowed.include?(:uri)
          arguments[:uri] = uri
        elsif allowed.include?(:path)
          arguments[:path] = uri.request_uri
        end
        arguments[:headers] = headers if keyrest || allowed.include?(:headers)
        arguments[:body] = body if keyrest || allowed.include?(:body)
        arguments[:max_bytes] = max_bytes if keyrest || allowed.include?(:max_bytes)
        arguments
      end

      def normalize_response(response)
        return response if response.is_a?(RegistryResponse)
        if response.is_a?(Hash)
          return RegistryResponse.new(status: response[:status] || response["status"], headers: response[:headers] || response["headers"] || {}, body: response[:body] || response["body"] || "")
        end
        status = response.respond_to?(:status) ? response.status : response.status_code
        headers = response.respond_to?(:headers) ? response.headers : {}
        body = response.respond_to?(:body) ? response.body : ""
        RegistryResponse.new(status: status, headers: headers, body: body)
      rescue NoMethodError, ArgumentError, TypeError => error
        raise RegistryError.new("registry transport returned an invalid response: #{error.message}", cause: error), cause: error
      end

      def ensure_success!(response, operation)
        return response if response.success?
        detail = response.body.to_s.byteslice(0, 1024).to_s.gsub(/[\r\n]/, " ")
        detail = ": #{detail}" unless detail.empty?
        raise RegistryError, "registry request #{operation} failed with HTTP #{response.status}#{detail}"
      end

      def parse_json_response(response, description)
        StrictJSON.parse(response.body)
      rescue StrictJSON::Error, JSON::ParserError => error
        raise AuthenticationError.new("#{description} is not valid JSON: #{error.message}", cause: error), cause: error
      end

      def verify_response_digest!(body, expected, header_digest)
        expected_digest = expected && Digest.parse(expected)
        header = header_digest && Digest.parse(header_digest)
        if expected_digest && Digest.from_bytes(body) != expected_digest
          raise DigestMismatch, "registry response digest does not match the requested digest"
        end
        if header && Digest.from_bytes(body) != header
          raise DigestMismatch, "registry response digest does not match Docker-Content-Digest"
        end
        true
      rescue DigestMismatch
        raise
      rescue DigestError => error
        raise RegistryError.new("registry returned an invalid content digest: #{error.message}", cause: error), cause: error
      end

      def verify_stream_digest!(digest_state, expected, header_digest)
        expected_digest = expected && Digest.parse(expected)
        header = header_digest && Digest.parse(header_digest)
        actual = digest_state.hexdigest
        if expected_digest && !secure_compare(actual, expected_digest.hex)
          raise DigestMismatch, "registry response digest does not match the requested digest"
        end
        if header && !secure_compare(actual, header.hex)
          raise DigestMismatch, "registry response digest does not match Docker-Content-Digest"
        end
        true
      rescue DigestMismatch
        raise
      rescue DigestError => error
        raise RegistryError.new("registry returned an invalid content digest: #{error.message}", cause: error), cause: error
      end

      def parse_authenticate(value)
        text = value.to_s.strip
        return nil if text.empty?
        return nil if text.match?(/[\x00-\x1f\x7f]/)

        match = /\A(Bearer|Basic)(?:[ \t]+(.+))?\z/i.match(text)
        return nil unless match

        scheme = match[1].downcase
        remainder = match[2].to_s
        return {scheme: scheme} if remainder.empty?

        attributes = {}
        cursor = 0
        length = remainder.bytesize
        while cursor < length
          cursor += 1 while cursor < length && whitespace_byte?(remainder.getbyte(cursor))
          return nil if cursor >= length

          name_start = cursor
          cursor += 1 while cursor < length && token_byte?(remainder.getbyte(cursor))
          return nil if cursor == name_start
          name = remainder.byteslice(name_start, cursor - name_start).downcase
          cursor += 1 while cursor < length && whitespace_byte?(remainder.getbyte(cursor))
          return nil unless remainder.getbyte(cursor) == 61 # "="

          cursor += 1
          cursor += 1 while cursor < length && whitespace_byte?(remainder.getbyte(cursor))
          return nil if cursor >= length

          value_start = cursor
          if remainder.getbyte(cursor) == 34 # quote
            cursor += 1
            parsed = String.new(encoding: Encoding::UTF_8)
            closed = false
            while cursor < length
              byte = remainder.getbyte(cursor)
              if byte == 34
                cursor += 1
                closed = true
                break
              elsif byte == 92
                cursor += 1
                return nil if cursor >= length || ![34, 92].include?(remainder.getbyte(cursor))
                parsed << remainder.byteslice(cursor, 1)
              elsif byte < 0x20 || byte == 0x7f
                return nil
              else
                parsed << remainder.byteslice(cursor, 1)
              end
              cursor += 1
            end
            return nil unless closed
            parsed_value = parsed
          else
            cursor += 1 while cursor < length && token_byte?(remainder.getbyte(cursor))
            return nil if cursor == value_start
            parsed_value = remainder.byteslice(value_start, cursor - value_start)
          end

          return nil if attributes.key?(name.to_sym)
          attributes[name.to_sym] = parsed_value
          cursor += 1 while cursor < length && whitespace_byte?(remainder.getbyte(cursor))
          if cursor < length
            return nil unless remainder.getbyte(cursor) == 44 # comma

            cursor += 1
            return nil if cursor >= length
          end
        end

        return nil if scheme == "bearer" && (!attributes[:realm].is_a?(String) || attributes[:realm].empty?)

        {scheme: scheme, **attributes}
      end

      def parse_endpoint(value, allow_insecure:)
        uri = URI.parse(value.to_s)
        unless ["https", "http"].include?(uri.scheme) && uri.host && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
          raise RegistryError, "registry endpoint must be an HTTPS URL without userinfo, query, or fragment"
        end
        if uri.scheme != "https" && !allow_insecure
          raise RegistryError, "registry endpoint must use HTTPS"
        end
        uri.path = "" if uri.path == "/"
        uri
      rescue URI::InvalidURIError => error
        raise RegistryError.new("registry endpoint is invalid: #{error.message}", cause: error), cause: error
      end

      def build_uri(path)
        value = path.is_a?(URI) ? path.dup : URI.parse(path.to_s)
        return value if value.scheme
        value.path = "/#{value.path}" unless value.path.start_with?("/")
        prefix = endpoint.path.to_s
        prefix = "" if prefix == "/"
        value.path = "#{prefix}#{value.path}" unless prefix.empty? || value.path == prefix || value.path.start_with?("#{prefix}/")
        base = endpoint.dup
        base.path = value.path
        base.query = value.query
        base.fragment = value.fragment
        base
      rescue URI::InvalidURIError => error
        raise RegistryError.new("registry request path is invalid: #{error.message}", cause: error), cause: error
      end

      def normalize_basic_auth(basic_auth, username, password)
        if basic_auth
          if basic_auth.is_a?(Array)
            username ||= basic_auth[0]
            password ||= basic_auth[1]
          elsif basic_auth.is_a?(Hash)
            username ||= basic_auth[:username] || basic_auth["username"]
            password ||= basic_auth[:password] || basic_auth["password"]
          else
            raise RegistryError, "basic_auth must be a username/password pair"
          end
        end
        [username, password]
      end

      def validate_credentials!
        if @username.nil? ^ @password.nil?
          raise RegistryError, "registry basic authentication requires username and password"
        end
        [@username, @password, @bearer_token].compact.each do |value|
          raise RegistryError, "registry credentials must be strings without control characters" unless value.is_a?(String) && !value.match?(/[\x00-\x1f\x7f]/)
        end
        return if @username.nil? && @password.nil? && @bearer_token.nil?
        return if endpoint.scheme == "https"
        raise RegistryError, "registry credentials require HTTPS"
      end

      def basic_configured?
        !@username.nil? && !@password.nil?
      end

      def basic_authorization
        encoded = Base64.strict_encode64("#{@username}:#{@password}")
        "Basic #{encoded}"
      end

      def validate_auth_uri!(uri)
        if uri.scheme != "https" && !@allow_insecure
          raise AuthenticationError, "registry token realm must use HTTPS"
        end
        raise AuthenticationError, "registry token realm must include a host" if uri.host.to_s.empty?
        raise AuthenticationError, "registry token realm must not contain userinfo" if uri.userinfo
        raise AuthenticationError, "registry token realm must not contain a query or fragment" if uri.query || uri.fragment
        return if same_origin?(uri) || @token_realm_allowlist.include?(origin_key(uri))
        # Without Basic credentials nothing secret reaches the realm, and the
        # bearer token it returns is only ever sent back to this registry, so an
        # anonymous pull may exchange at any HTTPS realm (Docker Hub answers from
        # registry-1.docker.io with realm auth.docker.io).  With credentials the
        # realm must be same-origin, allowlisted, or the registry's well-known one.
        return unless basic_configured?
        return if WELL_KNOWN_TOKEN_REALMS.fetch(@endpoint.host.to_s.downcase, []).include?(uri.host.to_s.downcase)

        raise AuthenticationError, "registry token realm is outside the configured trust boundary"
      end

      def normalize_token_realm_allowlist(value)
        Array(value).filter_map do |entry|
          uri = URI.parse(entry.to_s)
          unless ["https", "http"].include?(uri.scheme) && uri.host && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
            raise RegistryError, "token realm allowlist entries must be absolute HTTP(S) URLs without userinfo, query, or fragment"
          end
          if uri.scheme != "https" && !@allow_insecure
            raise RegistryError, "token realm allowlist entries must use HTTPS"
          end
          origin_key(uri)
        rescue URI::InvalidURIError => error
          raise RegistryError.new("token realm allowlist entry is invalid: #{error.message}", cause: error), cause: error
        end.uniq.freeze
      end

      def same_origin?(uri)
        origin_key(uri) == origin_key(endpoint)
      end

      def origin_key(uri)
        scheme = uri.scheme.to_s.downcase
        host = uri.host.to_s.downcase
        port = uri.port
        port = nil if (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
        [scheme, host, port].freeze
      end

      def token_byte?(byte)
        return false unless byte

        byte >= 0x21 && byte <= 0x7e && ![34, 40, 41, 44, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 123, 125].include?(byte)
      end

      def whitespace_byte?(byte)
        byte == 0x20 || byte == 0x09
      end

      def monotonic_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        result = 0
        left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
        result.zero?
      end
    end

    # Result returned by RegistryClient#pull.
    class Image
      attr_reader :reference, :manifest, :config, :config_path, :layers, :rootfs, :config_object

      def initialize(reference:, manifest:, config:, config_path: nil, layers: [], rootfs: nil, config_object: nil)
        @reference = reference
        @manifest = manifest
        @config = config.to_s.b.freeze
        @config_path = config_path
        @layers = layers.freeze
        @rootfs = rootfs
        @config_object = config_object
        freeze
      end

      def digest
        manifest.digest
      end
    end

    Registry = RegistryClient
  end
end
