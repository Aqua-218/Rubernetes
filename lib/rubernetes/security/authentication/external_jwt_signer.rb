# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "time"

module Rubernetes
  module Security
    module Authentication
      # pkg/serviceaccount/externaljwt (--service-account-signing-endpoint,
      # ExternalServiceAccountTokenSigner): service account tokens are signed
      # by an external signer over gRPC on a Unix socket, which also serves
      # the public keys the tokens are verified with and the maximum token
      # lifetime.  Sign and FetchKeys calls are counted and timed in the
      # apiserver_externaljwt_* series.
      class ExternalJWTSigner
        class Error < Security::Error; end

        FALLBACK_REFRESH_SECONDS = 10.0
        DEFAULT_KEY_SYNC_TIMEOUT = 10.0
        ALLOWED_ALGORITHMS = %w[RS256 ES256 ES384 ES512].freeze
        SERVICE = "/v1.ExternalJWTSigner"

        PublicKey = Struct.new(:key_id, :key, :exclude_from_oidc_discovery, keyword_init: true)
        VerificationKeys = Struct.new(:keys, :data_timestamp, :next_refresh_at, keyword_init: true)

        class << self
          attr_accessor :metrics

          def load_stubs!
            return if defined?(ExternalJWTProto::ExternalJWTSigner::Stub)

            require "grpc"
            require_relative "generated/externaljwt_services_pb"
          end

          # status.Code(err).String(): the gRPC status name, "OK" for none.
          def error_code(error)
            return "OK" if error.nil?
            return "Unknown" unless defined?(GRPC::BadStatus) && error.is_a?(GRPC::BadStatus)

            name = GRPC::Core::StatusCodes.constants.find { |constant| GRPC::Core::StatusCodes.const_get(constant) == error.code }
            name ? name.to_s.split("_").map(&:capitalize).join : "Unknown"
          end

          def record_request(method, code, seconds)
            metrics&.observe("apiserver_externaljwt_request_duration_seconds", seconds, {"code" => code, "method" => "#{SERVICE}/#{method}"})
          rescue StandardError
            nil
          end

          def record_fetch_keys(code, now)
            metrics&.increment("apiserver_externaljwt_fetch_keys_request_total", {"code" => code})
            metrics&.set("apiserver_externaljwt_fetch_keys_success_timestamp", now) if code == "OK"
          rescue StandardError
            nil
          end

          def record_key_data_timestamp(seconds)
            metrics&.set("apiserver_externaljwt_fetch_keys_data_timestamp", seconds)
          rescue StandardError
            nil
          end

          def record_sign(code)
            metrics&.increment("apiserver_externaljwt_sign_request_total", {"code" => code})
          rescue StandardError
            nil
          end
        end

        attr_reader :socket, :issuer, :verification_keys

        # +client+: an object answering sign / fetch_keys / metadata (the
        # gRPC stub by default) for tests.
        def initialize(socket:, issuer:, allow_signing_with_non_oidc_keys: false, key_sync_timeout: DEFAULT_KEY_SYNC_TIMEOUT,
                       clock: -> { Time.now.utc }, client: nil, logger: nil)
          @socket = socket
          @issuer = issuer.to_s
          @allow_non_oidc = allow_signing_with_non_oidc_keys
          @key_sync_timeout = key_sync_timeout.to_f
          @clock = clock
          @logger = logger
          @client = client
          @mutex = Mutex.new
          @sync_mutex = Mutex.new
          @verification_keys = VerificationKeys.new(keys: [], data_timestamp: nil, next_refresh_at: nil)
          @listeners = []
          @thread = nil
          @stop = false
        end

        def client
          @client ||= begin
            self.class.load_stubs!
            ExternalJWTProto::ExternalJWTSigner::Stub.new("unix:#{@socket}", :this_channel_is_insecure)
          end
        end

        # initialFill + scheduleSync: the keys before any token is issued,
        # then refreshed on the signer's hint (10 s after a failure).
        def start!
          sync_keys!
          @stop = false
          @thread = Thread.new do
            Thread.current.name = "externaljwt-keys"
            until @stop
              wait = [(@verification_keys.next_refresh_at || @clock.call) - @clock.call, 0.1].max
              sleep_interruptibly(wait)
              break if @stop

              begin
                sync_keys!
              rescue StandardError => error
                @logger&.warn("externaljwt.key_sync_failed", error: error.message) if @logger.respond_to?(:warn)
                @verification_keys.next_refresh_at = @clock.call + FALLBACK_REFRESH_SECONDS
              end
            end
          end
          self
        end

        def stop
          @stop = true
          thread = @thread
          @thread = nil
          thread&.wakeup
          thread&.join(2)
          self
        end

        def add_listener(&block) = @mutex.synchronize { @listeners << block }

        # {kid => OpenSSL::PKey} for token verification.
        def keys_by_id
          @verification_keys.keys.to_h { |key| [key.key_id, key.key] }
        end

        # The keys advertised at /openid/v1/jwks.
        def discovery_keys
          @verification_keys.keys.reject(&:exclude_from_oidc_discovery)
        end

        # GetPublicKeys: the keys with this id, fetching again for an unknown one.
        def public_keys(key_id)
          found = find_keys(key_id)
          return found unless found.empty?

          begin
            sync_keys!
          rescue StandardError
            return []
          end
          find_keys(key_id)
        end

        def cache_age_max_seconds
          value = ((@verification_keys.next_refresh_at || @clock.call) - @clock.call).to_i
          value.negative? ? 0 : value
        end

        # GenerateToken: the signer signs base64url(payload) and returns the
        # header and signature; the header is checked before assembly.
        def sign(claims)
          payload = Base64.urlsafe_encode64(JSON.generate(claims), padding: false)
          response = timed("Sign") { client.sign(ExternalJWTProto::SignJWTRequest.new(claims: payload), deadline: Time.now + @key_sync_timeout) }
          validate_header!(response.header)
          raise Error, "empty signature returned" if response.signature.to_s.empty?

          token = "#{response.header}.#{payload}.#{response.signature}"
          self.class.record_sign("OK")
          token
        rescue StandardError => error
          self.class.record_sign(self.class.error_code(error))
          raise Error, "while signing jwt: #{error.message}" unless error.is_a?(Error)

          raise
        end

        # Metadata: the signer's maximum token lifetime.
        def max_token_expiration_seconds
          response = timed("Metadata") { client.metadata(ExternalJWTProto::MetadataRequest.new, deadline: Time.now + @key_sync_timeout) }
          response.max_token_expiration_seconds.to_i
        end

        # syncKeys: FetchKeys, validated; listeners run when the set changed.
        def sync_keys!
          @sync_mutex.synchronize do
            previous = @verification_keys
            fresh = begin
              fetch_verification_keys
            rescue StandardError => error
              self.class.record_fetch_keys(self.class.error_code(error), @clock.call.to_f)
              raise Error, "while fetching token verification keys: #{error.message}"
            end
            self.class.record_fetch_keys("OK", @clock.call.to_f)
            @verification_keys = fresh
            self.class.record_key_data_timestamp(fresh.data_timestamp.to_f)
            notify_listeners if keys_changed?(previous, fresh)
            fresh
          end
        end

        private

        def find_keys(key_id)
          keys = @verification_keys.keys
          return [] if keys.empty?
          return keys if key_id.to_s.empty?

          keys.select { |key| key.key_id == key_id }
        end

        def timed(method)
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          code = "OK"
          begin
            self.class.load_stubs! if @client.nil?
            yield
          rescue StandardError => error
            code = self.class.error_code(error)
            raise
          ensure
            self.class.record_request(method, code, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          end
        end

        def fetch_verification_keys
          response = timed("FetchKeys") { client.fetch_keys(ExternalJWTProto::FetchKeysRequest.new, deadline: Time.now + @key_sync_timeout) }
          raise Error, "found invalid refresh hint (#{response.refresh_hint_seconds}s)" if response.refresh_hint_seconds.to_i <= 0
          raise Error, "found no keys" if response.keys.to_a.empty?
          raise Error, "invalid data timestamp" if response.data_timestamp.nil?

          keys = response.keys.map do |entry|
            raise Error, "found invalid public key id #{entry.key_id.inspect}" if entry.key_id.to_s.empty? || entry.key_id.to_s.length > 1024
            raise Error, "found empty public key" if entry.key.to_s.empty?

            parsed = begin
              OpenSSL::PKey.read(entry.key.to_s.b)
            rescue OpenSSL::PKey::PKeyError => error
              raise Error, "while parsing external public keys: #{error.message}"
            end
            PublicKey.new(key_id: entry.key_id.to_s, key: parsed, exclude_from_oidc_discovery: entry.exclude_from_oidc_discovery == true)
          end
          timestamp = Time.at(response.data_timestamp.seconds, response.data_timestamp.nanos, :nsec).utc
          VerificationKeys.new(keys: keys, data_timestamp: timestamp, next_refresh_at: @clock.call + response.refresh_hint_seconds.to_i)
        end

        def keys_changed?(old, new)
          return true if old.data_timestamp != new.data_timestamp
          return true if old.keys.length != new.keys.length

          old.keys.zip(new.keys).any? { |a, b| a.key_id != b.key_id || a.exclude_from_oidc_discovery != b.exclude_from_oidc_discovery }
        end

        def notify_listeners
          listeners = @mutex.synchronize { @listeners.dup }
          listeners.each do |listener|
            Thread.new { listener.call }
          end
        end

        def validate_header!(encoded)
          json = Base64.urlsafe_decode64(encoded.to_s)
          header = JSON.parse(json)
          raise Error, "while parsing header JSON: unknown fields" unless (header.keys - %w[alg kid typ]).empty?
          raise Error, "bad type" unless header["typ"] == "JWT"
          raise Error, "key id missing" if header["kid"].to_s.empty?
          raise Error, "key id longer than 1 kb" if header["kid"].to_s.length > 1024
          raise Error, "bad signing algorithm #{header["alg"].inspect}" unless ALLOWED_ALGORITHMS.include?(header["alg"])
          return if @allow_non_oidc

          if public_keys(header["kid"]).any?(&:exclude_from_oidc_discovery)
            raise Error, "key used for signing JWT (kid: #{header["kid"]}) is excluded from OIDC discovery docs"
          end
        rescue ArgumentError, JSON::ParserError => error
          raise Error, "while unwrapping header: #{error.message}"
        end

        def sleep_interruptibly(seconds)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
          while !@stop && (remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)).positive?
            sleep([remaining, 1.0].min)
          end
        end
      end
    end
  end
end
