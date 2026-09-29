# frozen_string_literal: true

require "digest"
require "json"
require "net/http"
require "openssl"
require "uri"

require_relative "../identity"
require_relative "jwt"

module Rubernetes
  module Security
    module Authentication
      # OIDC / structured JWT authenticator (AuthenticationConfiguration.jwt,
      # k8s.io/apiserver/plugin/pkg/authenticator/token/oidc).  Each
      # JWTAuthenticator has an issuer (url, audiences, audienceMatchPolicy,
      # discoveryURL, certificateAuthority), claimValidationRules
      # (claim/requiredValue or expression), claimMappings (username, groups,
      # uid, extra: prefix or expression) and userValidationRules.
      # Expressions are CEL; the evaluator is injected so the engine and the
      # authenticator evolve independently.
      class JWTAuthenticator
        NAME = "jwt"
        DEFAULT_ALGORITHMS = %w[RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512].freeze

        class KeySet
          def initialize(jwks:, fetched_at:)
            @jwks = jwks
            @fetched_at = fetched_at
          end

          attr_reader :fetched_at

          def keys
            @keys ||= @jwks.fetch("keys", []).each_with_object({}) do |jwk, hash|
              next if jwk["use"] && jwk["use"] != "sig"

              key = JWT.from_jwk(jwk)
              hash[jwk["kid"] || JWT.key_id(key)] = key
            rescue JWT::Error
              next
            end
          end
        end

        # apiserver_authentication_jwt_authenticator_* (oidc/metrics.go):
        # latency per token verification, and with
        # StructuredAuthenticationConfigurationJWKSMetrics (Beta on) the last
        # JWKS fetch time per result and the hash of the last key set, all
        # labelled by sha256 hashes of the issuer and the API server ID.
        LATENCY = "apiserver_authentication_jwt_authenticator_latency_seconds"
        JWKS_TIMESTAMP = "apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds"
        JWKS_KEY_SET = "apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info"
        LATENCY_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10].freeze

        class << self
          attr_accessor :api_server_id
          attr_reader :metrics

          def metrics=(metrics)
            @metrics = metrics
            return unless metrics

            metrics.register(LATENCY, type: :histogram, buckets: LATENCY_BUCKETS,
                                      help: "Latency of jwt authentication operations in seconds. This is the time spent authenticating " \
                                            "a token for cache miss only (i.e. when the token is not found in the cache).")
            metrics.register(JWKS_TIMESTAMP, type: :gauge,
                                             help: "Timestamp of the last successful or failed JWKS fetch split by result, api server identity " \
                                                   "and jwt issuer for the JWT authenticator.")
            metrics.register(JWKS_KEY_SET, type: :gauge,
                                           help: "Information about the last JWKS fetched by the JWT authenticator with hash as label, split " \
                                                 "by api server identity and jwt issuer.")
          end

          def metric_hash(value) = value.to_s.empty? ? "" : "sha256:#{Digest::SHA256.hexdigest(value.to_s)}"
        end

        def initialize(config:, cel: nil, key_fetcher: nil, clock: -> { Time.now.utc }, http_client: nil, key_refresh_seconds: 300)
          @config = config
          @issuer = config.fetch("issuer")
          @issuer_url = @issuer.fetch("url")
          raise ConfigurationError, "jwt issuer url must use https" unless @issuer_url.start_with?("https://")

          @audiences = Array(@issuer["audiences"]).map(&:to_s)
          raise ConfigurationError, "jwt issuer needs at least one audience" if @audiences.empty?

          @match_policy = @issuer["audienceMatchPolicy"] || "MatchAny"
          @discovery_url = @issuer["discoveryURL"] || "#{@issuer_url.chomp("/")}/.well-known/openid-configuration"
          @ca_pem = @issuer["certificateAuthority"]
          @cel = cel
          @clock = clock
          @key_fetcher = key_fetcher || method(:fetch_keys_over_https)
          @http_client = http_client
          @key_refresh_seconds = key_refresh_seconds
          @key_set = nil
          @mutex = Mutex.new
          validate_config!
        end

        def name
          NAME
        end

        def issuer_url
          @issuer_url
        end

        def authenticate(context)
          token = context.bearer_token
          token && authenticate_token(token)
        end

        # Returns nil when the token is not for this issuer.
        def authenticate_token(token, _audiences = nil)
          header, claims = begin
            JWT.parse(token).first(2)
          rescue JWT::Error
            return nil
          end
          return nil unless claims["iss"] == @issuer_url

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = verify_token(token)
          record_latency("success", started)
          result
        rescue AuthenticationError
          record_latency("failure", started) if started
          raise
        end

        def verify_token(token)
          keys = key_set.keys
          _header, claims = JWT.verify(token, keys: keys, allowed_algorithms: DEFAULT_ALGORITHMS)
          now = @clock.call.to_i
          raise AuthenticationError, "jwt: token has expired" unless claims["exp"].is_a?(Integer) && claims["exp"] > now
          raise AuthenticationError, "jwt: token is not yet valid" if claims["nbf"].is_a?(Integer) && claims["nbf"] > now + 60

          token_audiences = Array(claims["aud"]).map(&:to_s)
          matched = token_audiences & @audiences
          raise AuthenticationError, "jwt: audience #{token_audiences.inspect} does not match" if matched.empty?
          raise AuthenticationError, "jwt: audience must match all configured audiences" if @match_policy == "MatchAll" && (@audiences - token_audiences).any?

          validate_claims!(claims)
          user = map_user(claims)
          validate_user!(user)
          AuthenticationResult.new(user: user, authenticator: NAME, audiences: matched)
        end
        private :verify_token

        def record_latency(result, started)
          metrics = self.class.metrics
          return unless metrics

          metrics.observe(LATENCY, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                          {"result" => result, "jwt_issuer_hash" => self.class.metric_hash(@issuer_url)})
        end
        private :record_latency

        private

        def validate_config!
          mappings = @config.fetch("claimMappings", {})
          username = mappings["username"] || {}
          raise ConfigurationError, "jwt claimMappings.username needs claim or expression" if username["claim"].to_s.empty? && username["expression"].to_s.empty?
          if username["claim"] && username["prefix"].nil?
            raise ConfigurationError, "jwt claimMappings.username.prefix is required when claim is set"
          end
          groups = mappings["groups"] || {}
          if groups["claim"] && groups["prefix"].nil?
            raise ConfigurationError, "jwt claimMappings.groups.prefix is required when claim is set"
          end
          needs_cel = [username, groups, mappings["uid"] || {}].any? { |mapping| mapping["expression"] } ||
                      Array(mappings["extra"]).any? ||
                      Array(@config["claimValidationRules"]).any? { |rule| rule["expression"] } ||
                      Array(@config["userValidationRules"]).any?
          raise ConfigurationError, "jwt authenticator uses CEL expressions but no evaluator is configured" if needs_cel && @cel.nil?
        end

        def key_set
          @mutex.synchronize do
            now = @clock.call
            if @key_set.nil? || now - @key_set.fetched_at > @key_refresh_seconds
              begin
                jwks = @key_fetcher.call(@discovery_url, @ca_pem)
              rescue StandardError
                record_jwks_fetch("failure", nil)
                raise
              end
              @key_set = KeySet.new(jwks: jwks, fetched_at: now)
              record_jwks_fetch("success", jwks)
            end
            @key_set
          end
        end

        def record_jwks_fetch(result, jwks)
          metrics = self.class.metrics
          return unless metrics

          labels = {"jwt_issuer_hash" => self.class.metric_hash(@issuer_url),
                    "apiserver_id_hash" => self.class.metric_hash(self.class.api_server_id)}
          metrics.set(JWKS_TIMESTAMP, Time.now.to_f, labels.merge("result" => result))
          return unless jwks

          # One key-set series per issuer and server: the previous hash goes.
          metrics.delete(JWKS_KEY_SET, @last_key_set_hash_labels) if @last_key_set_hash_labels
          @last_key_set_hash_labels = labels.merge("hash" => self.class.metric_hash(JSON.generate(jwks)))
          metrics.set(JWKS_KEY_SET, 1, @last_key_set_hash_labels)
        end

        def fetch_keys_over_https(discovery_url, ca_pem)
          discovery = https_get(discovery_url, ca_pem)
          raise AuthenticationError, "jwt: discovery document issuer mismatch" unless discovery["issuer"] == @issuer_url

          https_get(discovery.fetch("jwks_uri"), ca_pem)
        end

        def https_get(url, ca_pem)
          uri = URI.parse(url)
          raise ConfigurationError, "jwt: #{url} must be https" unless uri.scheme == "https"

          http = Net::HTTP.new(uri.host, uri.port, nil)
          http.use_ssl = true
          http.open_timeout = 10
          http.read_timeout = 10
          if ca_pem
            store = OpenSSL::X509::Store.new
            OpenSSL::X509::Certificate.load(ca_pem).each { |certificate| store.add_cert(certificate) }
            http.cert_store = store
          end
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          response = http.get(uri.request_uri, {"accept" => "application/json"})
          raise AuthenticationError, "jwt: #{url} returned HTTP #{response.code}" unless response.code.to_i == 200

          JSON.parse(response.body)
        rescue SystemCallError, SocketError, OpenSSL::SSL::SSLError, JSON::ParserError, Net::OpenTimeout, Net::ReadTimeout => error
          raise AuthenticationError, "jwt: key fetch from #{url} failed: #{error.message}"
        end

        def validate_claims!(claims)
          Array(@config["claimValidationRules"]).each do |rule|
            if rule["claim"]
              value = claims[rule["claim"]]
              raise AuthenticationError, "jwt: claim #{rule["claim"]} is missing" if value.nil?
              raise AuthenticationError, "jwt: claim #{rule["claim"]} does not equal the required value" unless value.to_s == rule["requiredValue"].to_s
            elsif rule["expression"]
              result = @cel.evaluate(rule["expression"], {"claims" => claims})
              raise AuthenticationError, "jwt: #{rule["message"] || "claim validation rule failed"}" unless result == true
            end
          end
        end

        def map_user(claims)
          mappings = @config.fetch("claimMappings", {})
          username = mapped_string(mappings["username"], claims, required: true)
          groups = mapped_list(mappings["groups"], claims)
          uid = mapped_string(mappings["uid"] || {}, claims, required: false)
          extra = {}
          Array(mappings["extra"]).each do |entry|
            value = @cel.evaluate(entry.fetch("valueExpression"), {"claims" => claims})
            extra[entry.fetch("key")] = value.is_a?(Array) ? value.map(&:to_s) : [value.to_s] unless value.nil?
          end
          UserInfo.new(name: username, uid: uid, groups: groups + [UserInfo::ALL_AUTHENTICATED], extra: extra)
        end

        def mapped_string(mapping, claims, required:)
          return nil if mapping.nil? || mapping.empty?

          if mapping["expression"]
            value = @cel.evaluate(mapping["expression"], {"claims" => claims})
            raise AuthenticationError, "jwt: mapping expression returned no value" if required && (value.nil? || value.to_s.empty?)
            return value&.to_s
          end
          value = claims[mapping["claim"]]
          raise AuthenticationError, "jwt: claim #{mapping["claim"]} is missing" if required && value.nil?
          return nil if value.nil?
          raise AuthenticationError, "jwt: claim #{mapping["claim"]} must be a string" unless value.is_a?(String)

          "#{mapping["prefix"]}#{value}"
        end

        def mapped_list(mapping, claims)
          return [] if mapping.nil? || mapping.empty?

          values = if mapping["expression"]
                     @cel.evaluate(mapping["expression"], {"claims" => claims})
                   else
                     claims[mapping["claim"]]
                   end
          return [] if values.nil?

          list = values.is_a?(Array) ? values : [values]
          raise AuthenticationError, "jwt: groups claim must be a list of strings" unless list.all? { |entry| entry.is_a?(String) }

          list.map { |entry| mapping["expression"] ? entry : "#{mapping["prefix"]}#{entry}" }
        end

        def validate_user!(user)
          Array(@config["userValidationRules"]).each do |rule|
            result = @cel.evaluate(rule.fetch("expression"), {"user" => user.to_h})
            raise AuthenticationError, "jwt: #{rule["message"] || "user validation rule failed"}" unless result == true
          end
          reserved = user.groups.select { |group| group.start_with?("system:") && group != UserInfo::ALL_AUTHENTICATED }
          raise AuthenticationError, "jwt: groups must not use the system: prefix" unless reserved.empty?
          raise AuthenticationError, "jwt: username must not use the system: prefix" if user.name.start_with?("system:")
        end
      end
    end
  end
end
