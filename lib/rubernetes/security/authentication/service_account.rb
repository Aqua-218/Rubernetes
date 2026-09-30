# frozen_string_literal: true

require "securerandom"
require "time"

require_relative "../identity"
require_relative "jwt"

module Rubernetes
  module Security
    module Authentication
      # ServiceAccount token issuer and authenticator
      # (pkg/serviceaccount: claims.go, jwt.go, legacy.go).
      #
      # Bound tokens (TokenRequest) carry iss/aud/exp/iat/nbf/sub and the
      # kubernetes.io claim with namespace, serviceaccount {name, uid} and an
      # optional pod/secret/node binding.  Validation checks the signature,
      # issuer, audience intersection, expiry and that the ServiceAccount
      # (and bound object) still exist with the same UID.
      class ServiceAccount
        NAME = "serviceaccount"
        DEFAULT_EXPIRATION_SECONDS = 3600
        MAX_EXPIRATION_SECONDS = 1 << 32
        WARN_AFTER_SECONDS = 3600
        PRIVATE_CLAIM = "kubernetes.io"
        # legacy.go: secret-based tokens.
        LEGACY_ISSUER = "kubernetes/serviceaccount"
        LEGACY_PREFIX = "kubernetes.io/serviceaccount/"
        INVALID_SINCE_LABEL = "kubernetes.io/legacy-token-invalid-since"
        LAST_USED_LABEL = "kubernetes.io/legacy-token-last-used"
        METRICS = {"serviceaccount_legacy_tokens_total" => "Cumulative legacy service account tokens used",
                   "serviceaccount_stale_tokens_total" => "Cumulative stale projected service account tokens used",
                   "serviceaccount_legacy_manual_token_uses_total" => "Cumulative manually created legacy tokens used",
                   "serviceaccount_legacy_auto_token_uses_total" => "Cumulative auto-generated legacy tokens used",
                   "serviceaccount_invalid_legacy_auto_token_uses_total" => "Cumulative invalid auto-generated legacy tokens used",
                   "serviceaccount_valid_tokens_total" => "Cumulative valid projected service account tokens used"}.freeze

        Lookup = Struct.new(:service_account, :pod, :secret, :node, keyword_init: true)

        # +external_signer+: an ExternalJWTSigner that signs the tokens and
        # serves the verification keys instead of +signing_key+.
        def initialize(issuer:, signing_key: nil, verification_keys: nil, api_audiences:, lookup:, clock: -> { Time.now.utc },
                       max_expiration_seconds: nil, extend_expiration: true, secret_writer: nil, external_signer: nil)
          @issuer = String(issuer)
          @external_signer = external_signer
          raise ArgumentError, "a signing key or an external signer is required" if signing_key.nil? && external_signer.nil?

          @signing_key = signing_key
          @key_id = signing_key ? JWT.key_id(public_key(signing_key)) : nil
          keys = Array(verification_keys).empty? ? [signing_key && public_key(signing_key)].compact : Array(verification_keys)
          @static_verification_keys = keys.to_h { |key| [JWT.key_id(key), key] }
          @api_audiences = Array(api_audiences).map(&:to_s)
          @lookup = lookup
          @clock = clock
          @max_expiration_seconds = max_expiration_seconds
          @extend_expiration = extend_expiration
          # (namespace, name, labels) -> merges labels into the Secret (the
          # legacy token's last-used date); nil disables the tracking.
          @secret_writer = secret_writer
          @metrics = nil
        end

        attr_reader :issuer, :api_audiences, :metrics, :external_signer

        # kid => public key: the static files, or the external signer's cache.
        def verification_keys
          @external_signer ? @external_signer.keys_by_id : @static_verification_keys
        end

        def sign_claims(claims)
          return @external_signer.sign(claims) if @external_signer

          JWT.sign(claims, key: @signing_key, algorithm: algorithm, key_id: @key_id)
        end

        def metrics=(registry)
          @metrics = registry
          METRICS.each { |name, help| registry&.register(name, type: :counter, help: help) }
        end

        # A legacy (secret-based) token, signed with the same keys as the
        # bound tokens (legacy.go / LegacyClaims).
        def issue_legacy(namespace:, service_account_name:, service_account_uid:, secret_name:)
          claims = {"iss" => LEGACY_ISSUER, "sub" => "#{UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX}#{namespace}:#{service_account_name}",
                    "#{LEGACY_PREFIX}namespace" => namespace, "#{LEGACY_PREFIX}secret.name" => secret_name,
                    "#{LEGACY_PREFIX}service-account.name" => service_account_name,
                    "#{LEGACY_PREFIX}service-account.uid" => service_account_uid}
          sign_claims(claims)
        end

        def name
          NAME
        end

        def algorithm
          key = @signing_key || verification_keys.values.first
          key.is_a?(OpenSSL::PKey::EC) ? "ES256" : "RS256"
        end

        # OpenID discovery documents served at /.well-known/openid-configuration and /openid/v1/jwks.
        def jwks
          published = @external_signer ? @external_signer.discovery_keys.to_h { |key| [key.key_id, key.key] } : @static_verification_keys
          {"keys" => published.map { |kid, key| JWT.to_jwk(key).merge("use" => "sig", "kid" => kid, "alg" => key.is_a?(OpenSSL::PKey::EC) ? "ES256" : "RS256") }}
        end

        def openid_configuration
          {"issuer" => @issuer, "jwks_uri" => "#{@issuer.chomp("/")}/openid/v1/jwks", "response_types_supported" => ["id_token"],
           "subject_types_supported" => ["public"], "id_token_signing_alg_values_supported" => [algorithm]}
        end

        # TokenRequest (authentication.k8s.io/v1): returns [token, expiration_time].
        def issue(namespace:, service_account_name:, service_account_uid:, audiences: nil, expiration_seconds: nil,
                  bound_object: nil, now: @clock.call)
          audiences = Array(audiences).map(&:to_s)
          audiences = @api_audiences if audiences.empty?
          requested = expiration_seconds.nil? ? DEFAULT_EXPIRATION_SECONDS : Integer(expiration_seconds)
          raise ArgumentError, "expirationSeconds must be at least 600" if requested < 600
          raise ArgumentError, "expirationSeconds exceeds the maximum" if requested > MAX_EXPIRATION_SECONDS

          capped = @max_expiration_seconds && requested > @max_expiration_seconds ? @max_expiration_seconds : requested
          issued = now.to_i
          private_claims = {"namespace" => namespace, "serviceaccount" => {"name" => service_account_name, "uid" => service_account_uid}}
          if bound_object
            kind = bound_object.fetch("kind").to_s.downcase
            private_claims[kind] = {"name" => bound_object.fetch("name"), "uid" => bound_object.fetch("uid")}
            private_claims["node"] = bound_object["node"] if kind == "pod" && bound_object["node"].is_a?(Hash)
          end
          claims = {
            "iss" => @issuer,
            "aud" => audiences.length == 1 ? audiences.first : audiences,
            "exp" => issued + capped,
            "iat" => issued,
            "nbf" => issued,
            "sub" => "#{UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX}#{namespace}:#{service_account_name}",
            "jti" => SecureRandom.uuid,
            PRIVATE_CLAIM => private_claims
          }
          # Tokens requested for longer than an hour are still issued for the
          # requested duration but the kubelet-style warnAfter marks them.
          claims[PRIVATE_CLAIM]["warnafter"] = issued + WARN_AFTER_SECONDS if capped > WARN_AFTER_SECONDS
          [JWT.sign(claims, key: @signing_key, algorithm: algorithm, key_id: @key_id), Time.at(issued + capped).utc]
        end

        def authenticate(context)
          token = context.bearer_token
          token && authenticate_token(token, @api_audiences)
        end

        # Returns an AuthenticationResult or nil when the token is not a
        # service account token at all; raises AuthenticationError when it is
        # one but invalid.
        def authenticate_token(token, audiences = @api_audiences)
          parts = token.to_s.split(".")
          return nil unless parts.length == 3

          header, claims = begin
            JWT.parse(token).first(2)
          rescue JWT::Error
            return nil
          end
          return authenticate_legacy(token) if claims["iss"] == LEGACY_ISSUER
          return nil unless claims["iss"] == @issuer && claims["sub"].to_s.start_with?(UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX)

          _header, claims = JWT.verify(token, keys: @verification_keys, allowed_algorithms: %w[RS256 ES256 RS384 RS512 ES384 ES512])
          now = @clock.call.to_i
          raise AuthenticationError, "serviceaccount: token has expired" if claims["exp"].is_a?(Integer) && claims["exp"] <= now
          raise AuthenticationError, "serviceaccount: token is not yet valid" if claims["nbf"].is_a?(Integer) && claims["nbf"] > now + 60

          token_audiences = Array(claims["aud"]).map(&:to_s)
          matched = token_audiences & Array(audiences).map(&:to_s)
          raise AuthenticationError, "serviceaccount: token audiences #{token_audiences.inspect} are invalid" if matched.empty? && !token_audiences.empty?

          private_claims = claims[PRIVATE_CLAIM]
          raise AuthenticationError, "serviceaccount: token is missing the #{PRIVATE_CLAIM} claim" unless private_claims.is_a?(Hash)

          namespace = private_claims["namespace"].to_s
          account = private_claims["serviceaccount"].is_a?(Hash) ? private_claims["serviceaccount"] : {}
          sa_name = account["name"].to_s
          sa_uid = account["uid"].to_s
          expected_subject = "#{UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX}#{namespace}:#{sa_name}"
          raise AuthenticationError, "serviceaccount: subject does not match private claims" unless claims["sub"] == expected_subject

          record = resolve(:service_account, namespace, sa_name)
          raise AuthenticationError, "serviceaccount: #{expected_subject} does not exist" if record.nil?
          raise AuthenticationError, "serviceaccount: #{expected_subject} UID mismatch" unless record.dig("metadata", "uid").to_s == sa_uid

          extra = {"authentication.kubernetes.io/credential-id" => ["JTI=#{claims["jti"]}"]}
          %w[pod secret node].each do |kind|
            binding = private_claims[kind]
            next unless binding.is_a?(Hash)

            # The node of a pod-bound token is informational: upstream's
            # validator checks it only when the node is the bound object.
            if kind == "node" && private_claims["pod"].is_a?(Hash)
              extra["authentication.kubernetes.io/node-name"] = [binding["name"].to_s]
              extra["authentication.kubernetes.io/node-uid"] = [binding["uid"].to_s] unless binding["uid"].to_s.empty?
              next
            end

            object = resolve(kind.to_sym, namespace, binding["name"].to_s)
            raise AuthenticationError, "serviceaccount: bound #{kind} #{binding["name"]} does not exist" if object.nil?
            raise AuthenticationError, "serviceaccount: bound #{kind} UID mismatch" unless object.dig("metadata", "uid").to_s == binding["uid"].to_s

            extra["authentication.kubernetes.io/#{kind}-name"] = [binding["name"].to_s]
            extra["authentication.kubernetes.io/#{kind}-uid"] = [binding["uid"].to_s]
            if kind == "pod" && object.dig("spec", "nodeName")
              extra["authentication.kubernetes.io/node-name"] = [object.dig("spec", "nodeName").to_s]
            end
          end
          # claims.go: past warnafter the token is stale.
          warn_after = private_claims["warnafter"]
          if warn_after.is_a?(Integer) && warn_after != 0
            count(now > warn_after ? "serviceaccount_stale_tokens_total" : "serviceaccount_valid_tokens_total")
          end
          user = UserInfo.service_account(namespace: namespace, name: sa_name, uid: sa_uid, extra: extra)
          AuthenticationResult.new(user: user, authenticator: NAME, audiences: matched)
        end

        # legacyValidator.Validate.
        def authenticate_legacy(token)
          _header, claims = JWT.verify(token, keys: @verification_keys, allowed_algorithms: %w[RS256 ES256 RS384 RS512 ES384 ES512])
          subject = claims["sub"].to_s
          raise AuthenticationError, "sub claim is missing" if subject.empty?

          namespace = claims["#{LEGACY_PREFIX}namespace"].to_s
          secret_name = claims["#{LEGACY_PREFIX}secret.name"].to_s
          sa_name = claims["#{LEGACY_PREFIX}service-account.name"].to_s
          sa_uid = claims["#{LEGACY_PREFIX}service-account.uid"].to_s
          raise AuthenticationError, "namespace claim is missing" if namespace.empty?
          raise AuthenticationError, "secretName claim is missing" if secret_name.empty?
          raise AuthenticationError, "serviceAccountName claim is missing" if sa_name.empty?
          raise AuthenticationError, "serviceAccountUID claim is missing" if sa_uid.empty?
          unless subject == "#{UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX}#{namespace}:#{sa_name}"
            raise AuthenticationError, "sub claim is invalid"
          end

          secret = resolve(:secret, namespace, secret_name)
          raise AuthenticationError, "Token has been invalidated" if secret.nil? || secret.dig("metadata", "deletionTimestamp")

          stored = secret.dig("data", "token").to_s
          stored = begin
            stored.unpack1("m")
          rescue ArgumentError
            ""
          end
          raise AuthenticationError, "Token does not match server's copy" unless secure_compare(stored, token)

          account = resolve(:service_account, namespace, sa_name)
          raise AuthenticationError, "serviceaccounts \"#{sa_name}\" not found" if account.nil?
          raise AuthenticationError, "ServiceAccount #{namespace}/#{sa_name} has been deleted" if account.dig("metadata", "deletionTimestamp")
          uid = account.dig("metadata", "uid").to_s
          raise AuthenticationError, "ServiceAccount UID (#{uid}) does not match claim (#{sa_uid})" unless uid == sa_uid

          count("serviceaccount_legacy_tokens_total")
          labels = secret.dig("metadata", "labels") || {}
          unless labels[INVALID_SINCE_LABEL].to_s.empty?
            count("serviceaccount_invalid_legacy_auto_token_uses_total")
            track_last_used(namespace, secret_name, labels)
            raise AuthenticationError, "the token in secret #{namespace}/#{secret_name} for service account #{namespace}/#{sa_name} has been marked invalid. " \
                                       "Use tokens from the TokenRequest API or manually created secret-based tokens, or remove the '#{INVALID_SINCE_LABEL}' label from the secret to temporarily allow use of this token"
          end
          auto_generated = Array(account["secrets"]).any? { |reference| reference["name"].to_s == secret_name }
          count(auto_generated ? "serviceaccount_legacy_auto_token_uses_total" : "serviceaccount_legacy_manual_token_uses_total")
          track_last_used(namespace, secret_name, labels)
          user = UserInfo.service_account(namespace: namespace, name: sa_name, uid: sa_uid, extra: {})
          AuthenticationResult.new(user: user, authenticator: NAME, audiences: @api_audiences)
        end

        private

        def count(name)
          @metrics&.increment(name)
        rescue StandardError
          nil
        end

        def secure_compare(left, right)
          return false unless left.bytesize == right.bytesize

          OpenSSL.fixed_length_secure_compare(left, right)
        end

        # patchSecretWithLastUsedDate: at most once a day.
        def track_last_used(namespace, name, labels)
          return unless @secret_writer

          now = @clock.call.utc
          today = now.strftime("%Y-%m-%d")
          tomorrow = (now + 86_400).strftime("%Y-%m-%d")
          last = labels[LAST_USED_LABEL].to_s
          return if last == today || last == tomorrow

          @secret_writer.call(namespace, name, {LAST_USED_LABEL => today})
        rescue StandardError
          nil
        end

        # Lookup members are callables (namespace, name) -> object or nil.
        def resolve(kind, namespace, name)
          resolver = @lookup.public_send(kind)
          raise ConfigurationError, "service account lookup has no #{kind} resolver" unless resolver.respond_to?(:call)

          resolver.call(namespace, name)
        end

        def public_key(key)
          case key
          when OpenSSL::PKey::RSA then OpenSSL::PKey::RSA.new(key.public_to_der)
          when OpenSSL::PKey::EC then OpenSSL::PKey::EC.new(key.public_to_der)
          else raise ConfigurationError, "service account signing key must be RSA or EC"
          end
        end
      end
    end
  end
end
