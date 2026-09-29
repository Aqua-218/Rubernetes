# frozen_string_literal: true

require "time"

require_relative "../identity"

module Rubernetes
  module Security
    module Authentication
      # Bootstrap token authenticator (plugin/pkg/auth/authenticator/token/bootstrap).
      # Tokens have the form [a-z0-9]{6}.[a-z0-9]{16}; the matching Secret
      # `bootstrap-token-<id>` of type bootstrap.kubernetes.io/token in
      # kube-system must carry the same secret, not be expired and have
      # usage-bootstrap-authentication=true.
      class BootstrapToken
        NAME = "bootstrap-token"
        NAMESPACE = "kube-system"
        SECRET_TYPE = "bootstrap.kubernetes.io/token"
        TOKEN_PATTERN = /\A([a-z0-9]{6})\.([a-z0-9]{16})\z/.freeze
        USER_PREFIX = "system:bootstrap:"
        GROUP = "system:bootstrappers"

        # secret_reader.call(namespace, name) -> Secret Hash or nil
        def initialize(secret_reader:, clock: -> { Time.now.utc })
          @secret_reader = secret_reader
          @clock = clock
        end

        def name
          NAME
        end

        def authenticate_token(token, _audiences = [])
          match = TOKEN_PATTERN.match(token.to_s)
          return nil unless match

          id, secret_part = match.captures
          secret = @secret_reader.call(NAMESPACE, "bootstrap-token-#{id}")
          return nil unless secret.is_a?(Hash) && secret["type"] == SECRET_TYPE

          data = decoded_data(secret)
          return nil unless data["token-id"] == id
          return nil unless secure_compare(data["token-secret"].to_s, secret_part)
          return nil unless data["usage-bootstrap-authentication"] == "true"

          expiration = data["expiration"]
          if expiration
            expires_at = begin
              Time.iso8601(expiration)
            rescue ArgumentError
              return nil
            end
            return nil if expires_at <= @clock.call
          end
          groups = data["auth-extra-groups"].to_s.split(",").map(&:strip).reject(&:empty?)
          return nil unless groups.all? { |group| group.start_with?("system:bootstrappers:") && group.match?(/\Asystem:bootstrappers:[a-z0-9:-]{0,255}[a-z0-9]\z/) }

          AuthenticationResult.new(user: UserInfo.new(name: "#{USER_PREFIX}#{id}", groups: [GROUP] + groups + [UserInfo::ALL_AUTHENTICATED]), authenticator: NAME)
        end

        def authenticate(context)
          token = context.bearer_token
          token && authenticate_token(token)
        end

        private

        def decoded_data(secret)
          data = secret["data"].is_a?(Hash) ? secret["data"] : {}
          decoded = data.each_with_object({}) do |(key, value), hash|
            hash[key] = value.is_a?(String) ? value.unpack1("m0") : value.to_s
          rescue ArgumentError
            hash[key] = ""
          end
          string_data = secret["stringData"].is_a?(Hash) ? secret["stringData"] : {}
          decoded.merge(string_data)
        end

        def secure_compare(left, right)
          return false unless left.bytesize == right.bytesize

          result = 0
          left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
          result.zero?
        end
      end
    end
  end
end
