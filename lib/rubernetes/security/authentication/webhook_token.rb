# frozen_string_literal: true

require "json"

require_relative "../identity"

module Rubernetes
  module Security
    module Authentication
      # Webhook token authenticator (k8s.io/apiserver/plugin/pkg/authenticator/token/webhook).
      # Posts a TokenReview and trusts the webhook's status.  Results are
      # cached per token for the configured TTLs.  A webhook transport error
      # is an authentication failure for that token, never anonymous.
      class WebhookToken
        NAME = "webhook-token"

        # transport.call(body_json) -> [status_code, body_json]
        def initialize(transport:, api_audiences: [], authenticated_ttl: 120, unauthenticated_ttl: 30, clock: -> { Time.now.utc },
                       version: "v1")
          @transport = transport
          @api_audiences = Array(api_audiences).map(&:to_s)
          @authenticated_ttl = authenticated_ttl
          @unauthenticated_ttl = unauthenticated_ttl
          @clock = clock
          @version = version
          @cache = {}
          @mutex = Mutex.new
        end

        def name
          NAME
        end

        def authenticate(context)
          token = context.bearer_token
          token && authenticate_token(token, @api_audiences)
        end

        def authenticate_token(token, audiences = @api_audiences)
          key = [token, Array(audiences)]
          now = @clock.call
          cached = @mutex.synchronize { @cache[key] }
          return cached[:result] if cached && cached[:expires_at] > now

          review = {"apiVersion" => "authentication.k8s.io/#{@version}", "kind" => "TokenReview",
                    "spec" => {"token" => token, "audiences" => Array(audiences).map(&:to_s)}}
          code, body = @transport.call(JSON.generate(review))
          raise AuthenticationError, "webhook token authenticator returned HTTP #{code}" unless code.to_i.between?(200, 299)

          response = body.is_a?(String) ? JSON.parse(body) : body
          status = response.is_a?(Hash) ? response["status"] : nil
          result = if status.is_a?(Hash) && status["authenticated"] == true
                     user = status["user"].is_a?(Hash) ? status["user"] : {}
                     raise AuthenticationError, "webhook token authenticator returned an empty username" if user["username"].to_s.empty?

                     returned = Array(status["audiences"]).map(&:to_s)
                     matched = returned.empty? ? Array(audiences) : (returned & Array(audiences).map(&:to_s))
                     if !returned.empty? && matched.empty?
                       raise AuthenticationError,
                             "webhook token authenticator returned audiences outside the request"
                     end

                     AuthenticationResult.new(user: UserInfo.new(name: user["username"], uid: user["uid"],
                                                                 groups: Array(user["groups"]) + [UserInfo::ALL_AUTHENTICATED], extra: user["extra"] || {}),
                                              authenticator: NAME, audiences: matched)
                   end
          ttl = result ? @authenticated_ttl : @unauthenticated_ttl
          @mutex.synchronize { @cache[key] = {result: result, expires_at: now + ttl} }
          result
        rescue JSON::ParserError => error
          raise AuthenticationError, "webhook token authenticator returned invalid JSON: #{error.message}"
        end
      end
    end
  end
end
