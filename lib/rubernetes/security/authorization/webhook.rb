# frozen_string_literal: true

require "json"

require_relative "attributes"

module Rubernetes
  module Security
    module Authorization
      # Webhook authorizer (k8s.io/apiserver/plugin/pkg/authorizer/webhook):
      # posts a SubjectAccessReview and honours status.allowed / status.denied.
      # Decisions are cached; a transport failure yields NoOpinion (the
      # upstream default for failurePolicy NoOpinion) unless configured to deny.
      class Webhook
        NAME = "Webhook"

        # transport.call(body_json) -> [status_code, body_json]
        def initialize(transport:, authorized_ttl: 300, unauthorized_ttl: 30, clock: -> { Time.now.utc }, failure_policy: "NoOpinion", version: "v1")
          @transport = transport
          @authorized_ttl = authorized_ttl
          @unauthorized_ttl = unauthorized_ttl
          @clock = clock
          @failure_policy = failure_policy
          @version = version
          @cache = {}
          @mutex = Mutex.new
        end

        def name
          NAME
        end

        def authorize(attributes)
          key = attributes.to_h
          now = @clock.call
          cached = @mutex.synchronize { @cache[key] }
          return cached[:decision] if cached && cached[:expires_at] > now

          review = {"apiVersion" => "authorization.k8s.io/#{@version}", "kind" => "SubjectAccessReview", "spec" => key}
          decision = begin
            code, body = @transport.call(JSON.generate(review))
            raise Error, "webhook authorizer returned HTTP #{code}" unless code.to_i.between?(200, 299)

            response = body.is_a?(String) ? JSON.parse(body) : body
            status = response.is_a?(Hash) ? (response["status"] || {}) : {}
            if status["allowed"] == true
              Decision.allow(status["reason"], authorizer: NAME)
            elsif status["denied"] == true
              Decision.deny(status["reason"], authorizer: NAME)
            else
              Decision.no_opinion(status["reason"], authorizer: NAME)
            end
          rescue Error, JSON::ParserError, SystemCallError, IOError => error
            @failure_policy == "Deny" ? Decision.deny("Webhook: #{error.message}", authorizer: NAME) : Decision.no_opinion("Webhook: #{error.message}", authorizer: NAME)
          end
          ttl = decision.allowed? ? @authorized_ttl : @unauthorized_ttl
          @mutex.synchronize { @cache[key] = {decision: decision, expires_at: now + ttl} }
          decision
        end
      end
    end
  end
end
