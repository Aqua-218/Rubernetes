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

        # k8s.io/apiserver/plugin/pkg/authorizer/webhook/metrics on the
        # process-wide registry: every SubjectAccessReview round trip
        # (result "success", "error" or "timeout") and the ones a NoOpinion
        # failure policy let through.
        class << self
          def registry
            return nil unless defined?(Rubernetes::Observability::Metrics)

            Rubernetes::Observability::Metrics.global
          end

          def record_evaluation(name, result, seconds)
            metrics = registry
            return unless metrics

            %w[apiserver_authorization_webhook_evaluations_total apiserver_authorization_webhook_evaluations_fail_open_total].each do |metric|
              metrics.register(metric, type: :counter) unless metrics.registered?(metric)
            end
            metrics.register("apiserver_authorization_webhook_duration_seconds", type: :histogram) unless metrics.registered?("apiserver_authorization_webhook_duration_seconds")
            metrics.increment("apiserver_authorization_webhook_evaluations_total", {"name" => name.to_s, "result" => result})
            metrics.observe("apiserver_authorization_webhook_duration_seconds", seconds, {"name" => name.to_s, "result" => result})
          rescue StandardError
            nil
          end

          def record_fail_open(name, result)
            metrics = registry
            return unless metrics

            metrics.register("apiserver_authorization_webhook_evaluations_fail_open_total", type: :counter) unless metrics.registered?("apiserver_authorization_webhook_evaluations_fail_open_total")
            metrics.increment("apiserver_authorization_webhook_evaluations_fail_open_total", {"name" => name.to_s, "result" => result})
          rescue StandardError
            nil
          end
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
