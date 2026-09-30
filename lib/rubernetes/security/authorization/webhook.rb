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
        def initialize(transport:, authorized_ttl: 300, unauthorized_ttl: 30, clock: -> { Time.now.utc }, failure_policy: "NoOpinion", version: "v1",
                       name: NAME, match_conditions: nil)
          @transport = transport
          @name = name.to_s.empty? ? NAME : name.to_s
          @match_conditions = match_conditions
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
          @name
        end

        attr_reader :match_conditions

        def authorize(attributes)
          key = attributes.to_h
          # matchConditions first: an evaluation error (and no false) is the
          # failure policy's decision; a false skips the webhook.
          if @match_conditions && !@match_conditions.empty?
            outcome = @match_conditions.evaluate(key)
            if outcome.error
              return @failure_policy == "Deny" ? Decision.deny("Webhook: #{outcome.error.message}", authorizer: name) : Decision.no_opinion("Webhook: #{outcome.error.message}", authorizer: name)
            end
            return Decision.no_opinion("Webhook: match conditions excluded the request", authorizer: name) unless outcome.matches
          end
          now = @clock.call
          cached = @mutex.synchronize { @cache[key] }
          return cached[:decision] if cached && cached[:expires_at] > now

          review = {"apiVersion" => "authorization.k8s.io/#{@version}", "kind" => "SubjectAccessReview", "spec" => key}
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = "success"
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
            result = error.is_a?(Errno::ETIMEDOUT) || error.message.to_s.match?(/timed? ?out/i) ? "timeout" : "error"
            fail_open = @failure_policy != "Deny"
            self.class.record_fail_open(name, result) if fail_open
            fail_open ? Decision.no_opinion("Webhook: #{error.message}", authorizer: NAME) : Decision.deny("Webhook: #{error.message}", authorizer: NAME)
          end
          self.class.record_evaluation(name, result, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          ttl = decision.allowed? ? @authorized_ttl : @unauthorized_ttl
          @mutex.synchronize { @cache[key] = {decision: decision, expires_at: now + ttl} }
          decision
        end
      end
    end
  end
end
