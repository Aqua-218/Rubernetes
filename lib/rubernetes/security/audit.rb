# frozen_string_literal: true

require_relative "identity"
require_relative "audit/policy"
require_relative "audit/event"
require_relative "audit/backend"

module Rubernetes
  module Security
    module Audit
      # Per-request audit context: evaluates the policy once and emits the
      # RequestReceived / ResponseStarted / ResponseComplete / Panic stages.
      class Context
        attr_reader :audit_id, :level, :annotations

        def initialize(policy:, backend:, attributes:, request:, audit_id:, clock: -> { Time.now.utc })
          @policy = policy
          @backend = backend
          @attributes = attributes
          @request = request
          @audit_id = audit_id
          @clock = clock
          @level, @omitted_stages, @omit_managed_fields = policy.evaluate(attributes)
          # ObservePolicyLevel: one per request, None included.
          backend.observe_level(@level) if backend.respond_to?(:observe_level)
          @annotations = {}
          @request_object = nil
          @impersonated = nil
          @impersonation_constraint = nil
          @received_at = clock.call
        end

        def enabled?
          @level != "None"
        end

        def annotate(key, value)
          @annotations[key.to_s] = value.to_s
        end

        # audit.LogImpersonatedUser: the constraint is the constrained
        # impersonation verb that allowed it ("" for the legacy verb).
        def impersonated(user, constraint)
          @impersonated = user
          @impersonation_constraint = constraint.to_s
        end

        def request_object=(object)
          @request_object = object
        end

        def request_received
          emit("RequestReceived")
        end

        def response_started(response)
          emit("ResponseStarted", response: response)
        end

        def response_complete(response, response_object: nil)
          emit("ResponseComplete", response: response, response_object: response_object)
        end

        def panic(error)
          annotate("panic", "#{error.class}: #{error.message}")
          emit("Panic")
        end

        private

        def emit(stage, response: nil, response_object: nil)
          return unless enabled?
          return if @omitted_stages.include?(stage)

          event = Event.build(stage: stage, level: @level, audit_id: @audit_id, attributes: @attributes, request: @request,
                              response: response, request_object: @request_object, response_object: response_object,
                              omit_managed_fields: @omit_managed_fields, now: @clock.call, annotations: @annotations.dup,
                              impersonated: @impersonated, impersonation_constraint: @impersonation_constraint)
          event["requestReceivedTimestamp"] = @received_at.iso8601(6)
          @backend.process(event)
        end
      end
    end
  end
end
