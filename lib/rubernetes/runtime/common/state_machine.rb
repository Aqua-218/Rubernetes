# frozen_string_literal: true

require_relative "errors"

module Rubernetes
  module Runtime
    # Explicit lifecycle graph from §5.8.3.  The graph is intentionally kept
    # data-driven so traces can be compared with the normative state machine.
    class StateMachine
      STATES = %w[
        New Validated ImagePinned WorkspaceAllocated IsolationCreated
        ResourcesAttached WorkloadStopped Running Stopping Stopped Removed
        RollingBack CleanupPending StateUnknown
      ].freeze

      TRANSITIONS = {
        "New" => %w[Validated RollingBack StateUnknown],
        "Validated" => %w[ImagePinned RollingBack StateUnknown],
        "ImagePinned" => %w[WorkspaceAllocated RollingBack StateUnknown],
        "WorkspaceAllocated" => %w[IsolationCreated RollingBack StateUnknown],
        "IsolationCreated" => %w[ResourcesAttached RollingBack StateUnknown],
        "ResourcesAttached" => %w[WorkloadStopped RollingBack StateUnknown],
        "WorkloadStopped" => %w[Running RollingBack StateUnknown],
        "Running" => %w[Stopping StateUnknown],
        "Stopping" => %w[Stopped RollingBack StateUnknown],
        "Stopped" => %w[Removed RollingBack CleanupPending],
        "Removed" => [],
        "RollingBack" => %w[Stopped CleanupPending],
        "CleanupPending" => %w[RollingBack StateUnknown],
        "StateUnknown" => %w[Stopping RollingBack CleanupPending]
      }.freeze

      CLEANUP_STATES = %w[RollingBack CleanupPending StateUnknown].freeze
      UNKNOWN_ALLOWED_ACTIONS = %w[Cleanup Observe].freeze

      Transition = Struct.new(:from, :to, :operation_id, :owned_resources, :config_digest, keyword_init: true) do
        def to_h
          {
            "from" => from,
            "to" => to,
            "operation_id" => operation_id,
            "owned_resources" => Array(owned_resources),
            "config_digest" => config_digest
          }
        end
      end

      def self.allowed?(from, to)
        return true if from.to_s == to.to_s

        TRANSITIONS.fetch(from.to_s, []).include?(to.to_s)
      end

      def self.validate!(from, to)
        return true if allowed?(from, to)

        raise InvalidTransition, "invalid runtime transition #{from.inspect} -> #{to.inspect}"
      end

      def self.cleanup_state?(state)
        CLEANUP_STATES.include?(state.to_s)
      end

      def self.action_allowed?(state, action)
        state.to_s != "StateUnknown" || UNKNOWN_ALLOWED_ACTIONS.include?(action.to_s)
      end

      def self.ensure_action!(state, action)
        return true if action_allowed?(state, action)

        raise StateUnknownError, "StateUnknown permits cleanup or observe only; #{action} is forbidden"
      end

      def initialize(state: "New", operation_id: nil, config_digest: nil, owned_resources: [])
        raise ValidationError, "unknown runtime state #{state.inspect}" unless STATES.include?(state.to_s)

        @state = state.to_s
        @operation_id = operation_id&.to_s
        @config_digest = config_digest&.to_s
        @owned_resources = Array(owned_resources).map(&:to_s).freeze
        @gate_released = @state == "Running"
      end

      attr_reader :state, :operation_id, :config_digest, :owned_resources

      def gate_released?
        @gate_released
      end

      def transition(to, owned_resources: @owned_resources)
        to = to.to_s
        self.class.validate!(@state, to)
        if to == "Running" && @gate_released
          raise InvalidTransition, "workload gate can only be released once"
        end

        from = @state
        @state = to
        @owned_resources = Array(owned_resources).map(&:to_s).freeze
        @gate_released = true if to == "Running"
        Transition.new(from: from, to: to, operation_id: @operation_id,
                       owned_resources: @owned_resources, config_digest: @config_digest).freeze
      end

      def release_gate!
        transition("Running")
      end

      def workload_effect_allowed?
        @state == "Running" && @gate_released
      end

      def cleanup_only?
        self.class.cleanup_state?(@state)
      end
    end

    State = StateMachine
  end
end
