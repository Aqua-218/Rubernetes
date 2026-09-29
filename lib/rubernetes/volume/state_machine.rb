# frozen_string_literal: true

module Rubernetes
  module Volume
    # The node/controller lifecycle from spec/node/volume.md.  Transitions are
    # explicit so an ambiguous adapter response can never be guessed into a
    # successful attach or mount.
    class StateMachine
      STATES = %w[Declared Provisioned Attached Staged Published Unpublishing Unstaged Detached Unknown].freeze
      TRANSITIONS = {
        "Declared" => %w[Provisioned Unknown],
        "Provisioned" => %w[Attached Detached Unknown],
        "Attached" => %w[Staged Detached Unknown],
        "Staged" => %w[Published Unstaged Unknown],
        "Published" => %w[Unpublishing Unknown],
        "Unpublishing" => %w[Staged Unstaged Unknown],
        "Unstaged" => %w[Detached Attached Unknown],
        "Detached" => %w[Attached Provisioned Unknown],
        "Unknown" => %w[Declared Provisioned Attached Staged Published Unpublishing Unstaged Detached Unknown]
      }.freeze

      UNKNOWN_ALLOWED_ACTIONS = %w[Observe Recover Cleanup].freeze

      Transition = Struct.new(:from, :to, :operation, :token, :generation, keyword_init: true) do
        def to_h
          {"from" => from, "to" => to, "operation" => operation, "token" => token, "generation" => generation}
        end
      end

      def self.allowed?(from, to)
        return true if from.to_s == to.to_s

        TRANSITIONS.fetch(from.to_s, []).include?(to.to_s)
      end

      def self.validate!(from, to)
        return true if allowed?(from, to)

        raise InvalidStateError, "invalid volume transition #{from.inspect} -> #{to.inspect}"
      end

      class << self
        alias valid? allowed?
        alias transition_allowed? allowed?
      end

      def self.unknown?(state)
        state.to_s == "Unknown"
      end

      def self.action_allowed?(state, action)
        !unknown?(state) || UNKNOWN_ALLOWED_ACTIONS.include?(action.to_s)
      end

      def self.ensure_action!(state, action)
        return true if action_allowed?(state, action)

        raise StateUnknownError, "volume is Unknown; only observe, recovery, or cleanup is permitted"
      end

      def initialize(state: "Declared", generation: 0)
        @state = state.to_s
        raise ValidationError, "unknown volume state #{@state.inspect}" unless STATES.include?(@state)

        @generation = Integer(generation)
      end

      attr_reader :state, :generation

      alias status state

      def transition(to, operation: "transition", token: nil)
        target = to.to_s
        self.class.validate!(@state, target)
        from = @state
        @state = target
        @generation += 1 unless from == target
        Transition.new(from: from, to: target, operation: operation.to_s, token: token&.to_s, generation: @generation).freeze
      end

      def unknown!(operation: "recovery", token: nil)
        transition("Unknown", operation: operation, token: token)
      end

      def ensure_action!(action)
        self.class.ensure_action!(@state, action)
      end
    end

    VolumeStateMachine = StateMachine unless const_defined?(:VolumeStateMachine, false)
  end
end
