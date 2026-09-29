# frozen_string_literal: true

module Rubernetes
  module Runtime
    # Base error for runtime lifecycle and durability failures.
    class Error < StandardError
      attr_reader :operation_id, :cleanup_errors

      def initialize(message = nil, operation_id: nil, cleanup_errors: [])
        super(message)
        @operation_id = operation_id
        @cleanup_errors = Array(cleanup_errors).map { |error| error.dup.freeze }.freeze
      end
    end

    class ValidationError < Error; end
    class InvalidTransition < Error; end
    class OwnershipConflict < Error; end
    class JournalCorruption < Error; end
    class SnapshotCorruption < Error; end
    class RecoveryRequired < Error; end
    class StateUnknownError < RecoveryRequired; end
    class AmbiguousResult < RecoveryRequired; end

    # Keeps the first effect error as the primary failure while exposing every
    # cleanup error.  Cleanup failures must never hide the operation failure.
    class OperationFailure < Error
      attr_reader :cause_error

      def initialize(message, operation_id:, cause_error:, cleanup_errors: [])
        @cause_error = cause_error
        super(message, operation_id: operation_id, cleanup_errors: cleanup_errors)
      end
    end

    class IdentityMismatch < OwnershipConflict; end
  end
end
