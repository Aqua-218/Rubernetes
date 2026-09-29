# frozen_string_literal: true

module Rubernetes
  module Network
    # Base error raised by the data-plane implementation.
    class Error < StandardError; end

    class ValidationError < Error; end
    class DurabilityError < Error; end
    class TransactionError < Error; end
    class OwnershipError < Error; end
    class OperationConflict < OwnershipError; end
    class LeaseError < TransactionError; end
    class LeaseUnavailable < LeaseError; end
    class LeaseStateError < LeaseError; end
    class RecoveryRequired < Error; end
    class NetlinkError < Error
      attr_reader :errno, :operation, :sequence

      def initialize(message, errno: nil, operation: nil, sequence: nil)
        super(message)
        @errno = errno
        @operation = operation
        @sequence = sequence
      end
    end

    class PolicyError < Error; end
    class PolicyRevisionError < PolicyError; end
    class DNSQueryError < Error; end
    class DNSUpstreamError < DNSQueryError; end
    class DNSProjectionError < Error; end

    # Raised when an injected adapter reports a failure.  The exception keeps
    # the operation and the original cause so callers can decide whether a
    # retry is safe without parsing an error string.
    class EffectError < Error
      attr_reader :operation, :cause_error, :applied

      def initialize(message, operation: nil, cause_error: nil, applied: nil)
        super(message)
        @operation = operation
        @cause_error = cause_error
        @applied = applied
      end
    end
  end
end
