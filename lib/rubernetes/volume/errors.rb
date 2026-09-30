# frozen_string_literal: true

module Rubernetes
  module Volume
    class Error < StandardError
      attr_reader :operation, :resource_id, :details

      def initialize(message = nil, operation: nil, resource_id: nil, details: nil)
        super(message)
        @operation = operation
        @resource_id = resource_id
        @details = details
      end
    end

    class ValidationError < Error; end
    class UnsupportedError < Error; end
    class NotFoundError < Error; end
    class ConflictError < Error; end
    class CapacityError < ValidationError; end
    class BindingError < ConflictError; end
    class MultiAttachError < ConflictError; end
    class InvalidStateError < ConflictError; end
    class StateUnknownError < ConflictError; end
    class OperationTokenError < ConflictError; end
    class OperationTokenConflict < OperationTokenError; end
    class OperationUnknown < OperationTokenError; end
    class SecurityError < Error; end
    class PathSecurityError < SecurityError; end
    class MountIdentityError < SecurityError; end

    # A cleanup response that is false, raises, or cannot be verified leaves
    # the resource ownership ambiguous. Callers must fence the volume and let
    # recovery reconcile the effect instead of treating the original error as
    # a deterministic failure.
    class CleanupError < MountIdentityError
      attr_reader :cleanup_errors

      def initialize(message = nil, cleanup_errors: [], **)
        super(message, **)
        @cleanup_errors = Array(cleanup_errors).freeze
      end

      def ambiguous?
        true
      end
    end

    class SecretPersistenceError < SecurityError; end
    # A projected podCertificate whose PodCertificateRequest is not issued yet.
    class PodCertificateNotReadyError < Error; end
    # Snapshot payload bytes no longer match the digests recorded when the
    # snapshot was taken.  Restoring them would present corrupted data as a
    # faithful copy, so the restore must fail before any file is written.
    class SnapshotIntegrityError < SecurityError; end

    class CSIError < Error
      attr_reader :ambiguous

      def initialize(message = nil, ambiguous: false, **)
        super(message, **)
        @ambiguous = ambiguous == true
      end

      def ambiguous?
        ambiguous
      end
    end

    class CSIUnavailable < UnsupportedError; end
    class JournalError < Error; end
  end
end
