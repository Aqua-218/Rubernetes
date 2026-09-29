# frozen_string_literal: true

module Rubernetes
  # Declarative control-loop primitives and the built-in controller runtime.
  module Controller
    class Error < StandardError; end

    class ValidationError < Error; end
    class UnknownGVKError < ValidationError; end
    class UnknownControllerError < ValidationError; end
    class DuplicateControllerError < ValidationError; end
    class OwnershipCycleError < ValidationError; end
    class ScopeMismatchError < ValidationError; end
    class MissingReconcileError < ValidationError; end
    class InvalidWatchError < ValidationError; end
    class MissingControllerError < ValidationError; end
    class RegistrySealedError < ValidationError; end

    class StoreError < Error; end
    class LeaseConflictError < StoreError; end
    class LeadershipLostError < StoreError; end
    class ProviderUnavailableError < Error; end
  end
end
