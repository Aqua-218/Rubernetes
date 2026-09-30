# frozen_string_literal: true

module Rubernetes
  # Raised when an operation has no primary failure but one or more cleanup
  # operations failed. The individual exceptions remain available so callers
  # can report or retry every failed cleanup rather than only the first one.
  class CleanupError < StandardError
    attr_reader :cleanup_errors

    def initialize(message = nil, cleanup_errors: [])
      @cleanup_errors = Array(cleanup_errors).compact.freeze
      super(message || "cleanup failed with #{@cleanup_errors.length} error(s)")
    end
  end

  # Shared exception plumbing for shutdown paths. Cleanup must not replace a
  # parser, consumer, or worker failure that is already in flight.
  module Cleanup
    module_function

    def attach(primary_error, cleanup_errors)
      failures = Array(cleanup_errors).compact
      return primary_error if failures.empty?

      existing = primary_error.respond_to?(:cleanup_errors) ? Array(primary_error.cleanup_errors) : []
      combined = (existing + failures).freeze
      primary_error.instance_variable_set(:@cleanup_errors, combined)
      primary_error.define_singleton_method(:cleanup_errors) { @cleanup_errors } unless primary_error.respond_to?(:cleanup_errors)
      primary_error
    rescue StandardError
      # A frozen or otherwise restricted exception cannot carry a singleton
      # field. The original exception remains the primary failure; callers
      # still receive the cleanup aggregate when there is no primary error.
      primary_error
    end

    def aggregate(cleanup_errors, operation: "cleanup")
      failures = Array(cleanup_errors).compact
      return nil if failures.empty?

      CleanupError.new(
        "#{operation} failed with #{failures.length} cleanup error(s)",
        cleanup_errors: failures
      )
    end
  end
end
