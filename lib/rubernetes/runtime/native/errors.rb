# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      class Error < Rubernetes::Runtime::Error; end
      class ConfigurationError < Error; end
      class CapabilityError < Error; end
      class InvalidState < Error; end
      class ResourceError < Error
        attr_reader :cleanup_errors

        def initialize(message = nil, cleanup_errors: [])
          super(message)
          @cleanup_errors = Array(cleanup_errors).map do |entry|
            entry.respond_to?(:dup) ? entry.dup.freeze : entry
          end.freeze
        end
      end
      class UnsupportedProfile < Error; end
      class FailClosed < Error; end
    end
  end
end
