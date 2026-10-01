# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      class Error < StandardError
        attr_reader :errno, :operation, :resource_id, :details

        def initialize(errno:, operation:, resource_id:, details: {})
          @errno = Integer(errno)
          @operation = String(operation).dup.freeze
          @resource_id = String(resource_id).dup.freeze
          @details = details.dup.freeze
          description = SystemCallError.new(@operation, @errno).message
          super("#{description}; resource=#{@resource_id}")
        end

        def code
          Errno.constants.find do |name|
            candidate = Errno.const_get(name)
            candidate.is_a?(Class) && candidate < SystemCallError && errno == candidate::Errno
          end
        end

        def to_h
          {
            errno: errno,
            errno_name: code&.then { |klass| klass.name.to_s.split("::").last },
            operation: operation,
            resource_id: resource_id,
            details: details,
            message: message
          }
        end

        def self.wrap(error, operation:, resource_id:, details: {})
          raise ArgumentError, "error does not carry errno" unless error.respond_to?(:errno) && error.errno

          new(errno: error.errno, operation: operation, resource_id: resource_id, details: details)
        end
      end
    end
  end
end
