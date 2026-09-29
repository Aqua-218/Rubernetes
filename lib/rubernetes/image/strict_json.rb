# frozen_string_literal: true

require "json"

module Rubernetes
  module Image
    # Bounded, unambiguous decoding for registry-controlled OCI JSON. Ruby's
    # default parser silently accepts duplicate object keys, which can make a
    # digest-verified document mean different things to different consumers.
    module StrictJSON
      DEFAULT_MAX_BYTES = 1024 * 1024
      DEFAULT_MAX_DEPTH = 100

      class Error < StandardError; end
      class DuplicateKeyError < Error; end
      class LimitError < Error; end
      class ParseError < Error; end

      class DuplicateCheckingHash < Hash
        def []=(key, value)
          raise DuplicateKeyError, "duplicate JSON object key #{key.inspect}" if key?(key)

          super
        end
      end

      module_function

      def parse(input, max_bytes: DEFAULT_MAX_BYTES, max_depth: DEFAULT_MAX_DEPTH)
        raise ParseError, "JSON input must be a String" unless input.is_a?(String)

        byte_limit = positive_integer(max_bytes, "max_bytes")
        depth_limit = positive_integer(max_depth, "max_depth")
        raise LimitError, "JSON document exceeds #{byte_limit} bytes" if input.bytesize > byte_limit

        utf8 = input.dup.force_encoding(Encoding::UTF_8)
        raise ParseError, "JSON input is not valid UTF-8" unless utf8.valid_encoding?

        value = JSON.parse(
          utf8,
          object_class: DuplicateCheckingHash,
          array_class: Array,
          allow_nan: false,
          max_nesting: depth_limit + 1
        )
        validate_depth!(value, depth_limit)
      rescue Error
        raise
      rescue JSON::NestingError => error
        raise LimitError, "JSON nesting exceeds #{depth_limit} levels", cause: error
      rescue JSON::ParserError, EncodingError, TypeError => error
        raise ParseError, "invalid JSON: #{error.message}", cause: error
      end

      def validate_depth!(value, maximum, depth: 0)
        raise LimitError, "JSON nesting exceeds #{maximum} levels" if depth > maximum

        case value
        when Array
          value.each { |child| validate_depth!(child, maximum, depth: depth + 1) }
        when Hash
          value.each_value { |child| validate_depth!(child, maximum, depth: depth + 1) }
        end
        value
      end

      def positive_integer(value, name)
        integer = Integer(value)
        raise ArgumentError, "#{name} must be positive" unless integer.positive?

        integer
      rescue ArgumentError, TypeError => error
        raise ParseError, "#{name} must be a positive integer: #{error.message}", cause: error
      end
      private_class_method :positive_integer
    end
  end
end
