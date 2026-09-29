# frozen_string_literal: true

require "json"

module Rubernetes
  module Runtime
    # Bounded JSON decoding for durable runtime records. Ruby's JSON parser
    # otherwise silently keeps the last value for duplicate object members,
    # which would make a signed/hash-chained record ambiguous at recovery time.
    module StrictJSON
      DEFAULT_MAX_BYTES = 1 * 1024 * 1024
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

      def parse(input, max_bytes: DEFAULT_MAX_BYTES, max_depth: DEFAULT_MAX_DEPTH, require_newline: false)
        raise ParseError, "JSON input must be a String" unless input.is_a?(String)

        max_bytes = positive_integer(max_bytes, "max_bytes")
        max_depth = positive_integer(max_depth, "max_depth")
        raise LimitError, "JSON document exceeds #{max_bytes} bytes" if input.bytesize > max_bytes
        if require_newline && !input.end_with?("\n")
          raise ParseError, "JSON document is not newline terminated"
        end

        utf8 = input.dup.force_encoding(Encoding::UTF_8)
        raise ParseError, "JSON input is not valid UTF-8" unless utf8.valid_encoding?

        value = JSON.parse(
          utf8,
          object_class: DuplicateCheckingHash,
          array_class: Array,
          create_additions: false,
          allow_nan: false,
          max_nesting: max_depth + 1
        )
        validate_depth!(value, max_depth)
      rescue Error
        raise
      rescue JSON::NestingError => error
        raise LimitError, "JSON nesting exceeds #{max_depth} levels", cause: error
      rescue JSON::ParserError, EncodingError, TypeError => error
        raise ParseError, "invalid JSON: #{error.message}", cause: error
      end

      def validate_depth!(value, max_depth, depth: 0)
        raise LimitError, "JSON nesting exceeds #{max_depth} levels" if depth > max_depth

        case value
        when Array
          value.each { |child| validate_depth!(child, max_depth, depth: depth + 1) }
        when Hash
          value.each_value { |child| validate_depth!(child, max_depth, depth: depth + 1) }
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
