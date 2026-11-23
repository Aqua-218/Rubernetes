# frozen_string_literal: true

require "json"

module Rubernetes
  # The caller supplies its protocol-specific errors and duplicate-checking Hash.
  module BoundedJSON
    module_function

    def parse(input, family, max_bytes:, max_depth:, require_newline: false)
      raise family::ParseError, "JSON input must be a String" unless input.is_a?(String)

      max_bytes = positive_integer(max_bytes, "max_bytes", family::ParseError)
      max_depth = positive_integer(max_depth, "max_depth", family::ParseError)
      raise family::LimitError, "JSON document exceeds #{max_bytes} bytes" if input.bytesize > max_bytes
      raise family::ParseError, "JSON document is not newline terminated" if require_newline && !input.end_with?("\n")

      utf8 = input.dup.force_encoding(Encoding::UTF_8)
      raise family::ParseError, "JSON input is not valid UTF-8" unless utf8.valid_encoding?

      value = JSON.parse(
        utf8,
        object_class: family::DuplicateCheckingHash,
        array_class: Array,
        allow_nan: false,
        max_nesting: max_depth + 1
      )
      validate_depth!(value, max_depth, family::LimitError)
    rescue JSON::NestingError => error
      raise family::LimitError, "JSON nesting exceeds #{max_depth} levels", cause: error
    rescue JSON::ParserError, EncodingError, TypeError => error
      raise family::ParseError, "invalid JSON: #{error.message}", cause: error
    end

    def validate_depth!(value, max_depth, limit_error, depth: 0)
      raise limit_error, "JSON nesting exceeds #{max_depth} levels" if depth > max_depth

      case value
      when Array
        value.each { |child| validate_depth!(child, max_depth, limit_error, depth: depth + 1) }
      when Hash
        value.each_value { |child| validate_depth!(child, max_depth, limit_error, depth: depth + 1) }
      end
      value
    end

    def positive_integer(value, name, parse_error)
      integer = Integer(value)
      raise ArgumentError, "#{name} must be positive" unless integer.positive?

      integer
    rescue ArgumentError, TypeError => error
      raise parse_error, "#{name} must be a positive integer: #{error.message}", cause: error
    end
    private_class_method :positive_integer
  end
end
