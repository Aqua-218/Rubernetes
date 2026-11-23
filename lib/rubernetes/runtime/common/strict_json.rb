# frozen_string_literal: true

require_relative "../../support/bounded_json"

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
        BoundedJSON.parse(input, StrictJSON, max_bytes: max_bytes, max_depth: max_depth, require_newline: require_newline)
      end

      def validate_depth!(value, maximum, depth: 0)
        BoundedJSON.validate_depth!(value, maximum, LimitError, depth: depth)
      end
    end
  end
end
