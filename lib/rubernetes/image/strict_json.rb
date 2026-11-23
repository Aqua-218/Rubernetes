# frozen_string_literal: true

require_relative "../support/bounded_json"

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
        BoundedJSON.parse(input, StrictJSON, max_bytes: max_bytes, max_depth: max_depth)
      end

      def validate_depth!(value, maximum, depth: 0)
        BoundedJSON.validate_depth!(value, maximum, LimitError, depth: depth)
      end
    end
  end
end
