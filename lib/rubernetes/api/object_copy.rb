# frozen_string_literal: true

require_relative "../support/object_tree"

module Rubernetes
  module API
    # Copy JSON containers and normalize field names at the API boundary.
    module ObjectCopy
      private

      def deep_copy(value) = ObjectTree.stringify_keys(value)
    end
  end
end
