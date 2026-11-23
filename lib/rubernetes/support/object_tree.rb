# frozen_string_literal: true

module Rubernetes
  # Operations on acyclic Hash/Array trees. Copies own the containers and share scalar values.
  module ObjectTree
    module_function

    def copy(value)
      case value
      when Hash
        result = {}
        value.each_pair { |key, child| result[key] = copy(child) }
        result
      when Array then value.map { |child| copy(child) }
      else value
      end
    end

    def stringify_keys(value)
      case value
      when Hash
        result = {}
        value.each_pair { |key, child| result[key.to_s] = stringify_keys(child) }
        result
      when Array then value.map { |child| stringify_keys(child) }
      else value
      end
    end

    def deep_freeze(value, nested_keys: true)
      case value
      when Hash
        value.each_pair do |key, child|
          nested_keys ? deep_freeze(key) : key.freeze
          deep_freeze(child, nested_keys: nested_keys)
        end
      when Array
        value.each { |child| deep_freeze(child, nested_keys: nested_keys) }
      end
      value.freeze
    end
  end
end
