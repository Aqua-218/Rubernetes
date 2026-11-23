# frozen_string_literal: true

module Rubernetes
  # Detached copies for informer and controller objects. Track container
  # identity so shared children and cycles survive copying.
  module ObjectGraph
    module_function

    def copy(value, seen = nil, immutable: false, &copy_object)
      case value
      when Hash, Array
        seen ||= {}.compare_by_identity
        return seen[value] if seen.key?(value)

        if value.is_a?(Hash)
          result = seen[value] = {}
          value.each_pair do |key, child|
            result[copy(key, seen, immutable: immutable, &copy_object)] = copy(child, seen, immutable: immutable, &copy_object)
          end
        else
          result = seen[value] = []
          value.each { |child| result << copy(child, seen, immutable: immutable, &copy_object) }
        end
      when String then result = value.dup
      when Symbol, Numeric, TrueClass, FalseClass, NilClass then return value
      else
        return yield(value, seen, immutable: immutable) if block_given?

        result = value
      end
      immutable ? result.freeze : result
    end

    def immutable_copy(value, frozen_roots, &)
      return value if frozen_roots.key?(value)

      result = copy(value, nil, immutable: true, &)
      frozen_roots[result] = true if result.is_a?(Hash) || result.is_a?(Array)
      result
    end

    def deep_freeze(value, seen = nil)
      case value
      when Symbol, Numeric, TrueClass, FalseClass, NilClass then return value
      when Hash, Array
        seen ||= {}.compare_by_identity
        return value if seen.key?(value)

        seen[value] = true
        if value.is_a?(Hash)
          value.each_pair do |key, child|
            deep_freeze(key, seen)
            deep_freeze(child, seen)
          end
        else
          value.each { |child| deep_freeze(child, seen) }
        end
      end
      value.freeze
    end
  end
end
