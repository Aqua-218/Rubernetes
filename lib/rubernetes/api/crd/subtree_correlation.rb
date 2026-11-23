# frozen_string_literal: true

module Rubernetes
  module API
    module CRD
      # Pairs each new structural value with its old value. Objects correlate
      # by property name and map-lists by declared keys. Other lists are
      # indivisible for validation ratcheting and CEL transition rules.
      class SubtreeCorrelation
        attr_reader :value, :old_value

        def initialize(value, old_value, schema)
          @value = value
          @old_value = old_value
          @schema = schema
          @children = {}
        end

        def child(key)
          @children.fetch(key) { @children[key] = correlate_child(key) }
        end

        def unchanged?
          return @unchanged unless @unchanged.nil?

          @unchanged = value.eql?(old_value) || matching_children?
        end

        private

        def correlate_child(key)
          case value
          when Hash
            return unless old_value.is_a?(Hash) && old_value.key?(key) && value.key?(key)

            child_schema = (@schema["properties"] || {})[key] || @schema["additionalProperties"]
            self.class.new(value[key], old_value[key], child_schema) if child_schema.is_a?(Hash)
          when Array
            return unless @schema["x-kubernetes-list-type"] == "map" && old_value.is_a?(Array)

            old_item = map_list[map_list_key(value[key])]
            self.class.new(value[key], old_item, @schema.fetch("items")) if old_item
          end
        end

        def map_list
          @map_list ||= old_value.each_with_object({}) do |item, keyed|
            key = map_list_key(item)
            keyed[key] ||= item if key
          end
        end

        def map_list_key(item)
          return unless item.is_a?(Hash)

          keys = @schema.fetch("x-kubernetes-list-map-keys", [])
          return unless keys.all? { |key| item.key?(key) }

          keys.map { |key| item[key] }
        end

        def matching_children?
          case value
          when Hash
            old_value.is_a?(Hash) && value.size == old_value.size && value.each_key.all? { |key| child(key)&.unchanged? }
          when Array
            old_value.is_a?(Array) && value.size == old_value.size && value.each_index.all? { |index| child(index)&.unchanged? }
          else
            false
          end
        end
      end
    end
  end
end
