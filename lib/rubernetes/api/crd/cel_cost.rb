# frozen_string_literal: true

module Rubernetes
  module API
    module CRD
      # Static CEL work for a structural schema. Bound collection traversal by
      # its schema or by the maximum custom-resource request size.
      module CELCost
        MAX_REQUEST_BYTES = 3 * 1024 * 1024
        SCHEMA_TYPES = Security::Admission::PolicyTypeChecker::SchemaTypes
        STRING_MIN_SIZE = {"date" => 12, "date-time" => 12, "duration" => 3}.freeze
        STRING_MAX_SIZE = {"date" => 12, "date-time" => 32, "duration" => 32}.freeze
        STRING_TRAVERSAL_FACTOR = 0.1
        REGEX_LENGTH_FACTOR = 0.25
        LIST_TRAVERSALS = %w[sum min max isSorted indexOf lastIndexOf].freeze
        STRING_TRAVERSALS = %w[lowerAscii upperAscii trim split replace substring charAt].freeze
        PREFIX_SUFFIX = %w[startsWith endsWith].freeze
        LOGICAL_OPERATORS = %w[_&&_ _||_].freeze
        COMPARISONS = %w[_==_ _!=_ _<_ _<=_ _>_ _>=_].freeze

        module_function

        def cost(node, scope)
          case node.kind
          when :literal then 0
          when :ident then 1
          when :select then (node.test_only ? 0 : 1) + cost(node.operand, scope)
          when :call then call_cost(node, scope)
          when :list then 10 + node.elements.sum { |child| cost(child, scope) }
          when :map then 30 + node.entries.sum { |entry| cost(entry.key, scope) + cost(entry.value, scope) }
          when :struct then 40 + node.fields.sum { |field| cost(field.value, scope) }
          when :comprehension then comprehension_cost(node, scope)
          else 0
          end
        end

        def comprehension_cost(node, scope)
          range = node.iter_range
          schema = schema_for(range, scope)
          element = schema["items"] || schema["additionalProperties"] || {}
          iter = if schema["type"] == "object"
                   # CEL DeclType's map key is the shared StringType, whose
                   # MaxElements is zero. Only map values carry schema bounds.
                   {"type" => "string", "maxLength" => 0}
                 elsif node.iter_var2
                   {"type" => "integer"}
                 else
                   element
                 end
          locals = scope.merge(node.accu_var => schema_for(node.accu_init, scope), node.iter_var => iter)
          locals[node.iter_var2] = element if node.iter_var2
          item_cost = cost(node.loop_condition, locals) + cost(node.loop_step, locals)
          cost(range, scope) + cost(node.accu_init, scope) + cost(node.result, locals) + (size(range, scope) * item_cost)
        end

        def call_cost(node, scope)
          args = node.args
          target_cost = node.target ? cost(node.target, scope) : 0
          return target_cost + cost(args[0], scope) + args.drop(1).map { |branch| cost(branch, scope) }.max if node.name == "_?_:_"

          target_cost + args.sum { |arg| cost(arg, scope) } + intrinsic_cost(node, scope)
        end

        def intrinsic_cost(node, scope)
          args = node.args
          target = node.target
          return 0 if LOGICAL_OPERATORS.include?(node.name)
          return size(args[1], scope) if node.name == "@in" && schema_for(args[1], scope)["type"] == "array"
          return traversal(args[0], scope) if target && PREFIX_SUFFIX.include?(node.name)
          return traversal(target, scope) * traversal(args[0], scope) if target && node.name == "contains"

          if target && node.name == "matches"
            regex_cost = (size(args[0], scope) * REGEX_LENGTH_FACTOR).ceil
            return traversal(target, scope, padding: 1) * regex_cost
          end
          return traversal(target, scope) if target && STRING_TRAVERSALS.include?(node.name)
          return size(target, scope) if target && schema_for(target, scope)["type"] == "array" && LIST_TRAVERSALS.include?(node.name)
          if COMPARISONS.include?(node.name) && args.any? { |arg| schema_for(arg, scope)["type"] == "string" }
            return (args.map { |arg| size(arg, scope) }.min * STRING_TRAVERSAL_FACTOR).ceil
          end

          1
        end

        def traversal(node, scope, padding: 0)
          ((size(node, scope) + padding) * STRING_TRAVERSAL_FACTOR).ceil
        end

        def size(node, scope)
          case node.kind
          when :list then node.elements.length
          when :map then node.entries.length
          when :literal then node.value.is_a?(String) ? node.value.length : 1
          else max_size(schema_for(node, scope))
          end
        end

        def schema_for(node, scope)
          schema = case node.kind
                   when :ident then scope[node.name]
                   when :select
                     object = schema_for(node.operand, scope)
                     properties = object.fetch("properties", {})
                     properties[node.name] || properties.find { |key, _| SCHEMA_TYPES.escape(key) == node.name }&.last || object["additionalProperties"]
                   when :call then indexed_schema(node, scope)
                   when :list then {"type" => "array", "maxItems" => node.elements.length}
                   when :map then {"type" => "object", "maxProperties" => node.entries.length}
                   when :literal then {"type" => ("string" if node.value.is_a?(String))}
                   end
          schema.is_a?(Hash) ? schema : {}
        end

        def indexed_schema(node, scope)
          return conditional_schema(node, scope) if node.name == "_?_:_"
          return unless %w[_[_] _[?_]].include?(node.name)

          target = schema_for(node.args.first, scope)
          target["items"] || target["additionalProperties"]
        end

        def conditional_schema(node, scope)
          left, right = node.args.drop(1).map { |branch| schema_for(branch, scope) }
          return left if left == right || right["maxItems"] == 0
          return right if left["maxItems"] == 0
          return unless left["type"] == "array" && right["type"] == "array"

          collection = {"type" => "array", "maxItems" => [max_size(left), max_size(right)].max}
          collection["items"] = left["items"] if left["items"] == right["items"]
          collection
        end

        def max_size(schema)
          case schema["type"]
          when "array" then [schema.fetch("maxItems") { (MAX_REQUEST_BYTES - 2) / (1 + min_json_size(schema["items"])) }, 0].max
          when "object" then [schema.fetch("maxProperties") { (MAX_REQUEST_BYTES - 2) / (6 + min_json_size(schema["additionalProperties"])) }, 0].max
          when "string" then max_string_size(schema)
          else MAX_REQUEST_BYTES
          end
        end

        def min_json_size(schema)
          case schema.is_a?(Hash) && schema["type"]
          when "object"
            2 + Array(schema["required"]).sum do |name|
              child = schema.dig("properties", name)
              child && !child.key?("default") ? name.bytesize + min_json_size(child) + 4 : 0
            end
          when "array" then 2
          when "string" then STRING_MIN_SIZE.fetch(schema["format"], 2)
          when "boolean" then 4
          else 1
          end
        end

        def max_string_size(schema)
          format = schema["format"]
          return STRING_MAX_SIZE[format] if STRING_MAX_SIZE.key?(format)
          return [schema["maxLength"], 0].max * (format == "byte" ? 1 : 4) if schema["maxLength"]
          return schema["enum"].grep(String).map(&:bytesize).max || 0 if schema["enum"].is_a?(Array)

          MAX_REQUEST_BYTES - 2
        end
      end
    end
  end
end
