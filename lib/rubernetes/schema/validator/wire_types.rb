# frozen_string_literal: true

module Rubernetes
  module Schema
    # Reports the type mismatch separately from the REST strategy's
    # semantic errors, so admission never receives an undecodable Go field.
    module WireTypes
      def wire_type_error(issues)
        issue = issues.find { |failure| failure.code == :type && !failure.value.nil? }
        return unless issue

        owner, path, field = wire_field_at(definition, issue.path)
        expected = wire_type_name(field, issue.expected)
        actual = json_type_name(issue.value)
        actual = "number #{issue.value}" if issue.value.is_a?(Numeric) && %w[int int32 int64].include?(expected)
        "json: cannot unmarshal #{actual} into Go struct field " \
          "#{(Array(owner) + path).join(".")} of type #{expected}"
      end

      private

      def wire_field_at(type, remaining, owner: nil, path: [])
        case type
        when Reference
          wire_field_at(type.resolve, remaining, owner: owner, path: path)
        when Definition
          return [owner, path, type] if remaining.empty?

          name, *tail = remaining
          wire_field_at(type.field(name), tail, owner: type.kind, path: path + [name])
        when Field
          return [owner, path, type] if remaining.empty?

          if type.array?
            wire_field_at(type.items, remaining.drop(1), owner: owner, path: path)
          elsif type.additional_properties
            wire_field_at(type.additional_properties, remaining.drop(1), owner: owner, path: path)
          elsif (nested = definition.nested_definition_for(type))
            wire_field_at(nested, remaining, owner: owner, path: path)
          else
            [owner, path, type]
          end
        else
          [owner, path, type]
        end
      end

      def wire_type_name(field, expected)
        if field.is_a?(Field)
          return "[]#{wire_type_name(field.items, expected_type(field.items))}" if field.array? && field.items

          if field.additional_properties.is_a?(Field)
            element = field.additional_properties
            return "map[string]#{wire_type_name(element, expected_type(element))}"
          end
          format = field.metadata[:format]
          return format if %w[int32 int64].include?(format)
          return "float32" if format == "float"
          return "float64" if format == "double"

          field = field.type
        end

        return field.name.split(".").last(2).join(".") if field.is_a?(Reference) || field.is_a?(Definition)

        {integer: "int", boolean: "bool", number: "float64"}.fetch(expected, expected.to_s)
      end

      def json_type_name(value)
        case value
        when Numeric then "number"
        when TrueClass, FalseClass then "bool"
        else type_name(value).downcase
        end
      end
    end
  end
end
