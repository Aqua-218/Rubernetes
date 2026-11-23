# frozen_string_literal: true

require_relative "../../security/admission/policy_type_checker"

module Rubernetes
  module API
    module CRD
      # CEL object selections use escaped schema field names. An
      # additionalProperties map still exposes the original string keys.
      module CELValues
        CHECKER = Security::Admission::PolicyTypeChecker
        SCHEMA_TYPES = CHECKER::SchemaTypes

        class Fields < Hash
          def initialize(values, schema, names: nil)
            super()
            update(values)
            @properties = schema["properties"]
            @additional = schema["additionalProperties"]
            @names = names
          end

          def key?(name)
            super(@names ? @names[name] : name)
          end

          def [](name)
            field = @names ? @names[name] : name
            schema = @properties ? @properties[field] : @additional
            CELValues.wrap(super(field), schema)
          end
        end

        module_function

        def wrap(value, schema, resource: false)
          return value unless schema.is_a?(Hash)

          case value
          when Hash then wrap_map(value, schema, resource: resource || schema["x-kubernetes-embedded-resource"] == true)
          when Array then value.map { |item| wrap(item, schema["items"]) }
          else value
          end
        end

        def wrap_map(value, schema, resource:)
          schema = SCHEMA_TYPES.with_type_and_object_meta(schema) if resource
          properties = schema["properties"]
          return Fields.new(value, schema) if schema["additionalProperties"].is_a?(Hash)
          return value unless properties.is_a?(Hash)

          fields = value.each_key.with_object({}) do |key, names|
            next unless properties.key?(key)

            escaped = SCHEMA_TYPES.escape(key)
            next unless escaped

            names[escaped] = key
            names[key] = key if CHECKER::CEL_RESERVED.include?(key)
          end
          # Keep all raw keys in the underlying hash for equality, including
          # preserved unknown fields that a CEL selection cannot reach.
          Fields.new(value, schema, names: fields)
        end
      end
    end
  end
end
