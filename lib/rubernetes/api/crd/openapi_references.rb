# frozen_string_literal: true

module Rubernetes
  module API
    module CRD
      # A schema field may contain arbitrary user JSON. Follow references in
      # child schemas only, including a property literally named "default".
      module OpenAPIReferences
        COMPONENTS = "#/components/schemas/"

        module_function

        def schema(value, &)
          return value unless value.is_a?(Hash)

          result = value.dup
          %w[properties patternProperties definitions dependencies].each do |key|
            result[key] = value[key].transform_values { |child| schema(child, &) } if value[key].is_a?(Hash)
          end
          %w[items additionalItems additionalProperties not allOf anyOf oneOf].each do |key|
            case (child = value[key])
            when Hash then result[key] = schema(child, &)
            when Array then result[key] = child.map { |item| schema(item, &) }
            end
          end
          yield(result)
          result
        end

        def v3(value, referenced)
          schema(value) do |node|
            ref = node["$ref"]
            next unless ref.is_a?(String)

            referenced << ref.delete_prefix(COMPONENTS) if ref.start_with?(COMPONENTS)
            node["allOf"] = [{"$ref" => node.delete("$ref")}] if node.size > 1
          end
        end

        def v2(value)
          schema(value) do |node|
            node.delete("default")
            ref = node["$ref"]
            node["$ref"] = "#/definitions/#{ref.delete_prefix(COMPONENTS)}" if ref.is_a?(String) && ref.start_with?(COMPONENTS)
          end
        end

        # CRD operations use schemas in parameters and request/response media
        # types. Path and operation extensions and examples are opaque data.
        def routes(value, referenced)
          case value
          when Hash
            value.to_h do |key, child|
              updated = if key == "schema"
                          v3(child, referenced)
                        elsif %w[example examples].include?(key) || key.start_with?("x-")
                          child
                        else
                          routes(child, referenced)
                        end
              [key, updated]
            end
          when Array then value.map { |item| routes(item, referenced) }
          else value
          end
        end
      end
    end
  end
end
