# frozen_string_literal: true

module Rubernetes
  module API
    module CRD
      # Both Kubernetes discovery documents describe the same CRD routes.
      # Swagger 2 puts bodies among the parameters and MIME types on each
      # operation. Its shared parameters refer to the pinned global document.
      class OpenAPIV2Routes
        MIME_TYPES = %w[application/json application/yaml].freeze
        PATCH_TYPES = %w[application/json-patch+json application/merge-patch+json application/apply-patch+yaml].freeze

        def initialize(shared_parameters)
          @references = shared_parameters.to_h { |name, parameter| [parameter, {"$ref" => "#/parameters/#{name}"}] }
        end

        def convert(paths)
          paths.transform_values do |item|
            item.to_h do |verb, value|
              result = if verb == "parameters"
                         value.map { |parameter| convert_parameter(parameter) }
                       else
                         convert_operation(verb, value)
                       end
              [verb, result]
            end
          end
        end

        private

        def convert_operation(verb, operation)
          result = operation.except("parameters", "requestBody", "responses").merge(
            "consumes" => verb == "patch" ? PATCH_TYPES : MIME_TYPES,
            "produces" => MIME_TYPES, "schemes" => ["https"]
          )
          parameters = Array(operation["parameters"]).map { |parameter| convert_parameter(parameter) }
          if (body = operation["requestBody"])
            parameter = body.slice("description", "required").merge("name" => "body", "in" => "body", "schema" => content_schema(body))
            parameters.unshift(@references.fetch(parameter, parameter))
          end
          result["parameters"] = parameters unless parameters.empty?
          if operation["responses"]
            result["responses"] = operation["responses"].transform_values do |response|
              schema = content_schema(response)
              schema ? response.except("content").merge("schema" => schema) : response.except("content")
            end
          end
          result
        end

        def convert_parameter(parameter)
          inline = parameter.except("schema").merge(parameter.fetch("schema", {}))
          @references.fetch(inline, inline)
        end

        def content_schema(object)
          schema = object.fetch("content", {}).each_value.first&.fetch("schema", nil)
          return schema unless schema && schema["$ref"]

          schema.merge("$ref" => schema.fetch("$ref").sub(%r{\A#/components/schemas/}, "#/definitions/"))
        end
      end
    end
  end
end
