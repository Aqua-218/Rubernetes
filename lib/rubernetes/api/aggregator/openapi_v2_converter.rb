# frozen_string_literal: true

module Rubernetes
  module API
    class Aggregator
      # Mirrors kube-openapi/pkg/openapiconv for legacy APIService documents.
      module OpenAPIV2Converter
        module_function

        def convert(document)
          return unless object(document)["swagger"] == "2.0"

          paths = document["paths"]
          info = document["info"]
          converted = {"openapi" => "3.0.0", "info" => info && object(info), "components" => components(document)}
          if paths
            converted["paths"] = extensions(paths).merge(object(paths).select { |name, _| name.start_with?("/") }
                                                               .transform_values { |path| path_item(path) })
          end
          converted["externalDocs"] = external_docs(document["externalDocs"]) if document["externalDocs"]
          converted
        end

        def components(document)
          result = {}
          add_map(result, "schemas", document["definitions"]) { |value| schema(value) }
          add_map(result, "securitySchemes", document["securityDefinitions"]) { |value| security_scheme(value) }
          add_map(result, "responses", document["responses"]) { |value| response(value, document["produces"]) }
          result
        end

        def path_item(source)
          result = fields(source, "$ref")
          %w[get put post delete options head patch].each do |verb|
            result[verb] = operation(source[verb]) if source[verb]
          end
          parameters = Array(source["parameters"]).map { |entry| parameter(entry) }
          result["parameters"] = parameters unless parameters.empty?
          result
        end

        def operation(source)
          result = fields(source, "description", "tags", "summary", "deprecated", "operationId")
          result["externalDocs"] = external_docs(source["externalDocs"]) if source["externalDocs"]
          body, parameters = Array(source["parameters"]).partition { |entry| object(entry)["name"] == "body" && entry["schema"] }
          result["requestBody"] = content(body.last["schema"], source["consumes"]) if body.last
          result["parameters"] = parameters.map { |entry| parameter(entry) } unless parameters.empty?
          if source["responses"]
            responses = object(source["responses"])
            statuses = responses.select { |name, _| name == "default" || name.match?(/\A[0-9]+\z/) }
            result["responses"] = extensions(responses).merge(statuses.transform_values { |entry| response(entry, source["produces"]) })
          end
          result
        end

        def parameter(source)
          result = fields(source, "$ref", "name", "description", "in", "required", "allowEmptyValue")
          rewrite_ref(result, "parameters")
          result["schema"] = if source["schema"]
                               schema(source["schema"])
                             else
                               selected_fields(source, "format", "uniqueItems").merge("type" => source.fetch("type", ""))
                             end
          result
        end

        def response(source, produces)
          return nil unless source

          result = fields(source, "$ref", "description")
          rewrite_ref(result, "responses")
          source["schema"] ? result.merge(content(source["schema"], produces)) : result
        end

        def security_scheme(source)
          return nil unless source

          result = fields(source, "description", "type", "name", "in")
          flow = source["flow"]
          result["flows"] = {flow => selected_fields(source, "authorizationUrl", "tokenUrl", "scopes")} if flow.is_a?(String) && !flow.empty?
          result
        end

        def schema(source, convert_refs: true)
          case source
          when nil, true, false then source
          when Array then source.map { |child| schema(child, convert_refs: convert_refs) }
          when Hash then schema_object(source, convert_refs)
          else raise TypeError, "invalid Swagger schema"
          end
        end

        def schema_object(source, convert_refs)
          result = source.dup
          add_map(result, "properties", source["properties"]) { |child| schema(child, convert_refs: convert_refs) }
          %w[items additionalProperties additionalItems].each do |name|
            result[name] = schema(source[name], convert_refs: convert_refs) if source.key?(name)
          end
          # ConvertSchema rewrites definition references in the fields above.
          # Its final WrapRefs walk also visits composition and pattern schemas.
          %w[allOf oneOf anyOf not].each do |name|
            result[name] = schema(source[name], convert_refs: false) if source[name]
          end
          add_map(result, "patternProperties", source["patternProperties"]) { |child| schema(child, convert_refs: false) }
          ref = result["$ref"]
          if ref.is_a?(String) && !ref.empty?
            _, suffix = ref.split("#/definitions/", 2)
            result["$ref"] = "#/components/schemas/#{suffix}" if convert_refs && suffix
            result["allOf"] = [{"$ref" => result.delete("$ref")}] if result.size > 1
          end
          result
        end

        def external_docs(source)
          selected_fields(source, "description", "url")
        end

        def add_map(target, name, values, &)
          target[name] = object(values).transform_values(&) if values && !object(values).empty?
        end

        def content(source, media_types)
          return {} if media_types.nil? || media_types == []
          raise TypeError, "invalid Swagger media types" unless media_types.is_a?(Array) && media_types.all?(String)

          converted = schema(source)
          {"content" => media_types.to_h { |type| [type, {"schema" => converted}] }}
        end

        def rewrite_ref(target, component)
          ref = target["$ref"]
          target["$ref"] = ref.sub("#/#{component}/", "#/components/#{component}/") if ref.is_a?(String)
        end

        def fields(source, *names)
          extensions(source).merge(selected_fields(source, *names))
        end

        def selected_fields(source, *names)
          object(source).slice(*names).reject { |_, value| [nil, false, "", [], {}].include?(value) }
        end

        def extensions(source)
          object(source).select { |name, _| extension?(name) }
        end

        def extension?(name)
          name.downcase.start_with?("x-")
        end

        def object(value)
          raise TypeError, "invalid Swagger object" unless value.is_a?(Hash)

          value
        end
      end
    end
  end
end
