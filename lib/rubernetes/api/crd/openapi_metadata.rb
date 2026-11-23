# frozen_string_literal: true

module Rubernetes
  module API
    module CRD
      # The API server publishes Kubernetes metadata for both top-level and
      # embedded custom resources. The structural schema used for validation
      # retains the restrictions the CRD author declared.
      module OpenAPIMetadata
        # The canonical wording, from apimachinery meta/v1 types.go TypeMeta and
        # ObjectMeta -- the same strings every built-in kind publishes.
        ROOT_DESCRIPTIONS = {
          "apiVersion" => "APIVersion defines the versioned schema of this representation of an object. " \
                          "Servers should convert recognized schemas to the latest internal value, and " \
                          "may reject unrecognized values. More info: " \
                          "https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources",
          "kind" => "Kind is a string value representing the REST resource this object represents. " \
                    "Servers may infer this from the endpoint the client submits requests to. " \
                    "Cannot be updated. In CamelCase. More info: " \
                    "https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds",
          "metadata" => "Standard object's metadata. More info: " \
                        "https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata"
        }.freeze

        EMBEDDED_DESCRIPTIONS = {
          "apiVersion" => "apiVersion defines the versioned schema of this representation of an object. More info: " \
                          "https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources",
          "kind" => "kind is a string value representing the type of this object. In CamelCase. More info: " \
                    "https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
        }.freeze

        module_function

        def list_schema(definition_name, plural, gvk, list_kind)
          {"type" => "object", "description" => "#{list_kind} is a list of #{gvk.fetch("kind")}", "required" => ["items"],
           "properties" => {
             "apiVersion" => {"type" => "string", "description" => ROOT_DESCRIPTIONS.fetch("apiVersion")},
             "kind" => {"type" => "string", "description" => ROOT_DESCRIPTIONS.fetch("kind")},
             "metadata" => {"$ref" => "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta",
                            "description" => "Standard list metadata. More info: " \
                                             "https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"},
             "items" => {"type" => "array", "items" => {"$ref" => "#/components/schemas/#{definition_name}"},
                         "description" => "List of #{plural}. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md"}
           },
           "x-kubernetes-group-version-kind" => [gvk.merge("kind" => list_kind)]}
        end

        def add_properties(schema, descriptions = ROOT_DESCRIPTIONS)
          properties = schema["properties"] ||= {}
          %w[apiVersion kind].each do |field|
            properties[field] = {"type" => "string", "description" => descriptions.fetch(field)}
          end
          properties["metadata"] = {"$ref" => "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta",
                                    "description" => ROOT_DESCRIPTIONS.fetch("metadata")}
        end

        # Only schema locations are visited. Defaults and examples can contain
        # arbitrary objects, including objects with these same extension names.
        def with_embedded(schema, v2:)
          return schema unless schema.is_a?(Hash)

          node = schema.dup
          node["properties"] = schema["properties"].transform_values { |child| with_embedded(child, v2: v2) } if schema["properties"].is_a?(Hash)
          %w[items additionalProperties].each do |key|
            node[key] = with_embedded(schema[key], v2: v2) if schema[key].is_a?(Hash)
          end
          if node["x-kubernetes-embedded-resource"] == true && !(v2 && node["x-kubernetes-preserve-unknown-fields"] == true)
            add_properties(node, EMBEDDED_DESCRIPTIONS)
            node["required"] = Array(node["required"]) | %w[kind apiVersion]
          end
          node
        end
      end
    end
  end
end
