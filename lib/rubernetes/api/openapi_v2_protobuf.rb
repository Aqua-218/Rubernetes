# frozen_string_literal: true

require "yaml"

require_relative "../schema/codec/protobuf"

module Rubernetes
  module API
    # Serves the OpenAPI v2 document as the gnostic `openapi.v2.Document`
    # protobuf message that kubectl requests from /openapi/v2 with
    # `Accept: application/com.github.proto-openapi.spec.v2@v1.0+protobuf`
    # (k8s.io/client-go/discovery OpenAPISchema).  Field numbers follow
    # github.com/google/gnostic-models/openapiv2/OpenAPIv2.proto at the
    # Kubernetes v1.36.2 vendored revision; the JSON to message mapping is the
    # one gnostic's compiler performs (maps become repeated Named* entries,
    # free-form values become Any with a YAML rendering, vendor extensions are
    # every `x-` key).  kube-openapi reads definitions, their schemas, and the
    # vendor extensions (`x-kubernetes-group-version-kind`) from this form.
    module OpenAPIV2Protobuf
      CONTENT_TYPE = "application/com.github.proto-openapi.spec.v2@v1.0+protobuf"
      # The Accept value is not a valid RFC 2045 media type ("@" is a
      # tspecial), so the served Content-Type is application/octet-stream as
      # kube-openapi's handler responds; client-go's response transform would
      # otherwise fail in mime.ParseMediaType.
      RESPONSE_CONTENT_TYPE = "application/octet-stream"
      Protobuf = Schema::Codec::Protobuf

      # openapi.v2.Schema field numbers.
      SCHEMA_STRING_FIELDS = {
        "$ref" => 1, "format" => 2, "title" => 3, "description" => 4, "pattern" => 13, "discriminator" => 26
      }.freeze
      SCHEMA_DOUBLE_FIELDS = {"multipleOf" => 6, "maximum" => 7, "minimum" => 9}.freeze
      SCHEMA_BOOL_FIELDS = {"exclusiveMaximum" => 8, "exclusiveMinimum" => 10, "uniqueItems" => 16, "readOnly" => 27}.freeze
      SCHEMA_INT_FIELDS = {
        "maxLength" => 11, "minLength" => 12, "maxItems" => 14, "minItems" => 15, "maxProperties" => 17, "minProperties" => 18
      }.freeze

      module_function

      def accepts?(accept_header)
        accept_header.to_s.split(",").any? { |clause| clause.split(";", 2).first.to_s.strip.casecmp?(CONTENT_TYPE) }
      end

      # openapi.v2.Document
      def encode(document)
        raise ArgumentError, "OpenAPI v2 document must be a Hash" unless document.is_a?(Hash)

        fields = []
        fields << [1, string(document["swagger"] || "2.0"), :string]
        fields << [2, encode_info(document["info"] || {}), :bytes]
        fields << [3, document["host"], :string] if present?(document["host"])
        fields << [4, document["basePath"], :string] if present?(document["basePath"])
        %w[schemes consumes produces].each_with_index do |key, index|
          Array(document[key]).each { |value| fields << [5 + index, string(value), :string] }
        end
        fields << [8, encode_paths(document["paths"] || {}), :bytes]
        fields << [9, encode_definitions(document["definitions"] || {}), :bytes]
        fields << [15, encode_external_docs(document["externalDocs"]), :bytes] if document["externalDocs"].is_a?(Hash)
        vendor_extensions(document).each { |extension| fields << [16, extension, :bytes] }
        Protobuf.encode_message(fields)
      end

      # openapi.v2.Info
      def encode_info(info)
        fields = []
        fields << [1, string(info["title"]), :string] if present?(info["title"])
        fields << [2, string(info["version"]), :string] if present?(info["version"])
        fields << [3, string(info["description"]), :string] if present?(info["description"])
        fields << [4, string(info["termsOfService"]), :string] if present?(info["termsOfService"])
        vendor_extensions(info).each { |extension| fields << [7, extension, :bytes] }
        Protobuf.encode_message(fields)
      end

      # openapi.v2.Paths: kubectl reads no path items from the protobuf
      # form, so only vendor extensions are carried; NamedPathItem entries
      # would triple the payload for no consumer.
      def encode_paths(paths)
        fields = vendor_extensions(paths).map { |extension| [1, extension, :bytes] }
        Protobuf.encode_message(fields)
      end

      # openapi.v2.Definitions: repeated NamedSchema in key order, as gnostic
      # emits them.
      def encode_definitions(definitions)
        fields = definitions.keys.sort.map do |name|
          [1, encode_named_schema(name, definitions.fetch(name)), :bytes]
        end
        Protobuf.encode_message(fields)
      end

      def encode_named_schema(name, schema)
        Protobuf.encode_message([[1, string(name), :string], [2, encode_schema(schema), :bytes]])
      end

      # openapi.v2.Schema
      def encode_schema(schema)
        schema = {} unless schema.is_a?(Hash)
        fields = []
        SCHEMA_STRING_FIELDS.each { |key, number| fields << [number, string(schema[key]), :string] if present?(schema[key]) }
        fields << [5, encode_any(schema["default"]), :bytes] if schema.key?("default")
        SCHEMA_DOUBLE_FIELDS.each { |key, number| fields << [number, Float(schema[key]), :double] if schema[key].is_a?(Numeric) }
        SCHEMA_BOOL_FIELDS.each { |key, number| fields << [number, true, :bool] if schema[key] == true }
        SCHEMA_INT_FIELDS.each { |key, number| fields << [number, Integer(schema[key]), :int64] if schema[key].is_a?(Integer) }
        Array(schema["required"]).each { |value| fields << [19, string(value), :string] }
        Array(schema["enum"]).each { |value| fields << [20, encode_any(value), :bytes] } if schema.key?("enum")
        if schema.key?("additionalProperties")
          fields << [21, encode_additional_properties(schema["additionalProperties"]), :bytes]
        end
        if schema.key?("type")
          type_names = schema["type"].is_a?(Array) ? schema["type"] : [schema["type"]]
          types = type_names.map { |value| [1, string(value), :string] }
          fields << [22, Protobuf.encode_message(types), :bytes]
        end
        if schema.key?("items")
          # Swagger 2.0 items is one schema; gnostic keeps a one-element list.
          item_schemas = schema["items"].is_a?(Array) ? schema["items"] : [schema["items"]]
          items = item_schemas.map { |value| [1, encode_schema(value), :bytes] }
          fields << [23, Protobuf.encode_message(items), :bytes]
        end
        Array(schema["allOf"]).each { |value| fields << [24, encode_schema(value), :bytes] }
        if schema["properties"].is_a?(Hash)
          properties = schema["properties"].keys.sort.map { |name| [1, encode_named_schema(name, schema["properties"].fetch(name)), :bytes] }
          fields << [25, Protobuf.encode_message(properties), :bytes]
        end
        fields << [28, encode_xml(schema["xml"]), :bytes] if schema["xml"].is_a?(Hash)
        fields << [29, encode_external_docs(schema["externalDocs"]), :bytes] if schema["externalDocs"].is_a?(Hash)
        fields << [30, encode_any(schema["example"]), :bytes] if schema.key?("example")
        vendor_extensions(schema).each { |extension| fields << [31, extension, :bytes] }
        Protobuf.encode_message(fields)
      end

      # openapi.v2.AdditionalPropertiesItem (oneof schema | boolean)
      def encode_additional_properties(value)
        if value.is_a?(Hash)
          Protobuf.encode_message([[1, encode_schema(value), :bytes]])
        else
          Protobuf.encode_message([[2, value == true, :bool]])
        end
      end

      def encode_xml(xml)
        fields = []
        %w[name namespace prefix].each_with_index { |key, index| fields << [index + 1, string(xml[key]), :string] if present?(xml[key]) }
        fields << [4, true, :bool] if xml["attribute"] == true
        fields << [5, true, :bool] if xml["wrapped"] == true
        vendor_extensions(xml).each { |extension| fields << [6, extension, :bytes] }
        Protobuf.encode_message(fields)
      end

      def encode_external_docs(docs)
        fields = []
        fields << [1, string(docs["description"]), :string] if present?(docs["description"])
        fields << [2, string(docs["url"]), :string] if present?(docs["url"])
        vendor_extensions(docs).each { |extension| fields << [3, extension, :bytes] }
        Protobuf.encode_message(fields)
      end

      # openapi.v2.Any: gnostic keeps the YAML rendering of a free-form value
      # in `yaml`; kube-openapi decodes exactly that field.
      def encode_any(value)
        Protobuf.encode_message([[2, yaml_for(value), :string]])
      end

      # repeated NamedAny for every `x-` key of a JSON object.
      def vendor_extensions(object)
        return [] unless object.is_a?(Hash)

        object.keys.select { |key| key.to_s.start_with?("x-") }.sort.map do |key|
          Protobuf.encode_message([[1, string(key), :string], [2, encode_any(object.fetch(key)), :bytes]])
        end
      end

      def yaml_for(value)
        text = ::YAML.dump(value, line_width: -1)
        text = text.delete_prefix("---\n").delete_prefix("--- ")
        text = "#{text}\n" unless text.end_with?("\n")
        text
      end

      def string(value)
        String(value)
      end

      def present?(value)
        !value.nil? && !(value.respond_to?(:empty?) && value.empty?)
      end
    end
  end
end
