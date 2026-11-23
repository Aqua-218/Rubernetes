# frozen_string_literal: true

require_relative "../schema/codec/protobuf"
require_relative "openapi_media"
require_relative "openapi_protobuf_any"

module Rubernetes
  module API
    # gnostic's openapi.v2.Document representation used by client-go. Field
    # order and unions follow the OpenAPIv2.proto vendored in Kubernetes v1.36.2.
    module OpenAPIV2Protobuf
      extend OpenAPIMedia

      CONTENT_TYPE = "application/com.github.proto-openapi.spec.v2.v1.0+protobuf"
      DEPRECATED_TYPE = "application/com.github.proto-openapi.spec.v2@v1.0+protobuf"
      RESPONSE_CONTENT_TYPE = CONTENT_TYPE
      SUPPORTED_TYPES = [Negotiation::JSON_TYPE, CONTENT_TYPE, DEPRECATED_TYPE].freeze
      Protobuf = Schema::Codec::Protobuf
      EMPTY_BYTES = "".b.freeze

      PRIMITIVE_VALUE_FIELDS = [
        ["type", :string], ["format", :string], ["items", :PrimitivesItems], ["collectionFormat", :string],
        ["default", :Any], ["maximum", :double], ["exclusiveMaximum", :bool],
        ["minimum", :double], ["exclusiveMinimum", :bool], ["maxLength", :int64], ["minLength", :int64],
        ["pattern", :string], ["maxItems", :int64], ["minItems", :int64], ["uniqueItems", :bool],
        ["enum", [:Any]], ["multipleOf", :double]
      ].freeze
      PARAMETER_FIELDS = [["required", :bool], ["in", :string], ["description", :string], ["name", :string]].freeze
      SIMPLE_PARAMETER_FIELDS = [*PARAMETER_FIELDS, *PRIMITIVE_VALUE_FIELDS, ["x-", :extensions]].freeze
      EMPTY_VALUE_PARAMETER_FIELDS = [*PARAMETER_FIELDS, ["allowEmptyValue", :bool], *PRIMITIVE_VALUE_FIELDS, ["x-", :extensions]].freeze

      # Each entry occupies the field number given by its position (starting
      # at 1). An array type denotes repeated elements in the source document.
      OBJECT_FIELDS = {
        Document: [
          ["swagger", :string], ["info", :Info], ["host", :string], ["basePath", :string],
          ["schemes", [:string]], ["consumes", [:string]], ["produces", [:string]], ["paths", :Paths],
          ["definitions", :Definitions], ["parameters", :ParameterDefinitions], ["responses", :ResponseDefinitions],
          ["security", [:SecurityRequirement]], ["securityDefinitions", :SecurityDefinitions], ["tags", [:Tag]],
          ["externalDocs", :ExternalDocs], ["x-", :extensions]
        ],
        Info: [
          ["title", :string], ["version", :string], ["description", :string], ["termsOfService", :string],
          ["contact", :Contact], ["license", :License], ["x-", :extensions]
        ],
        Contact: [["name", :string], ["url", :string], ["email", :string], ["x-", :extensions]],
        License: [["name", :string], ["url", :string], ["x-", :extensions]],
        ExternalDocs: [["description", :string], ["url", :string], ["x-", :extensions]],
        Tag: [["name", :string], ["description", :string], ["externalDocs", :ExternalDocs], ["x-", :extensions]],
        PathItem: [
          ["$ref", :string], ["get", :Operation], ["put", :Operation], ["post", :Operation], ["delete", :Operation],
          ["options", :Operation], ["head", :Operation], ["patch", :Operation],
          ["parameters", [:ParametersItem]], ["x-", :extensions]
        ],
        Operation: [
          ["tags", [:string]], ["summary", :string], ["description", :string], ["externalDocs", :ExternalDocs],
          ["operationId", :string], ["produces", [:string]], ["consumes", [:string]], ["parameters", [:ParametersItem]],
          ["responses", :Responses], ["schemes", [:string]], ["deprecated", :bool],
          ["security", [:SecurityRequirement]], ["x-", :extensions]
        ],
        BodyParameter: [
          ["description", :string], ["name", :string], ["in", :string], ["required", :bool],
          ["schema", :Schema], ["x-", :extensions]
        ],
        PrimitivesItems: [*PRIMITIVE_VALUE_FIELDS, ["x-", :extensions]],
        Header: [*PRIMITIVE_VALUE_FIELDS, ["description", :string], ["x-", :extensions]],
        HeaderParameterSubSchema: SIMPLE_PARAMETER_FIELDS,
        PathParameterSubSchema: SIMPLE_PARAMETER_FIELDS,
        QueryParameterSubSchema: EMPTY_VALUE_PARAMETER_FIELDS,
        FormDataParameterSubSchema: EMPTY_VALUE_PARAMETER_FIELDS,
        JsonReference: [["$ref", :string], ["description", :string]],
        Response: [["description", :string], ["schema", :SchemaItem], ["headers", :Headers], ["examples", :Examples], ["x-", :extensions]],
        Schema: [
          ["$ref", :string], ["format", :string], ["title", :string], ["description", :string], ["default", :Any],
          ["multipleOf", :double], ["maximum", :double], ["exclusiveMaximum", :bool], ["minimum", :double],
          ["exclusiveMinimum", :bool], ["maxLength", :int64], ["minLength", :int64], ["pattern", :string],
          ["maxItems", :int64], ["minItems", :int64], ["uniqueItems", :bool], ["maxProperties", :int64],
          ["minProperties", :int64], ["required", [:string]], ["enum", [:Any]], ["additionalProperties", :AdditionalPropertiesItem],
          ["type", :TypeItem], ["items", :ItemsItem], ["allOf", [:Schema]], ["properties", :Properties],
          ["discriminator", :string], ["readOnly", :bool], ["xml", :Xml], ["externalDocs", :ExternalDocs],
          ["example", :Any], ["x-", :extensions]
        ],
        FileSchema: [
          ["format", :string], ["title", :string], ["description", :string], ["default", :Any], ["required", [:string]],
          ["type", :string], ["readOnly", :bool], ["externalDocs", :ExternalDocs], ["example", :Any], ["x-", :extensions]
        ],
        Xml: [["name", :string], ["namespace", :string], ["prefix", :string], ["attribute", :bool], ["wrapped", :bool], ["x-", :extensions]],
        BasicAuthenticationSecurity: [["type", :string], ["description", :string], ["x-", :extensions]],
        ApiKeySecurity: [["type", :string], ["name", :string], ["in", :string], ["description", :string], ["x-", :extensions]],
        Oauth2ImplicitSecurity: [
          ["type", :string], ["flow", :string], ["scopes", :Oauth2Scopes], ["authorizationUrl", :string],
          ["description", :string], ["x-", :extensions]
        ],
        Oauth2AccessCodeSecurity: [
          ["type", :string], ["flow", :string], ["scopes", :Oauth2Scopes], ["authorizationUrl", :string],
          ["tokenUrl", :string], ["description", :string], ["x-", :extensions]
        ],
        # Password and client-credentials OAuth flows share the same fields.
        Oauth2TokenSecurity: [
          ["type", :string], ["flow", :string], ["scopes", :Oauth2Scopes], ["tokenUrl", :string],
          ["description", :string], ["x-", :extensions]
        ]
      }.freeze

      # The map messages wrap repeated Named* entries in field 1. The keys in
      # Paths and Responses share their object with vendor extensions.
      MAP_VALUE_TYPES = {
        Definitions: :Schema, Properties: :Schema, Examples: :Any, Headers: :Header,
        ParameterDefinitions: :Parameter, ResponseDefinitions: :Response, Oauth2Scopes: :string,
        SecurityDefinitions: :SecurityDefinitionsItem, SecurityRequirement: :StringArray
      }.freeze
      PRIMITIVES = %i[string bool int64 double].freeze
      PARAMETER_LOCATIONS = {
        "header" => [1, :HeaderParameterSubSchema], "formData" => [2, :FormDataParameterSubSchema],
        "query" => [3, :QueryParameterSubSchema], "path" => [4, :PathParameterSubSchema]
      }.freeze
      SECURITY_FLOWS = {
        "implicit" => [3, :Oauth2ImplicitSecurity], "password" => [4, :Oauth2TokenSecurity],
        "application" => [5, :Oauth2TokenSecurity], "accessCode" => [6, :Oauth2AccessCodeSecurity]
      }.freeze

      module_function

      def accepts?(accept_header)
        negotiate(accept_header) == CONTENT_TYPE
      rescue Status::NotAcceptable
        false
      end

      def encode(document)
        raise ArgumentError, "OpenAPI v2 document must be a Hash" unless document.is_a?(Hash)

        encode_message(:Document, document)
      end

      def encode_message(type, value)
        if (entry_type = MAP_VALUE_TYPES[type])
          return encode_map(1, entry_type, value)
        end

        case type
        when :Any
          OpenAPIProtobufAny.encode(value)
        when :Paths
          encode_map(1, :Any, value) { |name| name.start_with?("x-") } +
            encode_map(2, :PathItem, value) { |name| name.start_with?("/") }
        when :Responses
          encode_map(1, :ResponseValue, value) { |name| name.match?(/\A(?:[0-9]{3}|default)\z/) } +
            encode_map(2, :Any, value) { |name| name.start_with?("x-") }
        when :ParametersItem
          encode_reference_or(:Parameter, value)
        when :ResponseValue
          encode_reference_or(:Response, value)
        when :Parameter
          value["in"] == "body" ? encode_field(1, :BodyParameter, value) : encode_field(2, :NonBodyParameter, value)
        when :NonBodyParameter
          number, subtype = PARAMETER_LOCATIONS.fetch(value["in"])
          encode_field(number, subtype, value)
        when :SchemaItem
          value["type"] == "file" ? encode_field(2, :FileSchema, value) : encode_field(1, :Schema, value)
        when :AdditionalPropertiesItem
          value.is_a?(Hash) ? encode_field(1, :Schema, value) : Protobuf.encode_field(2, value == true, type: :bool)
        when :ItemsItem
          items = value.is_a?(Array) ? value : [value]
          encode_repeated(1, :Schema, items)
        when :TypeItem, :StringArray
          encode_repeated(1, :string, Array(value))
        when :SecurityDefinitionsItem
          encode_security(value)
        else
          encode_object(type, value)
        end
      end

      def encode_reference_or(type, value)
        value.key?("$ref") ? encode_field(2, :JsonReference, value) : encode_field(1, type, value)
      end

      def encode_security(value)
        case value["type"]
        when "basic" then encode_field(1, :BasicAuthenticationSecurity, value)
        when "apiKey" then encode_field(2, :ApiKeySecurity, value)
        when "oauth2"
          number, subtype = SECURITY_FLOWS.fetch(value["flow"])
          encode_field(number, subtype, value)
        else
          raise ArgumentError, "unknown OpenAPI v2 security type #{value["type"].inspect}"
        end
      end

      def encode_object(type, value)
        return EMPTY_BYTES unless value.is_a?(Hash)

        output = +EMPTY_BYTES
        OBJECT_FIELDS.fetch(type).each_with_index do |(name, field_type), index|
          number = index + 1
          if field_type == :extensions
            output << encode_map(number, :Any, value) { |key| key.start_with?("x-") }
          elsif value.key?(name)
            field_value = value[name]
            output << if field_type.is_a?(Array)
                        encode_repeated(number, field_type.first, Array(field_value))
                      else
                        encode_field(number, field_type, field_value)
                      end
          end
        end
        output
      end

      def encode_map(number, type, value)
        return EMPTY_BYTES unless value.is_a?(Hash)

        value.each_with_object(+EMPTY_BYTES) do |(key, entry), output|
          name = key.to_s
          next if block_given? && !yield(name)

          pair = encode_field(1, :string, name) + encode_field(2, type, entry)
          output << Protobuf.encode_field(number, pair, type: :bytes)
        end
      end

      def encode_repeated(number, type, values)
        values.each_with_object(+EMPTY_BYTES) do |value, output|
          output << encode_field(number, type, value, repeated: true)
        end
      end

      def encode_field(number, type, value, repeated: false)
        return Protobuf.encode_field(number, encode_message(type, value), type: :bytes) unless PRIMITIVES.include?(type)
        return EMPTY_BYTES if !repeated && (value.nil? || value == false || value == "" || value == 0)

        value = value.to_s.encode(Encoding::UTF_8) if type == :string && !(value.is_a?(String) && value.encoding == Encoding::UTF_8)
        Protobuf.encode_field(number, value, type: type)
      end
    end
  end
end
