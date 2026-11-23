# frozen_string_literal: true

require_relative "../schema/codec/protobuf"
require_relative "openapi_media"
require_relative "openapi_protobuf_any"
require_relative "openapi_v3_protobuf_schema"

module Rubernetes
  module API
    # gnostic's openapi.v3.Document protobuf representation. The wire fields
    # come from the pinned schema. Named* entries, reference unions and YAML
    # values follow the mapping in gnostic's generated OpenAPIv3.go parser.
    module OpenAPIV3Protobuf
      extend OpenAPIMedia

      CONTENT_TYPE = "application/com.github.proto-openapi.spec.v3.v1.0+protobuf"
      DEPRECATED_TYPE = "application/com.github.proto-openapi.spec.v3@v1.0+protobuf"
      SUPPORTED_TYPES = [Negotiation::JSON_TYPE, CONTENT_TYPE, DEPRECATED_TYPE].freeze
      PROTOBUF = Schema::Codec::Protobuf
      PRIMITIVES = {"string" => :string, "double" => :double, "bool" => :bool, "int64" => :int64}.freeze
      EMPTY_BYTES = "".b.freeze

      module_function

      def encode(document)
        encode_message("Document", document)
      end

      def encode_message(type, value)
        case type
        when "Any"
          OpenAPIProtobufAny.encode(value)
        when "AnyOrExpression"
          embedded_field(2, "Expression", value)
        when "AdditionalPropertiesItem"
          if value.is_a?(Hash)
            embedded_field(1, "SchemaOrReference", value)
          else
            PROTOBUF.encode_field(2, value == true, type: :bool)
          end
        when "DefaultType", "SpecificationExtension"
          scalar_union(value)
        when "ItemsItem"
          embedded_field(1, "SchemaOrReference", value)
        when "StringArray"
          PROTOBUF.encode_field(1, value, type: :string)
        else
          if type.end_with?("OrReference") && !type.start_with?("Named")
            reference_union(type, value)
          else
            object_fields(type, value)
          end
        end
      end

      def reference_union(type, value)
        if value.is_a?(Hash) && value.key?("$ref")
          embedded_field(2, "Reference", value)
        else
          embedded_field(1, type.delete_suffix("OrReference"), value)
        end
      end

      def scalar_union(value)
        case value
        when Numeric then PROTOBUF.encode_field(1, value, type: :double)
        when true, false then PROTOBUF.encode_field(2, value, type: :bool)
        when String then PROTOBUF.encode_field(3, value, type: :string)
        else EMPTY_BYTES # The pinned gnostic DefaultType has no compound value.
        end
      end

      def object_fields(type, node)
        raise Schema::Codec::EncodeError, "OpenAPI v3 #{type} must be an object" unless node.is_a?(Hash)

        output = +EMPTY_BYTES
        OpenAPIV3ProtobufSchema::MESSAGES.fetch(type).each do |number, name, child_type, repeated|
          if repeated && child_type.start_with?("Named")
            append_named_fields(output, number, type, name, child_type, node)
          elsif node.key?(name)
            value = node[name]
            if repeated
              Array(value).each { |entry| output << field(number, child_type, entry, repeated: true) }
            else
              output << field(number, child_type, value)
            end
          end
        end
        output
      end

      def append_named_fields(output, number, parent, field_name, child_type, node)
        node.each do |name, value|
          next unless named_field?(parent, field_name, name)

          output << embedded_field(number, child_type, {"name" => name, "value" => value})
        end
      end

      def named_field?(parent, field, name)
        case field
        when "specificationExtension" then name.start_with?("x-")
        when "path" then parent == "Callback" || name.start_with?("/")
        when "responseOrReference" then name.match?(/\A[0-9X]{3}\z/)
        else true
        end
      end

      def field(number, type, value, repeated: false)
        primitive = PRIMITIVES[type]
        return embedded_field(number, type, value) unless primitive
        return EMPTY_BYTES if !repeated && (value.nil? || value == false || value == "" || value == 0)

        PROTOBUF.encode_field(number, value, type: primitive)
      end

      def embedded_field(number, type, value)
        PROTOBUF.encode_field(number, encode_message(type, value), type: :bytes)
      end
    end
  end
end
