# frozen_string_literal: true

# Wire-format codecs used by the schema and API layers.  The facade deliberately
# keeps the registry out of this file: callers can pass a registry/schema to the
# strict validation hooks without making the low-level codecs depend on it.

require "json"
require "psych"

module Rubernetes
  module Schema
    class Codec
      DEFAULT_MAX_BYTES = 8 * 1024 * 1024
      DEFAULT_MAX_DEPTH = 100
      UNKNOWN_MODES = %i[preserve prune reject].freeze

      class Error < StandardError; end
      class ParseError < Error; end
      class EncodeError < Error; end
      class LimitError < Error; end
      class DuplicateKeyError < ParseError; end
      class UnknownFieldError < ParseError; end
      class UnsupportedTypeError < EncodeError; end

      attr_reader :max_bytes, :max_depth, :strict

      def initialize(max_bytes: DEFAULT_MAX_BYTES, max_depth: DEFAULT_MAX_DEPTH, strict: true)
        @max_bytes = self.class.validate_limit(max_bytes, :max_bytes)
        @max_depth = self.class.validate_limit(max_depth, :max_depth)
        @strict = !!strict
      end

      def load_json(input, strict: @strict, schema: nil, known_fields: nil, fields: nil,
                    max_bytes: @max_bytes, max_depth: @max_depth, preserve_unknown: nil,
                    unknown_fields: nil)
        value = JSONCodec.load(
          input,
          strict: strict,
          max_bytes: max_bytes,
          max_depth: max_depth
        )
        schema = schema_definition_for(schema)
        mode = unknown_mode(
          unknown_fields: unknown_fields,
          preserve_unknown: preserve_unknown,
          schema: schema,
          object: value,
          operation: :load,
          strict: strict
        )
        if schema
          normalize_typed_value(value, schema, mode, path: [])
        else
          validate_schema_fields!(value, schema: schema, known_fields: known_fields || fields,
                                         strict: strict, preserve_unknown: preserve_unknown,
                                         unknown_fields: mode)
        end
      end

      def dump_json(object, canonical: false, strict: @strict, schema: nil, known_fields: nil, fields: nil,
                    max_bytes: @max_bytes, max_depth: @max_depth, preserve_unknown: nil,
                    unknown_fields: nil)
        schema = schema_definition_for(schema) || schema_definition_for(object)
        mode = unknown_mode(
          unknown_fields: unknown_fields,
          preserve_unknown: preserve_unknown,
          schema: schema,
          object: object,
          operation: :dump,
          strict: strict
        )
        normalized = if schema
                       normalize_typed_value(object, schema, mode, path: [])
                     else
                       validate_schema_fields!(object, schema: schema, known_fields: known_fields || fields,
                                                       strict: strict, preserve_unknown: preserve_unknown,
                                                       unknown_fields: mode)
                       object
                     end
        JSONCodec.dump(
          normalized,
          canonical: canonical,
          max_bytes: max_bytes,
          max_depth: max_depth
        )
      end

      def canonical_json(object, **)
        dump_json(object, **, canonical: true)
      end

      def strict_load_json(input, **)
        load_json(input, **, strict: true)
      end

      def strict_dump_json(object, **)
        dump_json(object, **, strict: true)
      end

      def load_yaml(input, strict: @strict, schema: nil, known_fields: nil, fields: nil,
                    max_bytes: @max_bytes, max_depth: @max_depth, preserve_unknown: nil,
                    unknown_fields: nil)
        value = YAMLCodec.load(
          input,
          strict: strict,
          max_bytes: max_bytes,
          max_depth: max_depth
        )
        schema = schema_definition_for(schema)
        mode = unknown_mode(
          unknown_fields: unknown_fields,
          preserve_unknown: preserve_unknown,
          schema: schema,
          object: value,
          operation: :load,
          strict: strict
        )
        if schema
          normalize_typed_value(value, schema, mode, path: [])
        else
          validate_schema_fields!(value, schema: schema, known_fields: known_fields || fields,
                                         strict: strict, preserve_unknown: preserve_unknown,
                                         unknown_fields: mode)
        end
      end

      def dump_yaml(object, canonical: false, strict: @strict, schema: nil, known_fields: nil, fields: nil,
                    max_bytes: @max_bytes, max_depth: @max_depth, preserve_unknown: nil,
                    unknown_fields: nil)
        schema = schema_definition_for(schema) || schema_definition_for(object)
        mode = unknown_mode(
          unknown_fields: unknown_fields,
          preserve_unknown: preserve_unknown,
          schema: schema,
          object: object,
          operation: :dump,
          strict: strict
        )
        normalized = if schema
                       normalize_typed_value(object, schema, mode, path: [])
                     else
                       validate_schema_fields!(object, schema: schema, known_fields: known_fields || fields,
                                                       strict: strict, preserve_unknown: preserve_unknown,
                                                       unknown_fields: mode)
                       object
                     end
        YAMLCodec.dump(
          normalized,
          canonical: canonical,
          max_bytes: max_bytes,
          max_depth: max_depth
        )
      end

      def strict_load_yaml(input, **)
        load_yaml(input, **, strict: true)
      end

      def strict_dump_yaml(object, **)
        dump_yaml(object, **, strict: true)
      end

      def encode_cbor(object, canonical: true, max_bytes: @max_bytes, max_depth: @max_depth)
        CBOR.encode(object, canonical: canonical, max_bytes: max_bytes, max_depth: max_depth)
      end

      alias dump_cbor encode_cbor

      def canonical_cbor(object, max_bytes: @max_bytes, max_depth: @max_depth)
        encode_cbor(object, canonical: true, max_bytes: max_bytes, max_depth: max_depth)
      end

      def decode_cbor(input, strict: true, max_bytes: @max_bytes, max_depth: @max_depth)
        CBOR.decode(input, strict: strict, max_bytes: max_bytes, max_depth: max_depth)
      end

      def encode_protobuf(object = nil, raw: nil, content_type: "application/json",
                          content_encoding: nil, type_meta: nil,
                          max_bytes: @max_bytes, max_depth: @max_depth)
        Protobuf.encode_envelope(
          object,
          raw: raw,
          content_type: content_type,
          content_encoding: content_encoding,
          type_meta: type_meta,
          max_bytes: max_bytes,
          max_depth: max_depth
        )
      end

      alias dump_protobuf encode_protobuf
      alias encode_kubernetes_protobuf encode_protobuf
      alias strict_encode_protobuf encode_protobuf

      def decode_protobuf(input, strict: true, max_bytes: @max_bytes, max_depth: @max_depth)
        Protobuf.decode_envelope(input, strict: strict, max_bytes: max_bytes, max_depth: max_depth)
      end

      alias decode_kubernetes_protobuf decode_protobuf

      def decode_protobuf_json(input, strict: true, max_bytes: @max_bytes, max_depth: @max_depth)
        envelope = decode_protobuf(input, strict: strict, max_bytes: max_bytes, max_depth: max_depth)
        load_json(
          envelope.raw,
          strict: strict,
          max_bytes: max_bytes,
          max_depth: max_depth
        )
      end

      class << self
        def load_json(input, **options)
          new(**codec_options(options)).load_json(input, **options)
        end

        alias strict_load_json load_json

        def dump_json(object, **options)
          new(**codec_options(options)).dump_json(object, **options)
        end

        alias strict_dump_json dump_json

        def canonical_json(object, **options)
          new(**codec_options(options)).canonical_json(object, **options)
        end

        def load_yaml(input, **options)
          new(**codec_options(options)).load_yaml(input, **options)
        end

        alias strict_load_yaml load_yaml

        def dump_yaml(object, **options)
          new(**codec_options(options)).dump_yaml(object, **options)
        end

        alias strict_dump_yaml dump_yaml

        def encode_cbor(object, **options)
          new(**codec_options(options)).encode_cbor(object, **options)
        end

        alias dump_cbor encode_cbor

        def canonical_cbor(object, **options)
          new(**codec_options(options)).canonical_cbor(object, **options)
        end

        def decode_cbor(input, **options)
          new(**codec_options(options)).decode_cbor(input, **options)
        end

        def encode_protobuf(object = nil, **options)
          new(**codec_options(options)).encode_protobuf(object, **options)
        end

        alias dump_protobuf encode_protobuf
        alias encode_kubernetes_protobuf encode_protobuf

        def decode_protobuf(input, **options)
          new(**codec_options(options)).decode_protobuf(input, **options)
        end

        alias decode_kubernetes_protobuf decode_protobuf

        def decode_protobuf_json(input, **options)
          new(**codec_options(options)).decode_protobuf_json(input, **options)
        end

        def load(input, format: :json, **)
          case format.to_sym
          when :json then load_json(input, **)
          when :yaml, :yml then load_yaml(input, **)
          when :cbor then decode_cbor(input, **)
          when :protobuf, :kubernetes_protobuf then decode_protobuf(input, **)
          else
            raise ArgumentError, "unsupported codec format #{format.inspect}"
          end
        end

        def dump(object, format: :json, **)
          case format.to_sym
          when :json then dump_json(object, **)
          when :yaml, :yml then dump_yaml(object, **)
          when :cbor then encode_cbor(object, **)
          when :protobuf, :kubernetes_protobuf then encode_protobuf(object, **)
          else
            raise ArgumentError, "unsupported codec format #{format.inspect}"
          end
        end

        private

        def codec_options(options)
          options.slice(:max_bytes, :max_depth, :strict)
        end
      end

      # Convert schema objects without allowing arbitrary application methods to
      # execute.  The schema compiler owns richer typed conversion; this layer
      # intentionally accepts only Hash/to_h plus JSON/YAML/CBOR primitives.
      def self.normalize_value(value, depth: 0, max_depth: DEFAULT_MAX_DEPTH, seen: {})
        raise LimitError, "codec nesting exceeds #{max_depth} levels" if depth > max_depth

        case value
        when NilClass, TrueClass, FalseClass, Integer, String
          value
        when Float
          raise EncodeError, "codec does not support non-finite Float values" unless value.finite?

          value
        when Array
          detect_cycle!(value, seen)
          begin
            value.map do |child|
              normalize_value(child, depth: depth + 1, max_depth: max_depth, seen: seen)
            end
          ensure
            seen.delete(value.object_id)
          end
        when Hash
          detect_cycle!(value, seen)
          begin
            value.each_with_object({}) do |(key, child), normalized|
              normalized_key = normalize_key(key)
              raise DuplicateKeyError, "object contains duplicate key #{normalized_key.inspect}" if normalized.key?(normalized_key)

              normalized[normalized_key] = normalize_value(
                child,
                depth: depth + 1,
                max_depth: max_depth,
                seen: seen
              )
            end
          ensure
            seen.delete(value.object_id)
          end
        else
          raise UnsupportedTypeError, "unsupported codec value #{value.class}" unless value.respond_to?(:to_h)

          hash = value.to_h
          raise UnsupportedTypeError, "to_h for #{value.class} must return a Hash" unless hash.is_a?(Hash)

          normalize_value(hash, depth: depth, max_depth: max_depth, seen: seen)

        end
      end

      def self.validate_depth!(value, max_depth, depth: 0)
        raise LimitError, "codec nesting exceeds #{max_depth} levels" if depth > max_depth

        case value
        when Array
          value.each { |child| validate_depth!(child, max_depth, depth: depth + 1) }
        when Hash
          value.each_value { |child| validate_depth!(child, max_depth, depth: depth + 1) }
        end
        value
      end

      def self.validate_finite_numbers!(value)
        case value
        when Float
          raise ParseError, "non-finite numeric values are not supported" unless value.finite?
        when Array
          value.each { |child| validate_finite_numbers!(child) }
        when Hash
          value.each_value { |child| validate_finite_numbers!(child) }
        end
        value
      end

      def self.validate_body!(input, max_bytes)
        raise ParseError, "codec input must be a String, got #{input.class}" unless input.is_a?(String)

        raise LimitError, "codec body exceeds #{max_bytes} bytes" if input.bytesize > max_bytes

        input
      end

      def self.validate_output!(output, max_bytes)
        raise LimitError, "codec body exceeds #{max_bytes} bytes" if output.bytesize > max_bytes

        output
      end

      def self.validate_limit(value, name)
        integer = Integer(value)
        raise ArgumentError, "#{name} must be a non-negative Integer" if integer.negative?

        integer
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a non-negative Integer"
      end

      def self.normalize_key(key)
        case key
        when String then key
        when Symbol then key.to_s
        else
          raise UnsupportedTypeError, "object keys must be String or Symbol, got #{key.class}"
        end
      end

      def self.detect_cycle!(value, seen)
        object_id = value.object_id
        return unless seen.key?(object_id)

        raise UnsupportedTypeError, "cyclic codec value graph is not supported"
      ensure
        seen[object_id] = true if object_id && !seen.key?(object_id)
      end

      def schema_definition_for(schema)
        candidate = if schema_definition?(schema)
                      schema
                    elsif schema.respond_to?(:definition)
                      schema.definition
                    else
                      schema
                    end
        return candidate if schema_definition?(candidate)

        nil
      end

      def schema_definition?(candidate)
        return false unless candidate
        return true if defined?(Rubernetes::Schema::Definition) && candidate.is_a?(Rubernetes::Schema::Definition)
        return false if candidate.respond_to?(:raw_values) && candidate.respond_to?(:unknown_fields)

        candidate.respond_to?(:fields) && candidate.respond_to?(:field) &&
          candidate.respond_to?(:preserve_unknown_fields)
      end

      def unknown_mode(unknown_fields:, preserve_unknown:, schema:, object:, operation:, strict:)
        mode = if unknown_fields
                 unknown_fields.to_sym
               elsif !preserve_unknown.nil?
                 preserve_unknown ? :preserve : :reject
               elsif schema
                 # JSON/YAML decoding into a concrete Kubernetes type is strict by
                 # default, while encoding a typed value follows the generated schema's
                 # pruning policy.  Callers can select :preserve or :prune explicitly.
                 operation == :load && strict ? :reject : :prune
               elsif object.respond_to?(:to_h_for_codec)
                 :prune
               else
                 :preserve
               end
        return mode if UNKNOWN_MODES.include?(mode)

        raise ArgumentError, "unknown_fields must be :preserve, :prune, or :reject"
      end

      def normalize_typed_value(value, object_definition, mode, path: [])
        return normalize_generic_value(value, path: path, mode: mode) if opaque_scalar?(object_definition, value)

        union_target = union_object_definition(object_definition)
        if union_target
          unless value.is_a?(Hash) || (value.respond_to?(:raw_values) && value.respond_to?(:unknown_fields))
            return normalize_generic_value(value, path: path,
                                                  mode: mode)
          end

          value = value.raw_values.merge(value.unknown_fields) unless value.is_a?(Hash)
          return normalize_typed_value(value, union_target, mode, path: path)
        end

        source = typed_value_parts(value, object_definition)
        result = {}
        supplied = {}
        object_definition.fields.each_value do |field|
          next unless source.fetch(:known).key?(field.name)

          supplied[field.name] = true
          result[field.json_name] = normalize_typed_field(
            source.fetch(:known).fetch(field.name),
            field,
            mode_for_field(mode, field),
            path: path + [field.json_name]
          )
        end

        unknown = source.fetch(:unknown)
        unknown.each_key do |name|
          next if supplied.key?(name)

          handle_unknown_field!(result, name, unknown.fetch(name), object_definition, mode, path)
        end
        result
      end

      def typed_value_parts(value, object_definition)
        if value.respond_to?(:raw_values) && value.respond_to?(:unknown_fields)
          known = value.raw_values.each_with_object({}) do |(key, item), result|
            field = object_definition.field(key)
            result[field ? field.name : key.to_s] = item
          end
          return {known: known, unknown: value.unknown_fields}
        end

        raise EncodeError, "expected an object for #{object_definition.kind}, got #{value.class}" unless value.is_a?(Hash)

        known = {}
        unknown = {}
        value.each do |key, item|
          key_string = key.to_s
          field = object_definition.fields.values.find do |candidate|
            [candidate.name, candidate.json_name, candidate.ruby_name].include?(key_string)
          end
          if field
            raise DuplicateKeyError, "field #{field.json_name.inspect} was supplied more than once" if known.key?(field.name)

            known[field.name] = item
          else
            unless key.is_a?(String) || key.is_a?(Symbol)
              raise UnsupportedTypeError,
                    "object keys must be String or Symbol, got #{key.class}"
            end

            raise DuplicateKeyError, "object contains duplicate key #{key_string.inspect}" if unknown.key?(key_string)

            unknown[key_string] = item
          end
        end
        {known: known, unknown: unknown}
      end

      def normalize_typed_field(value, field, mode, path:)
        return nil if value.nil?

        if field.array?
          raise EncodeError, "expected an array at #{display_path(path)}, got #{value.class}" unless value.is_a?(Array)

          return value.each_with_index.map do |item, index|
            normalize_typed_item(item, field.items, mode, path: path + [index.to_s])
          end
        end

        nested = nested_definition_for(field)
        if nested
          # An opaque carrier (apiextensions JSON, JSONSchemaPropsOr*) is any
          # JSON value on the wire; only an object is walked as a struct.
          return normalize_generic_value(value, path: path, mode: mode) if opaque_scalar?(nested, value)

          return normalize_typed_value(value, nested, mode, path: path)
        end

        return normalize_typed_map(value, field, mode, path: path) if field.object? && value.is_a?(Hash)

        normalize_generic_value(value, path: path, mode: mode)
      end

      def normalize_typed_item(value, item, mode, path:)
        return nil if value.nil?
        return normalize_typed_field(value, item, mode, path: path) if item.respond_to?(:type) && item.respond_to?(:name)

        if item && item.respond_to?(:fields) && item.respond_to?(:preserve_unknown_fields)
          return normalize_generic_value(value, path: path, mode: mode) if opaque_scalar?(item, value)

          return normalize_typed_value(value, item, mode, path: path)
        end
        if item && item.respond_to?(:resolve)
          resolved = item.resolve
          return normalize_generic_value(value, path: path, mode: mode) if opaque_scalar?(resolved, value)

          return normalize_typed_value(value, resolved, mode, path: path)
        end

        normalize_generic_value(value, path: path, mode: mode)
      end

      # A union carrier (apiextensions JSONSchemaPropsOr*) is an object of its
      # target schema or a scalar/array alternative.
      def union_object_definition(definition)
        return nil unless definition.respond_to?(:metadata) && definition.metadata.is_a?(Hash)

        name = definition.metadata[:union_object_schema] || definition.metadata["union_object_schema"]
        return nil unless name.is_a?(String) && defined?(Rubernetes::Generated) && Rubernetes::Generated.respond_to?(:definition_for)

        Rubernetes::Generated.definition_for(name)
      rescue KeyError, NameError
        nil
      end

      def opaque_scalar?(definition, value)
        return false if value.is_a?(Hash) || (value.respond_to?(:raw_values) && value.respond_to?(:unknown_fields))

        definition.respond_to?(:preserve_unknown_fields) && definition.preserve_unknown_fields &&
          definition.respond_to?(:fields) && definition.fields.empty?
      end

      def normalize_typed_map(value, field, mode, path:)
        additional = field.additional_properties
        properties = field.properties
        if additional == false && properties.empty?
          unknown = value.keys.map(&:to_s)
          if unknown.any?
            return value.each_with_object({}) do |(key, item), result|
              handle_unknown_field!(result, key.to_s, item, field, mode, path)
            end
          end
        end

        value.each_with_object({}) do |(key, item), result|
          key_string = self.class.normalize_key(key)
          property = properties[key_string]
          item_schema = property || additional
          if property
            result[key_string] = normalize_typed_field(item, property, mode_for_field(mode, property), path: path + [key_string])
          elsif additional == false || additional.nil?
            handle_unknown_field!(result, key_string, item, field, mode, path)
          elsif additional == true
            result[key_string] = normalize_generic_value(item, path: path + [key_string], mode: mode)
          else
            result[key_string] = normalize_typed_item(item, item_schema, mode, path: path + [key_string])
          end
        end
      end

      def normalize_generic_value(value, path:, mode: :preserve)
        nested_schema = schema_definition_for(value)
        return normalize_typed_value(value, nested_schema, mode, path: path) if nested_schema
        if value.respond_to?(:to_h_for_codec)
          return normalize_generic_value(value.to_h_for_codec(unknown_fields: mode), path: path, mode: mode)
        end

        case value
        when Hash
          value.each_with_object({}) do |(key, item), result|
            result[self.class.normalize_key(key)] = normalize_generic_value(item, path: path + [key.to_s], mode: mode)
          end
        when Array
          value.each_with_index.map do |item, index|
            normalize_generic_value(item, path: path + [index.to_s], mode: mode)
          end
        else
          value
        end
      end

      def mode_for_field(mode, field)
        field.respond_to?(:preserve_unknown_fields) && field.preserve_unknown_fields ? :preserve : mode
      end

      def nested_definition_for(field)
        type = field.type
        return type if schema_definition?(type)
        return type.resolve if type.respond_to?(:resolve)
        return nil unless field.object? && !field.properties.empty?

        Rubernetes::Schema::Definition.new(
          name: "Typed#{field.name.capitalize}",
          group: "",
          version: "v1",
          kind: "Typed#{field.name.capitalize}",
          fields: field.properties,
          preserve_unknown_fields: field.preserve_unknown_fields
        )
      end

      def handle_unknown_field!(result, name, value, object_definition, mode, path)
        raise_unknown_field!(path + [name]) if mode == :reject && !object_definition.respond_to?(:preserve_unknown_fields)
        if mode == :reject && object_definition.respond_to?(:preserve_unknown_fields) &&
           !object_definition.preserve_unknown_fields
          raise_unknown_field!(path + [name])
        end
        return if mode == :prune && object_definition.respond_to?(:preserve_unknown_fields) &&
                  !object_definition.preserve_unknown_fields

        result[name] = normalize_generic_value(value, path: path + [name], mode: mode)
      end

      def raise_unknown_field!(path)
        raise UnknownFieldError, "unknown field #{display_path(path)} is not allowed"
      end

      def display_path(path)
        path.empty? ? "$" : path.join(".")
      end

      def extract_known_fields(schema, known_fields)
        candidate = known_fields
        candidate = schema if candidate.nil? && schema.is_a?(Array)
        candidate = schema.keys if candidate.nil? && schema.is_a?(Hash)
        if candidate.nil? && schema
          candidate = if schema.respond_to?(:known_fields)
                        schema.known_fields
                      elsif schema.respond_to?(:fields)
                        schema.fields
                      end
        end
        return nil if candidate.nil?

        values = candidate.is_a?(Hash) ? candidate.keys : Array(candidate)
        values.map(&:to_s).uniq.freeze
      end

      def validate_schema_fields!(value, schema:, known_fields:, strict:, preserve_unknown:, unknown_fields:)
        return value unless value.is_a?(Hash)

        allowed = extract_known_fields(schema, known_fields)
        return value unless allowed

        unknown = value.keys.map(&:to_s).reject { |name| allowed.include?(name) }
        return value if unknown.empty?

        raise UnknownFieldError, "unknown fields: #{unknown.sort.join(", ")}" if unknown_fields == :reject && strict
        return value unless unknown_fields == :prune

        value.each_with_object({}) do |(key, item), result|
          result[key] = item if allowed.include?(key.to_s)
        end
      end

      class << self
        private :detect_cycle!
      end
    end
  end
end

require_relative "codec/json"
require_relative "codec/yaml"
require_relative "codec/protobuf"
require_relative "codec/cbor"

module Rubernetes
  module Schema
    JSONCodec = Codec::JSONCodec unless const_defined?(:JSONCodec, false)
    YAMLCodec = Codec::YAMLCodec unless const_defined?(:YAMLCodec, false)
    ProtobufCodec = Codec::Protobuf unless const_defined?(:ProtobufCodec, false)
    CBORCodec = Codec::CBOR unless const_defined?(:CBORCodec, false)
  end
end

# The descriptor registry is part of the codec surface, while schema registry
# loading remains owned by the higher-level schema layer.
require_relative "codec/proto_descriptor" unless Rubernetes::Schema::Codec.const_defined?(:ProtoDescriptor, false)
