# frozen_string_literal: true

require "json"

module Rubernetes
  module Manifest
    class Error < StandardError; end
    class UnknownField < Error; end
    class DuplicateMethod < Error; end

    class Builder
      RESERVED_METHODS = (
        BasicObject.instance_methods + Object.instance_methods + Kernel.instance_methods +
        %i[resource result object schema_definition append_resource]
      ).map(&:to_s).uniq.freeze

      attr_reader :result

      def self.load(registry_path:, openapi_path:)
        registry = JSON.parse(File.binread(registry_path), max_nesting: 512)
        openapi = JSON.parse(File.binread(openapi_path), max_nesting: 512)
        new(registry: registry, definitions: openapi.fetch("definitions"))
      rescue JSON::ParserError, KeyError => error
        raise Error.new("cannot load generated manifest schema: #{error.message}"), cause: error
      end

      def initialize(registry:, definitions:)
        @registry = registry
        @definitions = definitions
        @resources = registry.fetch("resources")
        @types = registry.fetch("types")
        @result = []
        extend(build_resource_methods)
      end

      def resource(api_version:, kind:, name:, namespace: nil, **metadata, &block)
        group, version = split_api_version(api_version)
        type = @types.find do |entry|
          entry.fetch("gvks").any? do |gvk|
            gvk.fetch("group") == group && gvk.fetch("version") == version && gvk.fetch("kind") == kind
          end
        end
        raise Error, "unknown GVK #{api_version}/#{kind}" unless type

        object = {
          "apiVersion" => api_version,
          "kind" => kind,
          "metadata" => stringify_keys(metadata).merge("name" => String(name))
        }
        object.fetch("metadata")["namespace"] = String(namespace) if namespace
        context = ObjectBuilder.new(object: object, schema_name: type.fetch("schema"), definitions: @definitions)
        context.instance_exec(&block) if block
        @result << deep_freeze(object)
        object
      end

      private

      def build_resource_methods
        methods = Module.new
        registrations = {}
        @types.each do |type|
          type.fetch("gvks").each do |gvk|
            method_name = underscore(gvk.fetch("kind"))
            qualified_parts = [gvk.fetch("group").split(".").first, gvk.fetch("version"), gvk.fetch("kind")]
            qualified = underscore(qualified_parts.compact.reject(&:empty?).join("_"))
            api_version = gvk.fetch("group").empty? ? gvk.fetch("version") : "#{gvk.fetch("group")}/#{gvk.fetch("version")}"
            install_resource_method(methods, qualified, api_version, gvk.fetch("kind"))
            registrations[method_name] ||= []
            registrations.fetch(method_name) << [api_version, gvk.fetch("kind")]
          end
        end
        registrations.each do |method_name, targets|
          preferred = preferred_target(targets)
          install_resource_method(methods, method_name, *preferred)
        end
        methods
      end

      def install_resource_method(methods, method_name, api_version, kind)
        validate_method_name!(method_name)
        return if methods.method_defined?(method_name.to_sym, false)

        methods.define_method(method_name) do |name, namespace: nil, **metadata, &block|
          resource(api_version: api_version, kind: kind, name: name, namespace: namespace, **metadata, &block)
        end
      end

      def preferred_target(targets)
        targets.min_by do |api_version, _kind|
          version = api_version.split("/").last
          stability = if version.match?(/\Av\d+\z/)
                        0
                      else
                        version.include?("beta") ? 1 : 2
                      end
          [stability, version]
        end
      end

      def underscore(value)
        value.gsub(/([A-Z]+)([A-Z][a-z])/, "\\1_\\2")
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-.", "__")
          .downcase
      end

      def validate_method_name!(method_name)
        return if method_name.match?(/\A[a-z_]\w*[!?=]?\z/) && !RESERVED_METHODS.include?(method_name)

        raise DuplicateMethod, "unsafe generated manifest method #{method_name.inspect}"
      end

      def split_api_version(api_version)
        api_version.include?("/") ? api_version.split("/", 2) : ["", api_version]
      end

      def stringify_keys(value)
        value.to_h { |key, child| [String(key), child] }
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each do |key, child|
            key.freeze
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end
    end

    class ObjectBuilder
      RESERVED_METHODS = (Builder::RESERVED_METHODS + %w[field set]).freeze

      def initialize(object:, schema_name:, definitions:)
        @object = object
        @schema_name = schema_name
        @definitions = definitions
        extend(build_field_methods(schema_name))

        install_spec_shortcuts
      end

      def field(json_name, value = :__rubernetes_missing__, **keywords, &)
        schema = schema_definition(@schema_name)
        field_schema = schema.fetch("properties", {})[String(json_name)]
        raise UnknownField, "unknown field #{json_name.inspect} in #{@schema_name}" unless field_schema

        @object[String(json_name)] = build_value(field_schema, value, keywords, &)
      end

      private

      def build_field_methods(schema_name)
        methods = Module.new
        schema_definition(schema_name).fetch("properties", {}).keys.sort.each do |json_name|
          method_name = underscore(json_name)
          next if RESERVED_METHODS.include?(method_name)
          raise DuplicateMethod, "invalid field method #{method_name.inspect}" unless method_name.match?(/\A[a-z_]\w*\z/)
          raise DuplicateMethod, "field method collision #{method_name}" if methods.method_defined?(method_name.to_sym, false)

          methods.define_method(method_name) do |value = :__rubernetes_missing__, **keywords, &block|
            field(json_name, value, **keywords, &block)
          end
        end
        methods
      end

      def install_spec_shortcuts
        spec_schema = property_schema("spec")
        return unless spec_schema

        referenced = reference_name(spec_schema)
        return unless referenced

        methods = build_field_methods(referenced)
        collision_free = Module.new
        methods.instance_methods(false).each do |method_name|
          next if respond_to?(method_name)

          collision_free.define_method(method_name) do |value = :__rubernetes_missing__, **keywords, &block|
            @object["spec"] ||= {}
            spec_builder = ObjectBuilder.new(object: @object.fetch("spec"), schema_name: referenced, definitions: @definitions)
            spec_builder.public_send(method_name, value, **keywords, &block)
          end
        end
        extend(collision_free)
      end

      def build_value(field_schema, value, keywords, &block)
        unless keywords.empty?
          raise Error, "cannot combine positional and keyword values" unless value == :__rubernetes_missing__

          value = keywords.transform_keys(&:to_s)
        end
        if block
          raise Error, "cannot combine a value and block" unless value == :__rubernetes_missing__

          reference = reference_name(field_schema)
          raise Error, "field does not accept a nested object" unless reference

          value = {}
          ObjectBuilder.new(object: value, schema_name: reference, definitions: @definitions).instance_exec(&block)
        elsif value == :__rubernetes_missing__
          raise Error, "field value or block is required"
        end
        normalize_value(value)
      end

      def normalize_value(value)
        case value
        when Hash
          value.to_h { |key, child| [String(key), normalize_value(child)] }
        when Array
          value.map { |child| normalize_value(child) }
        else
          value
        end
      end

      def property_schema(name)
        schema_definition(@schema_name).fetch("properties", {})[name]
      end

      def reference_name(schema)
        schema["$ref"]&.delete_prefix("#/definitions/")
      end

      def schema_definition(name)
        @definitions.fetch(name) { raise Error, "missing schema definition #{name}" }
      end

      def underscore(value)
        value.gsub(/([A-Z]+)([A-Z][a-z])/, "\\1_\\2")
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-.", "__")
          .downcase
      end
    end
  end
end
