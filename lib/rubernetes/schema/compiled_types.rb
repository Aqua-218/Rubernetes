# frozen_string_literal: true

require "json"
require_relative "../schema"

module Rubernetes
  module Schema
    # Installs the Ruby API for a compiler-produced registry. A Ruby autoload
    # covers one schema package, so loading a Pod does not build every API.
    class CompiledTypes
      attr_reader :constants

      def initialize(namespace, directory)
        @namespace = namespace
        records = JSON.parse(File.binread(File.join(directory, "../schema/registry.json")), freeze: true).fetch("types")
        @types = records.to_h { |type| [type.fetch("schema"), type] }.freeze
        @constants = @types.transform_values { |type| type.fetch("ruby_constant") }.freeze
        constants.each do |name, constant|
          package = self.class.package(name)
          namespace.autoload(constant, File.join(directory, "types", "#{package}.rb"))
        end
      end

      def self.package(name)
        # Use a single path component, including for unqualified custom types.
        package = name.rpartition(".").first
        /\A[\w-]+(?:\.[\w-]+)*\z/.match?(package) && package.bytesize < 250 ? package : "_other"
      end

      def definition_for(name)
        @namespace.const_get(constants.fetch(name), false).const_get(:DEFINITION, false)
      end

      def define(name, readers)
        type = @types.fetch(name)
        klass = Class.new(ValueObject)
        fields = DeepFreeze.call(field_map(type.fetch("field_definitions")))
        identity = type.fetch("gvks").first || inferred_identity(name)
        options = type.slice("preserve_unknown_fields", "union_object_schema", "union_scalar_types").transform_keys(&:to_sym)
        definition = Definition.new(name: name, **identity.transform_keys(&:to_sym), fields: fields, required: type.fetch("required"), **options)
        klass.const_set(:SCHEMA_NAME, name)
        klass.const_set(:FIELDS, type.fetch("fields"))
        klass.const_set(:REQUIRED_FIELDS, type.fetch("required"))
        klass.const_set(:FIELD_DEFINITIONS, fields)
        klass.const_set(:DEFINITION, definition)
        readers.each do |reader|
          method, field_name = reader.is_a?(Array) ? reader : [reader, reader]
          klass.define_method(method) { field(field_name) }
        end
        @namespace.const_set(constants.fetch(name), klass)
      end

      private

      def field_map(fields)
        fields.transform_values { |options| field_options(options) }
      end

      def field_options(options)
        result = options.transform_keys(&:to_sym)
        result[:type] = if result[:type] == "reference"
                          name = result.delete(:reference)
                          Reference.new(name) { definition_for(name) }
                        else
                          result.fetch(:type).to_sym
                        end
        result[:properties] = field_map(result[:properties]) if result[:properties]
        %i[items additional_properties].each do |key|
          result[key] = field_options(result[key]) if result[key].is_a?(Hash)
        end
        result
      end

      def inferred_identity(name)
        parts = name.split(".")
        index = parts.rindex { |part| part.match?(/\Av\d/) }
        {
          group: index&.positive? && parts[index - 1] != "core" ? parts[index - 1] : "",
          version: index ? parts[index] : "internal",
          kind: parts.last
        }
      end
    end
  end
end
