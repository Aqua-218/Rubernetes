# frozen_string_literal: true

module Rubernetes
  module Manifest
    class Error < StandardError; end
    class UnknownField < Error; end
    class DuplicateMethod < Error; end

    # A ConfigMap or Secret named in a manifest (`configmap("app-config")`).
    Reference = Data.define(:kind, :name)

    # The OpenAPI definitions a manifest is checked against while it is
    # built.  Ruby values become the JSON the API expects: a field may be
    # written in snake_case, a field the type does not have is an error that
    # names the type and the nearest field, and the keys of a map (labels,
    # ConfigMap data) are left exactly as written.
    class Schema
      def self.underscore(value)
        value.gsub(/([A-Z]+)([A-Z][a-z])/, "\\1_\\2")
          .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
          .tr("-.", "__")
          .downcase
      end

      def initialize(definitions)
        @definitions = definitions
      end

      def definition(name)
        @definitions.fetch(name) { raise Error, "missing schema definition #{name}" }
      end

      def defined?(name) = @definitions.key?(name)

      def reference(schema)
        schema["$ref"]&.delete_prefix("#/definitions/")
      end

      def coerce(schema, value, path)
        referenced = reference(schema)
        return object(referenced, value, path) if referenced

        if schema["type"] == "array" && value.is_a?(Array)
          items = schema["items"] || {}
          value.each_with_index.map { |item, index| coerce(items, item, "#{path}[#{index}]") }
        elsif schema["additionalProperties"].is_a?(Hash) && value.is_a?(Hash)
          value.to_h { |key, item| [String(key), coerce(schema["additionalProperties"], item, "#{path}.#{key}")] }
        else
          plain(value)
        end
      end

      # `value` as an object of the named type.  A type without fields of its
      # own (a Quantity, an IntOrString, arbitrary JSON) takes the value as
      # it is.
      def object(name, value, path)
        properties = self.defined?(name) ? definition(name)["properties"] : nil
        return plain(value) unless properties && value.is_a?(Hash)

        value.to_h do |key, item|
          json_name = json_name(properties, key) || raise(UnknownField, unknown_field(key, name, properties, path))
          [json_name, coerce(properties.fetch(json_name), item, "#{path}.#{json_name}")]
        end
      end

      private

      def json_name(properties, key)
        text = String(key)
        properties.key?(text) ? text : properties.each_key.find { |name| self.class.underscore(name) == text }
      end

      def unknown_field(key, type, properties, path)
        candidates = properties.keys.map { |name| self.class.underscore(name) }
        nearest = DidYouMean::SpellChecker.new(dictionary: candidates).correct(String(key)).first
        "#{path}: #{type.split(".").last} has no field #{String(key).inspect}#{" (did you mean #{nearest.inspect}?)" if nearest}"
      end

      def plain(value)
        case value
        when Hash then value.to_h { |key, item| [String(key), plain(item)] }
        when Array then value.map { |item| plain(item) }
        when Symbol then value.to_s
        else value
        end
      end
    end
  end
end
