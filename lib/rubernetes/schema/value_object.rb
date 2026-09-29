# frozen_string_literal: true

module Rubernetes
  module Schema
    class GenerationError < StandardError; end

    # Immutable runtime representation of a schema-defined API object.
    class ValueObject
      class << self
        def for(definition)
          raise ArgumentError, "value class requires a Schema::Definition" unless definition.is_a?(Definition)

          cache_mutex.synchronize do
            return class_cache[definition] if class_cache.key?(definition)

            generated = Class.new(self)
            generated.const_set(:DEFINITION, definition)
            generated.define_singleton_method(:definition) { const_get(:DEFINITION) }
            generated.define_singleton_method(:schema_fields) { definition.fields }
            generated.define_singleton_method(:field) { |name| definition.field(name) }
            generated.define_singleton_method(:gvk) { definition.gvk }
            generated.define_singleton_method(:gvr) { definition.gvr }
            define_accessors(generated, definition)
            class_cache[definition] = generated
          end
        end

        def definition
          if const_defined?(:DEFINITION, false)
            const_get(:DEFINITION)
          elsif const_defined?(:FIELDS, false)
            @generated_definition ||= generated_definition
          else
            nil
          end
        end

        def schema_fields
          definition ? definition.fields : {}.freeze
        end

        def known_fields
          schema_fields.keys.freeze
        end

        def schema_name
          if const_defined?(:SCHEMA_NAME, false)
            const_get(:SCHEMA_NAME)
          elsif definition
            definition.name
          end
        end

        def build(definition, values = {}, **keywords)
          self.for(definition).new(values, **keywords)
        end

        private

        def class_cache
          @class_cache ||= {}
        end

        def cache_mutex
          @cache_mutex ||= Mutex.new
        end

        def define_accessors(klass, definition)
          seen = {}
          definition.fields.each_value do |field|
            ruby_name = field.ruby_name
            if seen.key?(ruby_name)
              raise GenerationError, "fields #{seen.fetch(ruby_name).json_name.inspect} and #{field.json_name.inspect} collide with accessor #{ruby_name.inspect}"
            end

            seen[ruby_name] = field
            if instance_methods.include?(ruby_name.to_sym) || private_instance_methods.include?(ruby_name.to_sym) ||
               protected_instance_methods.include?(ruby_name.to_sym) || seen.values[0...-1].any? { |item| item.ruby_name == ruby_name }
              raise GenerationError, "field #{field.json_name.inspect} collides with generated accessor #{ruby_name.inspect}"
            end

            klass.define_method(ruby_name) { self[field.json_name] }
            presence_name = "#{ruby_name}?"
            unless instance_methods.include?(presence_name.to_sym) || private_instance_methods.include?(presence_name.to_sym)
              klass.define_method(presence_name) { present?(field.json_name) }
            end
          end
        end

        def generated_definition
          schema_name = const_defined?(:SCHEMA_NAME, false) ? const_get(:SCHEMA_NAME).to_s : name.to_s
          parts = schema_name.split(".")
          version_index = parts.rindex { |part| part.match?(/\Av\d/) }
          version = version_index ? parts[version_index] : "v1"
          group = version_index && version_index.positive? && parts[version_index - 1] != "core" ? parts[version_index - 1] : ""
          kind = parts.last.to_s
          fields = Array(const_get(:FIELDS)).to_h { |field| [field.to_s, :any] }
          Definition.new(name: kind, group: group, version: version, kind: kind, fields: fields)
        end
      end

      attr_reader :presence

      def initialize(values = {}, **keywords)
        values = normalize_input(values, keywords)
        unless values.respond_to?(:each_pair)
          raise ArgumentError, "schema object values must be a Hash or another ValueObject"
        end

        definition = self.class.definition
        unless definition
          raise ArgumentError, "ValueObject subclasses must declare a schema Definition"
        end

        known = {}
        unknown = {}
        presence = {}
        values.each_pair do |key, value|
          field = field_for_key(definition, key)
          if field
            canonical = field.name
            raise ArgumentError, "field #{key.inspect} was supplied more than once" if presence.key?(canonical)

            known[canonical] = normalize_value(field, value)
            presence[canonical] = true
          else
            canonical = key.to_s
            raise ArgumentError, "unknown field key cannot be nil" if canonical.empty?

            raise ArgumentError, "unknown field #{canonical.inspect} was supplied more than once" if unknown.key?(canonical)

            unknown[canonical] = deep_copy(value)
          end
        end

        @values = DeepFreeze.call(known)
        @unknown_fields = DeepFreeze.call(unknown)
        @presence = DeepFreeze.call(presence)
        freeze
      end

      def definition
        self.class.definition
      end

      def gvk
        definition.gvk
      end

      def gvr
        definition.gvr
      end

      # Generated source uses this finite lookup instead of dynamic dispatch.
      def field(name)
        self[name]
      end

      def [](name)
        field = find_field(name)
        return @values[field.name] if field && @presence.key?(field.name)
        return @unknown_fields[name.to_s] if field.nil? && @unknown_fields.key?(name.to_s)

        nil
      end

      def fetch(name, default = (missing = true; nil), &block)
        canonical = canonical_field_name(name)
        return @values[canonical] if canonical && @presence.key?(canonical)
        return @unknown_fields[name.to_s] if canonical.nil? && @unknown_fields.key?(name.to_s)
        return default unless missing
        return block.call(name) if block

        raise KeyError, "key #{name.inspect} is not present in #{definition.kind}"
      end

      def key?(name)
        present?(name) || @unknown_fields.key?(name.to_s)
      end
      alias has_key? key?

      def present?(name)
        canonical = canonical_field_name(name)
        canonical ? @presence.key?(canonical) : false
      end
      alias field_present? present?

      def absent?(name)
        !present?(name)
      end

      def fields
        @values.dup.freeze
      end

      def known_fields
        definition.fields.keys.freeze
      end

      def raw_values
        @values
      end

      def unknown_fields
        @unknown_fields
      end

      def unknown_field?(name)
        @unknown_fields.key?(name.to_s)
      end

      def present_fields
        @presence.keys.freeze
      end

      # Returns wire-format keys while retaining omission and unknown-field semantics.
      #
      # The public object representation preserves unknown fields by default so a
      # caller can inspect or explicitly forward data that the schema does not
      # understand.  Typed JSON codecs use +to_h_for_codec+ instead, which applies
      # the schema's field-level preservation policy while retaining this lossless
      # representation for protobuf and patch paths.
      def to_h(include_unknown: true, unknown_fields: :preserve)
        mode = normalize_unknown_mode(unknown_fields, include_unknown)
        result = {}
        @presence.each_key do |canonical|
          field = definition.field(canonical)
          result[field.json_name] = serialize_value(@values[canonical], field: field, unknown_fields: mode)
        end
        if include_unknown && (mode == :preserve || definition.preserve_unknown_fields)
          @unknown_fields.each { |key, value| result[key] = serialize_value(value, unknown_fields: mode) }
        end
        DeepFreeze.call(result)
      end
      alias to_hash to_h

      # Returns the representation consumed by a typed JSON/YAML codec.  Unknown
      # fields are pruned recursively unless an owning schema field explicitly
      # preserves them; protobuf callers continue to use the lossless +to_h+ path.
      def to_h_for_codec(unknown_fields: :prune)
        to_h(include_unknown: true, unknown_fields: unknown_fields)
      end

      def as_json(*)
        to_h
      end

      def with(values = nil, **changes)
        if values && !values.respond_to?(:each_pair)
          raise ArgumentError, "copy-with values must be a Hash"
        end

        updates = (values || {}).to_h.merge(changes)
        known = @values.dup
        unknown = @unknown_fields.dup
        present = @presence.dup
        updates.each do |key, value|
          field = find_field(key)
          if field
            known[field.name] = normalize_value(field, value)
            present[field.name] = true
          else
            unknown[key.to_s] = deep_copy(value)
          end
        end
        self.class.new(known.merge(unknown))
      end

      def without(*names)
        remove = names.flatten.map { |name| canonical_field_name(name) || name.to_s }
        retained = {}
        @presence.each_key do |canonical|
          retained[canonical] = @values[canonical] unless remove.include?(canonical)
        end
        @unknown_fields.each { |key, value| retained[key] = value unless remove.include?(key) }
        self.class.new(retained)
      end

      def ==(other)
        other.is_a?(ValueObject) && other.definition == definition && other.presence == presence &&
          other.raw_values == raw_values && other.unknown_fields == unknown_fields
      end
      alias eql? ==

      def hash
        [definition, @presence, @values, @unknown_fields].hash
      end

      def semantic_equal?(other, defaulting: true)
        return false unless other.is_a?(ValueObject) && other.definition.gvk == gvk

        if defaulting
          definition.defaulting.apply(self).to_h == definition.defaulting.apply(other).to_h
        else
          to_h == other.to_h
        end
      end

      def deconstruct_keys(keys)
        hash = to_h
        keys ? hash.slice(*keys) : hash
      end

      def inspect
        "#<#{self.class.name || 'Rubernetes::Schema::ValueObject'} #{to_h.inspect}>"
      end

      protected

      def field_for_key(definition, key)
        return nil if key.nil?
        name = key.to_s
        definition.fields[name] || definition.fields.values.find { |field| field.ruby_name == name || field.json_name == name }
      end

      def canonical_field_name(name)
        return nil if name.nil?
        field = find_field(name)
        field&.name
      end

      def find_field(name)
        definition.field(name) || definition.fields.values.find do |item|
          item.ruby_name == name.to_s || item.json_name == name.to_s
        end
      end

      def normalize_input(values, keywords)
        source = if values.is_a?(ValueObject)
                   values.to_h
                 else
                   values
                 end
        return source if keywords.empty?

        unless source.respond_to?(:each_pair)
          raise ArgumentError, "keyword fields require a Hash or another ValueObject"
        end
        source.to_h.merge(keywords)
      end

      def normalize_value(field, value)
        return nil if value.nil?

        type = field.type
        if field.array?
          values = value.is_a?(Array) ? value : raise(ArgumentError, "field #{field.name} expects an Array")
          return values.map { |item| normalize_item(field.items, item) }
        end

        nested = nested_definition(field)
        return nested.value_class.new(value) if nested && !value.is_a?(ValueObject)
        return value if value.is_a?(ValueObject)

        if type == :object && value.is_a?(Hash) && field.additional_properties && field.additional_properties != true
          return value.each_with_object({}) do |(key, item), result|
            result[deep_copy(key)] = normalize_item(field.additional_properties, item)
          end
        end

        if type == :object && value.is_a?(Hash) && field.properties.empty?
          return deep_copy(value)
        end

        deep_copy(value)
      end

      def normalize_item(item, value)
        return deep_copy(value) if item.nil?
        return value if value.nil?
        if item.is_a?(Field)
          return normalize_value(item, value)
        end
        if item.is_a?(Definition)
          return item.value_class.new(value)
        end
        if item.is_a?(Reference)
          return item.resolve.value_class.new(value)
        end
        return deep_copy(value) if item == :any
        return deep_copy(value) if item.is_a?(Class) && value.is_a?(item)
        deep_copy(value)
      end

      def nested_definition(field)
        return field.type if field.type.is_a?(Definition)
        return field.type.resolve if field.type.is_a?(Reference)
        return field.items if field.items.is_a?(Definition)
        return field.items.resolve if field.items.is_a?(Reference)
        return nil unless field.object? && !field.properties.empty?

        Definition.new(
          name: "#{definition.kind}#{field.name.capitalize}",
          group: definition.group,
          version: definition.version,
          kind: "#{definition.kind}#{field.name.capitalize}",
          resource: "#{definition.resource}-#{field.name}",
          scope: definition.scope,
          fields: field.properties,
          preserve_unknown_fields: field.preserve_unknown_fields
        )
      end

      def normalize_unknown_mode(mode, include_unknown)
        mode = include_unknown ? :preserve : :prune if mode.nil?
        mode = mode.to_sym
        return mode if %i[preserve prune].include?(mode)

        raise ArgumentError, "unknown_fields must be :preserve or :prune"
      end

      def serialize_value(value, field: nil, unknown_fields: :preserve)
        child_mode = if field&.preserve_unknown_fields
                       :preserve
                     else
                       unknown_fields
                     end

        case value
        when ValueObject
          value.to_h_for_codec(unknown_fields: child_mode)
        when Array
          item = field&.items
          value.map { |item_value| serialize_item(item_value, item, child_mode) }.freeze
        when Hash
          value.each_with_object({}) do |(key, item), result|
            result[key] = serialize_item(item, field&.additional_properties, child_mode)
          end.freeze
        else
          value
        end
      end

      def serialize_item(value, item, unknown_fields)
        return serialize_value(value, field: item, unknown_fields: unknown_fields) if item.is_a?(Field)
        return value.to_h_for_codec(unknown_fields: unknown_fields) if value.is_a?(ValueObject)
        return value.map { |child| serialize_item(child, item, unknown_fields) }.freeze if value.is_a?(Array)
        return value.each_with_object({}) { |(key, child), result| result[key] = serialize_item(child, item, unknown_fields) }.freeze if value.is_a?(Hash)

        value
      end

      def deep_copy(value)
        case value
        when ValueObject
          value
        when Hash
          value.each_with_object({}) { |(key, item), result| result[deep_copy(key)] = deep_copy(item) }
        when Array
          value.map { |item| deep_copy(item) }
        else
          value.dup
        end
      rescue TypeError
        value
      end
    end
  end
end
