# frozen_string_literal: true

module Rubernetes
  module Schema
    # Recursively freezes schema input so compiler state cannot be changed by a caller.
    module DeepFreeze
      # Containers already frozen all the way down, by identity.  Defaulting
      # freezes each nested object as it builds it and then the object that
      # holds it, so without this every level re-walked everything below it
      # -- 43% of defaulting a Pod.
      DEEP_FROZEN = ObjectSpace::WeakMap.new

      module_function

      def deep_frozen?(value)
        value.frozen? && DEEP_FROZEN.key?(value)
      end

      # Only containers can close a cycle, so only they are remembered, by
      # identity: recording every String by object_id (which allocates an id
      # in Ruby 3.4) was most of the cost of freezing a defaulted Pod.
      def call(value, seen = nil)
        case value
        when Hash
          return value if deep_frozen?(value)

          seen ||= {}.compare_by_identity
          return value if seen.key?(value)

          seen[value] = true
          value.each do |key, item|
            call(key, seen)
            call(item, seen)
          end
          value.freeze
          DEEP_FROZEN[value] = true
          value
        when Array
          return value if deep_frozen?(value)

          seen ||= {}.compare_by_identity
          return value if seen.key?(value)

          seen[value] = true
          value.each { |item| call(item, seen) }
          value.freeze
          DEEP_FROZEN[value] = true
          value
        when nil, Numeric, true, false, Symbol
          value
        else
          value.frozen? ? value : value.freeze
        end
      end
    end

    # The identifier of a Kubernetes API type.
    class GVK
      attr_reader :group, :version, :kind

      def initialize(group = "", version = nil, kind = nil, **keywords)
        if group.is_a?(Hash)
          keywords = group.transform_keys(&:to_sym).merge(keywords)
          group = ""
        end
        group = keywords.fetch(:group, group)
        version = keywords.fetch(:version, version)
        kind = keywords.fetch(:kind, kind)
        raise ArgumentError, "GVK version must be a non-empty String" unless version.is_a?(String) && !version.empty?
        raise ArgumentError, "GVK kind must be a non-empty String" unless kind.is_a?(String) && !kind.empty?

        @group = String(group).dup.freeze
        @version = version.dup.freeze
        @kind = kind.dup.freeze
        freeze
      end

      def self.parse(value)
        return value if value.is_a?(self)

        raise ArgumentError, "GVK must be a String such as 'apps/v1/Deployment'" unless value.is_a?(String)

        if value.include?(", Kind=")
          api_version, kind = value.split(", Kind=", 2)
          group, version = api_version.split("/", 2)
          return new(version ? group : "", version || group, kind)
        end

        parts = value.split("/")
        if parts.length == 2
          new("", parts[0], parts[1])
        elsif parts.length == 3
          new(parts[0], parts[1], parts[2])
        else
          raise ArgumentError, "GVK must be '<version>/<kind>' or '<group>/<version>/<kind>'"
        end
      end

      def api_version
        group.empty? ? version : "#{group}/#{version}"
      end

      alias group_version api_version

      def to_s
        "#{api_version}/#{kind}"
      end

      def to_h
        {group: group, version: version, kind: kind}.freeze
      end

      alias identifier to_s

      def ==(other)
        other.is_a?(GVK) && other.group == group && other.version == version && other.kind == kind
      end
      alias eql? ==

      def hash
        [group, version, kind].hash
      end
    end

    # The identifier used by the REST API for a Kubernetes resource.
    class GVR
      attr_reader :group, :version, :resource

      def initialize(group = "", version = nil, resource = nil, **keywords)
        if group.is_a?(Hash)
          keywords = group.transform_keys(&:to_sym).merge(keywords)
          group = ""
        end
        group = keywords.fetch(:group, group)
        version = keywords.fetch(:version, version)
        resource = keywords.fetch(:resource, resource)
        raise ArgumentError, "GVR version must be a non-empty String" unless version.is_a?(String) && !version.empty?
        raise ArgumentError, "GVR resource must be a non-empty String" unless resource.is_a?(String) && !resource.empty?

        @group = String(group).dup.freeze
        @version = version.dup.freeze
        @resource = resource.dup.freeze
        freeze
      end

      def self.parse(value)
        return value if value.is_a?(self)

        raise ArgumentError, "GVR must be a String such as 'apps/v1/deployments'" unless value.is_a?(String)

        parts = value.split("/")
        if parts.length == 2
          new("", parts[0], parts[1])
        elsif parts.length == 3
          new(parts[0], parts[1], parts[2])
        else
          raise ArgumentError, "GVR must be '<version>/<resource>' or '<group>/<version>/<resource>'"
        end
      end

      def api_version
        group.empty? ? version : "#{group}/#{version}"
      end

      alias group_version api_version

      def to_s
        "#{api_version}/#{resource}"
      end

      def to_h
        {group: group, version: version, resource: resource}.freeze
      end

      alias identifier to_s

      def ==(other)
        other.is_a?(GVR) && other.group == group && other.version == version && other.resource == resource
      end
      alias eql? ==

      def hash
        [group, version, resource].hash
      end
    end

    # A cycle-safe reference to another immutable schema definition.
    class Reference
      attr_reader :name

      def initialize(name, &resolver)
        raise ArgumentError, "schema reference name must be a non-empty String" unless name.is_a?(String) && !name.empty?
        raise ArgumentError, "schema reference requires a resolver block" unless resolver

        @name = name.dup.freeze
        @resolver = resolver.freeze
        freeze
      end

      def resolve
        definition = @resolver.call
        raise ArgumentError, "schema reference #{name.inspect} did not resolve to a Schema::Definition" unless definition.is_a?(Definition)

        definition
      end

      def to_h
        {reference: name}.freeze
      end

      def ==(other)
        other.is_a?(Reference) && other.name == name
      end
      alias eql? ==

      def hash
        name.hash
      end
    end

    # A field in a schema AST.
    class Field
      TYPE_ALIASES = {
        string: :string,
        integer: :integer,
        int: :integer,
        number: :number,
        float: :number,
        boolean: :boolean,
        bool: :boolean,
        object: :object,
        map: :object,
        array: :array,
        list: :array,
        any: :any,
        null: :null
      }.freeze

      attr_reader :lookup_keys, :lookup_symbols, :name, :json_name, :ruby_name, :type, :items, :properties, :required, :nullable,
                  :default_value, :enum, :minimum, :maximum, :exclusive_minimum, :exclusive_maximum, :pattern, :preserve_unknown_fields, :additional_properties, :metadata

      def initialize(name = nil, type = nil, **keywords)
        if type.is_a?(Hash) && keywords.empty?
          keywords = type.transform_keys(&:to_sym)
          type = keywords.delete(:type)
        end
        if name.is_a?(Hash)
          options = name
          name = options[:name] || options["name"] || options[:json_name] || options["json_name"]
          type = options[:type] || options["type"]
          keywords = options.transform_keys(&:to_sym).merge(keywords)
        end

        keywords = normalize_keyword_names(keywords)

        name = keywords.fetch(:name, name)
        json_name = keywords.fetch(:json_name, name)
        raise ArgumentError, "field name must be a non-empty String or Symbol" if name.nil? || name.to_s.empty?

        @name = name.to_s.freeze
        @json_name = json_name.to_s.freeze
        raise ArgumentError, "field JSON name must be a non-empty String" if @json_name.empty?

        @ruby_name = keywords.fetch(:ruby_name, safe_ruby_name(@json_name)).to_s.freeze
        # The spellings a value may carry this field under, in the order a
        # reader prefers them, with their Symbol forms (Validator#read_field).
        @lookup_keys = [@json_name, @name, @ruby_name].uniq.freeze
        @lookup_symbols = @lookup_keys.map(&:to_sym).freeze
        @type = normalize_type(keywords.fetch(:type, type), keywords)
        @items = normalize_items(keywords)
        @additional_properties = normalize_additional_properties(keywords)
        required_option = keywords.fetch(:required, false)
        @properties = normalize_properties(keywords, Array(required_option).map(&:to_s))
        @required = required_option == true
        @nullable = !!keywords.fetch(:nullable, false)
        @has_default = keywords.key?(:default)
        @default_value = (DeepFreeze.call(copy_value(keywords[:default])) if @has_default)
        @enum = normalize_enum(keywords.fetch(:enum, keywords[:one_of]))
        @minimum = keywords.fetch(:minimum, keywords[:min])
        @maximum = keywords.fetch(:maximum, keywords[:max])
        @exclusive_minimum = keywords.fetch(:exclusive_minimum, false)
        @exclusive_maximum = keywords.fetch(:exclusive_maximum, false)
        if @minimum.nil? && @exclusive_minimum.is_a?(Numeric)
          @minimum = @exclusive_minimum
          @exclusive_minimum = true
        end
        if @maximum.nil? && @exclusive_maximum.is_a?(Numeric)
          @maximum = @exclusive_maximum
          @exclusive_maximum = true
        end
        @pattern = normalize_pattern(keywords[:pattern])
        @preserve_unknown_fields = !!keywords.fetch(:preserve_unknown_fields,
                                                    keywords.fetch(:preserve_unknown, false))
        @metadata = DeepFreeze.call(copy_value(keywords.reject do |key, _|
          %i[name json_name ruby_name type items of properties required nullable default enum one_of minimum maximum min
             exclusive_minimum exclusive_maximum pattern preserve_unknown_fields preserve_unknown
             additional_properties].include?(key)
        end))
        freeze
      end

      def required?
        required
      end

      def nullable?
        nullable
      end

      def default?
        !default_value.nil? || @has_default
      end

      # The schema declared a default (even one whose value is nil).
      def explicit_default?
        @has_default
      end

      def array?
        type == :array
      end

      def object?
        type == :object || type.is_a?(Reference)
      end

      def reference?
        type.is_a?(Reference)
      end

      def scalar?
        !array? && !object?
      end

      def with(**changes)
        options = to_h.merge(changes)
        options.delete(:default) unless changes.key?(:default) || explicit_default?
        self.class.new(options)
      end

      def to_h
        result = {
          name: name,
          json_name: json_name,
          ruby_name: ruby_name,
          type: type,
          required: required,
          nullable: nullable,
          preserve_unknown_fields: preserve_unknown_fields
        }
        result[:items] = items unless items.nil?
        result[:additional_properties] = additional_properties unless additional_properties.nil?
        result[:properties] = properties unless properties.empty?
        result[:default] = default_value if has_default?
        result[:enum] = enum unless enum.nil?
        result[:minimum] = minimum unless minimum.nil?
        result[:maximum] = maximum unless maximum.nil?
        result[:exclusive_minimum] = exclusive_minimum if exclusive_minimum
        result[:exclusive_maximum] = exclusive_maximum if exclusive_maximum
        result[:pattern] = pattern.source if pattern
        result.merge!(metadata)
        DeepFreeze.call(result)
      end

      private

      def safe_ruby_name(value)
        candidate = value.to_s.gsub(/[^a-zA-Z0-9_]/, "_")
        candidate = "field_#{candidate}" if candidate.empty? || candidate.match?(/\A\d/)
        candidate
      end

      def normalize_type(value, keywords)
        value = keywords[:schema] if value.nil? && keywords.key?(:schema)
        return :array if value.nil? && (keywords.key?(:items) || keywords.key?(:of))

        case value
        when Symbol
          TYPE_ALIASES.fetch(value) { value }
        when String
          TYPE_ALIASES.fetch(value.downcase.to_sym) { value.dup.freeze }
        when Class
          return :string if value == String
          return :integer if value == Integer
          return :number if [Float, Numeric].include?(value)
          return :boolean if [TrueClass, FalseClass].include?(value)
          return :array if value == Array
          return :object if value == Hash

          value
        when Module
          value
        when Definition, Reference
          value
        when Hash
          :object
        when nil
          :any
        else
          value
        end
      end

      def normalize_keyword_names(keywords)
        aliases = {
          minLength: :min_length,
          maxLength: :max_length,
          minItems: :min_items,
          maxItems: :max_items,
          exclusiveMinimum: :exclusive_minimum,
          exclusiveMaximum: :exclusive_maximum,
          preserveUnknownFields: :preserve_unknown_fields,
          oneOf: :one_of,
          additionalProperties: :additional_properties
        }
        keywords.each_with_object({}) do |(key, value), result|
          normalized = aliases.fetch(key, key)
          result[normalized] = value
        end
      end

      def normalize_items(keywords)
        value = keywords.fetch(:items, keywords[:of])
        return nil if value.nil?
        return value if value.is_a?(Field) || value.is_a?(Definition) || value.is_a?(Reference) ||
                        value.is_a?(Class) || value.is_a?(Module)
        return Field.new("item", value) if value.is_a?(Symbol) || value.is_a?(String) || value.is_a?(Hash)

        value
      end

      def normalize_additional_properties(keywords)
        return nil unless keywords.key?(:additional_properties)

        value = keywords[:additional_properties]
        return value if value == true || value == false || value.is_a?(Field) || value.is_a?(Definition) ||
                        value.is_a?(Reference) || value.is_a?(Class) || value.is_a?(Module)
        return Field.new("value", value) if value.is_a?(Symbol) || value.is_a?(String) || value.is_a?(Hash)

        raise ArgumentError, "field additional_properties must be a schema or boolean"
      end

      def normalize_properties(keywords, required_names = [])
        source = keywords.fetch(:properties, {})
        raise ArgumentError, "field properties must be a Hash" unless source.respond_to?(:each_pair)

        source.each_with_object({}) do |(key, value), result|
          result[key.to_s] = if value.is_a?(Field)
                               value
                             elsif value.is_a?(Hash)
                               options = value.transform_keys(&:to_sym)
                               option_keys = %i[type items of properties required nullable default enum one_of minimum maximum
                                                min max exclusive_minimum exclusive_maximum pattern preserve_unknown_fields
                                                preserve_unknown ruby_name json_name]
                               if options.keys.any? { |option| option_keys.include?(option) }
                                 options[:required] = true if required_names.include?(key.to_s)
                                 Field.new(options.merge(name: key.to_s))
                               elsif required_names.include?(key.to_s)
                                 Field.new(key.to_s, :object, properties: value, required: true)
                               else
                                 Field.new(key.to_s, :object, properties: value)
                               end
                             else
                               Field.new(key.to_s, value, required: required_names.include?(key.to_s))
                             end
        end
      end

      def normalize_enum(value)
        return nil if value.nil?
        raise ArgumentError, "field enum must be enumerable" unless value.respond_to?(:to_a)

        DeepFreeze.call(value.to_a.map { |item| copy_value(item) })
      end

      def normalize_pattern(value)
        return nil if value.nil? || value.is_a?(Regexp)

        Regexp.new(value.to_s)
      end

      def copy_value(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, item), result| result[copy_value(key)] = copy_value(item) }
        when Array
          value.map { |item| copy_value(item) }
        else
          duplicate_value(value)
        end
      end

      def duplicate_value(value)
        value.dup
      rescue TypeError
        value
      end
    end

    # A complete schema definition, including its REST identifiers and fields.
    class Definition
      attr_reader :name, :gvk, :gvr, :scope, :fields, :metadata,
                  :preserve_unknown_fields, :description

      def initialize(name = nil, **keywords)
        if name.is_a?(Hash)
          keywords = name.transform_keys(&:to_sym).merge(keywords)
          name = keywords.delete(:name)
        end

        name ||= keywords.delete(:name)

        api_version = keywords.delete(:api_version)
        gvk_option = keywords.delete(:gvk)
        gvr_option = keywords.delete(:gvr)
        group = keywords.delete(:group)
        version = keywords.delete(:version)
        kind = keywords.delete(:kind) || name
        if gvk_option
          gvk_option = GVK.parse(gvk_option) unless gvk_option.is_a?(GVK)
          group ||= gvk_option.group
          version ||= gvk_option.version
          kind ||= gvk_option.kind
        end
        if gvr_option
          gvr_option = GVR.parse(gvr_option) unless gvr_option.is_a?(GVR)
          group ||= gvr_option.group
          version ||= gvr_option.version
        end
        if (group.nil? || version.nil?) && api_version
          parsed_group, parsed_version = parse_api_version(api_version)
          group ||= parsed_group
          version ||= parsed_version
        end

        raise ArgumentError, "schema kind must be a non-empty String" if kind.nil? || kind.to_s.empty?
        raise ArgumentError, "schema version must be a non-empty String" if version.nil? || version.to_s.empty?

        @name = (name || kind).to_s.freeze
        @gvk = GVK.new(group || "", version.to_s, kind.to_s)
        resource = keywords.delete(:resource) || gvr_option&.resource || pluralize(@name)
        @gvr = GVR.new(@gvk.group, @gvk.version, resource.to_s)
        namespaced = keywords.delete(:namespaced)
        @scope = normalize_scope(keywords.delete(:scope) || (if namespaced.nil?
                                                               :namespaced
                                                             else
                                                               (namespaced ? :namespaced : :cluster)
                                                             end))
        @description = keywords.delete(:description)&.to_s&.freeze
        @preserve_unknown_fields = !!(keywords.delete(:preserve_unknown_fields) ||
                                      keywords.delete(:preserve_unknown) ||
                                      keywords.delete(:x_kubernetes_preserve_unknown_fields))

        required_names = Array(keywords.delete(:required)).map(&:to_s)
        raw_fields = keywords.delete(:fields) || keywords.delete(:properties)
        raw_spec = keywords.delete(:spec)
        raw_status = keywords.delete(:status)
        raw_fields = {} if raw_fields.nil?
        raise ArgumentError, "schema fields must be a Hash" unless raw_fields.respond_to?(:each_pair)

        field_map = normalize_fields(raw_fields, required_names)
        field_map["spec"] = build_section_field("spec", raw_spec) if raw_spec && !field_map.key?("spec")
        field_map["status"] = build_section_field("status", raw_status) if raw_status && !field_map.key?("status")
        duplicate_json_names = field_map.values.group_by(&:json_name).select { |_json_name, values| values.length > 1 }
        unless duplicate_json_names.empty?
          raise ArgumentError, "schema contains duplicate JSON field names: #{duplicate_json_names.keys.sort.join(", ")}"
        end

        @fields = DeepFreeze.call(field_map)
        @known_keys = field_map.values.flat_map { |field| [field.name, field.json_name, field.ruby_name] }
          .to_h { |key| [key, true] }.freeze
        @metadata = DeepFreeze.call(copy_value(keywords))
        freeze
      end

      def kind
        gvk.kind
      end

      alias schema_name name

      def field_names
        fields.keys
      end

      alias known_fields field_names

      def api_version
        gvk.api_version
      end

      alias group_version api_version

      alias identifier gvk

      def group
        gvk.group
      end

      def version
        gvk.version
      end

      def resource
        gvr.resource
      end

      def namespaced?
        scope == :namespaced
      end

      def cluster_scoped?
        scope == :cluster
      end

      def field(name)
        fields[name.to_s]
      end

      # Whether +key+ names one of this definition's fields in any spelling.
      def known_key?(key)
        @known_keys.key?(key)
      end

      def has_field?(name)
        fields.key?(name.to_s)
      end

      def required_fields
        fields.values.select(&:required?)
      end

      def spec_definition
        field = self.field("spec")
        nested_definition_for(field)
      end

      def status_definition
        field = self.field("status")
        nested_definition_for(field)
      end

      def value_class
        raise LoadError, "Rubernetes::Schema::ValueObject must be loaded before generating value classes" unless defined?(ValueObject)

        ValueObject.for(self)
      end

      def build(values = {}, **keywords)
        value_class.new(values, **keywords)
      end
      alias new build

      def defaulting
        Defaulting.new(self)
      end

      def validator
        Validator.new(self)
      end

      def diff
        Diff.new(self)
      end

      def to_h
        result = {
          name: name,
          group: group,
          version: version,
          kind: kind,
          api_version: gvk.api_version,
          resource: resource,
          scope: scope,
          fields: fields.transform_values(&:to_h),
          preserve_unknown_fields: preserve_unknown_fields
        }
        result[:description] = description if description
        result.merge!(metadata)
        DeepFreeze.call(result)
      end

      def ==(other)
        other.is_a?(Definition) && to_h == other.to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end

      private

      def parse_api_version(value)
        parts = value.to_s.split("/", 2)
        parts.length == 1 ? ["", parts[0]] : parts
      end

      def normalize_scope(value)
        normalized = value.to_s.downcase
        return :namespaced if %w[namespaced namespace].include?(normalized)
        return :cluster if %w[cluster clusterscoped cluster_scoped].include?(normalized)

        raise ArgumentError, "schema scope must be :namespaced or :cluster"
      end

      def normalize_fields(source, required_names = [])
        normalize_fields_with_required(source, required_names)
      end

      def normalize_fields_with_required(source, required_names)
        source.each_with_object({}) do |(key, value), result|
          result[key.to_s] = if value.is_a?(Field)
                               value
                             elsif value.is_a?(Hash)
                               options = value.transform_keys(&:to_sym)
                               option_keys = %i[type items of properties required nullable default enum one_of minimum maximum
                                                min max exclusive_minimum exclusive_maximum pattern preserve_unknown_fields
                                                preserve_unknown ruby_name json_name]
                               if options.keys.any? { |option| option_keys.include?(option) }
                                 options[:required] = true if required_names.include?(key.to_s)
                                 Field.new(options.merge(name: key.to_s))
                               elsif required_names.include?(key.to_s)
                                 Field.new(key.to_s, :object, properties: value, required: true)
                               else
                                 Field.new(key.to_s, :object, properties: value)
                               end
                             else
                               Field.new(key.to_s, value, required: required_names.include?(key.to_s))
                             end
        end
      end

      def build_section_field(name, source)
        nested_fields = source.is_a?(Definition) ? source.fields : normalize_fields(source)
        Field.new(name, :object, properties: nested_fields)
      end

      def nested_definition_for(field)
        return nil unless field
        return field.type if field.type.is_a?(Definition)
        return field.type.resolve if field.type.is_a?(Reference)
        return field.items if field.items.is_a?(Definition)
        return field.items.resolve if field.items.is_a?(Reference)
        return nil unless field.object?

        Definition.new(
          name: "#{kind}#{field.name.capitalize}",
          group: group,
          version: version,
          kind: "#{kind}#{field.name.capitalize}",
          resource: "#{resource}-#{field.name}",
          scope: scope,
          fields: field.properties,
          preserve_unknown_fields: field.preserve_unknown_fields
        )
      end

      def pluralize(value)
        return value.downcase if value.end_with?("s")
        return "#{value[0..-2].downcase}ies" if value.end_with?("y") && value.length > 1

        "#{value.downcase}s"
      end

      def copy_value(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, item), result| result[copy_value(key)] = copy_value(item) }
        when Array
          value.map { |item| copy_value(item) }
        else
          duplicate_value(value)
        end
      end

      def duplicate_value(value)
        value.dup
      rescue TypeError
        value
      end
    end

    GroupVersionKind = GVK
    GroupVersionResource = GVR
    SchemaDefinition = Definition
    FieldDefinition = Field
  end
end
