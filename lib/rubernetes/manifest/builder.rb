# frozen_string_literal: true

require "json"

require_relative "schema"
require_relative "workload"

module Rubernetes
  module Manifest
    # The receiver a Ruby manifest is evaluated against.  Every API kind is a
    # method (`deployment`, `config_map`, ...), generated from the schema
    # registry; inside its block every field of the kind is one too.
    class Builder
      RESERVED_METHODS = (
        BasicObject.instance_methods + Object.instance_methods + Kernel.instance_methods +
        %i[resource result object schema_definition append_resource]
      ).map(&:to_s).uniq.freeze
      OBJECT_META = "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"

      attr_reader :result

      def self.load(registry_path:, openapi_path:)
        registry = JSON.parse(File.binread(registry_path), max_nesting: 512)
        openapi = JSON.parse(File.binread(openapi_path), max_nesting: 512)
        new(registry: registry, definitions: openapi.fetch("definitions"))
      rescue JSON::ParserError, KeyError => error
        raise Error.new("cannot load generated manifest schema: #{error.message}"), cause: error
      end

      # Evaluates a manifest's source; an error is raised as an Error whose
      # message names the line of the manifest and what was meant, in one
      # line -- what the isolated worker can hand back.
      def evaluate(source, filename)
        instance_eval(source, filename, 1)
        result
      rescue Error, NameError, ArgumentError, TypeError, KeyError => error
        line = error.backtrace&.filter_map { |frame| frame[/\A#{Regexp.escape(filename)}:(\d+)/, 1] }&.first
        raise Error, "#{File.basename(filename)}#{":#{line}" if line}: #{describe(error)}"
      end

      def initialize(registry:, definitions:)
        @registry = registry
        @schema = Schema.new(definitions)
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

        object = {"apiVersion" => api_version, "kind" => kind,
                  "metadata" => @schema.object(OBJECT_META, metadata, "metadata").merge("name" => String(name))}
        object.fetch("metadata")["namespace"] = String(namespace) if namespace
        context = ObjectBuilder.new(object: object, schema_name: type.fetch("schema"), schema: @schema, helpers: self)
        Workload.install(context, object, type.fetch("schema"), @schema)
        context.instance_exec(&block) if block
        context.finish
        @result << deep_freeze(object)
        object
      end

      private

      # A method that does not exist is a field that does not exist: say
      # which type was being written and which of its fields is nearest.
      def describe(error)
        return error.message unless error.is_a?(NoMethodError) && error.receiver.is_a?(ObjectBuilder)

        candidates = error.receiver.singleton_class.included_modules.flat_map { |mod| mod.instance_methods(false) } +
                     error.receiver.singleton_methods(false)
        nearest = DidYouMean::SpellChecker.new(dictionary: candidates).correct(error.name).first
        "#{error.receiver.type_name} has no field or helper #{error.name.to_s.inspect}#{" (did you mean #{nearest.to_s.inspect}?)" if nearest}"
      end

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

      def underscore(value) = Schema.underscore(value)

      def validate_method_name!(method_name)
        return if method_name.match?(/\A[a-z_]\w*[!?=]?\z/) && !RESERVED_METHODS.include?(method_name)

        raise DuplicateMethod, "unsafe generated manifest method #{method_name.inspect}"
      end

      def split_api_version(api_version)
        api_version.include?("/") ? api_version.split("/", 2) : ["", api_version]
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

    # The receiver inside a resource's block, and inside the block of any
    # field that holds an object: one method per field of that type.
    class ObjectBuilder
      RESERVED_METHODS = (Builder::RESERVED_METHODS + %w[field set finish]).freeze
      MISSING = :__rubernetes_missing__

      def initialize(object:, schema_name:, schema:, helpers: nil, path: "")
        @object = object
        @schema_name = schema_name
        @schema = schema
        @helpers = helpers
        @path = path
        @finishers = []
        extend(build_field_methods(schema_name))

        install_spec_shortcuts
        share_helpers
      end

      def field(json_name, value = MISSING, **keywords, &)
        field_schema = @schema.definition(@schema_name).fetch("properties", {})[String(json_name)]
        raise UnknownField, "unknown field #{json_name.inspect} in #{@schema_name}" unless field_schema

        @object[String(json_name)] = build_value(String(json_name), field_schema, value, keywords, &)
      end

      def type_name = @schema_name.split(".").last

      # Work a helper left for the end of the resource's block, when
      # everything the block declares is known.
      def at_finish(&block) = @finishers << block

      def finish
        @finishers.each(&:call)
        nil
      end

      private

      def build_field_methods(schema_name)
        methods = Module.new
        @schema.definition(schema_name).fetch("properties", {}).keys.sort.each do |json_name|
          method_name = Schema.underscore(json_name)
          next if RESERVED_METHODS.include?(method_name)
          raise DuplicateMethod, "invalid field method #{method_name.inspect}" unless method_name.match?(/\A[a-z_]\w*\z/)
          raise DuplicateMethod, "field method collision #{method_name}" if methods.method_defined?(method_name.to_sym, false)

          methods.define_method(method_name) do |value = MISSING, **keywords, &block|
            field(json_name, value, **keywords, &block)
          end
        end
        methods
      end

      def install_spec_shortcuts
        spec_schema = @schema.definition(@schema_name).fetch("properties", {})["spec"]
        referenced = spec_schema && @schema.reference(spec_schema)
        return unless referenced

        methods = build_field_methods(referenced)
        collision_free = Module.new
        methods.instance_methods(false).each do |method_name|
          next if respond_to?(method_name)

          collision_free.define_method(method_name) do |value = MISSING, **keywords, &block|
            @object["spec"] ||= {}
            spec_builder = ObjectBuilder.new(object: @object.fetch("spec"), schema_name: referenced, schema: @schema, helpers: @helpers,
                                             path: "spec")
            spec_builder.public_send(method_name, value, **keywords, &block)
          end
        end
        extend(collision_free)
      end

      # A `def` at the top of the manifest file is a method of the top-level
      # builder; blocks run against other objects, so each of those methods
      # is given to them by name.  Nothing is looked up when a call misses.
      #
      # configmap("name") and secret("name") name an object to read from
      # (`env from:`, `volume from:`).  At the top level `secret` declares a
      # Secret; inside a block there is nothing to declare, so there it
      # refers to one -- unless the type has a field of that name.
      def share_helpers
        {configmap: "ConfigMap", secret: "Secret"}.each do |name, kind|
          define_singleton_method(name) { |object_name| Reference.new(kind, String(object_name)) } unless respond_to?(name)
        end
        return unless @helpers

        @helpers.singleton_methods(false).each do |name|
          # Inside this block the name already means the field: the call
          # would set it, silently, instead of reaching the method.
          raise Error, "the method `#{name}` defined in the manifest has the name of a field of #{type_name}; rename it" if respond_to?(name)

          helpers = @helpers
          define_singleton_method(name) { |*arguments, **keywords, &block| helpers.public_send(name, *arguments, **keywords, &block) }
        end
      end

      def build_value(json_name, field_schema, value, keywords, &block)
        unless keywords.empty?
          raise Error, "cannot combine positional and keyword values" unless value == MISSING

          value = keywords
        end
        path = [@path, json_name].reject(&:empty?).join(".")
        if block
          raise Error, "cannot combine a value and block" unless value == MISSING

          reference = @schema.reference(field_schema)
          raise Error, "field does not accept a nested object" unless reference

          # A block adds to what is there: `template do ... end` after
          # `container ...` describes the same template.
          value = @object[json_name].is_a?(Hash) ? @object[json_name] : {}
          ObjectBuilder.new(object: value, schema_name: reference, schema: @schema, helpers: @helpers, path: path).instance_exec(&block)
          return value
        end
        raise Error, "field value or block is required" if value == MISSING

        @schema.coerce(field_schema, value, path)
      end
    end
  end
end
