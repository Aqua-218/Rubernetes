# frozen_string_literal: true

module Rubernetes
  module Schema
    # Base error for schema registry failures.
    class RegistryError < StandardError; end

    class DuplicateGVKError < RegistryError
      attr_reader :gvk, :existing

      def initialize(gvk, existing = nil)
        @gvk = gvk
        @existing = existing
        suffix = existing ? " (already registered by #{existing.name})" : ""
        super("GVK #{gvk} is already registered#{suffix}")
      end
    end

    class DuplicateGVRError < RegistryError
      attr_reader :gvr, :existing

      def initialize(gvr, existing = nil)
        @gvr = gvr
        @existing = existing
        suffix = existing ? " (already registered by #{existing.name})" : ""
        super("GVR #{gvr} is already registered#{suffix}")
      end
    end

    AlreadyRegistered = DuplicateGVKError

    class UnknownSchemaError < RegistryError
      attr_reader :identifier

      def initialize(identifier)
        @identifier = identifier
        super("schema #{identifier.inspect} is not registered")
      end
    end

    # A thread-safe, one-to-one registry of schema definitions.
    class Registry
      include Enumerable

      def initialize(definitions = nil)
        @by_gvk = {}
        @by_gvr = {}
        @mutex = Mutex.new
        @sealed = false
        register_many(definitions) if definitions
      end

      def register(definition = nil, gvk: nil, gvr: nil, schema: nil, **keywords)
        if schema
          definition = schema
          definition = Definition.new(definition) unless definition.is_a?(Definition)
        end
        if definition.nil? && (gvk || gvr)
          gvk_object = gvk && normalize_gvk(gvk)
          gvr_object = gvr && normalize_gvr(gvr)
          group = (gvk_object || gvr_object).group
          version = (gvk_object || gvr_object).version
          kind = gvk_object&.kind || keywords[:kind]
          resource = gvr_object&.resource || keywords[:resource]
          kind ||= resource.to_s.delete_suffix("s").split(/[-_]/).map { |part| part[0].to_s.upcase + part[1..].to_s }.join
          attributes = keywords.merge(group: group, version: version)
          attributes[:kind] = kind if kind
          attributes[:resource] = resource if resource
          definition = Definition.new(**attributes)
        end
        definition ||= Definition.new(**keywords)
        definition = Definition.new(definition) if definition.is_a?(Hash)
        validate_definition!(definition)

        @mutex.synchronize do
          ensure_open!
          if (existing = @by_gvk[definition.gvk])
            raise DuplicateGVKError.new(definition.gvk, existing)
          end
          if (existing = @by_gvr[definition.gvr])
            raise DuplicateGVRError.new(definition.gvr, existing)
          end

          @by_gvk[definition.gvk] = definition
          @by_gvr[definition.gvr] = definition
        end
        definition
      end
      alias register! register

      # Registers all definitions atomically. No index is changed on failure.
      def register_many(definitions)
        items = definitions.respond_to?(:each) && !definitions.is_a?(Hash) ? definitions.to_a : [definitions]
        items.compact!
        items.map! { |item| item.is_a?(Definition) ? item : Definition.new(item) }
        items.each { |item| validate_definition!(item) }

        @mutex.synchronize do
          ensure_open!
          local_gvks = {}
          local_gvrs = {}
          items.each do |definition|
            raise DuplicateGVKError.new(definition.gvk, @by_gvk[definition.gvk]) if local_gvks.key?(definition.gvk) || @by_gvk.key?(definition.gvk)
            raise DuplicateGVRError.new(definition.gvr, @by_gvr[definition.gvr]) if local_gvrs.key?(definition.gvr) || @by_gvr.key?(definition.gvr)

            local_gvks[definition.gvk] = definition
            local_gvrs[definition.gvr] = definition
          end
          @by_gvk.merge!(local_gvks)
          @by_gvr.merge!(local_gvrs)
        end
        items.freeze
      end

      def fetch(identifier)
        found = find(identifier)
        return found if found

        raise UnknownSchemaError, identifier
      end

      def [](identifier)
        find(identifier)
      end

      def find(identifier)
        case identifier
        when Definition
          identifier
        when GVK
          @mutex.synchronize { @by_gvk[identifier] }
        when GVR
          @mutex.synchronize { @by_gvr[identifier] }
        when String, Symbol
          value = identifier.to_s
          @mutex.synchronize do
            @by_gvk[parse_gvk(value)] || @by_gvr[parse_gvr(value)]
          end
        end
      rescue ArgumentError
        nil
      end

      def fetch_gvk(identifier)
        gvk = identifier.is_a?(GVK) ? identifier : GVK.parse(identifier.to_s)
        @mutex.synchronize { @by_gvk.fetch(gvk) { raise UnknownSchemaError, gvk } }
      end

      def find_gvk(kind:, group: "", version: "v1")
        @mutex.synchronize { @by_gvk[GVK.new(group: group, version: version, kind: kind)] }
      end

      alias lookup_gvk find_gvk
      alias resource_for_gvk find_gvk

      def fetch_gvr(identifier)
        gvr = identifier.is_a?(GVR) ? identifier : GVR.parse(identifier.to_s)
        @mutex.synchronize { @by_gvr.fetch(gvr) { raise UnknownSchemaError, gvr } }
      end

      def find_gvr(resource:, group: "", version: "v1")
        @mutex.synchronize { @by_gvr[GVR.new(group: group, version: version, resource: resource)] }
      end

      alias lookup_gvr find_gvr
      alias resource_for_gvr find_gvr

      def by_gvk
        @mutex.synchronize { @by_gvk.dup.freeze }
      end

      def by_gvr
        @mutex.synchronize { @by_gvr.dup.freeze }
      end

      def definitions
        @mutex.synchronize { @by_gvk.values.sort_by { |definition| definition.gvk.to_s }.freeze }
      end

      alias resources definitions
      alias all definitions

      def each(&block)
        return enum_for(__method__) unless block

        definitions.each(&block)
      end

      def each_gvk(&block)
        return enum_for(__method__) unless block

        by_gvk.sort_by { |gvk, _| gvk.to_s }.each(&block)
      end

      def each_gvr(&block)
        return enum_for(__method__) unless block

        by_gvr.sort_by { |gvr, _| gvr.to_s }.each(&block)
      end

      def include?(identifier)
        !find(identifier).nil?
      end
      alias key? include?

      def size
        @mutex.synchronize { @by_gvk.size }
      end
      alias length size

      def empty?
        size.zero?
      end

      def sealed?
        @sealed
      end

      # Prevent later registration while retaining read access to this registry.
      def seal!
        @mutex.synchronize { @sealed = true }
        self
      end
      alias freeze! seal!

      def snapshot
        copy = self.class.new(definitions)
        copy.seal!
      end

      def to_h
        @mutex.synchronize do
          {
            gvk: @by_gvk.transform_keys(&:to_s),
            gvr: @by_gvr.transform_keys(&:to_s)
          }.each_value(&:freeze).freeze
        end
      end

      private

      def ensure_open!
        raise RegistryError, "schema registry is sealed and cannot be modified" if @sealed
      end

      def validate_definition!(definition)
        return if definition.is_a?(Definition)

        raise ArgumentError, "registry entries must be Rubernetes::Schema::Definition objects"
      end

      def parse_gvk(value)
        GVK.parse(value)
      end

      def parse_gvr(value)
        GVR.parse(value)
      end

      def normalize_gvk(value)
        value.is_a?(GVK) ? value : GVK.parse(value.to_s)
      end

      def normalize_gvr(value)
        value.is_a?(GVR) ? value : GVR.parse(value.to_s)
      end
    end
  end
end
