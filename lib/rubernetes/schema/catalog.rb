# frozen_string_literal: true

require "json"
require "pathname"

require_relative "definition"

module Rubernetes
  module Schema
    # Loads generated schema metadata without evaluating generated source.
    class Catalog
      SCHEMA_GVR = ::Rubernetes::Schema::GVR
      DEFAULT_ROOT = File.expand_path("../../../generated", __dir__).freeze
      DEFAULT_REGISTRY_PATH = "schema/registry.json"
      DEFAULT_OPENAPI_PATH = "openapi/v2.json"
      MAX_JSON_BYTES = 128 * 1024 * 1024

      class Error < StandardError; end
      class PathError < Error; end
      class InvalidJSONError < Error; end
      class InvalidCatalogError < Error; end
      class DuplicateGVKError < Error; end
      class DuplicateGVRError < Error; end
      class DuplicateTypeError < Error; end
      class MissingSchemaError < Error; end
      class MissingGVKError < Error; end
      class MissingGVRError < Error; end

      # Immutable generated type metadata indexed by every GVK it declares.
      class Type
        attr_reader :schema_name, :ruby_constant, :fields, :required,
                    :gvks, :patch_fields, :openapi_schema, :metadata

        def initialize(payload:, openapi_schema:)
          @schema_name = required_string(payload, "schema")
          @ruby_constant = required_string(payload, "ruby_constant")
          @fields = string_set(payload.fetch("fields", []), "fields")
          @required = string_set(payload.fetch("required", []), "required")
          @patch_fields = string_set(payload.fetch("patch_fields", @fields), "patch_fields")
          @gvks = normalize_gvks(payload.fetch("gvks") do
            raise InvalidCatalogError, "type is missing gvks"
          end)
          @openapi_schema = Catalog.deep_freeze(Catalog.send(:deep_copy, openapi_schema))
          @metadata = Catalog.deep_freeze(Catalog.send(:deep_copy, payload.reject do |key, _value|
            %w[schema ruby_constant fields required patch_fields gvks].include?(key.to_s)
          end))
          freeze
        end

        def name
          schema_name
        end

        def schema
          schema_name
        end

        alias openapi openapi_schema

        def gvk
          gvks.first
        end

        def field_set
          fields
        end

        def patch_set
          patch_fields
        end

        def required?(field)
          required.include?(field.to_s)
        end

        def to_h
          result = {
            "schema" => schema_name,
            "ruby_constant" => ruby_constant,
            "fields" => fields,
            "required" => required,
            "patch_fields" => patch_fields,
            "gvks" => gvks.map(&:to_h)
          }
          result.merge!(metadata)
          Catalog.deep_freeze(result)
        end

        private

        def required_string(payload, key)
          value = payload.fetch(key)
          raise InvalidCatalogError, "type #{key} must be a non-empty String" unless value.is_a?(String) && !value.empty?

          value.dup.freeze
        rescue KeyError
          raise InvalidCatalogError, "type is missing #{key}"
        end

        def string_set(value, key)
          unless value.is_a?(Array) && value.all? { |item| item.is_a?(String) && !item.empty? }
            raise InvalidCatalogError, "type #{key} must be an array of non-empty Strings"
          end

          values = value.map(&:dup)
          raise InvalidCatalogError, "type #{key} contains duplicate fields" if values.uniq.length != values.length

          values.map(&:freeze).freeze
        end

        def normalize_gvks(value)
          raise InvalidCatalogError, "type gvks must be an array" unless value.is_a?(Array)

          gvks = value.map do |entry|
            if entry.is_a?(GVK)
              entry
            elsif entry.is_a?(Hash)
              group = entry.key?("group") ? entry["group"] : entry.fetch(:group, "")
              version = entry.key?("version") ? entry["version"] : entry.fetch(:version)
              kind = entry.key?("kind") ? entry["kind"] : entry.fetch(:kind)
              GVK.new(group: group, version: version, kind: kind)
            else
              GVK.parse(entry.to_s)
            end
          rescue KeyError, ArgumentError => error
            raise InvalidCatalogError, "invalid type GVK: #{error.message}"
          end
          raise DuplicateGVKError, "type contains duplicate GVK registrations" if gvks.uniq.length != gvks.length

          gvks.freeze
        end
      end

      # Immutable registration for every covered GVK. Some protocol-only
      # entries intentionally have no generated schema type.
      class GVKEntry
        attr_reader :gvk, :group, :version, :kind, :identifier, :schema_name,
                    :type, :metadata

        def initialize(payload:, type: nil)
          @group = required_string(payload, "group", allow_empty: true)
          @version = required_string(payload, "version")
          @kind = required_string(payload, "kind")
          @gvk = GVK.new(group: group, version: version, kind: kind)
          expected_identifier = source_identifier
          supplied_identifier = payload["identifier"]
          if supplied_identifier && supplied_identifier != expected_identifier
            raise InvalidCatalogError, "GVK identifier #{supplied_identifier.inspect} does not match #{expected_identifier.inspect}"
          end

          @identifier = (supplied_identifier || expected_identifier).dup.freeze
          raw_schema = payload["schema"]
          unless raw_schema.nil? || (raw_schema.is_a?(String) && !raw_schema.empty?)
            raise InvalidCatalogError, "GVK schema must be a non-empty String or null"
          end

          @schema_name = raw_schema&.dup&.freeze
          @type = type
          @metadata = Catalog.deep_freeze(Catalog.send(:deep_copy, payload.reject do |key, _value|
            %w[group version kind identifier schema].include?(key.to_s)
          end))
          freeze
        end

        def api_version
          gvk.api_version
        end

        alias group_version api_version

        def to_s
          gvk.to_s
        end

        def type_backed?
          !type.nil?
        end

        def protocol_only?
          type.nil?
        end

        def schema
          type
        end

        def name
          schema_name || identifier
        end

        def gvks
          [gvk].freeze
        end

        def openapi_schema
          type&.openapi_schema
        end

        def fields
          type ? type.fields : [].freeze
        end

        def patch_fields
          type ? type.patch_fields : [].freeze
        end

        def field_set
          fields
        end

        def patch_set
          patch_fields
        end

        def ruby_constant
          type&.ruby_constant
        end

        def required
          type ? type.required : [].freeze
        end

        def required?(field)
          required.include?(field.to_s)
        end

        def to_h
          result = {
            "group" => group,
            "version" => version,
            "kind" => kind,
            "identifier" => identifier,
            "schema" => schema_name
          }
          result.merge!(metadata)
          Catalog.deep_freeze(result)
        end

        def ==(other)
          other.respond_to?(:gvk) && other.gvk == gvk
        end
        alias eql? ==

        def hash
          gvk.hash
        end

        private

        def required_string(payload, key, allow_empty: false)
          value = payload.fetch(key)
          unless value.is_a?(String) && (allow_empty || !value.empty?)
            qualifier = allow_empty ? "String" : "non-empty String"
            raise InvalidCatalogError, "GVK #{key} must be a #{qualifier}"
          end
          value.dup.freeze
        rescue KeyError
          raise InvalidCatalogError, "GVK is missing #{key}"
        end

        def source_identifier
          prefix = group.empty? ? "core" : group
          "#{prefix}/#{version}/#{kind}"
        end
      end

      # Immutable entry for every served GVR, including subresources and
      # discovery-only endpoints that do not have a primary Resource record.
      class GVR
        attr_reader :gvr, :group, :version, :resource, :identifier, :kind,
                    :scope, :verbs, :primary_resource, :subresource_metadata,
                    :schema_name, :type, :metadata

        def initialize(payload:, primary_resource: nil, subresource_metadata: nil)
          @group = required_string(payload, "group", allow_empty: true)
          @version = required_string(payload, "version")
          @resource = required_string(payload, "resource")
          @gvr = SCHEMA_GVR.new(group: group, version: version, resource: resource)
          expected_identifier = source_identifier
          supplied_identifier = payload["identifier"]
          if supplied_identifier && supplied_identifier != expected_identifier
            raise InvalidCatalogError, "GVR identifier #{supplied_identifier.inspect} does not match #{expected_identifier.inspect}"
          end

          @identifier = (supplied_identifier || expected_identifier).dup.freeze
          @primary_resource = primary_resource
          @subresource_metadata = (Catalog.deep_freeze(Catalog.send(:deep_copy, subresource_metadata)) if subresource_metadata)
          @kind = optional_string(subresource_metadata, "kind") || primary_resource&.kind
          @scope = primary_resource&.scope
          @verbs = normalize_verbs(subresource_metadata, primary_resource)
          @schema_name = primary_resource&.schema_name
          @type = primary_resource&.type
          @metadata = Catalog.deep_freeze(Catalog.send(:deep_copy, payload.reject do |key, _value|
            %w[group version resource identifier].include?(key.to_s)
          end))
          freeze
        end

        def api_version
          gvr.api_version
        end

        alias group_version api_version

        def gvk
          return nil unless kind

          GVK.new(group: group, version: version, kind: kind)
        end

        def to_s
          gvr.to_s
        end

        def primary?
          !primary_resource.nil? && resource == primary_resource.resource
        end

        def subresource?
          resource.include?("/")
        end

        alias subresource subresource_metadata

        alias parent_resource primary_resource

        def namespaced?
          scope == :namespaced
        end

        def cluster_scoped?
          scope == :cluster
        end

        def fields
          type ? type.fields : [].freeze
        end

        def patch_fields
          type ? type.patch_fields : [].freeze
        end

        def field_set
          fields
        end

        def patch_set
          patch_fields
        end

        def schema
          type
        end

        def openapi_schema
          type&.openapi_schema
        end

        def merge_keys
          primary_resource ? primary_resource.merge_keys : {}.freeze
        end

        def patch_strategy
          primary_resource&.patch_strategy
        end

        def field_paths
          primary_resource ? primary_resource.field_paths : [].freeze
        end

        def patch_strategies
          primary_resource ? primary_resource.patch_strategies : {}.freeze
        end

        def subresources
          primary_resource ? primary_resource.subresources : [].freeze
        end

        def short_names
          primary_resource ? primary_resource.short_names : [].freeze
        end

        def categories
          primary_resource ? primary_resource.categories : [].freeze
        end

        def singular
          primary_resource&.singular
        end

        def list_kind
          primary_resource&.list_kind
        end

        def to_h
          result = {
            "group" => group,
            "version" => version,
            "resource" => resource,
            "identifier" => identifier
          }
          result["kind"] = kind if kind
          result["scope"] = scope if scope
          result["verbs"] = verbs
          result["schema"] = schema_name if schema_name
          result.merge!(metadata)
          Catalog.deep_freeze(result)
        end

        def ==(other)
          other.respond_to?(:gvr) && other.gvr == gvr
        end
        alias eql? ==

        def hash
          gvr.hash
        end

        private

        def required_string(payload, key, allow_empty: false)
          value = payload.fetch(key)
          unless value.is_a?(String) && (allow_empty || !value.empty?)
            qualifier = allow_empty ? "String" : "non-empty String"
            raise InvalidCatalogError, "GVR #{key} must be a #{qualifier}"
          end
          value.dup.freeze
        rescue KeyError
          raise InvalidCatalogError, "GVR is missing #{key}"
        end

        def optional_string(payload, key)
          return nil unless payload

          value = payload[key]
          return nil if value.nil?
          return value.dup.freeze if value.is_a?(String) && !value.empty?

          raise InvalidCatalogError, "GVR #{key} must be a non-empty String"
        end

        def normalize_verbs(subresource, primary)
          return primary ? primary.verbs : [].freeze if subresource.nil? || !subresource.key?("verbs")

          value = subresource.fetch("verbs")
          unless value.is_a?(Array) && value.all? { |verb| verb.is_a?(String) && !verb.empty? }
            raise InvalidCatalogError, "GVR verbs must be an array of non-empty Strings"
          end

          duplicate = value.length != value.uniq.length
          raise InvalidCatalogError, "GVR verbs contain duplicate values" if duplicate

          value.map(&:dup).map(&:freeze).freeze
        end

        def source_identifier
          prefix = group.empty? ? "core" : group
          "#{prefix}/#{version}/#{resource}"
        end
      end

      # Immutable generated REST resource metadata indexed by every GVR.
      class Resource
        attr_reader :group, :version, :resource, :kind, :scope, :verbs,
                    :short_names, :categories, :singular, :list_kind,
                    :merge_keys, :patch_strategy, :field_paths,
                    :patch_strategies, :subresources, :schema_name, :type,
                    :metadata

        def initialize(payload:, type:)
          @group = required_string(payload, "group", allow_empty: true)
          @version = required_string(payload, "version")
          @resource = required_string(payload, "resource")
          @kind = required_string(payload, "kind")
          @scope = normalize_scope(payload.fetch("scope", :cluster))
          @verbs = string_set(payload.fetch("verbs", []), "verbs")
          @short_names = string_set(payload.fetch("short_names", payload.fetch("shortNames", [])), "short_names")
          @categories = string_set(payload.fetch("categories", []), "categories")
          @singular = (payload["singular"] || payload["singular_name"] || payload["singularName"] || "").to_s.freeze
          @list_kind = (payload["list_kind"] || payload["listKind"] || "#{kind}List").to_s.freeze
          @merge_keys = normalize_merge_keys(payload.fetch("merge_keys", payload.fetch("mergeKeys", {})))
          raw_patch_strategy = payload["patch_strategy"] || payload["patchStrategy"]
          @patch_strategy = normalize_patch_strategy(raw_patch_strategy)
          @field_paths = string_set(payload.fetch("field_paths", payload.fetch("fieldPaths", [])), "field_paths")
          @patch_strategies = normalize_string_map(
            payload.fetch("patch_strategies", payload.fetch("patchStrategies", {})), "patch_strategies"
          )
          @subresources = normalize_subresources(payload.fetch("subresources", []))
          @type = type
          @schema_name = type.schema_name
          @metadata = Catalog.deep_freeze(Catalog.send(:deep_copy, payload.reject do |key, _value|
            %w[group version resource kind scope verbs short_names shortNames categories singular singular_name
               singularName list_kind listKind merge_keys mergeKeys patch_strategy patchStrategy field_paths fieldPaths
               patch_strategies patchStrategies subresources schema].include?(key.to_s)
          end))
          freeze
        end

        def gvr
          SCHEMA_GVR.new(group: group, version: version, resource: resource)
        end

        def gvk
          GVK.new(group: group, version: version, kind: kind)
        end

        def api_version
          gvr.api_version
        end

        def group_version
          api_version
        end

        def namespaced?
          scope == :namespaced
        end

        def cluster_scoped?
          !namespaced?
        end

        def fields
          type.fields
        end

        def patch_fields
          type.patch_fields
        end

        def field_set
          fields
        end

        def patch_set
          patch_fields
        end

        def schema
          type
        end

        def openapi_schema
          type.openapi_schema
        end

        alias openapi openapi_schema

        def to_h
          result = {
            "group" => group,
            "version" => version,
            "resource" => resource,
            "kind" => kind,
            "scope" => scope,
            "verbs" => verbs,
            "short_names" => short_names,
            "categories" => categories,
            "singular" => singular,
            "list_kind" => list_kind,
            "merge_keys" => merge_keys,
            "field_paths" => field_paths,
            "patch_strategies" => patch_strategies,
            "subresources" => subresources,
            "schema" => schema_name
          }
          result["patch_strategy"] = patch_strategy if patch_strategy
          result.merge!(metadata)
          Catalog.deep_freeze(result)
        end

        private

        def required_string(payload, key, allow_empty: false)
          value = payload.fetch(key)
          unless value.is_a?(String) && (allow_empty || !value.empty?)
            raise InvalidCatalogError, "resource #{key} must be a #{allow_empty ? "String" : "non-empty String"}"
          end

          value.dup.freeze
        rescue KeyError
          raise InvalidCatalogError, "resource is missing #{key}"
        end

        def normalize_scope(value)
          normalized = value.to_s.downcase
          return :namespaced if %w[namespaced namespace].include?(normalized)
          return :cluster if %w[cluster clusterscoped cluster_scoped].include?(normalized)

          raise InvalidCatalogError, "resource scope must be Namespaced or Cluster"
        end

        def string_set(value, key)
          unless value.is_a?(Array) && value.all? { |item| item.is_a?(String) && !item.empty? }
            raise InvalidCatalogError, "resource #{key} must be an array of non-empty Strings"
          end

          values = value.map(&:dup)
          raise InvalidCatalogError, "resource #{key} contains duplicate values" if values.uniq.length != values.length

          values.map(&:freeze).freeze
        end

        def normalize_merge_keys(value)
          raise InvalidCatalogError, "resource merge_keys must be an object" unless value.respond_to?(:each_pair)

          normalized = value.each_with_object({}) do |(key, child), result|
            unless key.is_a?(String) && !key.empty? && child.is_a?(String) && !child.empty?
              raise InvalidCatalogError, "resource merge_keys must map non-empty Strings to non-empty Strings"
            end

            result[key.dup] = child.dup
          end
          Catalog.deep_freeze(normalized)
        end

        def normalize_patch_strategy(value)
          return nil if value.nil?
          return value.to_sym if value.is_a?(String) || value.is_a?(Symbol)

          raise InvalidCatalogError, "resource patch_strategy must be a String or Symbol"
        end

        def normalize_string_map(value, key)
          raise InvalidCatalogError, "resource #{key} must be an object" unless value.respond_to?(:each_pair)

          normalized = value.each_with_object({}) do |(child_key, child_value), result|
            unless child_key.is_a?(String) && !child_key.empty? && child_value.is_a?(String) && !child_value.empty?
              raise InvalidCatalogError, "resource #{key} must map non-empty Strings to non-empty Strings"
            end

            result[child_key.dup] = child_value.dup
          end
          Catalog.deep_freeze(normalized)
        end

        def normalize_subresources(value)
          unless value.is_a?(Array) && value.all? { |entry| entry.is_a?(Hash) }
            raise InvalidCatalogError, "resource subresources must be an array of objects"
          end

          Catalog.deep_freeze(Catalog.send(:deep_copy, value))
        end
      end

      attr_reader :root, :registry_path, :openapi_path, :types, :resources, :gvks, :gvrs

      def self.load(registry_path = nil, openapi_path = nil, **options)
        options = options.dup
        options[:registry_path] ||= registry_path if registry_path
        options[:openapi_path] ||= openapi_path if openapi_path
        new(**options)
      end

      def self.default(registry_path = nil, openapi_path = nil, **)
        load(registry_path, openapi_path, **)
      end

      def initialize(root: nil, registry_path: nil, openapi_path: nil)
        supplied_paths = registry_path || openapi_path
        @root = resolve_root(root, supplied_paths)
        @registry_path = resolve_input_path(registry_path || DEFAULT_REGISTRY_PATH, "registry")
        @openapi_path = resolve_input_path(openapi_path || DEFAULT_OPENAPI_PATH, "OpenAPI")
        registry = read_json(@registry_path, "registry")
        openapi = read_json(@openapi_path, "OpenAPI")
        build_indexes(registry, openapi)
        freeze
      end

      def type(identifier = nil, group: nil, version: nil, kind: nil, schema_name: nil, gvk: nil, gvr: nil)
        return type_for_gvk_entry(find_gvk(gvk)) if gvk
        return find_gvr(gvr)&.type if gvr
        return type_for_gvk_entry(find_gvk(group: group, version: version, kind: kind)) if group || version || kind
        return @types_by_schema.fetch(schema_name.to_s) if schema_name
        return identifier if identifier.is_a?(Type)
        return identifier.type || identifier if identifier.is_a?(GVKEntry)
        return identifier.type if identifier.is_a?(Resource)
        return type_for_gvk_entry(find_gvk(identifier)) if identifier.is_a?(GVK)
        return identifier.type if identifier.is_a?(GVR)
        return find_gvr(identifier)&.type if identifier.is_a?(SCHEMA_GVR)
        return type_for_gvk_entry(find_gvk(identifier)) if identifier.is_a?(Hash)

        value = identifier.to_s
        return @types_by_schema[value] if @types_by_schema.key?(value)
        return @types_by_ruby_constant[value] if @types_by_ruby_constant.key?(value)

        type_for_gvk_entry(find_gvk(value))
      rescue KeyError
        nil
      end

      def find_gvk(identifier = nil, *parts, group: nil, version: nil, kind: nil, gvk: nil)
        key = normalize_gvk_lookup(identifier, parts, group, version, kind, gvk)
        @gvk_entries_by_gvk[key]
      rescue ArgumentError, KeyError, IndexError
        nil
      end

      def find_gvk_entry(identifier = nil, *parts, group: nil, version: nil, kind: nil, gvk: nil)
        find_gvk(identifier, *parts, group: group, version: version, kind: kind, gvk: gvk)
      end

      def find_gvr(identifier = nil, *parts, group: nil, version: nil, resource: nil, gvr: nil)
        identifier = gvr if gvr
        gvr = if !parts.empty?
                SCHEMA_GVR.new(group: identifier, version: parts.fetch(0), resource: parts.fetch(1))
              elsif identifier.is_a?(GVR)
                identifier.gvr
              elsif identifier.is_a?(SCHEMA_GVR)
                identifier
              elsif identifier.is_a?(Hash)
                SCHEMA_GVR.new(identifier)
              elsif group || version || resource
                SCHEMA_GVR.new(group: group || "", version: version, resource: resource)
              else
                parse_gvr(identifier)
              end
        @served_gvrs_by_gvr[gvr]
      rescue ArgumentError, KeyError, IndexError
        nil
      end

      def resource(identifier = nil, *parts, group: nil, version: nil, resource: nil, gvr: nil)
        entry = find_gvr(identifier, *parts, group: group, version: version, resource: resource, gvr: gvr)
        entry&.primary_resource || entry
      end

      def schema_name(identifier = nil, **options)
        candidate = if options.empty?
                      identifier
                    elsif options.key?(:schema_name)
                      options.fetch(:schema_name)
                    elsif options.key?(:resource) || options.key?(:gvr)
                      find_gvr(**options)
                    else
                      find_gvk(**options)
                    end
        entry = resolve_catalog_entry(candidate)
        entry&.schema_name
      end

      def openapi_schema(identifier = nil, **options)
        candidate = if options.empty?
                      identifier
                    elsif options.key?(:resource) || options.key?(:gvr)
                      find_gvr(**options)
                    else
                      type(identifier, **options)
                    end
        entry = resolve_catalog_entry(candidate)
        entry&.openapi_schema
      end

      def field_set(identifier = nil, **options)
        entry = resolve_entry(identifier, options)
        entry&.fields
      end

      def patch_set(identifier = nil, **options)
        entry = resolve_entry(identifier, options)
        entry&.patch_fields
      end

      def type_count
        types.length
      end

      def resource_count
        resources.length
      end

      def gvk_count
        gvks.length
      end

      def gvr_count
        gvrs.length
      end

      def route_gvr_count
        resources.length + resources.sum { |entry| entry.subresources.length }
      end

      def known_gvks
        @gvk_entries_by_gvk.keys.freeze
      end

      def known_gvrs
        @served_gvrs_by_gvr.keys.freeze
      end

      def type_index
        @types_by_gvk.dup.freeze
      end

      def gvk_index
        @gvk_entries_by_gvk.dup.freeze
      end

      def resource_index
        @resources_by_gvr.dup.freeze
      end

      def gvr_index
        @served_gvrs_by_gvr.dup.freeze
      end

      def to_h
        {
          "types" => types.map(&:to_h),
          "gvks" => gvks.map(&:to_h),
          "resources" => resources.map(&:to_h),
          "gvrs" => gvrs.map(&:to_h)
        }.then { |value| self.class.deep_freeze(value) }
      end

      class << self
        def deep_freeze(value, seen = {})
          return value if value.nil? || value.is_a?(Numeric) || value == true || value == false || value.is_a?(Symbol)
          return value if seen.key?(value.object_id)

          seen[value.object_id] = true
          case value
          when Hash
            value.each do |key, child|
              deep_freeze(key, seen)
              deep_freeze(child, seen)
            end
          when Array
            value.each { |child| deep_freeze(child, seen) }
          end
          value.freeze
        end

        private

        def deep_copy(value, seen = {})
          case value
          when Hash
            return seen.fetch(value.object_id) if seen.key?(value.object_id)

            copy = {}
            seen[value.object_id] = copy
            value.each { |key, child| copy[deep_copy(key, seen)] = deep_copy(child, seen) }
            copy
          when Array
            return seen.fetch(value.object_id) if seen.key?(value.object_id)

            copy = []
            seen[value.object_id] = copy
            value.each { |child| copy << deep_copy(child, seen) }
            copy
          when String
            value.dup
          else
            value
          end
        end
      end

      private

      def resolve_root(root, supplied_paths)
        if root.nil? && supplied_paths.nil?
          begin
            return Pathname.new(DEFAULT_ROOT).realpath
          rescue SystemCallError => error
            raise PathError, "default catalog root is not accessible: #{DEFAULT_ROOT}: #{error.message}"
          end
        end
        return nil if root.nil?

        root_path = safe_pathname(root, "root")
        reject_path_traversal!(root_path.to_s, "root")
        begin
          real = root_path.expand_path.realpath
        rescue SystemCallError => error
          raise PathError, "catalog root is not accessible: #{root}: #{error.message}"
        end
        raise PathError, "catalog root must be a directory: #{real}" unless real.directory?

        real
      end

      def resolve_input_path(input, label)
        path = safe_pathname(input, label)
        reject_path_traversal!(path.to_s, label)
        candidate = if @root
                      path.absolute? ? path : @root.join(path)
                    else
                      raise PathError, "#{label} path must be absolute when root is omitted" unless path.absolute?

                      path
                    end
        raise PathError, "#{label} path escapes catalog root: #{input.inspect}" if @root && !within_root?(candidate)

        begin
          real = candidate.expand_path.realpath
        rescue SystemCallError => error
          raise PathError, "#{label} file is not accessible: #{candidate}: #{error.message}"
        end
        raise PathError, "#{label} file escapes catalog root through a symlink: #{input.inspect}" if @root && !within_root?(real)
        raise PathError, "#{label} path is not a regular file: #{real}" unless real.file?

        real
      end

      def reject_path_traversal!(value, label)
        raise PathError, "#{label} path contains a NUL byte" if value.include?("\0")

        components = value.tr("\\", "/").split("/")
        raise PathError, "#{label} path contains a parent traversal component" if components.include?("..")
      end

      def safe_pathname(input, label)
        Pathname.new(input.to_s)
      rescue ArgumentError => error
        raise PathError, "#{label} path is invalid: #{error.message}"
      end

      def within_root?(path)
        root_string = @root.to_s.end_with?(File::SEPARATOR) ? @root.to_s : "#{@root}#{File::SEPARATOR}"
        path_string = Pathname.new(path).expand_path.to_s
        path_string == @root.to_s || path_string.start_with?(root_string)
      end

      def read_json(path, label)
        size = File.size(path)
        raise InvalidJSONError, "#{label} file exceeds #{MAX_JSON_BYTES} bytes: #{path}" if size > MAX_JSON_BYTES

        JSON.parse(File.binread(path), max_nesting: 512)
      rescue JSON::ParserError => error
        raise InvalidJSONError, "invalid #{label} JSON #{path}: #{error.message}"
      rescue SystemCallError => error
        raise PathError, "cannot read #{label} file #{path}: #{error.message}"
      end

      def build_indexes(registry, openapi)
        raise InvalidCatalogError, "registry root must be a JSON object" unless registry.is_a?(Hash)
        raise InvalidCatalogError, "OpenAPI root must be a JSON object" unless openapi.is_a?(Hash)

        definitions = openapi.fetch("definitions") { raise InvalidCatalogError, "OpenAPI document is missing definitions" }
        raise InvalidCatalogError, "OpenAPI definitions must be a JSON object" unless definitions.is_a?(Hash)

        raw_types = registry.fetch("types") { raise InvalidCatalogError, "registry is missing types" }
        raw_resources = registry.fetch("resources") { raise InvalidCatalogError, "registry is missing resources" }
        raise InvalidCatalogError, "registry types and resources must be arrays" unless raw_types.is_a?(Array) && raw_resources.is_a?(Array)

        @raw_registry = self.class.deep_freeze(self.class.send(:deep_copy, registry))
        @raw_openapi = self.class.deep_freeze(self.class.send(:deep_copy, openapi))
        @types_by_schema = {}
        @types_by_ruby_constant = {}
        @types_by_gvk = {}
        raw_types.each do |payload|
          raise InvalidCatalogError, "registry type entries must be JSON objects" unless payload.is_a?(Hash)

          schema_name = payload.fetch("schema") { raise InvalidCatalogError, "type is missing schema" }
          raise DuplicateTypeError, "duplicate schema type #{schema_name.inspect}" if @types_by_schema.key?(schema_name)
          raise MissingSchemaError, "OpenAPI definition is missing for schema #{schema_name.inspect}" unless definitions.key?(schema_name)

          openapi_schema = definitions.fetch(schema_name)
          raise InvalidCatalogError, "OpenAPI definition for #{schema_name.inspect} must be an object" unless openapi_schema.is_a?(Hash)

          entry = Type.new(payload: payload, openapi_schema: openapi_schema)
          if @types_by_ruby_constant.key?(entry.ruby_constant)
            raise DuplicateTypeError, "duplicate Ruby constant #{entry.ruby_constant.inspect}"
          end

          @types_by_schema[entry.schema_name] = entry
          @types_by_ruby_constant[entry.ruby_constant] = entry
          entry.gvks.each do |gvk|
            raise DuplicateGVKError, "duplicate GVK registration #{gvk}" if @types_by_gvk.key?(gvk)

            @types_by_gvk[gvk] = entry
          end
        end

        raw_gvks = registry.key?("gvks") ? registry.fetch("gvks") : derived_gvk_payloads
        build_gvk_entries(raw_gvks)

        @resources_by_gvr = {}
        @subresources_by_gvr = {}
        raw_resources.each do |payload|
          raise InvalidCatalogError, "registry resource entries must be JSON objects" unless payload.is_a?(Hash)

          resource_gvr = resource_gvr(payload)
          if @resources_by_gvr.key?(resource_gvr) || @subresources_by_gvr.key?(resource_gvr)
            raise DuplicateGVRError, "duplicate GVR registration #{resource_gvr}"
          end

          entry_type = type_for_resource(payload)
          entry = Resource.new(payload: payload, type: entry_type)
          @resources_by_gvr[resource_gvr] = entry
          index_subresources(payload, entry)
        end
        @types = @types_by_schema.values.sort_by(&:schema_name).freeze
        @resources = @resources_by_gvr.values.sort_by { |entry| entry.gvr.to_s }.freeze
        raw_gvrs = registry.key?("gvrs") ? registry.fetch("gvrs") : derived_gvr_payloads
        build_served_gvrs(raw_gvrs)
        @types_by_schema.freeze
        @types_by_ruby_constant.freeze
        @types_by_gvk.freeze
        @gvk_entries_by_gvk.freeze
        @resources_by_gvr.freeze
        @subresources_by_gvr.freeze
      end

      def derived_gvk_payloads
        @types_by_gvk.map do |gvk, type|
          {
            "group" => gvk.group,
            "version" => gvk.version,
            "kind" => gvk.kind,
            "identifier" => source_gvk_identifier(gvk),
            "schema" => type.schema_name
          }
        end
      end

      def build_gvk_entries(raw_gvks)
        raise InvalidCatalogError, "registry gvks must be an array" unless raw_gvks.is_a?(Array)

        @gvk_entries_by_gvk = {}
        raw_gvks.each do |payload|
          raise InvalidCatalogError, "registry GVK entries must be JSON objects" unless payload.is_a?(Hash)

          key = covered_gvk(payload)
          raise DuplicateGVKError, "duplicate covered GVK registration #{key}" if @gvk_entries_by_gvk.key?(key)

          schema_name = payload["schema"]
          type = schema_name && @types_by_schema[schema_name]
          raise MissingSchemaError, "registry type is missing for covered GVK schema #{schema_name.inspect}" if schema_name && !type

          expected_type = @types_by_gvk[key]
          if expected_type && expected_type != type
            raise MissingSchemaError, "covered GVK #{key} must reference schema #{expected_type.schema_name.inspect}"
          end

          @gvk_entries_by_gvk[key] = GVKEntry.new(payload: payload, type: type)
        end
        missing = @types_by_gvk.keys - @gvk_entries_by_gvk.keys
        raise MissingGVKError, "registry is missing covered GVKs: #{missing.map(&:to_s).sort.join(", ")}" unless missing.empty?

        @gvks = @gvk_entries_by_gvk.values.sort_by(&:to_s).freeze
      end

      def covered_gvk(payload)
        GVK.new(
          group: payload.fetch("group", ""),
          version: payload.fetch("version"),
          kind: payload.fetch("kind")
        )
      rescue KeyError, ArgumentError => error
        raise InvalidCatalogError, "invalid covered GVK: #{error.message}"
      end

      def source_gvk_identifier(gvk)
        prefix = gvk.group.empty? ? "core" : gvk.group
        "#{prefix}/#{gvk.version}/#{gvk.kind}"
      end

      def resource_gvr(payload)
        SCHEMA_GVR.new(group: payload.fetch("group", ""), version: payload.fetch("version"), resource: payload.fetch("resource"))
      rescue KeyError, ArgumentError => error
        raise InvalidCatalogError, "invalid resource GVR: #{error.message}"
      end

      def index_subresources(payload, primary_resource)
        raw_subresources = payload.fetch("subresources", [])
        raise InvalidCatalogError, "resource subresources must be an array" unless raw_subresources.is_a?(Array)

        raw_subresources.each do |subresource|
          raise InvalidCatalogError, "resource subresource entries must be JSON objects" unless subresource.is_a?(Hash)

          child = subresource["resource"]
          unless child.is_a?(String) && !child.empty? && !child.include?("/")
            raise InvalidCatalogError, "resource subresource must be a non-empty path component"
          end

          full_resource = "#{primary_resource.resource}/#{child}"
          key = SCHEMA_GVR.new(
            group: primary_resource.group,
            version: primary_resource.version,
            resource: full_resource
          )
          if @subresources_by_gvr.key?(key) || @resources_by_gvr.key?(key)
            raise DuplicateGVRError, "duplicate served GVR registration #{key}"
          end

          @subresources_by_gvr[key] = {
            "primary_resource" => primary_resource,
            "metadata" => self.class.deep_freeze(self.class.send(:deep_copy, subresource))
          }.freeze
        end
      end

      def derived_gvr_payloads
        expected_gvrs.map do |gvr|
          {
            "group" => gvr.group,
            "version" => gvr.version,
            "resource" => gvr.resource,
            "identifier" => source_identifier(gvr)
          }
        end
      end

      def expected_gvrs
        (@resources_by_gvr.keys + @subresources_by_gvr.keys).uniq
      end

      def build_served_gvrs(raw_gvrs)
        raise InvalidCatalogError, "registry gvrs must be an array" unless raw_gvrs.is_a?(Array)

        @served_gvrs_by_gvr = {}
        raw_gvrs.each do |payload|
          raise InvalidCatalogError, "registry GVR entries must be JSON objects" unless payload.is_a?(Hash)

          key = served_gvr(payload)
          raise DuplicateGVRError, "duplicate served GVR registration #{key}" if @served_gvrs_by_gvr.key?(key)

          subresource = @subresources_by_gvr[key]
          primary_resource = @resources_by_gvr[key] || subresource&.fetch("primary_resource")
          @served_gvrs_by_gvr[key] = GVR.new(
            payload: payload,
            primary_resource: primary_resource,
            subresource_metadata: subresource && subresource.fetch("metadata")
          )
        end
        missing = expected_gvrs - @served_gvrs_by_gvr.keys
        raise MissingGVRError, "registry is missing served GVRs: #{missing.map(&:to_s).sort.join(", ")}" unless missing.empty?

        @gvrs = @served_gvrs_by_gvr.values.sort_by(&:to_s).freeze
        @served_gvrs_by_gvr.freeze
      end

      def served_gvr(payload)
        group = payload.fetch("group", "")
        version = payload.fetch("version")
        resource = payload.fetch("resource")
        SCHEMA_GVR.new(group: group, version: version, resource: resource)
      rescue KeyError, ArgumentError => error
        raise InvalidCatalogError, "invalid served GVR: #{error.message}"
      end

      def source_identifier(gvr)
        prefix = gvr.group.empty? ? "core" : gvr.group
        "#{prefix}/#{gvr.version}/#{gvr.resource}"
      end

      def type_for_resource(payload)
        raise MissingSchemaError, "resource is missing schema" unless payload.key?("schema")

        schema_name = payload["schema"]
        raise InvalidCatalogError, "resource schema must be a non-empty String" unless schema_name.is_a?(String) && !schema_name.empty?

        entry = @types_by_schema[schema_name]
        raise MissingSchemaError, "registry type is missing for resource schema #{schema_name.inspect}" unless entry

        entry
      rescue KeyError, ArgumentError => error
        raise InvalidCatalogError, "invalid resource schema reference: #{error.message}"
      end

      def resolve_entry(identifier, options)
        return identifier if identifier.is_a?(Type) || identifier.is_a?(Resource) || identifier.is_a?(GVKEntry)
        return identifier if identifier.is_a?(GVR)
        return find_gvr(**options) if options.key?(:resource) || options.key?(:gvr)

        type(identifier, **options) || (options.empty? ? find_gvr(identifier) : nil)
      end

      def resolve_catalog_entry(identifier)
        return identifier.type if identifier.is_a?(Resource)
        return identifier.type if identifier.is_a?(GVR)
        return identifier.type || identifier if identifier.is_a?(GVKEntry)
        return identifier if identifier.is_a?(Type)

        type(identifier) || find_gvr(identifier)
      end

      def type_for_gvk_entry(entry)
        entry.is_a?(GVKEntry) ? (entry.type || entry) : entry
      end

      def normalize_gvk_lookup(identifier, parts, group, version, kind, explicit_gvk)
        identifier = explicit_gvk if explicit_gvk
        if !parts.empty?
          GVK.new(group: identifier, version: parts.fetch(0), kind: parts.fetch(1))
        elsif identifier.is_a?(GVKEntry)
          identifier.gvk
        elsif identifier.is_a?(GVK)
          identifier
        elsif identifier.is_a?(Hash)
          GVK.new(identifier)
        elsif group || version || kind
          GVK.new(group: group || "", version: version, kind: kind)
        else
          parse_gvk(identifier)
        end
      end

      def parse_gvk(identifier)
        return identifier if identifier.is_a?(GVK)

        value = identifier.to_s
        parts = value.split("/")
        return GVK.new(group: "", version: parts.fetch(1), kind: parts.fetch(2)) if parts.length == 3 && parts.first == "core"

        GVK.parse(value)
      end

      def parse_gvr(identifier)
        return identifier if identifier.is_a?(SCHEMA_GVR)

        value = identifier.to_s
        parts = value.split("/")
        if parts.length >= 3
          group = parts.shift
          group = "" if group == "core"
          return SCHEMA_GVR.new(group: group, version: parts.shift, resource: parts.join("/"))
        end
        SCHEMA_GVR.parse(value)
      end
    end

    SchemaCatalog = Catalog
  end
end
