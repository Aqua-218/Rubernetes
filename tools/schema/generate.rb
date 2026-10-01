#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "tmpdir"
require_relative "../../lib/rubernetes/schema"

module RubernetesSchemaGenerator
  VERSION = "1.1.0"
  ROOT = Pathname.new(File.expand_path("../..", __dir__))
  DEFAULT_CORPUS = ROOT.join("schema/kubernetes/v1.36.2")
  DEFAULT_OUTPUT = ROOT.join("generated")

  class Error < StandardError; end

  module_function

  def canonical_json(value)
    case value
    when Hash
      "{" + value.keys.sort.map { |key| "#{JSON.generate(key)}:#{canonical_json(value.fetch(key))}" }.join(",") + "}"
    when Array
      "[" + value.map { |child| canonical_json(child) }.join(",") + "]"
    else
      JSON.generate(value)
    end
  end

  def digest_files(paths, base:)
    material = paths.sort.map do |path|
      relative = Pathname.new(path).relative_path_from(base).to_s
      "#{relative}\0#{Digest::SHA256.file(path).hexdigest}\n"
    end.join
    Digest::SHA256.hexdigest(material)
  end

  def ruby_constant(schema_name)
    parts = schema_name.split(/[^A-Za-z0-9]+/).reject(&:empty?)
    constant = parts.map { |part| part.match?(/\A\d/) ? "V#{part}" : part.sub(/\A./, &:upcase) }.join
    constant = "Type#{constant}" unless constant.match?(/\A[A-Z]/)
    constant
  end

  def ruby_method(field_name)
    candidate = field_name.gsub(/([a-z\d])([A-Z])/, "\\1_\\2").tr("-.", "__").downcase
    return nil unless candidate.match?(/\A[a-z_]\w*[!?=]?\z/)
    return nil if RESERVED_METHODS.include?(candidate)

    candidate
  end

  RUBY_KEYWORDS = %w[
    BEGIN END __ENCODING__ __FILE__ __LINE__ alias and begin break case class def defined
    do else elsif end ensure false for if in module next nil not or redo rescue retry return
    self super then true undef unless until when while yield
  ].map(&:downcase).freeze

  RESERVED_METHODS = (
    Object.instance_methods(false) + Kernel.instance_methods(false) + BasicObject.instance_methods(false) +
    Rubernetes::Schema::ValueObject.instance_methods +
    %i[field with to_h schema_name fields present? unknown_fields validate] + RUBY_KEYWORDS
  ).map(&:to_s).uniq.freeze

  class Compiler
    attr_reader :corpus_directory, :output_directory

    def initialize(corpus_directory:, output_directory:)
      @corpus_directory = Pathname.new(corpus_directory).expand_path
      @output_directory = Pathname.new(output_directory).expand_path
    end

    def compile
      swagger_path = [corpus_directory.join("openapi/v2.json"), corpus_directory.join("openapi/swagger.json")].find(&:file?) ||
                     corpus_directory.join("openapi/v2.json")
      discovery_path = corpus_directory.join("discovery/aggregated_v2.json")
      core_discovery_path = corpus_directory.join("discovery/api__v1.json")
      sources_path = corpus_directory.join("sources.json")
      required = [swagger_path, discovery_path, core_discovery_path, sources_path]
      missing = required.reject(&:file?)
      raise Error, "missing canonical corpus files: #{missing.join(", ")}" unless missing.empty?

      swagger = parse_object(swagger_path)
      discovery = parse_object(discovery_path)
      sources = parse_object(sources_path)
      definitions = swagger.fetch("definitions")
      resources = normalize_resources(discovery)
      resources.concat(normalize_legacy_resources(parse_object(core_discovery_path))) if core_discovery_path.file?
      resources.sort_by! { |resource| [resource.fetch("group"), resource.fetch("version"), resource.fetch("resource")] }
      types = normalize_types(definitions)
      resources = enrich_resources(resources, types, definitions)
      gvks = normalize_expected_gvks(sources, types)
      gvrs = normalize_expected_gvrs(sources)
      verify_unique!(types, resources)
      corpus_files = Dir.glob(corpus_directory.join("**/*")).select { |path| File.file?(path) }
      input_digest = RubernetesSchemaGenerator.digest_files(corpus_files, base: corpus_directory)
      artifacts = render_artifacts(swagger, types, resources, gvks, gvrs, input_digest)
      write_artifacts(artifacts)
      artifacts
    end

    def check
      temporary = Pathname.new(Dir.mktmpdir("rubernetes-schema-check-"))
      begin
        expected_directory = output_directory
        generated = self.class.new(corpus_directory: corpus_directory, output_directory: temporary)
        generated.compile
        compare_trees(expected_directory, temporary)
      ensure
        FileUtils.remove_entry(temporary) if temporary.exist?
      end
    end

    private

    def parse_object(path)
      value = JSON.parse(path.binread, max_nesting: 512)
      raise Error, "corpus document must be an object: #{path}" unless value.is_a?(Hash)

      value
    rescue JSON::ParserError => error
      raise Error.new("invalid corpus JSON #{path}: #{error.message}"), cause: error
    end

    def normalize_types(definitions)
      definitions.keys.sort.map do |schema_name|
        schema = definitions.fetch(schema_name)
        properties = schema.fetch("properties", {})
        raise Error, "OpenAPI schema #{schema_name}.properties must be an object" unless properties.is_a?(Hash)

        fields = properties.keys.sort
        required = Array(schema["required"]).sort
        unless required.all? { |field_name| field_name.is_a?(String) && properties.key?(field_name) }
          raise Error, "OpenAPI schema #{schema_name} has invalid required fields"
        end

        gvks = Array(schema["x-kubernetes-group-version-kind"]).map do |gvk|
          {"group" => gvk.fetch("group"), "version" => gvk.fetch("version"), "kind" => gvk.fetch("kind")}
        end.sort_by { |gvk| [gvk.fetch("group"), gvk.fetch("version"), gvk.fetch("kind")] }
        field_definitions = fields.to_h do |field_name|
          context = "#{schema_name}.properties.#{field_name}"
          [field_name, normalize_field_schema(properties.fetch(field_name), required: required.include?(field_name), context: context,
                                                                            definitions: definitions)]
        end
        normalized = {
          "schema" => schema_name,
          "ruby_constant" => RubernetesSchemaGenerator.ruby_constant(schema_name),
          "fields" => fields,
          "field_definitions" => field_definitions,
          "required" => required,
          "gvks" => gvks,
          "patch_fields" => fields
        }
        normalized["preserve_unknown_fields"] = true if preserve_unknown_root?(schema)
        normalized.merge!(union_schema(schema_name, schema) || {})
        normalized
      end
    end

    # A root schema normally follows Kubernetes' typed-object pruning rules.
    # The OpenAPI corpus does not expose a root extension for the three
    # intentionally opaque JSON carriers, so derive the exception from the
    # schema's own marker/description rather than an identifier allowlist.
    def preserve_unknown_root?(schema)
      return true if schema["x-kubernetes-preserve-unknown-fields"] == true

      properties = schema.fetch("properties", {})
      return false unless properties.empty? && !schema.key?("additionalProperties")

      description = schema["description"].to_s
      return true if schema["type"].nil? && description.start_with?("JSON represents any valid JSON value.")
      return true if schema["type"] == "object" && description.match?(/\bin JSON format\b|\braw JSON\b/i)

      false
    end

    # apiextensions' JSONSchemaPropsOr{Bool,Array,StringArray} are unions with
    # custom JSON marshalers (apiextensions/v1/marshal.go): an object is a
    # JSONSchemaProps (typed, unknown fields dropped like any struct) and the
    # alternative is a bool or an array.  The corpus describes them as
    # "X represents JSONSchemaProps or ..." with no properties.
    def union_schema(schema_name, schema)
      description = schema["description"].to_s
      return nil unless schema["type"].nil? && schema.fetch("properties", {}).empty? &&
                        description.match?(/\AJSONSchemaPropsOr\w+ represents /)

      {
        "union_object_schema" => schema_name.sub(/\.JSONSchemaPropsOr\w+\z/, ".JSONSchemaProps"),
        "union_scalar_types" => schema_name.end_with?("OrBool") ? ["boolean"] : ["array"]
      }
    end

    def normalize_field_schema(schema, required:, context:, definitions:)
      raise Error, "OpenAPI field #{context} must be an object" unless schema.is_a?(Hash)

      normalized = normalize_field_type(schema, context: context, definitions: definitions)
      normalized["required"] = true if required
      nullable = schema["nullable"] || schema["x-nullable"] || schema["x-kubernetes-nullable"]
      normalized["nullable"] = true if nullable
      normalized["preserve_unknown_fields"] = true if schema["x-kubernetes-preserve-unknown-fields"]

      {
        "format" => "format",
        "default" => "default",
        "enum" => "enum",
        "minimum" => "minimum",
        "maximum" => "maximum",
        "exclusiveMinimum" => "exclusive_minimum",
        "exclusiveMaximum" => "exclusive_maximum",
        "pattern" => "pattern",
        "minLength" => "min_length",
        "maxLength" => "max_length",
        "minItems" => "min_items",
        "maxItems" => "max_items",
        "uniqueItems" => "unique_items",
        "minProperties" => "min_properties",
        "maxProperties" => "max_properties",
        "multipleOf" => "multiple_of"
      }.each do |source, target|
        normalized[target] = deep_copy(schema.fetch(source)) if schema.key?(source)
      end
      schema.keys.grep(/\Ax-kubernetes-/).sort.each do |extension|
        next if %w[x-kubernetes-nullable x-kubernetes-preserve-unknown-fields].include?(extension)

        normalized[extension.tr("-", "_")] = deep_copy(schema.fetch(extension))
      end
      normalized.sort.to_h
    end

    def normalize_field_type(schema, context:, definitions:)
      if schema.key?("$ref")
        reference = schema.fetch("$ref")
        prefix = "#/definitions/"
        unless reference.is_a?(String) && reference.start_with?(prefix) && reference.length > prefix.length
          raise Error, "OpenAPI field #{context} has invalid reference #{reference.inspect}"
        end

        schema_name = reference.delete_prefix(prefix)
        raise Error, "OpenAPI field #{context} references missing schema #{schema_name.inspect}" unless definitions.key?(schema_name)

        target = definitions.fetch(schema_name)
        unless target["type"].nil? || target["type"] == "object"
          scalar = normalize_field_schema(target, required: false, context: "definitions.#{schema_name}", definitions: definitions)
          return scalar.merge("schema_reference" => schema_name)
        end

        return {"type" => "reference", "reference" => schema_name}
      end

      type = schema["type"]
      type = "object" if type.nil? && (schema.key?("properties") || schema.key?("additionalProperties"))
      type = "any" if type.nil? && schema["x-kubernetes-int-or-string"]
      type ||= "any"
      raise Error, "OpenAPI field #{context} has unsupported type #{type.inspect}" unless %w[any array boolean integer null number object string].include?(type)

      normalized = {"type" => type}
      if type == "array"
        items = schema["items"]
        raise Error, "OpenAPI array field #{context} must declare an items schema" unless items.is_a?(Hash)

        normalized["items"] = normalize_field_schema(items, required: false, context: "#{context}.items", definitions: definitions)
      end
      if type == "object" && schema.key?("properties")
        properties = schema.fetch("properties")
        raise Error, "OpenAPI field #{context}.properties must be an object" unless properties.is_a?(Hash)

        required = Array(schema["required"])
        unless required.all? { |field_name| field_name.is_a?(String) && properties.key?(field_name) }
          raise Error, "OpenAPI field #{context} has invalid required fields"
        end

        normalized["properties"] = properties.keys.sort.to_h do |field_name|
          [field_name, normalize_field_schema(properties.fetch(field_name), required: required.include?(field_name),
                                                                            context: "#{context}.properties.#{field_name}", definitions: definitions)]
        end
      end
      if type == "object" && schema.key?("additionalProperties")
        additional = schema.fetch("additionalProperties")
        normalized["additional_properties"] = if [true, false].include?(additional)
                                                additional
                                              elsif additional.is_a?(Hash)
                                                normalize_field_schema(additional, required: false,
                                                                                   context: "#{context}.additionalProperties",
                                                                                   definitions: definitions)
                                              else
                                                raise Error, "OpenAPI field #{context}.additionalProperties must be a schema or boolean"
                                              end
      end
      normalized
    end

    def deep_copy(value)
      case value
      when Hash
        value.keys.sort.to_h { |key| [key, deep_copy(value.fetch(key))] }
      when Array
        value.map { |item| deep_copy(item) }
      else
        value
      end
    end

    def normalize_resources(discovery)
      discovery.fetch("items").flat_map do |group_document|
        group = group_document.dig("metadata", "name").to_s
        group_document.fetch("versions").flat_map do |version_document|
          version = version_document.fetch("version")
          version_document.fetch("resources").map do |resource|
            response_kind = resource.fetch("responseKind", {})
            {
              "group" => group == "core" ? "" : group,
              "version" => version,
              "resource" => resource.fetch("resource"),
              "singular" => resource.fetch("singularResource", ""),
              "kind" => response_kind.fetch("kind", ""),
              "scope" => resource.fetch("scope") == "Namespaced" ? "Namespaced" : "Cluster",
              "verbs" => Array(resource["verbs"]).sort,
              "categories" => Array(resource["categories"]).sort,
              "short_names" => Array(resource["shortNames"]).sort,
              "subresources" => Array(resource["subresources"]).map do |subresource|
                {
                  "resource" => subresource.fetch("subresource"),
                  "kind" => subresource.fetch("responseKind", {}).fetch("kind", ""),
                  "verbs" => Array(subresource["verbs"]).sort
                }
              end.sort_by { |entry| entry.fetch("resource") }
            }
          end
        end
      end.sort_by { |resource| [resource.fetch("group"), resource.fetch("version"), resource.fetch("resource")] }
    end

    def normalize_legacy_resources(discovery)
      group_version = discovery.fetch("groupVersion")
      group, version = group_version.include?("/") ? group_version.split("/", 2) : ["", group_version]
      primaries = discovery.fetch("resources").reject { |resource| resource.fetch("name").include?("/") }
      subresources = discovery.fetch("resources").select { |resource| resource.fetch("name").include?("/") }
      primaries.map do |resource|
        resource_name = resource.fetch("name")
        {
          "group" => group,
          "version" => version,
          "resource" => resource_name,
          "singular" => resource.fetch("singularName", ""),
          "kind" => resource.fetch("kind", ""),
          "scope" => resource.fetch("namespaced") ? "Namespaced" : "Cluster",
          "verbs" => Array(resource["verbs"]).sort,
          "categories" => Array(resource["categories"]).sort,
          "short_names" => Array(resource["shortNames"]).sort,
          "subresources" => subresources.filter_map do |child|
            parent, subresource = child.fetch("name").split("/", 2)
            next unless parent == resource_name

            {
              "resource" => subresource,
              "kind" => child.fetch("kind", ""),
              "verbs" => Array(child["verbs"]).sort
            }
          end.sort_by { |entry| entry.fetch("resource") }
        }
      end
    end

    def verify_unique!(types, resources)
      constants = types.group_by { |type| type.fetch("ruby_constant") }.select { |_key, values| values.length > 1 }
      raise Error, "generated Ruby constant collisions: #{constants.keys.sort.join(", ")}" unless constants.empty?

      gvks = types.flat_map { |type| type.fetch("gvks").map { |gvk| [gvk, type.fetch("schema")] } }
      duplicate_gvks = gvks.group_by(&:first).select { |_key, values| values.length > 1 }
      raise Error, "duplicate GVK registrations: #{duplicate_gvks.keys.inspect}" unless duplicate_gvks.empty?

      duplicate_gvrs = resources.group_by do |resource|
        [resource.fetch("group"), resource.fetch("version"), resource.fetch("resource")]
      end.select { |_key, values| values.length > 1 }
      raise Error, "duplicate GVR registrations: #{duplicate_gvrs.keys.inspect}" unless duplicate_gvrs.empty?
    end

    def enrich_resources(resources, types, definitions)
      type_by_gvk = {}
      types.each do |type|
        type.fetch("gvks").each do |gvk|
          type_by_gvk[[gvk.fetch("group"), gvk.fetch("version"), gvk.fetch("kind")]] = type.fetch("schema")
        end
      end
      resources.map do |resource|
        schema_name = type_by_gvk[[resource.fetch("group"), resource.fetch("version"), resource.fetch("kind")]]
        metadata = if schema_name
                     patch_metadata(definitions,
                                    schema_name)
                   else
                     {"merge_keys" => {}, "patch_strategies" => {}, "field_paths" => []}
                   end
        resource.merge("schema" => schema_name).merge(metadata)
      end
    end

    def normalize_expected_gvrs(sources)
      identifiers = sources.dig("coverage", "covered_gvrs")
      raise Error, "sources.json coverage.covered_gvrs must be an array of strings" unless identifiers.is_a?(Array) && identifiers.all?(String)
      raise Error, "sources.json contains duplicate covered GVRs" unless identifiers.uniq.length == identifiers.length

      identifiers.sort.map do |identifier|
        parts = identifier.split("/")
        raise Error, "invalid covered GVR #{identifier.inspect}" if parts.length < 3

        group = parts.shift
        version = parts.shift
        resource = parts.join("/")
        {
          "identifier" => identifier,
          "group" => group == "core" ? "" : group,
          "version" => version,
          "resource" => resource
        }
      end
    end

    def normalize_expected_gvks(sources, types)
      registrations = {}
      types.each do |type|
        type.fetch("gvks").each do |gvk|
          identifier = gvk_identifier(gvk.fetch("group"), gvk.fetch("version"), gvk.fetch("kind"))
          raise Error, "duplicate OpenAPI GVK registration #{identifier}" if registrations.key?(identifier)

          registrations[identifier] = gvk.merge("identifier" => identifier, "schema" => type.fetch("schema"))
        end
      end

      covered = sources.dig("coverage", "covered_gvks")
      if covered
        raise Error, "sources.json coverage.covered_gvks must be an array of strings" unless covered.is_a?(Array) && covered.all?(String)
        raise Error, "sources.json contains duplicate covered GVKs" unless covered.uniq.length == covered.length

        covered.each do |identifier|
          parts = identifier.split("/", 3)
          raise Error, "invalid covered GVK #{identifier.inspect}" unless parts.length == 3 && parts.all? { |part| !part.empty? }

          group, version, kind = parts
          normalized_group = group == "core" ? "" : group
          canonical_identifier = gvk_identifier(normalized_group, version, kind)
          next if registrations.key?(canonical_identifier)

          candidates = types.select { |type| type.fetch("schema").split(".").last == kind }
          candidate = select_alias_schema(candidates, kind)
          registrations[canonical_identifier] = {
            "identifier" => canonical_identifier,
            "group" => normalized_group,
            "version" => version,
            "kind" => kind,
            "schema" => candidate&.fetch("schema")
          }
        end
      end
      registrations.values.sort_by { |entry| entry.fetch("identifier") }
    end

    def select_alias_schema(candidates, kind)
      return candidates.first if candidates.length <= 1
      return candidates.find { |type| type.fetch("schema").include?(".authentication.") } if kind == "TokenRequest"

      nil
    end

    def gvk_identifier(group, version, kind)
      "#{group.to_s.empty? ? "core" : group}/#{version}/#{kind}"
    end

    def patch_metadata(definitions, root_schema)
      merge_keys = {}
      patch_strategies = {}
      field_paths = []
      visit = lambda do |schema_name, prefix, stack|
        return if stack.include?(schema_name)

        schema = definitions[schema_name]
        return unless schema

        schema.fetch("properties", {}).keys.sort.each do |field_name|
          field_schema = schema.fetch("properties").fetch(field_name)
          path = (prefix + [field_name]).join(".")
          field_paths << path
          merge_key = field_schema["x-kubernetes-patch-merge-key"] || Array(field_schema["x-kubernetes-list-map-keys"]).first
          merge_keys[path] = merge_key if merge_key
          strategy = field_schema["x-kubernetes-patch-strategy"]
          patch_strategies[path] = strategy if strategy
          referenced = field_schema["$ref"] || field_schema.dig("items", "$ref")
          next unless referenced&.start_with?("#/definitions/")

          visit.call(referenced.delete_prefix("#/definitions/"), prefix + [field_name], stack + [schema_name])
        end
      end
      visit.call(root_schema, [], [])
      {
        "merge_keys" => merge_keys.sort.to_h,
        "patch_strategies" => patch_strategies.sort.to_h,
        "field_paths" => field_paths.sort
      }
    end

    def render_artifacts(swagger, types, resources, gvks, gvrs, input_digest)
      registry = {
        "schema_version" => 1,
        "kubernetes_version" => "v1.36.2",
        "input_sha256" => input_digest,
        "types" => types,
        "resources" => resources,
        "gvks" => gvks,
        "gvrs" => gvrs
      }
      fields = types.to_h do |type|
        [type.fetch("schema"), {
          "ruby" => type.fetch("fields"),
          "rbs" => type.fetch("fields"),
          "openapi" => type.fetch("fields"),
          "codec" => type.fetch("fields"),
          "patch" => type.fetch("patch_fields"),
          "dsl" => type.fetch("fields").filter_map { |field| RubernetesSchemaGenerator.ruby_method(field) }
        }]
      end
      artifacts = {
        "schema/registry.json" => RubernetesSchemaGenerator.canonical_json(registry) << "\n",
        "fixtures/field-sets.json" => RubernetesSchemaGenerator.canonical_json(fields) << "\n",
        "ruby/kubernetes_types.rb" => render_ruby(types, input_digest),
        "rbs/kubernetes_types.rbs" => render_rbs(types, input_digest),
        "openapi/v2.json" => RubernetesSchemaGenerator.canonical_json(swagger) << "\n"
      }
      artifacts.merge!(render_openapi_v3(swagger, resources))
      artifact_digests = artifacts.keys.sort.to_h do |path|
        [path, Digest::SHA256.hexdigest(artifacts.fetch(path))]
      end
      manifest = {
        "schema_version" => 1,
        "compiler_version" => VERSION,
        "input_sha256" => input_digest,
        "kubernetes_version" => "v1.36.2",
        "type_count" => types.length,
        "gvk_count" => gvks.length,
        "type_gvk_count" => types.sum { |type| type.fetch("gvks").length },
        "gvr_count" => gvrs.length,
        "route_gvr_count" => resources.length + resources.sum { |resource| resource.fetch("subresources").length },
        "methods" => types.to_h do |type|
          [type.fetch("schema"), type.fetch("fields").filter_map do |field|
            RubernetesSchemaGenerator.ruby_method(field)
          end]
        end,
        "artifacts" => artifact_digests
      }
      artifacts["manifest.json"] = RubernetesSchemaGenerator.canonical_json(manifest) << "\n"
      artifacts
    end

    def render_ruby(types, input_digest)
      lines = [
        "# frozen_string_literal: true",
        "# Generated by Rubernetes schema compiler #{VERSION}; do not edit.",
        "# Input SHA-256: #{input_digest}",
        "",
        "require_relative \"../../lib/rubernetes/schema\"",
        "",
        "module Rubernetes",
        "  module Generated",
        "    SCHEMA_CONSTANTS = #{ruby_literal(types.to_h { |type| [type.fetch("schema"), type.fetch("ruby_constant")] })}.freeze",
        "",
        "    def self.definition_for(schema_name)",
        "      constant_name = SCHEMA_CONSTANTS.fetch(schema_name)",
        "      const_get(constant_name, false).const_get(:DEFINITION, false)",
        "    end"
      ]
      types.each do |type|
        identity = definition_identity(type)
        lines << "    class #{type.fetch("ruby_constant")} < Rubernetes::Schema::ValueObject"
        lines << "      SCHEMA_NAME = #{type.fetch("schema").dump}.freeze"
        lines << "      FIELDS = #{type.fetch("fields").inspect}.freeze"
        lines << "      REQUIRED_FIELDS = #{type.fetch("required").inspect}.freeze"
        lines << "      FIELD_DEFINITIONS = Rubernetes::Schema::DeepFreeze.call(#{render_field_map(type.fetch("field_definitions"))})"
        lines << "      DEFINITION = Rubernetes::Schema::Definition.new("
        lines << "        name: SCHEMA_NAME, group: #{identity.fetch("group").dump}, version: #{identity.fetch("version").dump},"
        preserve = type.fetch("preserve_unknown_fields", false)
        union = type["union_object_schema"]
        if preserve
          lines << "        kind: #{identity.fetch("kind").dump}, fields: FIELD_DEFINITIONS, required: REQUIRED_FIELDS,"
          lines << "        preserve_unknown_fields: true"
        elsif union
          lines << "        kind: #{identity.fetch("kind").dump}, fields: FIELD_DEFINITIONS, required: REQUIRED_FIELDS,"
          lines << "        union_object_schema: #{union.dump}, union_scalar_types: #{type.fetch("union_scalar_types").inspect}"
        else
          lines << "        kind: #{identity.fetch("kind").dump}, fields: FIELD_DEFINITIONS, required: REQUIRED_FIELDS"
        end
        lines << "      )"
        type.fetch("fields").each do |field|
          method_name = RubernetesSchemaGenerator.ruby_method(field)
          next unless method_name

          lines << "      def #{method_name}"
          lines << "        field(#{field.dump})"
          lines << "      end"
        end
        lines << "    end"
      end
      lines.push("  end", "end", "")
      lines.join("\n")
    end

    def definition_identity(type)
      gvk = type.fetch("gvks").first
      return gvk if gvk

      parts = type.fetch("schema").split(".")
      version_index = parts.rindex { |part| part.match?(/\Av\d/) }
      {
        "group" => version_index&.positive? && parts[version_index - 1] != "core" ? parts[version_index - 1] : "",
        "version" => version_index ? parts.fetch(version_index) : "internal",
        "kind" => parts.last
      }
    end

    def render_field_map(fields)
      "{" + fields.keys.sort.map do |field_name|
        "#{field_name.dump} => #{render_field_options(fields.fetch(field_name))}"
      end.join(", ") + "}"
    end

    def render_field_options(options)
      pairs = []
      if options.fetch("type") == "reference"
        reference = options.fetch("reference")
        pairs << "type: Rubernetes::Schema::Reference.new(#{reference.dump}) { Rubernetes::Generated.definition_for(#{reference.dump}) }"
      else
        pairs << "type: :#{options.fetch("type")}"
      end
      options.keys.sort.each do |key|
        next if %w[type reference].include?(key)

        value = options.fetch(key)
        rendered = case key
                   when "items", "additional_properties"
                     value.is_a?(Hash) ? render_field_options(value) : ruby_literal(value)
                   when "properties"
                     render_field_map(value)
                   else
                     ruby_literal(value)
                   end
        pairs << "#{key}: #{rendered}"
      end
      "{" + pairs.join(", ") + "}"
    end

    def ruby_literal(value)
      case value
      when Hash
        "{" + value.keys.sort.map { |key| "#{ruby_literal(key)} => #{ruby_literal(value.fetch(key))}" }.join(", ") + "}"
      when Array
        "[" + value.map { |item| ruby_literal(item) }.join(", ") + "]"
      when String
        value.dump
      when Symbol
        value.inspect
      when Numeric, true, false, nil
        value.inspect
      else
        raise Error, "cannot render #{value.class} as a deterministic Ruby literal"
      end
    end

    def render_rbs(types, input_digest)
      lines = [
        "# Generated by Rubernetes schema compiler #{VERSION}; do not edit.",
        "# Input SHA-256: #{input_digest}",
        "",
        "module Rubernetes",
        "  module Generated",
        "    SCHEMA_CONSTANTS: Hash[String, String]",
        "    def self.definition_for: (String schema_name) -> Rubernetes::Schema::Definition"
      ]
      types.each do |type|
        lines << "    class #{type.fetch("ruby_constant")} < Rubernetes::Schema::ValueObject"
        lines << "      SCHEMA_NAME: String"
        lines << "      FIELDS: Array[String]"
        lines << "      REQUIRED_FIELDS: Array[String]"
        lines << "      FIELD_DEFINITIONS: Hash[String, untyped]"
        lines << "      DEFINITION: Rubernetes::Schema::Definition"
        type.fetch("fields").each do |field|
          method_name = RubernetesSchemaGenerator.ruby_method(field)
          lines << "      def #{method_name}: () -> untyped" if method_name
        end
        lines << "    end"
      end
      lines.push("  end", "end", "")
      lines.join("\n")
    end

    # The pinned upstream OpenAPI v3 documents (schema/kubernetes/v1.36.2-openapi-v3,
    # tools/schema/import_kubernetes_openapi_v3.rb) supply the served path
    # operations; the schemas still come from the pinned v2 definitions so
    # the field sets stay identical to the generated types.
    OPENAPI_V3_PINNED = File.expand_path("../../schema/kubernetes/v1.36.2-openapi-v3", __dir__)
    OPENAPI_V3_SCALAR_SCHEMAS = %w[io.k8s.apimachinery.pkg.api.resource.Quantity
                                   io.k8s.apimachinery.pkg.util.intstr.IntOrString].freeze

    def pinned_openapi_v3(key)
      path = File.join(OPENAPI_V3_PINNED, "#{key}.json")
      return nil unless File.file?(path)

      JSON.parse(File.read(path))
    end

    def render_openapi_v3(swagger, resources)
      definitions = swagger.fetch("definitions")
      schemas_by_group_version = resources.group_by { |resource| [resource.fetch("group"), resource.fetch("version")] }
      # kube-apiserver's /openapi/v3 root is a bare {"paths": ...} document.
      index = {"paths" => {}}
      artifacts = {}
      schemas_by_group_version.keys.sort.each do |group, version|
        key = group.empty? ? "api/#{version}" : "apis/#{group}/#{version}"
        relative = "openapi/v3/#{key}.json"
        index.fetch("paths")[key] = {"serverRelativeURL" => "/openapi/v3/#{key}?hash=#{Digest::SHA256.hexdigest(key)[0, 16]}"}
        roots = definitions.filter_map do |schema_name, schema|
          gvks = Array(schema["x-kubernetes-group-version-kind"])
          schema_name if gvks.any? { |gvk| gvk.fetch("group") == group && gvk.fetch("version") == version }
        end
        pinned = pinned_openapi_v3(key)
        paths = pinned ? pinned.fetch("paths", {}) : {}
        # Operations reference shared meta types (Status, DeleteOptions,
        # Patch, WatchEvent, ListMeta ...): pull them into the closure.
        referenced = paths.to_s.scan(%r{#/components/schemas/([A-Za-z0-9_.-]+)}).flatten.uniq
        selected_definitions = schema_closure(definitions, (roots + referenced.select { |name| definitions.key?(name) }).uniq)
        schemas = deep_transform_refs(selected_definitions)
        # The v2 definitions describe Quantity and IntOrString as plain
        # strings; upstream's v3 documents give them their oneOf shape, which
        # is what `kubectl explain` prints as <Quantity>.  Take those two from
        # the pinned v3 document whenever it has them.
        pinned_schemas = pinned ? pinned.dig("components", "schemas") || {} : {}
        OPENAPI_V3_SCALAR_SCHEMAS.each do |name|
          schemas[name] = pinned_schemas.fetch(name) if schemas.key?(name) && pinned_schemas.key?(name)
        end
        document = {
          "openapi" => "3.0.0",
          "info" => {"title" => "Rubernetes Kubernetes #{group.empty? ? "core" : group}/#{version}", "version" => "v1.36.2"},
          "paths" => paths,
          "components" => {"schemas" => schemas}
        }
        artifacts[relative] = RubernetesSchemaGenerator.canonical_json(document) << "\n"
      end
      # Root, group-index and auxiliary documents are served verbatim from the pin.
      %w[api apis version logs openid/v1/jwks .well-known/openid-configuration].each do |key|
        pinned = pinned_openapi_v3(key)
        next if pinned.nil?

        index.fetch("paths")[key] = {"serverRelativeURL" => "/openapi/v3/#{key}?hash=#{Digest::SHA256.hexdigest(key)[0, 16]}"}
        artifacts["openapi/v3/#{key}.json"] = RubernetesSchemaGenerator.canonical_json(pinned) << "\n"
      end
      schemas_by_group_version.keys.map(&:first).reject(&:empty?).uniq.sort.each do |group|
        pinned = pinned_openapi_v3("apis/#{group}")
        next if pinned.nil?

        index.fetch("paths")["apis/#{group}"] = {"serverRelativeURL" => "/openapi/v3/apis/#{group}?hash=#{Digest::SHA256.hexdigest("apis/#{group}")[0, 16]}"}
        artifacts["openapi/v3/apis/#{group}.json"] = RubernetesSchemaGenerator.canonical_json(pinned) << "\n"
      end
      artifacts["openapi/v3/index.json"] = RubernetesSchemaGenerator.canonical_json(index) << "\n"
      artifacts
    end

    def schema_closure(definitions, roots)
      selected = {}
      pending = roots.sort
      until pending.empty?
        schema_name = pending.shift
        next if selected.key?(schema_name)

        schema = definitions[schema_name]
        next unless schema

        selected[schema_name] = schema
        referenced_schemas(schema).each { |reference| pending << reference unless selected.key?(reference) }
      end
      selected.sort.to_h
    end

    def referenced_schemas(value)
      case value
      when Hash
        reference = value["$ref"]
        direct = reference.delete_prefix("#/definitions/") if reference.is_a?(String)
        nested = value.flat_map { |_key, child| referenced_schemas(child) }
        direct ? [direct, *nested].uniq : nested.uniq
      when Array
        value.flat_map { |child| referenced_schemas(child) }.uniq
      else
        []
      end
    end

    def deep_transform_refs(value)
      case value
      when Hash
        value.to_h do |key, child|
          transformed = if key == "$ref" && child.is_a?(String)
                          child.sub("#/definitions/",
                                    "#/components/schemas/")
                        else
                          deep_transform_refs(child)
                        end
          [key, transformed]
        end
      when Array
        value.map { |child| deep_transform_refs(child) }
      else
        value
      end
    end

    def write_artifacts(artifacts)
      expected = artifacts.keys.sort
      output_directory.mkpath
      existing = Dir.glob(output_directory.join("**/*")).select { |path| File.file?(path) }
      existing.each do |path|
        relative = Pathname.new(path).relative_path_from(output_directory).to_s
        File.delete(path) unless expected.include?(relative) || relative.start_with?("platform/") || relative == "README.md"
      end
      artifacts.each do |relative, content|
        path = output_directory.join(relative)
        path.dirname.mkpath
        temporary = Pathname.new("#{path}.tmp-#{Process.pid}")
        temporary.binwrite(content)
        File.rename(temporary, path)
      ensure
        temporary&.delete if temporary&.exist?
      end
    end

    def compare_trees(expected_directory, actual_directory)
      expected_files = source_files(expected_directory)
      actual_files = source_files(actual_directory)
      differences = []
      differences << "file inventory differs" unless expected_files == actual_files
      (expected_files & actual_files).each do |relative|
        expected = expected_directory.join(relative)
        actual = actual_directory.join(relative)
        differences << "content differs: #{relative}" unless FileUtils.compare_file(expected, actual)
      end
      raise Error, differences.join("; ") unless differences.empty?

      true
    end

    def source_files(directory)
      Dir.glob(directory.join("**/*")).select { |path| File.file?(path) }.map do |path|
        Pathname.new(path).relative_path_from(directory).to_s
      end.reject { |relative| relative.start_with?("platform/") || relative == "README.md" }.sort
    end
  end
end

options = {
  corpus: RubernetesSchemaGenerator::DEFAULT_CORPUS,
  output: RubernetesSchemaGenerator::DEFAULT_OUTPUT,
  check: false
}
OptionParser.new do |parser|
  parser.banner = "Usage: generate.rb [options]"
  parser.on("--corpus PATH", "canonical Kubernetes corpus") { |path| options[:corpus] = Pathname.new(path) }
  parser.on("--output PATH", "generated output tree") { |path| options[:output] = Pathname.new(path) }
  parser.on("--check", "compare regenerated output with the canonical tree") { options[:check] = true }
end.parse!(ARGV)

compiler = RubernetesSchemaGenerator::Compiler.new(
  corpus_directory: options.fetch(:corpus),
  output_directory: options.fetch(:output)
)
result = options.fetch(:check) ? compiler.check : compiler.compile
puts(JSON.generate("ok" => true, "artifact_count" => result.respond_to?(:length) ? result.length : nil))
