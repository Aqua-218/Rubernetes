#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "tempfile"

require_relative "../../lib/rubernetes/schema"
require_relative "../../lib/rubernetes/schema/codec/proto_descriptor"

module RubernetesFieldParity
  ROOT = File.expand_path("../..", __dir__).freeze
  CORPUS_RELATIVE_PATH = "schema/kubernetes/v1.36.2"
  GENERATED_RELATIVE_PATH = "generated"

  EXPECTED_TYPE_COUNT = 771
  EXPECTED_TYPE_GVK_COUNT = 311
  EXPECTED_GVK_COUNT = 321
  EXPECTED_PRIMARY_GVR_COUNT = 95
  EXPECTED_SERVED_GVR_COUNT = 153
  EXPECTED_ROUTE_GVR_COUNT = 150

  PROTOBUF_EXCEPTIONS = {
    "io.k8s.apimachinery.pkg.version.Info" => "upstream has no generated.proto"
  }.freeze

  RUBY_KEYWORDS = %w[
    __ENCODING__ __FILE__ __LINE__ BEGIN END alias and begin break case class def
    defined? do else elsif end ensure false for if in module next nil not or redo
    rescue retry return self super then true undef unless until when while yield
  ].to_set.freeze

  class Error < StandardError; end
  class DuplicateKeyError < Error; end

  class DuplicateCheckingHash < Hash
    def []=(key, value)
      raise DuplicateKeyError, "duplicate JSON object key #{key.inspect}" if key?(key)

      super
    end
  end

  module_function

  def reserved_methods
    @reserved_methods ||= begin
      names = Object.instance_methods + Kernel.instance_methods + BasicObject.instance_methods
      names.concat(Rubernetes::Schema::ValueObject.instance_methods)
      names.push(:field, :with, :to_h, :schema_name, :fields, :present?, :unknown_fields, :validate)
      names.to_set(&:to_s).merge(RUBY_KEYWORDS).freeze
    end
  end

  def ruby_method(field_name)
    candidate = field_name.gsub(/([a-z\d])([A-Z])/, "\\1_\\2").tr("-.", "__").downcase
    return nil unless candidate.match?(/\A[a-z_]\w*[!?=]?\z/)
    return nil if reserved_methods.include?(candidate)

    candidate
  end

  def canonical_value(value)
    case value
    when Hash
      value.keys.sort.to_h { |key| [key, canonical_value(value.fetch(key))] }
    when Array
      value.map { |item| canonical_value(item) }
    else
      value
    end
  end

  def canonical_json(value)
    JSON.generate(canonical_value(value), ascii_only: false) << "\n"
  end

  class Verifier
    attr_reader :root, :corpus_root, :generated_root, :issues

    def initialize(root: ROOT, corpus_root: nil, generated_root: nil)
      @root = File.expand_path(root)
      @corpus_root = File.expand_path(corpus_root || File.join(@root, CORPUS_RELATIVE_PATH))
      @generated_root = File.expand_path(generated_root || File.join(@root, GENERATED_RELATIVE_PATH))
      @issues = []
    end

    def verify
      load_inputs
      verify_type_inventory
      verify_field_surfaces
      verify_generated_sources
      verify_gvks
      verify_gvrs
      verify_patch_metadata
      verify_protobuf
      verify_manifest
      report
    rescue Error, JSON::ParserError, KeyError, Errno::ENOENT,
           Rubernetes::Schema::Codec::ProtoDescriptor::Error => error
      issue("input_error", error.class.name, nil, error.message)
      report
    end

    private

    def load_inputs
      @swagger = parse_json(File.join(corpus_root, "openapi/swagger.json"), "canonical OpenAPI")
      @sources = parse_json(File.join(corpus_root, "sources.json"), "canonical sources manifest")
      @registry = parse_json(File.join(generated_root, "schema/registry.json"), "generated registry")
      @field_sets = parse_json(File.join(generated_root, "fixtures/field-sets.json"), "generated field sets")
      @manifest = parse_json(File.join(generated_root, "manifest.json"), "generated manifest")
      @ruby_source = read_file(File.join(generated_root, "ruby/kubernetes_types.rb"))
      @rbs_source = read_file(File.join(generated_root, "rbs/kubernetes_types.rbs"))

      definitions = @swagger.fetch("definitions")
      raise Error, "OpenAPI definitions must be an object" unless definitions.is_a?(Hash)
      raise Error, "registry types must be an array" unless @registry["types"].is_a?(Array)
      raise Error, "registry resources must be an array" unless @registry["resources"].is_a?(Array)
      raise Error, "registry gvks must be an array" unless @registry["gvks"].is_a?(Array)
      raise Error, "registry gvrs must be an array" unless @registry["gvrs"].is_a?(Array)
      raise Error, "field sets must be an object" unless @field_sets.is_a?(Hash)

      @definitions = definitions
      @types = index_unique(@registry.fetch("types"), "schema", "registry type")
      @resources = @registry.fetch("resources")
      @ruby_classes = parse_ruby_classes(@ruby_source)
      @rbs_classes = parse_rbs_classes(@rbs_source)
    end

    def verify_type_inventory
      compare("type_count", "OpenAPI definitions", EXPECTED_TYPE_COUNT, @definitions.length)
      compare("type_count", "registry types", EXPECTED_TYPE_COUNT, @types.length)
      compare("type_inventory", "registry types", @definitions.keys.sort, @types.keys.sort)
      compare("type_inventory", "field sets", @definitions.keys.sort, @field_sets.keys.sort)

      constants = @types.values.map { |type| type.fetch("ruby_constant") }
      duplicate_values(constants).each do |constant|
        issue("duplicate_ruby_constant", constant, "unique", constants.count(constant))
      end
      compare("ruby_class_count", "generated Ruby", EXPECTED_TYPE_COUNT, @ruby_classes.length)
      compare("rbs_class_count", "generated RBS", EXPECTED_TYPE_COUNT, @rbs_classes.length)
      compare("ruby_class_inventory", "generated Ruby", constants.sort, @ruby_classes.keys.sort)
      compare("rbs_class_inventory", "generated RBS", constants.sort, @rbs_classes.keys.sort)
    end

    def verify_field_surfaces
      @definitions.keys.sort.each do |schema_name|
        definition = @definitions.fetch(schema_name)
        expected_fields = properties_for(definition, schema_name).keys.sort
        expected_required = Array(definition["required"]).sort
        type = @types.fetch(schema_name)
        field_set = @field_sets.fetch(schema_name)

        validate_unique_array(expected_required, "OpenAPI required", schema_name)
        %w[fields patch_fields required gvks].each do |field|
          issue("invalid_array", "#{schema_name}.#{field}", "Array", type[field].class.name) unless type[field].is_a?(Array)
        end
        %w[ruby rbs openapi codec patch dsl].each do |surface|
          issue("invalid_array", "#{schema_name}.#{surface}", "Array", field_set[surface].class.name) unless field_set[surface].is_a?(Array)
        end
        issue("invalid_object", "#{schema_name}.field_definitions", "Hash", type["field_definitions"].class.name) unless type["field_definitions"].is_a?(Hash)
        next if issues.any? { |entry| entry.fetch("subject").start_with?(schema_name) && entry.fetch("code") == "invalid_array" }

        validate_unique_array(type.fetch("fields"), "registry fields", schema_name)
        validate_unique_array(type.fetch("patch_fields"), "registry patch fields", schema_name)
        validate_unique_array(type.fetch("required"), "registry required", schema_name)
        field_set.each { |surface, values| validate_unique_array(values, "field set #{surface}", schema_name) }

        compare("field_parity", "#{schema_name}:registry", expected_fields, type.fetch("fields").sort)
        compare("field_ast_parity", "#{schema_name}:registry", expected_fields, type.fetch("field_definitions", {}).keys.sort)
        compare("required_parity", "#{schema_name}:registry", expected_required, type.fetch("required").sort)
        compare("patch_field_parity", "#{schema_name}:registry", expected_fields, type.fetch("patch_fields").sort)
        %w[ruby rbs openapi codec patch].each do |surface|
          compare("field_parity", "#{schema_name}:#{surface}", expected_fields, field_set.fetch(surface).sort)
        end
        expected_methods = expected_fields.filter_map { |field| RubernetesFieldParity.ruby_method(field) }.sort
        compare("dsl_method_parity", "#{schema_name}:dsl", expected_methods, field_set.fetch("dsl").sort)
      end
    end

    def verify_generated_sources
      @types.each do |schema_name, type|
        constant = type.fetch("ruby_constant")
        ruby_class = @ruby_classes[constant]
        rbs_class = @rbs_classes[constant]
        next unless ruby_class && rbs_class

        fields = properties_for(@definitions.fetch(schema_name), schema_name).keys.sort
        required = Array(@definitions.fetch(schema_name)["required"]).sort
        methods = fields.filter_map { |field| RubernetesFieldParity.ruby_method(field) }.sort
        compare("ruby_schema_name", constant, schema_name, ruby_class.fetch("schema"))
        compare("ruby_fields", constant, fields, ruby_class.fetch("fields").sort)
        compare("ruby_required", constant, required, ruby_class.fetch("required").sort)
        compare("ruby_methods", constant, methods, ruby_class.fetch("methods").keys.sort)
        compare("rbs_methods", constant, methods, rbs_class.fetch("methods").sort)

        ruby_class.fetch("methods").each do |method_name, field_name|
          if RubernetesFieldParity.reserved_methods.include?(method_name)
            issue("reserved_accessor", "#{constant}##{method_name}", "not reserved",
                  method_name)
          end
          expected_field = fields.find { |field| RubernetesFieldParity.ruby_method(field) == method_name }
          compare("accessor_target", "#{constant}##{method_name}", expected_field, field_name)
        end
      end

      manifest_methods = @manifest.fetch("methods")
      unless manifest_methods.is_a?(Hash)
        issue("invalid_manifest_methods", "manifest.methods", "Hash", manifest_methods.class.name)
        return
      end
      compare("manifest_method_inventory", "manifest.methods", @definitions.keys.sort, manifest_methods.keys.sort)
      @definitions.each do |schema_name, definition|
        expected = properties_for(definition, schema_name).keys.filter_map { |field| RubernetesFieldParity.ruby_method(field) }.sort
        actual = manifest_methods[schema_name]
        compare("manifest_methods", schema_name, expected, Array(actual).sort)
      end
    end

    def verify_gvks
      expected_type_gvks = []
      @definitions.each do |schema_name, definition|
        Array(definition["x-kubernetes-group-version-kind"]).each do |gvk|
          group = gvk.fetch("group")
          version = gvk.fetch("version")
          kind = gvk.fetch("kind")
          expected_type_gvks << {
            "group" => group,
            "version" => version,
            "kind" => kind,
            "identifier" => gvk_identifier(group, version, kind),
            "schema" => schema_name
          }
        end
      end
      validate_unique_records(expected_type_gvks, "identifier", "OpenAPI GVK")
      compare("type_gvk_count", "OpenAPI GVKs", EXPECTED_TYPE_GVK_COUNT, expected_type_gvks.length)

      actual_type_gvks = @types.values.flat_map do |type|
        type.fetch("gvks").map do |gvk|
          gvk.merge(
            "identifier" => gvk_identifier(gvk.fetch("group"), gvk.fetch("version"), gvk.fetch("kind")),
            "schema" => type.fetch("schema")
          )
        end
      end
      validate_unique_records(actual_type_gvks, "identifier", "registry type GVK")
      compare_records("type_gvk_parity", "registry type GVKs", expected_type_gvks, actual_type_gvks, "identifier")

      expected_all = expected_gvk_union(expected_type_gvks)
      actual_all = @registry.fetch("gvks")
      validate_unique_records(actual_all, "identifier", "registry GVK")
      compare("gvk_count", "canonical GVK union", EXPECTED_GVK_COUNT, expected_all.length)
      compare("gvk_count", "registry GVKs", EXPECTED_GVK_COUNT, actual_all.length)
      compare_records("gvk_parity", "registry GVKs", expected_all, actual_all, "identifier")
    end

    def verify_gvrs
      covered = @sources.dig("coverage", "covered_gvrs")
      unless covered.is_a?(Array) && covered.all? { |identifier| valid_identifier?(identifier) }
        issue("invalid_served_gvrs", "sources.coverage.covered_gvrs", "GVR identifier array", covered)
        return
      end
      validate_unique_array(covered, "covered GVR", "sources manifest")
      compare("served_gvr_count", "canonical discovery", EXPECTED_SERVED_GVR_COUNT, covered.length)

      actual = @registry.fetch("gvrs")
      validate_unique_records(actual, "identifier", "registry GVR")
      compare("served_gvr_count", "registry GVRs", EXPECTED_SERVED_GVR_COUNT, actual.length)
      compare("served_gvr_inventory", "registry GVRs", covered.sort, actual.map { |record| record.fetch("identifier") }.sort)
      actual.each do |record|
        expected_identifier = gvr_identifier(record.fetch("group"), record.fetch("version"), record.fetch("resource"))
        compare("gvr_identifier", record.fetch("identifier"), expected_identifier, record.fetch("identifier"))
      end

      compare("primary_gvr_count", "registry resources", EXPECTED_PRIMARY_GVR_COUNT, @resources.length)
      primary = []
      routes = []
      @resources.each do |resource|
        identifier = gvr_identifier(resource.fetch("group"), resource.fetch("version"), resource.fetch("resource"))
        primary << identifier
        routes << identifier
        Array(resource.fetch("subresources")).each do |subresource|
          routes << gvr_identifier(resource.fetch("group"), resource.fetch("version"),
                                   "#{resource.fetch("resource")}/#{subresource.fetch("resource")}")
        end
      end
      validate_unique_array(primary, "primary GVR", "registry resources")
      validate_unique_array(routes, "route GVR", "registry resources")
      compare("route_gvr_count", "registry resource routes", EXPECTED_ROUTE_GVR_COUNT, routes.length)
      missing_routes = routes.reject { |identifier| covered.include?(identifier) }
      compare("route_gvr_coverage", "registry resource routes", [], missing_routes.sort)
    end

    def verify_patch_metadata
      @resources.each do |resource|
        subject = gvr_identifier(resource.fetch("group"), resource.fetch("version"), resource.fetch("resource"))
        expected = patch_metadata(resource["schema"])
        %w[field_paths merge_keys patch_strategies].each do |field|
          compare("patch_metadata", "#{subject}:#{field}", expected.fetch(field), resource.fetch(field))
        end
      end
    end

    def verify_protobuf
      proto_root = File.join(corpus_root, "protobuf")
      registry = Rubernetes::Schema::Codec::ProtoDescriptor::Registry.load(proto_root, max_bytes: 8 * 1024 * 1024)
      capabilities = []
      supported_count = 0
      roundtrip_count = 0

      @definitions.keys.sort.each do |schema_name|
        expected_exception = PROTOBUF_EXCEPTIONS[schema_name]
        descriptor = resolve_proto(registry, schema_name)
        if expected_exception
          issue("unexpected_protobuf_support", schema_name, nil, descriptor.full_name) if descriptor
          capabilities << {
            "schema" => schema_name,
            "protobuf_supported" => false,
            "reason" => expected_exception
          }
          next
        end

        unless descriptor
          issue("missing_protobuf_descriptor", schema_name, "concrete descriptor", nil)
          capabilities << {"schema" => schema_name, "protobuf_supported" => false, "reason" => "descriptor missing"}
          next
        end
        supported_count += 1
        begin
          bytes = registry.encode(descriptor, {})
          decoded = registry.decode(descriptor, bytes)
          if decoded.respond_to?(:to_h) && decoded.to_h.empty?
            roundtrip_count += 1
          else
            issue("protobuf_roundtrip", schema_name, {}, decoded.respond_to?(:to_h) ? decoded.to_h : decoded)
          end
        rescue StandardError => error
          issue("protobuf_roundtrip", schema_name, "empty object roundtrip", "#{error.class}: #{error.message}")
        end
        capabilities << {
          "schema" => schema_name,
          "protobuf_supported" => true,
          "message" => descriptor.full_name
        }
      end

      compare("protobuf_exception_inventory", "protobuf unsupported schemas", PROTOBUF_EXCEPTIONS.keys.sort,
              capabilities.reject { |entry| entry.fetch("protobuf_supported") }.map { |entry| entry.fetch("schema") }.sort)
      compare("protobuf_supported_count", "protobuf descriptors", EXPECTED_TYPE_COUNT - PROTOBUF_EXCEPTIONS.length,
              supported_count)
      compare("protobuf_roundtrip_count", "protobuf empty concrete roundtrips",
              EXPECTED_TYPE_COUNT - PROTOBUF_EXCEPTIONS.length, roundtrip_count)
      @protobuf_report = {
        "descriptor_file_count" => registry.files.length,
        "descriptor_message_count" => registry.messages.length,
        "supported_count" => supported_count,
        "unsupported_count" => capabilities.length - supported_count,
        "roundtrip_count" => roundtrip_count,
        "capabilities" => capabilities
      }
    end

    def verify_manifest
      compare("manifest_type_count", "manifest.type_count", EXPECTED_TYPE_COUNT, @manifest["type_count"])
      compare("manifest_type_gvk_count", "manifest.type_gvk_count", EXPECTED_TYPE_GVK_COUNT, @manifest["type_gvk_count"])
      compare("manifest_gvk_count", "manifest.gvk_count", EXPECTED_GVK_COUNT, @manifest["gvk_count"])
      compare("manifest_gvr_count", "manifest.gvr_count", EXPECTED_SERVED_GVR_COUNT, @manifest["gvr_count"])
      compare("manifest_route_gvr_count", "manifest.route_gvr_count", EXPECTED_ROUTE_GVR_COUNT, @manifest["route_gvr_count"])

      artifacts = @manifest["artifacts"]
      unless artifacts.is_a?(Hash)
        issue("invalid_artifact_manifest", "manifest.artifacts", "Hash", artifacts.class.name)
        return
      end
      artifacts.each do |relative_path, expected_digest|
        path = File.join(generated_root, relative_path)
        actual_digest = Digest::SHA256.file(path).hexdigest
        compare("artifact_digest", relative_path, expected_digest, actual_digest)
      rescue Errno::ENOENT
        issue("artifact_digest", relative_path, expected_digest, nil)
      end
    end

    def expected_gvk_union(type_gvks)
      registrations = type_gvks.to_h { |record| [record.fetch("identifier"), record] }
      covered = @sources.dig("coverage", "covered_gvks")
      unless covered.is_a?(Array) && covered.all? { |identifier| valid_identifier?(identifier) }
        issue("invalid_covered_gvks", "sources.coverage.covered_gvks", "GVK identifier array", covered)
        return registrations.values.sort_by { |record| record.fetch("identifier") }
      end
      validate_unique_array(covered, "covered GVK", "sources manifest")
      covered.each do |identifier|
        next if registrations.key?(identifier)

        group, version, kind = identifier.split("/", 3)
        candidates = @types.values.select { |type| type.fetch("schema").split(".").last == kind }
        candidate = if candidates.length <= 1
                      candidates.first
                    elsif kind == "TokenRequest"
                      candidates.find { |type| type.fetch("schema").include?(".authentication.") }
                    end
        registrations[identifier] = {
          "identifier" => identifier,
          "group" => group == "core" ? "" : group,
          "version" => version,
          "kind" => kind,
          "schema" => candidate&.fetch("schema")
        }
      end
      registrations.values.sort_by { |record| record.fetch("identifier") }
    end

    def patch_metadata(root_schema)
      merge_keys = {}
      patch_strategies = {}
      field_paths = []
      visit = lambda do |schema_name, prefix, stack|
        next if schema_name.nil? || stack.include?(schema_name)

        schema = @definitions[schema_name]
        next unless schema

        properties_for(schema, schema_name).keys.sort.each do |field_name|
          field_schema = schema.fetch("properties").fetch(field_name)
          path = (prefix + [field_name]).join(".")
          field_paths << path
          merge_key = field_schema["x-kubernetes-patch-merge-key"] || Array(field_schema["x-kubernetes-list-map-keys"]).first
          merge_keys[path] = merge_key if merge_key
          strategy = field_schema["x-kubernetes-patch-strategy"]
          patch_strategies[path] = strategy if strategy
          reference = field_schema["$ref"] || field_schema.dig("items", "$ref")
          next unless reference&.start_with?("#/definitions/")

          visit.call(reference.delete_prefix("#/definitions/"), prefix + [field_name], stack + [schema_name])
        end
      end
      visit.call(root_schema, [], [])
      {
        "field_paths" => field_paths.sort,
        "merge_keys" => merge_keys.sort.to_h,
        "patch_strategies" => patch_strategies.sort.to_h
      }
    end

    def resolve_proto(registry, schema_name)
      direct = registry.resolve_schema(schema_name)
      return direct if direct

      proto_name = schema_name.sub(/\Aio\.k8s\./, "k8s.io.").tr("-", "_")
      registry.messages[proto_name]
    end

    def parse_ruby_classes(source)
      class_names = source.scan(/^    class (\w+) < Rubernetes::Schema::ValueObject$/).flatten
      duplicate_values(class_names).each { |name| issue("duplicate_ruby_class", name, "unique", class_names.count(name)) }
      blocks = {}
      source.scan(/^    class (\w+) < Rubernetes::Schema::ValueObject\n(.*?)^    end$/m) do |constant, body|
        schema_matches = body.scan(/^      SCHEMA_NAME = ("(?:\\.|[^"])*")\.freeze$/).flatten
        fields_matches = body.scan(/^      FIELDS = (\[.*\])\.freeze$/).flatten
        required_matches = body.scan(/^      REQUIRED_FIELDS = (\[.*\])\.freeze$/).flatten
        field_definition_count = body.scan(/^      FIELD_DEFINITIONS = Rubernetes::Schema::DeepFreeze\.call\(/).length
        definition_count = body.scan(/^      DEFINITION = Rubernetes::Schema::Definition\.new\($/).length
        unless schema_matches.length == 1 && fields_matches.length == 1 && required_matches.length == 1 &&
               field_definition_count == 1 && definition_count == 1
          issue("malformed_ruby_class", constant, "one schema/fields/required/field AST/definition declaration",
                [schema_matches.length, fields_matches.length, required_matches.length, field_definition_count, definition_count])
          next
        end
        method_names = body.scan(/^      def (\S+)$/).flatten
        methods = {}
        body.scan(/^      def (\S+)\n        field\(("(?:\\.|[^"])*")\)\n      end$/) do |method_name, field_literal|
          if methods.key?(method_name)
            issue("duplicate_ruby_method", "#{constant}##{method_name}", "unique", 2)
          else
            methods[method_name] = JSON.parse(field_literal)
          end
        end
        compare("ruby_method_shape", constant, method_names.sort, methods.keys.sort)
        blocks[constant] = {
          "schema" => JSON.parse(schema_matches.first),
          "fields" => JSON.parse(fields_matches.first),
          "required" => JSON.parse(required_matches.first),
          "methods" => methods
        }
      rescue JSON::ParserError => error
        issue("malformed_ruby_literal", constant, "JSON-compatible generated literal", error.message)
      end
      blocks
    end

    def parse_rbs_classes(source)
      class_names = source.scan(/^    class (\w+) < Rubernetes::Schema::ValueObject$/).flatten
      duplicate_values(class_names).each { |name| issue("duplicate_rbs_class", name, "unique", class_names.count(name)) }
      blocks = {}
      source.scan(/^    class (\w+) < Rubernetes::Schema::ValueObject\n(.*?)^    end$/m) do |constant, body|
        methods = body.scan(/^      def (\S+): \(\) -> untyped$/).flatten
        duplicate_values(methods).each { |name| issue("duplicate_rbs_method", "#{constant}##{name}", "unique", methods.count(name)) }
        methods.each do |method_name|
          if RubernetesFieldParity.reserved_methods.include?(method_name)
            issue("reserved_accessor", "#{constant}##{method_name}", "not reserved",
                  method_name)
          end
        end
        blocks[constant] = {"methods" => methods}
      end
      blocks
    end

    def parse_json(path, label)
      JSON.parse(read_file(path), object_class: DuplicateCheckingHash, allow_nan: false)
    rescue DuplicateKeyError => error
      raise Error, "#{label} contains #{error.message}"
    end

    def read_file(path)
      File.binread(path).force_encoding(Encoding::UTF_8).tap do |text|
        raise Error, "#{path} is not valid UTF-8" unless text.valid_encoding?
      end
    end

    def properties_for(definition, schema_name)
      properties = definition.fetch("properties", {})
      raise Error, "#{schema_name}.properties must be an object" unless properties.is_a?(Hash)

      properties
    end

    def index_unique(records, field, label)
      result = {}
      records.each do |record|
        raise Error, "#{label} must be an object" unless record.is_a?(Hash)

        key = record.fetch(field)
        issue("duplicate_#{field}", "#{label}:#{key}", "unique", 2) if result.key?(key)
        result[key] ||= record
      end
      result
    end

    def validate_unique_array(values, label, subject)
      unless values.is_a?(Array)
        issue("invalid_array", "#{subject}:#{label}", "Array", values.class.name)
        return
      end
      duplicate_values(values).each { |value| issue("duplicate_value", "#{subject}:#{label}", "unique", value) }
    end

    def validate_unique_records(records, field, label)
      unless records.is_a?(Array)
        issue("invalid_records", label, "Array", records.class.name)
        return
      end
      values = records.map { |record| record.fetch(field) }
      duplicate_values(values).each { |value| issue("duplicate_#{field}", "#{label}:#{value}", "unique", values.count(value)) }
    rescue KeyError => error
      issue("invalid_record", label, field, error.message)
    end

    def duplicate_values(values)
      values.group_by(&:itself).select { |_value, copies| copies.length > 1 }.keys
    end

    def compare_records(code, subject, expected, actual, key)
      expected_index = expected.to_h { |record| [record.fetch(key), record] }
      actual_index = actual.to_h { |record| [record.fetch(key), record] }
      compare(code, subject, expected_index, actual_index)
    rescue KeyError => error
      issue(code, subject, "records containing #{key}", error.message)
    end

    def compare(code, subject, expected, actual)
      issue(code, subject, expected, actual) unless expected == actual
    end

    def issue(code, subject, expected, actual)
      @issues << {"code" => code, "subject" => subject.to_s, "expected" => expected, "actual" => actual}
    end

    def valid_identifier?(identifier)
      identifier.is_a?(String) && identifier.split("/").length >= 3 &&
        identifier.split("/").none?(&:empty?)
    end

    def gvk_identifier(group, version, kind)
      "#{group.to_s.empty? ? "core" : group}/#{version}/#{kind}"
    end

    def gvr_identifier(group, version, resource)
      "#{group.to_s.empty? ? "core" : group}/#{version}/#{resource}"
    end

    def report
      {
        "schema_version" => 1,
        "passed" => issues.empty?,
        "counts" => {
          "types" => @definitions&.length,
          "type_gvks" => @types&.values&.sum { |type| Array(type["gvks"]).length },
          "gvks" => @registry&.dig("gvks")&.length,
          "primary_gvrs" => @resources&.length,
          "served_gvrs" => @registry&.dig("gvrs")&.length,
          "route_gvrs" => @resources&.sum { |resource| 1 + Array(resource["subresources"]).length }
        },
        "protobuf" => @protobuf_report,
        "issue_count" => issues.length,
        "issues" => issues
      }
    end
  end

  def atomic_write(path, bytes)
    FileUtils.mkdir_p(File.dirname(path))
    raise Error, "refusing to overwrite symlink: #{path}" if File.symlink?(path)

    temporary = Tempfile.new([".#{File.basename(path)}.", ".tmp"], File.dirname(path))
    temporary.binmode
    temporary.write(bytes)
    temporary.flush
    temporary.fsync
    temporary.close
    File.rename(temporary.path, path)
  ensure
    temporary&.close!
  end

  def run!(argv = ARGV)
    options = {root: ROOT, corpus_root: nil, generated_root: nil, output: nil, pretty: false}
    parser = OptionParser.new do |opts|
      opts.banner = "Usage: ruby tools/schema/field_parity.rb [--check] [--output PATH]"
      opts.on("--check", "verify parity and exit non-zero on any difference") {}
      opts.on("--root PATH", "repository root") { |value| options[:root] = value }
      opts.on("--corpus-root PATH", "canonical Kubernetes corpus root") { |value| options[:corpus_root] = value }
      opts.on("--generated-root PATH", "generated artifact root") { |value| options[:generated_root] = value }
      opts.on("--output PATH", "atomically write the JSON report") { |value| options[:output] = value }
      opts.on("--pretty", "pretty-print JSON on stdout") { options[:pretty] = true }
    end
    parser.parse!(argv)
    report = Verifier.new(root: options.fetch(:root), corpus_root: options[:corpus_root],
                          generated_root: options[:generated_root]).verify
    bytes = if options.fetch(:pretty)
              JSON.pretty_generate(report) << "\n"
            else
              canonical_json(report)
            end
    options[:output] ? atomic_write(File.expand_path(options[:output]), bytes) : $stdout.write(bytes)
    report.fetch("passed") ? 0 : 1
  rescue Error, OptionParser::ParseError => error
    warn "field parity verification failed: #{error.message}"
    1
  end
end

exit RubernetesFieldParity.run! if $PROGRAM_NAME == __FILE__
