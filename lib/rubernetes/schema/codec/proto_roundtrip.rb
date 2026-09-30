# frozen_string_literal: true

require "digest"
require "json"

require_relative "proto_descriptor"

module Rubernetes
  module Schema
    class Codec
      module ProtoDescriptor
        # Runs a deterministic, exhaustive round-trip over the canonical
        # OpenAPI definition set and emits a JSON-safe evidence report.
        #
        # This verifies generic protobuf descriptor wire behavior.  It does not
        # claim generator-specific gogoproto custom marshaling or semantic JSON
        # transformations such as base64 bytes, Quantity, Time, or RawExtension.
        class RoundtripCoverage
          FORMAT = "rubernetes.protobuf-concrete-roundtrip.v1"
          DEFAULT_EXPECTED_SCHEMA_COUNT = 771
          DEFAULT_EXPECTED_SUPPORTED_SCHEMA_COUNT = 770
          DEFAULT_UNSUPPORTED_SCHEMAS = {
            "io.k8s.apimachinery.pkg.version.Info" =>
              "Kubernetes v1.36.2 publishes this OpenAPI schema without an upstream generated.proto descriptor."
          }.freeze
          UNKNOWN_PAYLOAD = "rubernetes-unknown-wire".b.freeze
          DEFAULT_MAX_SAMPLE_DEPTH = 3

          COMPATIBILITY = {
            "level" => "generic_descriptor_wire",
            "guarantees" => [
              "canonical generated.proto descriptor parsing",
              "deterministic scalar/map/repeated/nested concrete wire encoding",
              "runtime.Unknown k8s\\u0000 envelope framing",
              "unknown concrete field byte preservation"
            ].freeze,
            "exclusions" => [
              "gogoproto generator-specific custom marshalers",
              "protobuf JSON semantic conversion for bytes and well-known values",
              "semantic Time, Quantity, IntOrString, and RawExtension conversion",
              "unknown fields inside synthetic map-entry messages"
            ].freeze,
            "enum_note" => "The pinned Kubernetes generated.proto corpus declares no protobuf enums; enum sampling remains supported when descriptors declare them."
          }.freeze

          class CoverageError < Error
            attr_reader :report

            def initialize(report)
              @report = report
              failures = report.fetch("failures")
              detail = failures.first(3).map { |failure| "#{failure.fetch("schema", "corpus")}: #{failure.fetch("message")}" }.join("; ")
              suffix = failures.length > 3 ? "; and #{failures.length - 3} more" : ""
              super("protobuf round-trip coverage failed (#{failures.length} failures): #{detail}#{suffix}")
            end
          end

          attr_reader :openapi_path, :protobuf_root, :expected_schema_count,
                      :expected_supported_schema_count, :unsupported_schemas,
                      :max_bytes, :max_depth, :max_sample_depth

          def self.run(**)
            new(**).run
          end

          def self.run!(**)
            new(**).run!
          end

          def initialize(openapi_path:, protobuf_root:,
                         expected_schema_count: DEFAULT_EXPECTED_SCHEMA_COUNT,
                         expected_supported_schema_count: DEFAULT_EXPECTED_SUPPORTED_SCHEMA_COUNT,
                         unsupported_schemas: DEFAULT_UNSUPPORTED_SCHEMAS,
                         max_bytes: Codec::DEFAULT_MAX_BYTES,
                         max_depth: Codec::DEFAULT_MAX_DEPTH,
                         max_sample_depth: DEFAULT_MAX_SAMPLE_DEPTH)
            @openapi_path = ::File.expand_path(String(openapi_path))
            @protobuf_root = ::File.expand_path(String(protobuf_root))
            @expected_schema_count = expected_schema_count.nil? ? nil : Integer(expected_schema_count)
            @expected_supported_schema_count = expected_supported_schema_count.nil? ? nil : Integer(expected_supported_schema_count)
            @unsupported_schemas = unsupported_schemas.each_with_object({}) do |(schema, reason), result|
              result[String(schema)] = String(reason)
            end.freeze
            @max_bytes = Integer(max_bytes)
            @max_depth = Integer(max_depth)
            @max_sample_depth = Integer(max_sample_depth)
            raise ArgumentError, "expected_schema_count must be non-negative" if @expected_schema_count&.negative?
            raise ArgumentError, "expected_supported_schema_count must be non-negative" if @expected_supported_schema_count&.negative?
            raise ArgumentError, "max_bytes must be positive" unless @max_bytes.positive?
            raise ArgumentError, "max_depth must be non-negative" if @max_depth.negative?
            raise ArgumentError, "max_sample_depth must be non-negative" if @max_sample_depth.negative?
          end

          def run
            return @report if defined?(@report) && @report

            openapi_bytes = ::File.binread(openapi_path)
            openapi = Codec::JSONCodec.load(openapi_bytes, max_bytes: max_bytes, max_depth: max_depth)
            definitions = openapi.fetch("definitions") do
              raise CoverageError, failure_report("OpenAPI document has no definitions")
            end
            raise CoverageError, failure_report("OpenAPI definitions must be an object") unless definitions.is_a?(Hash)

            registry = Registry.load(protobuf_root, max_bytes: max_bytes, max_depth: max_depth)
            schema_names = definitions.keys.sort
            failures = []
            if expected_schema_count && schema_names.length != expected_schema_count
              failures << failure("corpus", "schema_count",
                                  "expected #{expected_schema_count} OpenAPI schemas, found #{schema_names.length}")
            end

            resolved = {}
            unsupported = []
            unsupported_schemas.each do |schema_name, reason|
              if definitions.key?(schema_name)
                unsupported << {"schema" => schema_name, "capability" => "concrete_protobuf", "reason" => reason}.freeze
              else
                failures << failure(schema_name, "unsupported_declaration",
                                    "declared unsupported schema is absent from OpenAPI")
              end
            end
            schema_names.each do |schema_name|
              next if unsupported_schemas.key?(schema_name)

              descriptor = registry.resolve(schema_name)
              if descriptor
                resolved[schema_name] = descriptor
              else
                failures << failure(schema_name, "descriptor_resolution",
                                    "OpenAPI schema has no concrete protobuf descriptor")
              end
            end
            if expected_supported_schema_count && resolved.length != expected_supported_schema_count
              failures << failure("corpus", "supported_schema_count",
                                  "expected #{expected_supported_schema_count} supported schemas, resolved #{resolved.length}")
            end

            coverage = empty_coverage
            cases = []
            resolved.each do |schema_name, descriptor|
              result = run_case(registry, schema_name, descriptor)
              cases << result
              merge_coverage!(coverage, result.fetch("field_kinds"))
              coverage["empty_cases"] += 1
              coverage["sample_cases"] += 1
              coverage["unknown_wire_cases"] += 1
            rescue StandardError => error
              failures << failure(schema_name, "roundtrip", error.message, error.class.name)
            end

            report = {
              "format" => FORMAT,
              "success" => failures.empty? && resolved.length + unsupported.length == schema_names.length,
              "input_sha256" => input_digest(openapi_bytes),
              "schema_count" => schema_names.length,
              "resolved_count" => resolved.length,
              "unsupported_count" => unsupported.length,
              "case_count" => cases.length,
              "failure_count" => failures.length,
              "coverage" => coverage,
              "compatibility" => COMPATIBILITY,
              "unsupported" => unsupported,
              "failures" => failures,
              "cases" => cases
            }
            @report = deep_freeze(report)
          rescue CoverageError
            raise
          rescue StandardError => error
            raise CoverageError, failure_report(error.message, error.class.name)
          end

          def run!
            report = run
            raise CoverageError, report unless report.fetch("success")

            report
          end

          def generate_json(strict: true, pretty: false)
            report = strict ? run! : run
            pretty ? ::JSON.pretty_generate(report) : Codec::JSONCodec.dump(report, canonical: true, max_bytes: max_bytes)
          end

          alias to_json_report generate_json

          # Exposed for external oracle adapters.  The returned object is the
          # exact deterministic all-field sample used by this coverage runner.
          def sample_for(registry, descriptor)
            descriptor = registry.fetch(descriptor)
            deep_freeze(sample_message(registry, descriptor))
          end

          def unknown_field_number_for(descriptor)
            unknown_field_number(descriptor)
          end

          private

          def run_case(registry, schema_name, descriptor)
            empty = verify_value_roundtrip(registry, descriptor, {})
            sample = sample_message(registry, descriptor)
            sample_result = verify_value_roundtrip(registry, descriptor, sample)
            concrete = sample_result.fetch(:concrete)
            clean_envelope = sample_result.fetch(:envelope)
            unknown_number = unknown_field_number(descriptor)
            unknown_field = Codec::Protobuf.encode_field(unknown_number, UNKNOWN_PAYLOAD, type: :bytes)
            runtime_unknown = Codec::Protobuf.decode_envelope(clean_envelope)
            raw_with_unknown = concrete + unknown_field
            envelope_with_unknown = Codec::Protobuf.encode_envelope(
              raw: raw_with_unknown,
              type_meta: runtime_unknown.type_meta,
              content_encoding: runtime_unknown.content_encoding,
              content_type: runtime_unknown.content_type,
              max_bytes: max_bytes,
              max_depth: max_depth
            )
            decoded_unknown = registry.decode_envelope(descriptor, envelope_with_unknown,
                                                       max_bytes: max_bytes, max_depth: max_depth)
            preserved = decoded_unknown.unknown_fields.any? do |field|
              field[:number] == unknown_number && field[:encoded] == unknown_field
            end
            raise Codec::ParseError, "unknown concrete field #{unknown_number} was not retained" unless preserved
            unless registry.encode(descriptor, decoded_unknown, max_bytes: max_bytes, max_depth: max_depth) == raw_with_unknown
              raise Codec::EncodeError, "unknown concrete field bytes changed during re-encode"
            end
            unless registry.encode_envelope(descriptor, decoded_unknown, max_bytes: max_bytes,
                                                                         max_depth: max_depth) == envelope_with_unknown
              raise Codec::EncodeError, "runtime.Unknown envelope bytes changed during re-encode"
            end

            wire_numbers = Codec::Protobuf.parse_fields(concrete, max_bytes: max_bytes, max_depth: max_depth).map do |field|
              field.fetch(:number)
            end.uniq
            omitted = descriptor.fields.reject { |field| wire_numbers.include?(field.number) }
            raise Codec::EncodeError, "deterministic sample omitted fields: #{omitted.map(&:name).join(", ")}" unless omitted.empty?

            {
              "schema" => schema_name,
              "message" => descriptor.full_name,
              "field_count" => descriptor.fields.length,
              "field_kinds" => field_kinds(descriptor),
              "empty_json_sha256" => empty.fetch(:json_sha256),
              "empty_concrete_sha256" => empty.fetch(:concrete_sha256),
              "sample_json_sha256" => sample_result.fetch(:json_sha256),
              "sample_concrete_sha256" => sample_result.fetch(:concrete_sha256),
              "sample_envelope_sha256" => sample_result.fetch(:envelope_sha256),
              "unknown_field_number" => unknown_number,
              "unknown_wire_preserved" => true
            }.freeze
          end

          def verify_value_roundtrip(registry, descriptor, value)
            source_json = Codec::JSONCodec.dump(value, canonical: true, max_bytes: max_bytes, max_depth: max_depth)
            json_value = Codec::JSONCodec.load(source_json, max_bytes: max_bytes, max_depth: max_depth)
            concrete = registry.encode(descriptor, json_value, max_bytes: max_bytes, max_depth: max_depth)
            second_concrete = registry.encode(descriptor, json_value, max_bytes: max_bytes, max_depth: max_depth)
            raise Codec::EncodeError, "concrete protobuf encoding is not deterministic" unless concrete == second_concrete

            envelope = registry.encode_envelope(descriptor, json_value, max_bytes: max_bytes, max_depth: max_depth)
            decoded = registry.decode_envelope(descriptor, envelope, max_bytes: max_bytes, max_depth: max_depth)
            decoded_json = Codec::JSONCodec.dump(decoded, canonical: true, max_bytes: max_bytes, max_depth: max_depth)
            raise Codec::ParseError, "JSON/concrete protobuf round-trip mismatch" unless decoded_json == source_json
            unless registry.encode_envelope(descriptor, decoded, max_bytes: max_bytes, max_depth: max_depth) == envelope
              raise Codec::EncodeError, "runtime.Unknown envelope encoding is not deterministic"
            end

            {
              concrete: concrete,
              envelope: envelope,
              json_sha256: Digest::SHA256.hexdigest(source_json),
              concrete_sha256: Digest::SHA256.hexdigest(concrete),
              envelope_sha256: Digest::SHA256.hexdigest(envelope)
            }.freeze
          end

          def sample_message(registry, descriptor, depth: 0, ancestors: [])
            descriptor.fields.each_with_object({}) do |field, result|
              result[field.json_name] = sample_field(registry, field, depth: depth, ancestors: ancestors + [descriptor.full_name])
            end
          end

          def sample_field(registry, field, depth:, ancestors:)
            if field.map?
              value = if field.value_type_kind == :scalar
                        sample_scalar(field.value_type)
                      else
                        sample_nested(registry, registry.type_for(field), depth: depth, ancestors: ancestors)
                      end
              return {sample_map_key(field.key_type) => value}
            end

            value = if field.scalar?
                      sample_scalar(field.type)
                    elsif field.enum?
                      enum = registry.type_for(field)
                      enum.values.first&.number || 0
                    else
                      sample_nested(registry, registry.type_for(field), depth: depth, ancestors: ancestors)
                    end
            field.repeated? ? [value] : value
          end

          def sample_nested(registry, descriptor, depth:, ancestors:)
            return {} if depth >= max_sample_depth || ancestors.include?(descriptor.full_name)

            sample_message(registry, descriptor, depth: depth + 1, ancestors: ancestors)
          end

          def sample_scalar(type)
            case type.to_sym
            # Numeric text and non-negative signed values remain valid for
            # Kubernetes custom protobuf types such as Quantity and Time while
            # still exercising every scalar wire kind deterministically.
            when :string then "1"
            when :bytes then "bytes"
            when :bool then true
            when :double, :float then 1.5
            when :int32, :int64, :sint32, :sint64, :sfixed32, :sfixed64 then 7
            when :uint32, :uint64, :fixed32, :fixed64, :enum then 7
            else
              raise UnsupportedTypeError, "no deterministic sample for scalar #{type.inspect}"
            end
          end

          def sample_map_key(type)
            case type.to_sym
            when :string then "key"
            when :bool then "true"
            else "1"
            end
          end

          def field_kinds(descriptor)
            kinds = {
              "fields" => descriptor.fields.length,
              "scalar_fields" => 0,
              "map_fields" => 0,
              "repeated_fields" => 0,
              "nested_fields" => 0,
              "enum_fields" => 0
            }
            descriptor.fields.each do |field|
              kinds["map_fields"] += 1 if field.map?
              kinds["repeated_fields"] += 1 if field.repeated?
              kinds["scalar_fields"] += 1 if field.scalar? && !field.map?
              kinds["nested_fields"] += 1 if field.message? && !field.map?
              kinds["enum_fields"] += 1 if field.enum?
            end
            kinds.freeze
          end

          def empty_coverage
            {
              "empty_cases" => 0,
              "sample_cases" => 0,
              "unknown_wire_cases" => 0,
              "fields" => 0,
              "scalar_fields" => 0,
              "map_fields" => 0,
              "repeated_fields" => 0,
              "nested_fields" => 0,
              "enum_fields" => 0
            }
          end

          def merge_coverage!(coverage, kinds)
            kinds.each { |key, value| coverage[key] += value }
          end

          def unknown_field_number(descriptor)
            used = descriptor.fields_by_number
            number = MAX_FIELD_NUMBER
            number -= 1 while used.key?(number)
            raise Codec::EncodeError, "no protobuf field number available for unknown-field coverage" if number <= 0

            number
          end

          def input_digest(openapi_bytes)
            digest = Digest::SHA256.new
            digest << "openapi/swagger.json\0" << openapi_bytes
            descriptor_paths.each do |path|
              relative = path.delete_prefix("#{protobuf_root}/")
              digest << relative << "\0" << ::File.binread(path)
            end
            digest.hexdigest
          end

          def descriptor_paths
            Dir.glob(::File.join(protobuf_root, "**", "*.proto")).select { |path| ::File.file?(path) }.sort
          end

          def failure(schema, stage, message, error_class = nil)
            result = {"schema" => schema, "stage" => stage, "message" => String(message)}
            result["error_class"] = error_class if error_class
            result.freeze
          end

          def failure_report(message, error_class = nil)
            {
              "format" => FORMAT,
              "success" => false,
              "schema_count" => 0,
              "resolved_count" => 0,
              "unsupported_count" => 0,
              "case_count" => 0,
              "failure_count" => 1,
              "coverage" => empty_coverage,
              "compatibility" => COMPATIBILITY,
              "unsupported" => [],
              "failures" => [failure("corpus", "input", message, error_class)],
              "cases" => []
            }
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

        Roundtrip = RoundtripCoverage
        ExhaustiveRoundtrip = RoundtripCoverage

        class << self
          def roundtrip_report(**)
            RoundtripCoverage.run!(**)
          end
        end
      end
    end
  end
end
