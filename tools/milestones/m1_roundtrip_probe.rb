#!/usr/bin/env ruby
# frozen_string_literal: true

# Exercise every generated schema type through JSON and concrete Kubernetes
# protobuf codecs. Missing protobuf descriptors are recorded as failed cases;
# the probe never substitutes the generic runtime.Unknown envelope for a
# concrete message.

require "base64"

require_relative "m1_probe_support"
require_relative "m1_kubernetes_protobuf_oracle"
require_relative "m1_kubernetes_semantic_oracle"
require_relative "m1_kubernetes_validation_oracle"
require_relative "m1_gate"

$LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
require "rubernetes/schema"
require "rubernetes/schema/codec/proto_roundtrip"
require File.join(ROOT, "generated/ruby/kubernetes_types")

UPSTREAM_PROTOBUF_UNSUPPORTED = {
  "io.k8s.apimachinery.pkg.version.Info" =>
    "Kubernetes v1.36.2 does not publish a generated.proto descriptor for this OpenAPI type"
}.freeze
KUBERNETES_SOURCE_ROOT = ENV.fetch(
  "RUBERNETES_KUBERNETES_SOURCE",
  "/tmp/kubernetes-v1.36.2"
).freeze
ORACLE_UNKNOWN_PAYLOAD = "rubernetes-m1-oracle-unknown".b.freeze
ORACLE_MALFORMED_WIRE = "\x0a\x80".b.freeze
MINIMAL_SAMPLE_MAX_DEPTH = 16

def generated_class(type)
  Rubernetes::Generated.const_get(type.fetch("ruby_constant"), false)
rescue NameError => error
  raise M1ProbeSupport::ProbeError,
        "generated class #{type.fetch("ruby_constant").inspect} is missing: #{error.message}"
end

def type_backed_gvks(types)
  types.flat_map do |type|
    Array(type.fetch("gvks")).map do |gvk|
      M1ProbeSupport.identifier(gvk.fetch("group", ""), gvk.fetch("version"), gvk.fetch("kind"))
    end
  end.uniq.sort
end

def minimal_required_values(type, types_by_schema, depth: 0, ancestors: [], include_zero_references: false)
  schema_name = type.fetch("schema")
  return {} if depth >= MINIMAL_SAMPLE_MAX_DEPTH || ancestors.include?(schema_name)

  definitions = type.fetch("field_definitions", {})
  result = Array(type.fetch("required", [])).each_with_object({}) do |name, values|
    field = definitions.fetch(name) do
      raise M1ProbeSupport::ProbeError, "required field #{schema_name}.#{name} has no definition"
    end
    values[name] = minimal_field_value(
      field,
      types_by_schema,
      depth: depth + 1,
      ancestors: ancestors + [schema_name],
      include_zero_references: include_zero_references
    )
  end
  return result unless include_zero_references

  # Kubernetes versioned API structs use value-typed nested objects for many
  # fields (`json:",omitempty"` does not omit a non-pointer struct).  The
  # OpenAPI corpus records the reference edge but not Go's pointer/value
  # distinction, so the semantic fixture intentionally materializes the
  # zero-value object graph.  Arrays/maps remain omitted because their nil
  # zero value is omitted by encoding/json.
  definitions.each do |name, field|
    next if result.key?(name) || field["type"] != "reference"

    reference = field.fetch("reference")
    target = types_by_schema.fetch(reference) do
      raise M1ProbeSupport::ProbeError, "reference #{reference.inspect} is absent from the generated registry"
    end
    result[name] = minimal_required_values(
      target,
      types_by_schema,
      depth: depth + 1,
      ancestors: ancestors + [schema_name],
      include_zero_references: true
    )
  end
  result
end

def minimal_field_value(field, types_by_schema, depth:, ancestors:, include_zero_references: false)
  type = field.fetch("type")
  case type
  when "reference"
    reference = field.fetch("reference")
    target = types_by_schema.fetch(reference) do
      raise M1ProbeSupport::ProbeError, "required reference #{reference.inspect} is absent from the generated registry"
    end
    minimal_required_values(
      target,
      types_by_schema,
      depth: depth,
      ancestors: ancestors,
      include_zero_references: include_zero_references
    )
  when "array"
    [minimal_field_value(
      field.fetch("items"),
      types_by_schema,
      depth: depth + 1,
      ancestors: ancestors,
      include_zero_references: include_zero_references
    )]
  when "object"
    additional = field["additional_properties"]
    if additional
      {"key" => minimal_field_value(
        additional,
        types_by_schema,
        depth: depth + 1,
        ancestors: ancestors,
        include_zero_references: include_zero_references
      )}
    else
      {}
    end
  when "string"
    case field["schema_reference"]
    when "io.k8s.apimachinery.pkg.apis.meta.v1.MicroTime"
      "1970-01-01T00:00:00.000000Z"
    else
      case field["format"]
      when "date-time" then "1970-01-01T00:00:00Z"
      when "byte" then Base64.strict_encode64("m1")
      else "1"
      end
    end
  when "integer" then 1
  when "number" then 1.0
  when "boolean" then true
  when "null" then nil
  else
    raise M1ProbeSupport::ProbeError, "unsupported required OpenAPI field type #{type.inspect}"
  end
end

def build_oracle_request(registry, runner, schema_name, descriptor_name)
  descriptor = registry.fetch(descriptor_name)
  sample = runner.sample_for(registry, descriptor)
  raw = registry.encode(descriptor, sample)
  unknown_number = runner.unknown_field_number_for(descriptor)
  unknown = Rubernetes::Schema::Codec::Protobuf.encode_field(
    unknown_number,
    ORACLE_UNKNOWN_PAYLOAD,
    type: :bytes
  )
  clean_envelope = registry.encode_envelope(descriptor, sample)
  outer = Rubernetes::Schema::Codec::Protobuf.decode_envelope(clean_envelope)
  envelope_with_unknown = Rubernetes::Schema::Codec::Protobuf.encode_envelope(
    raw: raw + unknown,
    type_meta: outer.type_meta,
    content_encoding: outer.content_encoding,
    content_type: outer.content_type
  )
  request = {
    "id" => schema_name,
    "descriptor" => descriptor.full_name,
    "raw" => Base64.strict_encode64(raw),
    "raw_with_unknown" => Base64.strict_encode64(raw + unknown),
    "envelope_with_unknown" => Base64.strict_encode64(envelope_with_unknown)
  }
  local = {
    descriptor: descriptor,
    raw: raw,
    raw_with_unknown: raw + unknown,
    envelope_with_unknown: envelope_with_unknown,
    unknown_number: unknown_number
  }
  [request, local]
end

def oracle_observable_sha256(parts)
  payload = parts.sort.to_h do |name, value|
    encoded = value.is_a?(String) ? ["bytes", Base64.strict_encode64(value.b)] : ["json", value]
    [name, encoded]
  end
  Digest::SHA256.hexdigest(JSON.generate(payload))
end

def compare_oracle_case(registry, local, result)
  errors = []
  if result["error"]
    errors << "upstream generated protobuf: #{result.fetch("error")}"
    expected_sha = Digest::SHA256.hexdigest("upstream generated protobuf success")
    actual_sha = Digest::SHA256.hexdigest(result.fetch("error"))
    return {
      "id" => result.fetch("id"), "attempt_count" => 1, "passed" => false,
      "expected_source" => "kubernetes_external", "actual_source" => "rubernetes",
      "expected_sha256" => expected_sha, "actual_sha256" => actual_sha,
      "errors" => errors
    }
  end

  descriptor = local.fetch(:descriptor)
  known = Base64.strict_decode64(result.fetch("known_remarshal"))
  second_known = Base64.strict_decode64(result.fetch("known_second_remarshal"))
  unknown = Base64.strict_decode64(result.fetch("unknown_remarshal"))
  zero = Base64.strict_decode64(result.fetch("zero_marshal"))
  envelope = Base64.strict_decode64(result.fetch("envelope_remarshal"))
  envelope_raw = Base64.strict_decode64(result.fetch("envelope_raw"))

  ruby_known = registry.encode(
    descriptor,
    registry.decode(descriptor, known, compatibility: :kubernetes)
  )
  ruby_unknown_value = registry.decode(
    descriptor,
    local.fetch(:raw_with_unknown),
    compatibility: :kubernetes
  )
  ruby_unknown = registry.encode(descriptor, ruby_unknown_value)
  ruby_unknown_numbers = Rubernetes::Schema::Codec::Protobuf.parse_fields(ruby_unknown).map do |field|
    field.fetch(:number)
  end
  ruby_zero = registry.encode(
    descriptor,
    registry.decode(descriptor, zero, compatibility: :kubernetes)
  )
  ruby_malformed_rejected = begin
    registry.decode(descriptor, ORACLE_MALFORMED_WIRE, compatibility: :kubernetes)
    false
  rescue Rubernetes::Schema::Codec::Error
    true
  end
  ruby_unknown_discarded = ruby_unknown_value.unknown_fields.empty? &&
                           !ruby_unknown_numbers.include?(local.fetch(:unknown_number))

  expected = {
    "go_canonical_concrete" => known,
    "ruby_upstream_concrete" => known,
    "go_unknown_discard" => known,
    "ruby_unknown_discard" => true,
    "runtime_unknown_envelope" => local.fetch(:envelope_with_unknown),
    "runtime_unknown_raw" => local.fetch(:raw_with_unknown),
    "zero_value_serializer" => zero,
    "go_malformed_wire_rejected" => true,
    "ruby_malformed_wire_rejected" => true
  }
  actual = {
    "go_canonical_concrete" => second_known,
    "ruby_upstream_concrete" => ruby_known,
    "go_unknown_discard" => unknown,
    "ruby_unknown_discard" => ruby_unknown_discarded,
    "runtime_unknown_envelope" => envelope,
    "runtime_unknown_raw" => envelope_raw,
    "zero_value_serializer" => ruby_zero,
    "go_malformed_wire_rejected" => result.fetch("malformed_wire_rejected"),
    "ruby_malformed_wire_rejected" => ruby_malformed_rejected
  }
  expected.each do |name, expected_value|
    errors << "#{name} differs from Kubernetes v1.36.2" unless actual.fetch(name) == expected_value
  end
  expected_sha = oracle_observable_sha256(expected)
  actual_sha = oracle_observable_sha256(actual)
  {
    "id" => result.fetch("id"),
    "go_type" => result.fetch("go_type"),
    "attempt_count" => 1,
    "passed" => errors.empty? && expected_sha == actual_sha,
    "expected_sha256" => expected_sha,
    "actual_sha256" => actual_sha,
    "expected_source" => "kubernetes_external",
    "actual_source" => "rubernetes",
    "source_concrete_sha256" => Digest::SHA256.hexdigest(local.fetch(:raw)),
    "upstream_concrete_sha256" => Digest::SHA256.hexdigest(known),
    "generator_normalized" => local.fetch(:raw) != known,
    "checks" => actual.to_h { |name, value| [name, value == expected.fetch(name)] },
    "errors" => errors
  }
end

def semantic_digest(value)
  M1Gate.canonical_document_digest(value)
end

def semantic_error_record(error)
  return nil unless error.is_a?(Hash)

  {
    "message" => error["message"].to_s,
    "field" => error["field"].to_s
  }
end

def semantic_error_signature(errors)
  Array(errors).map do |error|
    if error.respond_to?(:code)
      detail = error.message.to_s
      # OpenAPI required fields are represented by the generic schema
      # validator, while Kubernetes' field.Required uses an empty detail for
      # the same rule.  Keep the generic public issue message intact and
      # normalize only this external REST-observable projection.
      detail = "" if error.code.to_sym == :required && detail.match?(/\Afield .* is required\z/)
      if error.code.to_sym == :enum && error.expected.is_a?(Array)
        detail = "supported values: #{error.expected.map { |item| JSON.generate(item) }.join(", ")}"
      end
      {
        "type" => error.respond_to?(:kubernetes_error_type) ? error.kubernetes_error_type : error.code.to_s,
        "field" => error.respond_to?(:kubernetes_field) ? error.kubernetes_field : error.path.to_s,
        "detail" => detail
      }
    elsif error.is_a?(Hash)
      {
        "type" => error["type"].to_s,
        "field" => error["field"].to_s,
        "detail" => error["detail"].to_s
      }
    else
      {"type" => "error", "field" => "", "detail" => error.to_s}
    end
  end.sort_by { |error| [error.fetch("field"), error.fetch("type"), error.fetch("detail")] }
end

def semantic_dimension(expected:, actual:, applicable:, reason: nil)
  expected_value = if applicable
                     expected
                   else
                     {"applicable" => false}
                   end
  actual_value = if applicable
                   actual
                 else
                   {"applicable" => false}
                 end
  {
    "applicable" => applicable,
    "reason" => reason,
    "expected_sha256" => semantic_digest(expected_value),
    "actual_sha256" => semantic_digest(actual_value),
    "expected_source" => "kubernetes_external",
    "actual_source" => "rubernetes",
    "expected" => expected_value,
    "actual" => actual_value,
    "matches" => expected_value == actual_value
  }
end

def validation_scalar_fixture(schema)
  case schema
  when "io.k8s.apimachinery.pkg.api.resource.Quantity"
    "1"
  when "io.k8s.apimachinery.pkg.util.intstr.IntOrString"
    1
  when "io.k8s.apimachinery.pkg.apis.meta.v1.Time",
    "1970-01-01T00:00:00Z"
  when "io.k8s.apimachinery.pkg.apis.meta.v1.MicroTime"
    "1970-01-01T00:00:00.000000Z"
  else
    "1"
  end
end

SEMANTIC_SCALAR_SCHEMAS = {
  "io.k8s.apimachinery.pkg.api.resource.Quantity" => "1",
  "io.k8s.apimachinery.pkg.apis.meta.v1.MicroTime" => "1970-01-01T00:00:00.000000Z",
  "io.k8s.apimachinery.pkg.apis.meta.v1.Time" => "1970-01-01T00:00:00Z",
  "io.k8s.apimachinery.pkg.util.intstr.IntOrString" => 1
}.freeze

def semantic_scalar_fixture(schema)
  SEMANTIC_SCALAR_SCHEMAS.fetch(schema)
end

def semantic_scalar_schema?(schema, type)
  SEMANTIC_SCALAR_SCHEMAS.key?(schema) && type.fetch("field_definitions", {}).empty?
end

def go_struct_field_metadata(source_root, go_package, go_type, cache:)
  key = [source_root, go_package, go_type]
  return cache.fetch(key) if cache.key?(key)

  package_root = File.join(source_root, "staging/src", go_package)
  source_files = Dir.glob(File.join(package_root, "**/*.go")).filter_map do |path|
    [path, File.read(path)]
  rescue Errno::ENOENT, Errno::EACCES
    nil
  end
  source = source_files.find do |_path, content|
    content.match?(/(?:^|\n)type\s+#{Regexp.escape(go_type)}\s+struct\s*\{/m)
  end
  # A number of versioned API packages keep compatibility aliases instead of
  # redeclaring a struct (for example v1alpha1.MatchCondition).  Follow the
  # alias into its imported package so JSON declaration order remains the
  # order used by encoding/json rather than the registry's alphabetical
  # field order.
  unless source
    alias_source = source_files.find do |_path, content|
      content.match?(/(?:^|\n)type\s+#{Regexp.escape(go_type)}\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)(?:\s|$)/m)
    end
    if alias_source
      content = alias_source.last
      target = content.match(/(?:^|\n)type\s+#{Regexp.escape(go_type)}\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)(?:\s|$)/m)&.captures&.first
      imports = {}
      content.scan(/^\s*(?:(\w+)\s+)?"([^"]+)"\s*$/).each do |alias_name, imported_package|
        imports[alias_name || imported_package.split("/").last] = imported_package
      end
      target_package, target_type = if target&.include?(".")
                                      alias_name, aliased_type = target.split(".", 2)
                                      [imports[alias_name], aliased_type]
                                    else
                                      [go_package, target]
                                    end
      if target_package && target_type
        metadata = go_struct_field_metadata(source_root, target_package, target_type, cache: cache)
        cache[key] = metadata
        return metadata
      end
    end
  end

  body = source&.last&.match(/(?:^|\n)type\s+#{Regexp.escape(go_type)}\s+struct\s*\{(.*?)^\}/m)&.captures&.first
  source_content = source&.last.to_s
  imports = {}
  source_content.scan(/^\s*(?:(\w+)\s+)?"([^"]+)"\s*$/).each do |alias_name, imported_package|
    imports[alias_name || imported_package.split("/").last] = imported_package
  end

  resolve_embedded = lambda do |raw_type|
    raw_type = raw_type.to_s.sub(/^[*]/, "")
    if raw_type.include?(".")
      alias_name, embedded_type = raw_type.split(".", 2)
      [imports[alias_name] || go_package, embedded_type]
    else
      [go_package, raw_type]
    end
  end

  metadata = {}
  Array(body&.lines).each do |line|
    tag = line.match(/`([^`]*)`/)&.captures&.first
    next unless tag

    json_tag = tag.match(/(?:^|\s)json:"([^"]*)"/)&.captures&.first
    next unless json_tag

    name, *options = json_tag.split(",")
    next if name == "-"

    declaration = line.split("`", 2).first.strip
    declaration_parts = declaration.split(/\s+/, 2)
    if name.to_s.empty? && options.include?("inline") && declaration_parts.first
      embedded_package, embedded_type = resolve_embedded.call(declaration_parts.first)
      inline_metadata = go_struct_field_metadata(
        source_root, embedded_package, embedded_type, cache: cache
      )
      metadata.merge!(inline_metadata)
      next
    end
    next if name.nil? || name.empty?

    # Embedded Go fields have no separate field-name token (for example
    # `metav1.ObjectMeta `json:"metadata,omitempty"``).  The JSON tag is
    # authoritative for the wire name, so retain those fields for source
    # declaration ordering and zero-value materialization as well.
    field_name, field_type = if declaration_parts.length == 1
                               [name, declaration_parts.first]
                             else
                               declaration_parts
                             end
    next if field_name.nil? || field_type.nil?

    metadata[name] = {
      "omitempty" => options.include?("omitempty"),
      "omitzero" => options.include?("omitzero"),
      "pointer" => field_type.include?("*"),
      "slice_or_map" => field_type.start_with?("[]", "map[")
    }
  end
  cache[key] = metadata
end

def semantic_zero_value(field, source_field)
  return nil if source_field["pointer"] || source_field["slice_or_map"]

  case field["schema_reference"]
  when "io.k8s.apimachinery.pkg.api.resource.Quantity"
    return "0"
  when "io.k8s.apimachinery.pkg.apis.meta.v1.MicroTime"
    return nil
  when "io.k8s.apimachinery.pkg.apis.meta.v1.Time"
    return nil
  when "io.k8s.apimachinery.pkg.util.intstr.IntOrString"
    return 0
  end

  case field.fetch("type")
  when "string" then ""
  when "integer", "number" then 0
  when "boolean" then false
  when "array", "object" then nil
  when "reference" then {}
  end
end

def augment_semantic_fixture(value, type, types_by_schema:, go_info_by_schema:, source_root:, cache:, depth: 0)
  return value unless value.is_a?(Hash) || depth >= MINIMAL_SAMPLE_MAX_DEPTH

  schema_name = type.fetch("schema")
  info = go_info_by_schema[schema_name]
  metadata = info ? go_struct_field_metadata(source_root, info.fetch("go_package"), info.fetch("go_type"), cache: cache) : {}
  definitions = type.fetch("field_definitions", {})

  definitions.each do |name, field|
    source_field = metadata[name]
    if value.key?(name) && source_field
      omittable = source_field.fetch("omitempty") || source_field.fetch("omitzero")
      custom_zero_struct = %w[
        io.k8s.apimachinery.pkg.api.resource.Quantity
        io.k8s.apimachinery.pkg.apis.meta.v1.MicroTime
        io.k8s.apimachinery.pkg.apis.meta.v1.Time
        io.k8s.apimachinery.pkg.util.intstr.IntOrString
      ].include?(field["schema_reference"])
      # `minimal_required_values` deliberately materializes reference
      # fields so value structs reach the JSON encoder.  Pointer fields are
      # different: a zero `{}` here represents a nil Go pointer and must be
      # removed when the tag permits omission.  Go's `omitzero` likewise
      # suppresses zero custom time structs.
      if omittable && source_field.fetch("pointer")
        value.delete(name)
        next
      end
      if source_field.fetch("omitzero") && custom_zero_struct && (value[name].nil? || value[name] == {})
        value.delete(name)
        next
      end
    end
    if value.key?(name)
      case field["type"]
      when "reference"
        target = types_by_schema.fetch(field.fetch("reference"))
        augment_semantic_fixture(
          value[name], target, types_by_schema: types_by_schema, go_info_by_schema: go_info_by_schema,
                               source_root: source_root, cache: cache, depth: depth + 1
        )
      when "array"
        item = field["items"]
        if item && item["reference"] && value[name].is_a?(Array)
          target = types_by_schema.fetch(item.fetch("reference"))
          value[name].each do |child|
            augment_semantic_fixture(
              child, target, types_by_schema: types_by_schema, go_info_by_schema: go_info_by_schema,
                             source_root: source_root, cache: cache, depth: depth + 1
            )
          end
        end
      end
      next
    end

    special_struct = %w[
      io.k8s.apimachinery.pkg.api.resource.Quantity
      io.k8s.apimachinery.pkg.apis.meta.v1.MicroTime
      io.k8s.apimachinery.pkg.apis.meta.v1.Time
      io.k8s.apimachinery.pkg.util.intstr.IntOrString
    ].include?(field["schema_reference"])
    # Go 1.24+'s `omitzero` is distinct from `omitempty`: zero-valued
    # value structs such as ObjectMeta.CreationTimestamp are omitted even
    # though their Ruby schema representation is a non-nullable reference.
    # Custom JSON scalar wrappers still need their wire zero when only
    # `omitempty` is present because encoding/json cannot omit a struct by
    # emptiness alone.
    omittable = source_field && (source_field.fetch("omitempty") || source_field.fetch("omitzero"))
    next unless source_field &&
                (!omittable || (special_struct && !source_field.fetch("pointer") && !source_field.fetch("omitzero")))

    zero = semantic_zero_value(field, source_field)
    value[name] = zero
  end
  value
end

def semantic_ordered_value(value, type, types_by_schema:, go_info_by_schema:, source_root:, cache:, depth: 0)
  return value unless value.is_a?(Hash) || depth >= MINIMAL_SAMPLE_MAX_DEPTH

  schema_name = type.fetch("schema")
  info = go_info_by_schema[schema_name]
  metadata = info ? go_struct_field_metadata(source_root, info.fetch("go_package"), info.fetch("go_type"), cache: cache) : {}
  definitions = type.fetch("field_definitions", {})
  ordered = {}
  keys = metadata.keys + value.keys.map(&:to_s).reject { |key| metadata.key?(key) }
  keys.uniq.each do |name|
    next unless value.key?(name)

    field = definitions[name]
    item = value[name]
    ordered[name] = if field && field["type"] == "reference" && item.is_a?(Hash)
                      target = types_by_schema.fetch(field.fetch("reference"))
                      semantic_ordered_value(
                        item, target, types_by_schema: types_by_schema, go_info_by_schema: go_info_by_schema,
                                      source_root: source_root, cache: cache, depth: depth + 1
                      )
                    elsif field && field["type"] == "array" && item.is_a?(Array) && field.dig("items", "reference")
                      target = types_by_schema.fetch(field.dig("items", "reference"))
                      item.map do |child|
                        semantic_ordered_value(
                          child, target, types_by_schema: types_by_schema, go_info_by_schema: go_info_by_schema,
                                         source_root: source_root, cache: cache, depth: depth + 1
                        )
                      end
                    elsif field && field["type"] == "object" && item.is_a?(Hash) && field["additional_properties"]
                      item.keys.map(&:to_s).sort.to_h { |key| [key, item[key] || item[key.to_sym]] }
                    else
                      item
                    end
  end
  ordered
end

def semantic_fixture_json(value, type, codec:, types_by_schema:, go_info_by_schema:, source_root:, cache:, schema: nil)
  return JSON.generate(value) if value.is_a?(String) || value.is_a?(Numeric) || value == true || value == false || value.nil?

  normalized = if schema
                 codec.load_json(JSON.generate(value), schema: schema, unknown_fields: :prune)
               else
                 value
               end
  ordered = semantic_ordered_value(
    normalized,
    type,
    types_by_schema: types_by_schema,
    go_info_by_schema: go_info_by_schema,
    source_root: source_root,
    cache: cache
  )
  JSON.generate(ordered)
end

# Embed the target descriptor at its owner path.  Intermediate containers
# keep the owner's generated siblings (for example containers[0].name next to
# an embedded lifecycle handler) so the owner stays a valid request object.
def validation_embed_fixture(value, path, target, target_schema)
  return JSON.parse(JSON.generate(target)) if path.empty?

  edge = path.fetch(0)
  result = value.is_a?(Hash) ? JSON.parse(JSON.generate(value)) : {}
  existing = result[edge.fetch("field")]
  current = case edge.fetch("container")
            when "array" then existing.is_a?(Array) && existing.first.is_a?(Hash) ? existing.first : {}
            when "map" then existing.is_a?(Hash) && existing["m1"].is_a?(Hash) ? existing["m1"] : {}
            else existing.is_a?(Hash) ? existing : {}
            end
  child = if path.length == 1 && edge.fetch("container") == "scalar"
            validation_scalar_fixture(target_schema)
          else
            validation_embed_fixture(current, path.drop(1), target, target_schema)
          end
  result[edge.fetch("field")] = case edge.fetch("container")
                                when "array" then [child] + (existing.is_a?(Array) ? existing.drop(1) : [])
                                when "map" then (existing.is_a?(Hash) ? existing : {}).merge("m1" => child)
                                else child
                                end
  result
end

def validation_owner_api_version(gvk)
  group = gvk.fetch("group")
  group.empty? ? gvk.fetch("version") : "#{group}/#{gvk.fetch("version")}"
end

def build_validation_parent_fixture(codec:, mapping:, owner_type:, target_json:, target_schema:, types_by_schema:, augment: nil)
  owner_klass = generated_class(owner_type)
  gvk = mapping.fetch("owner_gvk")
  base = JSON.parse(
    JSON.generate(minimal_required_values(owner_type, types_by_schema, include_zero_references: true))
  )
  # The owner object is decoded by kube-apiserver like any other request:
  # value structs are materialized and nil pointers are absent.  The
  # generated minimal object materializes every reference, so apply the same
  # Go-struct augmentation the target fixture received before embedding it.
  base = augment.call(base, owner_type) if augment
  base["apiVersion"] = validation_owner_api_version(gvk)
  base["kind"] = gvk.fetch("kind")
  target = JSON.parse(target_json)
  owner_hash = validation_embed_fixture(base, mapping.fetch("target_path"), target, target_schema)
  # REST strategies must observe a meaningful object.  The generated schema
  # does not carry Go pointer/value information for every metadata field, so
  # provide a deterministic name on the owner wire object after embedding the
  # target descriptor.
  owner_hash["metadata"] = {} unless owner_hash["metadata"].is_a?(Hash)
  owner_hash["metadata"]["name"] = "m1-validation"
  owner_hash["metadata"]["namespace"] = "m1-validation" if mapping["namespace_scoped"] == true
  # Strategy roots whose generated minimal object is not a valid upstream
  # object carry upstream-cited patches in the oracle table; a nested patch
  # keeps the embedded descriptor valid on top of the owner-level patch.
  fixture = mapping["fixture"].is_a?(Hash) ? mapping["fixture"] : {}
  nested = fixture.fetch("nested", {})
  nested = nested[target_schema] || nested[target_schema.to_s.split(".").last] || {}
  unless nested.empty? || nested.key?("create") || nested.key?("invalid") || nested.key?("update") || nested.key?("expectations")
    nested = {"create" => nested}
  end
  owner_hash = apply_fixture_patch(owner_hash, fixture["create"]) if fixture["create"]
  owner_hash = apply_fixture_patch(owner_hash, nested["create"]) if nested["create"]
  owner_missing_hash = {
    "apiVersion" => validation_owner_api_version(gvk),
    "kind" => gvk.fetch("kind"),
    "metadata" => {}
  }
  invalid_patch = nested["invalid"] || fixture["invalid"]
  owner_invalid_hash = JSON.parse(JSON.generate(owner_hash))
  if invalid_patch
    owner_invalid_hash = apply_fixture_patch(owner_invalid_hash, invalid_patch)
  else
    # Keep the invalid fixture decodable so REST validation, rather than JSON
    # type checking, supplies the negative observation.
    owner_invalid_hash.fetch("metadata")["name"] = ""
  end
  update_patch = nested["update"] || fixture["update"]
  owner_update_hash = JSON.parse(JSON.generate(owner_hash))
  if update_patch
    owner_update_hash = apply_fixture_patch(owner_update_hash, update_patch)
  else
    owner_update_hash.fetch("metadata")["resourceVersion"] = "1"
  end
  owner_json = codec.canonical_json(owner_hash, schema: owner_klass.definition)
  owner_missing_json = codec.canonical_json(owner_missing_hash, schema: owner_klass.definition)
  owner_update_json = codec.canonical_json(owner_update_hash, schema: owner_klass.definition)
  # Keep the invalid fixture as a non-empty JSON object, but do not run it
  # through the Ruby codec: the empty metadata.name is intentionally a
  # Kubernetes REST validation observation.
  owner_invalid_json = JSON.generate(owner_invalid_hash)
  owner_validation = begin
    validator = owner_klass.definition.validator
    # The external strategy receives the canonical JSON fixture, not the
    # in-memory graph used to construct it.  In particular, encoding/json
    # prunes nil/empty optional reference fields; validating owner_hash here
    # would incorrectly apply Pod/volume rules to materialized zero-value
    # references that never cross the wire (notably PersistentVolume source
    # pointers and Pod status).  Parse the exact request payload for the
    # Ruby-side observation so both implementations see identical input.
    owner_wire_hash = JSON.parse(owner_json)
    owner_missing_wire_hash = JSON.parse(owner_missing_json)
    owner_update_wire_hash = JSON.parse(owner_update_json)
    owner_invalid_wire_hash = JSON.parse(owner_invalid_json)
    # The REST validation oracle observes the object after the owning
    # strategy's PrepareForCreate/PrepareForUpdate hook.  Keep preparation
    # explicit and fixture-local: normal public validation must not require
    # server-assigned metadata.uid for Job create requests.
    prepare = gvk.fetch("kind") == "Job"
    create_errors = validator.errors(owner_wire_hash, unknown_fields: :reject, operation: :create,
                                                      strategy_prepare: prepare)
    invalid_errors = validator.errors(owner_invalid_wire_hash, unknown_fields: :reject, operation: :create,
                                                               strategy_prepare: prepare)
    update_errors = validator.errors(owner_update_wire_hash, unknown_fields: :reject, operation: :update,
                                                             old: owner_wire_hash, strategy_prepare: prepare)
    missing_errors = validator.errors(owner_missing_wire_hash, unknown_fields: :reject, operation: :create,
                                                               strategy_prepare: prepare)
    {
      "applicable" => true,
      "create_accepted" => create_errors.empty?,
      "create_errors" => semantic_error_signature(create_errors),
      "invalid_accepted" => invalid_errors.empty?,
      "invalid_errors" => semantic_error_signature(invalid_errors),
      "update_accepted" => update_errors.empty?,
      "update_errors" => semantic_error_signature(update_errors),
      "missing_accepted" => missing_errors.empty?,
      "missing_errors" => semantic_error_signature(missing_errors)
    }
  rescue Rubernetes::Schema::GenerationError => error
    unavailable = [{
      "type" => "ruby_generation_unavailable",
      "field" => "",
      "detail" => error.message
    }]
    {
      "applicable" => false,
      "reason" => "Rubernetes generated owner class is unavailable: #{error.message}",
      "create_accepted" => false,
      "create_errors" => unavailable,
      "invalid_accepted" => false,
      "invalid_errors" => unavailable,
      "update_accepted" => false,
      "update_errors" => unavailable,
      "missing_accepted" => false,
      "missing_errors" => unavailable
    }
  end
  {
    "owner_fixture_json" => owner_json,
    "owner_invalid_fixture_json" => owner_invalid_json,
    "owner_missing_fixture_json" => owner_missing_json,
    "owner_update_fixture_json" => owner_update_json,
    "owner_validation" => owner_validation
  }
end

# Deep-merge a fixture patch; the "__delete__" marker removes a key so a
# generated minimal object can drop a mutually exclusive field.
def apply_fixture_patch(base, patch)
  result = JSON.parse(JSON.generate(base))
  Hash(patch).each do |key, value|
    if value == "__delete__"
      result.delete(key)
    elsif value.is_a?(Hash)
      result[key] = apply_fixture_patch(result[key].is_a?(Hash) ? result[key] : {}, value)
    elsif value.is_a?(Array) && result[key].is_a?(Array)
      result[key] = value.each_with_index.map do |item, index|
        current = result[key][index]
        if item.is_a?(Hash)
          apply_fixture_patch(current.is_a?(Hash) ? current : {}, item)
        else
          strip_fixture_markers(item)
        end
      end
    else
      result[key] = strip_fixture_markers(value)
    end
  end
  result
end

# A patch value copied into a fixture that lacks the key must not carry the
# "__delete__" marker (or the keys it removes) into the wire object.
def strip_fixture_markers(value)
  case value
  when Hash
    value.each_with_object({}) do |(key, item), cleaned|
      next if item == "__delete__"

      cleaned[key] = strip_fixture_markers(item)
    end
  when Array
    value.map { |item| strip_fixture_markers(item) }
  else
    JSON.parse(JSON.generate(value))
  end
end

def validation_fixture_metadata!(hash, mapping)
  policy = mapping.fetch("metadata_policy", "name")
  case policy
  when "none"
    hash.delete("metadata")
  when "empty"
    hash["metadata"] = {}
  when "namespace_only"
    hash["metadata"] = {"namespace" => "m1-validation"}
  else
    hash["metadata"] = {} unless hash["metadata"].is_a?(Hash)
    hash["metadata"]["name"] = "m1-validation"
    hash["metadata"]["namespace"] = "m1-validation" if mapping["namespace_scoped"] == true
  end
  hash
end

# The REST handler receives the request after the versioned decoder applied
# schema defaults (kube-apiserver's UniversalDecoder), so the local
# observation validates the defaulted object too.
def local_validation_observation(validator, wire_hash, operation:, old: nil, prepare: false, definition: nil)
  subject = wire_hash
  subject = definition.defaulting.apply_hash(wire_hash, kubernetes_admission_defaults: false) if definition.respond_to?(:defaulting)
  old_subject = old
  old_subject = definition.defaulting.apply_hash(old, kubernetes_admission_defaults: false) if old && definition.respond_to?(:defaulting)
  errors = validator.errors(subject, unknown_fields: :reject, operation: operation, old: old_subject, strategy_prepare: prepare)
  [errors.empty?, semantic_error_signature(errors)]
end

# REST handler roots validate a request object through a validation function
# rather than a strategy: fixtures come from the generated minimal object plus
# the upstream-cited patches in the oracle table.
def build_validation_handler_fixture(codec:, mapping:, owner_type:, target_json:, target_schema:, types_by_schema:, augment: nil)
  owner_klass = generated_class(owner_type)
  gvk = mapping.fetch("owner_gvk")
  base = JSON.parse(JSON.generate(minimal_required_values(owner_type, types_by_schema, include_zero_references: true)))
  base["apiVersion"] = validation_owner_api_version(gvk)
  base["kind"] = gvk.fetch("kind")
  target = JSON.parse(target_json)
  base = validation_embed_fixture(base, mapping.fetch("target_path"), target, target_schema)
  fixture = mapping.fetch("fixture")
  # A nested descriptor keeps its embedded instance valid through the
  # owner-level override recorded for it; the default create patch may
  # otherwise remove the very field the descriptor lives in.
  nested = fixture.fetch("nested", {})[target_schema]
  nested = {"create" => nested} if nested.is_a?(Hash) && !nested.key?("create")
  nested ||= {}
  create_patch = nested.fetch("create", fixture["create"])
  invalid_patch = nested.fetch("invalid", fixture["invalid"])
  update_patch = nested.fetch("update",
                              fixture["update"] || (if mapping.fetch("metadata_policy",
                                                                     "name") == "none"
                                                      {"dryRun" => ["All"]}
                                                    else
                                                      {"metadata" => {"resourceVersion" => "1"}}
                                                    end))
  # The apiserver decoder materializes every non-pointer Go struct before
  # defaulting and validation; the minimal object carries the same zero
  # values (and drops nil pointers) before the upstream-cited patches apply.
  base = augment.call(base, owner_type) if augment
  create_hash = validation_fixture_metadata!(apply_fixture_patch(base, create_patch), mapping)
  invalid_hash = apply_fixture_patch(create_hash, invalid_patch)
  missing_hash = {"apiVersion" => validation_owner_api_version(gvk), "kind" => gvk.fetch("kind")}
  missing_hash["metadata"] = {} unless mapping.fetch("metadata_policy", "name") == "none"
  update_hash = apply_fixture_patch(create_hash, update_patch)
  definition = owner_klass.definition
  create_json = codec.canonical_json(create_hash, schema: definition)
  invalid_json = JSON.generate(invalid_hash)
  missing_json = JSON.generate(missing_hash)
  update_json = codec.canonical_json(update_hash, schema: definition)
  validator = definition.validator
  missing_local = augment ? augment.call(JSON.parse(missing_json), owner_type) : JSON.parse(missing_json)
  create_accepted, create_errors = local_validation_observation(validator, JSON.parse(create_json), operation: :create,
                                                                                                    definition: definition)
  invalid_accepted, invalid_errors = local_validation_observation(validator, JSON.parse(invalid_json), operation: :create,
                                                                                                       definition: definition)
  missing_accepted, missing_errors = local_validation_observation(validator, missing_local, operation: :create, definition: definition)
  update_accepted, update_errors = local_validation_observation(validator, JSON.parse(update_json), operation: :update,
                                                                                                    old: JSON.parse(create_json), definition: definition)
  {
    "owner_fixture_json" => create_json,
    "owner_invalid_fixture_json" => invalid_json,
    "owner_missing_fixture_json" => missing_json,
    "owner_update_fixture_json" => update_json,
    "owner_validation" => {
      "applicable" => true,
      "create_accepted" => create_accepted, "create_errors" => create_errors,
      "invalid_accepted" => invalid_accepted, "invalid_errors" => invalid_errors,
      "update_accepted" => update_accepted, "update_errors" => update_errors,
      "missing_accepted" => missing_accepted, "missing_errors" => missing_errors
    }
  }
end

# A *List envelope validates each item through the item owner; the local
# observation validates every item with the owner validator and prefixes the
# field path like meta.ExtractList-driven validation does upstream.
def build_validation_list_fixture(codec:, mapping:, raw_json:, types_by_schema:, augment: nil)
  item_schema = mapping.fetch("item_schema")
  item_type = types_by_schema.fetch(item_schema)
  item_mapping = mapping.merge("validation_mode" => mapping.fetch("item_mode"), "target_path" => mapping.fetch("item_target_path"))
  list_value = JSON.parse(raw_json)
  item_target = Array(list_value["items"]).first || JSON.parse(JSON.generate(minimal_required_values(item_type, types_by_schema,
                                                                                                     include_zero_references: true)))
  owner_type = types_by_schema.fetch(mapping.fetch("owner_schema"))
  inner = if mapping.fetch("item_mode") == "handler"
            build_validation_handler_fixture(codec: codec, mapping: item_mapping, owner_type: owner_type, target_json: JSON.generate(item_target),
                                             target_schema: item_schema, types_by_schema: types_by_schema, augment: augment)
          else
            build_validation_parent_fixture(codec: codec, mapping: item_mapping, owner_type: owner_type, target_json: JSON.generate(item_target),
                                            target_schema: item_schema, types_by_schema: types_by_schema)
          end
  list_gvk = mapping.fetch("list_gvk")
  wrap = lambda do |item_json|
    JSON.generate("apiVersion" => validation_owner_api_version(list_gvk), "kind" => list_gvk.fetch("kind"), "metadata" => {},
                  "items" => [JSON.parse(item_json)])
  end
  prefix = lambda do |errors|
    Array(errors).map { |error| error.merge("field" => "items[0].#{error["field"]}") }
      .sort_by { |error| [error.fetch("field"), error.fetch("type"), error.fetch("detail")] }
  end
  validation = inner.fetch("owner_validation")
  {
    "owner_fixture_json" => wrap.call(inner.fetch("owner_fixture_json")),
    "owner_invalid_fixture_json" => wrap.call(inner.fetch("owner_invalid_fixture_json")),
    "owner_missing_fixture_json" => wrap.call(inner.fetch("owner_missing_fixture_json")),
    "owner_update_fixture_json" => wrap.call(inner.fetch("owner_update_fixture_json")),
    "owner_validation" => validation.merge(
      "create_errors" => prefix.call(validation.fetch("create_errors")),
      "invalid_errors" => prefix.call(validation.fetch("invalid_errors")),
      "update_errors" => prefix.call(validation.fetch("update_errors")),
      "missing_errors" => prefix.call(validation.fetch("missing_errors"))
    )
  }
end

def build_validation_fixture_for_mode(codec:, mapping:, raw_json:, schema_name:, types_by_schema:, augment: nil)
  case mapping.fetch("validation_mode")
  when "rest_endpoint", "response"
    {
      "owner_fixture_json" => "{}", "owner_invalid_fixture_json" => "{}", "owner_missing_fixture_json" => "{}",
      "owner_update_fixture_json" => "{}",
      "owner_validation" => {"applicable" => true, "evidence" => mapping.fetch("evidence")}
    }
  when "list"
    build_validation_list_fixture(codec: codec, mapping: mapping, raw_json: raw_json, types_by_schema: types_by_schema, augment: augment)
  when "handler"
    owner_type = types_by_schema.fetch(mapping.fetch("owner_schema"))
    build_validation_handler_fixture(codec: codec, mapping: mapping, owner_type: owner_type, target_json: raw_json,
                                     target_schema: schema_name, types_by_schema: types_by_schema, augment: augment)
  else
    owner_type = types_by_schema.fetch(mapping.fetch("owner_schema"))
    build_validation_parent_fixture(codec: codec, mapping: mapping, owner_type: owner_type, target_json: raw_json,
                                    target_schema: schema_name, types_by_schema: types_by_schema, augment: augment)
  end
end

def compact_validation_operation(operation, error_catalog: nil)
  errors = semantic_error_signature(operation["errors"])
  digest = semantic_digest(errors)
  error_catalog[digest] = errors if error_catalog
  {
    "completed" => operation.fetch("completed", true),
    "accepted" => operation.fetch("accepted", false),
    "error" => operation["error"],
    "expected_accepted" => operation["expected_accepted"],
    "expectation_matches" => operation["expectation_matches"],
    "errors" => errors,
    "error_count" => errors.length,
    "errors_sha256" => digest,
    "field_paths" => errors.map { |error| error.fetch("field") }.uniq.sort
  }
end

def compact_validation_oracle(document)
  catalog = {}
  comparisons = document.fetch("comparisons").sort_by { |entry| entry.fetch("id") }.map do |entry|
    compact = entry.slice("id", "passed", "applicable", "reason", "owner_schema", "target_path", "source_paths", "error",
                          "mode", "evidence", "collaborators")
    if entry["applicable"] == true
      observations = %w[create invalid update missing].map do |operation|
        compact_validation_operation(entry.fetch(operation), error_catalog: catalog)
      end
      compact["operations"] = %w[create invalid update missing].to_h do |operation|
        [operation, observations.fetch(%w[create invalid update missing].index(operation))]
      end
      compact["operation_observation_sha256"] = semantic_digest(observations)
    end
    compact
  end
  document.merge("error_catalog" => catalog, "comparisons" => comparisons)
end

def compare_validation_operation(operation)
  compact_validation_operation(operation)
end

def compact_local_validation_operation(accepted:, errors:, expected_accepted:)
  # Braces keep the operation a positional Hash; a brace-less string-keyed
  # hash is consumed as keyword arguments by a method declaring keywords.
  compact_validation_operation({
                                 "completed" => true,
                                 "accepted" => accepted,
                                 "error" => nil,
                                 "expected_accepted" => expected_accepted,
                                 "expectation_matches" => accepted == expected_accepted &&
      (expected_accepted ? Array(errors).empty? : !Array(errors).empty?),
                                 "errors" => errors
                               })
end

def compare_direct_validation_case(local, external, mapping)
  if mapping.fetch("validation_mode") == "protocol"
    reason = mapping.fetch("reason", mapping.fetch("validation_reason", "protocol validation is not applicable"))
    observation = {"applicable" => false, "reason" => reason, "source_paths" => mapping.fetch("source_paths")}
    return semantic_dimension(expected: observation, actual: observation, applicable: false, reason: reason)
  end

  unless mapping.fetch("applicable")
    reason = mapping.fetch("reason")
    observation = {
      "applicable" => false,
      "reason" => reason,
      "source_paths" => mapping.fetch("source_paths")
    }
    return semantic_dimension(expected: observation, actual: observation, applicable: false, reason: reason)
  end

  parent = local.fetch("validation_parent").fetch("owner_validation")
  if %w[rest_endpoint response].include?(mapping.fetch("validation_mode"))
    # The observation lives in the API differential against the isolated
    # kube-apiserver; both sides record the same evidence reference and the
    # gate verifies those operations passed.
    reference = {"applicable" => true, "mode" => mapping.fetch("validation_mode"), "evidence" => mapping.fetch("evidence")}
    external_reference = {"applicable" => true, "mode" => external["mode"], "evidence" => external["evidence"]}
    return semantic_dimension(expected: external_reference, actual: reference, applicable: true)
  end
  expectations = mapping["expectations"] || {"create" => true, "invalid" => false, "missing" => false, "update" => true}
  expected = {
    "applicable" => true,
    "create" => compare_validation_operation(external.fetch("create")),
    "invalid" => compare_validation_operation(external.fetch("invalid")),
    "update" => compare_validation_operation(external.fetch("update")),
    "missing" => compare_validation_operation(external.fetch("missing"))
  }
  actual = {
    "applicable" => true,
    "create" => compact_local_validation_operation(
      accepted: parent.fetch("create_accepted"),
      errors: parent.fetch("create_errors"),
      expected_accepted: expectations.fetch("create")
    ),
    "invalid" => compact_local_validation_operation(
      accepted: parent.fetch("invalid_accepted"),
      errors: parent.fetch("invalid_errors"),
      expected_accepted: expectations.fetch("invalid")
    ),
    "update" => compact_local_validation_operation(
      accepted: parent.fetch("update_accepted"),
      errors: parent.fetch("update_errors"),
      expected_accepted: expectations.fetch("update")
    ),
    "missing" => compact_local_validation_operation(
      accepted: parent.fetch("missing_accepted"),
      errors: parent.fetch("missing_errors"),
      expected_accepted: expectations.fetch("missing")
    )
  }
  semantic_dimension(expected: expected, actual: actual, applicable: true)
end

def compare_semantic_case(local, external, validation_override: nil)
  errors = []
  external_error = external.fetch("error", "").to_s
  errors << "Kubernetes semantic helper error: #{external_error}" unless external_error.empty?
  external_json = external.fetch("json")
  local_json = local.fetch("json")
  json_expected = {
    "accepted" => external_json.fetch("accepted"),
    "canonical_sha256" => external_json["canonical_sha256"],
    "unknown_accepted" => external_json.fetch("unknown").fetch("accepted"),
    "unknown_canonical_sha256" => external_json.fetch("unknown")["canonical_sha256"],
    "unknown_field_preserved" => external_json.fetch("unknown").fetch("field_preserved"),
    "strict_unknown_accepted" => external_json.fetch("strict_unknown").fetch("accepted")
  }
  json_actual = {
    "accepted" => true,
    "canonical_sha256" => Digest::SHA256.hexdigest(local.fetch("json_canonical_json")),
    "unknown_accepted" => local_json.fetch("unknown_accepted"),
    "unknown_canonical_sha256" => Digest::SHA256.hexdigest(local.fetch("json_unknown_canonical_json")),
    "unknown_field_preserved" => local_json.fetch("unknown_field_preserved"),
    "strict_unknown_accepted" => local_json.fetch("strict_unknown_accepted")
  }
  json_dimension = semantic_dimension(expected: json_expected, actual: json_actual, applicable: true)
  json_dimension["expected_observation"] = {
    "raw_sha256" => external_json["raw_sha256"],
    "canonical_sha256" => external_json["canonical_sha256"],
    "unknown_raw_sha256" => external_json.fetch("unknown")["raw_sha256"],
    "unknown_canonical_sha256" => external_json.fetch("unknown")["canonical_sha256"]
  }
  json_dimension["actual_observation"] = {
    "raw_sha256" => Digest::SHA256.hexdigest(local.fetch("json_raw")),
    "canonical_sha256" => Digest::SHA256.hexdigest(local.fetch("json_canonical_json")),
    "unknown_raw_sha256" => Digest::SHA256.hexdigest(local.fetch("json_unknown_raw")),
    "unknown_canonical_sha256" => Digest::SHA256.hexdigest(local.fetch("json_unknown_canonical_json"))
  }
  json_dimension["expected_errors"] = {
    "decode" => semantic_error_record(external_json["error"]),
    "unknown_decode" => semantic_error_record(external_json.fetch("unknown")["error"]),
    "strict_unknown" => semantic_error_record(external_json.fetch("strict_unknown")["error"])
  }
  json_dimension["actual_errors"] = {
    "decode" => local_json["error"],
    "unknown_decode" => local_json["unknown_error"],
    "strict_unknown" => local_json["strict_unknown_error"]
  }
  errors << "JSON acceptance or unknown-field behavior differs" unless json_dimension.fetch("matches")

  external_defaulting = external.fetch("defaulting")
  defaulting_applicable = external_defaulting.fetch("applicable")
  local_defaulting = if defaulting_applicable
                       {
                         "applicable" => true,
                         "before_sha256" => Digest::SHA256.hexdigest(local.fetch("defaulting_before_json")),
                         "after_sha256" => Digest::SHA256.hexdigest(local.fetch("defaulting_after_json")),
                         "changed" => local.fetch("defaulting_before_json") != local.fetch("defaulting_after_json")
                       }
                     else
                       {"applicable" => false, "reason" => external_defaulting.fetch("reason", "")}
                     end
  expected_defaulting = if defaulting_applicable && external_defaulting["error"].nil?
                          {
                            "applicable" => true,
                            "before_sha256" => external_defaulting.fetch("before_sha256"),
                            "after_sha256" => external_defaulting.fetch("after_sha256"),
                            "changed" => external_defaulting.fetch("changed")
                          }
                        elsif defaulting_applicable
                          {
                            "applicable" => true,
                            "accepted" => false,
                            "error" => semantic_error_record(external_defaulting["error"])
                          }
                        else
                          {"applicable" => false, "reason" => external_defaulting.fetch("reason", "")}
                        end
  defaulting_dimension = semantic_dimension(
    expected: expected_defaulting,
    actual: local_defaulting,
    applicable: defaulting_applicable,
    reason: external_defaulting["reason"]
  )
  defaulting_dimension["expected_error"] = semantic_error_record(external_defaulting["error"])
  defaulting_dimension["actual_error"] = local["defaulting_error"]
  defaulting_dimension["expected_observation"] = {
    "scheme_registered" => external_defaulting["scheme_registered"],
    "before_sha256" => external_defaulting["before_sha256"],
    "after_sha256" => external_defaulting["after_sha256"],
    "changed" => external_defaulting["changed"]
  }
  defaulting_dimension["actual_observation"] = {
    "before_sha256" => Digest::SHA256.hexdigest(local.fetch("defaulting_before_json")),
    "after_sha256" => Digest::SHA256.hexdigest(local.fetch("defaulting_after_json")),
    "changed" => local.fetch("defaulting_before_json") != local.fetch("defaulting_after_json")
  }
  errors << "Scheme defaulting behavior differs" unless defaulting_dimension.fetch("matches")

  external_validation = external.fetch("validation")
  validation_applicable = external_validation.fetch("applicable")
  local_validation = if validation_applicable
                       {
                         "applicable" => true,
                         "accepted" => local.fetch("validation_accepted"),
                         "errors" => local.fetch("validation_errors"),
                         "missing_accepted" => local.fetch("validation_missing_accepted"),
                         "missing_errors" => local.fetch("validation_missing_errors"),
                         "source_paths" => local.fetch("validation_source_paths")
                       }
                     else
                       {
                         "applicable" => false,
                         "reason" => external_validation.fetch("reason", ""),
                         "source_paths" => external_validation.fetch("source_paths", [])
                       }
                     end
  expected_validation = if validation_applicable && external_validation["error"].nil?
                          {
                            "applicable" => true,
                            "accepted" => external_validation.fetch("accepted"),
                            "errors" => semantic_error_signature(external_validation.fetch("errors")),
                            "missing_accepted" => external_validation.fetch("missing_accepted"),
                            "missing_errors" => semantic_error_signature(external_validation.fetch("missing_errors")),
                            "source_paths" => external_validation.fetch("source_paths", [])
                          }
                        elsif validation_applicable
                          {
                            "applicable" => true,
                            "accepted" => false,
                            "errors" => [],
                            "missing_accepted" => false,
                            "missing_errors" => [],
                            "source_paths" => external_validation.fetch("source_paths", []),
                            "error" => semantic_error_record(external_validation["error"])
                          }
                        else
                          {
                            "applicable" => false,
                            "reason" => external_validation.fetch("reason", ""),
                            "source_paths" => external_validation.fetch("source_paths", [])
                          }
                        end
  validation_dimension = semantic_dimension(
    expected: expected_validation,
    actual: local_validation,
    applicable: validation_applicable,
    reason: external_validation["reason"]
  )
  if validation_override
    validation_dimension = validation_override
    validation_applicable = validation_override.fetch("applicable")
  end
  validation_dimension["expected_error"] = semantic_error_record(external_validation["error"])
  validation_dimension["actual_error"] = local["validation_error"]
  errors << "Scheme validation acceptance or field paths differ" unless validation_dimension.fetch("matches")

  differences = []
  differences << "json" unless json_dimension.fetch("matches")
  differences << "defaulting" unless defaulting_dimension.fetch("matches")
  differences << "validation" unless validation_dimension.fetch("matches")
  comparison = {
    "id" => local.fetch("id"),
    "go_type" => external.fetch("go_type"),
    "attempt_count" => 1,
    "passed" => errors.empty? && external.fetch("error", "").to_s.empty? && external.fetch("passed", false) == true,
    "json" => json_dimension,
    "defaulting" => defaulting_dimension,
    "validation" => validation_dimension,
    "json_expected_source" => "kubernetes_external",
    "json_actual_source" => "rubernetes",
    "json_expected_sha256" => semantic_digest(json_expected),
    "json_actual_sha256" => semantic_digest(json_actual),
    "defaulting_applicable" => defaulting_applicable,
    "defaulting_expected_source" => "kubernetes_external",
    "defaulting_actual_source" => "rubernetes",
    "defaulting_expected_sha256" => defaulting_dimension.fetch("expected_sha256"),
    "defaulting_actual_sha256" => defaulting_dimension.fetch("actual_sha256"),
    "validation_applicable" => validation_applicable,
    "validation_expected_source" => "kubernetes_external",
    "validation_actual_source" => "rubernetes",
    "validation_expected_sha256" => validation_dimension.fetch("expected_sha256"),
    "validation_actual_sha256" => validation_dimension.fetch("actual_sha256"),
    "external_error" => external_error.empty? ? nil : external_error,
    "differences" => differences,
    "errors" => errors
  }
  if validation_override
    mapping = local.fetch("validation_mapping")
    comparison["validation_owner_schema"] = mapping["owner_schema"]
    comparison["validation_target_path"] = mapping["target_path"]
    comparison["validation_source_paths"] = mapping["source_paths"]
  end
  comparison
end

def build_semantic_case(registry:, codec:, type:, wire_case:, types_by_schema:, go_info_by_schema:, source_root:, validation_mapping:,
                        go_metadata_cache:)
  schema_name = type.fetch("schema")
  klass = generated_class(type)
  scalar_schema = semantic_scalar_schema?(schema_name, type)
  required_values = minimal_required_values(type, types_by_schema, include_zero_references: true)
  # Keep the semantic fixture as a typed Hash.  Constructing every nested
  # zero-value reference through ValueObject would make unrelated accessor
  # collisions (for example a field named `exec`) observable while building a
  # JSON fixture.  The typed codec and validator consume the same schema AST
  # without requiring generated nested accessor classes.
  value = scalar_schema ? semantic_scalar_fixture(schema_name) : required_values
  unless scalar_schema
    augment_semantic_fixture(
      value,
      type,
      types_by_schema: types_by_schema,
      go_info_by_schema: go_info_by_schema,
      source_root: source_root,
      cache: go_metadata_cache
    )
  end
  unknown_value = if scalar_schema
                    value
                  else
                    JSON.parse(JSON.generate(value)).merge("m1FutureField" => {"value" => 1})
                  end
  missing_value = scalar_schema ? value : {}
  descriptor = registry.fetch(wire_case.fetch("message"))
  descriptor_file = registry.files.find { |file| file.package == descriptor.package }
  raise M1ProbeSupport::ProbeError, "protobuf descriptor file is missing for #{descriptor.full_name}" unless descriptor_file

  raw_json = if scalar_schema
               JSON.generate(value)
             else
               semantic_fixture_json(
                 value,
                 type,
                 codec: codec,
                 types_by_schema: types_by_schema,
                 go_info_by_schema: go_info_by_schema,
                 source_root: source_root,
                 cache: go_metadata_cache,
                 schema: klass.definition
               )
             end
  unknown_json = if scalar_schema
                   raw_json
                 else
                   semantic_fixture_json(
                     unknown_value,
                     type,
                     codec: codec,
                     types_by_schema: types_by_schema,
                     go_info_by_schema: go_info_by_schema,
                     source_root: source_root,
                     cache: go_metadata_cache,
                     schema: klass.definition
                   )
                 end
  missing_json = scalar_schema ? raw_json : JSON.generate(missing_value)
  invalid_value = if scalar_schema
                    value
                  else
                    JSON.parse(JSON.generate(value)).tap do |invalid|
                      invalid["apiVersion"] = 7 if invalid.is_a?(Hash)
                      invalid["m1InvalidField"] = {"value" => 1} if invalid.is_a?(Hash) && invalid["apiVersion"] != 7
                    end
                  end
  invalid_json = scalar_schema ? raw_json : JSON.generate(invalid_value)
  unknown_wire_value = scalar_schema ? value : codec.load_json(unknown_json, schema: klass.definition)
  defaulted = if scalar_schema
                value
              else
                klass.definition.defaulting.apply_hash(
                  value,
                  kubernetes_admission_defaults: false
                )
              end
  validator = klass.definition.validator
  validation_errors = scalar_schema ? [] : validator.errors(value, unknown_fields: :reject)
  validation_missing_errors = scalar_schema ? [] : validator.errors(missing_value, unknown_fields: :reject)
  unknown_validation_errors = scalar_schema ? [] : validator.errors(unknown_wire_value, unknown_fields: :reject)
  unknown_field_errors = unknown_validation_errors.select { |issue| issue.code == :unknown_field }
  validation = M1KubernetesSemanticOracle.validation_registration(
    source_root: source_root,
    go_package: descriptor_file.options.fetch("go_package"),
    go_type: descriptor.name
  )
  parent_fixture = if validation_mapping.fetch("applicable") && validation_mapping.fetch("validation_mode") != "protocol"
                     build_validation_fixture_for_mode(
                       codec: codec,
                       mapping: validation_mapping,
                       raw_json: raw_json,
                       schema_name: schema_name,
                       types_by_schema: types_by_schema,
                       augment: lambda do |hash, owner_type|
                         augment_semantic_fixture(hash, owner_type, types_by_schema: types_by_schema, go_info_by_schema: go_info_by_schema,
                                                                    source_root: source_root, cache: go_metadata_cache)
                         hash
                       end
                     )
                   end
  request = {
    "id" => schema_name,
    "go_package" => descriptor_file.options.fetch("go_package"),
    "go_type" => descriptor.name,
    "raw_json" => raw_json,
    "unknown_json" => unknown_json,
    "missing_json" => missing_json,
    "validation_applicable" => validation.fetch("applicable"),
    "validation_reason" => validation.fetch("reason"),
    "validation_source_paths" => validation.fetch("source_paths")
  }
  local = {
    "id" => schema_name,
    "json" => {
      "accepted" => true,
      "unknown_accepted" => true,
      "unknown_field_preserved" => begin
        parsed_unknown = JSON.parse(unknown_json)
        parsed_unknown.is_a?(Hash) && parsed_unknown.key?("m1FutureField")
      end,
      "strict_unknown_accepted" => unknown_field_errors.empty?,
      "strict_unknown_error" => semantic_error_signature(unknown_field_errors)
    },
    "json_raw" => raw_json,
    "json_canonical_json" => raw_json,
    "json_unknown_raw" => unknown_json,
    "json_unknown_canonical_json" => unknown_json,
    "defaulting_before_json" => raw_json,
    "defaulting_after_json" => if scalar_schema
                                 raw_json
                               else
                                 semantic_fixture_json(
                                   defaulted,
                                   type,
                                   codec: codec,
                                   types_by_schema: types_by_schema,
                                   go_info_by_schema: go_info_by_schema,
                                   source_root: source_root,
                                   cache: go_metadata_cache,
                                   schema: klass.definition
                                 )
                               end,
    "validation_accepted" => validation_errors.empty?,
    "validation_errors" => semantic_error_signature(validation_errors),
    "validation_missing_accepted" => validation_missing_errors.empty?,
    "validation_missing_errors" => semantic_error_signature(validation_missing_errors),
    "strict_unknown_error" => semantic_error_signature(unknown_field_errors),
    "validation_source_paths" => validation.fetch("source_paths"),
    "validation_mapping" => validation_mapping,
    "validation_parent" => parent_fixture
  }
  validation_request = {
    "id" => schema_name,
    "validation_mapping" => validation_mapping.fetch("applicable") ? validation_mapping : nil,
    "validation_reason" => validation_mapping["reason"].to_s,
    "validation_source_paths" => validation_mapping.fetch("source_paths"),
    "fixture_json" => parent_fixture ? parent_fixture.fetch("owner_fixture_json") : raw_json,
    "invalid_fixture_json" => parent_fixture ? parent_fixture.fetch("owner_invalid_fixture_json") : invalid_json,
    "missing_fixture_json" => parent_fixture ? parent_fixture.fetch("owner_missing_fixture_json") : missing_json,
    "update_fixture_json" => parent_fixture ? parent_fixture.fetch("owner_update_fixture_json") : raw_json,
    "validation_expectations" => validation_mapping["expectations"] || {"create" => true, "invalid" => false, "missing" => false,
                                                                        "update" => true}
  }
  [request, local, validation_request]
end

M1ProbeSupport.run_probe("m1_roundtrip_report", pretty: false) do |_current, input|
  registry_path = File.join(ROOT, "generated/schema/registry.json")
  registry_document = M1ProbeSupport.parse_json(registry_path, label: "generated schema registry")
  types = registry_document.fetch("types")
  types_by_schema = types.to_h { |type| [type.fetch("schema"), type] }
  gvks = type_backed_gvks(types)
  openapi_path = File.join(ROOT, "schema/kubernetes/v1.36.2/openapi/swagger.json")
  descriptor_root = File.join(ROOT, "schema/kubernetes/v1.36.2/protobuf")
  wire_runner = Rubernetes::Schema::Codec::ProtoDescriptor::RoundtripCoverage.new(
    openapi_path: openapi_path,
    protobuf_root: descriptor_root
  )
  wire_report = wire_runner.run
  wire_cases = wire_report.fetch("cases").to_h { |entry| [entry.fetch("schema"), entry] }
  descriptor_registry = Rubernetes::Schema::Codec::ProtoDescriptor::Registry.load(descriptor_root)
  codec = Rubernetes::Schema::Codec.new

  unsupported_types = types.filter_map do |type|
    reason = UPSTREAM_PROTOBUF_UNSUPPORTED[type.fetch("schema")]
    {"id" => type.fetch("schema"), "reason" => reason} if reason
  end
  supported_types = types.reject { |type| UPSTREAM_PROTOBUF_UNSUPPORTED.key?(type.fetch("schema")) }

  cases = supported_types.map do |type|
    schema_name = type.fetch("schema")
    klass = generated_class(type)
    required_values = minimal_required_values(type, types_by_schema)
    checks = {
      "json_roundtrip" => false,
      "protobuf_roundtrip" => false,
      "unknown_field" => false,
      "defaulting" => false,
      "validation" => false
    }
    errors = []
    json_unknown_ok = false
    protobuf_unknown_ok = false

    begin
      value = klass.new(required_values)
      encoded_json = codec.canonical_json(value)
      decoded_json = codec.load_json(encoded_json)
      rebuilt = klass.new(decoded_json)
      checks["json_roundtrip"] = encoded_json == codec.canonical_json(rebuilt)
      errors << "canonical JSON changed after decode/encode" unless checks["json_roundtrip"]

      unknown_value = klass.new(required_values.merge("m1FutureField" => {"value" => 1}))
      unknown_json = codec.canonical_json(unknown_value)
      unknown_rebuilt = klass.new(codec.load_json(unknown_json))
      expected_unknown_preserved = klass.definition.preserve_unknown_fields
      json_unknown_ok = unknown_rebuilt.unknown_field?("m1FutureField") == expected_unknown_preserved &&
                        unknown_json == codec.canonical_json(unknown_rebuilt)
      errors << "JSON unknown field policy differs from the generated schema" unless json_unknown_ok

      defaulted_once = klass.definition.defaulting.apply_hash(
        value,
        kubernetes_admission_defaults: false
      )
      defaulted_twice = klass.definition.defaulting.apply_hash(
        defaulted_once,
        kubernetes_admission_defaults: false
      )
      checks["defaulting"] = defaulted_once == defaulted_twice
      errors << "defaulting is not idempotent" unless checks["defaulting"]

      validator = klass.definition.validator
      declared_required = klass.definition.required_fields.map(&:json_name).sort
      registry_required = Array(type.fetch("required", [])).map(&:to_s).sort
      # kube-apiserver decodes an absent or null list/map to Go's nil slice or
      # map and never fails "required" on it (a client marshals an empty
      # slice as null); only scalar and struct fields are enforced by the
      # schema, entries by kind-specific validation.  The validator follows
      # that, so an empty object must report exactly the non-collection
      # required fields.
      enforced_required = klass.definition.required_fields.reject do |field|
        field.array? || (field.type == :object && !field.additional_properties.nil?)
      end.map(&:json_name).sort
      known_issues = validator.errors(value, unknown_fields: :reject)
      missing_value = klass.new({})
      missing_issues = validator.errors(missing_value, unknown_fields: :reject)
      required_issues = missing_issues.select { |issue| issue.code == :required }.map(&:field).sort
      unexpected_missing_issues = missing_issues.reject { |issue| issue.code == :required }
      unknown_issues = validator.errors(unknown_value, unknown_fields: :reject)
      unknown_rejected = unknown_issues.any? do |issue|
        issue.code == :unknown_field && issue.field == "m1FutureField"
      end
      expected_unknown_rejected = !klass.definition.preserve_unknown_fields
      checks["validation"] = declared_required == registry_required &&
                             required_issues == enforced_required &&
                             known_issues.empty? && unexpected_missing_issues.empty? &&
                             (unknown_rejected == expected_unknown_rejected)
      errors << "generated and registry required-field inventories differ" unless declared_required == registry_required
      errors << "required-field validation result differs from the generated definition" unless required_issues == enforced_required
      errors << "type-compatible required-field sample failed validation" unless known_issues.empty?
      errors << "empty value produced unexpected validation issues" unless unexpected_missing_issues.empty?
      errors << "unknown-field validation policy differs from the generated schema" unless unknown_rejected == expected_unknown_rejected
    rescue StandardError => error
      errors << "JSON/defaulting/validation: #{error.class}: #{error.message}"
    end

    wire_case = wire_cases[schema_name]
    if wire_case.nil?
      wire_failure = wire_report.fetch("failures").find { |failure| failure["schema"] == schema_name }
      errors << (if wire_failure
                   "concrete protobuf coverage: #{wire_failure.fetch("message")}"
                 else
                   "concrete protobuf coverage case is missing"
                 end)
    else
      checks["protobuf_roundtrip"] = true
      protobuf_unknown_ok = wire_case.fetch("unknown_wire_preserved") == true
      errors << "concrete protobuf unknown field was not preserved" unless protobuf_unknown_ok
    end

    checks["unknown_field"] = json_unknown_ok && protobuf_unknown_ok
    {
      "id" => schema_name,
      "ruby_constant" => type.fetch("ruby_constant"),
      "descriptor" => wire_case && wire_case.fetch("message"),
      "wire_coverage" => wire_case,
      "attempt_count" => 1,
      **checks,
      "passed" => checks.values.all?,
      "errors" => errors
    }
  end
  validation_mapping_by_schema = {}
  validation_mapping_error = nil
  begin
    validation_mappings = M1KubernetesValidationOracle.map_types(
      source_root: KUBERNETES_SOURCE_ROOT,
      types: supported_types
    )
    validation_mapping_by_schema = validation_mappings.to_h { |mapping| [mapping.fetch("target_schema"), mapping] }
  rescue StandardError => error
    validation_mapping_error = "Kubernetes validation applicability mapping failed: #{error.class}: #{error.message}"
  end

  semantic_requests = []
  semantic_locals = {}
  validation_requests = []
  semantic_build_error = nil
  begin
    raise M1ProbeSupport::ProbeError, validation_mapping_error if validation_mapping_error

    go_info_by_schema = supported_types.to_h do |type|
      schema_name = type.fetch("schema")
      wire_case = wire_cases.fetch(schema_name)
      descriptor = descriptor_registry.fetch(wire_case.fetch("message"))
      descriptor_file = descriptor_registry.files.find { |file| file.package == descriptor.package }
      raise M1ProbeSupport::ProbeError, "protobuf descriptor file is missing for #{descriptor.full_name}" unless descriptor_file

      [schema_name, {
        "go_package" => descriptor_file.options.fetch("go_package"),
        "go_type" => descriptor.name
      }]
    end
    go_metadata_cache = {}
    supported_types.each do |type|
      schema_name = type.fetch("schema")
      wire_case = wire_cases.fetch(schema_name) do
        raise M1ProbeSupport::ProbeError, "cannot build semantic oracle request without wire case for #{schema_name}"
      end
      request, local, validation_request = build_semantic_case(
        registry: descriptor_registry,
        codec: codec,
        type: type,
        wire_case: wire_case,
        types_by_schema: types_by_schema,
        go_info_by_schema: go_info_by_schema,
        source_root: KUBERNETES_SOURCE_ROOT,
        validation_mapping: validation_mapping_by_schema.fetch(schema_name),
        go_metadata_cache: go_metadata_cache
      )
      semantic_requests << request
      validation_requests << validation_request
      semantic_locals[schema_name] = local
    end
  rescue StandardError => error
    semantic_build_error = "Kubernetes semantic oracle fixture construction failed: #{error.class}: #{error.message}"
  end

  failure_counts = {
    "json_roundtrip_failures" => cases.count { |entry| !entry.fetch("json_roundtrip") },
    "protobuf_roundtrip_failures" => cases.count { |entry| !entry.fetch("protobuf_roundtrip") },
    "unknown_field_failures" => cases.count { |entry| !entry.fetch("unknown_field") },
    "defaulting_failures" => cases.count { |entry| !entry.fetch("defaulting") },
    "validation_failures" => cases.count { |entry| !entry.fetch("validation") }
  }
  structural_errors = []
  oracle_requests = []
  oracle_locals = {}
  oracle = nil
  begin
    supported_types.each do |type|
      schema_name = type.fetch("schema")
      wire_case = wire_cases.fetch(schema_name) do
        raise M1ProbeSupport::ProbeError, "cannot build oracle request without wire case for #{schema_name}"
      end
      request, local = build_oracle_request(
        descriptor_registry,
        wire_runner,
        schema_name,
        wire_case.fetch("message")
      )
      oracle_requests << request
      oracle_locals[schema_name] = local
    end
    raw_oracle = M1KubernetesProtobufOracle.compare(
      source_root: KUBERNETES_SOURCE_ROOT,
      registry: descriptor_registry,
      requests: oracle_requests
    )
    oracle_results = raw_oracle.fetch("results")
    comparisons = oracle_results.map do |result|
      compare_oracle_case(descriptor_registry, oracle_locals.fetch(result.fetch("id")), result)
    end.sort_by { |comparison| comparison.fetch("id") }
    oracle = raw_oracle.reject { |key, _value| key == "results" }.merge("comparisons" => comparisons)
  rescue StandardError => error
    reason = "Kubernetes protobuf oracle failed closed: #{error.class}: #{error.message}"
    structural_errors << reason
    oracle = {
      "executed" => false,
      "kubernetes_version" => M1KubernetesProtobufOracle::KUBERNETES_VERSION,
      "source_commit" => M1KubernetesProtobufOracle::SOURCE_COMMIT,
      "source_root" => KUBERNETES_SOURCE_ROOT,
      "runner_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/m1_kubernetes_protobuf_oracle.rb")).hexdigest,
      "request_seed_sha256" => Digest::SHA256.hexdigest(JSON.generate(oracle_requests)),
      "comparison_count" => 0,
      "missing_comparison_count" => cases.length,
      "comparisons" => [],
      "reason" => reason
    }
  end

  validation_oracle = nil
  validation_results_by_id = {}
  validation_criterion = nil
  begin
    raise M1ProbeSupport::ProbeError, validation_mapping_error if validation_mapping_error

    raw_validation_oracle = M1KubernetesValidationOracle.compare(
      source_root: KUBERNETES_SOURCE_ROOT,
      requests: validation_requests
    )
    validation_criterion = raw_validation_oracle.fetch("validation_criterion")
    validation_oracle = compact_validation_oracle(raw_validation_oracle)
    validation_oracle.delete("validation_criterion")
    validation_oracle["validation_criterion_sha256"] = semantic_digest(validation_criterion)
    validation_results_by_id = raw_validation_oracle.fetch("comparisons").to_h do |comparison|
      [comparison.fetch("id"), comparison]
    end
  rescue StandardError => error
    reason = "Kubernetes REST validation oracle failed closed: #{error.class}: #{error.message}"
    structural_errors << reason
    validation_oracle = {
      "executed" => false,
      "kubernetes_version" => M1KubernetesValidationOracle::KUBERNETES_VERSION,
      "source_commit" => M1KubernetesValidationOracle::SOURCE_COMMIT,
      "source_tag" => M1KubernetesValidationOracle::KUBERNETES_VERSION,
      "source_root" => KUBERNETES_SOURCE_ROOT,
      "source_tree_clean" => true,
      "runner_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/m1_kubernetes_validation_oracle.rb")).hexdigest,
      "request_seed_sha256" => Digest::SHA256.hexdigest(JSON.generate(validation_requests)),
      "comparison_count" => 0,
      "missing_comparison_count" => cases.length,
      "validation_criterion" => {
        "status" => "INCOMPLETE",
        "applicable_count" => 0,
        "not_applicable_count" => cases.length,
        "ledger" => []
      },
      "comparisons" => [],
      "reason" => reason
    }
    validation_criterion = validation_oracle.fetch("validation_criterion")
    validation_oracle.delete("validation_criterion")
    validation_oracle["validation_criterion_sha256"] = semantic_digest(validation_criterion)
  end

  # The generated protobuf oracle above remains the 770-type wire oracle. The
  # semantic oracle is an independent Go runner over the same generated JSON
  # fixtures. Validation is overridden below by the REST strategy oracle so
  # nested descriptors are compared through their observable owner resource.
  semantic_oracle = nil
  semantic_comparisons = []
  begin
    raise M1ProbeSupport::ProbeError, semantic_build_error if semantic_build_error

    raw_semantic_oracle = M1KubernetesSemanticOracle.compare(
      source_root: KUBERNETES_SOURCE_ROOT,
      requests: semantic_requests
    )
    semantic_comparisons = raw_semantic_oracle.fetch("comparisons").map do |external|
      id = external.fetch("id")
      validation_mapping = validation_mapping_by_schema.fetch(id)
      direct_validation = validation_results_by_id.fetch(id) do
        raise M1ProbeSupport::ProbeError, "REST validation comparison is missing for #{id}"
      end
      compare_semantic_case(
        semantic_locals.fetch(id),
        external,
        validation_override: compare_direct_validation_case(
          semantic_locals.fetch(id),
          direct_validation,
          validation_mapping
        )
      )
    end.sort_by { |comparison| comparison.fetch("id") }
    semantic_oracle = raw_semantic_oracle.reject { |key, _value| key == "comparisons" }.merge(
      "validation_criterion" => validation_criterion,
      "comparisons" => semantic_comparisons
    )
  rescue StandardError => error
    reason = "Kubernetes semantic oracle failed closed: #{error.class}: #{error.message}"
    structural_errors << reason
    fallback_provenance = {
      "kind" => M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "pinned Go encoding/json plus runtime.Scheme Default and generated validation",
      "source" => {
        "version" => M1KubernetesSemanticOracle::KUBERNETES_VERSION,
        "commit" => M1KubernetesSemanticOracle::SOURCE_COMMIT,
        "tag" => M1KubernetesSemanticOracle::KUBERNETES_VERSION,
        "root" => KUBERNETES_SOURCE_ROOT,
        "tree_clean" => true
      },
      "runner_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/m1_kubernetes_semantic_oracle.rb")).hexdigest,
      "request_seed_sha256" => Digest::SHA256.hexdigest(JSON.generate(semantic_requests))
    }
    fallback_provenance["provenance_sha256"] = M1Gate.canonical_document_digest(fallback_provenance)
    semantic_oracle = {
      "executed" => false,
      "kubernetes_version" => M1KubernetesSemanticOracle::KUBERNETES_VERSION,
      "source_commit" => M1KubernetesSemanticOracle::SOURCE_COMMIT,
      "source_root" => KUBERNETES_SOURCE_ROOT,
      "runner_sha256" => fallback_provenance.fetch("runner_sha256"),
      "request_seed_sha256" => fallback_provenance.fetch("request_seed_sha256"),
      "comparison_count" => 0,
      "missing_comparison_count" => cases.length,
      "comparisons" => [],
      "provenance" => fallback_provenance,
      "reason" => reason
    }
  end

  ruby_validation_error_catalog = {}
  semantic_locals.each_value do |local|
    parent = local.dig("validation_parent", "owner_validation")
    next unless parent.is_a?(Hash)

    %w[create_errors invalid_errors update_errors missing_errors].each do |key|
      errors = Array(parent[key])
      ruby_validation_error_catalog[semantic_digest(errors)] = errors
    end
  end
  validation_oracle["rubernetes_error_catalog"] = ruby_validation_error_catalog if validation_oracle.is_a?(Hash)

  comparisons_by_id = oracle.fetch("comparisons").to_h { |comparison| [comparison.fetch("id"), comparison] }
  cases.each do |entry|
    comparison = comparisons_by_id[entry.fetch("id")]
    entry["kubernetes_oracle"] = comparison&.fetch("passed", false) == true
    entry["oracle_comparison"] = comparison
    entry["errors"].concat(Array(comparison && comparison["errors"]))
    entry["errors"] << "Kubernetes protobuf oracle comparison is missing" unless comparison
    entry["passed"] = entry.fetch("passed") && entry.fetch("kubernetes_oracle")
  end
  semantic_comparisons_by_id = semantic_comparisons.to_h { |comparison| [comparison.fetch("id"), comparison] }
  cases.each do |entry|
    comparison = semantic_comparisons_by_id[entry.fetch("id")]
    entry["semantic_oracle"] = comparison&.fetch("passed", false) == true
    # Keep the per-case report bounded; the complete semantic observation,
    # digests, and applicability ledger live in semantic_oracle.comparisons.
    entry["semantic_comparison"] = comparison && comparison.slice("id", "passed", "differences", "errors")
    entry["errors"].concat(Array(comparison && comparison["errors"]))
    entry["errors"] << "Kubernetes semantic oracle comparison is missing" unless comparison
    entry["passed"] = entry.fetch("passed") && entry.fetch("semantic_oracle")
  end
  oracle_difference_count = cases.count { |entry| !entry.fetch("kubernetes_oracle") }
  semantic_difference_count = cases.count { |entry| !entry.fetch("semantic_oracle") }
  failed_cases = cases.count { |entry| !entry.fetch("passed") }

  unknown_mismatches = semantic_comparisons.filter_map do |comparison|
    dimension = comparison["json"]
    next unless dimension.is_a?(Hash)

    next unless dimension.dig("expected", "unknown_accepted") == true

    expected = dimension.dig("expected", "unknown_field_preserved")
    actual = dimension.dig("actual", "unknown_field_preserved")
    next if expected == actual

    expected_observation = dimension.fetch("expected_observation", {})
    actual_observation = dimension.fetch("actual_observation", {})
    {
      "id" => comparison.fetch("id"),
      "field" => (if dimension.dig("expected_errors", "strict_unknown",
                                   "field").to_s.empty?
                    "m1FutureField"
                  else
                    dimension.dig("expected_errors", "strict_unknown", "field").to_s
                  end),
      "kubernetes_preserved" => expected,
      "rubernetes_preserved" => actual,
      "raw_sha256" => actual_observation["unknown_raw_sha256"],
      "kubernetes_canonical_sha256" => expected_observation["unknown_canonical_sha256"],
      "rubernetes_canonical_sha256" => actual_observation["unknown_canonical_sha256"]
    }
  end.sort_by { |entry| entry.fetch("id") }
  unknown_non_comparable = semantic_comparisons.filter_map do |comparison|
    dimension = comparison["json"]
    next unless dimension.is_a?(Hash)
    next unless dimension.dig("expected", "unknown_accepted") == false

    {
      "id" => comparison.fetch("id"),
      "field" => "m1FutureField",
      "reason" => "Kubernetes concrete JSON fixture was rejected before unknown-field handling",
      "kubernetes_error" => dimension.dig("expected_errors", "unknown_decode")
    }
  end.sort_by { |entry| entry.fetch("id") }
  unknown_groups = unknown_mismatches.group_by { |entry| entry.fetch("field") }.map do |field, entries|
    {
      "field" => field,
      "type_count" => entries.length,
      "type_ids_sha256" => Digest::SHA256.hexdigest(JSON.generate(entries.map { |entry| entry.fetch("id") }))
    }
  end.sort_by { |entry| entry.fetch("field") }
  unknown_field_mismatch_packet = {
    "executed" => semantic_oracle.fetch("executed", false) == true,
    "comparison_count" => semantic_comparisons.length,
    "mismatch_count" => unknown_mismatches.length,
    "non_comparable_count" => unknown_non_comparable.length,
    "groups" => unknown_groups,
    "by_type" => unknown_mismatches,
    "non_comparable_by_type" => unknown_non_comparable,
    "production_codec_fix_packet" => {
      "status" => unknown_mismatches.empty? ? "NOT_REQUIRED" : "REQUIRED",
      # Nothing is ever applied by the probe; when no mismatch exists the
      # packet is simply not required.
      "not_applied" => true,
      "target_files" => [
        "lib/rubernetes/schema/value_object.rb",
        "lib/rubernetes/schema/codec.rb",
        "lib/rubernetes/schema/codec/json.rb"
      ],
      "behavior" => "For Kubernetes typed JSON canonical encoding, prune unknown fields unless preservation is explicitly requested; retain strict unknown-field rejection and concrete protobuf unknown-field preservation.",
      "verification" => "Re-run the 770-type M1 semantic oracle and retain this packet until all per-type unknown-field digests match."
    }
  }

  structural_errors << "type-backed GVK count must equal 311 (got #{gvks.length})" unless gvks.length == 311
  structural_errors << "generated type count must equal 771 (got #{types.length})" unless types.length == 771
  structural_errors << "protobuf-supported type count must equal 770 (got #{supported_types.length})" unless supported_types.length == 770
  unless wire_report.fetch("success") == true && wire_report.fetch("failure_count").zero?
    structural_errors << "concrete protobuf all-field coverage report did not pass"
  end
  expected_unsupported = UPSTREAM_PROTOBUF_UNSUPPORTED.keys.sort
  actual_unsupported = unsupported_types.map { |entry| entry.fetch("id") }.sort
  unless actual_unsupported == expected_unsupported
    structural_errors << "protobuf unsupported inventory differs from the pinned upstream exception"
  end
  unless validation_criterion.is_a?(Hash) &&
         validation_criterion["status"] == "COMPLETE" &&
         validation_criterion["applicable_count"] == cases.length &&
         validation_criterion["not_applicable_count"] == 0
    structural_errors << "Kubernetes validation applicability criterion is not COMPLETE for every generated type"
  end
  registry_gvk_count = Array(registry_document.fetch("gvks")).length
  structural_errors << "generated registry GVK count must equal 321 (got #{registry_gvk_count})" unless registry_gvk_count == 321
  failure_count = failed_cases + structural_errors.length

  {
    "gvk_count" => gvks.length,
    "case_count" => cases.length,
    "registry_gvk_count" => registry_gvk_count,
    "protobuf_expected_supported_count" => 770,
    "protobuf_supported_count" => supported_types.length,
    "protobuf_unsupported_count" => unsupported_types.length,
    "protobuf_unsupported_types" => unsupported_types,
    "protobuf_wire_report" => wire_report.reject { |key, _value| key == "cases" },
    "gvks" => gvks,
    "cases" => cases,
    "oracle" => oracle,
    "validation_oracle" => validation_oracle,
    "semantic_oracle" => semantic_oracle,
    "unknown_field_mismatch_packet" => unknown_field_mismatch_packet,
    **failure_counts,
    "oracle_difference_count" => oracle_difference_count,
    "semantic_difference_count" => semantic_difference_count,
    "failure_count" => failure_count,
    "errors" => structural_errors,
    "passed" => input.fetch("stable") && failure_count.zero?
  }
end
