# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema/codec/proto_descriptor"

class ProtoDescriptorTest < Minitest::Test
  Descriptor = Rubernetes::Schema::Codec::ProtoDescriptor
  Protobuf = Rubernetes::Schema::Codec::Protobuf
  PROTO_ROOT = File.expand_path("../../schema/kubernetes/v1.36.2/protobuf", __dir__)

  def setup
    @registry = Descriptor.load(PROTO_ROOT)
  end

  def test_corpus_builds_message_field_and_map_descriptors
    config_map = @registry.fetch("io.k8s.api.core.v1.ConfigMap")
    metadata = @registry.fetch("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta")

    assert_equal "k8s.io.api.core.v1.ConfigMap", config_map.full_name
    assert_equal 1, config_map.field("metadata").number
    assert_equal :message, config_map.field("metadata").type_kind
    assert_predicate config_map.field("data"), :map?
    assert_equal :string, config_map.field("data").key_type
    assert_equal :string, config_map.field("data").value_type
    assert_equal 11, metadata.field("labels").number
    assert_equal 13, metadata.field("ownerReferences").number
  end

  def test_openapi_and_gvk_resolution_are_equivalent
    expected = @registry.fetch("k8s.io.api.apps.v1.Deployment")

    assert_same expected, @registry.resolve("io.k8s.api.apps.v1.Deployment")
    assert_same expected, @registry.resolve_gvk(group: "apps", version: "v1", kind: "Deployment")
    assert_same expected, @registry.resolve("apps/v1/Deployment")
    assert_same @registry.fetch("k8s.io.api.core.v1.ConfigMap"),
                @registry.resolve_gvk(group: "", version: "v1", kind: "ConfigMap")
  end

  def test_openapi_hyphenated_packages_resolve_to_proto_underscores
    apiextensions = @registry.resolve(
      "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition"
    )
    aggregator = @registry.resolve(
      "io.k8s.kube-aggregator.pkg.apis.apiregistration.v1.APIService"
    )

    assert_equal "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition",
                 apiextensions.full_name
    assert_equal "k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.APIService", aggregator.full_name
    assert_nil @registry.resolve("io.k8s.apimachinery.pkg.version.Info")
  end

  def test_config_map_map_and_object_meta_round_trip_deterministically
    value = {
      "metadata" => {"name" => "demo", "labels" => {"z" => "last", "a" => "first"}},
      "data" => {"z" => "last", "a" => "first"},
      "binaryData" => {"raw" => "\x00\xff".b},
      "immutable" => true
    }
    first = @registry.encode("io.k8s.api.core.v1.ConfigMap", value)
    second = @registry.encode("io.k8s.api.core.v1.ConfigMap", value)

    assert_equal first, second
    assert_equal [10, 29, 10, 4, 100, 101, 109, 111, 90, 10, 10, 1, 97, 18, 5, 102, 105, 114, 115,
                  116, 90, 9, 10, 1, 122, 18, 4, 108, 97, 115, 116, 18, 10, 10, 1, 97, 18, 5, 102,
                  105, 114, 115, 116, 18, 9, 10, 1, 122, 18, 4, 108, 97, 115, 116, 26, 9, 10, 3,
                  114, 97, 119, 18, 2, 0, 255, 32, 1], first.bytes
    assert_equal value, @registry.decode("io.k8s.api.core.v1.ConfigMap", first)
  end

  def test_pod_repeated_nested_messages_round_trip
    value = {
      "metadata" => {"name" => "demo"},
      "spec" => {
        "containers" => [
          {"name" => "web", "image" => "nginx", "ports" => [{"containerPort" => 80}]},
          {"name" => "sidecar", "image" => "busybox"}
        ],
        "restartPolicy" => "Never"
      }
    }

    encoded = @registry.encode("io.k8s.api.core.v1.Pod", value)
    decoded = @registry.decode("io.k8s.api.core.v1.Pod", encoded)

    assert_equal value, decoded
    assert_equal encoded, @registry.encode("io.k8s.api.core.v1.Pod", decoded)
  end

  def test_unknown_concrete_fields_are_retained_and_reencoded
    descriptor = "io.k8s.api.core.v1.ConfigMap"
    known = @registry.encode(descriptor, {"metadata" => {"name" => "demo"}})
    unknown = Protobuf.encode_field(99, "future", type: :string)
    decoded = @registry.decode(descriptor, known + unknown)

    assert_equal 99, decoded.unknown_fields.fetch(0).fetch(:number)
    assert_equal known + unknown, @registry.encode(descriptor, decoded)
  end

  def test_kubernetes_compatibility_discards_unknown_fields_but_preserves_known_wire_bytes
    descriptor = "io.k8s.api.core.v1.ConfigMap"
    known = @registry.encode(descriptor, {"metadata" => {"name" => "demo"}})
    unknown = Protobuf.encode_field(99, "future", type: :string)
    decoded = @registry.decode(descriptor, known + unknown, compatibility: :kubernetes)

    assert_empty decoded.unknown_fields
    assert_equal known, @registry.encode(descriptor, decoded)
  end

  def test_kubernetes_compatibility_rebuilds_envelope_without_unknown_concrete_fields
    descriptor = "io.k8s.api.core.v1.ConfigMap"
    value = {"metadata" => {"name" => "demo"}}
    known = @registry.encode(descriptor, value)
    unknown = Protobuf.encode_field(99, "future", type: :string)
    clean_envelope = Protobuf.decode_envelope(@registry.encode_envelope(descriptor, value))
    upstream_input = Protobuf.encode_envelope(
      raw: known + unknown,
      type_meta: clean_envelope.type_meta,
      content_encoding: clean_envelope.content_encoding,
      content_type: clean_envelope.content_type
    )

    decoded = @registry.decode_envelope(descriptor, upstream_input, compatibility: :kubernetes)
    rebuilt = Protobuf.decode_envelope(@registry.encode_envelope(descriptor, decoded))

    assert_empty decoded.unknown_fields
    assert_equal known, decoded.raw
    assert_equal known, rebuilt.raw
    refute_equal upstream_input, @registry.encode_envelope(descriptor, decoded)
  end

  def test_runtime_unknown_envelope_round_trip_uses_concrete_type_meta
    descriptor = "io.k8s.api.core.v1.ConfigMap"
    value = {"metadata" => {"name" => "demo"}, "data" => {"key" => "value"}}
    encoded = @registry.encode_envelope(descriptor, value)
    decoded = @registry.decode_envelope(descriptor, encoded)

    assert_equal "k8s\x00".b, encoded.byteslice(0, 4)
    assert_equal({api_version: "v1", kind: "ConfigMap"}, decoded.type_meta)
    assert_equal "application/vnd.kubernetes.protobuf", decoded.content_type
    assert_equal value, decoded
    assert_equal encoded, @registry.encode_envelope(descriptor, decoded)
  end

  def test_duplicate_field_numbers_and_limits_are_rejected
    source = <<~PROTO
      syntax = "proto2";
      package test;
      message Duplicate { optional string first = 1; optional string second = 1; }
    PROTO

    assert_raises(Descriptor::DuplicateFieldError) { Descriptor.parse(source) }
    assert_raises(Descriptor::LimitError) { Descriptor::Registry.parse("message A { optional string x = 1; }", max_bytes: 4) }
    assert_raises(Descriptor::LimitError) { @registry.decode("io.k8s.api.core.v1.ConfigMap", "\x0a\x03abc".b, max_depth: 0) }
  end
end
