# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema/codec"

class SchemaCodecTest < Minitest::Test
  Codec = Rubernetes::Schema::Codec

  def setup
    @codec = Codec.new
  end

  def test_strict_json_rejects_duplicate_keys_after_unescaping
    error = assert_raises(Codec::DuplicateKeyError) do
      @codec.load_json('{"name": "first", "\\u006eame": "second"}')
    end

    assert_match(/duplicate JSON object key/, error.message)
  end

  def test_json_unknown_fields_survive_load_and_dump
    value = @codec.load_json('{"kind":"Pod","futureField":{"enabled":true}}')

    assert_equal true, value.fetch("futureField").fetch("enabled")
    assert_equal '{"futureField":{"enabled":true},"kind":"Pod"}', @codec.canonical_json(value)
  end

  def test_canonical_json_sorts_keys_and_is_repeatable
    value = {"z" => 1, "a" => {"y" => 2, "x" => 3}, "m" => [true, nil]}

    first = @codec.canonical_json(value)
    second = @codec.canonical_json(value)

    assert_equal '{"a":{"x":3,"y":2},"m":[true,null],"z":1}', first
    assert_equal first, second
  end

  def test_canonical_json_uses_deterministic_number_forms
    assert_equal "1", @codec.canonical_json(1.0)
    assert_equal "0", @codec.canonical_json(-0.0)
    assert_equal "100000000000000000000", @codec.canonical_json(1e20)
    assert_equal "1e+21", @codec.canonical_json(1e21)
    assert_equal "0.000001", @codec.canonical_json(1e-6)
  end

  def test_strict_yaml_rejects_duplicate_keys_and_aliases
    assert_raises(Codec::DuplicateKeyError) { @codec.load_yaml("name: first\nname: second\n") }
    assert_raises(Codec::ParseError) { @codec.load_yaml("base: &base\n  enabled: true\ncopy: *base\n") }
  end

  def test_yaml_round_trip_preserves_unknown_fields
    value = {"apiVersion" => "v1", "unknown" => [1, {"flag" => false}]}
    encoded = @codec.dump_yaml(value)

    assert_equal value, @codec.load_yaml(encoded)
  end

  def test_json_and_yaml_limits_are_checked_before_processing
    limited = Codec.new(max_bytes: 8, max_depth: 2)

    assert_raises(Codec::LimitError) { limited.load_json('{"long":"value"}') }
    assert_raises(Codec::LimitError) { limited.load_json('{"a":{"b":{"c":1}}}') }
    assert_raises(Codec::LimitError) { limited.load_yaml("a:\n  b:\n    c: 1\n") }
  end

  def test_canonical_cbor_uses_shortest_forms_and_deterministic_map_order
    value = {"z" => 1, "a" => 1, "long" => 1}
    encoded = @codec.canonical_cbor(value)

    assert_equal [0xa3, 0x61, 0x61, 0x01, 0x61, 0x7a, 0x01, 0x64, 0x6c, 0x6f, 0x6e, 0x67, 0x01], encoded.bytes
    assert_equal value, @codec.decode_cbor(encoded)
  end

  def test_cbor_preserves_binary_strings_and_rejects_noncanonical_map_order
    binary = "\x00\xff".b
    encoded = @codec.encode_cbor(binary)

    assert_equal binary, @codec.decode_cbor(encoded)
    assert_raises(Codec::ParseError) { @codec.decode_cbor("\xa2\x61b\x01\x61a\x02".b) }
  end

  def test_cbor_depth_and_body_limits_are_checked
    limited = Codec.new(max_bytes: 4, max_depth: 1)

    assert_raises(Codec::LimitError) { limited.decode_cbor("\x82\x81\x01\x01".b) }
    assert_raises(Codec::LimitError) { limited.encode_cbor(["long"]) }
  end

  def test_kubernetes_protobuf_envelope_preserves_raw_bytes_and_unknown_fields
    raw = '{"kind":"Pod"}'.b
    unknown_field = "\x98\x06\x01".b # field 99, varint 1
    encoded = @codec.encode_protobuf(raw: raw, content_type: "application/json") + unknown_field
    decoded = @codec.decode_protobuf(encoded)

    assert_equal raw, decoded.raw
    assert_equal [0x6b, 0x38, 0x73, 0x00, 0x0a, 0x04, 0x0a, 0x00, 0x12, 0x00,
                  0x12, raw.bytesize, *raw.bytes,
                  0x1a, 0x00, 0x22, 0x10, *"application/json".bytes, 0x98, 0x06, 0x01], encoded.bytes
    assert_equal "application/json", decoded.content_type
    assert_equal 99, decoded.unknown_fields.fetch(0).fetch(:number)
    assert_equal raw, @codec.decode_protobuf(@codec.encode_protobuf(decoded)).raw
    assert_equal({"kind" => "Pod"}, @codec.decode_protobuf_json(@codec.encode_protobuf(raw: raw)))
  end

  def test_kubernetes_protobuf_rejects_invalid_magic_and_duplicate_envelope_fields
    assert_raises(Codec::ParseError) { @codec.decode_protobuf("not protobuf") }
    duplicate_raw = "\x12\x01a\x12\x01b".b
    assert_raises(Codec::DuplicateKeyError) { @codec.decode_protobuf("k8s\x00".b + duplicate_raw) }
  end

  def test_kubernetes_protobuf_preserves_runtime_unknown_metadata_fields
    encoded = @codec.encode_protobuf(
      raw: "payload".b,
      type_meta: {api_version: "apps/v1", kind: "Deployment"},
      content_encoding: "gzip",
      content_type: "application/json"
    )
    decoded = @codec.decode_protobuf(encoded)

    assert_equal({api_version: "apps/v1", kind: "Deployment"}, decoded.type_meta)
    assert_equal "gzip", decoded.content_encoding
    assert_equal "application/json", decoded.content_type
    assert_equal encoded, @codec.encode_protobuf(decoded)
  end

  def test_protobuf_primitives_round_trip_and_reject_noncanonical_varint
    protobuf = Codec::Protobuf

    assert_equal 300, protobuf.decode_varint(protobuf.encode_varint(300))
    assert_equal(-123, protobuf.decode_int32(protobuf.encode_int32(-123)))
    assert_equal(-123, protobuf.decode_sint64(protobuf.encode_sint64(-123)))
    assert_equal 0xfeedface, protobuf.decode_fixed32(protobuf.encode_fixed32(0xfeedface))
    assert_raises(Codec::ParseError) { protobuf.decode_varint("\x80\x00".b) }
  end

  def test_strict_schema_field_validation_is_opt_in_to_unknown_pruning
    input = '{"kind":"Pod","future":true}'

    assert_raises(Codec::UnknownFieldError) do
      @codec.load_json(input, known_fields: ["kind"], preserve_unknown: false)
    end
    assert_equal true, @codec.load_json(input, known_fields: ["kind"]).fetch("future")
  end
end
