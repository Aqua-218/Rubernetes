# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/schema/codec"
require_relative "../../generated/ruby/kubernetes_types"

class SchemaUnknownFieldsTest < Minitest::Test
  REGISTRY_PATH = File.expand_path("../../generated/schema/registry.json", __dir__)
  REGISTRY = JSON.parse(File.read(REGISTRY_PATH)).freeze
  TYPES = REGISTRY.fetch("types").freeze
  OPAQUE_TYPE_COUNT = TYPES.count { |type| type.fetch("preserve_unknown_fields", false) }

  def setup
    @codec = Rubernetes::Schema::Codec.new
  end

  def test_codec_policy_covers_every_generated_descriptor
    observations = TYPES.map do |type|
      klass = Rubernetes::Generated.const_get(type.fetch("ruby_constant"), false)
      value = klass.new("m1FutureField" => {"value" => 1})
      expected_preserved = klass.definition.preserve_unknown_fields
      encoded = @codec.canonical_json(value)
      preserved = JSON.parse(encoded).key?("m1FutureField")
      explicit_preserved = JSON.parse(
        @codec.canonical_json(value, unknown_fields: :preserve)
      ).key?("m1FutureField")
      rejected = begin
        @codec.canonical_json(value, unknown_fields: :reject)
        false
      rescue Rubernetes::Schema::Codec::UnknownFieldError
        true
      end
      {
        "schema" => type.fetch("schema"),
        "preserved" => preserved,
        "expected_preserved" => expected_preserved,
        "explicit_preserved" => explicit_preserved,
        "rejected" => rejected
      }
    end

    assert_equal 771, observations.length
    assert_equal 3, OPAQUE_TYPE_COUNT
    assert_empty observations.reject { |item| item.fetch("preserved") == item.fetch("expected_preserved") }
    assert observations.all? { |item| item.fetch("explicit_preserved") }
    assert(observations.all? do |item|
      item.fetch("rejected") == !item.fetch("expected_preserved")
    end)
  end

  def test_nested_schema_preserve_marker_overrides_parent_pruning
    definition = Rubernetes::Schema::Definition.new(
      name: "Envelope",
      version: "v1",
      kind: "Envelope",
      fields: {
        "opaque" => Rubernetes::Schema::Field.new(
          "opaque",
          :object,
          preserve_unknown_fields: true
        )
      }
    )
    value = definition.value_class.new(
      "opaque" => {"future" => {"enabled" => true}},
      "topFuture" => true
    )

    assert_equal(
      "{\"opaque\":{\"future\":{\"enabled\":true}}}",
      @codec.canonical_json(value)
    )
    assert_equal(
      {"opaque" => {"future" => {"enabled" => true}}},
      @codec.load_json(
        '{"opaque":{"future":{"enabled":true}},"topFuture":true}',
        schema: definition,
        unknown_fields: :prune
      )
    )
    assert_raises(Rubernetes::Schema::Codec::UnknownFieldError) do
      @codec.canonical_json(value, unknown_fields: :reject)
    end
    error = assert_raises(Rubernetes::Schema::Codec::UnknownFieldError) do
      @codec.load_json(
        '{"opaque":{"future":{"enabled":true}},"topFuture":true}',
        schema: definition
      )
    end
    assert_match(/topFuture/, error.message)
  end

  def test_value_object_lossless_view_remains_distinct_from_typed_codec_view
    definition = Rubernetes::Schema::Definition.new(
      name: "TypedObject",
      version: "v1",
      kind: "TypedObject",
      fields: {"name" => :string}
    )
    value = definition.value_class.new("name" => "ok", "future" => {"value" => 1})

    assert_equal({"name" => "ok", "future" => {"value" => 1}}, value.to_h)
    assert_equal({"name" => "ok"}, value.to_h_for_codec)
    assert_equal({"name" => "ok", "future" => {"value" => 1}}, value.to_h_for_codec(unknown_fields: :preserve))
  end
end
