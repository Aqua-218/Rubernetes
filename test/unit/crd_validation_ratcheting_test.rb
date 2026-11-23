# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class CRDValidationRatchetingTest < Minitest::Test
  SCHEMA = Rubernetes::API::CRD::StructuralSchema

  def test_json_errors_in_changed_indivisible_lists_are_checked_even_at_unchanged_indexes
    elements = {"type" => "string", "enum" => ["allowed"]}
    schema = validator("atomic" => {"type" => "array", "items" => elements},
                       "set" => {"type" => "array", "items" => elements, "x-kubernetes-list-type" => "set"})
    old = {"atomic" => ["legacy"], "set" => ["legacy"]}

    assert schema.validate(old.merge("metadata" => {"labels" => {"a" => "b"}}), old: old)
    error = assert_raises(SCHEMA::Invalid) do
      schema.validate({"atomic" => %w[legacy allowed], "set" => %w[legacy allowed]}, old: old)
    end
    assert_equal(%w[atomic[0] set[0]], error.causes.map { |cause| cause["field"] })
  end

  def test_cel_ratcheting_correlates_map_list_entries_after_reordering_and_new_entries
    field = {"type" => "string", "x-kubernetes-validations" => [{"rule" => "self == 'allowed'"}]}
    schema = validator("items" => list_map(field), "map" => {"type" => "object", "additionalProperties" => record(field)})
    first = {"key" => "one", "field" => "legacy-one"}
    second = {"key" => "two", "field" => "legacy-two"}
    old = {"items" => [first, second], "map" => {"existing" => {"field" => "legacy"}}}
    new_record = {"key" => "three", "field" => "allowed"}
    current = old.merge("items" => [second, new_record, first])

    assert schema.validate(current, old: old)
    changed = current.merge("items" => [second.merge("field" => "changed"), new_record, first],
                            "map" => {"existing" => {"field" => "changed"}})
    error = assert_raises(SCHEMA::Invalid) { schema.validate(changed, old: old) }

    assert_equal(%w[items[0].field map[existing].field], error.causes.map { |cause| cause["field"] })
  end

  def test_optional_old_self_receives_none_for_new_list_keys_and_preserves_transition_errors
    field = {"type" => "string", "x-kubernetes-validations" => [{"rule" => "!oldSelf.hasValue() || self != oldSelf.value()",
                                                                 "optionalOldSelf" => true}]}
    schema = validator("items" => list_map(field))
    existing = {"items" => [{"key" => "one", "field" => "same"}]}

    assert schema.validate(existing)
    error = assert_raises(SCHEMA::Invalid) do
      schema.validate(existing.merge("items" => [{"key" => "two", "field" => "same"}, existing.fetch("items").first]), old: existing)
    end
    assert_equal(["items[1].field"], error.causes.map { |cause| cause["field"] })
    assert schema.validate({"items" => [{"key" => "one", "field" => "different"}]}, old: existing)
  end

  private

  def validator(properties)
    SCHEMA.new({"type" => "object", "properties" => properties}, cel: Rubernetes::Security::CEL::Evaluator.new)
  end

  def record(field)
    {"type" => "object", "properties" => {"key" => {"type" => "string"}, "field" => field}}
  end

  def list_map(field)
    {"type" => "array", "x-kubernetes-list-type" => "map", "x-kubernetes-list-map-keys" => ["key"],
     "items" => record(field).merge("required" => ["key"])}
  end
end
