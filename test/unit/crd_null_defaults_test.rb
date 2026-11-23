# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api/crd/manager"

class CRDNullDefaultsTest < Minitest::Test
  def contract(properties, required: [])
    schema = {"type" => "object", "properties" => properties, "required" => required}
    structural = Rubernetes::API::CRD::StructuralSchema.new(schema)
    Rubernetes::API::CRD::Manager::Contract.new(schema: structural, scale: nil, status: true)
  end

  def test_absence_and_explicit_null_are_distinct_for_nullable_defaults
    string = {"type" => "string", "nullable" => true, "default" => "ready"}
    api = contract({"explicit" => string, "absent" => string,
                    "enabled" => {"type" => "boolean", "default" => false},
                    "replicas" => {"type" => "integer", "default" => 0}}, required: ["explicit"])
    input = {"explicit" => nil, "enabled" => nil}

    result = api.default(input)

    assert_equal({"explicit" => nil, "absent" => "ready", "enabled" => false, "replicas" => 0}, result)
    assert_empty(api.validate(result))
    assert_equal({"explicit" => nil, "enabled" => nil}, input)
  end

  def test_nonnullable_nulls_are_pruned_in_declared_properties_maps_and_list_objects
    fields = {"type" => "object", "properties" => {"finishedAt" => {"type" => "string", "format" => "date-time"}},
              "x-kubernetes-preserve-unknown-fields" => true}
    api = contract({"history" => {"type" => "array", "items" => fields},
                    "nodes" => {"type" => "object", "additionalProperties" => fields},
                    "phase" => {"type" => "string"}}, required: ["phase"])
    input = {"history" => [{"finishedAt" => nil, "unknown" => nil}],
             "nodes" => {"one" => {"finishedAt" => nil}, "two" => nil}, "phase" => nil}
    result = api.default(input)

    assert_equal({"history" => [{"unknown" => nil}], "nodes" => {"one" => {}}}, result)
    assert_equal([%w[phase FieldValueRequired]], api.validate(result).map { |e| e.values_at("field", "reason") })
    assert_empty(api.unknown_fields(input))
  end

  def test_list_positions_survive_pruning_and_each_default_is_an_independent_copy
    object = {"type" => "object", "default" => {}, "properties" => {"phase" => {"type" => "string", "default" => "new"}}}
    api = contract({"unset" => {"type" => "array", "items" => {"type" => "string"}},
                    "defaulted" => {"type" => "array", "items" => object},
                    "map" => {"type" => "object", "additionalProperties" => object}})
    result = api.default({"unset" => [nil, "ok"], "defaulted" => [nil, nil], "map" => {"item" => nil}})

    assert_equal([nil, "ok"], result["unset"])
    assert_equal([{"phase" => "new"}, {"phase" => "new"}], result["defaulted"])
    assert_equal({"item" => {"phase" => "new"}}, result["map"])
    assert_equal(["unset[0]"], api.validate(result).map { |e| e["field"] })
    result["defaulted"][0]["phase"] = "changed"

    assert_equal("new", result["defaulted"][1]["phase"])
    assert_empty(object["default"])
  end
end
