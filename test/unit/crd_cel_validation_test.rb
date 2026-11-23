# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/crd_aggregation_harness"
require "rubernetes/api"

class CRDCELValidationTest < Minitest::Test
  include CRDAggregationHarness

  API = Rubernetes::API
  CEL = Rubernetes::Security::CEL
  CRD_PATH = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"

  def definition(schema)
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "widgets.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced", "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget"},
                "versions" => [{"name" => "v1", "storage" => true, "served" => true,
                                "schema" => {"openAPIV3Schema" => {"type" => "object", "properties" => {"spec" => schema}}}}]}}
  end

  def post(schema)
    call("POST", CRD_PATH, body: definition(schema))
  end

  def test_invalid_rule_types_and_syntax_are_rejected_before_storage
    {"self.z == 100" => "undefined field 'z'", "self = 42" => "Syntax error", "self.x" => "must evaluate to a bool"}.each do |rule, message|
      schema = {"type" => "object", "properties" => {"x" => {"type" => "integer"}}, "x-kubernetes-validations" => [{"rule" => rule}]}
      answer = post(schema)

      assert_equal 422, answer.status, answer.body.inspect
      cause = answer.body.fetch("details").fetch("causes").first

      assert_includes cause.fetch("message"), message
      assert_equal "spec.versions[0].schema.openAPIV3Schema.properties[spec].x-kubernetes-validations[0].rule", cause.fetch("field")
    end
  end

  def test_static_estimation_accounts_for_cardinality_of_nested_rule_locations
    items = {"type" => "array", "maxItems" => 100, "items" => {"type" => "string"},
             "x-kubernetes-validations" => [{"rule" => "self.all(value, value == 'x')"}]}
    answer = post({"type" => "array", "items" => items})

    assert_equal 422, answer.status
    assert_includes answer.body.dig("details", "causes", 0, "message"), "estimated rule cost exceeds budget"
    assert_equal 201, post({"type" => "array", "maxItems" => 2, "items" => items}).status
  end

  def test_static_estimation_uses_declared_map_keys_and_conditional_collection_bounds
    labels = {"type" => "object", "additionalProperties" => {"type" => "string", "maxLength" => 63},
              "x-kubernetes-validations" => [{"rule" => "self.all(key, !key.contains('*'))"}]}
    addresses = {"type" => "array", "maxItems" => 4096, "items" => {"type" => "string", "maxLength" => 2048}}
    expression = "(has(self.addresses) ? self.addresses : []).all(address, !address.contains('/'))"
    schema = {"type" => "object", "properties" => {"labels" => labels, "addresses" => addresses},
              "x-kubernetes-validations" => [{"rule" => expression}]}
    response = post(schema)

    assert_equal 201, response.status, response.body.inspect
  end

  def test_rejects_optional_old_self_without_a_transition_and_transitions_below_atomic_items
    unused = {"type" => "integer", "x-kubernetes-validations" => [{"rule" => "self > 1", "optionalOldSelf" => false}]}
    answer = post(unused)

    assert_equal 422, answer.status
    assert_match(/optionalOldSelf/, answer.body.dig("details", "causes", 0, "field"))

    transition = {"type" => "integer", "x-kubernetes-validations" => [{"rule" => "self > oldSelf"}]}
    answer = post({"type" => "array", "maxItems" => 4, "items" => transition})

    assert_equal 422, answer.status
    assert_match(/uncorrelatable portion/, answer.body.dig("details", "causes", 0, "message"))
  end

  def test_rule_field_path_and_invalid_message_expression_result
    rule = {"rule" => "self.name == 'good'", "message" => "fallback", "messageExpression" => "'  '",
            "reason" => "FieldValueForbidden", "fieldPath" => "['name']"}
    schema = {"type" => "object", "properties" => {"name" => {"type" => "string"}}, "x-kubernetes-validations" => [rule]}

    assert_equal 201, post(schema).status

    validator = API::CRD::StructuralSchema.new(schema, cel: CEL::Evaluator.new)
    error = assert_raises(API::CRD::StructuralSchema::Invalid) { validator.validate({"name" => "bad"}) }
    assert_equal({"field" => "name", "reason" => "FieldValueForbidden", "message" => "Forbidden: fallback"}, error.causes.first)

    rule["fieldPath"] = ".missing"
    answer = post(schema)

    assert_equal 422, answer.status
    assert_match(/fieldPath/, answer.body.dig("details", "causes", 0, "field"))
  end

  def test_cel_escaped_object_fields_do_not_rename_storage_or_map_keys
    string = {"type" => "string", "maxLength" => 63}
    entries = {"type" => "array", "maxItems" => 2, "items" => {"type" => "object", "properties" => {"a/b" => string}}}
    reference = {"type" => "object", "properties" => {"namespace" => string, "__namespace__" => string, "a.b" => string, "entries" => entries}}
    labels = {"type" => "object", "maxProperties" => 3, "additionalProperties" => string}
    rule = "has(self.ref.__namespace__) && self.ref.__namespace__ == self.ref.namespace && " \
           "self.ref.__underscores__namespace__underscores__ == 'literal' && self.ref.a__dot__b == 'dotted' && " \
           "self.ref.entries.all(entry, entry.a__slash__b == 'slashed') && " \
           "self.labels['namespace'] == 'raw' && self.labels['__namespace__'] == 'escaped-looking'"
    transition = "!oldSelf.hasValue() || self.ref.__namespace__ == oldSelf.value().ref.__namespace__"
    schema = {"type" => "object", "properties" => {"ref" => reference, "labels" => labels},
              "x-kubernetes-validations" => [{"rule" => rule}, {"rule" => transition, "optionalOldSelf" => true}]}
    created_crd = post(schema)

    assert_equal 201, created_crd.status, created_crd.body.inspect
    assert_equal 201, call("POST", "/api/v1/namespaces", body: {"metadata" => {"name" => "apps"}}).status

    path = "/apis/example.com/v1/namespaces/apps/widgets"
    spec = {"ref" => {"namespace" => "apps", "__namespace__" => "literal", "a.b" => "dotted", "entries" => [{"a/b" => "slashed"}]},
            "labels" => {"namespace" => "raw", "__namespace__" => "escaped-looking"}}
    object = {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "probe"}, "spec" => spec}
    missing = object.merge("spec" => spec.merge("ref" => spec.fetch("ref").except("namespace")))

    assert_equal 422, call("POST", path, body: missing).status
    answer = call("POST", path, body: object)

    assert_equal 201, answer.status, answer.body.inspect
    assert_equal spec, answer.body.fetch("spec")

    changed = answer.body.merge("spec" => spec.merge("ref" => spec.fetch("ref").merge("namespace" => "other")))

    assert_equal 422, call("PUT", "#{path}/probe", body: changed).status
  end

  def test_runtime_call_cost_stops_later_rules
    schema = {"type" => "object", "properties" => {"x" => {"type" => "integer"}},
              "x-kubernetes-validations" => [{"rule" => "self.x + 1 == 2"}, {"rule" => "false", "message" => "later rule"}]}
    validator = API::CRD::StructuralSchema.new(schema, cel: CEL::Evaluator.new(cost_limit: 5))
    error = assert_raises(API::CRD::StructuralSchema::Invalid) { validator.validate({"x" => 1}) }
    assert_equal 1, error.causes.length
    assert_includes error.causes.first.fetch("message"), "call cost exceeds limit for rule"
  end

  def test_aggregate_cost_is_charged_across_evaluations
    evaluator = CEL::Evaluator.new
    budget = CEL::Evaluator::Budget.new(3)

    assert evaluator.evaluate("true && true", {}, budget)
    error = assert_raises(CEL::Evaluator::CostLimitExceeded) { evaluator.evaluate("true && true", {}, budget) }
    assert_predicate error, :aggregate?
  end
end
