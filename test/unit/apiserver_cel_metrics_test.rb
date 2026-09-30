# frozen_string_literal: true

# apiserver_cel_compilation_duration_seconds and
# apiserver_cel_evaluation_duration_seconds (apiextensions-apiserver
# schema/cel): one compilation per validator node cel.NewValidator builds, one
# evaluation per visit of a node that has a validator.

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"

class APIServerCELMetricsTest < Minitest::Test
  SCHEMA = {
    "type" => "object",
    "properties" => {
      "spec" => {
        "type" => "object",
        "x-kubernetes-validations" => [{"rule" => "self.size < 10", "messageExpression" => "'too big: ' + string(self.size)"}],
        "properties" => {
          "size" => {"type" => "integer", "x-kubernetes-validations" => [{"rule" => "self >= 0"}]},
          "color" => {"type" => "string"}
        }
      },
      "status" => {"type" => "object", "properties" => {"n" => {"type" => "integer"}}}
    }
  }.freeze

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    @previous = Rubernetes::API::CRD.metrics
    Rubernetes::API::CRD.metrics = @metrics
  end

  def teardown
    Rubernetes::API::CRD.metrics = @previous
  end

  def count(text, name) = text[/^#{name}_count (\d+)$/, 1].to_i

  def test_every_validator_node_is_compiled_and_only_rule_bearing_nodes_are_evaluated
    schema = Rubernetes::API::CRD::StructuralSchema.new(SCHEMA, cel: Rubernetes::Security::CEL::Evaluator.new)
    # root, spec, size, color, status, n.
    assert_equal 6, count(@metrics.render, "apiserver_cel_compilation_duration_seconds")

    schema.validate({"spec" => {"size" => 3, "color" => "red"}, "status" => {"n" => 1}})
    # root, spec and size carry validators; color, status and n do not.
    assert_equal 3, count(@metrics.render, "apiserver_cel_evaluation_duration_seconds")

    error = assert_raises(Rubernetes::API::CRD::StructuralSchema::Invalid) { schema.validate({"spec" => {"size" => 12}}) }
    assert_match(/too big: 12/, error.message)
    assert_equal 6, count(@metrics.render, "apiserver_cel_evaluation_duration_seconds")
  end

  def test_a_schema_without_rules_compiles_nothing
    Rubernetes::API::CRD::StructuralSchema.new(SCHEMA["properties"]["status"], cel: Rubernetes::Security::CEL::Evaluator.new)
    text = @metrics.render

    assert_equal 0, count(text, "apiserver_cel_compilation_duration_seconds")
    assert_match(/^# HELP apiserver_cel_compilation_duration_seconds \[BETA\] CEL compilation time in seconds\.$/, text)
    assert_match(/^# TYPE apiserver_cel_evaluation_duration_seconds histogram$/, text)
    assert_match(/^apiserver_cel_evaluation_duration_seconds_bucket\{le="0\.005"\} 0$/, text)
  end
end
