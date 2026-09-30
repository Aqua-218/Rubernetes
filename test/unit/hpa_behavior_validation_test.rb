# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# validateBehavior (pkg/apis/autoscaling/validation, v1.36.2) for both
# directions, including HPAConfigurableTolerance's per-direction tolerance.
class HPABehaviorValidationTest < Minitest::Test
  V = Rubernetes::Schema::KubernetesValidator

  def errors(behavior)
    hpa = {"spec" => {"minReplicas" => 1, "maxReplicas" => 3, "behavior" => behavior,
                      "scaleTargetRef" => {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "d"}}}
    V.hpa_errors(hpa).map { |issue| "#{issue.path.join(".")}: #{issue.message}" }
  end

  def rules(**overrides)
    {"stabilizationWindowSeconds" => 60, "selectPolicy" => "Max", "tolerance" => "0.05",
     "policies" => [{"type" => "Pods", "value" => 4, "periodSeconds" => 15}]}.merge(overrides.transform_keys(&:to_s))
  end

  def test_valid_rules_in_both_directions
    assert_empty errors({"scaleUp" => rules, "scaleDown" => rules(tolerance: "0")})
  end

  def test_every_rule_is_checked_in_both_directions
    bad = rules(stabilizationWindowSeconds: 4000, selectPolicy: "Most", tolerance: "-0.1",
                policies: [{"type" => "Nodes", "value" => 0, "periodSeconds" => 2000}])
    found = errors({"scaleUp" => bad, "scaleDown" => rules(policies: [])})

    assert_includes found, "spec.behavior.scaleUp.stabilizationWindowSeconds: must be less than or equal to 3600"
    assert_includes found, "spec.behavior.scaleUp.selectPolicy: supported values: \"Disabled\", \"Max\", \"Min\""
    assert_includes found, "spec.behavior.scaleUp.tolerance: must be greater than or equal to 0"
    assert_includes found, "spec.behavior.scaleUp.policies.0.type: supported values: \"Percent\", \"Pods\""
    assert_includes found, "spec.behavior.scaleUp.policies.0.value: must be greater than zero"
    assert_includes found, "spec.behavior.scaleUp.policies.0.periodSeconds: must be less than or equal to 1800"
    assert_includes found, "spec.behavior.scaleDown.policies: must specify at least one Policy"
    assert_includes errors({"scaleDown" => rules(stabilizationWindowSeconds: -1)}),
                    "spec.behavior.scaleDown.stabilizationWindowSeconds: must be greater than or equal to zero"
  end
end
