# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

# pkg/apis/autoscaling/{v1,v2}/defaults.go: minReplicas 1, the default CPU
# metric (v2) and the scaling rules a behavior leaves out.
class HPAAPIDefaultingTest < Minitest::Test
  def defaulted(name, object)
    Rubernetes::Generated.definition_for(name).defaulting.apply_hash(object, kubernetes_admission_defaults: true)
  end

  def hpa(spec) = {"metadata" => {"name" => "h", "namespace" => "ns"}, "spec" => {"scaleTargetRef" => {"kind" => "Deployment", "name" => "d"},
                                                                                "maxReplicas" => 5}.merge(spec)}

  def test_v2_defaults
    spec = defaulted("io.k8s.api.autoscaling.v2.HorizontalPodAutoscaler", hpa({}))["spec"]
    assert_equal 1, spec["minReplicas"]
    assert_equal [{"type" => "Resource", "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => 80}}}],
                 spec["metrics"]
    refute spec.key?("behavior"), "no behavior, no rules"

    behavior = defaulted("io.k8s.api.autoscaling.v2.HorizontalPodAutoscaler",
                         hpa("behavior" => {"scaleDown" => {"stabilizationWindowSeconds" => 60}}))["spec"]["behavior"]
    assert_equal 0, behavior.dig("scaleUp", "stabilizationWindowSeconds")
    assert_equal [{"type" => "Pods", "value" => 4, "periodSeconds" => 15}, {"type" => "Percent", "value" => 100, "periodSeconds" => 15}],
                 behavior.dig("scaleUp", "policies")
    assert_equal({"selectPolicy" => "Max", "policies" => [{"type" => "Percent", "value" => 100, "periodSeconds" => 15}],
                  "stabilizationWindowSeconds" => 60}, behavior["scaleDown"])
  end

  def test_v1_defaults_only_min_replicas
    spec = defaulted("io.k8s.api.autoscaling.v1.HorizontalPodAutoscaler", hpa({}))["spec"]
    assert_equal 1, spec["minReplicas"]
    refute spec.key?("metrics")
  end
end
