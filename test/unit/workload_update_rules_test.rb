# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateDaemonSetSpecUpdate / ValidateDeploymentUpdate /
# ValidateReplicaSetUpdate make the selector immutable
# (pkg/apis/apps/validation/validation.go:403,712,767), a ControllerRevision's
# data is immutable (line 366), and a StatefulSet accepts changes only to a
# named set of spec fields (line 268).  None of it was enforced.
class WorkloadUpdateRulesTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def workload(kind, spec)
    {"apiVersion" => "apps/v1", "kind" => kind, "metadata" => {"name" => "w", "namespace" => "ns"},
     "spec" => spec}
  end

  def selector_spec(selector = {"matchLabels" => {"app" => "demo"}})
    {"replicas" => 1, "selector" => selector,
     "template" => {"metadata" => {"labels" => {"app" => "demo"}},
                    "spec" => {"containers" => [{"name" => "c", "image" => "img"}]}}}
  end

  def immutable_errors(new_object, old_object, kind)
    Validator.send(:immutable_field_errors, new_object, old_object, kind, :update)
  end

  %w[Deployment ReplicaSet DaemonSet].each do |kind|
    define_method(:"test_#{kind.downcase}_selector_is_immutable") do
      old = workload(kind, selector_spec)
      changed = workload(kind, selector_spec("matchLabels" => {"app" => "other"}))

      refute_empty immutable_errors(changed, old, kind)
      assert_empty immutable_errors(workload(kind, selector_spec.merge("replicas" => 3)), old, kind)
    end
  end

  def test_controller_revision_data_is_immutable
    old = {"apiVersion" => "apps/v1", "kind" => "ControllerRevision", "data" => {"a" => 1}, "revision" => 1}
    changed = {"apiVersion" => "apps/v1", "kind" => "ControllerRevision", "data" => {"a" => 2}, "revision" => 1}

    refute_empty immutable_errors(changed, old, "ControllerRevision")
  end

  def stateful_errors(new_object, old_object, operation: :update)
    Validator.send(:stateful_set_update_errors, new_object, old_object, operation)
  end

  def stateful(spec_extra = {})
    workload("StatefulSet", selector_spec.merge("serviceName" => "svc",
                                                "podManagementPolicy" => "OrderedReady").merge(spec_extra))
  end

  def test_statefulset_replicas_may_change
    assert_empty stateful_errors(stateful("replicas" => 5), stateful)
  end

  def test_statefulset_template_may_change
    changed = stateful
    changed["spec"]["template"]["spec"]["containers"][0]["image"] = "img:2"

    assert_empty stateful_errors(changed, stateful)
  end

  def test_statefulset_service_name_may_not_change
    refute_empty stateful_errors(stateful("serviceName" => "other"), stateful)
  end

  def test_statefulset_pod_management_policy_may_not_change
    refute_empty stateful_errors(stateful("podManagementPolicy" => "Parallel"), stateful)
  end

  def test_a_create_is_never_restricted
    assert_empty stateful_errors(stateful("serviceName" => "other"), stateful, operation: :create)
  end
end
