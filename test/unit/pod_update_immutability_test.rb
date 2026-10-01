# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidatePodUpdate (pkg/apis/core/validation/validation.go:5691): a Pod's spec
# is immutable on update apart from image, activeDeadlineSeconds, tolerations
# (additions) and terminationGracePeriodSeconds.  Nothing enforced it, so a
# client could rewrite a running Pod's volumes, nodeName or security context
# and the API accepted it while the kubelet kept running the old one.
class PodUpdateImmutabilityTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def pod(spec_extra = {}, container_extra = {})
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns"},
     "spec" => {"nodeName" => "node-a",
                "containers" => [{"name" => "c", "image" => "img:1"}.merge(container_extra)]}.merge(spec_extra)}
  end

  def errors(new_pod, old_pod)
    Validator.send(:pod_update_errors, new_pod, "Pod", :update, old_pod)
  end

  def test_an_unchanged_spec_is_accepted
    assert_empty errors(pod, pod)
  end

  def test_the_image_may_change
    assert_empty errors(pod({}, {"image" => "img:2"}), pod)
  end

  def test_active_deadline_seconds_may_change
    assert_empty errors(pod("activeDeadlineSeconds" => 30), pod)
  end

  def test_tolerations_may_change
    assert_empty errors(pod("tolerations" => [{"key" => "k", "operator" => "Exists"}]), pod)
  end

  # Only a negative grace period may become 1; any other change is refused.
  def test_termination_grace_period_only_from_negative_to_one
    assert_empty errors(pod("terminationGracePeriodSeconds" => 1), pod("terminationGracePeriodSeconds" => -1))
    refute_empty errors(pod("terminationGracePeriodSeconds" => 1), pod("terminationGracePeriodSeconds" => 30))
  end

  def test_the_node_name_may_not_change
    refute_empty errors(pod("nodeName" => "node-b"), pod)
  end

  def test_volumes_may_not_change
    refute_empty errors(pod("volumes" => [{"name" => "v", "emptyDir" => {}}]), pod)
  end

  def test_the_command_may_not_change
    refute_empty errors(pod({}, {"command" => ["sh"]}), pod)
  end

  def test_the_security_context_may_not_change
    refute_empty errors(pod("securityContext" => {"runAsUser" => 1000}), pod)
  end

  # Resources change only through pods/resize (ValidatePodResize); the main
  # resource refuses them like any other spec field.
  def test_resources_may_not_change_on_the_main_resource
    refute_empty errors(pod({}, {"resources" => {"limits" => {"cpu" => "1"}}}), pod)
  end

  def test_scheduling_gates_are_validated_elsewhere
    assert_empty errors(pod, pod("schedulingGates" => [{"name" => "g"}]))
  end

  # Upstream refuses them through the main resource (the diff shows them);
  # the ephemeralcontainers subresource is the way to add them.
  def test_ephemeral_containers_change_only_through_their_subresource
    refute_empty errors(pod("ephemeralContainers" => [{"name" => "d", "image" => "busybox"}]), pod)
    new_pod = pod("ephemeralContainers" => [{"name" => "d", "image" => "busybox"}])
    issues = Validator.send(:cross_field_errors, new_pod, "Pod", :update, pod, subresource: "ephemeralcontainers")

    assert_empty(issues.select { |issue| issue.path == ["spec"] && issue.code == :forbidden })
  end

  def test_a_create_is_never_restricted
    assert_empty Validator.send(:pod_update_errors, pod("nodeName" => "other"), "Pod", :create, pod)
  end
end
