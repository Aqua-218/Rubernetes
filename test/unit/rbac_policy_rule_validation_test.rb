# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidatePolicyRule (pkg/apis/rbac/validation/validation.go:106): every rule
# needs at least one verb, a namespaced Role cannot carry nonResourceURLs, and
# no rule may mix resources with non-resource URLs.  None of it was checked, so
# a Role could be stored with rules that grant nothing and silently deny.
class RBACPolicyRuleValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def role(rules, kind: "Role")
    {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => kind,
     "metadata" => {"name" => "r", "namespace" => "ns"}, "rules" => rules}
  end

  def errors(rules, kind: "Role")
    Validator.send(:rbac_errors, role(rules, kind: kind), kind)
  end

  def test_a_complete_rule_is_accepted
    assert_empty errors([{"apiGroups" => [""], "resources" => ["pods"], "verbs" => ["get"]}])
  end

  def test_a_rule_without_verbs_is_rejected
    refute_empty errors([{"apiGroups" => [""], "resources" => ["pods"], "verbs" => []}])
    refute_empty errors([{"apiGroups" => [""], "resources" => ["pods"]}])
  end

  def test_a_namespaced_role_may_not_use_non_resource_urls
    refute_empty errors([{"nonResourceURLs" => ["/healthz"], "verbs" => ["get"]}])
  end

  def test_a_cluster_role_may_use_non_resource_urls
    assert_empty errors([{"nonResourceURLs" => ["/healthz"], "verbs" => ["get"]}], kind: "ClusterRole")
  end

  def test_a_rule_may_not_mix_resources_and_non_resource_urls
    refute_empty errors([{"nonResourceURLs" => ["/healthz"], "resources" => ["pods"],
                          "apiGroups" => [""], "verbs" => ["get"]}], kind: "ClusterRole")
  end

  def test_a_resource_rule_still_needs_groups_and_resources
    refute_empty errors([{"verbs" => ["get"]}], kind: "ClusterRole")
  end
end
