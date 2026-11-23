# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

class ServiceLoadBalancerFieldsTest < Minitest::Test
  CLASS = "spec.loadBalancerClass"
  ALLOCATE = "spec.allocateLoadBalancerNodePorts"

  def service(type, **fields)
    spec = if type == "ExternalName"
             {"type" => type, "externalName" => "example.org"}
           else
             {"type" => type, "ports" => [{"port" => 80}]}
           end
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "service", "namespace" => "default"},
     "spec" => spec.merge(fields.transform_keys(&:to_s))}
  end

  def property_issues(object, old: nil, subresource: nil)
    validator = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Service").validator
    validator.errors(object, operation: old ? :update : :create, old: old, subresource: subresource).select do |issue|
      [CLASS, ALLOCATE].include?(issue.kubernetes_field)
    end
  end

  def test_load_balancer_class_is_a_qualified_name
    ["edge", "example.org/Edge_v1.2", "x" * 63].each do |name|
      assert_empty property_issues(service("LoadBalancer", loadBalancerClass: name)), name
    end
    ["", "example.org/", "Example.org/edge", "a/b/c", "edge*", "x" * 64].each do |name|
      issues = property_issues(service("LoadBalancer", loadBalancerClass: name))

      refute_empty issues, name
      assert(issues.all? { |issue| issue.kubernetes_field == CLASS && issue.kubernetes_error_type == "Invalid value" }, name)
    end
    overlong = property_issues(service("LoadBalancer", loadBalancerClass: "é" * 32))

    assert_equal "name part must be no more than 63 bytes", overlong.first.message
  end

  def test_both_fields_are_only_available_to_load_balancers
    [true, false].each do |allocate|
      assert_empty property_issues(service("LoadBalancer", allocateLoadBalancerNodePorts: allocate))
      %w[ClusterIP NodePort ExternalName].each do |type|
        issues = property_issues(service(type, loadBalancerClass: "edge", allocateLoadBalancerNodePorts: allocate))
        signatures = issues.map { |issue| [issue.kubernetes_field, issue.kubernetes_error_type] }

        assert_equal [[ALLOCATE, "Forbidden"], [CLASS, "Forbidden"]], signatures
      end
    end
  end

  def test_class_is_immutable_while_type_remains_load_balancer
    plain = service("LoadBalancer")
    custom = service("LoadBalancer", loadBalancerClass: "example.org/edge")
    renamed = service("LoadBalancer", loadBalancerClass: "example.org/other")
    allocate = service("LoadBalancer", loadBalancerClass: "example.org/edge", allocateLoadBalancerNodePorts: false)

    assert_empty property_issues(custom, old: custom)
    assert_empty property_issues(allocate, old: custom)
    [[plain, custom], [custom, plain], [renamed, custom]].each do |desired, old|
      messages = property_issues(desired, old: old).map { |issue| [issue.kubernetes_field, issue.message] }

      assert_equal [[CLASS, "may not change once set"]], messages
    end
    assert_empty property_issues(custom, old: service("NodePort"))
  end

  def test_type_change_can_carry_old_fields_for_the_registry_to_drop
    old = service("LoadBalancer", loadBalancerClass: "edge", allocateLoadBalancerNodePorts: false)
    carried = service("NodePort", loadBalancerClass: "edge", allocateLoadBalancerNodePorts: false)
    changed = service("NodePort", loadBalancerClass: "other", allocateLoadBalancerNodePorts: true)

    assert_empty property_issues(carried, old: old)
    assert_empty property_issues(service("NodePort"), old: old)
    assert_equal [CLASS, ALLOCATE, CLASS], property_issues(changed, old: old).map(&:kubernetes_field)
  end

  def test_status_updates_leave_existing_service_fields_alone
    old = service("LoadBalancer", loadBalancerClass: "legacy*")

    assert_empty property_issues(old.merge("status" => {"loadBalancer" => {}}), old: old, subresource: "status")
  end
end
