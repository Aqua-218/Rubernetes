# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# ResourceQuota spec.scopes / spec.scopeSelector select which objects a quota
# counts.  Both were accepted and validated by the API server and read by
# nobody, so every quota counted every Pod: a quota scoped to Terminating
# reported the usage of a Pod that has no activeDeadlineSeconds.  Conformance:
# "[sig-api-machinery] ResourceQuota should verify ResourceQuota with
# terminating scopes / with best effort scope" (resource_quota.go).
class ResourceQuotaScopesTest < Minitest::Test
  Controller = Rubernetes::Controller::ResourceQuotaController

  def controller
    Controller.allocate
  end

  def quota(scopes: nil, selector: nil)
    spec = {"hard" => {"pods" => "5"}}
    spec["scopes"] = scopes if scopes
    spec["scopeSelector"] = selector if selector
    {"apiVersion" => "v1", "kind" => "ResourceQuota",
     "metadata" => {"name" => "q", "namespace" => "ns"}, "spec" => spec}
  end

  def pod(name:, deadline: nil, resources: nil, priority_class: nil, affinity: nil)
    container = {"name" => "c", "image" => "img"}
    container["resources"] = resources if resources
    spec = {"containers" => [container]}
    spec["activeDeadlineSeconds"] = deadline unless deadline.nil?
    spec["priorityClassName"] = priority_class if priority_class
    spec["affinity"] = affinity if affinity
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns"}, "spec" => spec}
  end

  def selected(quota_object, pods)
    controller.send(:objects_in_scope, quota_object, pods).map { |p| p.dig("metadata", "name") }
  end

  def test_terminating_selects_only_pods_with_a_deadline
    pods = [pod(name: "with", deadline: 30), pod(name: "without")]

    assert_equal ["with"], selected(quota(scopes: ["Terminating"]), pods)
  end

  def test_not_terminating_selects_only_pods_without_a_deadline
    pods = [pod(name: "with", deadline: 30), pod(name: "without")]

    assert_equal ["without"], selected(quota(scopes: ["NotTerminating"]), pods)
  end

  def test_best_effort_selects_pods_with_no_requests_or_limits
    pods = [pod(name: "besteffort"),
            pod(name: "burstable", resources: {"requests" => {"cpu" => "100m"}})]

    assert_equal ["besteffort"], selected(quota(scopes: ["BestEffort"]), pods)
    assert_equal ["burstable"], selected(quota(scopes: ["NotBestEffort"]), pods)
  end

  def test_scopes_combine_with_and
    pods = [pod(name: "both", deadline: 30),
            pod(name: "deadline-only", deadline: 30, resources: {"limits" => {"cpu" => "1"}}),
            pod(name: "neither")]

    assert_equal ["both"], selected(quota(scopes: %w[Terminating BestEffort]), pods)
  end

  def test_a_quota_without_scopes_counts_everything
    pods = [pod(name: "a", deadline: 5), pod(name: "b")]

    assert_equal %w[a b], selected(quota, pods)
  end

  def test_priority_class_scope_selector_in
    pods = [pod(name: "high", priority_class: "high"), pod(name: "low", priority_class: "low"),
            pod(name: "none")]
    selector = {"matchExpressions" => [{"scopeName" => "PriorityClass", "operator" => "In",
                                        "values" => ["high"]}]}

    assert_equal ["high"], selected(quota(selector: selector), pods)
  end

  def test_priority_class_scope_selector_does_not_exist
    pods = [pod(name: "high", priority_class: "high"), pod(name: "none")]
    selector = {"matchExpressions" => [{"scopeName" => "PriorityClass", "operator" => "DoesNotExist"}]}

    assert_equal ["none"], selected(quota(selector: selector), pods)
  end

  def test_non_pod_objects_are_never_filtered_by_scopes
    service = {"apiVersion" => "v1", "kind" => "Service",
               "metadata" => {"name" => "svc", "namespace" => "ns"}, "spec" => {}}
    pods = [pod(name: "without"), service]

    assert_equal ["svc"], selected(quota(scopes: ["Terminating"]), pods)
  end

  def test_cross_namespace_pod_affinity_scope
    affinity = {"podAffinity" => {"requiredDuringSchedulingIgnoredDuringExecution" =>
                                    [{"namespaces" => ["other"], "topologyKey" => "k"}]}}
    pods = [pod(name: "cross", affinity: affinity), pod(name: "local")]

    assert_equal ["cross"], selected(quota(scopes: ["CrossNamespacePodAffinity"]), pods)
  end
end
