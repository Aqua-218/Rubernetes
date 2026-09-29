# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/observability/metrics"

# pkg/controller/podgc/gc_controller.go (v1.36.2).
class PodGCControllerUpstreamTest < Minitest::Test
  GC = Rubernetes::Controller::PodGarbageCollectorController

  def pod(name, phase: "Running", node: "n1", created: 0, reason: nil, deleting: false)
    object = {"apiVersion" => "v1", "kind" => "Pod",
              "metadata" => {"name" => name, "namespace" => "ns", "uid" => "u-#{name}",
                             "creationTimestamp" => (Time.utc(2026, 1, 1) + created).iso8601},
              "spec" => {"nodeName" => node}, "status" => {"phase" => phase}}
    object["status"]["reason"] = reason if reason
    object["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z" if deleting
    object
  end

  def node(name, ready: true, taints: [])
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name},
     "spec" => {"taints" => taints}, "status" => {"conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False"}]}}
  end

  def deletes(result) = result.operations.select(&:delete?).map { |operation| operation.object.dig("metadata", "name") }

  def test_terminated_pods_over_the_threshold_go_evicted_first_then_oldest
    pods = [pod("a", phase: "Succeeded", created: 1), pod("b", phase: "Failed", created: 2, reason: "Evicted"),
            pod("c", phase: "Failed", created: 0), pod("d")]
    result = GC.new.plan(pods: pods, nodes: [node("n1")], threshold: 1)
    assert_equal %w[b c], deletes(result)
    assert(result.operations.select(&:delete?).all? { |operation| operation.patch == {"gracePeriodSeconds" => 0} }, "force deleted")
    assert_empty result.operations.reject(&:delete?), "terminal Pods are not re-marked"
  end

  def test_orphans_wait_out_the_quarantine_and_get_a_disruption_condition
    now = Time.utc(2026, 1, 1, 0, 1)
    gc = GC.new(clock: -> { now })
    pods = [pod("orphan", node: "gone")]
    assert_empty gc.plan(pods: pods, nodes: [node("n1")]).operations, "the node may be coming back"
    now += 41
    result = gc.plan(pods: pods, nodes: [node("n1")])
    status = result.operations.find { |operation| operation.action == :status_update }.patch
    assert_equal "Failed", status["phase"]
    assert_equal({"type" => "DisruptionTarget", "status" => "True", "reason" => "DeletionByPodGC", "message" => "PodGC: node no longer exists"},
                 status["conditions"].first.slice("type", "status", "reason", "message"))
    assert_equal ["orphan"], deletes(result)
  end

  def test_terminating_pods_on_out_of_service_nodes_and_unscheduled_ones
    tainted = node("down", ready: false, taints: [{"key" => "node.kubernetes.io/out-of-service", "effect" => "NoExecute"}])
    pods = [pod("stuck", node: "down", deleting: true), pod("fine", node: "n1", deleting: true), pod("never", node: "", deleting: true)]
    result = GC.new.plan(pods: pods, nodes: [tainted, node("n1")])
    assert_equal %w[stuck never], deletes(result)
    assert_equal 2, result.operations.count { |operation| operation.action == :status_update }, "both are marked Failed first"
  end
  # metrics.DeletingPodsTotal / DeletingPodsErrorTotal by namespace and reason.
  def test_force_delete_metrics
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kube-controller-manager")
    Rubernetes::Controller.metrics = registry
    tainted = node("down", ready: false, taints: [{"key" => "node.kubernetes.io/out-of-service", "effect" => "NoExecute"}])
    result = GC.new.plan(pods: [pod("a", phase: "Failed"), pod("b", phase: "Failed", created: 1), pod("stuck", node: "down", deleting: true)],
                         nodes: [node("n1"), tainted], threshold: 1)
    result.operations.each { |operation| operation.notify(operation.object.dig("metadata", "name") != "stuck" || operation.delete?) }
    text = registry.render
    assert_includes text, %(pod_gc_collector_force_delete_pods_total{namespace="ns",reason="terminated"} 1)
    assert_includes text, %(pod_gc_collector_force_delete_pods_total{namespace="ns",reason="out-of-service"} 1)
    assert_includes text, %(pod_gc_collector_force_delete_pod_errors_total{namespace="ns",reason="out-of-service"} 1)
  ensure
    Rubernetes::Controller.metrics = nil
  end
end
