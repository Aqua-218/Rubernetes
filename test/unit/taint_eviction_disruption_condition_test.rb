# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# Upstream's taint managers (addConditionAndDeletePod, device deletePod) patch
# a DisruptionTarget condition onto the Pod before deleting it, and record a
# Normal event on the Pod.  Ours deleted it bare and put a Warning with an
# invented message on the Node.
class TaintEvictionDisruptionConditionTest < Minitest::Test
  Controller = Rubernetes::Controller
  NOW = Time.utc(2026, 9, 23, 12, 0, 0)

  def node(key)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "worker-2"},
     "spec" => {"taints" => [{"key" => key, "effect" => "NoExecute", "timeAdded" => "2026-09-23T11:00:00Z"}]},
     "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def pod(conditions: [])
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u-1", "generation" => 3},
     "spec" => {"nodeName" => "worker-2", "containers" => [{"name" => "c", "image" => "i"}]},
     "status" => {"phase" => "Running", "conditions" => conditions}}
  end

  def test_node_taint_adds_condition_then_deletes
    result = Controller::TaintEvictionController.new.plan(node("example.com/evict"), pods: [pod], now: NOW)
    status, delete = result.operations

    assert_equal %i[status_update delete], result.operations.map(&:action)
    condition = status.patch["conditions"].find { |entry| entry["type"] == "DisruptionTarget" }

    assert_equal({"type" => "DisruptionTarget", "status" => "True", "reason" => "DeletionByTaintManager",
                  "message" => "Taint manager: deleting due to NoExecute taint", "observedGeneration" => 3,
                  "lastProbeTime" => nil, "lastTransitionTime" => "2026-09-23T12:00:00Z"}, condition)
    assert_nil delete.patch
    event = result.events.first

    assert_equal "Normal", event["type"]
    assert_equal "TaintManagerEviction", event["reason"]
    assert_equal "Marking for deletion Pod ns/p", event["message"]
    assert_equal({"apiVersion" => "v1", "kind" => "Pod", "namespace" => "ns", "name" => "p", "uid" => "u-1"},
                 event["involvedObject"])
  end

  def test_existing_condition_is_not_patched_again
    existing = {"type" => "DisruptionTarget", "status" => "True", "reason" => "DeletionByTaintManager",
                "message" => "Taint manager: deleting due to NoExecute taint", "observedGeneration" => 3,
                "lastTransitionTime" => "2026-09-23T11:59:00Z"}
    result = Controller::TaintEvictionController.new.plan(node("example.com/evict"), pods: [pod(conditions: [existing])],
                                                                                     now: NOW)

    assert_equal %i[delete], result.operations.map(&:action)
  end

  def test_changed_reason_keeps_transition_time_when_status_unchanged
    existing = {"type" => "DisruptionTarget", "status" => "True", "reason" => "EvictionByEvictionAPI",
                "lastTransitionTime" => "2026-09-23T11:59:00Z"}
    result = Controller::TaintEvictionController.new.plan(node("example.com/evict"), pods: [pod(conditions: [existing])],
                                                                                     now: NOW)
    condition = result.operations.first.patch["conditions"].first

    assert_equal "DeletionByTaintManager", condition["reason"]
    assert_equal "2026-09-23T11:59:00Z", condition["lastTransitionTime"]
  end

  def test_device_taint_uses_device_reason_and_uid_precondition
    taint = {"key" => "resource.kubernetes.io/broken", "effect" => "NoExecute", "timeAdded" => "2026-09-23T11:00:00Z"}
    result = Controller::DeviceTaintEvictionController.new.plan(node("unrelated"), pods: [pod], device_taints: [taint],
                                                                                   now: NOW)
    status, delete = result.operations

    assert_equal "DeletionByDeviceTaintManager", status.patch["conditions"].first["reason"]
    assert_equal "Device Taint manager: deleting due to NoExecute taint", status.patch["conditions"].first["message"]
    assert_equal({"preconditions" => {"uid" => "u-1"}}, delete.patch)
    assert_equal ["Normal", "DeviceTaintManagerEviction", "Marking for deletion"],
                 result.events.first.values_at("type", "reason", "message")
  end
end
