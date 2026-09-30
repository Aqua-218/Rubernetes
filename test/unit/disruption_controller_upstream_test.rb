# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# pkg/controller/disruption/disruption_test.go (v1.36.2), case by case:
# maxUnavailable is read before minAvailable, a nil selector selects
# nothing, a Pod whose controller cannot be found makes the sync fail safe
# (SyncFailed, no disruptions), disrupted Pods expire after two minutes,
# and a stale DisruptionTarget condition is reset.
class DisruptionControllerUpstreamTest < Minitest::Test
  Controller = Rubernetes::Controller
  NOW = Time.utc(2026, 9, 23, 12, 0, 0)

  def setup
    @controller = Controller::DisruptionController.new
    @pods = []
    @replica_sets = []
    @deployments = []
    @replication_controllers = []
    @stateful_sets = []
    @pdb = nil
  end

  def pdb(min_available: nil, max_unavailable: nil, selector: {"matchLabels" => {"foo" => "bar"}})
    spec = {"selector" => selector}
    spec["minAvailable"] = min_available unless min_available.nil?
    spec["maxUnavailable"] = max_unavailable unless max_unavailable.nil?
    spec.delete("selector") if selector == :none
    @pdb = {"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget",
            "metadata" => {"name" => "foobar", "namespace" => "default", "uid" => "pdb-uid", "generation" => 1},
            "spec" => spec, "status" => {}}
  end

  def pod(name, ready: true, labels: {"foo" => "bar"}, owner: nil)
    metadata = {"name" => name, "namespace" => "default", "uid" => "uid-#{name}", "labels" => labels}
    metadata["ownerReferences"] = [owner] if owner
    conditions = ready ? [{"type" => "Ready", "status" => "True"}] : []
    object = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata, "spec" => {}, "status" => {"conditions" => conditions}}
    @pods << object
    object
  end

  def owner(object, kind: object["kind"], api_version: object["apiVersion"])
    {"apiVersion" => api_version, "kind" => kind, "name" => object.dig("metadata", "name"), "uid" => object.dig("metadata", "uid"),
     "controller" => true}
  end

  def workload(kind, name, replicas, api_version: "apps/v1")
    {"apiVersion" => api_version, "kind" => kind, "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
     "spec" => {"replicas" => replicas}}
  end

  def sync
    result = @controller.plan(@pdb, pods: @pods, replica_sets: @replica_sets, deployments: @deployments,
                                    replication_controllers: @replication_controllers, stateful_sets: @stateful_sets, now: NOW)
    @pdb = @pdb.merge("status" => result.status)
    @last = result
    result
  end

  def verify(allowed, healthy, desired, expected, disrupted = {})
    status = @pdb["status"]

    assert_equal [allowed, healthy, desired, expected],
                 status.values_at("disruptionsAllowed", "currentHealthy", "desiredHealthy", "expectedPods")
    assert_equal disrupted, status["disruptedPods"] || {}
  end

  def events = @last.events.map { |event| event["reason"] }

  def test_no_selector
    pdb(min_available: 3, selector: {})
    sync
    verify(0, 0, 3, 0)
    pod("yo-yo-yo")
    sync
    verify(0, 1, 3, 1)
  end

  def test_a_nil_selector_selects_nothing
    pdb(min_available: 1, selector: :none)
    pod("anything")
    sync
    verify(0, 0, 1, 0)

    assert_includes events, "NoPods"
  end

  def test_unavailable
    pdb(min_available: 3)
    sync
    4.times do |i|
      verify(0, i, 3, i)
      pod("yo-yo-yo #{i}")
      sync
    end
    verify(1, 4, 3, 4)
    @pods.first["status"]["conditions"] = []
    sync
    verify(0, 3, 3, 4)
  end

  def test_integer_max_unavailable_with_a_naked_pod
    pdb(max_unavailable: 1)
    sync

    assert_equal 0, @pdb.dig("status", "disruptionsAllowed")
    pod("naked")
    sync

    assert_equal 0, @pdb.dig("status", "disruptionsAllowed")
    assert_includes events, "UnmanagedPods"
  end

  def test_integer_max_unavailable_with_scaling
    pdb(max_unavailable: 2)
    rs = workload("ReplicaSet", "rs", 7)
    @replica_sets << rs
    pod("pod", owner: owner(rs))
    sync
    verify(0, 1, 5, 7)
    rs["spec"]["replicas"] = 5
    sync
    verify(0, 1, 3, 5)
  end

  def test_percentage_max_unavailable_with_scaling
    pdb(max_unavailable: "30%")
    rs = workload("ReplicaSet", "rs", 7)
    @replica_sets << rs
    pod("pod", owner: owner(rs))
    sync
    verify(0, 1, 4, 7)
    rs["spec"]["replicas"] = 3
    sync
    verify(0, 1, 2, 3)
  end

  def test_naked_pod_with_a_percentage
    pdb(min_available: "28%")
    pod("naked")
    sync

    assert_equal 0, @pdb.dig("status", "disruptionsAllowed")
    assert_includes events, "UnmanagedPods"
    message = @last.events.find { |event| event["reason"] == "UnmanagedPods" }["message"]

    assert_includes message,
                    "(selector: &LabelSelector{MatchLabels:map[string]string{foo: bar,},MatchExpressions:[]LabelSelectorRequirement{},})"
    condition = @pdb.dig("status", "conditions").first

    assert_equal %w[DisruptionAllowed False InsufficientPods], condition.values_at("type", "status", "reason"),
                 "unmanaged Pods are not a sync failure"
  end

  def test_an_unknown_controller_fails_safe
    pdb(min_available: "28%")
    pod("naked", owner: {"apiVersion" => "apps.test.io/v1", "kind" => "TestWorkload", "name" => "fake-controller",
                         "uid" => "b7329742-8daa-493a-8881-6ca07139172b", "controller" => true})
    sync

    assert_equal 0, @pdb.dig("status", "disruptionsAllowed")
    assert_includes events, "CalculateExpectedPodCountFailed"
    condition = @pdb.dig("status", "conditions").first

    assert_equal %w[DisruptionAllowed False SyncFailed], condition.values_at("type", "status", "reason")
  end

  def test_replica_set_without_a_deployment
    pdb(min_available: "20%")
    rs = workload("ReplicaSet", "rs", 10)
    @replica_sets << rs
    pod("pod", owner: owner(rs))
    sync
    verify(0, 1, 2, 10)
  end

  def test_a_replica_set_of_a_deployment_counts_the_deployment
    pdb(max_unavailable: 1)
    deployment = workload("Deployment", "web", 4)
    rs = workload("ReplicaSet", "web-abc", 99)
    rs["metadata"]["ownerReferences"] = [owner(deployment)]
    @deployments << deployment
    @replica_sets << rs
    4.times { |i| pod("web-#{i}", owner: owner(rs)) }
    sync
    verify(1, 4, 3, 4)
  end

  def test_replication_controller_and_stateful_set
    pdb(min_available: "50%")
    rc = workload("ReplicationController", "rc", 4, api_version: "v1")
    set = workload("StatefulSet", "ss", 2)
    @replication_controllers << rc
    @stateful_sets << set
    pod("rc-0", owner: owner(rc))
    pod("ss-0", owner: owner(set))
    sync
    verify(0, 2, 3, 6)
  end

  def test_two_controllers_of_one_pod_group_count_once
    pdb(min_available: "28%")
    rc = workload("ReplicationController", "rc", 11, api_version: "v1")
    @replication_controllers << rc
    11.times { |i| pod("quux #{i}", owner: owner(rc), ready: i >= 6) }
    sync
    verify(1, 5, 4, 11)
  end

  def test_update_disrupted_pods
    pdb(min_available: 1)
    stamp = ->(offset) { (NOW + offset).utc.strftime("%Y-%m-%dT%H:%M:%SZ") }
    @pdb["status"]["disruptedPods"] =
      {"p1" => stamp.call(0), "p2" => stamp.call(-180), "p3" => stamp.call(-60), "notthere" => stamp.call(0)}
    deleting = pod("p1")
    deleting["metadata"]["deletionTimestamp"] = stamp.call(0)
    pod("p2")
    pod("p3")
    result = sync
    verify(0, 1, 1, 3, {"p3" => stamp.call(-60)})

    assert_in_delta 60.0, result.requeue_after, 0.001, "rechecked when p3's expected deletion passes"
    assert_includes events, "NotDeleted"
  end

  def test_a_status_that_is_up_to_date_is_not_written_again
    pdb(min_available: 1)
    pod("a")
    sync

    refute_empty @last.operations
    sync

    assert_empty @last.operations
  end

  def test_stale_pod_disruption_is_reset_after_two_minutes
    stamp = ->(offset) { (NOW + offset).utc.strftime("%Y-%m-%dT%H:%M:%SZ") }
    target = pod("victim")
    target["status"]["conditions"] << {"type" => "DisruptionTarget", "status" => "True", "reason" => "EvictionByEvictionAPI",
                                       "lastTransitionTime" => stamp.call(-30)}
    early = @controller.plan(target, now: NOW)

    assert_empty early.operations
    assert_in_delta 90.0, early.requeue_after, 0.001

    target["status"]["conditions"].last["lastTransitionTime"] = stamp.call(-121)
    reset = @controller.plan(target, now: NOW)
    condition = reset.operations.first.patch["conditions"].find { |entry| entry["type"] == "DisruptionTarget" }

    assert_equal "False", condition["status"]
    assert_nil condition["reason"]

    target["status"]["conditions"].last["reason"] = "TerminationByKubelet"

    assert_empty @controller.plan(target, now: NOW).operations, "the kubelet's own condition is left alone"
  end
end
