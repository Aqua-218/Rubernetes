# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"
require "rubernetes/observability/metrics"

# SchedulerQueueingHints: plugins' hints decide which cluster events move an
# unschedulable Pod, and events that arrive while a Pod is in flight are
# replayed when it comes back unschedulable.
class SchedulerQueueingHintsTest < Minitest::Test
  S = Rubernetes::Scheduler
  H = S::QueueingHints

  def pod(name, uid: name, node: "", **spec)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns", "uid" => uid, "labels" => spec.delete(:labels) || {}},
     "spec" => {"nodeName" => node,
                "containers" => [{"name" => "c", "resources" => {"requests" => spec.delete(:requests) || {"cpu" => "1"}}}]}.merge(spec.transform_keys(&:to_s)),
     "status" => {}}
  end

  def node(name, labels: {}, taints: [], allocatable: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"}, unschedulable: false)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => labels},
     "spec" => {"taints" => taints, "unschedulable" => unschedulable}, "status" => {"allocatable" => allocatable, "capacity" => allocatable}}
  end

  def strategy(pod, plugins, event, old, new) = H.strategy(S::Pod.new(pod), plugins, event, old, new)

  def test_node_hints_follow_the_upstream_rules
    pending = pod("p", nodeSelector: {"zone" => "a"}, tolerations: [])

    assert_equal :after_backoff, strategy(pending, ["NodeAffinity"], "NodeAdd", nil, S::Node.new(node("n", labels: {"zone" => "a"})))
    assert_equal :skip, strategy(pending, ["NodeAffinity"], "NodeAdd", nil, S::Node.new(node("n", labels: {"zone" => "b"})))
    assert_equal :after_backoff,
                 strategy(pending, ["NodeAffinity"], "NodeUpdateNodeLabel", S::Node.new(node("n", labels: {"zone" => "b"})),
                          S::Node.new(node("n", labels: {"zone" => "a"})))
    assert_equal :skip,
                 strategy(pending, ["NodeAffinity"], "NodeUpdateNodeLabel", S::Node.new(node("n", labels: {"zone" => "a"})),
                          S::Node.new(node("n", labels: {"zone" => "a", "x" => "y"})))
    assert_equal :skip, strategy(pending, ["NodeAffinity"], "NodeUpdateNodeAllocatable", nil, S::Node.new(node("n"))),
                 "an event the plugin did not register"

    tainted = S::Node.new(node("n", taints: [{"key" => "dedicated", "value" => "gpu", "effect" => "NoSchedule"}]))
    clean = S::Node.new(node("n"))

    assert_equal :after_backoff, strategy(pending, ["TaintToleration"], "NodeUpdateNodeTaint", tainted, clean)
    assert_equal :skip, strategy(pending, ["TaintToleration"], "NodeUpdateNodeTaint", clean, tainted)
    assert_equal :after_backoff,
                 strategy(pending, ["NodeUnschedulable"], "NodeUpdateNodeTaint", S::Node.new(node("n", unschedulable: true)), clean)
    assert_equal :skip, strategy(pending, ["NodeUnschedulable"], "NodeAdd", nil, S::Node.new(node("n", unschedulable: true)))

    big = pod("big", requests: {"cpu" => "6"})

    assert_equal :skip, strategy(big, ["NodeResourcesFit"], "NodeAdd", nil, clean), "a node too small does not help"
    assert_equal :after_backoff,
                 strategy(big, ["NodeResourcesFit"], "NodeAdd", nil,
                          S::Node.new(node("n", allocatable: {"cpu" => "8", "memory" => "8Gi", "pods" => "110"})))
    assert_equal :after_backoff,
                 strategy(big, ["NodeResourcesFit"], "NodeUpdateNodeAllocatable", clean,
                          S::Node.new(node("n", allocatable: {"cpu" => "8", "memory" => "8Gi", "pods" => "110"})))
    assert_equal :after_backoff, strategy(big, ["NodeResourcesFit"], "assignedPodDelete", S::Pod.new(pod("gone", node: "n")), nil)
    assert_equal :skip, strategy(big, ["NodeResourcesFit"], "PodDelete", S::Pod.new(pod("gone")), nil),
                 "an unbound Pod's deletion frees nothing"
    assert_equal :after_backoff, strategy(big, [], "NodeUpdateNodeCondition", nil, clean), "no rejecting plugins: any event"
    assert_equal :after_backoff, strategy(big, ["UnknownPlugin"], "NodeUpdateNodeCondition", nil, clean)
  end

  def test_pod_and_volume_hints
    pending = pod("p", tolerations: [],
                       topologySpreadConstraints: [{"maxSkew" => 1, "topologyKey" => "zone", "whenUnsatisfiable" => "DoNotSchedule",
                                                    "labelSelector" => {"matchLabels" => {"app" => "web"}}}])
    web_gone = S::Pod.new(pod("web", node: "n", labels: {"app" => "web"}))
    other_gone = S::Pod.new(pod("db", node: "n", labels: {"app" => "db"}))

    assert_equal :after_backoff, strategy(pending, ["PodTopologySpread"], "assignedPodDelete", web_gone, nil)
    assert_equal :skip, strategy(pending, ["PodTopologySpread"], "assignedPodDelete", other_gone, nil)
    assert_equal :after_backoff, strategy(pending, ["SchedulingGates"], "PodUpdatePodSchedulingGatesEliminated", nil, S::Pod.new(pod("p")))
    assert_equal :skip, strategy(pending, ["SchedulingGates"], "PodUpdatePodSchedulingGatesEliminated", nil, S::Pod.new(pod("q")))
    claimer = pod("c", volumes: [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "pvc-1"}}])
    pvc = {"metadata" => {"name" => "pvc-1", "namespace" => "ns"}}

    assert_equal :after_backoff, strategy(claimer, ["VolumeBinding"], "PersistentVolumeClaimAdd", nil, pvc)
    assert_equal :skip,
                 strategy(claimer, ["VolumeBinding"], "PersistentVolumeClaimAdd", nil,
                          pvc.merge("metadata" => {"name" => "other", "namespace" => "ns"}))
    assert_equal :after_backoff, strategy(claimer, ["VolumeZone"], "StorageClassAdd", nil, {"volumeBindingMode" => "WaitForFirstConsumer"})
    assert_equal :skip, strategy(claimer, ["VolumeZone"], "StorageClassAdd", nil, {"volumeBindingMode" => "Immediate"})
    ports = pod("ports", containers: [{"name" => "c", "ports" => [{"hostPort" => 8080, "protocol" => "TCP"}]}])
    freed = S::Pod.new(pod("old", node: "n", containers: [{"name" => "c", "ports" => [{"hostPort" => 8080, "protocol" => "TCP"}]}]))

    assert_equal :after_backoff, strategy(ports, ["NodePorts"], "assignedPodDelete", freed, nil)
    assert_equal :skip, strategy(ports, ["NodePorts"], "assignedPodDelete", S::Pod.new(pod("old", node: "n")), nil)
  end

  def test_queue_moves_only_the_pods_the_hints_allow_and_replays_in_flight_events
    queue = S::SchedulingQueue.new
    calls = []
    queue.hint_strategy = lambda do |pod, plugins, event, _old, _new|
      calls << [pod.name, plugins, event]
      plugins.include?("NodeAffinity") && event.start_with?("NodeUpdateNodeLabel") ? :after_backoff : :skip
    end
    affinity = S::Pod.new(pod("affinity"))
    resources = S::Pod.new(pod("resources"))
    queue.enqueue_unschedulable(affinity, reason: "no match", plugins: ["NodeAffinity"])
    queue.enqueue_unschedulable(resources, reason: "insufficient", plugins: ["NodeResourcesFit"])
    moved = queue.move_on_event("NodeUpdateNodeLabel", old_object: nil, new_object: nil)

    assert_equal(["affinity"], moved.map { |item| item.pod.name })
    assert_equal 1, queue.unschedulable_size
    assert_equal(["affinity"], queue.pending.map { |entry| entry.pod.name })
    assert_empty queue.move_on_event("NodeUpdateNodeAllocatable")

    # In flight: the label event arrives while "affinity" is being scheduled;
    # coming back unschedulable it is retried at once instead of parking.
    item = queue.pop

    assert_equal "affinity", item.pod.name
    assert_equal 1, queue.in_flight_pods
    queue.move_on_event("NodeUpdateNodeLabel", old_object: nil, new_object: nil)

    assert_equal({"NodeUpdateNodeLabel" => 1}, queue.in_flight_event_counts)
    queue.enqueue_unschedulable(item.pod, reason: "still no match", plugins: ["NodeAffinity"])

    assert_includes queue.pending.map { |entry| entry.pod.name }, "affinity", "the in-flight event moved it back to active"
    assert_equal 0, queue.in_flight_pods
    assert_empty queue.in_flight_event_counts, "the event is dropped once nothing in flight needs it"

    # A Pod that finishes with no event in flight parks as usual.
    item = queue.pop
    queue.done(item.pod)
    queue.enqueue_unschedulable(item.pod, reason: "no match", plugins: ["NodeAffinity"])

    assert_equal 2, queue.unschedulable_size
  end

  def test_framework_records_hint_and_in_flight_metrics
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, component: "kube-scheduler")
    metrics = S::Metrics.new(registry: registry)
    framework = S::Framework.new(metrics: metrics)
    framework.queue.enqueue_unschedulable(S::Pod.new(pod("p", nodeSelector: {"zone" => "a"})), reason: "no match",
                                                                                               plugins: ["NodeAffinity"])
    moved = framework.requeue_on_event("NodeAdd", old_object: nil, new_object: S::Node.new(node("n", labels: {"zone" => "a"})))

    assert_equal 1, moved.length
    text = registry.render

    assert_match(/scheduler_queueing_hint_execution_duration_seconds_count\{event="NodeAdd",hint="Queue",plugin="NodeAffinity"\} 1/, text)
    item = framework.queue.pop
    framework.requeue_on_event("NodeUpdateNodeTaint", old_object: nil, new_object: S::Node.new(node("n")))

    assert_match(/scheduler_inflight_events\{event="NodeUpdateNodeTaint"\} 1/, registry.render)
    framework.queue.done(item.pod)
    framework.send(:record_in_flight_events)

    assert_match(/scheduler_inflight_events\{event="NodeUpdateNodeTaint"\} 0/, registry.render)
  end
end
