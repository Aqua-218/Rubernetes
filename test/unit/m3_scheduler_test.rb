# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

class M3SchedulerTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler

  def pod(name = "pod", requests: {}, priority: 0, labels: {}, node_name: nil, extra_spec: {})
    spec = {
      "priority" => priority,
      "containers" => [{"name" => "container", "resources" => {"requests" => requests}}]
    }.merge(extra_spec)
    spec["nodeName"] = node_name if node_name
    {
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}", "labels" => labels},
      "spec" => spec
    }
  end

  def node(name, allocatable: {"cpu" => "2", "memory" => "2Gi"}, labels: {}, conditions: [{"type" => "Ready", "status" => "True"}],
           taints: [], requested: nil, pods: nil, used_ports: nil, volume_limits: nil, image_states: nil)
    value = {
      "apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => labels},
      "spec" => {"taints" => taints},
      "status" => {"allocatable" => allocatable, "conditions" => conditions}
    }
    value["requested"] = requested if requested
    value["pods"] = pods if pods
    value["usedPorts"] = used_ports if used_ports
    value["volumeLimits"] = volume_limits if volume_limits
    value["imageStates"] = image_states if image_states
    value
  end

  # kube-scheduler breaks a score tie by reservoir sampling over the
  # highest-scoring nodes (pkg/scheduler/schedule_one.go selectHost), not by
  # name.  This test used to assert the name order, which is the behaviour that
  # sent every BestEffort Pod -- every Pod that requests nothing, so every node
  # scores 100 -- to the alphabetically first node.  A seeded generator keeps
  # the choice reproducible; see SchedulerTieBreakTest for the spread itself.
  def test_dsl_uses_typed_frozen_inputs_and_breaks_ties_between_equal_nodes
    test = self
    scheduler = Scheduler.new(random: Random.new(11)) do
      filter :typed do |pending, candidate|
        test.assert_instance_of Scheduler::Pod, pending
        test.assert_instance_of Scheduler::Node, candidate
        test.assert_predicate pending.to_h, :frozen?
        test.assert_predicate candidate.to_h, :frozen?
        true
      end
      score :fixed, weight: 3 do |_pending, _candidate|
        40
      end
    end

    result = scheduler.schedule(pod, [node("z"), node("a")])

    assert_predicate result, :scheduled?
    assert_includes %w[a z], result.node_name
    assert_equal "SchedulingGates", result.trace.events.first.fetch("plugin")
    filter_events = result.trace.events.select { |event| event.fetch("phase") == "filter" }

    assert_equal(%w[NodeUnschedulable NodeName TaintToleration NodeAffinity NodePorts
                    NodeResourcesFit VolumeRestrictions NodeVolumeLimits VolumeBinding VolumeZone
                    PodTopologySpread InterPodAffinity DynamicResources NodeDeclaredFeatures typed],
                 filter_events.first(15).map { |event| event.fetch("plugin") })
    assert_equal result.trace.digest, result.trace_sha256
    # The trace records what every plugin saw and scored, which does not depend
    # on which of the tied nodes won.
    assert_equal result.trace.digest, scheduler.schedule(pod, [node("z"), node("a")]).trace.digest
    seeded = -> { Scheduler.new(random: Random.new(3)) { score(:fixed) { |_pending, _candidate| 40 } } }

    assert_equal(seeded.call.schedule(pod, [node("z"), node("a")]).node_name,
                 seeded.call.schedule(pod, [node("z"), node("a")]).node_name)
  end

  def test_standard_filters_cover_resources_name_selector_affinity_taint_and_ready
    tainted = node("tainted", taints: [{"key" => "dedicated", "value" => "batch", "effect" => "NoSchedule"}])
    wrong_label = node("wrong", labels: {"disk" => "hdd"})
    not_ready = node("down", labels: {"disk" => "ssd"}, conditions: [{"type" => "Ready", "status" => "False"}])
    good = node("good", labels: {"disk" => "ssd"})
    pending = pod("filtered", requests: {"cpu" => "3"}, extra_spec: {
                    "nodeSelector" => {"disk" => "ssd"},
                    "tolerations" => [{"key" => "dedicated", "operator" => "Equal", "value" => "batch", "effect" => "NoSchedule"}],
                    "affinity" => {"nodeAffinity" => {"requiredDuringSchedulingIgnoredDuringExecution" => {
                      "nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "disk", "operator" => "In", "values" => ["ssd"]}]}]
                    }}}
                  })
    # Make only the good node fit after the request is reduced.
    pending["spec"]["containers"].first["resources"]["requests"]["cpu"] = "1"
    result = Scheduler.new.schedule(pending, [tainted, wrong_label, not_ready, good])

    assert_equal "good", result.node_name
    assert_equal "node is not Ready", result.filtered.fetch("down").fetch("reason")
    assert_equal "node does not match nodeSelector disk=ssd", result.filtered.fetch("wrong").fetch("reason")
  end

  def test_node_name_filter_rejects_other_nodes
    result = Scheduler.new.schedule(pod("fixed", node_name: "missing"), [node("a")])

    assert_predicate result, :unschedulable?
    assert_equal "pod nodeName \"missing\" does not match node \"a\"", result.filtered.fetch("a").fetch("reason")
  end

  def test_required_pod_anti_affinity_and_affinity_use_topology_and_namespace
    existing = pod("existing", labels: {"app" => "web"}, node_name: "a")
    affinity = pod("affinity", labels: {"app" => "client"}, extra_spec: {"affinity" => {
                     "podAffinity" => {"requiredDuringSchedulingIgnoredDuringExecution" => [{
                       "labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "zone"
                     }]}
                   }})
    nodes = [node("a", labels: {"zone" => "one"}), node("b", labels: {"zone" => "two"})]

    assert_equal "a", Scheduler.new.schedule(affinity, nodes, pods: [existing]).node_name

    anti = pod("anti", extra_spec: {"affinity" => {
                 "podAntiAffinity" => {"requiredDuringSchedulingIgnoredDuringExecution" => [{
                   "labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "zone"
                 }]}
               }})

    assert_equal "b", Scheduler.new.schedule(anti, nodes, pods: [existing]).node_name
  end

  def test_least_allocated_and_topology_spread_scores_are_bounded
    occupied = pod("occupied", requests: {"cpu" => "1"}, labels: {"app" => "web"}, node_name: "a")
    pending = pod("spread", requests: {"cpu" => "500m"}, labels: {"app" => "web"}, extra_spec: {
                    "topologySpreadConstraints" => [{"maxSkew" => 1, "topologyKey" => "zone", "whenUnsatisfiable" => "ScheduleAnyway",
                                                     "labelSelector" => {"matchLabels" => {"app" => "web"}}}]
                  })
    scheduler = Scheduler.new
    result = scheduler.schedule(pending, [node("a", labels: {"zone" => "one"}), node("b", labels: {"zone" => "two"})], pods: [occupied])

    assert_equal "b", result.node_name
    result.scores.each do |score|
      assert_operator score.total, :>=, 0
      assert(score.plugins.all? { |item| item["score"].between?(0, 100) })
    end
  end

  def test_resource_filter_preserves_node_requested_aggregate_without_pod_snapshot
    pending = pod("aggregate-request", requests: {"cpu" => "1500m"})
    candidate = node("a", allocatable: {"cpu" => "2"}, requested: {"cpu" => "1"})
    scheduler = Scheduler.new(preemption: false)

    result = scheduler.schedule(pending, [candidate])

    assert_predicate result, :unschedulable?
    assert_equal "node has insufficient resources", result.reason
  end

  def test_plugin_score_validation_and_input_mutation_fail_the_cycle
    bad_score = Scheduler.new do
      score :bad do |_pod, _node|
        101
      end
    end
    assert_raises(Scheduler::PluginError) { bad_score.schedule(pod, [node("a")]) }

    mutating = Scheduler.new do
      filter :mutating do |_pod, candidate|
        candidate.labels["changed"] = "yes"
        true
      end
    end
    assert_raises(Scheduler::PluginError) { mutating.schedule(pod, [node("a")]) }
  end

  def test_bind_failure_unreserves_and_requeues
    calls = []
    scheduler = Scheduler.new(
      reserve: lambda { |_pod, candidate|
        calls << [:reserve, candidate.name]
        :token
      },
      unreserve: ->(token) { calls << [:unreserve, token.external] },
      bind: lambda { |_pod, _candidate|
        calls << [:bind]
        false
      }
    )
    result = scheduler.schedule(pod("rollback"), [node("a")])

    assert_predicate result, :requeued?
    assert_equal [[:reserve, "a"], [:bind], %i[unreserve token]], calls
    # Requeued means "queued again, after a backoff", not "back in the active
    # queue": see M3SchedulerQueueStarvationRegressionTest.
    assert_equal 0, scheduler.queue.size
    assert_equal 1, scheduler.queue.backoff_size
    assert_includes scheduler.queue, Scheduler::Pod.new(pod("rollback"))
  end

  def test_bind_cas_rejects_external_node_name_change
    candidate = pod("cas")
    scheduler = Scheduler.new(bind: lambda do |_typed, _node|
      candidate["spec"]["nodeName"] = "other"
      nil
    end)
    result = scheduler.schedule(candidate, [node("a")])

    assert_predicate result, :requeued?
    assert_instance_of Scheduler::BindError, result.error
  end

  def test_successful_bind_handler_returns_a_bound_pod_and_releases_reservation
    scheduler = Scheduler.new(
      reserve: ->(_pending, _candidate) { :reservation },
      bind: ->(_pending, _candidate) { true }
    )

    result = scheduler.schedule(pod("bound"), [node("a")])

    assert_predicate result, :scheduled?
    assert_equal "a", result.bound_pod.node_name
    assert_empty scheduler.instance_variable_get(:@reservations)
  end

  def test_preemption_uses_an_explicit_empty_pod_snapshot
    low = pod("low-stale", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    pending = pod("high-stale", requests: {"cpu" => "1500m"}, priority: 10)
    candidate = node("a", allocatable: {"cpu" => "2"}, requested: {"cpu" => "1"}, pods: [low])
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })

    result = scheduler.schedule(pending, [candidate], pods: [low])

    assert_predicate result, :unschedulable?
    assert_equal "a", result.nominated_node
    assert_equal ["low-stale"], result.victims.map(&:name)
    assert scheduler.wait_for_preemptions
    assert_equal ["low-stale"], deleted
  end

  def test_preemption_recomputes_a_raw_requested_aggregate_after_victim_removal
    low = pod("low-aggregate", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    pending = pod("high-aggregate", requests: {"cpu" => "1500m"}, priority: 10)
    candidate = node("a", allocatable: {"cpu" => "2"}, requested: {"cpu" => "1"})
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })

    result = scheduler.schedule(pending, [candidate], pods: [low])

    assert_predicate result, :unschedulable?
    assert_equal "a", result.nominated_node
    assert scheduler.wait_for_preemptions
    assert_equal ["low-aggregate"], deleted
  end

  def test_plugin_registry_and_trace_are_immutable_after_configuration
    scheduler = Scheduler.new

    assert_predicate scheduler.plugins.filters, :frozen?

    assert_raises(FrozenError) { scheduler.plugins.filters.clear }

    trace = scheduler.schedule(pod("immutable-trace"), [node("a")]).trace

    assert_predicate trace.events, :frozen?
    assert_raises(FrozenError) { trace.events.clear }
  end

  def test_adversarial_resource_and_plugin_values_fail_closed
    assert_raises(Scheduler::PluginError) do
      Scheduler.new.schedule(pod("negative", requests: {"cpu" => "-1"}), [node("a")])
    end

    assert_raises(Scheduler::ValidationError) do
      Scheduler::Plugin.new(name: "fractional", kind: :score, weight: 1.5, block: ->(_pod, _node) { 1 })
    end
  end

  def test_preemption_chooses_minimum_lower_priority_victim_and_unschedulable_queue
    low = pod("low", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    pending = pod("high", requests: {"cpu" => "1500m"}, priority: 10)
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })
    result = scheduler.schedule(pending, [node("a", allocatable: {"cpu" => "2"})], pods: [low])

    assert_equal :unschedulable, result.status
    assert_equal "a", result.nominated_node
    assert_equal ["low"], result.victims.map(&:name)
    assert scheduler.wait_for_preemptions
    assert_equal ["low"], deleted

    never = pod("never", requests: {"cpu" => "3"}, priority: 10, extra_spec: {"preemptionPolicy" => "Never"})
    no_preemption_scheduler = Scheduler.new
    no_preemption = no_preemption_scheduler.schedule(never, [node("a", allocatable: {"cpu" => "2"})])

    assert_predicate no_preemption, :unschedulable?
    assert_equal 1, no_preemption_scheduler.queue.unschedulable_size
  end

  def test_preemption_without_delete_handler_is_requeued_fail_closed
    low = pod("low-no-delete", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    pending = pod("high-no-delete", requests: {"cpu" => "1500m"}, priority: 10)
    scheduler = Scheduler.new

    result = scheduler.schedule(pending, [node("a", allocatable: {"cpu" => "2"})], pods: [low])

    assert_predicate result, :requeued?
    assert_instance_of Scheduler::PreemptionError, result.error
    assert_equal ["low-no-delete"], result.victims.map(&:name)
    assert_equal 0, scheduler.queue.size
    assert_equal 1, scheduler.queue.backoff_size
  end

  # Upstream never binds the preemptor in the cycle that preempted: the
  # victims only start their graceful termination, so the Pod is nominated
  # to the node and waits in the unschedulable pool until they are gone.
  def test_the_preemptor_is_nominated_and_bound_once_its_victims_are_gone
    low = pod("low-wait", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    pending = pod("high-wait", requests: {"cpu" => "1500m"}, priority: 10)
    candidate = node("a", allocatable: {"cpu" => "2"})
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name }, bind: ->(_pod, _node) { true })

    first = scheduler.schedule(pending, [candidate], pods: [low, pending])

    assert_predicate first, :unschedulable?
    assert_equal "a", first.nominated_node
    assert scheduler.wait_for_preemptions
    assert_equal ["low-wait"], deleted
    assert_equal "a", scheduler.nominated_node_for(Scheduler::Pod.new(pending))

    # The victim is gone: the next cycle tries the nominated node first.
    second = scheduler.schedule(pending, [candidate], pods: [pending])

    assert_predicate second, :scheduled?
    assert_equal "a", second.node_name
    assert_equal "", scheduler.nominated_node_for(Scheduler::Pod.new(pending)),
                 "a bound Pod keeps no nomination"
  end

  # PodEligibleToPreemptOthers: while victims of its earlier preemption are
  # still terminating on the nominated node, the Pod waits; it does not
  # evict anything else.
  def test_a_preemptor_waits_for_terminating_victims_instead_of_preempting_again
    terminating = pod("victim-terminating", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    terminating["metadata"]["deletionTimestamp"] = "2026-09-25T00:00:00Z"
    terminating["status"] = {"conditions" => [{"type" => "DisruptionTarget", "status" => "True",
                                               "reason" => "PreemptionByScheduler"}]}
    other = pod("other-low", requests: {"cpu" => "1"}, priority: 1, node_name: "b")
    pending = pod("high-nominated", requests: {"cpu" => "1500m"}, priority: 10)
    pending["status"] = {"nominatedNodeName" => "a"}
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })

    result = scheduler.schedule(pending, [node("a", allocatable: {"cpu" => "2"}), node("b", allocatable: {"cpu" => "2"})],
                                pods: [terminating, other, pending])

    assert_predicate result, :unschedulable?
    assert_empty result.victims
    assert scheduler.wait_for_preemptions
    assert_empty deleted
  end

  # RunFilterPluginsWithNominatedPods: a Pod nominated to a node holds its
  # room there against Pods of lower priority, not against higher ones.
  def test_nominated_pods_hold_room_against_lower_priority_pods
    nominated = pod("nominated-mid", requests: {"cpu" => "1500m"}, priority: 5)
    nominated["status"] = {"nominatedNodeName" => "a"}
    candidate = node("a", allocatable: {"cpu" => "2"})

    low = Scheduler.new(preemption: false).schedule(pod("low-late", requests: {"cpu" => "1"}, priority: 1),
                                                    [candidate], pods: [nominated])

    assert_predicate low, :unschedulable?

    high = Scheduler.new(preemption: false).schedule(pod("high-late", requests: {"cpu" => "1"}, priority: 10),
                                                     [candidate], pods: [nominated])

    assert_predicate high, :scheduled?
  end

  # SchedulerAsyncPreemption: the Pod is gated while its victims are being
  # evicted and activated once the eviction calls are done.
  def test_async_preemption_gates_the_preemptor_until_its_victims_are_evicted
    low = pod("low-async", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    pending = pod("high-async", requests: {"cpu" => "1500m"}, priority: 10)
    release = Queue.new
    deleted = []
    scheduler = Scheduler.new(delete_pod: lambda { |victim|
      release.pop
      deleted << victim.name
    })
    candidate = node("a", allocatable: {"cpu" => "2"})

    assert_predicate scheduler.schedule(pending, [candidate], pods: [low, pending]), :unschedulable?
    assert scheduler.preempting?(Scheduler::Pod.new(pending))
    gated = scheduler.schedule(pending, [candidate], pods: [low, pending])

    assert_predicate gated, :gated?
    assert_equal 1, scheduler.queue.unschedulable_size

    release << true

    assert scheduler.wait_for_preemptions
    assert_equal ["low-async"], deleted
    refute scheduler.preempting?(Scheduler::Pod.new(pending))
    assert_equal 0, scheduler.queue.unschedulable_size
    assert_equal 1, scheduler.queue.size, "the preemptor is activated"
  end

  # prepareCandidateAsync: victims that are all terminating already need no
  # call and nothing is gated.
  def test_terminating_victims_are_not_deleted_again_and_nothing_is_gated
    low = pod("low-going", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    low["metadata"]["deletionTimestamp"] = "2026-09-25T00:00:00Z"
    pending = pod("high-going", requests: {"cpu" => "1500m"}, priority: 10)
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })

    result = scheduler.schedule(pending, [node("a", allocatable: {"cpu" => "2"})], pods: [low, pending])

    assert_equal "a", result.nominated_node
    refute scheduler.preempting?(Scheduler::Pod.new(pending))
    assert scheduler.wait_for_preemptions
    assert_empty deleted
  end

  # "[sig-scheduling] SchedulerPreemption ... with the async preemption":
  # medium Pods preempt low Pods one after another while the earlier victims
  # are still terminating.  A Pod nominated to the node holds the room the
  # terminating victim frees, so the next preemptor needs a fresh victim.
  # The DefaultPreemption plugin's evaluator handed the framework's filter a
  # CycleContext where the remaining Pods belong, and every such cycle failed
  # ("undefined method 'uid' for ... CycleContext").
  def test_successive_preemptions_evict_a_fresh_victim_each
    terminating = pod("low-0", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    terminating["metadata"]["deletionTimestamp"] = "2026-09-25T00:00:00Z"
    fresh = pod("low-1", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    nominated = pod("medium-0", requests: {"cpu" => "1"}, priority: 5)
    nominated["status"] = {"nominatedNodeName" => "a"}
    pending = pod("medium-1", requests: {"cpu" => "1"}, priority: 5)
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })

    result = scheduler.schedule(pending, [node("a", allocatable: {"cpu" => "2"})],
                                pods: [terminating, fresh, nominated, pending])

    assert_equal "a", result.nominated_node, result.error&.message
    assert scheduler.wait_for_preemptions
    assert_equal ["low-1"], deleted
  end

  # executor.go: every victim but the last in parallel, the last one after.
  def test_victims_are_evicted_in_parallel_and_the_last_one_last
    victims = %w[v1 v2 v3].map { |name| pod(name, requests: {"cpu" => "1"}, priority: 1, node_name: "a") }
    pending = pod("high-many", requests: {"cpu" => "3"}, priority: 10)
    order = Queue.new
    scheduler = Scheduler.new(delete_pod: lambda { |victim|
      sleep 0.2
      order << victim.name
    })
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = scheduler.schedule(pending, [node("a", allocatable: {"cpu" => "3"})], pods: victims + [pending])

    assert scheduler.wait_for_preemptions
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    deleted = Array.new(order.size) { order.pop }

    assert_equal %w[v1 v2 v3], deleted.sort
    assert_equal result.victims.last.name, deleted.last
    assert_operator elapsed, :<, 0.55, "the first victims were not evicted one after another"
  end

  # Lower-priority Pods nominated to the preempted node lose that
  # nomination: they no longer fit there.
  def test_preemption_clears_lower_priority_nominations_on_the_node
    low = pod("low-running", requests: {"cpu" => "1"}, priority: 1, node_name: "a")
    waiting = pod("mid-nominated", requests: {"cpu" => "500m"}, priority: 3)
    waiting["status"] = {"nominatedNodeName" => "a"}
    pending = pod("high-clearing", requests: {"cpu" => "1500m"}, priority: 10)
    cleared = []
    scheduler = Scheduler.new(delete_pod: ->(_victim) { true },
                              clear_nomination: ->(nominee) { cleared << nominee.name })

    result = scheduler.schedule(pending, [node("a", allocatable: {"cpu" => "2"})], pods: [low, waiting, pending])

    assert_equal "a", result.nominated_node
    assert scheduler.wait_for_preemptions
    assert_equal ["mid-nominated"], cleared
    assert_equal "", scheduler.nominated_node_for(Scheduler::Pod.new(waiting))
  end

  # NominatedNodeNameForExpectation: a Pod whose PreBind has work to do is
  # nominated to its node before PreBind runs.
  def test_a_pod_with_pre_bind_work_is_nominated_before_binding
    busy = Class.new(Scheduler::DynamicResources) do
      def pre_bind_preflight?(_pod, _node = nil, _context = nil) = true
    end.new
    nominated = []
    scheduler = Scheduler.new(dynamic_resources: busy, bind: ->(_pod, _node) { true },
                              nominate: ->(pending, node_name) { nominated << [pending.name, node_name] })

    assert_predicate scheduler.schedule(pod("claims"), [node("a")]), :scheduled?
    assert_equal [%w[claims a]], nominated

    plain = []
    Scheduler.new(bind: ->(_pod, _node) { true }, nominate: ->(pending, node_name) { plain << [pending.name, node_name] })
      .schedule(pod("no-work"), [node("a")])

    assert_empty plain, "a Pod bound right away is not nominated"
  end

  def test_default_filters_reject_invalid_node_assignments_table
    cases = [
      {
        name: "SchedulingGates",
        plugin: Scheduler::Filters::SchedulingGates.new,
        pending: pod("gated", extra_spec: {"schedulingGates" => [{"name" => "hold"}]}),
        candidate: node("a")
      },
      {
        name: "NodePorts",
        plugin: Scheduler::Filters::NodePorts.new,
        pending: pod("ports", extra_spec: {"containers" => [{"name" => "c", "ports" => [{"hostPort" => 8080}]}]}),
        candidate: node("a", used_ports: [{"hostPort" => 8080, "protocol" => "TCP"}])
      },
      {
        name: "VolumeRestrictions",
        plugin: Scheduler::Filters::VolumeRestrictions.new,
        pending: pod("volume-conflict", extra_spec: {"volumes" => [{"name" => "disk", "gcePersistentDisk" => {"pdName" => "disk-a"}}]}),
        candidate: node("a", pods: [pod("existing-volume", node_name: "a", extra_spec: {
                                          "volumes" => [{"name" => "disk", "gcePersistentDisk" => {"pdName" => "disk-a"}}]
                                        })])
      },
      {
        name: "VolumeZone",
        plugin: Scheduler::Filters::VolumeZone.new,
        pending: pod("zone-volume", extra_spec: {"volumes" => [{"name" => "claim", "persistentVolumeClaim" => {"claimName" => "claim"}}]}),
        candidate: node("a", labels: {"topology.kubernetes.io/zone" => "zone-b"}),
        context: Scheduler::CycleContext.new(nodes: [], pods: [], volume_data: {
                                               "persistentVolumeClaims" => {"default/claim" => {"metadata" => {"name" => "claim", "namespace" => "default"},
                                                                                                "spec" => {"volumeName" => "pv-a"}}},
                                               "persistentVolumes" => {"pv-a" => {
                                                 "metadata" => {"name" => "pv-a"},
                                                 "nodeAffinity" => {"required" => {"nodeSelectorTerms" => [{"matchExpressions" => [{
                                                   "key" => "topology.kubernetes.io/zone", "operator" => "In", "values" => ["zone-a"]
                                                 }]}]}}
                                               }}
                                             })
      },
      {
        name: "NodeVolumeLimits",
        plugin: Scheduler::Filters::NodeVolumeLimits.new,
        pending: pod("volume-limit", extra_spec: {"volumes" => [{"name" => "claim", "persistentVolumeClaim" => {"claimName" => "claim"}}]}),
        candidate: node("a", volume_limits: {"example.csi" => 0}),
        context: Scheduler::CycleContext.new(nodes: [], pods: [], volume_data: {
                                               "persistentVolumeClaims" => {"default/claim" => {"metadata" => {"name" => "claim", "namespace" => "default"},
                                                                                                "spec" => {"volumeName" => "pv-a"}}},
                                               "persistentVolumes" => {"pv-a" => {"metadata" => {"name" => "pv-a"},
                                                                                  "csi" => {"driver" => "example.csi"}}}
                                             })
      },
      {
        name: "VolumeBinding",
        plugin: Scheduler::Filters::VolumeBinding.new,
        pending: pod("unbound", extra_spec: {"volumes" => [{"name" => "claim", "persistentVolumeClaim" => {"claimName" => "missing"}}]}),
        candidate: node("a"),
        context: Scheduler::CycleContext.new(nodes: [], pods: [], volume_data: {
                                               "persistentVolumeClaims" => {"default/missing" => {"metadata" => {"name" => "missing", "namespace" => "default"},
                                                                                                  "spec" => {"resources" => {"requests" => {"storage" => "1Gi"}}}}},
                                               "persistentVolumes" => []
                                             })
      },
      {
        name: "PodTopologySpread",
        plugin: Scheduler::Filters::PodTopologySpread.new,
        pending: pod("spread-reject", labels: {"app" => "web"}, extra_spec: {
                       "topologySpreadConstraints" => [{"maxSkew" => 1, "topologyKey" => "zone", "whenUnsatisfiable" => "DoNotSchedule",
                                                        "labelSelector" => {"matchLabels" => {"app" => "web"}}}]
                     }),
        candidate: node("a", labels: {"zone" => "zone-a"}),
        context: Scheduler::CycleContext.new(
          nodes: [node("a", labels: {"zone" => "zone-a"}), node("b", labels: {"zone" => "zone-b"})],
          pods: [pod("existing-spread", labels: {"app" => "web"}, node_name: "a")]
        )
      }
    ]

    cases.each do |entry|
      pending = Scheduler::Pod.new(entry.fetch(:pending))
      candidate = Scheduler::Node.new(entry.fetch(:candidate))
      source_context = entry[:context]
      context = if source_context
                  Scheduler::CycleContext.new(
                    nodes: source_context.nodes.map { |item| item.is_a?(Scheduler::Node) ? item : Scheduler::Node.new(item) },
                    pods: source_context.pods.map { |item| item.is_a?(Scheduler::Pod) ? item : Scheduler::Pod.new(item) },
                    volume_data: source_context.volume_data
                  )
                else
                  Scheduler::CycleContext.new(nodes: [candidate], pods: candidate.pods)
                end
      result = entry.fetch(:plugin).call(pending, candidate, context)

      assert_instance_of Scheduler::Rejection, result, entry.fetch(:name)
    end
  end

  def test_default_scores_are_normalized_to_scheduler_range_table
    existing = pod("existing-score", labels: {"app" => "web"}, node_name: "a")
    pending = pod("pending-score", labels: {"app" => "web"}, requests: {"cpu" => "500m"}, extra_spec: {
                    "affinity" => {"nodeAffinity" => {"preferredDuringSchedulingIgnoredDuringExecution" => [{
                      "weight" => 50, "preference" => {"matchExpressions" => [{"key" => "disk", "operator" => "In", "values" => ["ssd"]}]}
                    }]}},
                    "topologySpreadConstraints" => [{"maxSkew" => 1, "topologyKey" => "zone", "whenUnsatisfiable" => "ScheduleAnyway",
                                                     "labelSelector" => {"matchLabels" => {"app" => "web"}}}],
                    "containers" => [{"name" => "c", "image" => "example/app:1", "resources" => {"requests" => {"cpu" => "500m"}}}]
                  })
    nodes = [
      node("a", labels: {"zone" => "one", "disk" => "ssd"},
                image_states: {"example/app:1" => {"sizeBytes" => 50 * 1024 * 1024, "numNodes" => 1}}),
      node("b", labels: {"zone" => "two", "disk" => "hdd"})
    ]
    typed_nodes = nodes.map { |item| Scheduler::Node.new(item) }
    context = Scheduler::CycleContext.new(nodes: typed_nodes, pods: [Scheduler::Pod.new(existing)])
    pending = Scheduler::Pod.new(pending)
    scores = [Scheduler::Scores::TaintToleration.new, Scheduler::Scores::NodeAffinity.new,
              Scheduler::Scores::LeastAllocated.new, Scheduler::Scores::TopologySpread.new,
              Scheduler::Scores::InterPodAffinity.new, Scheduler::Scores::NodeResourcesBalancedAllocation.new,
              Scheduler::Scores::ImageLocality.new]

    scores.each do |plugin|
      typed_nodes.each do |candidate|
        value = plugin.call(pending, candidate, context)

        assert_kind_of Integer, value, plugin.class.name
        assert_includes 0..100, value, plugin.class.name
      end
    end
  end

  def test_priority_sort_queue_order_and_default_binding
    queue = Scheduler::SchedulingQueue.new
    entries = [
      ["low", 1, "2026-01-01T00:00:00Z"],
      ["high-new", 10, "2026-01-01T00:00:02Z"],
      ["high-old", 10, "2026-01-01T00:00:01Z"]
    ]
    entries.each do |name, priority, timestamp|
      queue.enqueue(pod(name, priority: priority).merge("metadata" => {"name" => name, "uid" => name,
                                                                       "creationTimestamp" => timestamp}))
    end

    assert_equal(%w[high-old high-new low], Array.new(3) { queue.pop.pod.name })

    pending = pod("default-bind")
    result = Scheduler.new(preemption: false).schedule(pending, [node("bound-node")])

    assert_predicate result, :scheduled?
    assert_equal "bound-node", result.bound_pod.node_name
    assert_equal "bound-node", result.pod.spec["nodeName"]
  end
end
