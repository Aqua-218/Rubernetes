# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require_relative "../support/node_lifecycle_fakes"

# The node side of an eviction: the eviction manager's killPodFunc stops the
# Pod within the eviction grace period and reports it Failed/Evicted with the
# kubelet's message and a DisruptionTarget condition (TerminationByKubelet),
# and the Pod is never started again -- whatever its restart policy, as
# for a Pod killed for exceeding activeDeadlineSeconds.  The agent wires the
# eviction admit handler into admission and the pressure conditions into
# the Node.
class NodeEvictionLifecycleTest < Minitest::Test
  Runtime = NodeLifecycleFakes::Runtime
  Reporter = NodeLifecycleFakes::Reporter

  MESSAGE = "The node was low on resource: memory. Threshold quantity: 100Mi, available: 50Mi. "

  def setup
    @reporter = Reporter.new
    @runtime = Runtime.new
    @lifecycle = Rubernetes::Node::Lifecycle.new(runtime: @runtime, reporter: @reporter, sleeper: ->(_seconds) {})
  end

  def pod(restart_policy: "Always", grace: 30)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "victim", "namespace" => "ns", "uid" => "pod-1", "generation" => 3},
     "spec" => {"nodeName" => "node-1", "restartPolicy" => restart_policy, "terminationGracePeriodSeconds" => grace,
                "containers" => [{"name" => "app", "image" => "example/busybox"}]}}
  end

  def condition = {"type" => "DisruptionTarget", "status" => "True", "reason" => "TerminationByKubelet",
                   "message" => MESSAGE, "observedGeneration" => 3}

  def test_evicted_pod_is_failed_with_reason_message_and_disruption_target
    spec = pod
    @lifecycle.start(spec)
    @lifecycle.evict(spec, message: MESSAGE, grace_period_seconds: 1, condition: condition)

    assert_equal [["app", 1]], @runtime.stopped, "the eviction grace period overrides terminationGracePeriodSeconds"
    status = @reporter.statuses.last
    assert_equal "Failed", status["phase"]
    assert_equal "Evicted", status["reason"]
    assert_equal MESSAGE, status["message"]
    target = status["conditions"].find { |entry| entry["type"] == "DisruptionTarget" }
    assert_equal "True", target["status"]
    assert_equal "TerminationByKubelet", target["reason"]
    assert_equal MESSAGE, target["message"]
    assert_equal 3, target["observedGeneration"]
    refute_nil target["lastTransitionTime"]

    # restartPolicy Always: still never started again.
    @lifecycle.reconcile(spec)
    @lifecycle.reconcile(spec.merge("status" => status))
    assert_equal ["app"], @runtime.created
    assert_equal 1, @runtime.sandboxes
  end

  def test_requested_eviction_is_carried_out_by_the_next_sync
    spec = pod(grace: 7)
    @lifecycle.start(spec)
    @lifecycle.request_eviction("pod-1", message: MESSAGE, grace_period_seconds: 7, condition: condition)
    assert_empty @runtime.stopped
    @lifecycle.reconcile(spec)
    assert_equal [["app", 7]], @runtime.stopped
    assert_equal "Evicted", @reporter.statuses.last["reason"]
    @lifecycle.reconcile(spec)
    assert_equal ["app"], @runtime.created
  end

  def test_active_deadline_failure_is_final_even_with_restart_policy_always
    spec = pod
    spec["spec"]["activeDeadlineSeconds"] = 1
    @lifecycle.start(spec)
    @lifecycle.send(:record, "pod-1")[:started_at] = (Time.now.utc - 60).iso8601(6)
    @lifecycle.reconcile(spec)
    assert_equal "DeadlineExceeded", @reporter.statuses.last["reason"]
    @lifecycle.reconcile(spec)
    @lifecycle.reconcile(spec)
    assert_equal ["app"], @runtime.created, "a Pod the kubelet failed is not restarted"
  end

  class API
    attr_reader :nodes

    def initialize = @nodes = []
    def register_node(node) = (@nodes << node).last
    def renew_lease(lease) = lease
  end

  class Loop
    def start(**) = true
    def stop(**) = true
  end

  class Lifecycle
    def recover(**) = {"ready" => true, "errors" => [], "blocked" => []}
    def admitted_pods = []
    def record(_uid) = nil
  end

  class Stats
    attr_accessor :available

    def initialize = @available = 8 * 1024**3
    def summary = {"node" => {"memory" => {"availableBytes" => available, "workingSetBytes" => 1024**3, "time" => Time.now.utc.iso8601(6)}},
                   "pods" => []}
  end

  def test_agent_wires_pressure_into_node_conditions_and_admission
    api = API.new
    stats = Stats.new
    agent = Rubernetes::Node::Agent.new(node_name: "node-a", api: api, lifecycle: Lifecycle.new, sync_loop: Loop.new,
                                        sleeper: ->(_) {}, capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"},
                                        stats_provider: stats)
    agent.start
    memory = api.nodes.last.dig("status", "conditions").find { |entry| entry["type"] == "MemoryPressure" }
    assert_equal "False", memory["status"]
    assert_equal "KubeletHasSufficientMemory", memory["reason"]
    assert_equal "kubelet has sufficient memory available", memory["message"]
    first_transition = memory["lastTransitionTime"]

    stats.available = 50 * 1024**2
    agent.eviction_manager.synchronize
    memory = api.nodes.last.dig("status", "conditions").find { |entry| entry["type"] == "MemoryPressure" }
    assert_equal "True", memory["status"], "a condition change is published at once"
    assert_equal "KubeletHasInsufficientMemory", memory["reason"]

    best_effort = {"metadata" => {"name" => "p", "uid" => "u"}, "spec" => {"containers" => [{"name" => "c"}]}}
    decision = agent.instance_variable_get(:@admission).admit(best_effort)
    refute decision.accepted
    assert_equal "Evicted", decision.reason
    assert_equal "The node had condition: [MemoryPressure]. ", decision.message

    disk = api.nodes.last.dig("status", "conditions").find { |entry| entry["type"] == "DiskPressure" }
    assert_equal "False", disk["status"]
    refute_nil first_transition
  ensure
    agent&.stop rescue nil
  end

  class ImageStats < Stats
    def image_fs_stats = {"capacityBytes" => 100, "availableBytes" => 50}
  end

  class ImageResolver
    def staging_root = nil
    def cached_images = []
    def evict_cached_image(*, **) = false
  end

  # Image GC runs over the resolver's cache and is the disk signals'
  # node-level reclaim.
  def test_agent_builds_image_gc_and_uses_it_for_disk_reclaim
    agent = Rubernetes::Node::Agent.new(node_name: "node-a", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new,
                                        sleeper: ->(_) {}, stats_provider: ImageStats.new, image_resolver: ImageResolver.new)
    refute_nil agent.image_gc_manager
    reclaim = agent.eviction_manager.instance_variable_get(:@node_reclaim)
    assert_equal %w[containerfs.available containerfs.inodesFree imagefs.available imagefs.inodesFree nodefs.available nodefs.inodesFree],
                 reclaim.keys.sort
    assert_empty agent.image_gc_manager.garbage_collect
    assert_nil Rubernetes::Node::Agent.new(node_name: "node-a", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new,
                                           sleeper: ->(_) {}, stats_provider: ImageStats.new, image_resolver: ImageResolver.new,
                                           image_gc: {"enabled" => false}).image_gc_manager
  end

  def test_eviction_can_be_disabled_and_is_absent_without_stats
    agent = Rubernetes::Node::Agent.new(node_name: "node-a", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new,
                                        sleeper: ->(_) {}, stats_provider: Stats.new, eviction: {"enabled" => false})
    assert_nil agent.eviction_manager
    assert_nil Rubernetes::Node::Agent.new(node_name: "node-a", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new,
                                           sleeper: ->(_) {}).eviction_manager
  end
end
