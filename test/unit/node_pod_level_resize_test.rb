# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# In-place resize on the node (InPlacePodLevelResourcesVerticalScaling and
# InPlacePodVerticalScaling, v1.36.2): pod-level resources are resized in place
# through the Pod cgroup instead of recreating the Pod; a resize that does not
# fit waits as PodResizePending/Deferred; a pod memory limit below current usage
# is refused with PodResizeInProgress/Error; status.resources and
# status.allocatedResources report the Pod's pod-level resources.
class NodePodLevelResizeTest < Minitest::Test
  class Runtime
    attr_reader :pod_updates, :container_updates, :created
    attr_accessor :memory_current

    def initialize
      @counter = 0
      @pod_updates = []
      @container_updates = []
      @created = []
      @memory_current = 10 * (1024**2)
      @cgroup = {"cpu.weight" => "39", "cpu.max" => "100000 100000", "memory.max" => (512 * (1024**2)).to_s}
    end

    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"

    def create_container(_sandbox, spec)
      @created << spec["name"]
      "c#{@counter += 1}"
    end

    def start_container(_id) = true
    def container_status(_id) = {"state" => "running"}
    def stop_container(_id, timeout:) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true

    def update_container_resources(id, resources:, pod_spec: nil)
      @container_updates << [id, resources]
      {}
    end

    def update_pod_resources(sandbox_id, pod_spec:)
      @pod_updates << [sandbox_id, pod_spec["resources"]]
      limits = pod_spec.dig("resources", "limits") || {}
      @cgroup["memory.max"] = Rubernetes::Runtime::Native::Resources.bytes(limits["memory"]).to_s if limits["memory"]
      @cgroup["cpu.max"] = "#{Rubernetes::Runtime::Native::Resources.milli_cpu(limits["cpu"]) * 100} 100000" if limits["cpu"]
      {}
    end

    def pod_cgroup_readback(_sandbox_id) = @cgroup.merge("memory.current" => @memory_current.to_s)
  end

  class Reporter
    attr_reader :statuses

    def initialize = @statuses = []
    def report(_pod, status) = @statuses << status.to_h
  end

  class StaticPolicies
    attr_writer :metrics

    def start(**) = self
    def cpu_manager_policy = "static"
    def memory_manager_policy = "Static"
    def admit(_pod) = Rubernetes::Node::TopologyManager::AdmitResult.ok
    def pre_start(_pod, _container, _id) = nil
  end

  def setup
    @runtime = Runtime.new
    @reporter = Reporter.new
    @admission = Rubernetes::Node::Admission.new(node_name: "node-1", capacity: {"cpu" => "4", "memory" => "4Gi", "pods" => "10"})
    @events = []
    @lifecycle = Rubernetes::Node::Lifecycle.new(runtime: @runtime, reporter: @reporter, admission: @admission, sleeper: ->(_) {},
                                                 event_sink: ->(_uid, entry) { @events << entry })
  end

  def pod(generation:, pod_resources:, container_resources: {})
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "plr", "namespace" => "ns", "uid" => "pod-1", "generation" => generation},
     "spec" => {"nodeName" => "node-1", "resources" => pod_resources,
                "containers" => [{"name" => "c1", "image" => "i", "resources" => container_resources}]}}
  end

  def conditions(type)
    Array(@reporter.statuses.last["conditions"]).select { |entry| entry["type"] == type }
  end

  def test_pod_level_resize_is_actuated_in_place
    @lifecycle.start(pod(generation: 1,
                         pod_resources: {"requests" => {"cpu" => "1", "memory" => "256Mi"},
                                         "limits" => {"cpu" => "1", "memory" => "512Mi"}}))
    status = @reporter.statuses.last

    assert_equal({"cpu" => "1", "memory" => "256Mi"}, status["allocatedResources"])
    @lifecycle.reconcile(pod(generation: 2,
                             pod_resources: {"requests" => {"cpu" => "2", "memory" => "256Mi"},
                                             "limits" => {"cpu" => "2", "memory" => "512Mi"}}))

    assert_equal ["c1"], @runtime.created, "the Pod was not recreated"
    assert_equal({"requests" => {"cpu" => "2", "memory" => "256Mi"}, "limits" => {"cpu" => "2", "memory" => "512Mi"}},
                 @runtime.pod_updates.last[1])
    status = @reporter.statuses.last

    assert_equal({"cpu" => "2", "memory" => "256Mi"}, status["allocatedResources"])
    assert_equal "2", status.dig("resources", "limits", "cpu")
    assert_empty conditions("PodResizePending")
    assert_empty conditions("PodResizeInProgress")
    assert(@events.any? { |event| event["type"] == "pod.resize_started" && event["message"].start_with?("Pod resize started: {") })
    assert(@events.any? { |event| event["type"] == "pod.resize_completed" })
  end

  def test_resize_that_does_not_fit_is_deferred
    @lifecycle.start(pod(generation: 1, pod_resources: {"requests" => {"cpu" => "1"}, "limits" => {"cpu" => "1"}}))
    @lifecycle.reconcile(pod(generation: 2, pod_resources: {"requests" => {"cpu" => "8"}, "limits" => {"cpu" => "8"}}))

    assert_empty @runtime.pod_updates
    pending = conditions("PodResizePending").fetch(0)

    assert_equal "Deferred", pending["reason"]
    assert_equal 2, pending["observedGeneration"]
    assert_equal "Node didn't have enough resource: cpu, requested: 8000, used: 0, capacity: 4000", pending["message"]
    assert_equal({"cpu" => "1"}, @reporter.statuses.last["allocatedResources"], "the allocation is unchanged")
    assert(@events.any? { |event| event["type"] == "pod.resize_deferred" })

    # Reverting the request clears the pending resize.
    @lifecycle.reconcile(pod(generation: 3, pod_resources: {"requests" => {"cpu" => "1"}, "limits" => {"cpu" => "1"}}))

    assert_empty conditions("PodResizePending")
  end

  def queued_cpu_resize(uid, cpu, generation: 1, priority: 0, guaranteed: false)
    amounts = {"cpu" => cpu}
    amounts["memory"] = "100Mi" if guaranteed
    value = pod(generation: generation, pod_resources: nil, container_resources: {"requests" => amounts, "limits" => amounts})
    value.fetch("metadata").merge!("name" => uid, "uid" => uid)
    value.fetch("spec")["priority"] = priority
    value
  end

  def test_deferred_resizes_share_capacity_in_priority_qos_and_arrival_order
    @lifecycle.start(queued_cpu_resize("blocker", "2500m"))
    requests = {"older" => {}, "younger" => {}, "guaranteed" => {guaranteed: true}, "priority" => {priority: 1000}}
    desired = requests.to_h do |name, flags|
      @lifecycle.start(queued_cpu_resize(name, "250m", **flags))
      [name, queued_cpu_resize(name, "2500m", generation: 2, **flags)]
    end
    desired.each_value { |pod| @lifecycle.reconcile(pod) }

    assert_empty @runtime.container_updates
    @lifecycle.pod_removed("blocker")

    %w[priority guaranteed older younger].each do |expected|
      desired.each_value { |pod| @lifecycle.reconcile(pod) }

      actual = desired.keys.select do |name|
        @lifecycle.record(name).dig(:pod, "spec", "containers", 0, "resources", "requests", "cpu") == "2500m"
      end

      assert_equal [expected], actual
      @lifecycle.pod_removed(expected)
      desired.delete(expected)
    end
  end

  def test_memory_limit_below_usage_is_refused
    @lifecycle.start(pod(generation: 1, pod_resources: {"requests" => {"memory" => "256Mi"}, "limits" => {"memory" => "256Mi"}}))
    @runtime.memory_current = 200 * (1024**2)
    @lifecycle.reconcile(pod(generation: 2, pod_resources: {"requests" => {"memory" => "100Mi"}, "limits" => {"memory" => "100Mi"}}))

    assert_empty @runtime.pod_updates
    progress = conditions("PodResizeInProgress").fetch(0)

    assert_equal "Error", progress["reason"]
    assert_equal "cannot decrease memory limits: attempting to set pod memory limit (#{100 * (1024**2)}) below current usage (#{200 * (1024**2)})",
                 progress["message"]

    @runtime.memory_current = 50 * (1024**2)
    @lifecycle.reconcile(pod(generation: 3, pod_resources: {"requests" => {"memory" => "100Mi"}, "limits" => {"memory" => "100Mi"}}))

    assert_equal 1, @runtime.pod_updates.length
    assert_empty conditions("PodResizeInProgress")
  end

  def test_refused_container_memory_decrease_does_not_change_actuated_status
    before = {"requests" => {"memory" => "256Mi"}, "limits" => {"memory" => "256Mi"}}
    after = {"requests" => {"memory" => "100Mi"}, "limits" => {"memory" => "100Mi"}}
    @lifecycle.start(pod(generation: 1, pod_resources: nil, container_resources: before))
    @runtime.memory_current = 200 * (1024**2)
    @lifecycle.reconcile(pod(generation: 2, pod_resources: nil, container_resources: after))

    assert_empty @runtime.container_updates
    assert_equal "Error", conditions("PodResizeInProgress").fetch(0)["reason"]
    assert_equal before, @reporter.statuses.last.dig("containerStatuses", 0, "resources")
  end

  def test_running_init_applies_resize_before_next_container_starts
    desired = pod(generation: 1, pod_resources: nil)
    desired["spec"]["initContainers"] = [{"name" => "init", "image" => "i", "resources" => {"requests" => {"cpu" => "100m"}}}]
    @lifecycle.desired_pod_lookup = ->(_uid) { desired }
    resized = {"requests" => {"cpu" => "200m"}}
    original = desired
    @runtime.define_singleton_method(:wait_container) do |_id, timeout:|
      if desired.equal?(original)
        desired = Rubernetes::Node::Helpers.deep_copy(original)
        desired["metadata"]["generation"] = 2
        desired["spec"]["initContainers"][0]["resources"] = resized
        {"state" => "running"}
      else
        {"state" => "terminated", "exitCode" => 0}
      end
    end

    result = @lifecycle.start(original)

    assert_equal "Running", result.state
    assert_equal %w[init c1], @runtime.created
    assert_equal [["c1", resized]], @runtime.container_updates
    assert_equal 2, @reporter.statuses.last["observedGeneration"]
  end

  def test_deleted_pod_unblocks_the_worker_waiting_on_its_init
    original = pod(generation: 1, pod_resources: nil)
    original["spec"]["initContainers"] = [{"name" => "init", "image" => "i"}]
    desired = original
    waits = 0
    @lifecycle.desired_pod_lookup = ->(_uid) { desired }
    @runtime.define_singleton_method(:wait_container) do |_id, timeout:|
      waits += 1
      desired = Rubernetes::Node::Helpers.deep_copy(original)
      desired["metadata"]["deletionTimestamp"] = "2026-11-19T16:00:00Z"
      waits == 1 ? {"state" => "running"} : {"state" => "terminated", "exitCode" => 0}
    end

    result = @lifecycle.start(original)

    assert_equal "WorkloadStopped", result.state
    assert_equal ["init"], @runtime.created
    assert_equal 1, waits
  end

  def test_allocated_resources_without_pod_level_resources
    @lifecycle.start({"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-2", "generation" => 1},
                      "spec" => {"nodeName" => "node-1", "containers" => [{"name" => "a", "image" => "i", "resources" => {"requests" => {"cpu" => "100m"}}},
                                                                          {"name" => "b", "image" => "i",
                                                                           "resources" => {"requests" => {"cpu" => "200m"}}}]}})

    assert_equal({"cpu" => "300m"}, @reporter.statuses.last["allocatedResources"])
  end

  def test_cpu_resize_requires_the_exclusive_cpu_gate_under_the_static_cpu_policy
    lifecycle = agent_lifecycle("InPlacePodVerticalScalingExclusiveMemory" => true)

    assert_equal "Running", lifecycle.start(guaranteed_pod(generation: 1)).state
    lifecycle.reconcile(guaranteed_pod(generation: 2, cpu: "2"))

    assert_empty @runtime.container_updates
    assert_equal "Infeasible", conditions("PodResizePending").fetch(0)["reason"]
    assert_match(/CPU Manager policy "static"/, conditions("PodResizePending").fetch(0)["message"])
  end

  def test_memory_resize_requires_the_exclusive_memory_gate_under_the_static_memory_policy
    lifecycle = agent_lifecycle("InPlacePodVerticalScalingExclusiveCPUs" => true)

    assert_equal "Running", lifecycle.start(guaranteed_pod(generation: 1)).state
    lifecycle.reconcile(guaranteed_pod(generation: 2, memory: "512Mi"))

    assert_empty @runtime.container_updates
    assert_equal "Infeasible", conditions("PodResizePending").fetch(0)["reason"]
    assert_match(/Memory Manager policy "Static"/, conditions("PodResizePending").fetch(0)["message"])
  end

  def test_agent_exclusive_resize_gates_allow_updates_to_the_running_container
    lifecycle = agent_lifecycle("InPlacePodVerticalScalingExclusiveCPUs" => true, "InPlacePodVerticalScalingExclusiveMemory" => true)
    desired = guaranteed_pod(generation: 2, cpu: "2", memory: "512Mi")

    assert_equal "Running", lifecycle.start(guaranteed_pod(generation: 1)).state
    lifecycle.reconcile(desired)

    assert_empty conditions("PodResizePending")
    assert_equal ["c1"], @runtime.created
    assert_equal [["c1", desired.dig("spec", "containers", 0, "resources")]], @runtime.container_updates
  end

  private

  def agent_lifecycle(feature_gates)
    Rubernetes::Node::Agent.new(
      node_name: "node-1", api: Object.new, runtime: @runtime, reporter: @reporter, admission: @admission,
      container_manager: StaticPolicies.new, feature_gates: feature_gates, publish_events: false, sleeper: ->(_) {}
    ).lifecycle
  end

  def guaranteed_pod(generation:, cpu: "1", memory: "256Mi")
    quantities = {"cpu" => cpu, "memory" => memory}
    pod(generation: generation, pod_resources: nil, container_resources: {"requests" => quantities, "limits" => quantities})
  end
end
