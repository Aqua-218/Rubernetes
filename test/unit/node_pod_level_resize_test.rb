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

  def test_allocated_resources_without_pod_level_resources
    @lifecycle.start({"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-2", "generation" => 1},
                      "spec" => {"nodeName" => "node-1", "containers" => [{"name" => "a", "image" => "i", "resources" => {"requests" => {"cpu" => "100m"}}},
                                                                          {"name" => "b", "image" => "i",
                                                                           "resources" => {"requests" => {"cpu" => "200m"}}}]}})

    assert_equal({"cpu" => "300m"}, @reporter.statuses.last["allocatedResources"])
  end
end
