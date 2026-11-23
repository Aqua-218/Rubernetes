# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# The internal container lifecycle in the Pod lifecycle: PreCreateContainer
# puts the pinned cpuset.cpus/cpuset.mems into the runtime spec's explicit
# cgroup settings, PreStartContainer runs between create and start, and
# PostStopContainer runs when the container is removed.
class NodeContainerManagerLifecycleTest < Minitest::Test
  class Runtime
    attr_reader :calls, :specs

    def initialize
      @calls = []
      @specs = {}
      @counter = 0
    end

    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"

    def create_container(_sandbox, spec)
      @counter += 1
      @specs[spec["name"]] = spec
      @calls << [:create, spec["name"]]
      "c#{@counter}"
    end

    def start_container(id) = @calls << [:start, id]
    def wait_container(_id) = 0
    def container_status(id) = (@stopped ||= {}).key?(id) ? {"state" => "exited", "exit_code" => 0} : {"state" => "running"}
    def stop_container(id, timeout:) = ((@stopped ||= {})[id] = true)
    def remove_container(id) = @calls << [:remove, id]
    def remove_sandbox(_id) = true
  end

  class Manager
    attr_reader :calls

    def initialize(runtime) = (@runtime = runtime) && (@calls = [])

    def container_limits(_pod, container)
      container["name"] == "pinned" ? {"cpuset.cpus" => "2-3", "cpuset.mems" => "0"} : {}
    end

    def pre_start(pod, container, container_id)
      @runtime.calls << [:pre_start, container_id]
      @calls << [:pre_start, pod.dig("metadata", "uid"), container["name"], container_id]
    end

    def post_stop(container_id)
      @runtime.calls << [:post_stop, container_id]
    end
  end

  class Spec
    def build(container:, **) = Marshal.load(Marshal.dump(container)).merge("env" => [], "mounts" => [])
    def pod_hostname(pod) = pod.dig("metadata", "name")
  end

  def test_pinning_registration_and_release
    runtime = Runtime.new
    manager = Manager.new(runtime)
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_) {}, container_spec: Spec.new, container_manager: manager)
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "uid-p"},
           "spec" => {"restartPolicy" => "Always",
                      "containers" => [{"name" => "pinned", "image" => "x"}, {"name" => "plain", "image" => "x"}]}}
    lifecycle.start(pod)

    assert_equal({"cpuset.cpus" => "2-3", "cpuset.mems" => "0"}, runtime.specs.fetch("pinned")["limits"])
    assert_nil runtime.specs.fetch("plain")["limits"], "nothing pinned, nothing added"
    first = runtime.calls.index([:pre_start, "c1"])

    assert first && runtime.calls.index([:start, "c1"]) > first, "PreStartContainer runs before the start"
    assert_equal [[:pre_start, "uid-p", "pinned", "c1"], [:pre_start, "uid-p", "plain", "c2"]], manager.calls

    lifecycle.terminate(pod)
    removed = runtime.calls.index([:remove, "c1"])

    assert removed, "the container is removed"
    assert_operator runtime.calls.index([:post_stop, "c1"]), :<, removed, "PostStopContainer runs as it is removed"
  end

  def test_static_cpu_assignments_survive_admission_for_all_containers
    runtime = Runtime.new
    manager = static_cpu_manager
    admission = Rubernetes::Node::Admission.new(node_name: "n1", capacity: {"cpu" => "4", "memory" => "1Gi", "pods" => "10"})
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_) {}, container_spec: Spec.new,
                                                container_manager: manager, admission: admission)
    manager.start(active_pods: -> { lifecycle.admitted_pods(include_allocating: true) })
    admission.allocation_admit_handler = lambda do |value|
      result = manager.admit(value)

      assert_empty lifecycle.admitted_pods
      manager.cpu_manager.reconcile_state
      result
    end
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "uid-p"},
           "spec" => {"restartPolicy" => "Never", "containers" => [guaranteed_container("app")],
                      "initContainers" => [guaranteed_container("init"), guaranteed_container("sidecar").merge("restartPolicy" => "Always")]}}
    lifecycle.start(pod)

    cpu_pins = %w[init sidecar app].map { |name| runtime.specs.fetch(name).dig("limits", "cpuset.cpus") }

    assert_equal %w[1 1 2], cpu_pins

    lifecycle.terminate(pod)
    manager.cpu_manager.reconcile_state

    assert_empty manager.cpu_manager.state.assignments
  end

  private

  def static_cpu_manager
    cores = Array.new(4) { |id| {id: id, socket_id: 0, threads: [id], uncore_caches: []} }
    machine = {num_cores: 4, num_sockets: 1, topology: [{id: 0, cores: cores, memory: 1024**3, hugepages: [], distances: [10]}]}
    Rubernetes::Node::ContainerManager.new(
      state_directory: nil, reservation: {"cpu" => "1"},
      cpu: {"policy" => "static"}, reserved_system_cpus: "0", machine: machine
    )
  end

  def guaranteed_container(name)
    resources = {"cpu" => "1", "memory" => "100Mi"}
    {"name" => name, "image" => "x", "resources" => {"requests" => resources, "limits" => resources}}
  end
end
