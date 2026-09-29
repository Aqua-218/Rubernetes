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
           "spec" => {"restartPolicy" => "Always", "containers" => [{"name" => "pinned", "image" => "x"}, {"name" => "plain", "image" => "x"}]}}
    lifecycle.start(pod)

    assert_equal({"cpuset.cpus" => "2-3", "cpuset.mems" => "0"}, runtime.specs.fetch("pinned")["limits"])
    assert_nil runtime.specs.fetch("plain")["limits"], "nothing pinned, nothing added"
    first = runtime.calls.index([:pre_start, "c1"])
    assert first && runtime.calls.index([:start, "c1"]) > first, "PreStartContainer runs before the start"
    assert_equal [[:pre_start, "uid-p", "pinned", "c1"], [:pre_start, "uid-p", "plain", "c2"]], manager.calls

    lifecycle.terminate(pod)
    removed = runtime.calls.index([:remove, "c1"])
    assert removed, "the container is removed"
    assert runtime.calls.index([:post_stop, "c1"]) < removed, "PostStopContainer runs as it is removed"
  end
end
