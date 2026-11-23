# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "tmpdir"

# DRA in the Pod lifecycle: claims are prepared before the sandbox exists
# (kuberuntime SyncPod), a failure is FailedPrepareDynamicResources and the
# Pod stays ContainerCreating, CDI devices reach only the containers that name
# the claim, and the claims are unprepared once the containers are gone.
class NodeDRALifecycleTest < Minitest::Test
  class Runtime
    attr_reader :calls, :specs

    def initialize
      @calls = []
      @specs = {}
      @counter = 0
    end

    def run_sandbox(_pod, runtime_class: nil)
      @calls << :sandbox
      "sandbox-1"
    end

    def create_container(_sandbox, spec)
      @counter += 1
      id = "c#{@counter}"
      @specs[spec["name"]] = spec
      @calls << [:create, spec["name"]]
      id
    end

    def start_container(_id) = true
    def container_status(id) = (@stopped ||= {}).key?(id) ? {"state" => "exited", "exit_code" => 0} : {"state" => "running"}
    def stop_container(id, timeout:) = ((@stopped ||= {})[id] = true)
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
  end

  class DRA
    attr_reader :calls
    attr_accessor :fail_prepare

    def initialize(runtime) = (@runtime = runtime) && (@calls = [])

    def prepare_resources(pod)
      @runtime.calls << :prepare
      raise Rubernetes::Node::DRAManager::Error, "DRA driver gpu.example.com is not registered" if fail_prepare

      @calls << [:prepare, pod.dig("metadata", "name")]
      true
    end

    def container_cdi_devices(_pod, container)
      Array(container.dig("resources", "claims")).empty? ? [] : ["example.com/gpu=gpu-0"]
    end

    def unprepare_resources(pod)
      @calls << [:unprepare, pod.dig("metadata", "name")]
      true
    end

    # ResourceHealthStatus: no device health to report.
    def allocated_resources_status(_pod, _container) = []
  end

  class Sink
    attr_reader :events

    def initialize = @events = []
    def record(**event) = @events << event
    def call(event) = @events << event
  end

  def setup
    @dir = Dir.mktmpdir("dra-lifecycle")
    FileUtils.mkdir_p(File.join(@dir, "cdi"))
    File.write(File.join(@dir, "cdi", "gpu.json"), JSON.generate(
      "cdiVersion" => "0.6.0", "kind" => "example.com/gpu",
      "devices" => [{"name" => "gpu-0", "containerEdits" => {"env" => ["GPU=gpu-0"], "mounts" => [
        {"hostPath" => @dir, "containerPath" => "/opt/gpu", "options" => %w[ro bind]}
      ]}}],
      "containerEdits" => {"env" => ["VENDOR=example"]}
    ))
    @runtime = Runtime.new
    @dra = DRA.new(@runtime)
    spec = Rubernetes::Node::ContainerSpec.new(swap_controller: false)
    @lifecycle = Rubernetes::Node::Lifecycle.new(runtime: @runtime, sleeper: ->(_) {}, container_spec: spec, dra_manager: @dra,
                                                 cdi_spec_dirs: [File.join(@dir, "cdi")])
  end

  def teardown = FileUtils.rm_rf(@dir)

  def pod
    {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "uid-p"},
     "spec" => {"restartPolicy" => "Always", "resourceClaims" => [{"name" => "g", "resourceClaimName" => "c1"}],
                "containers" => [{"name" => "app", "image" => "x", "resources" => {"claims" => [{"name" => "g"}]}},
                                 {"name" => "plain", "image" => "x"}]}}
  end

  def test_claims_are_prepared_before_the_sandbox_and_cdi_reaches_the_container
    @lifecycle.start(pod)

    assert_equal :prepare, @runtime.calls.first
    assert_equal :sandbox, @runtime.calls[1], "prepared before the sandbox"
    app = @runtime.specs.fetch("app")
    app_environment = app.fetch("env").last(3).map { |entry| entry.values_at("name", "value") }
    plain_environment = @runtime.specs.fetch("plain").fetch("env").map { |entry| entry.fetch("name") }

    assert_equal [["VENDOR", "example"], ["GPU", "gpu-0"], ["HOME", "/"]], app_environment
    assert_equal [{"name" => "cdi-mount-0", "source" => @dir, "destination" => "/opt/gpu", "readonly" => true, "propagation" => "None"}],
                 app["mounts"]
    assert_equal %w[HOSTNAME HOME], plain_environment

    @lifecycle.terminate(pod)

    assert_equal [[:prepare, "p"], [:unprepare, "p"]], @dra.calls
  end

  def test_a_cdi_home_keeps_its_value_and_order_in_the_final_environment
    cdi_path = File.join(@dir, "cdi", "gpu.json")
    device = JSON.parse(File.read(cdi_path))
    device.fetch("devices").first.fetch("containerEdits").fetch("env").push("HOME=/from-cdi", "MARKER=last")
    File.write(cdi_path, JSON.generate(device))
    workload = pod
    workload.dig("spec", "containers", 0)["env"] = [{"name" => "HOME", "value" => "/from-pod"}]
    @lifecycle.start(workload)

    env = @runtime.specs.fetch("app").fetch("env").map { |entry| entry.values_at("name", "value") }

    assert_equal [["HOME", "/from-cdi"], ["MARKER", "last"]], env.last(2)
    assert_equal(1, env.count { |name, _value| name == "HOME" })
  end

  def test_a_preparation_failure_keeps_the_pod_creating_and_is_reported
    @dra.fail_prepare = true
    result = @lifecycle.start(pod)

    refute_includes @runtime.calls, :sandbox
    record = @lifecycle.send(:record, "uid-p")

    assert_equal "Pending", record[:phase]
    assert_equal "ContainerCreating", record[:reason]
    failure = record[:events].find { |event| event["type"] == "pod.dra_prepare_failed" }

    assert_equal "Failed to prepare dynamic resources: DRA driver gpu.example.com is not registered", failure["message"]
    refute record[:events].any? { |event| event["type"] == "pod.failed" }, "no second, generic Failed event"
    _ = result
  end

  def test_an_unresolvable_cdi_device_fails_the_container
    File.delete(File.join(@dir, "cdi", "gpu.json"))
    @lifecycle.start(pod)
    record = @lifecycle.send(:record, "uid-p")

    assert_equal "CreateContainerError", record[:reason]
    assert_includes record[:error], "CDI device injection failed: unresolvable CDI devices example.com/gpu=gpu-0"
  end
end
