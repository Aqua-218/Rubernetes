# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/observability/metrics"
require "rubernetes/node"

# pkg/kubelet/cm/devicemanager: registration events, capacity/allocatable,
# devicesToAllocate, Allocate responses, health (ResourceHealthStatus) and the
# checkpoint -- against a fake broker (the gRPC side is covered by
# test/integration/device_plugins_test.rb).
class DevicePluginsManagerTest < Minitest::Test
  DP = Rubernetes::Node::DevicePlugins

  class FakeBroker
    attr_reader :calls
    attr_accessor :preferred

    def initialize = (@calls = []) && (@preferred = nil)
    def start = self
    def stop = self

    def call(endpoint, method, request = {}, **)
      @calls << [endpoint, method, request]
      case method
      when "Allocate"
        ids = request["container_requests"].first["devices_ids"]
        {"container_responses" => [{"envs" => {"GPUS" => ids.sort.join(",")},
                                    "devices" => [{"container_path" => "/dev/fake0", "host_path" => "/dev/null", "permissions" => "rw"}],
                                    "mounts" => [], "annotations" => {}, "cdi_devices" => []}]}
      when "GetPreferredAllocation" then {"container_responses" => [{"deviceIDs" => @preferred}]}
      else {}
      end
    end
  end

  def setup
    @dir = Dir.mktmpdir("rbn-dp-")
    @now = 1000.0
    @broker = FakeBroker.new
    @changes = 0
    @manager = DP::Manager.new(directory: @dir, broker: @broker, on_change: -> { @changes += 1 }, clock: -> { @now })
  end

  def teardown = FileUtils.rm_rf(@dir)

  def register(options = {})
    @manager.handle_event("event" => "registered", "resource" => "example.com/gpu", "endpoint" => "gpu.sock", "options" => options)
    @manager.handle_event("event" => "devices", "resource" => "example.com/gpu",
                          "devices" => [{"ID" => "d1", "health" => "Healthy"}, {"ID" => "d2", "health" => "Healthy"},
                                        {"ID" => "d3", "health" => "Unhealthy"}])
  end

  def pod(uid, containers, init: [])
    {"metadata" => {"uid" => uid, "name" => uid, "namespace" => "ns"},
     "spec" => {"initContainers" => init, "containers" => containers}}
  end

  def container(name, count, restart: nil)
    entry = {"name" => name, "resources" => {"limits" => {"example.com/gpu" => count.to_s}}}
    entry["restartPolicy"] = restart if restart
    entry
  end

  # DevicePluginRegistrationCount and DevicePluginAllocationDuration.
  def test_registration_and_allocation_metrics
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kubelet")
    @manager.metrics = registry
    @manager.handle_event("event" => "register_request", "resource" => "example.com/gpu")
    register
    @manager.allocate_pod(pod("u1", [container("app", 1)]))
    text = registry.render
    assert_includes text, %(kubelet_device_plugin_registration_total{resource_name="example.com/gpu"} 1)
    assert_includes text, %(kubelet_device_plugin_alloc_duration_seconds_count{resource_name="example.com/gpu"} 1)
  end

  def test_capacity_counts_every_device_and_allocatable_the_healthy_ones
    register
    assert_equal [{"example.com/gpu" => 3}, {"example.com/gpu" => 2}], @manager.capacity
    assert_equal 2, @changes
  end

  def test_allocation_applies_the_plugin_response_and_reports_health
    register("pre_start_required" => true)
    @manager.allocate_pod(pod("u1", [container("app", 2)]))
    allocation = @manager.container_allocation("u1", "app")
    assert_equal({"GPUS" => "d1,d2"}, allocation["envs"])
    assert_equal "/dev/fake0", allocation["devices"].first["container_path"]
    assert_equal %w[PreStartContainer Allocate], @broker.calls.map { |call| call[1] }
    assert_equal [{"name" => "example.com/gpu", "resources" => [{"resourceID" => "d1", "health" => "Healthy"},
                                                                  {"resourceID" => "d2", "health" => "Healthy"}]}],
                 @manager.allocated_resources_status("u1", "app")
    @manager.handle_event("event" => "devices", "resource" => "example.com/gpu",
                          "devices" => [{"ID" => "d1", "health" => "Unhealthy"}, {"ID" => "d2", "health" => "Healthy"}])
    assert_equal "Unhealthy", @manager.allocated_resources_status("u1", "app").first["resources"].first["health"]
  end

  def test_requests_beyond_the_healthy_free_devices_fail_with_upstreams_message
    register
    @manager.allocate_pod(pod("u1", [container("app", 1)]))
    error = assert_raises(DP::Manager::Error) { @manager.allocate_pod(pod("u2", [container("app", 2)])) }
    assert_equal "requested number of devices unavailable for example.com/gpu. Requested: 2, Available: 1", error.message
    @manager.remove_stale(%w[u2])
    @manager.allocate_pod(pod("u2", [container("app", 2)]))
    assert_equal 2, @manager.container_allocation("u2", "app")["envs"]["GPUS"].split(",").length
  end

  def test_init_container_devices_are_reused_and_preferred_allocation_is_asked
    register("get_preferred_allocation_available" => true)
    @broker.preferred = %w[d2]
    @manager.allocate_pod(pod("u1", [container("app", 1)], init: [container("init", 1)]))
    assert_equal "d2", @manager.container_allocation("u1", "init")["envs"]["GPUS"]
    assert_equal "d2", @manager.container_allocation("u1", "app")["envs"]["GPUS"], "the init container's device goes to the app container"
  end

  def test_a_stopped_plugin_goes_unhealthy_then_away_and_allocations_survive_a_restart
    register
    @manager.allocate_pod(pod("u1", [container("app", 1)]))
    @manager.handle_event("event" => "disconnected", "resource" => "example.com/gpu")
    assert_equal [{"example.com/gpu" => 3}, {"example.com/gpu" => 0}], @manager.capacity
    restarted = DP::Manager.new(directory: @dir, broker: FakeBroker.new, clock: -> { @now })
    assert_equal "d1", restarted.container_allocation("u1", "app")["envs"]["GPUS"], "kubelet_internal_checkpoint"
    @now += DP::Manager::STOP_GRACE_PERIOD + 1
    assert_equal [{}, {}], @manager.capacity
    error = assert_raises(DP::Manager::Error) { restarted.allocate_pod(pod("u9", [container("app", 1)])) }
    assert_match(/no healthy devices present|cannot allocate unregistered device/, error.message)
  end
end
