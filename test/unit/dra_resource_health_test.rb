# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/dra_manager"

# ResourceHealthStatus for DRA (pkg/kubelet/cm/dra, v1.36.2): the health
# cache and its checkpoint, the stream handler that finds affected Pods, and
# UpdateAllocatedResourcesStatus.
class DRAResourceHealthTest < Minitest::Test
  DRIVER = "gpu.example.com"
  Health = Rubernetes::Node::DRAHealth

  # NodePrepareResources answers two devices per claim.
  class FakeRPC
    def self.call(socket:, service:, method:, request:, timeout:)
      return {"claims" => {}} unless method == "NodePrepareResources"

      {"claims" => request["claims"].to_h do |claim|
        [claim["uid"], {"devices" => [
          {"pool_name" => "pool", "device_name" => "gpu-0", "request_names" => ["gpu"], "cdi_device_ids" => ["#{DRIVER}/gpu=gpu-0"]},
          {"pool_name" => "pool", "device_name" => "nic-0", "request_names" => ["nic"], "cdi_device_ids" => []}
        ]}]
      end}
    end
  end

  class Client
    def get(_resource, name, namespace:, api_version:)
      {"metadata" => {"name" => name, "namespace" => namespace, "uid" => "uid-#{name}"},
       "status" => {"allocation" => {"devices" => {"results" => [{"request" => "gpu", "driver" => DRIVER, "pool" => "pool", "device" => "gpu-0"}]}},
                    "reservedFor" => [{"resource" => "pods", "name" => "p", "uid" => "pod-uid"}]}}
    end
  end

  # Records start/stop instead of spawning a helper.
  class FakeStream
    attr_reader :endpoint, :on_event, :started, :stopped

    def initialize(endpoint, on_event)
      (@endpoint = endpoint
       @on_event = on_event)
    end

    def start = (@started = true) && self
    def stop = (@stopped = true) && self
  end

  def pod
    {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-uid"},
     "spec" => {"resourceClaims" => [{"name" => "g", "resourceClaimName" => "c1"}],
                "containers" => [{"name" => "app", "resources" => {"claims" => [{"name" => "g", "request" => "gpu"}]}},
                                 {"name" => "all", "resources" => {"claims" => [{"name" => "g"}]}},
                                 {"name" => "plain"}]}}
  end

  def manager(dir, now: -> { @now })
    @streams = []
    changes = @changes = []
    dra = Rubernetes::Node::DRAManager.new(client: Client.new, node_name: "node-1", state_directory: dir, rpc: FakeRPC,
                                           resource_health: true, on_health_change: ->(uids) { changes << uids },
                                           health_stream: lambda { |endpoint, on_event|
                                             FakeStream.new(endpoint, on_event).tap do |s|
                                               @streams << s
                                             end
                                           },
                                           health_clock: now)
    dra.register_plugin(DRIVER, "/plugins/gpu.sock", ["v1.DRAPlugin"])
    dra
  end

  def report(stream, *devices)
    stream.on_event.call({"event" => "devices", "devices" => devices.map do |pool, device, health, message = "", timeout = "0"|
      {"device" => {"pool_name" => pool, "device_name" => device}, "health" => health, "last_updated_time" => "0",
       "health_check_timeout_seconds" => timeout, "message" => message}
    end})
  end

  def setup
    @now = Time.utc(2026, 9, 24, 12, 0, 0)
  end

  def test_registration_starts_a_stream_and_deregistration_stops_it
    Dir.mktmpdir do |dir|
      dra = manager(dir)
      stream = @streams.first

      assert stream.started
      assert_equal "/plugins/gpu.sock", stream.endpoint
      dra.deregister_plugin(DRIVER, "/plugins/gpu.sock")

      assert stream.stopped
    end
  end

  def test_status_reports_health_per_claim_request_with_message
    Dir.mktmpdir do |dir|
      dra = manager(dir)
      dra.prepare_resources(pod)
      app, all, plain = pod["spec"]["containers"]
      # Never reported: Unknown.
      assert_equal [{"name" => "claim:g/gpu", "resources" => [{"resourceID" => "#{DRIVER}/gpu=gpu-0", "health" => "Unknown"}]}],
                   dra.allocated_resources_status(pod, app)
      assert_equal [], dra.allocated_resources_status(pod, plain)

      affected = report(@streams.first, ["pool", "gpu-0", "UNHEALTHY", "ECC errors"], %w[pool nic-0 HEALTHY])

      assert_equal ["pod-uid"], affected
      assert_equal [["pod-uid"]], @changes
      assert_equal [{"name" => "claim:g/gpu", "resources" => [{"resourceID" => "#{DRIVER}/gpu=gpu-0", "health" => "Unhealthy",
                                                               "message" => "ECC errors"}]}],
                   dra.allocated_resources_status(pod, app)
      # No request: every device of the claim; no CDI ID: driver/pool/device.
      assert_equal [{"name" => "claim:g", "resources" => [
        {"resourceID" => "#{DRIVER}/gpu=gpu-0", "health" => "Unhealthy", "message" => "ECC errors"},
        {"resourceID" => "#{DRIVER}/pool/nic-0", "health" => "Healthy"}
      ]}], dra.allocated_resources_status(pod, all)
      # The same report again changes nothing.
      assert_equal [], report(@streams.first, ["pool", "gpu-0", "UNHEALTHY", "ECC errors"], %w[pool nic-0 HEALTHY])
    end
  end

  def test_health_goes_unknown_after_the_timeout_and_when_the_stream_ends
    Dir.mktmpdir do |dir|
      dra = manager(dir)
      report(@streams.first, ["pool", "gpu-0", "HEALTHY", "", "10"])

      assert_equal "Healthy", dra.health.get(DRIVER, "pool", "gpu-0")["health"]
      @now += 11

      assert_equal "Unknown", dra.health.get(DRIVER, "pool", "gpu-0")["health"]
      @now -= 11
      @streams.first.on_event.call({"event" => "ended"})

      assert_equal "Unknown", dra.health.get(DRIVER, "pool", "gpu-0")["health"]
    end
  end

  def test_unreported_stale_devices_turn_unknown_on_the_next_update
    Dir.mktmpdir do |dir|
      cache = Health::Cache.new(path: File.join(dir, "state"), clock: -> { @now })
      cache.update(DRIVER, [Health.device_from_wire({"device" => {"pool_name" => "p", "device_name" => "a"}, "health" => "HEALTHY"})])
      @now += 31
      changed = cache.update(DRIVER,
                             [Health.device_from_wire({"device" => {"pool_name" => "p", "device_name" => "b"}, "health" => "HEALTHY"})])

      assert_equal(%w[b a], changed.map { |device| device["device"] })
      assert_equal "Unknown", changed.last["health"]
    end
  end

  def test_checkpoint_uses_the_kubelet_layout_and_survives_a_restart
    Dir.mktmpdir do |dir|
      path = File.join(dir, Health::CHECKPOINT)
      cache = Health::Cache.new(path: path, clock: -> { @now })
      cache.update(DRIVER, [Health.device_from_wire({"device" => {"pool_name" => "p", "device_name" => "a"}, "health" => "UNHEALTHY",
                                                     "health_check_timeout_seconds" => "60", "message" => "x" * 2000})])
      document = JSON.parse(File.read(path))
      device = document.dig(DRIVER, "Devices", "p/a")

      assert_equal %w[DeviceName Health HealthCheckTimeout LastUpdated Message PoolName], device.keys.sort
      assert_equal 60_000_000_000, device["HealthCheckTimeout"]
      assert_equal 1024, device["Message"].length
      assert device["Message"].end_with?("...")
      restored = Health::Cache.new(path: path, clock: -> { @now + 30 })

      assert_equal "Unhealthy", restored.get(DRIVER, "p", "a")["health"]
      cache.clear(DRIVER)

      assert_equal({}, JSON.parse(File.read(path)))
    end
  end

  def test_disabled_health_starts_no_stream
    Dir.mktmpdir do |dir|
      started = []
      dra = Rubernetes::Node::DRAManager.new(client: Client.new, node_name: "n", state_directory: dir, rpc: FakeRPC,
                                             health_stream: ->(*args) { started << args })
      dra.register_plugin(DRIVER, "/x.sock", ["v1.DRAPlugin"])

      assert_empty started
    end
  end
end
