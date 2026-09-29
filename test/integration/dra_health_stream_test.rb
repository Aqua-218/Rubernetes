# frozen_string_literal: true

require "rbconfig"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/dra_manager"

# The DRAResourceHealth.NodeWatchResources stream end to end: a DRA driver
# (a separate Ruby process with grpc, like any real driver) streams device
# health, the helper forwards each message, a driver without the service
# answers Unimplemented and the stream is retried.
class DRAHealthStreamIntegrationTest < Minitest::Test
  LIB = File.expand_path("../../lib", __dir__)

  DRIVER = <<~'RUBY'
    require "grpc"
    $LOAD_PATH.unshift(ARGV.fetch(0))
    require "rubernetes/node/plugins/generated/dra_health_v1alpha1_services_pb"
    api = Rubernetes::Node::Plugins::Generated::DRAHealthV1alpha1
    socket = ARGV.fetch(1)
    with_health = ARGV.fetch(2) == "true"
    server = GRPC::RpcServer.new
    server.add_http2_port("unix:#{socket}", :this_port_is_insecure)
    if with_health
      health = Class.new(api::DRAResourceHealth::Service) do
        define_method(:node_watch_resources) do |_request, _call|
          Enumerator.new do |yielder|
            device = ->(name, status, message) do
              api::DeviceHealth.new(device: api::DeviceIdentifier.new(pool_name: "pool", device_name: name), health: status,
                                    last_updated_time: Time.now.to_i, health_check_timeout_seconds: 45, message: message)
            end
            yielder << api::NodeWatchResourcesResponse.new(devices: [device.call("gpu-0", :HEALTHY, "")])
            sleep 0.2
            yielder << api::NodeWatchResourcesResponse.new(devices: [device.call("gpu-0", :UNHEALTHY, "XID 79")])
            sleep 0.2
          end
        end
      end
      server.handle(health)
    else
      # A driver serving something else, but not the health service.
      require "rubernetes/node/plugins/generated/pluginregistration_v1_services_pb"
      server.handle(Class.new(Rubernetes::Node::Plugins::Generated::PluginRegistrationV1::Registration::Service))
    end
    server.run_till_terminated_or_interrupted(%w[TERM])
  RUBY

  def with_driver(health:)
    Dir.mktmpdir("dra-health") do |dir|
      socket = File.join(dir, "driver.sock")
      pid = Process.spawn(RbConfig.ruby, "-e", DRIVER, LIB, socket, health.to_s, err: File::NULL, out: File::NULL)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 60
      sleep 0.05 until File.socket?(socket) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      raise "driver never created #{socket}" unless File.socket?(socket)

      yield socket
    ensure
      if pid
        Process.kill("TERM", pid) rescue nil
        Process.wait(pid) rescue nil
      end
    end
  end

  def collect(socket, until_count:)
    events = Queue.new
    stream = Rubernetes::Node::DRAHealth::Stream.new(endpoint: socket, on_event: ->(event) { events << event }, retry_period: 0.3)
    stream.start
    seen = []
    Timeout.timeout(90) { seen << events.pop until yield(seen) || seen.length >= until_count }
    seen
  ensure
    stream&.stop
  end

  def test_devices_stream_then_end_and_restart
    with_driver(health: true) do |socket|
      seen = collect(socket, until_count: 50) { |events| events.count { |event| event["event"] == "started" } >= 2 }
      devices = seen.select { |event| event["event"] == "devices" }.map { |event| event["devices"].first }
      assert_equal %w[HEALTHY UNHEALTHY], devices.first(2).map { |device| device["health"] }
      assert_equal({"pool_name" => "pool", "device_name" => "gpu-0"}, devices.first["device"])
      assert_equal "XID 79", devices[1]["message"]
      parsed = Rubernetes::Node::DRAHealth.device_from_wire(devices[1])
      assert_equal({"pool" => "pool", "device" => "gpu-0", "health" => "Unhealthy", "timeout" => 45.0, "message" => "XID 79"}, parsed)
      assert(seen.any? { |event| event["event"] == "ended" }, "the finished stream was reported")
    end
  end

  def test_a_driver_without_the_service_answers_unimplemented
    with_driver(health: false) do |socket|
      seen = collect(socket, until_count: 10) { |events| events.any? { |event| event["event"] == "ended" } }
      ended = seen.find { |event| event["event"] == "ended" }
      assert_equal 12, ended["code"] # GRPC::Core::StatusCodes::UNIMPLEMENTED
    end
  end
end
