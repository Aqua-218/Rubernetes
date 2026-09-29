# frozen_string_literal: true

require "rbconfig"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"

# The device plugin gRPC API end to end: the broker's helper serves
# v1beta1.Registration on kubelet.sock, a device plugin (a separate Ruby
# process with grpc, like any real plugin) registers, the manager follows its
# ListAndWatch stream and Allocates devices through it; a plugin with an
# unsupported API version is refused with kubelet's message.
class DevicePluginsIntegrationTest < Minitest::Test
  DP = Rubernetes::Node::DevicePlugins
  LIB = File.expand_path("../../lib", __dir__)

  PLUGIN = <<~'RUBY'
    require "grpc"
    $LOAD_PATH.unshift(ARGV.fetch(0))
    require "rubernetes/node/plugins/generated/deviceplugin_v1beta1_services_pb"
    api = Rubernetes::Node::Plugins::Generated::DevicePluginV1beta1
    dir = ARGV.fetch(1)
    version = ARGV.fetch(2)
    health = ["Healthy", "Healthy"]
    updates = Queue.new
    plugin = Class.new(api::DevicePlugin::Service) do
      define_method(:get_device_plugin_options) { |_req, _call| api::DevicePluginOptions.new(pre_start_required: false) }
      define_method(:list_and_watch) do |_req, _call|
        Enumerator.new do |yielder|
          loop do
            yielder << api::ListAndWatchResponse.new(devices: health.each_with_index.map { |h, i| api::Device.new(ID: "dev#{i}", health: h) })
            updates.pop
          end
        end
      end
      define_method(:allocate) do |request, _call|
        ids = request.container_requests.first.devices_ids.to_a
        api::AllocateResponse.new(container_responses: [api::ContainerAllocateResponse.new(envs: {"FAKE_DEVICES" => ids.join(",")})])
      end
    end
    server = GRPC::RpcServer.new
    server.add_http2_port("unix:#{File.join(dir, "fake.sock")}", :this_port_is_insecure)
    server.handle(plugin.new)
    Thread.new { server.run }
    server.wait_till_running(10)
    registration = api::Registration::Stub.new("unix:#{File.join(dir, "kubelet.sock")}", :this_channel_is_insecure)
    begin
      registration.register(api::RegisterRequest.new(version: version, endpoint: "fake.sock", resource_name: "example.com/fake"))
      puts "registered"
    rescue GRPC::BadStatus => error
      puts "refused: #{error.details}"
    end
    $stdout.flush
    while (line = $stdin.gets)
      health[1] = "Unhealthy" if line.strip == "unhealthy"
      updates << true
    end
  RUBY

  def setup
    skip "grpc is not installed" unless Gem::Specification.find_all_by_name("grpc").any?

    @dir = Dir.mktmpdir("rbn-dpi-")
    @events = Queue.new
    @manager = DP::Manager.new(directory: @dir, on_change: -> { @events << :changed })
    @manager.start
  end

  def teardown
    @plugin_in&.close rescue nil
    Process.kill(:KILL, @plugin) rescue nil if @plugin
    Process.wait(@plugin) rescue nil if @plugin
    @manager&.stop
    FileUtils.rm_rf(@dir) if @dir
  end

  def start_plugin(version)
    reader, writer = IO.pipe
    plugin_in, @plugin_in = IO.pipe
    @plugin = Process.spawn(RbConfig.ruby, "-e", PLUGIN, LIB, @dir, version, in: plugin_in, out: writer, err: File::NULL)
    plugin_in.close
    writer.close
    Timeout.timeout(30) { reader.gets.to_s.strip }
  end

  def wait_for(timeout: 20)
    Timeout.timeout(timeout) { sleep 0.05 until yield }
  end

  def test_a_plugin_registers_advertises_and_allocates
    assert_equal "registered", start_plugin("v1beta1")
    wait_for { @manager.capacity.first["example.com/fake"] == 2 }
    assert_equal [{"example.com/fake" => 2}, {"example.com/fake" => 2}], @manager.capacity
    pod = {"metadata" => {"uid" => "u1"}, "spec" => {"containers" => [{"name" => "c", "resources" => {"limits" => {"example.com/fake" => "1"}}}]}}
    @manager.allocate_pod(pod)
    assert_equal({"FAKE_DEVICES" => "dev0"}, @manager.container_allocation("u1", "c")["envs"])
    @plugin_in.puts("unhealthy")
    wait_for { @manager.capacity.last["example.com/fake"] == 1 }
    Process.kill(:KILL, @plugin)
    Process.wait(@plugin)
    @plugin = nil
    wait_for { @manager.capacity.last["example.com/fake"].zero? }
    assert_equal "Unhealthy", @manager.allocated_resources_status("u1", "c").first["resources"].first["health"]
  end

  def test_an_unsupported_api_version_is_refused
    assert_equal %(refused: requested API version "v1alpha" is not supported by kubelet. Supported version is ["v1beta1"]), start_plugin("v1alpha")
    assert_equal [{}, {}], @manager.capacity
  end
end
