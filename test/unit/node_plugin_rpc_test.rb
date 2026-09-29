# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/plugins/rpc"
require "tmpdir"
require_relative "../support/grpc_fake_server"

# Plugin gRPC calls from a forked helper, against a real gRPC server in a
# separate process (grpc is never loaded into the calling process).  The
# server is a spawned interpreter (GRPCFakeServer), never a fork.
class NodePluginRPCTest < Minitest::Test
  RPC = Rubernetes::Node::Plugins::RPC

  # Serves pluginregistration.Registration and the DRA v1 service on
  # +socket+ in a child process; returns its pid.
  def self.serve(socket, info:, prepare: nil, record: nil)
    requires = [File.join(RPC::GENERATED, "pluginregistration_v1_services_pb"), File.join(RPC::GENERATED, "dra_v1_services_pb")]
    params = {"info" => info, "prepare" => prepare&.to_s, "record" => record}
    GRPCFakeServer.spawn(socket, <<~RUBY, params: params, requires: requires)
      generated = Rubernetes::Node::Plugins::Generated
      info = PARAMS.fetch("info").transform_keys(&:to_sym)
      record = PARAMS["record"]
      registration = Class.new(generated::PluginRegistrationV1::Registration::Service) do
        define_method(:get_info) { |_request, _call| generated::PluginRegistrationV1::PluginInfo.new(**info) }
        define_method(:notify_registration_status) do |request, _call|
          File.write(record, JSON.generate("registered" => request.plugin_registered, "error" => request.error)) if record
          generated::PluginRegistrationV1::RegistrationStatusResponse.new
        end
      end
      dra = Class.new(generated::DRAV1::DRAPlugin::Service) do
        define_method(:node_prepare_resources) do |request, _call|
          raise GRPC::Unavailable, "driver is busy" if PARAMS["prepare"] == "unavailable"

          claims = request.claims.to_h do |claim|
            [claim.uid, generated::DRAV1::NodePrepareResourceResponse.new(
              devices: [generated::DRAV1::Device.new(request_names: ["gpu"], pool_name: "pool", device_name: "gpu-0",
                                                     cdi_device_ids: ["example.com/gpu=gpu-0"])]
            )]
          end
          generated::DRAV1::NodePrepareResourcesResponse.new(claims: claims)
        end
      end
      server.handle(registration)
      server.handle(dra)
    RUBY
  end

  def with_server(**options)
    Dir.mktmpdir("plugin-rpc") do |dir|
      socket = File.join(dir, "plugin.sock")
      pid = self.class.serve(socket, **options)
      yield socket, dir
    ensure
      GRPCFakeServer.stop(pid)
    end
  end

  def test_registration_and_dra_calls_round_trip
    preloaded = defined?(::GRPC::Core)
    info = {type: "DRAPlugin", name: "gpu.example.com", endpoint: "/plugins/gpu/dra.sock", supported_versions: ["v1.DRAPlugin"]}
    with_server(info: info) do |socket, dir|
      got = RPC.call(socket: socket, service: "pluginregistration.Registration", method: "GetInfo")
      assert_equal({"type" => "DRAPlugin", "name" => "gpu.example.com", "endpoint" => "/plugins/gpu/dra.sock",
                    "supported_versions" => ["v1.DRAPlugin"]}, got)

      prepared = RPC.call(socket: socket, service: "k8s.io.kubelet.pkg.apis.dra.v1.DRAPlugin", method: "NodePrepareResources",
                          request: {"claims" => [{"namespace" => "ns", "uid" => "claim-uid", "name" => "claim"}]})
      device = prepared.dig("claims", "claim-uid", "devices", 0)
      assert_equal ["example.com/gpu=gpu-0"], device["cdi_device_ids"]
      assert_equal "gpu-0", device["device_name"]
      refute defined?(::GRPC), "grpc stays out of the calling process" unless preloaded
      _ = dir
    end
  end

  def test_grpc_errors_carry_their_code
    with_server(info: {type: "DRAPlugin", name: "x"}, prepare: :unavailable) do |socket, _dir|
      error = assert_raises(RPC::Error) do
        RPC.call(socket: socket, service: "k8s.io.kubelet.pkg.apis.dra.v1.DRAPlugin", method: "NodePrepareResources",
                 request: {"claims" => []})
      end
      assert_equal 14, error.code
      assert_includes error.message, "driver is busy"
    end
  end

  def test_a_missing_socket_fails_within_the_timeout
    error = assert_raises(RPC::Error) do
      RPC.call(socket: "/nonexistent/plugin.sock", service: "pluginregistration.Registration", method: "GetInfo", timeout: 1)
    end
    refute_nil error.message
  end
end
