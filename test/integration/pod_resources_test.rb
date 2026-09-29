# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/node/pod_resources"

# The pod resources API over its real transport: a gRPC client (as a
# monitoring agent would be) calls List, Get and GetAllocatableResources on
# <dir>/kubelet.sock served by the agent's helper.
class PodResourcesIntegrationTest < Minitest::Test
  def setup
    skip "grpc is not installed" unless Gem::Specification.find_all_by_name("grpc").any?

    require "grpc"
    require "rubernetes/node/plugins/generated/podresources_v1_services_pb"
    @dir = Dir.mktmpdir("rbn-podres-")
    pods = [{"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => {"containers" => [{"name" => "app"}]}}]
    plugins = Struct.new(:x) do
      def container_devices(_uid, _name) = {"example.com/gpu" => %w[d1]}
      def allocatable_devices = {"example.com/gpu" => %w[d1 d2]}
    end.new(nil)
    @server = Rubernetes::Node::PodResources.new(directory: @dir, pods: -> { pods }, device_plugins: plugins).start
    api = Rubernetes::Node::Plugins::Generated::PodResourcesV1
    @api = api
    @stub = api::PodResourcesLister::Stub.new("unix:#{File.join(@dir, "kubelet.sock")}", :this_channel_is_insecure)
  end

  def teardown
    @server&.stop
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_list_get_and_allocatable_over_grpc
    listed = @stub.list(@api::ListPodResourcesRequest.new)
    container = listed.pod_resources.first.containers.first
    assert_equal ["app", "example.com/gpu", ["d1"]], [container.name, container.devices.first.resource_name, container.devices.first.device_ids.to_a]
    got = @stub.get(@api::GetPodResourcesRequest.new(pod_name: "p", pod_namespace: "ns"))
    assert_equal "p", got.pod_resources.name
    error = assert_raises(GRPC::BadStatus) { @stub.get(@api::GetPodResourcesRequest.new(pod_name: "x", pod_namespace: "ns")) }
    assert_equal "pod x in namespace ns not found", error.details
    allocatable = @stub.get_allocatable_resources(@api::AllocatableResourcesRequest.new)
    assert_equal %w[d1 d2], allocatable.devices.first.device_ids.to_a
  end
end
