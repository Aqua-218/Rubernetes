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
    require "rubernetes/node/plugins/generated/podresources_v1alpha1_services_pb"
    @dir = Dir.mktmpdir("rbn-podres-")
    pods = [{"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"},
             "spec" => {"initContainers" => [{"name" => "once"}, {"name" => "sidecar", "restartPolicy" => "Always"}],
                        "containers" => [{"name" => "app"}]}}]
    plugins = Struct.new(:x) do
      def container_devices(_uid, name) = {"example.com/gpu" => [name == "sidecar" ? "d2" : "d1"]}
      def allocatable_devices = {"example.com/gpu" => %w[d1 d2]}
    end.new(nil)
    @server = Rubernetes::Node::PodResources.new(directory: @dir, pods: -> { pods }, device_plugins: plugins).start
    @api = Rubernetes::Node::Plugins::Generated::PodResourcesV1
    @endpoint = "unix:#{File.join(@dir, "kubelet.sock")}"
    @stub = @api::PodResourcesLister::Stub.new(@endpoint, :this_channel_is_insecure)
  end

  def teardown
    @server&.stop
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_list_get_and_allocatable_over_grpc
    listed = @stub.list(@api::ListPodResourcesRequest.new)
    containers = listed.pod_resources.first.containers

    assert_equal %w[sidecar app], containers.map(&:name)
    container = containers.last

    assert_equal ["app", "example.com/gpu", ["d1"]],
                 [container.name, container.devices.first.resource_name, container.devices.first.device_ids.to_a]
    got = @stub.get(@api::GetPodResourcesRequest.new(pod_name: "p", pod_namespace: "ns"))

    assert_equal "p", got.pod_resources.name
    error = assert_raises(GRPC::BadStatus) { @stub.get(@api::GetPodResourcesRequest.new(pod_name: "x", pod_namespace: "ns")) }
    assert_equal "pod x in namespace ns not found", error.details
    allocatable = @stub.get_allocatable_resources(@api::AllocatableResourcesRequest.new)

    assert_equal %w[d1 d2], allocatable.devices.first.device_ids.to_a
  end

  def test_v1alpha1_lists_only_application_containers_and_devices
    require "rubernetes/observability/metrics"
    metrics = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kubelet")
    @server.metrics = metrics
    api = Rubernetes::Node::Plugins::Generated::PodResourcesV1alpha1
    stub = api::PodResourcesLister::Stub.new(@endpoint, :this_channel_is_insecure)
    listed = stub.list(api::ListPodResourcesRequest.new)
    resources = listed.pod_resources.first

    assert_equal %w[p ns], [resources.name, resources.namespace]
    assert_equal %w[app], resources.containers.map(&:name)
    device = resources.containers.first.devices.first

    assert_equal ["example.com/gpu", ["d1"]], [device.resource_name, device.device_ids.to_a]
    assert_includes metrics.render, %(kubelet_pod_resources_endpoint_requests_total{server_api_version="v1alpha1"} 1)
  end
end
