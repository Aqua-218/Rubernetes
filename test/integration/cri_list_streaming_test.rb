# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/cri"
require "rubernetes/runtime/cri/generated/cri_runtime_v1_services_pb"
require "rubernetes/node/stats_provider"
require "rubernetes/node/agent"
require "rubernetes/node/streaming_server"
require "rubernetes/api/request"
require "rubernetes/runtime/multiplexer"

class CRIListStreamingTest < Minitest::Test
  CRI = Rubernetes::Runtime::CRI
  Wire = CRI::Generated::RuntimeV1

  class RuntimeService < Wire::RuntimeService::Service
    attr_reader :calls
    attr_accessor :stats_mode

    def initialize = @calls = Queue.new

    def stream_pod_sandboxes(request, _call)
      id = request.filter.id
      @calls << [:stream_pod_sandboxes, id]
      %w[a b].map { |suffix| Wire::StreamPodSandboxesResponse.new(pod_sandboxes: [{id: "#{id}-#{suffix}"}]) }
    end

    def stream_containers(request, _call)
      @calls << [:stream_containers, request.filter.id]
      raise GRPC::Unimplemented, "unary runtime"
    end

    def list_containers(request, _call)
      @calls << [:list_containers, request.filter.id]
      return Wire::ListContainersResponse.new(containers: [{id: "container", pod_sandbox_id: "sandbox"}]) if stats_mode == :unimplemented

      Wire::ListContainersResponse.new(containers: [{id: request.filter.id}])
    end

    def list_pod_sandbox(request, _call)
      id = request.filter.id
      @calls << [:list_pod_sandbox, id]
      Wire::ListPodSandboxResponse.new(items: [{id: id}])
    end

    def stream_pod_sandbox_stats(_request, _call)
      cpu = {timestamp: 123_000_000_000, usage_core_nano_seconds: {value: 456}, usage_nano_cores: {value: 12}}
      memory = {timestamp: 124_000_000_000, working_set_bytes: {value: 789}}
      container = {attributes: {id: "container", metadata: {name: "app"}}, cpu: cpu, memory: memory}
      [Wire::StreamPodSandboxStatsResponse.new(pod_sandbox_stats: [
                                                 {attributes: {id: "sandbox"}, linux: {cpu: cpu, memory: memory, containers: [container]}}
                                               ])]
    end

    def list_pod_sandbox_stats(_request, _call)
      raise GRPC::Unimplemented if stats_mode == :unimplemented
      raise GRPC::Unavailable if stats_mode == :unavailable

      memory = {timestamp: 124_000_000_000, working_set_bytes: {value: 789}}
      container = {attributes: {id: "container", metadata: {name: "app"}}}
      Wire::ListPodSandboxStatsResponse.new(stats: [{attributes: {id: "sandbox"}, linux: {memory: memory, containers: [container]}}])
    end

    def list_container_stats(_request, _call)
      rootfs = {timestamp: 125_000_000_000, used_bytes: {value: 49_152}, inodes_used: {value: 3}}
      cpu = {timestamp: 123_000_000_000, usage_core_nano_seconds: {value: 456}}
      container = {attributes: {id: "container", metadata: {name: "app"}}, cpu: cpu, writable_layer: rootfs}
      Wire::ListContainerStatsResponse.new(stats: [container])
    end

    def list_metric_descriptors(_request, _call)
      Wire::ListMetricDescriptorsResponse.new(descriptors: [{name: "test_cri_cpu", help: "CPU from CRI", label_keys: ["pod"]}])
    end

    def stream_pod_sandbox_metrics(_request, _call)
      metric = {name: "test_cri_cpu", metric_type: :GAUGE, label_values: ["demo"], value: {value: 42}}
      [Wire::StreamPodSandboxMetricsResponse.new(pod_sandbox_metrics: [{pod_sandbox_id: "sandbox", metrics: [metric]}])]
    end
  end

  class ImageService < Wire::ImageService::Service
    attr_reader :calls
    attr_accessor :filesystems

    def initialize = @calls = Queue.new

    def stream_images(_request, _call)
      @calls << :stream_images
      [Wire::StreamImagesResponse.new(images: [{id: "image"}])]
    end

    def list_images(_request, _call)
      @calls << :list_images
      Wire::ListImagesResponse.new
    end

    def image_fs_info(_request, _call)
      @calls << :image_fs_info
      raise GRPC::Unimplemented unless @filesystems

      Wire::ImageFsInfoResponse.new(**@filesystems)
    end
  end

  def setup
    @root = Dir.mktmpdir("cri-list-streaming")
    @endpoint = File.join(@root, "cri.sock")
    @runtime = RuntimeService.new
    @image = ImageService.new
    @server = GRPC::RpcServer.new
    @server.add_http2_port("unix:#{@endpoint}", :this_port_is_insecure)
    @server.handle(@runtime)
    @server.handle(@image)
    @thread = Thread.new { @server.run }

    raise "CRI gRPC fixture did not start within five seconds" unless @server.wait_till_running(5)
  end

  def teardown
    @client&.close
    @server&.stop
    @thread&.join(5)
    FileUtils.rm_rf(@root)
  end

  def test_streamed_batches_and_unimplemented_fallback_over_unix_grpc
    @client = CRI::Client.new(endpoint: @endpoint, stream_lists: true, timeout: 5)
    filter = {"filter" => {"id" => "requested"}}

    assert_equal(%w[requested-a requested-b], @client.runtime("ListPodSandbox", filter).fetch("items").map { |pod| pod.fetch("id") })
    assert_equal "requested", @client.runtime("ListContainers", filter).dig("containers", 0, "id")
    assert_equal "requested", @client.runtime("ListPodSandbox", filter).dig("items", 0, "id")
    assert_equal "image", @client.image("ListImages").dig("images", 0, "id")
    assert_equal [[:stream_pod_sandboxes, "requested"], [:stream_containers, "requested"],
                  [:list_containers, "requested"], [:list_pod_sandbox, "requested"]], Array.new(4) { @runtime.calls.pop }
    assert_equal :stream_images, @image.calls.pop
  end

  def test_disabled_gate_uses_unary_rpcs
    @client = CRI::Client.new(endpoint: @endpoint, timeout: 5)

    assert_equal "requested", @client.runtime("ListPodSandbox", {"filter" => {"id" => "requested"}}).dig("items", 0, "id")
    assert_equal [], @client.image("ListImages").fetch("images")
    assert_equal [:list_pod_sandbox, "requested"], @runtime.calls.pop
    assert_equal :list_images, @image.calls.pop
  end

  def test_summary_and_cadvisor_use_stats_and_descriptors_from_cri
    @client = CRI::Client.new(endpoint: @endpoint, stream_lists: true, timeout: 5)
    pod = {"metadata" => {"name" => "demo", "namespace" => "default", "uid" => "uid"}}
    records = [{uid: "uid", state: "Running", sandbox_id: "sandbox", pod: pod, containers: [{id: "container", name: "app"}]}]
    provider = Rubernetes::Node::StatsProvider.new(node_name: "node", lifecycle: Struct.new(:stats_records).new(records), runtime: Object.new,
                                                   cri_clients: [@client])
    node = Rubernetes::Node::StreamingServer.new(log_service: Object.new, stats_provider: provider)
    status, _, body = node.call(Rubernetes::API::Request.new(path: "/stats/summary"))

    assert_equal 200, status, body.join
    stats = JSON.parse(body.join).fetch("pods").first

    assert_equal 456, stats.dig("cpu", "usageCoreNanoSeconds")
    assert_equal 12, stats.dig("cpu", "usageNanoCores")
    assert_equal 789, stats.dig("containers", 0, "memory", "workingSetBytes")
    assert_equal "1970-01-01T00:02:03.000000000Z", stats.dig("cpu", "time")

    status, _, body = node.call(Rubernetes::API::Request.new(path: "/metrics/cadvisor"))

    assert_equal 200, status, body.join
    assert_includes body.join, "# TYPE test_cri_cpu gauge\ntest_cri_cpu{pod=\"demo\"} 42\n"
  end

  def test_summary_keeps_pod_counters_absent_and_fills_empty_container_sections
    streaming = stats_server(Object.new)
    status, _, body = streaming.call(Rubernetes::API::Request.new(path: "/stats/summary"))

    assert_equal 200, status
    stats = JSON.parse(body.join).fetch("pods").first

    refute stats.key?("cpu")
    assert_equal 789, stats.dig("memory", "workingSetBytes")
    refute stats.fetch("memory").key?("availableBytes")
    container = stats.fetch("containers").first

    assert_equal [0, 0], container.fetch("cpu").values_at("usageCoreNanoSeconds", "usageNanoCores")
    assert_equal [0, 0, 0], container.fetch("memory").values_at("workingSetBytes", "usageBytes", "rssBytes")
    refute container.fetch("memory").key?("availableBytes")
    assert_equal({"time" => nil}, container.fetch("rootfs"))
  end

  def test_unimplemented_sandbox_stats_preserve_cri_writable_layer_and_use_local_cgroup_stats
    @runtime.stats_mode = :unimplemented
    runtime = Struct.new(:usage) do
      def pod_usage(_id) = usage
    end.new({"pod" => {"cpu" => {"usage_usec" => "13"}},
             "containers" => [{"id" => "container", "usage" => {"cpu" => {"usage_usec" => "5"}}}]})
    streaming = stats_server(runtime)
    status, _, body = streaming.call(Rubernetes::API::Request.new(path: "/stats/summary"))

    assert_equal 200, status
    stats = JSON.parse(body.join).fetch("pods").first

    assert_equal 13_000, stats.dig("cpu", "usageCoreNanoSeconds")
    assert_equal 5_000, stats.dig("containers", 0, "cpu", "usageCoreNanoSeconds")
    assert_equal [49_152, 3], stats.dig("containers", 0, "rootfs").values_at("usedBytes", "inodesUsed")
    assert_equal [:list_containers, ""], @runtime.calls.pop(timeout: 1)

    runtime.usage = nil
    status, _, body = streaming.call(Rubernetes::API::Request.new(path: "/stats/summary"))

    assert_equal 200, status
    stats = JSON.parse(body.join).fetch("pods").first

    assert_equal 456, stats.dig("cpu", "usageCoreNanoSeconds")
    assert_equal 49_152, stats.dig("containers", 0, "rootfs", "usedBytes")
    assert_equal [:list_containers, ""], @runtime.calls.pop(timeout: 1)

    @runtime.stats_mode = :unavailable
    status, _, body = streaming.call(Rubernetes::API::Request.new(path: "/stats/summary"))

    assert_equal 500, status
    assert_includes body.join, "failed to get summary stats"
    assert_predicate @runtime.calls, :empty?
  end

  def test_node_runtime_filesystems_follow_only_the_default_cri_socket
    @client = CRI::Client.new(endpoint: @endpoint, timeout: 5)
    backend = CRI::Backend.new(client: @client)
    alternate_client = Object.new
    def alternate_client.image(*) = raise("alternate RuntimeClass was queried for the node's filesystem")
    alternate = CRI::Backend.new(client: alternate_client)
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {alternate: alternate, selected: backend}, default: "selected")
    agent = Rubernetes::Node::Agent.new(node_name: "node", api: Object.new, runtime: runtime, detect_host_resources: true, pod_root: @root)
    streaming = Rubernetes::Node::StreamingServer.new(log_service: Object.new, stats_provider: agent.stats_provider)

    %i[unimplemented empty].each do |mode|
      @image.filesystems = {} if mode == :empty
      node = node_summary(streaming)

      assert node["fs"]
      refute node.key?("runtime")
    end

    @image.filesystems = {image_filesystems: [filesystem(@root, bytes: 17, inodes: 2), filesystem("/", bytes: 100, inodes: 40)]}
    runtime_stats = node_summary(streaming).fetch("runtime")
    image, container = runtime_stats.values_at("imageFs", "containerFs")

    assert_equal [17, 2, "1970-01-01T00:02:03.000000000Z"], image.values_at("usedBytes", "inodesUsed", "time")
    assert_equal Rubernetes::Platform::Linux::Statfs.statfs(@root).capacity_bytes, image.fetch("capacityBytes")
    assert_equal image, container
    assert_equal %i[image_fs_info image_fs_info image_fs_info], Array.new(3) { @image.calls.pop(timeout: 1) }
    assert_predicate @image.calls, :empty?, "node Summary should perform one RPC on the selected socket per sample"
  end

  private

  def stats_server(runtime)
    @client = CRI::Client.new(endpoint: @endpoint, timeout: 5)
    pod = {"metadata" => {"name" => "demo", "namespace" => "default", "uid" => "uid"}}
    record = {uid: "uid", state: "Running", sandbox_id: "sandbox", pod: pod, containers: [{id: "container", name: "app"}]}
    provider = Rubernetes::Node::StatsProvider.new(node_name: "node", lifecycle: Struct.new(:stats_records).new([record]), runtime: runtime,
                                                   cri_clients: [@client])
    Rubernetes::Node::StreamingServer.new(log_service: Object.new, stats_provider: provider)
  end

  def filesystem(mountpoint, bytes:, inodes:)
    {fs_id: {mountpoint: mountpoint}, timestamp: 123_000_000_000, used_bytes: {value: bytes}, inodes_used: {value: inodes}}
  end

  def node_summary(streaming)
    status, _, body = streaming.call(Rubernetes::API::Request.new(path: "/stats/summary"))

    assert_equal 200, status, body.join
    JSON.parse(body.join).fetch("node")
  end
end
