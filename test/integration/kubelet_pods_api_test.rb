# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/bootstrap/config"
require "rubernetes/node"

class KubeletPodsAPITest < Minitest::Test
  Node = Rubernetes::Node

  class Source
    def initialize(pods) = @pods = pods

    def register_node(node) = node
    def renew_lease(lease) = lease
    def list(**) = {"items" => @pods}

    def watch(**)
      sleep 0.05
      []
    end
  end

  def test_agent_serves_local_pod_spec_status_and_watch_changes_on_the_upstream_socket
    begin
      require "rubernetes/node/plugins/generated/pods_v1alpha1_services_pb"
    rescue LoadError => error
      skip error.message
    end

    api = Node::Plugins::Generated::PodsV1alpha1
    Dir.mktmpdir("rubernetes-pods-api-") do |directory|
      initial = pod("pod-a", "uid-a")
      mirror = pod("pod-mirror", "uid-mirror")
      mirror["metadata"]["annotations"] = {"kubernetes.io/config.mirror" => "static"}
      source = Source.new([initial, mirror])
      sync = Node::SyncLoop.new(source: source, node_name: "worker-0", reconcile: ->(*) {})
      sync.resync
      agent = Node::Agent.new(node_name: "worker-0", api: source, runtime: Object.new, sync_loop: sync,
                              feature_gates: {"PodsAPI" => true}, pods_api_directory: directory, sleeper: ->(seconds) { sleep(seconds) })
      agent.start
      socket = File.join(directory, "pods-api.sock")

      assert File.socket?(socket)
      assert_equal 0o600, File.stat(socket).mode & 0o777

      stub = api::Pods::Stub.new("unix:#{socket}", :this_channel_is_insecure)
      response = stub.list_pods(api::ListPodsRequest.new, deadline: Time.now + 5)

      assert_equal(["uid-a"], response.pods.map { |bytes| decode(bytes).dig("metadata", "uid") })
      expected = response.pods.fetch(0)

      assert_equal expected, stub.get_pod(api::GetPodRequest.new(podUID: "uid-a"), deadline: Time.now + 5).pod
      assert_raises(GRPC::NotFound) do
        stub.get_pod(api::GetPodRequest.new(podUID: "uid-mirror"), deadline: Time.now + 5)
      end

      operation = stub.watch_pods(api::WatchPodsRequest.new, deadline: Time.now + 10, return_op: true)
      watch = operation.execute
      event = watch.next

      assert_equal :ADDED, event.type
      assert_equal expected, event.pod
      marker = watch.next

      assert_equal :INITIAL_SYNC_COMPLETE, marker.type
      assert_empty marker.pod

      observed = {"containers" => {"app" => {"state" => "running", "started" => true, "ready" => true}}}
      agent.status.aggregate(initial, phase: "Running", pod_ip: "10.240.0.3", state: observed)
      event = watch.next

      assert_equal :MODIFIED, event.type
      assert_equal "Running", decode(event.pod).dig("status", "phase")
      assert_equal "10.240.0.3", decode(event.pod).dig("status", "podIP")

      newly_scheduled = pod("pod-b", "uid-b")
      sync.process_event({"type" => "ADDED", "object" => newly_scheduled})

      assert_equal :ADDED, watch.next.type
      sync.process_event({"type" => "DELETED", "object" => initial})
      event = watch.next

      assert_equal :DELETED, event.type
      assert_equal({"name" => "pod-a", "namespace" => "default", "uid" => "uid-a"}, decode(event.pod).fetch("metadata"))
      assert_raises(GRPC::NotFound) do
        stub.get_pod(api::GetPodRequest.new(podUID: "uid-a"), deadline: Time.now + 5)
      end

      operation.cancel
      agent.stop
      agent = nil

      refute_path_exists socket
    ensure
      operation&.cancel
      agent&.stop
    end
  end

  private

  def pod(name, uid)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "uid" => uid},
     "spec" => {"nodeName" => "worker-0", "containers" => [{"name" => "app", "image" => "test/app"}]}}
  end

  def decode(bytes)
    @codec ||= Rubernetes::Schema::Codec::KubernetesProtobuf.new
    @codec.decode_message("k8s.io.api.core.v1.Pod", bytes)
  end
end
