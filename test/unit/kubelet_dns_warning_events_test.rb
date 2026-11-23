# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/node/event_sink"

class KubeletDNSWarningEventsTest < Minitest::Test
  Node = Rubernetes::Node
  Lifecycle = Struct.new(:records) { def record(uid) = records[uid] }

  class Client
    attr_reader :creates, :patches

    def initialize
      @creates = []
      @patches = []
    end

    def create(event, namespace:, api_version:)
      @creates << [event, namespace, api_version]
      raise "409 AlreadyExists" if event["count"] > 1

      event
    end

    def patch(resource, payload, **options)
      @patches << [resource, payload, options]
    end
  end

  def setup
    @client = Client.new
    sink = Node::EventSink.new(client: @client, async: false)
    recorder = Node::EventRecorder.new(sink: sink, event_time: false, reporting_component: "kubelet",
                                       reporting_instance: "worker-2", source: {"component" => "kubelet", "host" => "worker-2"})
    pod = {"metadata" => {"namespace" => "workloads", "name" => "resolver", "uid" => "pod-uid"}}
    lifecycle = Lifecycle.new({"pod-uid" => {pod: pod}})
    @publisher = Node::KubeletEventPublisher.new(recorder: recorder, node_name: "worker-2", lifecycle: lifecycle)
  end

  def test_missing_dns_records_the_node_in_default_and_the_pod_in_its_namespace
    node_message = 'kubelet does not have ClusterDNS IP configured and cannot create Pod using "ClusterFirst" policy. Falling back to "Default" policy.'
    pod_message = 'pod: "resolver_workloads(pod-uid)". ' + node_message
    emit("Node", "MissingClusterDNS", node_message)
    emit("Pod", "MissingClusterDNS", pod_message)
    node, node_namespace, node_version = @client.creates.fetch(0)
    pod, pod_namespace, pod_version = @client.creates.fetch(1)

    assert_equal 2, @client.creates.size
    assert_equal %w[default v1], [node_namespace, node_version]
    assert_equal %w[workloads v1], [pod_namespace, pod_version]
    assert_equal "default", node.dig("metadata", "namespace")
    assert_equal "workloads", pod.dig("metadata", "namespace")
    assert_equal({"kind" => "Node", "apiVersion" => "v1", "name" => "worker-2"}, node["involvedObject"])
    assert_equal({"kind" => "Pod", "apiVersion" => "v1", "name" => "resolver", "namespace" => "workloads", "uid" => "pod-uid"},
                 pod["involvedObject"])
    assert_equal ["Warning", "MissingClusterDNS", node_message], node.values_at("type", "reason", "message")
    assert_equal ["Warning", "MissingClusterDNS", pod_message], pod.values_at("type", "reason", "message")
    assert_equal({"component" => "kubelet", "host" => "worker-2"}, node["source"])
  end

  def test_dns_config_forming_is_a_pod_warning
    message = "Nameserver limits were exceeded, some nameservers have been omitted, the applied nameserver line is: 1.1.1.1"
    emit("Pod", "DNSConfigForming", message)
    event, namespace, _version = @client.creates.fetch(0)

    assert_equal ["Warning", "DNSConfigForming", message], event.values_at("type", "reason", "message")
    assert_equal %w[Pod workloads resolver], event["involvedObject"].values_at("kind", "namespace", "name")
    assert_equal "workloads", namespace
  end

  def test_repeated_node_warning_patches_the_same_event_in_default
    2.times { emit("Node", "MissingClusterDNS", "Kubelet has no cluster DNS configured.") }
    event, = @client.creates.fetch(0)
    resource, payload, options = @client.patches.fetch(0)

    assert_equal "events", resource
    assert_equal 2, payload["count"]
    assert_equal({type: :merge, namespace: "default", api_version: "v1", name: event.dig("metadata", "name")}, options)
  end

  def test_node_warning_is_accepted_and_readable_through_the_core_events_api
    api = Rubernetes::API
    event_resource = api::Resource.new(group: "", version: "v1", resource: "events", kind: "Event", scope: :namespaced)
    registry = api::Registry.new(resources: [event_resource], defaults: false)
    server = api::Server.new(registry: registry, store: api::MemoryStore.new)
    emit("Node", "MissingClusterDNS", "Kubelet has no cluster DNS configured.")
    event, namespace, = @client.creates.fetch(0)
    path = "/api/v1/namespaces/#{namespace}/events"
    created = server.call(api::Request.new(method: "POST", path: path, body: event))

    assert_equal 201, created.status
    fetched = server.call(api::Request.new(method: "GET", path: "#{path}/#{event.dig("metadata", "name")}"))

    assert_equal 200, fetched.status
    assert_equal "default", fetched.body.dig("metadata", "namespace")
    assert_equal({"kind" => "Node", "apiVersion" => "v1", "name" => "worker-2"}, fetched.body["involvedObject"])
  end

  private

  def emit(scope, reason, message)
    @publisher.call("pod-uid", {"type" => "dns.warning", "scope" => scope, "reason" => reason, "message" => message})
  end
end
