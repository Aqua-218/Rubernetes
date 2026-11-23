# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeAPIClientAdapterTest < Minitest::Test
  class Client
    attr_reader :calls

    def initialize
      @calls = []
      @objects = {}
    end

    def get(resource, api_version: "v1", query: nil, namespace: nil)
      @calls << [:get, resource, api_version, query, namespace]
      if resource.start_with?("/")
        raise Rubernetes::Client::APIError.new("not found", response: Response.new(404)) unless @objects.key?(resource)

        return @objects.fetch(resource)
      end
      {"items" => [], "metadata" => {"resourceVersion" => "7"}}
    end

    Response = Struct.new(:status) do
      def headers = {}
      def body = ""
    end

    attr_accessor :objects, :create_status

    def create(object, namespace: nil, api_version: "v1")
      @calls << [:create, object, namespace, api_version]
      raise Rubernetes::Client::APIError.new("exists", response: Response.new(create_status)) if create_status

      object.merge("metadata" => object["metadata"].merge("resourceVersion" => "1"))
    end

    def update(object, namespace:, path:)
      @calls << [:update, object, namespace, path]
      object.merge("metadata" => object["metadata"].merge("resourceVersion" => (object.dig("metadata", "resourceVersion").to_i + 1).to_s))
    end

    def watch_each(resource, api_version:, query:, namespace: nil)
      @calls << [:watch, resource, api_version, query, namespace]
      [{"type" => "BOOKMARK", "object" => {"metadata" => {"resourceVersion" => "8"}}}].each
    end

    def apply(object, path:, field_manager:)
      @calls << [:apply, object, path, field_manager]
      object
    end

    def patch(path, body, type:)
      @calls << [:patch, path, body, type]
      body
    end
  end

  def setup
    @client = Client.new
    @adapter = Rubernetes::Node::APIClientAdapter.new(client: @client, node_name: "node-a")
  end

  def test_list_and_watch_use_node_field_selector_and_resource_versions
    @adapter.list(resource_version: "6")
    events = @adapter.watch(resource_version: "7", timeout: 30).to_a

    list_call = @client.calls.fetch(0)
    watch_call = @client.calls.fetch(1)

    assert_equal([:get, "pods", "v1", {"fieldSelector" => "spec.nodeName=node-a", "resourceVersion" => "6"}, :all],
                 list_call)
    # Every namespace, explicitly: a nil namespace makes the client fall back to
    # the kubeconfig context and the node would only run "default" pods.
    assert_equal(:all, watch_call.fetch(4))
    assert_equal("spec.nodeName=node-a", watch_call.fetch(3).fetch("fieldSelector"))
    assert_equal("7", watch_call.fetch(3).fetch("resourceVersion"))
    assert_equal(30, watch_call.fetch(3).fetch("timeoutSeconds"))
    assert_equal("BOOKMARK", events.fetch(0).fetch("type"))
  end

  NODE = {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "node-a", "labels" => {"kubernetes.io/os" => "linux"}},
          "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}]}}.freeze

  # kubelet: created once, then labels, annotations and status patched on the
  # status subresource; an existing Node (409) goes straight to the patch.
  def test_the_node_is_created_once_then_its_status_is_patched
    @adapter.register_node(NODE)
    @adapter.register_node(NODE)

    assert_equal :create, @client.calls.fetch(0).fetch(0)
    assert_equal [:patch, "/api/v1/nodes/node-a/status",
                  {"metadata" => {"labels" => {"kubernetes.io/os" => "linux"}}, "status" => NODE["status"]}, :merge],
                 @client.calls.fetch(1)

    client = Client.new
    client.create_status = 409
    adapter = Rubernetes::Node::APIClientAdapter.new(client: client, node_name: "node-a")
    adapter.register_node(NODE)

    assert_equal %i[create patch], client.calls.map(&:first)
  end

  def test_registration_and_heartbeats_use_their_own_clients
    heartbeat = Client.new
    events = Client.new
    heartbeat.objects["/api/v1/nodes/node-a"] = {"metadata" => {"uid" => "node-id"}}
    adapter = Rubernetes::Node::APIClientAdapter.new(client: @client, heartbeat_client: heartbeat, event_client: events, node_name: "node-a")
    lease = {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease", "metadata" => {"name" => "node-a", "namespace" => "kube-node-lease"}}
    @client.create_status = 409

    adapter.register_node(NODE)
    adapter.register_node(NODE)
    adapter.renew_lease(lease)

    assert_equal %i[create patch], @client.calls.map(&:first)
    assert_equal %i[patch get get create], heartbeat.calls.map(&:first)
    assert_same events, adapter.event_client
  end

  def test_external_cloud_provider_keeps_control_of_node_addresses_after_registration
    adapter = Rubernetes::Node::APIClientAdapter.new(client: @client, node_name: "node-a", external_cloud_provider: true)
    agent = Rubernetes::Node::Agent.new(api: adapter, node_name: "node-a", runtime: Object.new, external_cloud_provider: true,
                                        provider_id: "test://worker-a", addresses: [{"type" => "InternalIP", "address" => "192.0.2.1"}])
    adapter.register_node(agent.node)
    adapter.register_node(agent.node)

    registration = @client.calls.fetch(0).fetch(1)

    assert_equal "test://worker-a", registration.dig("spec", "providerID")
    assert_equal [{"key" => "node.cloudprovider.kubernetes.io/uninitialized", "value" => "true", "effect" => "NoSchedule"}],
                 registration.dig("spec", "taints")
    assert_equal [{"type" => "InternalIP", "address" => "192.0.2.1"}], registration.dig("status", "addresses")
    patch = @client.calls.fetch(1).fetch(2)

    refute patch.fetch("status").key?("addresses")
    refute patch.key?("spec")
  end

  # The node lease controller: created when missing, renewed with an Update
  # of the latest Lease written (no read in between).
  def test_the_lease_is_created_then_renewed_with_updates
    @client.objects["/api/v1/nodes/node-a"] = {"metadata" => {"uid" => "node-id"}}
    lease = lambda { |time|
      {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease", "metadata" => {"name" => "node-a", "namespace" => "kube-node-lease"},
       "spec" => {"holderIdentity" => "node-a", "renewTime" => time}}
    }
    @adapter.renew_lease(lease.call("t1"))
    @adapter.renew_lease(lease.call("t2"))
    path = "/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/node-a"

    assert_equal %i[get get create update], @client.calls.map(&:first)
    assert_equal path, @client.calls.fetch(0).fetch(1)
    owner = {"apiVersion" => "v1", "kind" => "Node", "name" => "node-a", "uid" => "node-id"}
    update = @client.calls.fetch(3)

    assert_equal [owner], @client.calls.fetch(2).fetch(1).dig("metadata", "ownerReferences")
    assert_equal [owner], update.fetch(1).dig("metadata", "ownerReferences")
    assert_equal "t2", update.fetch(1).dig("spec", "renewTime")
    assert_equal "1", update.fetch(1).dig("metadata", "resourceVersion")
    assert_equal path, update.fetch(3)
  end

  def test_existing_lease_gets_its_node_owner_on_renewal
    path = "/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/node-a"
    lease = {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
             "metadata" => {"name" => "node-a", "namespace" => "kube-node-lease", "resourceVersion" => "1"}}
    @client.objects[path] = lease
    @client.objects["/api/v1/nodes/node-a"] = {"metadata" => {"uid" => "node-id"}}

    renewed = @adapter.renew_lease(lease)

    assert_equal %i[get get update], @client.calls.map(&:first)
    assert_equal "node-id", renewed.dig("metadata", "ownerReferences", 0, "uid")
  end

  def test_pod_status_uses_the_status_subresource
    @adapter.report(
      {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "web", "namespace" => "apps"}},
      "phase" => "Running"
    )

    assert_equal("/api/v1/namespaces/apps/pods/web/status", @client.calls.fetch(0).fetch(1))
    assert_equal({"status" => {"phase" => "Running"}}, @client.calls.fetch(0).fetch(2))
  end

  def test_watch_cannot_be_used_for_another_node
    assert_raises(ArgumentError) { @adapter.list(node_name: "node-b") }
  end
end
