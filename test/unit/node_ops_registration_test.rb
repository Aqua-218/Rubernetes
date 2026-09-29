# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/registration"

class NodeOpsRegistrationTest < Minitest::Test
  class Client
    attr_reader :objects, :calls

    def initialize
      @objects = {}
      @calls = []
    end

    def get(resource:, namespace:, name:)
      @objects.fetch([resource, namespace, name])
    end

    def create(resource:, namespace:, name:, object:)
      @calls << [:create, resource, namespace, name]
      @objects[[resource, namespace, name]] = object
    end

    def update(resource:, namespace:, name:, object:, subresource: nil)
      @calls << [:update, resource, namespace, name, subresource]
      @objects[[resource, namespace, name]] = object
    end
  end

  def test_registration_builds_node_status_and_lease_with_deterministic_clock
    clock = -> { Time.utc(2026, 1, 2, 3, 4, 5) }
    registration = Rubernetes::Node::Registration.new(
      node_name: "node-a",
      capacity: {"cpu" => "2", "memory" => "4Gi"},
      operating_system: "linux",
      architecture: "amd64",
      clock: clock
    )

    node = registration.build_node
    lease = registration.build_lease
    assert_equal("Node", node["kind"])
    assert_equal("node-a", node.dig("metadata", "name"))
    assert_equal("amd64", node.dig("status", "nodeInfo", "architecture"))
    assert_equal("linux", node.dig("status", "nodeInfo", "operatingSystem"))
    assert_equal("Unknown", node.dig("status", "conditions", 0, "status"))
    assert_equal("kube-node-lease", lease.dig("metadata", "namespace"))
    assert_equal("node-a", lease.dig("spec", "holderIdentity"))
    assert_equal("2026-01-02T03:04:05.000000Z", lease.dig("spec", "renewTime"))
  end

  def test_register_is_idempotent_and_heartbeat_only_updates_lease
    client = Client.new
    registration = Rubernetes::Node::Registration.new(node_name: "node-a", client: client, capacity: {"cpu" => "1"})

    first = registration.register
    second = registration.register
    registration.heartbeat

    assert_equal("node-a", first.node.dig("metadata", "name"))
    assert_equal("node-a", second.lease.dig("metadata", "name"))
    assert_equal(2, client.calls.count { |call| call.first == :create })
    assert_equal(5, client.calls.length)
    assert_equal(:update, client.calls.last.first)
    assert_equal("coordination.k8s.io/v1/leases", client.calls.last[1])
  end
end
