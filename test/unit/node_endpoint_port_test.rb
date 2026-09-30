# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# v1.DaemonEndpoint serialises its port as "Port" with a capital P
# (staging/src/k8s.io/api/core/v1/types.go: `json:"Port"`), which is unlike
# every field around it.  Spelling it "port" makes the API server drop the
# value, and the kubelet endpoint then defaults to the standard port -- so
# every logs/exec/attach/port-forward request is proxied to whatever else is
# listening there instead of to this node's streaming server.
class NodeEndpointPortTest < Minitest::Test
  Resolver = Rubernetes::API::NodeEndpointResolver

  def node(endpoint)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "worker-0"},
     "status" => {"addresses" => [{"type" => "InternalIP", "address" => "127.0.0.1"}],
                  "daemonEndpoints" => {"kubeletEndpoint" => endpoint}}}
  end

  class FakeStore
    def initialize(node)
      @node = node
    end

    def get(**_options)
      @node
    end

    def list(**_options)
      Rubernetes::API::MemoryStore::ListResult.new(items: [@node], resource_version: 1)
    end
  end

  def resolve(endpoint)
    resolver = Resolver.new(store: FakeStore.new(node(endpoint)),
                            resource: Rubernetes::API::Registry.new.find_gvr(group: "", version: "v1", resource: "nodes"))
    resolver.send(:kubelet_endpoint_port, node(endpoint))
  end

  def test_the_capitalised_port_field_is_what_upstream_writes
    assert_equal 21_250, resolve({"Port" => 21_250})
  end

  def test_a_lowercase_port_from_an_older_agent_is_still_accepted
    assert_equal 21_250, resolve({"port" => 21_250})
  end

  def test_a_zero_or_missing_port_falls_back_rather_than_being_used
    assert_nil resolve({"Port" => 0})
    assert_nil resolve({})
  end

  # The agent must publish the field the API server actually stores.
  def test_the_agent_publishes_the_capitalised_field
    source = File.read(File.expand_path("../../lib/rubernetes/node/agent.rb", __dir__))

    assert_includes source, '"kubeletEndpoint" => {"Port" =>',
                    "the node agent must publish daemonEndpoints.kubeletEndpoint.Port"
  end
end
