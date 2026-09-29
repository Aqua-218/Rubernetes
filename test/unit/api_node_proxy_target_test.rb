# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# The node proxy dials the kubelet where exec and logs do (the published
# streaming address) and maps the well-known kubelet port to the advertised
# one: every node dump in the e2e framework asks for nodes/<name>:10250/proxy.
class APINodeProxyTargetTest < Minitest::Test
  Store = Struct.new(:node) do
    def get(**) = node
  end
  Route = Struct.new(:resource)

  Resolver = Struct.new(:scheme)

  def target(port, annotations: {"node.rubernetes.io/streaming-address" => "127.0.0.1"}, resolver: nil)
    node = {"metadata" => {"name" => "worker-0", "annotations" => annotations},
            "status" => {"addresses" => [{"type" => "InternalIP", "address" => "10.240.0.1"}],
                         "daemonEndpoints" => {"kubeletEndpoint" => {"Port" => 21_250}}}}
    server = Rubernetes::API::Server.allocate
    server.instance_variable_set(:@store, Store.new(node))
    server.instance_variable_set(:@node_resolver, resolver)
    server.send(:node_proxy_target, Route.new(nil), "worker-0", port)
  end

  def test_streaming_address_and_advertised_port
    assert_equal({host: "127.0.0.1", port: 21_250, scheme: "https"}, target(nil))
    assert_equal({host: "127.0.0.1", port: 21_250, scheme: "https"}, target("10250"))
    assert_equal({host: "127.0.0.1", port: 9000, scheme: "https"}, target("9000"))
    assert_equal "10.240.0.1", target(nil, annotations: {})[:host]
    assert_equal "http", target(nil, resolver: Resolver.new("http"))[:scheme]
  end
end
