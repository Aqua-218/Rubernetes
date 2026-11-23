# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class UserNamespacesHostNetworkAPITest < Minitest::Test
  API = Rubernetes::API
  PODS = "/api/v1/namespaces/default/pods"

  def request(server, method, path, object)
    content_type = method == "PATCH" ? "application/merge-patch+json" : "application/json"
    server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                 body: JSON.generate(object), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def pod(name, **fields)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name},
     "spec" => {"containers" => [{"name" => "main", "image" => "nginx"}], "hostUsers" => false, "hostNetwork" => true}.merge(fields.transform_keys(&:to_s))}
  end

  def test_gate_allows_host_network_only_and_preserves_existing_pods_when_disabled
    store = API::MemoryStore.new
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    disabled = API::Server.new(store: store, registry: registry)
    enabled = API::Server.new(store: store, registry: registry, feature_gates: {"UserNamespacesHostNetworkSupport" => true})
    response = request(disabled, "POST", PODS, pod("disabled"))

    assert_equal 422, response.status, response.body.inspect
    assert_equal(["spec.hostNetwork"], response.body.dig("details", "causes").map { |cause| cause.fetch("field") })
    unshared_network = request(disabled, "POST", PODS, pod("unshared-network", hostNetwork: false))

    assert_equal 201, unshared_network.status, unshared_network.body.inspect
    response = request(enabled, "POST", PODS, pod("enabled"))

    assert_equal 201, response.status, response.body.inspect
    assert_equal [false, true], response.body.fetch("spec").values_at("hostUsers", "hostNetwork")

    response = request(disabled, "PATCH", "#{PODS}/enabled", {"metadata" => {"labels" => {"stage" => "disabled"}}})

    assert_equal 200, response.status, response.body.inspect
    assert_equal [false, true], response.body.fetch("spec").values_at("hostUsers", "hostNetwork")

    response = request(enabled, "POST", PODS, pod("invalid", hostPID: true, hostIPC: true))

    assert_equal 422, response.status, response.body.inspect
    assert_equal(%w[spec.HostPID spec.HostIPC], response.body.dig("details", "causes").map { |cause| cause.fetch("field") })
  end
end
