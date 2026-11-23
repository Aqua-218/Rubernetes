# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class EndpointSliceMirroringSubsetsTest < Minitest::Test
  API = Rubernetes::API
  Controller = Rubernetes::Controller
  Mirror = Controller::EndpointSliceMirroringController
  DISCOVERY = "discovery.k8s.io/v1"

  Transport = Struct.new(:server) do
    def request(method, path, body: nil, headers: {}, query: nil)
      identity = {"username" => "admin", "groups" => ["system:masters"]}
      server.call(API::Request.new(method: method, path: path, body: body, headers: headers, query: query, identity: identity))
    end
  end

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    server = API::Server.new(registry: registry)
    @client = Rubernetes::Client::KubernetesClient.new(rest_client: Transport.new(server), namespace: "default")
    store = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: @client, resource_descriptors: [Mirror::ENDPOINTS, Mirror::ENDPOINT_SLICE, Mirror::SERVICE])
    @mirror = Mirror.new(store: store)
    @client.create(resource("Service").merge("spec" => {"clusterIP" => "None", "ports" => [{"name" => "http", "port" => 80}]}))
  end

  def test_serving_ports_follow_their_addresses_and_readiness_across_subsets
    subsets = [
      subset([port(8080)], ready: %w[192.0.2.1 2001:db8::1]),
      subset([port(8080)], not_ready: %w[192.0.2.1 192.0.2.2]),
      subset([port(8443)], ready: %w[192.0.2.3]),
      subset([port(9090, name: "metrics", app_protocol: "example.com/metrics")], ready: %w[192.0.2.3]),
      subset([], ready: %w[192.0.2.4])
    ]
    endpoints = create_endpoints(subsets)
    created = @mirror.reconcile(endpoints)

    assert_equal 4, created.creates.size
    by_family_and_ports = slices.to_h do |slice|
      key = [slice.fetch("addressType"), slice.fetch("ports").map { |entry| entry.fetch("port") }]
      addresses = slice.fetch("endpoints").to_h { |endpoint| [endpoint.fetch("addresses").first, endpoint.dig("conditions", "ready")] }
      [key, addresses]
    end

    assert_equal({
                   ["IPv4", [8080]] => {"192.0.2.1" => false, "192.0.2.2" => false},
                   ["IPv6", [8080]] => {"2001:db8::1" => true},
                   ["IPv4", [8443, 9090]] => {"192.0.2.3" => true},
                   ["IPv4", []] => {"192.0.2.4" => true}
                 }, by_family_and_ports)
    slices.each do |slice|
      assert_equal "legacy", slice.dig("metadata", "labels", "app")
      assert_equal endpoints.dig("metadata", "uid"), slice.dig("metadata", "ownerReferences", 0, "uid")
    end
    assert_equal "example.com/metrics", slices.flat_map { |slice| slice.fetch("ports") }.find { |entry| entry["port"] == 9090 }.fetch("appProtocol")
    assert_empty @mirror.reconcile(endpoints).operations
  end

  def test_existing_port_groups_keep_their_uid_and_stale_slices_are_recycled_or_deleted
    first = subset([port(8080), port(8081, name: "metrics")], ready: ["192.0.2.1"])
    second = subset([port(9090)], ready: ["192.0.2.2"])
    endpoints = create_endpoints([first, second])
    @mirror.reconcile(endpoints)
    first_uid = slice_for_port(8080).dig("metadata", "uid")
    second_uid = slice_for_port(9090).dig("metadata", "uid")
    first["ports"].reverse!
    endpoints = update_endpoints(endpoints, [second, first])

    assert_empty @mirror.reconcile(endpoints).operations
    replacement = subset([port(9191)], ready: ["192.0.2.2"])
    endpoints = update_endpoints(endpoints, [first, replacement])

    assert_equal [:update], @mirror.reconcile(endpoints).operations.map(&:action)
    assert_equal second_uid, slice_for_port(9191).dig("metadata", "uid")
    assert_equal first_uid, slice_for_port(8080).dig("metadata", "uid")
    returning = subset([port(9090)], ready: ["192.0.2.3"])
    endpoints = update_endpoints(endpoints, [first, replacement, returning])

    assert_equal [:create], @mirror.reconcile(endpoints).operations.map(&:action)
    refute_equal second_uid, slice_for_port(9090).dig("metadata", "uid")
    endpoints = update_endpoints(endpoints, [first, subset([port(9191)], ready: ["2001:db8::2"]), returning])

    assert_equal %i[create delete], @mirror.reconcile(endpoints).operations.map(&:action)
    assert_equal "IPv6", slice_for_port(9191).fetch("addressType")
    refute_equal second_uid, slice_for_port(9191).dig("metadata", "uid")
    endpoints = update_endpoints(endpoints, [first])

    assert_equal %i[delete delete], @mirror.reconcile(endpoints).operations.map(&:action)
    assert_equal([first_uid], slices.map { |slice| slice.dig("metadata", "uid") })
    @client.delete("endpoints", "legacy", namespace: "default")
    @mirror.reconcile_orphans("default/legacy")

    assert_empty slices
  end

  private

  def resource(kind)
    {"apiVersion" => "v1", "kind" => kind, "metadata" => {"namespace" => "default", "name" => "legacy", "labels" => {"app" => "legacy"}}}
  end

  def port(number, name: "http", app_protocol: nil)
    {"name" => name, "port" => number, "appProtocol" => app_protocol}.compact
  end

  def subset(ports, ready: [], not_ready: [])
    {"ports" => ports, "addresses" => ready.map { |ip| {"ip" => ip} }, "notReadyAddresses" => not_ready.map { |ip| {"ip" => ip} }}
  end

  def create_endpoints(subsets)
    @client.create(resource("Endpoints").merge("subsets" => subsets))
  end

  def update_endpoints(endpoints, subsets)
    @client.update(endpoints.merge("subsets" => subsets))
  end

  def slices
    @client.get("endpointslices", api_version: DISCOVERY, namespace: "default").fetch("items")
  end

  def slice_for_port(number)
    slices.find { |slice| slice.fetch("ports").any? { |entry| entry["port"] == number } }
  end
end
