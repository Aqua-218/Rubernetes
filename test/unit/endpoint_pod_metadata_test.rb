# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"
require "rubernetes/controller"
require "rubernetes/network/dns"

class EndpointPodMetadataTest < Minitest::Test
  API = Rubernetes::API
  Endpoints = Rubernetes::Controller::EndpointController
  EndpointSlice = Rubernetes::Controller::EndpointSliceController
  ADDRESS = "10.0.0.2"
  NODE = {"apiVersion" => "v1", "kind" => "Node",
          "metadata" => {"name" => "worker", "labels" => {"topology.kubernetes.io/zone" => "east"}},
          "status" => {"conditions" => [{"type" => "Ready", "status" => "False"}]}}.freeze

  def test_hostname_zone_and_node_name_survive_api_persistence_and_feed_dns
    svc = service
    selected = pod("db-0", ADDRESS, hostname: "database")
    server = endpoint_api
    slice = EndpointSlice.new.plan(svc, pods: [selected], nodes: [NODE]).creates.first.object
    legacy = Endpoints.new.plan(svc, pods: [selected]).creates.first.object
    slice_response = create(server, "/apis/discovery.k8s.io/v1/namespaces/ns/endpointslices", slice)
    legacy_response = create(server, "/api/v1/namespaces/ns/endpoints", legacy)

    assert_equal 201, slice_response.status, slice_response.body.inspect
    assert_equal 201, legacy_response.status, legacy_response.body.inspect
    assert_equal({"hostname" => "database", "nodeName" => "worker", "zone" => "east"},
                 slice_response.body.dig("endpoints", 0).slice("hostname", "nodeName", "zone"))
    assert_equal({"hostname" => "database", "nodeName" => "worker"},
                 legacy_response.body.dig("subsets", 0, "addresses", 0).slice("hostname", "nodeName"))

    resolver = Rubernetes::Network::DNS::Resolver.new
    resolver.add_service(svc)
    resolver.add_endpoint_slice(slice_response.body)

    assert_equal [ADDRESS], resolver.resolve("database.db.ns.svc.cluster.local", type: "A").map(&:data)
    assert_equal ["database.db.ns.svc.cluster.local"], resolver.resolve("_sql._tcp.db.ns.svc.cluster.local", type: "SRV").map(&:data)
  end

  def test_hostname_requires_both_an_explicit_hostname_and_a_matching_subdomain
    svc = service
    wrong_subdomain = pod("p", ADDRESS, hostname: "named", subdomain: "other")
    no_hostname = pod("q", "10.0.0.3")
    no_hostname["spec"]["hostnameOverride"] = "overridden"
    selected = [wrong_subdomain, no_hostname]
    slice = EndpointSlice.new.plan(svc, pods: selected, nodes: [NODE]).creates.first.object
    legacy = Endpoints.new.plan(svc, pods: selected).creates.first.object

    assert_equal 2, slice.fetch("endpoints").length
    assert_equal 2, legacy.dig("subsets", 0, "addresses").length
    assert_empty(slice.fetch("endpoints").filter_map { |endpoint| endpoint["hostname"] })
    assert_empty(legacy.dig("subsets", 0, "addresses").filter_map { |address| address["hostname"] })
  end

  def test_pods_without_nodes_are_published_only_when_the_service_requests_not_ready_addresses
    svc = service
    selected = [pod("db-0", ADDRESS, hostname: "database")]
    absent = EndpointSlice.new.plan(svc, pods: selected, nodes: []).creates.first.object

    assert_empty absent.fetch("endpoints")

    svc["spec"]["publishNotReadyAddresses"] = true
    endpoint = EndpointSlice.new.plan(svc, pods: selected, nodes: []).creates.first.object.dig("endpoints", 0)

    assert_equal "worker", endpoint.fetch("nodeName")
    assert_equal "database", endpoint.fetch("hostname")
    refute endpoint.key?("zone")
  end

  def test_legacy_endpoints_keep_terminating_and_unready_addresses_only_when_requested
    svc = service
    ready = pod("ready", ADDRESS)
    ready["metadata"]["deletionTimestamp"] = nil
    unready = pod("unready", "10.0.0.3", ready: false)
    deleting = pod("deleting", "10.0.0.4", ready: false)
    deleting["metadata"]["deletionTimestamp"] = "2026-11-19T17:00:00Z"
    succeeded = pod("succeeded", "10.0.0.5", phase: "Succeeded")
    failed = pod("failed", "10.0.0.6", phase: "Failed")
    selected = [ready, unready, deleting, succeeded, failed]

    normal = Endpoints.new.plan(svc, pods: selected).creates.first.object.dig("subsets", 0)

    assert_equal(["ready"], normal.fetch("addresses").map { |entry| entry.dig("targetRef", "name") })
    assert_equal(["unready"], normal.fetch("notReadyAddresses").map { |entry| entry.dig("targetRef", "name") })
    svc["spec"]["publishNotReadyAddresses"] = true
    publish = Endpoints.new.plan(svc, pods: selected).creates.first.object.dig("subsets", 0)

    assert_equal %w[deleting ready unready], publish.fetch("addresses").map { |entry| entry.dig("targetRef", "name") }.sort
    refute publish.key?("notReadyAddresses")
  end

  private

  def service
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "db", "namespace" => "ns", "uid" => "svc-uid"},
     "spec" => {"clusterIP" => "None", "ipFamilies" => ["IPv4"], "selector" => {"app" => "db"},
                "ports" => [{"name" => "sql", "protocol" => "TCP", "port" => 5432}]}}
  end

  def pod(name, ip, hostname: nil, subdomain: "db", ready: true, phase: "Running")
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid", "labels" => {"app" => "db"}},
     "spec" => {"nodeName" => "worker", "hostname" => hostname, "subdomain" => subdomain}.compact,
     "status" => {"phase" => phase, "podIP" => ip, "podIPs" => [{"ip" => ip}],
                  "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False"}]}}
  end

  def endpoint_api
    resources = [
      API::Resource.new(resource: "endpoints", kind: "Endpoints", scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Endpoints")),
      API::Resource.new(group: "discovery.k8s.io", resource: "endpointslices", kind: "EndpointSlice", scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.discovery.v1.EndpointSlice"))
    ]
    API::Server.new(registry: API::Registry.new(resources: resources, defaults: false))
  end

  def create(server, path, object)
    server.call(API::Request.new(method: "POST", path: path, body: object))
  end
end
