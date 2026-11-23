# frozen_string_literal: true

# kube_apiserver_clusterip_allocator_* / kube_apiserver_nodeport_allocator_*
# (pkg/registry/core/service/{ipallocator,portallocator}/metrics.go):
# allocations by scope (static for a requested address or port, dynamic
# otherwise), errors, and the used and free counts of each range.
require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/bootstrap"

class ServiceAllocatorMetricsTest < Minitest::Test
  API = Rubernetes::API

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @metrics = Rubernetes::Observability::Metrics.new
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, metrics: @metrics,
                              service_cidrs: ["10.96.0.0/24"], node_port_range: 30_000..30_009)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}})
  end

  def call(method, path, body)
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                  body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def service(name, spec)
    call("POST", "/api/v1/namespaces/team/services", {"metadata" => {"name" => name}, "spec" => {"ports" => [{"port" => 80}]}.merge(spec)})
  end

  def test_allocations_errors_and_range_usage
    assert_equal 201, service("dynamic", {}).status
    assert_equal 201, service("static", {"clusterIP" => "10.96.0.5"}).status
    assert_equal 422, service("taken", {"clusterIP" => "10.96.0.5"}).status
    assert_equal 201,
                 service("nodeport",
                         {"type" => "NodePort",
                          "ports" => [{"port" => 80, "name" => "a", "nodePort" => 30_001}, {"port" => 81, "name" => "b"}]}).status
    text = @metrics.render

    assert_includes text, %(kube_apiserver_clusterip_allocator_allocation_total{cidr="10.96.0.0/24",scope="dynamic"} 2)
    assert_includes text, %(kube_apiserver_clusterip_allocator_allocation_total{cidr="10.96.0.0/24",scope="static"} 1)
    assert_includes text, %(kube_apiserver_clusterip_allocator_allocation_errors_total{cidr="10.96.0.0/24",scope="static"} 1)
    assert_includes text, %(kube_apiserver_clusterip_allocator_allocated_ips{cidr="10.96.0.0/24"} 3)
    assert_includes text, %(kube_apiserver_clusterip_allocator_available_ips{cidr="10.96.0.0/24"} 251)
    assert_includes text, %(kube_apiserver_clusterip_allocator_allocation_duration_seconds_count{cidr="10.96.0.0/24"} 2)
    assert_includes text, %(kube_apiserver_nodeport_allocator_allocation_total{scope="static"} 1)
    assert_includes text, %(kube_apiserver_nodeport_allocator_allocation_total{scope="dynamic"} 1)
    assert_includes text, "kube_apiserver_nodeport_allocator_allocated_ports 2"
    assert_includes text, "kube_apiserver_nodeport_allocator_available_ports 8"
  end

  def test_dynamic_node_ports_use_upper_band_before_falling_back_to_static_ports
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, node_port_range: 30_000..30_016)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}})
    dynamic = service("first", {"type" => "NodePort"})

    assert_equal 201, dynamic.status
    assert_equal 30_016, dynamic.body.dig("spec", "ports", 0, "nodePort")
    explicit = service("static", {"type" => "NodePort", "ports" => [{"port" => 80, "nodePort" => 30_000}]})

    assert_equal 201, explicit.status
    remaining = Array.new(15) { |index| {"name" => "p#{index}", "port" => 81 + index} }
    fallback = service("remaining", {"type" => "NodePort", "ports" => remaining})

    assert_equal 201, fallback.status
    assert_equal (30_001..30_015).to_a, fallback.body.dig("spec", "ports").map { |port| port.fetch("nodePort") }.sort
    full = service("full", {"type" => "NodePort"})
    health = service("full-health", {"type" => "LoadBalancer", "externalTrafficPolicy" => "Local", "allocateLoadBalancerNodePorts" => false})

    assert_equal 500, full.status
    assert_equal "Internal error occurred: failed to allocate a nodePort: range is full", full.body.fetch("message")
    assert_equal 500, health.status
    assert_equal "Internal error occurred: failed to allocate a HealthCheck NodePort 0: range is full", health.body.fetch("message")
  end

  def test_cluster_ip_pool_exhaustion_and_static_conflict_report_distinct_api_statuses
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, service_cidrs: ["10.96.0.0/30"])
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}})

    assert_equal 201, service("one", {"clusterIP" => "10.96.0.1"}).status
    assert_equal 201, service("two", {"clusterIP" => "10.96.0.2"}).status
    duplicate = service("duplicate", {"clusterIP" => "10.96.0.2"})

    assert_equal 422, duplicate.status
    assert_equal "spec.clusterIPs", duplicate.body.dig("details", "causes", 0, "field")
    assert_match(/Invalid value: \["10\.96\.0\.2"\]/, duplicate.body.dig("details", "causes", 0, "message"))
    exhausted = service("full", {})

    assert_equal 500, exhausted.status
    assert_equal 'failed to allocate a serviceIP for Service "full": range is full', exhausted.body.dig("details", "causes", 0, "message")
  end
end
