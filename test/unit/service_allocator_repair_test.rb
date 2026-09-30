# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# The ClusterIP / NodePort repair sweep (ipallocator + portallocator
# controllers): leaked IPAddresses are released, missing ones recreated,
# duplicates and out-of-range findings counted.
class ServiceAllocatorRepairTest < Minitest::Test
  API = Rubernetes::API

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @metrics = Rubernetes::Observability::Metrics.new
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, metrics: @metrics,
                              service_cidrs: ["10.96.0.0/24"], node_port_range: 30_000..30_009)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}})
  end

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                  body: body && JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def value(name, **labels)
    text = @metrics.render_own
    found = text.lines.map(&:chomp).find do |entry|
      entry.start_with?("#{name}{", "#{name} ") && labels.all? do |k, v|
        entry.include?("#{k}=\"#{v}\"")
      end
    end
    found && found.split.last.to_i
  end

  def test_repair_recreates_missing_and_releases_leaked_ipaddresses
    response = call("POST", "/api/v1/namespaces/team/services", {"metadata" => {"name" => "web"}, "spec" => {"ports" => [{"port" => 80}]}})
    body = response.body.is_a?(String) ? JSON.parse(response.body) : response.body
    ip = body.dig("spec", "clusterIP")

    refute_nil ip
    assert_equal({"ip_errors" => {}, "port_errors" => {}, "released" => 0, "recreated" => 0}, @server.service_allocator.repair!)

    # The Service's IPAddress vanished: recreated.
    assert_equal 200, call("DELETE", "/apis/networking.k8s.io/v1/ipaddresses/#{ip}").status
    report = @server.service_allocator.repair!

    assert_equal 1, report["recreated"]
    assert_equal 1, report["ip_errors"]["repair"]
    assert_equal 200, call("GET", "/apis/networking.k8s.io/v1/ipaddresses/#{ip}").status

    # A managed IPAddress with no Service behind it: released.
    stray = {"metadata" => {"name" => "10.96.0.200", "labels" => {"ipaddress.kubernetes.io/managed-by" => "ipallocator.kubernetes.io"}},
             "spec" => {"parentRef" => {"group" => "", "resource" => "services", "namespace" => "team", "name" => "gone"}}}

    assert_equal 201, call("POST", "/apis/networking.k8s.io/v1/ipaddresses", stray).status
    report = @server.service_allocator.repair!

    assert_equal 1, report["released"]
    assert_equal 1, report["ip_errors"]["leak"]
    assert_equal 404, call("GET", "/apis/networking.k8s.io/v1/ipaddresses/10.96.0.200").status
    assert_equal 1, value("apiserver_clusterip_repair_ip_errors_total", type: "leak")
    assert_equal 1, value("apiserver_clusterip_repair_ip_errors_total", type: "repair")
    assert_equal 0, value("apiserver_clusterip_repair_reconcile_errors_total")
    assert_equal 0, value("apiserver_nodeport_repair_reconcile_errors_total")
  end

  def test_node_port_sweep_counts_duplicates_and_out_of_range
    call("POST", "/api/v1/namespaces/team/services",
         {"metadata" => {"name" => "a"}, "spec" => {"type" => "NodePort", "ports" => [{"port" => 80, "nodePort" => 30_001}]}})
    # Write a conflicting Service straight into the store, as a replay or an
    # operator edit could.
    store = @server.instance_variable_get(:@store)
    registry = @server.instance_variable_get(:@registry)
    resource = registry.resources.find { |candidate| candidate.resource == "services" && candidate.group.to_s.empty? }
    store.create(resource: resource, namespace: "team", object: {"apiVersion" => "v1", "kind" => "Service",
                                                                 "metadata" => {"name" => "b", "namespace" => "team", "uid" => "b-uid"},
                                                                 "spec" => {"type" => "NodePort", "clusterIP" => "10.96.0.9", "clusterIPs" => ["10.96.0.9"],
                                                                            "ports" => [{"port" => 80, "nodePort" => 30_001}, {"port" => 81, "nodePort" => 40_000}]}})
    report = @server.service_allocator.repair!

    assert_equal 1, report["port_errors"]["duplicate"]
    assert_equal 1, report["port_errors"]["outside_range"]
    assert_equal 1, report["ip_errors"]["repair"], "the hand-written Service had no IPAddress"
  end
end
