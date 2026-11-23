# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class ServiceAllocatorDryRunTest < Minitest::Test
  API = Rubernetes::API
  SERVICES = "/api/v1/namespaces/team/services"
  ADDRESSES = "/apis/networking.k8s.io/v1/ipaddresses"
  MERGE = "application/merge-patch+json"
  APPLY = "application/apply-patch+yaml"
  EXTERNAL_NAME = {"type" => "ExternalName", "externalName" => "example.test"}.freeze

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @metrics = Rubernetes::Observability::Metrics.new
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, metrics: @metrics,
                              service_cidrs: ["10.96.0.0/24", "fd00:d8:5::/112"])
    request("POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}})
  end

  def request(method, path, body = nil, dry_run: false, content_type: "application/json")
    options = []
    options << "dryRun=All" if dry_run
    options << "fieldManager=preview&force=true" if content_type == APPLY
    path = "#{path}?#{options.join("&")}" unless options.empty?
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                  body: body && JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def service(name, ip: nil, port: nil)
    {"kind" => "Service", "apiVersion" => "v1", "metadata" => {"name" => name, "namespace" => "team"},
     "spec" => {"type" => "NodePort", "clusterIP" => ip, "ports" => [{"port" => 80, "nodePort" => port}.compact]}.compact}
  end

  def spec(response)
    object = response.body.is_a?(String) ? JSON.parse(response.body) : response.body
    object.fetch("spec")
  end

  def allocation_metrics
    @metrics.render_own.lines.grep(/\Akube_apiserver_(?:clusterip|nodeport)_allocator_allocation/)
  end

  def test_service_traffic_fields_reject_incompatible_types_and_keep_local_health_port_stable
    invalid = {
      "cluster-node" => [{"type" => "ClusterIP"}, "spec.ports[0].nodePort"],
      "private" => [{"type" => "ClusterIP", "externalTrafficPolicy" => "Local"}, "spec.externalTrafficPolicy"],
      "health" => [{"type" => "LoadBalancer", "healthCheckNodePort" => 30_900}, "spec.healthCheckNodePort"],
      "internal" => [{"type" => "ClusterIP", "internalTrafficPolicy" => "Other"}, "spec.internalTrafficPolicy"]
    }
    invalid.each do |name, (fields, expected)|
      candidate = service(name, port: (30_901 if name == "cluster-node"))
      candidate["spec"].merge!(fields)
      response = request("POST", SERVICES, candidate)

      assert_equal 422, response.status
      assert_equal expected, response.body.dig("details", "causes", 0, "field")
    end
    local = service("local")
    local["spec"].merge!("type" => "LoadBalancer", "externalTrafficPolicy" => "Local", "healthCheckNodePort" => 30_905)

    assert_equal 201, request("POST", SERVICES, local).status
    path = "#{SERVICES}/local"
    changed = request("PATCH", path, {"spec" => {"healthCheckNodePort" => 30_906}}, content_type: MERGE)

    assert_equal 422, changed.status
    assert_equal "FieldValueForbidden", changed.body.dig("details", "causes", 0, "reason")
    omitted = request("PATCH", path, {"spec" => {"healthCheckNodePort" => nil}}, content_type: MERGE)

    assert_equal 30_905, spec(omitted)["healthCheckNodePort"]
    global = request("PATCH", path, {"spec" => {"externalTrafficPolicy" => "Cluster"}}, content_type: MERGE)

    assert_equal 200, global.status
    refute spec(global).key?("healthCheckNodePort")
  end

  def test_external_name_node_port_is_visible_without_consuming_a_port
    external = service("dns", port: 30_902)
    external["spec"].merge!(EXTERNAL_NAME)
    external["spec"]["internalTrafficPolicy"] = "Local"
    result = request("POST", SERVICES, external)

    assert_equal 201, result.status
    assert_equal 30_902, spec(result).dig("ports", 0, "nodePort")
    refute spec(request("GET", "#{SERVICES}/dns")).key?("internalTrafficPolicy")
    assert_equal 201, request("POST", SERVICES, service("node", port: 30_902)).status
    conflict = request("POST", SERVICES, service("conflict", port: 30_902))

    assert_equal 422, conflict.status
    assert_equal "spec.ports[0].nodePort", conflict.body.dig("details", "causes", 0, "field")
  end

  def test_dry_run_creates_preview_without_changing_service_or_allocator
    before = allocation_metrics
    2.times do |index|
      response = request("POST", SERVICES, service("explicit-#{index}", ip: "10.96.0.77", port: 30_108), dry_run: true)

      assert_equal 201, response.status
      assert_equal ["10.96.0.77", 30_108], [spec(response)["clusterIP"], spec(response).dig("ports", 0, "nodePort")]
      response = request("POST", SERVICES, service("dynamic-#{index}"), dry_run: true)

      assert_equal 201, response.status
      assert_equal ["10.96.0.0", 32_769], [spec(response)["clusterIP"], spec(response).dig("ports", 0, "nodePort")]
      assert_equal 404, request("GET", "#{SERVICES}/explicit-#{index}").status
      assert_equal 404, request("GET", "#{SERVICES}/dynamic-#{index}").status
    end
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.77").status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.0").status
    assert_equal before, allocation_metrics
    assert_equal 201, request("POST", SERVICES, service("real", ip: "10.96.0.77", port: 30_108)).status
    assert_equal 200, request("GET", "#{ADDRESSES}/10.96.0.77").status
  end

  def test_dry_run_put_create_and_apply_create_do_not_reserve_addresses
    before = allocation_metrics
    response = request("PUT", "#{SERVICES}/replace", service("replace", ip: "10.96.0.79", port: 30_110), dry_run: true)

    assert_equal 201, response.status
    assert_equal ["10.96.0.79", 30_110], [spec(response)["clusterIP"], spec(response).dig("ports", 0, "nodePort")]
    response = request("PATCH", "#{SERVICES}/apply", service("apply"), dry_run: true, content_type: APPLY)

    assert_equal 201, response.status
    assert_equal ["10.96.0.0", 32_769], [spec(response)["clusterIP"], spec(response).dig("ports", 0, "nodePort")]
    assert_equal 404, request("GET", "#{SERVICES}/replace").status
    assert_equal 404, request("GET", "#{SERVICES}/apply").status
    assert_equal 404, request("PUT", "#{SERVICES}/replace/status", service("replace"), dry_run: true).status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.79").status
    assert_equal before, allocation_metrics
  end

  def test_dry_run_external_name_updates_keep_live_address_and_node_port
    original = service("live", ip: "10.96.0.78", port: 30_109)

    assert_equal 201, request("POST", SERVICES, original).status
    before = allocation_metrics
    external = {"spec" => EXTERNAL_NAME}
    path = "#{SERVICES}/live"
    updates = [["PATCH", external, MERGE], ["PUT", original.merge(external), "application/json"],
               ["PATCH", original.merge(external), APPLY]]

    updates.each do |method, candidate, content_type|
      response = request(method, path, candidate, dry_run: true, content_type: content_type)

      assert_equal 200, response.status
      assert_equal "ExternalName", spec(response)["type"]
      refute spec(response).key?("clusterIP")
      assert_equal 200, request("GET", "#{ADDRESSES}/10.96.0.78").status
      assert_equal 30_109, spec(request("GET", path)).dig("ports", 0, "nodePort")
    end
    assert_equal 201, request("POST", SERVICES, service("same-ip", ip: "10.96.0.78", port: 30_115), dry_run: true).status
    assert_equal 422, request("POST", SERVICES, service("same-port", port: 30_109), dry_run: true).status
    assert_equal before, allocation_metrics
    assert_equal 200, request("PATCH", path, external, content_type: MERGE).status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.78").status
    assert_equal 201, request("POST", SERVICES, service("reuse", ip: "10.96.0.78", port: 30_109)).status
  end

  def test_invalid_dry_run_second_ip_does_not_release_the_existing_first_ip
    assert_equal 201, request("POST", SERVICES, service("live", ip: "10.96.0.78", port: 30_109)).status
    before = allocation_metrics
    candidate = service("dual-stack", ip: "10.96.0.78")
    candidate["spec"].merge!("clusterIPs" => ["10.96.0.78", "fd00:cafe::9"], "ipFamilyPolicy" => "RequireDualStack")

    assert_equal 422, request("POST", SERVICES, candidate, dry_run: true).status
    assert_equal 200, request("GET", "#{ADDRESSES}/10.96.0.78").status
    assert_equal 404, request("GET", "#{ADDRESSES}/fd00:cafe::9").status
    assert_equal before, allocation_metrics
  end

  def test_load_balancer_with_manual_node_ports_keeps_only_requested_ports_and_allocates_a_health_port
    candidate = service("manual")
    candidate["spec"].merge!("type" => "LoadBalancer", "allocateLoadBalancerNodePorts" => false, "externalTrafficPolicy" => "Local",
                             "ports" => [{"name" => "web", "port" => 80}, {"name" => "admin", "port" => 81, "nodePort" => 30_109}])
    created = request("POST", SERVICES, candidate)

    assert_equal 201, created.status
    assert_equal([nil, 30_109], spec(created).fetch("ports").map { |port| port["nodePort"] })
    assert_includes 30_000..32_767, spec(created).fetch("healthCheckNodePort")
    changed = JSON.parse(JSON.generate(created.body))
    changed["spec"]["ports"].last.delete("nodePort")
    updated = request("PUT", "#{SERVICES}/manual", changed)

    assert_equal 200, updated.status
    assert_equal([nil, nil], spec(updated).fetch("ports").map { |port| port["nodePort"] })
    assert_equal spec(created)["healthCheckNodePort"], spec(updated)["healthCheckNodePort"]
  end

  def test_two_protocols_share_the_requested_node_port_and_keep_it_when_the_named_port_changes
    candidate = service("dns")
    candidate["spec"]["ports"] = [{"name" => "tcp", "port" => 53}, {"name" => "udp", "port" => 53, "protocol" => "UDP", "nodePort" => 30_112}]
    created = request("POST", SERVICES, candidate)

    assert_equal 201, created.status
    assert_equal([30_112, 30_112], spec(created).fetch("ports").map { |port| port["nodePort"] })
    changed = JSON.parse(JSON.generate(created.body))
    changed["spec"]["ports"].each do |port|
      port.delete("nodePort")
      port["port"] = 54
    end
    updated = request("PUT", "#{SERVICES}/dns", changed)

    assert_equal 200, updated.status
    assert_equal([30_112, 30_112], spec(updated).fetch("ports").map { |port| port["nodePort"] })
  end

  def test_dry_run_previews_dual_stack_and_load_balancer_health_port
    before = allocation_metrics
    candidate = service("dual-stack", ip: "10.96.0.77")
    candidate["spec"].merge!("type" => "LoadBalancer", "externalTrafficPolicy" => "Local", "ipFamilyPolicy" => "RequireDualStack",
                             "clusterIPs" => ["10.96.0.77", "fd00:d8:5::ffff"],
                             "ports" => [{"name" => "first", "port" => 80, "nodePort" => 30_111}, {"name" => "second", "port" => 81}])
    response = request("POST", SERVICES, candidate, dry_run: true)

    assert_equal 201, response.status
    assert_equal ["10.96.0.77", "fd00:d8:5::ffff"], spec(response)["clusterIPs"]
    assert_equal([30_111, 30_112], spec(response)["ports"].map { |port| port["nodePort"] })
    assert_equal 30_113, spec(response)["healthCheckNodePort"]
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.77").status
    assert_equal 404, request("GET", "#{ADDRESSES}/fd00:d8:5::ffff").status
    assert_equal before, allocation_metrics
  end
end
