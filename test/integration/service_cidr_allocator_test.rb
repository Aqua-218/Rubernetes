# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class ServiceCIDRAllocatorTest < Minitest::Test
  API = Rubernetes::API
  LABELS = Rubernetes::Support::ServiceCIDR
  SERVICES = "/api/v1/namespaces/default/services"
  CIDRS = "/apis/networking.k8s.io/v1/servicecidrs"
  ADDRESSES = "/apis/networking.k8s.io/v1/ipaddresses"
  IPV4 = "10.96.0.0/30"
  IPV6 = "fd00:96::/126"
  ADDED_V4 = "203.0.113.0/28"
  MERGE = "application/merge-patch+json"
  APPLY = "application/apply-patch+yaml"

  def start_server(cidrs = [IPV4], bootstrap: true)
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @metrics = Rubernetes::Observability::Metrics.new
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, metrics: @metrics, service_cidrs: cidrs)
    @server.service_allocator.bootstrap! if bootstrap
  end

  def test_static_address_requires_a_ready_pool_but_can_use_any_ready_overlap
    start_server
    create_cidr("a-narrow", "203.0.113.4/30")
    create_cidr("z-wide", ADDED_V4)
    readiness("z-wide", false)

    assert_equal 422, create_service("network-blocked", "203.0.113.4").status
    assert_equal 422, create_service("broadcast-blocked", "203.0.113.7").status
    readiness("z-wide", true)

    assert_equal 201, create_service("network-in-narrow", "203.0.113.4").status
    assert_equal 201, create_service("broadcast-in-narrow", "203.0.113.7").status
    address = request("GET", "#{ADDRESSES}/203.0.113.7").body

    assert_equal({LABELS::MANAGED_BY_LABEL => LABELS::MANAGER, LABELS::FAMILY_LABEL => "IPv4"}, address.dig("metadata", "labels"))
    assert_equal "broadcast-in-narrow", address.dig("spec", "parentRef", "name")
  end

  def test_unready_or_deleting_default_does_not_get_a_configuration_fallback
    start_server
    readiness("kubernetes", false)

    assert_equal 422, create_service("unready", "10.96.0.1").status
    create_cidr("also-default", IPV4, finalizers: ["example.com/hold"])

    assert_equal 201, create_service("other-owner", "10.96.0.1").status
    assert_equal 200, request("DELETE", "#{CIDRS}/also-default").status
    assert_equal 422, create_service("deleting-owner", "10.96.0.2").status
    assert_equal 200, request("GET", "#{ADDRESSES}/10.96.0.1").status
    assert_equal 200, request("DELETE", "#{CIDRS}/kubernetes").status
    assert_equal 422, create_service("missing-default", "10.96.0.2").status
  end

  def test_dynamic_allocation_falls_back_to_next_ready_pool_when_small_primary_is_full
    start_server
    create_cidr("second", "203.0.113.4/30")

    first = create_service("first")
    second = create_service("second")

    assert_equal [201, 201], [first.status, second.status]
    assert_equal %w[10.96.0.1 10.96.0.2], [cluster_ip(first), cluster_ip(second)].sort
    next_ip = cluster_ip(create_service("third"))
    last_ip = cluster_ip(create_service("fourth"))

    assert_equal %w[203.0.113.5 203.0.113.6], [next_ip, last_ip].sort
    exhausted = create_service("full")

    assert_equal 500, exhausted.status
    assert_equal "InternalError", exhausted.body.fetch("reason")
  end

  def test_dry_run_uses_active_pools_without_reservations_and_disallows_other_families
    start_server
    readiness("kubernetes", false)
    create_cidr("other", ADDED_V4)
    create_cidr("unsupported", IPV6)

    preview = create_service("preview", "203.0.113.14", dry_run: true)

    assert_equal 201, preview.status
    assert_equal "203.0.113.14", cluster_ip(preview)
    assert_equal "203.0.113.0", cluster_ip(create_service("dynamic-dry", nil, dry_run: true))
    assert_equal 422, create_service("unsupported-family", "fd00:96::2").status
    assert_equal 422, create_service("unready-dry", "10.96.0.1", dry_run: true).status
    assert_empty request("GET", ADDRESSES).body.fetch("items")
  end

  def test_simple_server_without_bootstrap_retains_its_configured_pool
    start_server(bootstrap: false)

    assert_equal 201, create_service("standalone", "10.96.0.1").status
    create_cidr("other", ADDED_V4)

    assert_equal 201, create_service("configured", "10.96.0.2").status
    assert_equal 201, create_service("additional", "203.0.113.14").status
  end

  def test_repair_migrates_old_managed_labels_and_recovers_addresses_in_added_ranges
    start_server
    create_cidr("other", ADDED_V4)

    assert_equal 201, create_service("legacy", "203.0.113.14").status
    legacy_labels = {LABELS::MANAGED_BY_LABEL => LABELS::LEGACY_MANAGER, LABELS::FAMILY_LABEL => nil, "local.example/label" => "keep"}
    path = "#{ADDRESSES}/203.0.113.14"
    legacy = request("PATCH", path, {"metadata" => {"labels" => legacy_labels}}, content_type: MERGE)

    assert_equal 200, legacy.status
    legacy_uid = legacy.body.dig("metadata", "uid")
    readiness("other", false)

    assert_empty @server.service_allocator.repair!["ip_errors"]
    labels = legacy_labels.merge(LABELS::MANAGED_BY_LABEL => LABELS::MANAGER, LABELS::FAMILY_LABEL => "IPv4")
    migrated = request("GET", path).body

    assert_equal labels, migrated.dig("metadata", "labels")
    assert_equal legacy_uid, migrated.dig("metadata", "uid")
    assert_equal 200, request("DELETE", path).status
    assert_equal 1, @server.service_allocator.repair!["recreated"]
    assert_equal 200, request("GET", path).status
    assert_includes @metrics.render_own, %(kube_apiserver_clusterip_allocator_allocated_ips{cidr="#{ADDED_V4}"} 1)
    assert_equal 200, request("DELETE", "#{CIDRS}/other").status
    assert_equal 1, @server.service_allocator.repair!.dig("ip_errors", "outside_range")
    assert_equal 200, request("GET", path).status
    refute_includes @metrics.render_own, %(kube_apiserver_clusterip_allocator_allocated_ips{cidr="#{ADDED_V4}"})
  end

  def test_failed_creates_release_only_their_new_reservations
    start_server([IPV4, IPV6])
    bound = service("bound", "10.96.0.1", "type" => "NodePort", "ports" => [{"port" => 80, "nodePort" => 30_001}])

    assert_equal 201, request("POST", SERVICES, bound).status
    candidate = service("invalid", "10.96.0.2", "type" => "NodePort", "ports" => [{"port" => 80, "nodePort" => 30_001}])

    assert_equal 422, request("POST", SERVICES, candidate).status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.2").status
    assert_equal 409, create_service("bound").status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.2").status
    out_of_range = service("dual", "10.96.0.2", "clusterIPs" => ["10.96.0.2", "fd00:cafe::2"], "ipFamilyPolicy" => "RequireDualStack")

    assert_equal 422, request("POST", SERVICES, out_of_range).status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.2").status
    assert_equal 200, request("GET", "#{ADDRESSES}/10.96.0.1").status
  end

  def test_storage_failures_roll_back_apply_create_and_update_transitions
    start_server
    fail_service_write(:create)
    applied = request("PATCH", "#{SERVICES}/apply-failed", service("apply-failed", "10.96.0.1"),
                      content_type: APPLY, query: "fieldManager=test")

    assert_equal 409, applied.status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.1").status
    stop_failing_service_write(:create)
    old = service("change", nil, "type" => "ExternalName", "externalName" => "old.example")
    created = request("POST", SERVICES, old)

    assert_equal 201, created.status
    fail_service_write(:update)
    changed = service("change", "10.96.0.1")
    changed["metadata"]["resourceVersion"] = created.body.dig("metadata", "resourceVersion")

    assert_equal 409, request("PUT", "#{SERVICES}/change", changed).status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.1").status
    stop_failing_service_write(:update)

    assert_equal 200, request("PUT", "#{SERVICES}/change", changed).status
    fail_service_write(:update)

    assert_equal 409, request("PATCH", "#{SERVICES}/change", {"spec" => {"type" => "ExternalName", "externalName" => "next.example"}},
                              content_type: MERGE).status
    assert_equal 200, request("GET", "#{ADDRESSES}/10.96.0.1").status
    stop_failing_service_write(:update)

    assert_equal 200, request("PATCH", "#{SERVICES}/change", {"spec" => {"type" => "ExternalName", "externalName" => "next.example"}},
                              content_type: MERGE).status
    assert_equal 404, request("GET", "#{ADDRESSES}/10.96.0.1").status
  end

  def test_dual_stack_update_keeps_old_ip_in_draining_pool_and_releases_removed_ip_after_commit
    start_server([IPV4, IPV6])
    create_cidr("secondary", "fd00:113::/126")
    create_cidr("too-wide", "fd10:113::/48")

    assert_equal 422, create_service("unsupported-ipv6-prefix", "fd10:113::2").status
    assert_equal 201, create_service("grow", "10.96.0.1").status
    readiness("kubernetes", false)
    dual = {"spec" => {"clusterIPs" => ["10.96.0.1", "fd00:113::2"], "ipFamilyPolicy" => "RequireDualStack", "ipFamilies" => %w[IPv4 IPv6]}}
    expanded = request("PATCH", "#{SERVICES}/grow", dual, content_type: MERGE)

    assert_equal 200, expanded.status, expanded.body.inspect
    assert_equal ["10.96.0.1", "fd00:113::2"], expanded.body.dig("spec", "clusterIPs")
    assert_equal "IPv6", request("GET", "#{ADDRESSES}/fd00:113::2").body.dig("metadata", "labels", LABELS::FAMILY_LABEL)
    reduced = request("PATCH", "#{SERVICES}/grow", {"spec" => {"ipFamilyPolicy" => "SingleStack"}}, content_type: MERGE)

    assert_equal 200, reduced.status, reduced.body.inspect
    assert_equal ["10.96.0.1"], reduced.body.dig("spec", "clusterIPs")
    assert_equal 200, request("GET", "#{ADDRESSES}/10.96.0.1").status
    assert_equal 404, request("GET", "#{ADDRESSES}/fd00:113::2").status
  end

  def test_rollback_cannot_delete_a_newer_reservation_or_share_an_uncommitted_ip
    start_server
    entered = false
    competitor = nil
    target = "#{ADDRESSES}/10.96.0.1"
    fail_service_write(:create) do
      next if entered

      entered = true
      competitor = create_service("concurrent", "10.96.0.1")
      request("PATCH", target, {"metadata" => {"labels" => {"other.example/replacement" => "true"}}}, content_type: MERGE)
    end

    assert_equal 409, create_service("concurrent", "10.96.0.1").status
    assert_equal 422, competitor.status
    assert_equal "true", request("GET", target).body.dig("metadata", "labels", "other.example/replacement")
  end

  private

  def request(method, path, body = nil, content_type: "application/json", query: nil)
    path = "#{path}?#{query}" if query
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type}, body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def create_cidr(name, range, finalizers: [])
    object = {"apiVersion" => "networking.k8s.io/v1", "kind" => "ServiceCIDR", "metadata" => {"name" => name, "finalizers" => finalizers},
              "spec" => {"cidrs" => [range]}}
    response = request("POST", CIDRS, object)

    assert_equal 201, response.status, response.body.inspect
  end

  def readiness(name, ready)
    condition = {"type" => "Ready", "status" => ready ? "True" : "False", "reason" => "Test",
                 "message" => "Status for this test", "lastTransitionTime" => "2026-11-18T00:00:00Z"}
    response = request("PATCH", "#{CIDRS}/#{name}/status", {"status" => {"conditions" => [condition]}}, content_type: MERGE)

    assert_equal 200, response.status, response.body.inspect
  end

  def service(name, ip = nil, **extra)
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => name},
     "spec" => {"clusterIP" => ip, "ports" => [{"port" => 80}]}.compact.merge(extra)}
  end

  def create_service(name, ip = nil, dry_run: false)
    request("POST", SERVICES, service(name, ip), query: ("dryRun=All" if dry_run))
  end

  def cluster_ip(response)
    response.body.dig("spec", "clusterIP")
  end

  def fail_service_write(method, &before_failure)
    store = @server.store
    original = store.method(method)
    store.define_singleton_method(method) do |resource:, **options|
      if resource.kind == "Service"
        before_failure&.call
        raise method == :create ? API::MemoryStore::AlreadyExists : API::MemoryStore::Conflict
      end

      original.call(resource: resource, **options)
    end
  end

  def stop_failing_service_write(method)
    @server.store.singleton_class.remove_method(method)
  end
end
