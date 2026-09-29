# frozen_string_literal: true

# pkg/registry/core/service/storage/alloc.go initIPFamilyFields and the
# related validation, through the API server on a dual-stack and on a
# single-stack cluster.  The oracle for these cases is
# tools/differential/service_ip_family_differential.rb (kube-apiserver
# v1.36.2 in dual-stack mode); this test pins what it proved.
require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/bootstrap"

class ServiceIPFamilyDefaultingTest < Minitest::Test
  API = Rubernetes::API
  DUAL = ["10.96.0.0/24", "fd00:d8:5::/112"].freeze
  SINGLE = ["10.96.0.0/24"].freeze

  def server(cidrs)
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    server = API::Server.new(registry: registry, store: API::MemoryStore.new, service_cidrs: cidrs, node_port_range: 30_000..30_009)
    call(server, "POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}})
    server
  end

  def call(server, method, path, body)
    server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                 body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def create(server, name, spec)
    response = call(server, "POST", "/api/v1/namespaces/team/services",
                    {"metadata" => {"name" => name}, "spec" => {"ports" => [{"port" => 80}]}.merge(spec)})
    body = response.body.is_a?(String) ? JSON.parse(response.body) : response.body
    [response.status, body["spec"] || {}, body["message"].to_s]
  end

  SELECTOR = {"selector" => {"app" => "x"}}.freeze

  def test_headless_selectorless_defaults_to_dual_stack_on_a_dual_stack_cluster
    status, spec, = create(server(DUAL), "hl", {"clusterIP" => "None"})
    assert_equal 201, status
    assert_equal "RequireDualStack", spec["ipFamilyPolicy"]
    assert_equal %w[IPv4 IPv6], spec["ipFamilies"]
    assert_equal ["None"], spec["clusterIPs"]
  end

  def test_headless_selectorless_carries_both_families_even_on_a_single_stack_cluster
    status, spec, = create(server(SINGLE), "hl", {"clusterIP" => "None"})
    assert_equal 201, status
    assert_equal "RequireDualStack", spec["ipFamilyPolicy"]
    assert_equal %w[IPv4 IPv6], spec["ipFamilies"]
  end

  def test_headless_selectorless_single_stack_when_asked
    status, spec, = create(server(DUAL), "hl", {"clusterIP" => "None", "ipFamilyPolicy" => "SingleStack"})
    assert_equal 201, status
    assert_equal ["IPv4"], spec["ipFamilies"]
    status, spec, = create(server(DUAL), "hl6", {"clusterIP" => "None", "ipFamilies" => ["IPv6"]})
    assert_equal 201, status
    assert_equal %w[IPv6 IPv4], spec["ipFamilies"]
  end

  def test_headless_with_selector_defaults_to_single_stack_primary
    status, spec, = create(server(DUAL), "hl", SELECTOR.merge("clusterIP" => "None"))
    assert_equal 201, status
    assert_equal "SingleStack", spec["ipFamilyPolicy"]
    assert_equal ["IPv4"], spec["ipFamilies"]
    status, spec, = create(server(DUAL), "hlp", SELECTOR.merge("clusterIP" => "None", "ipFamilyPolicy" => "PreferDualStack"))
    assert_equal 201, status
    assert_equal %w[IPv4 IPv6], spec["ipFamilies"]
  end

  def test_headless_with_selector_require_dual_stack_needs_a_dual_stack_cluster
    status, _, message = create(server(SINGLE), "hl", SELECTOR.merge("clusterIP" => "None", "ipFamilyPolicy" => "RequireDualStack"))
    assert_equal 422, status
    assert_includes message, "this cluster is not configured for dual-stack services"
  end

  def test_headfull_defaults_and_completion
    dual = server(DUAL)
    status, spec, = create(dual, "plain", SELECTOR)
    assert_equal 201, status
    assert_equal ["SingleStack", ["IPv4"], 1], [spec["ipFamilyPolicy"], spec["ipFamilies"], spec["clusterIPs"].length]
    status, spec, = create(dual, "prefer", SELECTOR.merge("ipFamilyPolicy" => "PreferDualStack"))
    assert_equal 201, status
    assert_equal [%w[IPv4 IPv6], 2], [spec["ipFamilies"], spec["clusterIPs"].length]
    status, spec, = create(dual, "v6-require", SELECTOR.merge("ipFamilies" => ["IPv6"], "ipFamilyPolicy" => "RequireDualStack"))
    assert_equal 201, status
    assert_equal %w[IPv6 IPv4], spec["ipFamilies"]
    assert spec["clusterIPs"].first.include?(":"), "the primary cluster IP follows the first family"
  end

  def test_single_stack_cluster_keeps_single_family_under_prefer_dual_stack
    status, spec, = create(server(SINGLE), "prefer", SELECTOR.merge("ipFamilyPolicy" => "PreferDualStack"))
    assert_equal 201, status
    assert_equal ["PreferDualStack", ["IPv4"]], [spec["ipFamilyPolicy"], spec["ipFamilies"]]
  end

  def test_two_families_without_a_policy_are_rejected
    status, _, message = create(server(DUAL), "both", SELECTOR.merge("ipFamilies" => %w[IPv4 IPv6]))
    assert_equal 422, status
    assert_includes message, "must be 'RequireDualStack' or 'PreferDualStack' when multiple IP families are specified"
  end

  def test_cluster_ips_without_cluster_ip_are_rejected
    status, _, message = create(server(DUAL), "ips", SELECTOR.merge("clusterIPs" => ["10.96.0.77", "fd00:d8:5::78"]))
    assert_equal 422, status
    assert_includes message, "must be empty when `clusterIP` is not specified"
  end

  def test_family_fields_are_forbidden_on_external_name
    status, _, message = create(server(DUAL), "ext", {"type" => "ExternalName", "externalName" => "example.com",
                                                      "ipFamilies" => ["IPv4"], "ipFamilyPolicy" => "SingleStack"})
    assert_equal 422, status
    assert_includes message, "spec.ipFamilies: Forbidden: may not be set for ExternalName services"
    assert_includes message, "spec.ipFamilyPolicy: Forbidden: may not be set for ExternalName services"
    status, spec, = create(server(DUAL), "ext-ok", {"type" => "ExternalName", "externalName" => "example.com"})
    assert_equal 201, status
    assert_nil spec["ipFamilies"]
  end
end
