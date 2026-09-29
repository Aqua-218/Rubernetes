# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# staging/src/k8s.io/endpointslice: one EndpointSlice set per address type
# the Service supports (getAddressTypesForService), each endpoint carrying
# the Pod's addresses of that family (getEndpointAddresses).  Taking only
# the first Pod IP gave every Service of a dual-stack cluster IPv4 slices,
# IPv6-only ones included, which then had no endpoints at all (found on the
# linux-amd64-dualstack-native profile, 2026-09-27).
class EndpointSliceDualStackTest < Minitest::Test
  Controller = Rubernetes::Controller::EndpointSliceController
  Endpoints = Rubernetes::Controller::EndpointsController

  def service(families:, cluster_ip: "10.96.0.10", policy: nil)
    spec = {"selector" => {"app" => "web"}, "ports" => [{"name" => "http", "port" => 80, "protocol" => "TCP"}]}
    spec["ipFamilies"] = families unless families.nil?
    spec["clusterIP"] = cluster_ip unless cluster_ip.nil?
    spec["ipFamilyPolicy"] = policy if policy
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "svc-uid"}, "spec" => spec}
  end

  def pod(name, ips)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid", "labels" => {"app" => "web"}},
     "spec" => {"nodeName" => "worker-0", "containers" => [{"name" => "c", "ports" => [{"containerPort" => 80}]}]},
     "status" => {"podIP" => ips.first, "podIPs" => ips.map { |ip| {"ip" => ip} }, "phase" => "Running",
                  "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  DUAL_POD = %w[10.240.0.2 fd00:d8::2].freeze

  def slices(result)
    result.operations.select { |operation| operation.action == :create }.map(&:object)
  end

  def reconcile(svc, pods:, slices: [])
    Controller.new.reconcile(svc, pods: pods, endpoint_slices: slices, apply: false)
  end

  def test_a_dual_stack_service_gets_one_slice_per_family
    created = slices(reconcile(service(families: %w[IPv4 IPv6], policy: "RequireDualStack"), pods: [pod("p", DUAL_POD)]))

    assert_equal %w[IPv4 IPv6], created.map { |slice| slice["addressType"] }.sort
    by_type = created.to_h { |slice| [slice["addressType"], slice["endpoints"].flat_map { |endpoint| endpoint["addresses"] }] }
    assert_equal ["10.240.0.2"], by_type["IPv4"]
    assert_equal ["fd00:d8::2"], by_type["IPv6"]
  end

  def test_an_ipv6_only_service_in_a_dual_stack_cluster_gets_an_ipv6_slice
    created = slices(reconcile(service(families: %w[IPv6], cluster_ip: "fd00:d8:5::10"), pods: [pod("p", DUAL_POD)]))

    assert_equal ["IPv6"], created.map { |slice| slice["addressType"] }
    assert_equal ["fd00:d8::2"], created.first["endpoints"].flat_map { |endpoint| endpoint["addresses"] }
  end

  def test_a_pod_without_an_address_of_a_family_is_absent_from_that_family
    created = slices(reconcile(service(families: %w[IPv4 IPv6], policy: "RequireDualStack"),
                               pods: [pod("dual", DUAL_POD), pod("v4only", ["10.240.0.3"])]))

    by_type = created.to_h { |slice| [slice["addressType"], slice["endpoints"].flat_map { |endpoint| endpoint["addresses"] }.sort] }
    assert_equal %w[10.240.0.2 10.240.0.3], by_type["IPv4"]
    assert_equal ["fd00:d8::2"], by_type["IPv6"]
  end

  def test_without_ip_families_the_cluster_ip_family_decides
    created = slices(reconcile(service(families: nil, cluster_ip: "fd00:d8:5::10"), pods: [pod("p", DUAL_POD)]))

    assert_equal ["IPv6"], created.map { |slice| slice["addressType"] }
  end

  def test_a_headless_service_without_ip_families_assumes_both
    created = slices(reconcile(service(families: nil, cluster_ip: "None"), pods: [pod("p", DUAL_POD)]))

    assert_equal %w[IPv4 IPv6], created.map { |slice| slice["addressType"] }.sort
  end

  def test_a_dual_stack_service_without_pods_gets_a_placeholder_per_family
    created = slices(reconcile(service(families: %w[IPv4 IPv6], policy: "RequireDualStack"), pods: []))

    assert_equal %w[IPv4 IPv6], created.map { |slice| slice["addressType"] }.sort
    assert created.all? { |slice| Array(slice["endpoints"]).empty? && Array(slice["ports"]).empty? }
  end

  def test_a_slice_of_a_family_the_service_dropped_is_deleted
    first = slices(reconcile(service(families: %w[IPv4 IPv6], policy: "RequireDualStack"), pods: [pod("p", DUAL_POD)]))
    result = reconcile(service(families: %w[IPv4]), pods: [pod("p", DUAL_POD)], slices: first)

    deleted = result.operations.select { |operation| operation.action == :delete }.map(&:object)
    assert_equal ["IPv6"], deleted.map { |slice| slice["addressType"] }
  end

  # pkg/controller/endpoint/endpoints_controller.go: the legacy Endpoints
  # object carries the Pod IP of the Service's primary family.
  def test_legacy_endpoints_use_the_primary_family_pod_ip
    result = Endpoints.new.reconcile(service(families: %w[IPv6], cluster_ip: "fd00:d8:5::10"), pods: [pod("p", DUAL_POD)], apply: false)
    endpoints = result.operations.find { |operation| operation.action == :create }.object

    assert_equal ["fd00:d8::2"], endpoints["subsets"].flat_map { |subset| subset["addresses"].map { |address| address["ip"] } }
  end
end
