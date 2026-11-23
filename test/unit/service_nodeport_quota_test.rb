# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/security"

class ServiceNodePortQuotaTest < Minitest::Test
  Controller = Rubernetes::Controller
  Admission = Rubernetes::Security::Admission
  HARD = {"services" => "10", "count/services" => "10", "services.nodeports" => "10", "services.loadbalancers" => "10"}.freeze

  class QuotaContext
    attr_reader :quota

    def initialize(quota) = @quota = quota
    def list(_resource, _namespace) = [quota]
    def update(_resource, _namespace, _name, candidate, resource_version:) = @quota = candidate
  end

  def controller = Controller::ResourceQuotaController.new(store: nil)

  def usage(spec)
    controller.plan(quota, objects: [service(spec)]).status.fetch("used")
  end

  def node_ports(spec)
    usage(spec).fetch("services.nodeports")
  end

  def quota(used: HARD.transform_values { "0" })
    {"apiVersion" => "v1", "kind" => "ResourceQuota", "metadata" => {"name" => "q", "namespace" => "ns", "resourceVersion" => "1"},
     "spec" => {"hard" => HARD}, "status" => {"hard" => HARD, "used" => used}}
  end

  def service(spec)
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "s", "namespace" => "ns"}, "spec" => spec}
  end

  def quota_after_admission(spec, old: nil)
    context = QuotaContext.new(quota(used: old ? usage(old) : HARD.transform_values { "0" }))
    plugin = Admission::Plugins::ResourceQuota.new("ResourceQuota", context: context, config: {})
    attributes = Admission::Attributes.new(operation: old ? "UPDATE" : "CREATE", user: nil, group: "", version: "v1", resource: "services",
                                           kind: "Service", name: "s", namespace: "ns", object: service(spec), old_object: old && service(old))
    plugin.validate(attributes)
    context.quota.dig("status", "used")
  end

  def ports(count)
    Array.new(count) { |index| {"name" => "p#{index}", "port" => 80 + index} }
  end

  def test_a_nodeport_service_charges_one_per_port
    assert_equal "2", node_ports("type" => "NodePort", "ports" => ports(2))
  end

  # The allocation has not happened yet at admission time, which is exactly
  # when the quota has to be decided.
  def test_an_unallocated_nodeport_service_still_charges
    spec = {"type" => "NodePort", "ports" => [{"port" => 80}]}

    assert_equal "1", node_ports(spec)
  end

  def test_a_loadbalancer_charges_node_ports_too
    assert_equal "3", node_ports("type" => "LoadBalancer", "ports" => ports(3))
  end

  def test_a_loadbalancer_that_disables_automatic_allocation_counts_explicit_node_ports
    3.times do |explicit|
      selected = ports(3)
      explicit.times { |index| selected[index]["nodePort"] = 30_000 + index }
      selected.last["nodePort"] = 0
      spec = {"type" => "LoadBalancer", "ports" => selected, "allocateLoadBalancerNodePorts" => false}
      expected = {"services.nodeports" => explicit.to_s, "services.loadbalancers" => "1", "services" => "1", "count/services" => "1"}

      assert_equal expected, usage(spec)
      assert_equal expected, quota_after_admission(spec)
    end
  end

  def test_a_clusterip_service_charges_nothing
    assert_equal "0", node_ports("type" => "ClusterIP", "ports" => ports(4))
    assert_equal "0", node_ports("ports" => ports(4))
  end

  def test_a_service_with_no_ports_charges_nothing
    assert_equal "0", node_ports("type" => "NodePort")
  end

  def test_an_update_charges_only_new_usage_when_a_service_changes_type_or_adds_a_port
    cluster_ip = {"type" => "ClusterIP", "ports" => ports(1)}
    node_port = cluster_ip.merge("type" => "NodePort")
    load_balancer = node_port.merge("type" => "LoadBalancer", "ports" => ports(2))

    assert_equal usage(node_port), quota_after_admission(node_port, old: cluster_ip)
    assert_equal usage(load_balancer), quota_after_admission(load_balancer, old: node_port)

    selected = ports(3)
    selected[0]["nodePort"] = 30_000
    old = {"type" => "LoadBalancer", "ports" => selected, "allocateLoadBalancerNodePorts" => false}
    selected = selected.map(&:dup)
    selected[2]["nodePort"] = 30_002
    current = old.merge("ports" => selected)

    assert_equal usage(current), quota_after_admission(current, old: old)
  end

  def test_the_controller_replenishes_quota_for_updates_that_release_service_usage
    load_balancer = {"type" => "LoadBalancer", "ports" => ports(2)}
    fewer_ports = load_balancer.merge("ports" => ports(1))
    node_port = load_balancer.merge("type" => "NodePort")

    refute controller.skip_event?(service(fewer_ports), service(load_balancer), :update)
    refute controller.skip_event?(service(node_port), service(load_balancer), :update)
    assert controller.skip_event?(service(load_balancer), service(fewer_ports), :update)
    assert controller.skip_event?(service(load_balancer), service(load_balancer), :update)
  end
end
