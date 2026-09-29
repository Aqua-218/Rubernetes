# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# quota/v1/evaluator/core/services.go charges node ports by the number of
# SERVICE PORTS -- "node port quota charging is based on service ports" -- not
# by the ports that already carry an allocated nodePort.  A client never sets
# nodePort; the API server allocates it.  Counting allocated ones charged every
# new Service zero, so a services.nodeports quota could never be exceeded and
# "[sig-api-machinery] ResourceQuota should create a ResourceQuota and capture
# the life of a service" saw its LoadBalancer accepted where it must be
# refused.
class ServiceNodePortQuotaTest < Minitest::Test
  Controller = Rubernetes::Controller

  def controller = Controller::ResourceQuotaController.new(store: nil)

  def usage(spec)
    controller.send(:service_node_port_usage, spec)
  end

  def ports(count)
    Array.new(count) { |index| {"name" => "p#{index}", "port" => 80 + index} }
  end

  def test_a_nodeport_service_charges_one_per_port
    assert_equal(2, usage("type" => "NodePort", "ports" => ports(2)))
  end

  # The allocation has not happened yet at admission time, which is exactly
  # when the quota has to be decided.
  def test_an_unallocated_nodeport_service_still_charges
    spec = {"type" => "NodePort", "ports" => [{"port" => 80}]}

    assert_equal(1, usage(spec))
  end

  def test_a_loadbalancer_charges_node_ports_too
    assert_equal(3, usage("type" => "LoadBalancer", "ports" => ports(3)))
  end

  # ...unless it asked not to allocate them.
  def test_a_loadbalancer_that_allocates_none_charges_none
    assert_equal(0, usage("type" => "LoadBalancer", "ports" => ports(3),
                          "allocateLoadBalancerNodePorts" => false))
  end

  def test_a_clusterip_service_charges_nothing
    assert_equal(0, usage("type" => "ClusterIP", "ports" => ports(4)))
    assert_equal(0, usage("ports" => ports(4)))
  end

  def test_a_service_with_no_ports_charges_nothing
    assert_equal(0, usage("type" => "NodePort"))
  end
end
