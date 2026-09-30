# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

class M4NetworkPropertyTest < Minitest::Test
  def test_many_pods_never_share_a_committed_ip
    ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/28", ipv4_node_prefix: 28)
    leases = Array.new(12) do |index|
      reserved = ipam.reserve(node: "node-a", pod_uid: "pod-#{index}", sandbox_id: "sandbox-#{index}", families: ["ipv4"])
      ipam.commit(reserved)
    end
    addresses = leases.map(&:ip)

    assert_equal addresses.length, addresses.uniq.length
  end

  def test_dual_stack_failure_does_not_leave_a_partial_reservation
    ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/30", ipv6_cidr: "fd00::/128",
                                         ipv4_node_prefix: 30, ipv6_node_prefix: 128)
    assert_raises(Rubernetes::Network::LeaseUnavailable) do
      ipam.reserve(node: "node-a", pod_uid: "pod-a", sandbox_id: "sandbox-a", dual_stack: true)
    end
    assert_empty ipam.leases(include_released: true)
  end

  def test_overlay_route_and_fdb_diff_is_idempotent
    overlay = Rubernetes::Network::Overlay.new(backend: :vxlan)
    current = {"routes" => [{"destination" => "10.1.0.0/24"}], "fdb" => [{"mac" => "aa:bb:cc:dd:ee:01"}]}
    desired = {"routes" => [{"destination" => "10.1.0.0/24"}], "fdb" => [{"mac" => "aa:bb:cc:dd:ee:01"}]}
    diff = overlay.diff(current: current, desired: desired, revision: 7)

    assert_empty diff.fetch("routes")
    assert_empty diff.fetch("fdb")
  end
end
