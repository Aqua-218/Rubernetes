# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/network"

class M4NetworkSecurityTest < Minitest::Test
  def test_netlink_nlmsg_error_is_never_treated_as_success
    adapter = Object.new
    adapter.define_singleton_method(:request) do |**request|
      [{type: Rubernetes::Network::Netlink::NLMSG_ERROR, error: -1, sequence: request.fetch(:sequence)}]
    end
    netlink = Rubernetes::Network::Netlink.new(adapter: adapter)
    assert_raises(Rubernetes::Network::NetlinkError) { netlink.link_set(name: "br0", up: true) }
  end

  def test_ipam_refuses_release_without_stop_confirmation_and_never_reuses_live_ip
    ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/24", ipv4_node_prefix: 24)
    lease = ipam.reserve(node: "node-a", pod_uid: "pod-a", sandbox_id: "sandbox-a", families: ["ipv4"])
    ipam.commit(lease)
    assert_raises(Rubernetes::Network::LeaseStateError) { ipam.release(lease) }
    other = ipam.reserve(node: "node-a", pod_uid: "pod-b", sandbox_id: "sandbox-b", families: ["ipv4"])

    refute_equal lease.ip, other.ip
  end

  def test_policy_adapter_failure_keeps_the_previous_atomic_revision
    adapter = Object.new
    calls = 0
    adapter.define_singleton_method(:atomic_swap) do |_snapshot|
      calls += 1
      raise "simulated map replacement failure" if calls == 2

      true
    end
    engine = Rubernetes::Network::PolicyEngine.new(adapter: adapter)
    policy = {"metadata" => {"name" => "deny", "namespace" => "default"}, "spec" => {"podSelector" => {}, "policyTypes" => ["Ingress"]}}
    engine.apply(policy)
    assert_raises(Rubernetes::Network::PolicyRevisionError) { engine.apply([policy], revision: 2) }
    assert_equal 1, engine.revision
  end

  def test_dns_rejects_spoofed_or_oversized_upstream_responses
    resolver = Rubernetes::Network::DNS::Resolver.new(upstream: "8.8.8.8", upstream_adapter: lambda do |packet:, **|
      {"packet" => [packet.byteslice(0, 2).unpack1("n") ^ 1].pack("n") + ("x" * 20)}
    end)
    assert_raises(Rubernetes::Network::DNSUpstreamError) { resolver.forward("\x01\x02query") }
  end

  def test_resolv_projection_rejects_symlink_target
    Dir.mktmpdir do |directory|
      target = File.join(directory, "resolv.conf")
      outside = File.join(directory, "outside")
      File.write(outside, "sentinel\n")
      File.symlink(outside, target)
      resolver = Rubernetes::Network::DNS::Resolver.new
      assert_raises(Rubernetes::Network::DNSProjectionError) { resolver.project_resolv_conf(path: target) }
      assert_equal "sentinel\n", File.read(outside)
    end
  end
end
