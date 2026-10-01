# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network/host_forward"

# A Pod network is only as good as the host's forward path: where the filter
# FORWARD policy is DROP -- the norm on any host already running a cluster --
# cross-node Pod traffic is discarded with no diagnostic beyond a timeout.
class NetworkHostForwardTest < Minitest::Test
  HostForward = Rubernetes::Network::HostForward

  class FakeRunner
    attr_reader :calls

    def initialize(present: [], refuse: [])
      @calls = []
      @present = present
      @refuse = refuse
    end

    def call(binary, *arguments)
      @calls << [binary, *arguments]
      return @present.include?(arguments) if arguments.first == "-C"
      return false if @refuse.include?(binary)

      true
    end
  end

  def test_installs_accept_rules_for_each_cidr_in_both_directions
    runner = FakeRunner.new
    result = HostForward.new(runner: runner).ensure!(["10.240.0.0/16"])

    assert_equal 2, result.installed.length
    assert_empty result.skipped
    inserts = runner.calls.select { |call| call[1] == "-I" }

    assert_equal 2, inserts.length
    assert_includes inserts, ["iptables", "-I", "FORWARD", "1", "-s", "10.240.0.0/16", "-j", "ACCEPT"]
    assert_includes inserts, ["iptables", "-I", "FORWARD", "1", "-d", "10.240.0.0/16", "-j", "ACCEPT"]
    # ipMasq: Pod egress to anything outside the cluster leaves as the node.
    nat = runner.calls.select { |call| call[1] == "-t" && call[2] == "nat" }

    refute_empty nat
    # One rule per destination (iptables takes a single -d): cluster CIDRs
    # and multicast are accepted in the chain, the rest masqueraded, and
    # POSTROUTING jumps there for the Pod CIDR.
    assert(nat.any? do |call|
      call.include?("RUBERNETES-POSTROUTING") && call.include?("-d") && call.include?("10.240.0.0/16") && call.include?("ACCEPT")
    end)
    assert(nat.any? { |call| call.include?("RUBERNETES-POSTROUTING") && call.include?("MASQUERADE") })
    assert(nat.any? do |call|
      call.include?("POSTROUTING") && call.include?("-s") && call.include?("10.240.0.0/16") && call.last == "RUBERNETES-POSTROUTING"
    end)
  end

  def test_an_existing_rule_is_not_installed_twice
    present = [["-C", "FORWARD", "-s", "10.240.0.0/16", "-j", "ACCEPT"],
               ["-C", "FORWARD", "-d", "10.240.0.0/16", "-j", "ACCEPT"]]
    runner = FakeRunner.new(present: present)
    result = HostForward.new(runner: runner).ensure!(["10.240.0.0/16"])

    assert_empty result.installed
    assert_equal 3, result.already_present.length, "two FORWARD accepts and the egress masquerade"
    refute(runner.calls.any? { |call| call[1] == "-I" })
  end

  def test_ipv6_cidrs_use_ip6tables
    runner = FakeRunner.new
    HostForward.new(runner: runner).ensure!(["fd00:10:244::/56"])

    assert(runner.calls.all? { |call| call.first == "ip6tables" })
  end

  # A host that has no iptables, or refuses the rule, must not take the node
  # down: Pods that never cross a node boundary work regardless.
  def test_a_refusing_host_is_reported_rather_than_raising
    runner = FakeRunner.new(refuse: %w[iptables])
    result = HostForward.new(runner: runner).ensure!(["10.240.0.0/16"])

    assert_empty result.installed
    assert_equal 3, result.skipped.length, "two FORWARD accepts and the egress masquerade"
  end
end
