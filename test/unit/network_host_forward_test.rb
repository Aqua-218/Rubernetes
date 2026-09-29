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
  end

  def test_an_existing_rule_is_not_installed_twice
    present = [["-C", "FORWARD", "-s", "10.240.0.0/16", "-j", "ACCEPT"],
               ["-C", "FORWARD", "-d", "10.240.0.0/16", "-j", "ACCEPT"]]
    runner = FakeRunner.new(present: present)
    result = HostForward.new(runner: runner).ensure!(["10.240.0.0/16"])

    assert_empty result.installed
    assert_equal 2, result.already_present.length
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
    assert_equal 2, result.skipped.length
  end
end
