# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# containerPort.hostPort was validated by the API server and used by the
# scheduler's NodePorts filter, but the node never programmed the mapping, so a
# Pod with a hostPort was scheduled and then unreachable.  Conformance:
# "[sig-network] HostPort validates that there is no conflict between pods with
# same hostPort but different hostIP and protocol".
class NetworkHostPortTest < Minitest::Test
  Subject = Rubernetes::Network::HostPort

  class Runner
    attr_reader :calls

    def initialize(check_result: false)
      @calls = []
      @check_result = check_result
    end

    def call(binary, *arguments)
      @calls << [binary, *arguments]
      return @check_result if arguments.include?("-C")

      true
    end
  end

  def pod(ports)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "uid-1"},
     "spec" => {"containers" => [{"name" => "c", "image" => "img", "ports" => ports}]}}
  end

  def test_mappings_are_read_from_the_pod_spec
    mappings = Subject.mappings_for(pod([{"containerPort" => 8080, "hostPort" => 8080},
                                         {"containerPort" => 9090, "hostPort" => 9091,
                                          "protocol" => "UDP", "hostIP" => "127.0.0.1"}]))

    assert_equal 2, mappings.length
    assert_equal [8080, "tcp", ""], [mappings[0].host_port, mappings[0].protocol, mappings[0].host_ip]
    assert_equal [9091, "udp", "127.0.0.1"], [mappings[1].host_port, mappings[1].protocol, mappings[1].host_ip]
  end

  def test_a_port_without_a_host_port_is_ignored
    assert_empty Subject.mappings_for(pod([{"containerPort" => 8080}]))
  end

  def test_sctp_is_not_published
    assert_empty Subject.mappings_for(pod([{"containerPort" => 1, "hostPort" => 1, "protocol" => "SCTP"}]))
  end

  def test_a_dnat_rule_is_installed_for_each_host_port
    runner = Runner.new
    Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "10.0.0.5",
                                        pod: pod([{"containerPort" => 8080, "hostPort" => 30_080}]))
    dnat = runner.calls.find { |c| c.include?("DNAT") && c.include?("-A") }

    refute_nil dnat, "a DNAT rule must be installed"
    assert_includes dnat, "10.0.0.5:8080"
    assert_includes dnat, "30080"
    assert_includes dnat, "rubernetes hostport uid-1"
  end

  def test_the_host_ip_narrows_the_rule
    runner = Runner.new
    Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "10.0.0.5",
                                        pod: pod([{"containerPort" => 80, "hostPort" => 80,
                                                   "hostIP" => "127.0.0.1"}]))
    dnat = runner.calls.find { |c| c.include?("DNAT") && c.include?("-A") }

    assert_includes dnat, "-d"
    assert_includes dnat, "127.0.0.1"
  end

  def test_a_hairpin_masquerade_accompanies_the_mapping
    runner = Runner.new
    Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "10.0.0.5",
                                        pod: pod([{"containerPort" => 8080, "hostPort" => 30_080}]))

    assert runner.calls.any? { |c| c.include?("MASQUERADE") }, "hairpin traffic needs a masquerade"
  end

  def test_an_existing_rule_is_not_installed_twice
    runner = Runner.new(check_result: true)
    published = Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "10.0.0.5",
                                                    pod: pod([{"containerPort" => 8080, "hostPort" => 30_080}]))

    assert_empty published
    refute(runner.calls.any? { |c| c.include?("-A") && c.include?("DNAT") })
  end

  def test_a_pod_with_no_host_ports_touches_nothing
    runner = Runner.new
    Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "10.0.0.5",
                                        pod: pod([{"containerPort" => 8080}]))

    assert_empty runner.calls
  end

  def test_a_pod_without_an_address_publishes_nothing
    runner = Runner.new
    Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "",
                                        pod: pod([{"containerPort" => 8080, "hostPort" => 30_080}]))

    assert_empty runner.calls
  end

  def test_the_chain_and_its_hooks_are_created
    runner = Runner.new
    Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "10.0.0.5",
                                        pod: pod([{"containerPort" => 8080, "hostPort" => 30_080}]))

    assert(runner.calls.any? { |c| c.include?("-N") && c.include?("KUBE-HOSTPORTS") })
    assert(runner.calls.any? { |c| c.include?("PREROUTING") })
    assert(runner.calls.any? { |c| c.include?("OUTPUT") })
  end

  def test_ipv6_uses_ip6tables_and_bracketed_destinations
    runner = Runner.new
    Subject.new(runner: runner).ensure!(pod_uid: "uid-1", pod_ip: "fd00::5",
                                        pod: pod([{"containerPort" => 8080, "hostPort" => 30_080}]),
                                        family: :ipv6)
    dnat = runner.calls.find { |c| c.include?("DNAT") && c.include?("-A") }

    assert_equal "ip6tables", dnat.first
    assert_includes dnat, "[fd00::5]:8080"
  end
end
