# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A hostPort is a node-wide resource: two Pods cannot both have it.  kubelet's
# own admission refuses the second one (PodFitsHostPorts in
# lifecycle/predicate.go GeneralPredicates), which is what makes the Pod Failed
# so its controller can replace it.  Admitting both instead let each install
# its own DNAT rule for the same port and neither Pod ever failed --
# "[sig-apps] StatefulSet Should recreate evicted statefulset" waits for
# exactly that failure, because it deliberately parks a Pod on the port the
# StatefulSet wants.
class NodeHostPortConflictTest < Minitest::Test
  Node = Rubernetes::Node

  def lifecycle
    Node::Lifecycle.new(runtime: Object.new)
  end

  def pod(name, uid:, host_port: nil, host_ip: nil, protocol: nil)
    port = {"containerPort" => 80}
    port["hostPort"] = host_port if host_port
    port["hostIP"] = host_ip if host_ip
    port["protocol"] = protocol if protocol
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => uid},
     "spec" => {"containers" => [{"name" => "c", "image" => "agnhost", "ports" => [port]}]},
     "status" => {"phase" => "Running"}}
  end

  def with_holder(subject, holder, state: "Running", phase: "Running")
    records = subject.instance_variable_get(:@records)
    records[holder.dig("metadata", "uid")] = {uid: holder.dig("metadata", "uid"), pod: holder,
                                              state: state, phase: phase, events: [], cleanup_errors: []}
    subject
  end

  def conflict(subject, candidate)
    subject.send(:host_port_conflict, candidate)
  end

  def test_the_same_host_port_conflicts
    subject = with_holder(lifecycle, pod("held", uid: "a", host_port: 21_017))

    refute_nil(conflict(subject, pod("want", uid: "b", host_port: 21_017)))
  end

  def test_a_different_host_port_does_not_conflict
    subject = with_holder(lifecycle, pod("held", uid: "a", host_port: 21_017))

    assert_nil(conflict(subject, pod("want", uid: "b", host_port: 21_018)))
  end

  def test_a_different_protocol_does_not_conflict
    subject = with_holder(lifecycle, pod("held", uid: "a", host_port: 21_017, protocol: "TCP"))

    assert_nil(conflict(subject, pod("want", uid: "b", host_port: 21_017, protocol: "UDP")))
  end

  # A specific address does not conflict with another specific address.
  def test_distinct_host_ips_do_not_conflict
    subject = with_holder(lifecycle, pod("held", uid: "a", host_port: 21_017, host_ip: "10.0.0.1"))

    assert_nil(conflict(subject, pod("want", uid: "b", host_port: 21_017, host_ip: "10.0.0.2")))
  end

  # 0.0.0.0 takes the port on every address.
  def test_a_wildcard_claim_conflicts_with_a_specific_address
    subject = with_holder(lifecycle, pod("held", uid: "a", host_port: 21_017))

    refute_nil(conflict(subject, pod("want", uid: "b", host_port: 21_017, host_ip: "10.0.0.2")))
  end

  # A Pod that has finished has given the port back.
  def test_a_terminated_pod_holds_nothing
    subject = with_holder(lifecycle, pod("held", uid: "a", host_port: 21_017),
                          state: "Removed", phase: "Succeeded")

    assert_nil(conflict(subject, pod("want", uid: "b", host_port: 21_017)))
  end

  # A Pod does not conflict with itself on a resync.
  def test_a_pod_does_not_conflict_with_itself
    subject = with_holder(lifecycle, pod("same", uid: "a", host_port: 21_017))

    assert_nil(conflict(subject, pod("same", uid: "a", host_port: 21_017)))
  end

  def test_a_pod_without_host_ports_never_conflicts
    subject = with_holder(lifecycle, pod("held", uid: "a", host_port: 21_017))

    assert_nil(conflict(subject, pod("want", uid: "b")))
  end
end
