# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# The host-port predicate counts admitted Pods only: a Pod still in admission,
# or one admission refused, holds no port.  Counting them let a StatefulSet's
# recreated Pod collide with its own previous incarnation for ever.
class LifecycleHostPortAdmissionTest < Minitest::Test
  def pod(uid, name: "ss-0", port: 21_017)
    {"metadata" => {"uid" => uid, "name" => name, "namespace" => "ns"},
     "spec" => {"containers" => [{"name" => "c", "ports" => [{"containerPort" => 80, "hostPort" => port, "protocol" => "TCP"}]}]}}
  end

  def lifecycle_with(records)
    lifecycle = Rubernetes::Node::Lifecycle.allocate
    lifecycle.instance_variable_set(:@records, records)
    lifecycle
  end

  def test_a_pod_still_in_admission_does_not_hold_its_port
    other = {uid: "old", state: "New", phase: "Pending", reason: nil, pod: pod("old")}
    lifecycle = lifecycle_with({"old" => other})

    assert_nil lifecycle.send(:host_port_conflict, pod("new"))
  end

  def test_a_pod_admission_refused_does_not_hold_its_port
    other = {uid: "old", state: "RollingBack", phase: "Pending", reason: "PodAdmissionFailed", pod: pod("old")}
    lifecycle = lifecycle_with({"old" => other})

    assert_nil lifecycle.send(:host_port_conflict, pod("new"))
  end

  def test_a_running_pod_still_holds_its_port
    other = {uid: "old", state: "Running", phase: "Running", reason: nil, pod: pod("old", name: "test-pod")}
    lifecycle = lifecycle_with({"old" => other})

    conflict = lifecycle.send(:host_port_conflict, pod("new"))

    assert_equal "test-pod", conflict.last
  end
end
