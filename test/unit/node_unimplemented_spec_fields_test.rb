# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# These PodSpec fields were accepted and validated by the API server and then
# read by NOTHING in the node: a source audit of every PodSpec/Container field
# against lib/rubernetes/node, runtime and platform found them with zero
# references.  Each one is a behaviour upstream's kubelet implements.
class NodeUnimplementedSpecFieldsTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  def lifecycle(now:)
    Lifecycle.allocate.tap do |value|
      value.instance_variable_set(:@clock, -> { now })
    end
  end

  def record(phase: "Running", state: "Running", started_at: nil)
    {uid: "u", phase: phase, state: state, started_at: started_at}
  end

  def pod(deadline: nil, ephemeral: nil)
    spec = {"containers" => [{"name" => "c", "image" => "img"}]}
    spec["activeDeadlineSeconds"] = deadline unless deadline.nil?
    spec["ephemeralContainers"] = ephemeral unless ephemeral.nil?
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => spec}
  end

  # --- activeDeadlineSeconds ------------------------------------------------

  def test_a_pod_past_its_deadline_is_exceeded
    now = Time.at(1_000)
    subject = lifecycle(now: now)

    assert subject.send(:active_deadline_exceeded?,
                        record(started_at: Time.at(900)), pod(deadline: 30))
  end

  def test_a_pod_inside_its_deadline_is_not
    now = Time.at(1_000)
    subject = lifecycle(now: now)

    refute subject.send(:active_deadline_exceeded?,
                        record(started_at: Time.at(990)), pod(deadline: 30))
  end

  def test_no_deadline_never_expires
    subject = lifecycle(now: Time.at(10**9))

    refute subject.send(:active_deadline_exceeded?, record(started_at: Time.at(0)), pod)
  end

  def test_a_terminal_pod_is_not_deadline_killed_again
    subject = lifecycle(now: Time.at(1_000))

    refute subject.send(:active_deadline_exceeded?,
                        record(phase: "Succeeded", state: "Removed", started_at: Time.at(0)),
                        pod(deadline: 1))
  end

  def test_a_pod_that_never_started_has_no_deadline_clock
    subject = lifecycle(now: Time.at(1_000))

    refute subject.send(:active_deadline_exceeded?, record(started_at: nil), pod(deadline: 1))
  end

  # --- ephemeralContainers --------------------------------------------------

  # An added ephemeral container is found by comparing the desired spec with
  # the containers the record has actually started.  It used to be found by
  # diffing config digests, but spec.ephemeralContainers is deliberately
  # stripped from the digest (adding one must restart nothing), so that
  # comparison could never be true and the container never started.
  def ephemeral_record(*started)
    {uid: "u", phase: "Running", state: "Running",
     containers: started.map { |name| {name: name, category: "ephemeral"} }}
  end

  def test_an_ephemeral_container_not_yet_started_is_pending
    subject = lifecycle(now: Time.at(0))
    desired = pod(ephemeral: [{"name" => "debugger", "image" => "busybox"}])

    assert subject.send(:pending_ephemeral_containers?, desired, ephemeral_record)
  end

  def test_an_ephemeral_container_already_started_is_not_pending
    subject = lifecycle(now: Time.at(0))
    desired = pod(ephemeral: [{"name" => "debugger", "image" => "busybox"}])

    refute subject.send(:pending_ephemeral_containers?, desired, ephemeral_record("debugger"))
  end

  # The predicate reads only spec.ephemeralContainers: an unrelated change to a
  # real container is the restart path's business, not this one's.
  def test_a_changed_real_container_does_not_make_one_pending
    subject = lifecycle(now: Time.at(0))
    desired = pod(ephemeral: [{"name" => "debugger", "image" => "busybox"}])
    desired["spec"]["containers"][0]["image"] = "other"

    refute subject.send(:pending_ephemeral_containers?, desired, ephemeral_record("debugger"))
  end

  def test_a_pod_with_no_ephemeral_containers_has_none_pending
    subject = lifecycle(now: Time.at(0))

    refute subject.send(:pending_ephemeral_containers?, pod, ephemeral_record)
  end
end
