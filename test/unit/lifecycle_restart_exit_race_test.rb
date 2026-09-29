# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A restarted container can run to completion before the restart path records
# "running": the exit observer had already stored "terminated" for the same
# container id.  The exit must win, or a Succeeded Pod reports its container
# Running again ("Container Runtime blackbox test ... terminate-cmd-rpof").
class LifecycleRestartExitRaceTest < Minitest::Test
  def lifecycle = Rubernetes::Node::Lifecycle.allocate

  def test_a_terminated_status_for_the_same_container_id_counts_as_exited
    entry = {id: "pod1.container-2", status: {"state" => "terminated", "terminated" => {"containerID" => "pod1.container-2", "exitCode" => 0}}}

    assert lifecycle.send(:exited_already?, entry)
  end

  def test_a_terminated_status_of_the_previous_container_does_not_block_the_restart
    entry = {id: "pod1.container-2", status: {"state" => "terminated", "terminated" => {"containerID" => "pod1.container-1", "exitCode" => 1}}}

    refute lifecycle.send(:exited_already?, entry)
  end

  # Two observers (the relist thread and a sync worker) of one exit: the first
  # claims it, the second is refused; the next container run is a new claim.
  def test_an_exit_is_claimed_exactly_once_per_container_run
    entry = {id: "pod1.container-1", status: {"state" => "running"}}
    subject = lifecycle

    assert subject.send(:claim_exit!, entry)
    refute subject.send(:claim_exit!, entry)
    entry[:id] = "pod1.container-2"
    entry[:status] = {"state" => "running"}
    assert subject.send(:claim_exit!, entry)
  end

  def test_running_or_missing_status_is_not_exited
    refute lifecycle.send(:exited_already?, {id: "x", status: {"state" => "running"}})
    refute lifecycle.send(:exited_already?, {id: "x", status: nil})
  end
end
