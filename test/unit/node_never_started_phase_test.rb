# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A Pod whose app containers never ran is not Succeeded.  The phase was read
# off "did anything exit non-zero", so a Pod whose container could not be
# created -- its own container status saying Waiting with
# CreateContainerConfigError -- was reported as completed.  kubelet keeps it
# Pending and retries creating the container, which is what "[sig-node]
# Variable Expansion should verify that a failing subpath expansion can be
# modified during the lifetime of a container" waits for.
class NodeNeverStartedPhaseTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  def phase_for(containers, reason: nil)
    lifecycle = Lifecycle.allocate
    lifecycle.send(:terminal_phase, {containers: containers, reason: reason})
  end

  def app(status)
    {category: "app", name: "c", status: status}
  end

  def test_a_pod_whose_containers_never_ran_stays_pending
    assert_equal "Pending", phase_for([app(nil)])
    assert_equal "Pending", phase_for([app(nil)], reason: "CreateContainerConfigError")
    assert_equal "Pending", phase_for([]), "no containers recorded at all"
    assert_equal "Pending", phase_for([{category: "init", name: "i", status: {"exitCode" => 0}}]),
                 "an init container that ran does not complete the Pod"
  end

  def test_an_admission_failure_is_terminal
    assert_equal "Failed", phase_for([app(nil)], reason: "PodAdmissionFailed")
  end

  def test_containers_that_ran_decide_as_before
    assert_equal "Succeeded", phase_for([app({"exitCode" => 0})])
    assert_equal "Failed", phase_for([app({"exitCode" => 1})])
    assert_equal "Failed", phase_for([app({"exitCode" => 0}), app({"exitCode" => 2})])
    assert_equal "Succeeded", phase_for([app({"exitCode" => 0}), {category: "init", name: "i", status: {"exitCode" => 0}}])
  end

  def test_a_started_container_without_an_exit_code_counts_as_success
    assert_equal "Succeeded", phase_for([app({"state" => "terminated"})])
  end
end
