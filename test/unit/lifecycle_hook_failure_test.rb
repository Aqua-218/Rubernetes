# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A preStop hook that fails does not stop the kill.  kubelet records a
# FailedPreStopHook event and carries on -- kuberuntime_container.go
# killContainer keeps killing whatever the hook did -- because the container
# has to go either way.  Counting a failed hook as a cleanup error instead left
# the Pod in CleanupPending, so the node never issued its final delete and the
# Pod stayed Terminating in the API for ever: a failed hook made the Pod
# immortal.
#
# And a lifecycle hook is not a probe: it calls another Pod over the network,
# so it gets the hook timeout rather than the one second a readiness check is
# happy with.
class LifecycleHookFailureTest < Minitest::Test
  Node = Rubernetes::Node

  class Runtime
    attr_reader :calls

    def initialize(fail: false)
      @calls = []
      @fail = fail
    end

    def http_get(container_id, definition, timeout: 1.0, **)
      @calls << {container: container_id, definition: definition, timeout: timeout}
      raise Rubernetes::Node::Lifecycle::LifecycleError, "hook unreachable" if @fail

      true
    end
  end

  def lifecycle(runtime)
    Node::Lifecycle.new(runtime: runtime)
  end

  def hook = {"httpGet" => {"path" => "/echo?msg=prestop", "port" => 8080}}

  def record(started: true)
    {uid: "pod-uid", events: [], state: "Running", phase: "Running", cleanup_errors: [],
     containers: [{name: "c", id: "c1", started: started,
                   spec: {"name" => "c", "lifecycle" => {"preStop" => hook}}}],
     pod: {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-uid"}, "spec" => {}}}
  end

  def test_a_hook_gets_the_hook_timeout_not_the_probe_default
    runtime = Runtime.new
    lifecycle(runtime).send(:execute_hook, "c1", hook)

    assert_equal(Node::Lifecycle::HOOK_TIMEOUT_SECONDS, runtime.calls.fetch(0).fetch(:timeout))
  end

  def test_a_prestop_hook_is_run_for_a_started_container
    runtime = Runtime.new
    entry = record
    lifecycle(runtime).send(:run_pre_stop_hooks, entry[:pod], entry)

    assert_equal(1, runtime.calls.length)
  end

  def test_a_container_that_never_started_has_no_prestop_hook
    runtime = Runtime.new
    entry = record(started: false)
    lifecycle(runtime).send(:run_pre_stop_hooks, entry[:pod], entry)

    assert_empty(runtime.calls)
  end

  # The hook raising must reach the caller so the caller can record the event
  # -- and the caller must not turn it into a cleanup error.
  def test_a_failing_hook_raises_to_its_caller
    runtime = Runtime.new(fail: true)
    entry = record

    assert_raises(Node::Lifecycle::LifecycleError) do
      lifecycle(runtime).send(:run_pre_stop_hooks, entry[:pod], entry)
    end
  end

  def test_a_failed_hook_is_reported_as_an_event_not_a_cleanup_error
    runtime = Runtime.new(fail: true)
    subject = lifecycle(runtime)
    entry = record

    begin
      subject.send(:run_pre_stop_hooks, entry[:pod], entry)
    rescue Node::Lifecycle::LifecycleError => error
      subject.send(:event, entry, "container.failed_prestop", reason: "FailedPreStopHook",
                                                              message: "PreStopHook failed: #{error.message}")
    end

    assert_empty(entry[:cleanup_errors], "a failed hook must not block the Pod's removal")
    assert_equal("FailedPreStopHook", entry[:events].last.fetch("reason"))
  end
end
