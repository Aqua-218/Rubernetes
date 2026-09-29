# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A Pod whose API object is already gone leaves no record behind: neither
# when the final delete answers 404 (the namespace deletion won) nor when the
# informer delivered DELETED.  Every such record used to stay for the life of
# the agent, and each later Pod start walked them all.
class LifecycleForgetGonePodTest < Minitest::Test
  class Runtime
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"

    def create_container(_sandbox, spec)
      @sequence = @sequence.to_i + 1
      "container-#{@sequence}"
    end

    def start_container(_id) = true
    def stop_container(_id, timeout: nil) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
    def wait_container(_id) = {"state" => "terminated", "exitCode" => 0}
  end

  def pod(deleting: false)
    metadata = {"name" => "p", "namespace" => "ns", "uid" => "u1"}
    metadata["deletionTimestamp"] = "2026-09-23T00:00:00Z" if deleting
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata,
     "spec" => {"nodeName" => "n", "restartPolicy" => "Always", "terminationGracePeriodSeconds" => 0,
                "containers" => [{"name" => "app", "image" => "img"}]}}
  end

  def lifecycle(deleter)
    subject = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, pod_deleter: deleter, sleeper: ->(_) {})
    subject.start(pod)
    subject
  end

  def test_a_404_on_the_final_delete_forgets_the_record
    deleter = ->(**) { raise %(Kubernetes API request DELETE /api/v1/namespaces/ns/pods/p failed with HTTP 404: pods "p" not found) }
    subject = lifecycle(deleter)
    subject.reconcile(pod(deleting: true))
    assert_nil subject.record(pod)
  end

  def test_a_deleted_event_forgets_the_record
    subject = lifecycle(nil)
    subject.reconcile(pod, action: "DELETED")
    assert_nil subject.record(pod)
  end

  def test_a_successful_final_delete_still_forgets_and_a_transient_failure_keeps_it
    subject = lifecycle(->(**) { true })
    subject.reconcile(pod(deleting: true))
    assert_nil subject.record(pod)

    kept = lifecycle(->(**) { raise "Kubernetes API request DELETE failed with HTTP 500: boom" })
    kept.reconcile(pod(deleting: true))
    refute_nil kept.record(pod), "a transient failure keeps the record so the next sync retries"
  end
end
