# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

# Upstream controllers ignore a create the API server refuses because the
# namespace is being deleted (NamespaceTerminatingCause) and carry on with
# the rest of the sync.  Our batch aborted on it: in conformance round 115 the
# Job of "should apply changes to a job status" wanted more Pods when its
# namespace began terminating, every sync stopped at the refused create, the
# finished Pod never lost batch.kubernetes.io/job-tracking, and the namespace
# stayed Terminating for two hours.
class ControllerNamespaceTerminatingCreateTest < Minitest::Test
  Controller = Rubernetes::Controller
  FINALIZER = "batch.kubernetes.io/job-tracking"

  class TerminatingNamespaceAdapter < Controller::StoreAdapter
    Refused = Class.new(StandardError)

    def apply_create(operation, fence: nil)
      raise Refused, "unable to create new content in namespace ns because it is being terminated"
    end
  end

  def job
    {"apiVersion" => "batch/v1", "kind" => "Job",
     "metadata" => {"name" => "j", "namespace" => "ns", "uid" => "job-uid"},
     "spec" => {"parallelism" => 2, "completions" => 4, "backoffLimit" => 6,
                "selector" => {"matchLabels" => {"batch.kubernetes.io/controller-uid" => "job-uid"}},
                "template" => {"metadata" => {"labels" => {"batch.kubernetes.io/controller-uid" => "job-uid"}},
                               "spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "c", "image" => "busybox"}]}}},
     "status" => {"startTime" => "2026-09-25T08:03:24Z"}}
  end

  def finished_pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "j-done", "namespace" => "ns", "uid" => "pod-uid", "finalizers" => [FINALIZER],
                    "labels" => {"batch.kubernetes.io/controller-uid" => "job-uid"},
                    "ownerReferences" => [{"apiVersion" => "batch/v1", "kind" => "Job", "name" => "j",
                                           "uid" => "job-uid", "controller" => true}]},
     "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}, "status" => {"phase" => "Succeeded"}}
  end

  def adapter(klass)
    store = Rubernetes::Storage::MemoryStore.new
    store.create("registry/batch/v1/jobs/ns/j", job)
    store.create("registry/v1/pods/ns/j-done", finished_pod)
    klass.new(store)
  end

  def test_a_refused_create_does_not_stop_the_finalizer_removal
    store_adapter = adapter(TerminatingNamespaceAdapter)
    controller = Controller::JobController.new(store: nil)
    live_job = store_adapter.find(Controller::ResourceDescriptor.parse("batch/v1/Job"), name: "j", namespace: "ns")
    planned = controller.plan(live_job, store: store_adapter, now: "2026-09-25T08:04:00Z")
    assert(planned.operations.any?(&:create?), "the Job wants more Pods")

    controller.reconcile(live_job, store: store_adapter, apply: true, now: "2026-09-25T08:04:00Z")

    pod = store_adapter.find(Controller::ResourceDescriptor.parse("Pod"), name: "j-done", namespace: "ns")
    refute_includes Array(pod.dig("metadata", "finalizers")), FINALIZER
  end

  def test_other_create_failures_still_fail_the_batch
    failing = Class.new(Controller::StoreAdapter) do
      def apply_create(operation, fence: nil) = raise(ArgumentError, "quota exceeded")
    end
    store_adapter = adapter(failing)
    live_job = store_adapter.find(Controller::ResourceDescriptor.parse("batch/v1/Job"), name: "j", namespace: "ns")
    assert_raises(ArgumentError) do
      Controller::JobController.new(store: nil).reconcile(live_job, store: store_adapter, apply: true, now: "2026-09-25T08:04:00Z")
    end
  end

  def test_namespace_terminating_is_recognised_by_cause_or_message
    status = {"kind" => "Status", "details" => {"causes" => [{"reason" => "NamespaceTerminating"}]}}
    error = Struct.new(:status_object, :message).new(status, "forbidden")
    assert Controller::StoreAdapter.namespace_terminating?(error)
    refute Controller::StoreAdapter.namespace_terminating?(StandardError.new("forbidden"))
  end
end
