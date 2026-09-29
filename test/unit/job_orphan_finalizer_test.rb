# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# syncOrphanPod removes the tracking finalizer from any Pod that carries it and
# is not controlled by a live Job -- it checks the Pod's controllerRef and
# nothing else, because a Pod whose Job was deleted with --cascade=orphan has
# had its owner reference STRIPPED and no longer names the Job at all.
#
# Matching on the Job's name instead left exactly those Pods holding the
# finalizer for ever: Succeeded, Terminating and unremovable, which also keeps
# their namespace from finishing its own deletion.
class JobOrphanFinalizerTest < Minitest::Test
  Controller = Rubernetes::Controller

  FINALIZER = "batch.kubernetes.io/job-tracking"

  def pod(name, owner: nil, finalizers: [FINALIZER])
    metadata = {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid"}
    metadata["finalizers"] = finalizers unless finalizers.empty?
    if owner
      metadata["ownerReferences"] = [{"apiVersion" => "batch/v1", "kind" => "Job", "name" => owner,
                                      "uid" => "#{owner}-uid", "controller" => true}]
    end
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata,
     "spec" => {}, "status" => {"phase" => "Succeeded"}}
  end

  def job(name)
    {"apiVersion" => "batch/v1", "kind" => "Job",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid"},
     "spec" => {"template" => {"spec" => {}}}, "status" => {}}
  end

  def adapter_with(objects)
    store = Rubernetes::Storage::MemoryStore.new
    Array(objects).each do |object|
      descriptor = Controller::ResourceDescriptor.parse(object)
      store.create("registry/#{descriptor.api_version}/#{descriptor.resource}/ns/#{object.dig("metadata", "name")}",
                   object)
    end
    Controller::StoreAdapter.new(store)
  end

  def controller = Controller::JobController.new(store: nil)

  def removed_names(objects, key: "ns/foo")
    result = controller.plan_orphans(key, store: adapter_with(objects))
    return [] if result.nil?

    result.operations.map { |operation| operation.object.dig("metadata", "name") }
  end

  # The orphan case the test suite actually produces: no owner reference left.
  def test_a_pod_with_no_owner_loses_the_finalizer
    assert_equal(%w[foo-1], removed_names([pod("foo-1")]))
  end

  # The older case still works: the reference names a Job that is gone.
  def test_a_pod_whose_job_is_gone_loses_the_finalizer
    assert_equal(%w[foo-1], removed_names([pod("foo-1", owner: "foo")]))
  end

  # A live Job keeps its Pods' finalizers: it still has to count them.
  def test_a_pod_owned_by_a_live_job_keeps_the_finalizer
    assert_empty(removed_names([job("foo"), pod("foo-1", owner: "foo")]))
  end

  def test_a_pod_without_the_finalizer_is_not_touched
    assert_empty(removed_names([pod("foo-1", finalizers: [])]))
  end

  # Another finalizer on the same Pod is left alone.
  def test_only_the_tracking_finalizer_is_removed
    result = controller.plan_orphans("ns/foo",
                                     store: adapter_with([pod("foo-1", finalizers: [FINALIZER, "example.com/x"])]))

    assert_equal([["example.com/x"]], result.operations.map { |o| o.object.dig("metadata", "finalizers") })
  end

  def test_a_key_without_a_name_plans_nothing
    assert_empty(removed_names([pod("foo-1")], key: "ns"))
  end
end
