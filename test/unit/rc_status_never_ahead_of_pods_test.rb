# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# The ReplicationController wrote its status FIRST (so a ReplicaFailure
# condition survives a refused create) and counted in it the Pods it was
# only about to create.  status.replicas therefore claimed Pods that did not
# exist yet: "[sig-api-machinery] Garbage collector should orphan pods created
# by rc if delete options say so" waits for status.replicas == 100, read it
# two seconds in, deleted the rc, and found 60 Pods.  The first status now
# counts what was observed; the count after the changes is written in a final
# batch that runs only once every change before it has landed.
class RcStatusNeverAheadOfPodsTest < Minitest::Test
  Controller = Rubernetes::Controller

  def rc(replicas)
    {"apiVersion" => "v1", "kind" => "ReplicationController",
     "metadata" => {"name" => "rc", "namespace" => "ns", "uid" => "rc-uid", "generation" => 1},
     "spec" => {"replicas" => replicas, "selector" => {"app" => "a"},
                "template" => {"metadata" => {"labels" => {"app" => "a"}},
                               "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}}}}
  end

  def status_replicas(operation)
    operation.patch.fetch("replicas")
  end

  def plan(replicas)
    Controller::ReplicationControllerController.new.plan(rc(replicas), pods: [])
  end

  def test_the_first_status_counts_only_the_pods_observed
    result = plan(100)
    first_batch = result.batches.first

    assert_equal [:status_update], first_batch.map(&:action)
    assert_equal 0, status_replicas(first_batch.first)
  end

  def test_the_settled_count_is_written_after_every_create
    result = plan(100)
    final_batch = result.batches.last
    create_positions = result.batches.each_index.select { |index| result.batches[index].any?(&:create?) }

    assert_equal [:status_update], final_batch.map(&:action)
    assert_equal 100, status_replicas(final_batch.first)
    assert(create_positions.all? { |index| index < result.batches.length - 1 },
           "the settled status must come after every batch of creates")
  end

  def test_a_sync_with_nothing_to_change_writes_one_status
    existing = Array.new(2) do |index|
      {"apiVersion" => "v1", "kind" => "Pod",
       "metadata" => {"name" => "rc-#{index}", "namespace" => "ns", "uid" => "p#{index}", "labels" => {"app" => "a"},
                      "ownerReferences" => [{"apiVersion" => "v1", "kind" => "ReplicationController", "name" => "rc",
                                             "uid" => "rc-uid", "controller" => true}]},
       "status" => {"phase" => "Running"}}
    end

    result = Controller::ReplicationControllerController.new.plan(rc(2), pods: existing)

    assert_equal(1, result.operations.count { |operation| operation.action == :status_update })
    assert_equal 2, result.status.fetch("replicas")
  end
end
