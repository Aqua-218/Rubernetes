# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# replica_set.go syncReplicaSet skips manageReplicas once the controller is
# being deleted.  Ours kept replacing Pods while its own deletion was
# removing them.  In "[sig-api-machinery] Garbage collector should keep the
# rc around until all its pods are deleted if the deleteOptions says so", the
# new Pods outlived the ReplicationController, and "expected no pods" failed
# every round.
class ControllerBeingDeletedGuardTest < Minitest::Test
  Controller = Rubernetes::Controller

  def template
    {"metadata" => {"labels" => {"app" => "a"}},
     "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}}
  end

  def rc(deleting:)
    metadata = {"name" => "rc", "namespace" => "ns", "uid" => "rc-uid", "generation" => 1}
    metadata["deletionTimestamp"] = "2026-09-18T12:00:00Z" if deleting
    {"apiVersion" => "v1", "kind" => "ReplicationController", "metadata" => metadata,
     "spec" => {"replicas" => 3, "selector" => {"app" => "a"}, "template" => template}}
  end

  def rs(deleting:)
    metadata = {"name" => "rs", "namespace" => "ns", "uid" => "rs-uid", "generation" => 1}
    metadata["deletionTimestamp"] = "2026-09-18T12:00:00Z" if deleting
    {"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "metadata" => metadata,
     "spec" => {"replicas" => 3, "selector" => {"matchLabels" => {"app" => "a"}}, "template" => template}}
  end

  def creates(result)
    result.operations.count { |operation| operation.action == :create }
  end

  def test_a_replication_controller_being_deleted_creates_no_pods
    assert_equal 0, creates(Controller::ReplicationControllerController.new.plan(rc(deleting: true), pods: []))
  end

  def test_a_live_replication_controller_still_scales_up
    assert_equal 3, creates(Controller::ReplicationControllerController.new.plan(rc(deleting: false), pods: []))
  end

  def test_a_replica_set_being_deleted_creates_no_pods
    assert_equal 0, creates(Controller::ReplicaSetController.new.plan(rs(deleting: true), pods: []))
  end

  def test_a_live_replica_set_still_scales_up
    assert_equal 3, creates(Controller::ReplicaSetController.new.plan(rs(deleting: false), pods: []))
  end
end
