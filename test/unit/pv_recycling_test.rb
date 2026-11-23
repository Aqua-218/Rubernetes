# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/volume/binding"

class PVRecyclingTest < Minitest::Test
  Controller = Rubernetes::Controller

  class LiveStorage < Controller::StoreAdapter
    attr_accessor :volume, :claim, :pod

    def initialize = super({})

    def find_live(descriptor, name:, namespace: nil)
      case descriptor.kind
      when "PersistentVolume" then volume
      when "PersistentVolumeClaim" then claim
      when "Pod" then pod
      end
    end
  end

  def setup
    @controller = Controller::PersistentVolumeBinderController.new
    @storage = LiveStorage.new
    @volume = {
      "apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => "scratch", "uid" => "volume-uid"},
      "spec" => {"persistentVolumeReclaimPolicy" => "Recycle", "capacity" => {"storage" => "11.5Gi"},
                 "claimRef" => {"namespace" => "test", "name" => "claim", "uid" => "claim-uid"},
                 "nfs" => {"server" => "192.0.2.24", "path" => "/export", "readOnly" => true}},
      "status" => {"phase" => "Released"}
    }
    @storage.volume = @volume
  end

  def test_volume_model_round_trips_the_recycle_policy
    volume = Rubernetes::Volume::PersistentVolume.new("name" => "scratch", "size" => "2Gi", "reclaimPolicy" => "Recycle")

    assert_equal "Recycle", volume.reclaim_policy
    assert_equal "Recycle", volume.with(phase: "Released").reclaim_policy
  end

  def test_nfs_recycler_uses_a_writable_mount_and_records_release_ownership
    operation = plan.operations.fetch(0)

    assert_predicate operation, :create?
    assert_equal({"name" => "vol", "nfs" => {"server" => "192.0.2.24", "path" => "/export"}}, operation.object.dig("spec", "volumes", 0))
    assert_equal 330, operation.object.dig("spec", "activeDeadlineSeconds")
    assert_equal "volume-uid", operation.object.dig("metadata", "ownerReferences", 0, "uid")
    assert_equal "claim-uid", operation.object.dig("metadata", "annotations", "pv.kubernetes.io/recycler-claim-uid")
  end

  def test_waits_for_release_to_be_persisted_and_does_not_act_while_the_claim_is_live
    @storage.volume = @volume.merge("status" => {"phase" => "Bound"})

    assert_empty plan.operations

    @storage.volume = @volume
    @storage.claim = {"metadata" => {"namespace" => "test", "name" => "claim", "uid" => "claim-uid"},
                      "spec" => {"volumeName" => "scratch"}}

    assert_empty plan.creates

    @storage.claim = nil

    assert_predicate plan.operations.first, :create?
  end

  def test_active_reference_keeps_a_released_volume_from_starting_a_scrub
    cached_claim = {"metadata" => {"namespace" => "test", "name" => "claim", "uid" => "claim-uid"},
                    "spec" => {"volumeName" => "scratch"}}
    pod = {"metadata" => {"namespace" => "test", "name" => "writer"}, "status" => {"phase" => "Running"},
           "spec" => {"volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}}]}}
    waiting = plan(claims: [cached_claim], pods: [pod])

    assert_empty waiting.operations
    assert_equal(["VolumeFailedRecycle"], waiting.events.map { |entry| entry["reason"] })

    pod["status"]["phase"] = "Succeeded"

    assert_predicate plan(claims: [cached_claim], pods: [pod]).operations.first, :create?
  end

  def test_failed_recycler_is_removed_with_its_uid_without_releasing_the_claim_reference
    pod = Controller::Support.deep_copy(plan.operations.first.object)
    pod["metadata"]["uid"] = "recycler-uid"
    pod["status"] = {"phase" => "Failed", "message" => "scrub failed"}
    @storage.pod = pod
    failed = plan
    deletion = failed.operations.find(&:delete?)

    assert_equal "recycler-uid", deletion.patch.dig("preconditions", "uid")
    phase = failed.operations.find { |operation| operation.action == :status_update }.patch["phase"]

    assert_equal "Failed", phase
    assert_equal(["Recycle failed: failed to recycle volume: scrub failed"], failed.events.map { |entry| entry["message"] })
    assert_in_delta 5, failed.requeue_after
    assert_equal "claim-uid", @volume.dig("spec", "claimRef", "uid")

    @storage.pod = nil

    assert_predicate plan.operations.first, :create?
  end

  private

  def plan(claims: [], pods: [])
    @controller.plan(@volume, store: @storage, persistent_volumes: [@volume], claims: claims, storage_classes: [], pods: pods)
  end
end
