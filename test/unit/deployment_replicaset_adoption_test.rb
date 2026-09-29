# frozen_string_literal: true

require "minitest/autorun"
require "rubernetes/controller"

# pkg/controller/deployment getReplicaSetsForDeployment claims every
# ReplicaSet in the namespace whose labels match the selector and that no
# controller owns.  Ours looked only at ReplicaSets that already carried an
# owner reference, so a Deployment created over an existing ReplicaSet never
# saw it: it found no old revision, numbered its new ReplicaSet 1 instead of
# the adopted one's revision plus one, and never scaled the old one down.
# "[sig-apps] Deployment RollingUpdateDeployment should delete old pods and
# create new ones" pre-creates a ReplicaSet annotated revision
# 3546343826724305832 and demands the Deployment reach 3546343826724305833.
class DeploymentReplicaSetAdoptionTest < Minitest::Test
  Controller = Rubernetes::Controller
  Support = Rubernetes::Controller::Support
  NOW = Time.utc(2026, 1, 1, 12, 0, 0)
  ADOPTED_REVISION = "3546343826724305832"

  def controller
    Controller::DeploymentController.new(clock: -> { NOW })
  end

  def deployment
    {"apiVersion" => "apps/v1", "kind" => "Deployment",
     "metadata" => {"name" => "web", "namespace" => "default", "uid" => "uid-deployment", "generation" => 1},
     "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "web"}},
                "strategy" => {"type" => "RollingUpdate"},
                "template" => {"metadata" => {"labels" => {"app" => "web"}},
                               "spec" => {"containers" => [{"name" => "web", "image" => "example/web:2"}]}}}}
  end

  # The orphan carries an extra label and no pod-template-hash, exactly like
  # the hand-built ReplicaSet the conformance test creates.
  def orphan
    {"apiVersion" => "apps/v1", "kind" => "ReplicaSet",
     "metadata" => {"name" => "web-controller", "namespace" => "default", "uid" => "uid-orphan",
                    "generation" => 1, "creationTimestamp" => (NOW - 3600).iso8601(6),
                    "labels" => {"app" => "web", "role" => "legacy"},
                    "annotations" => {"deployment.kubernetes.io/revision" => ADOPTED_REVISION}},
     "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "web", "role" => "legacy"}},
                "template" => {"metadata" => {"labels" => {"app" => "web", "role" => "legacy"}},
                               "spec" => {"containers" => [{"name" => "web", "image" => "example/web:1"}]}}},
     "status" => {"replicas" => 1, "readyReplicas" => 1, "availableReplicas" => 1, "observedGeneration" => 1}}
  end

  def test_a_matching_orphan_replica_set_gains_the_deployment_owner_reference
    result = controller.plan(deployment, replicasets: [orphan], now: NOW)
    adoption = result.operations.find do |operation|
      operation.action == :update && Support.name(operation.object) == "web-controller"
    end

    refute_nil adoption, "the orphan must be claimed"
    reference = Support.owner_references(adoption.object).last
    assert_equal "Deployment", Support.ref_value(reference, "kind", nil)
    assert_equal "uid-deployment", Support.ref_value(reference, "uid", nil)
    assert_equal true, Support.ref_value(reference, "controller", false)
  end

  def test_the_new_replica_set_continues_the_adopted_revision
    result = controller.plan(deployment, replicasets: [orphan], now: NOW)
    create = result.creates.first

    refute_nil create, "a new ReplicaSet must be created for the new template"
    assert_equal((Integer(ADOPTED_REVISION) + 1).to_s,
                 create.object.dig("metadata", "annotations", "deployment.kubernetes.io/revision"))
  end

  # ClaimReplicaSets skips anything another controller already owns.
  def test_a_replica_set_owned_by_another_controller_is_left_alone
    foreign = orphan
    foreign["metadata"]["ownerReferences"] =
      [{"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "other",
        "uid" => "uid-other", "controller" => true}]

    result = controller.plan(deployment, replicasets: [foreign], now: NOW)

    assert_empty(result.operations.select do |operation|
      operation.action == :update && Support.name(operation.object) == "web-controller"
    end)
    assert_equal "1", result.creates.first.object.dig("metadata", "annotations",
                                                     "deployment.kubernetes.io/revision")
  end

  def test_a_deployment_being_deleted_adopts_nothing
    deleted = deployment
    deleted["metadata"]["deletionTimestamp"] = NOW.iso8601(6)

    result = controller.plan(deleted, replicasets: [orphan], now: NOW)

    assert_empty(result.operations.select do |operation|
      operation.action == :update && Support.name(operation.object) == "web-controller"
    end)
  end
end
