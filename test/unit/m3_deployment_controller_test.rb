# frozen_string_literal: true

# The controller package is loaded directly so an unrelated package syntax
# error cannot mask a Deployment semantics regression.
require "minitest/autorun"
require "rubernetes/controller"

# Deployment controller semantics pinned to pkg/controller/deployment at
# Kubernetes v1.36.2.
class M3DeploymentControllerTest < Minitest::Test
  Controller = Rubernetes::Controller
  Support = Rubernetes::Controller::Support
  NOW = Time.utc(2026, 1, 1, 12, 0, 0)
  HASH_ALPHABET = /\A[bcdfghjklmnpqrstvwxz2456789]{1,10}\z/

  def test_new_replica_set_uses_fnv32a_safe_encoded_hash_with_collision_count
    deployment = deployment(replicas: 2)
    result = controller.plan(deployment, replicasets: [], now: NOW)
    create = result.creates.first
    hash = create.object.dig("metadata", "labels", "pod-template-hash")

    assert_match HASH_ALPHABET, hash
    assert_equal "web-#{hash}", create.object.dig("metadata", "name")
    assert_equal hash, create.object.dig("spec", "selector", "matchLabels", "pod-template-hash")
    assert_equal hash, create.object.dig("spec", "template", "metadata", "labels", "pod-template-hash")
    assert_equal Support.pod_template_hash(deployment.dig("spec", "template")), hash
    refute_equal hash, Support.pod_template_hash(deployment.dig("spec", "template"), 1)
    assert_equal({"deployment.kubernetes.io/revision" => "1", "deployment.kubernetes.io/desired-replicas" => "2",
                  "deployment.kubernetes.io/max-replicas" => "3"}, create.object.dig("metadata", "annotations"))
    assert_equal 2, create.object.dig("spec", "replicas")
    progressing = result.status.fetch("conditions").find { |condition| condition.fetch("type") == "Progressing" }

    assert_equal "NewReplicaSetCreated", progressing.fetch("reason")
    assert_equal(["Scaled up replica set web-#{hash} from 0 to 2"], result.events.map { |event| event.fetch("message") })
  end

  def test_hash_collision_bumps_collision_count_instead_of_adopting_a_foreign_replica_set
    deployment = deployment(replicas: 1)
    hash = Support.pod_template_hash(deployment.dig("spec", "template"))
    foreign = replica_set("web-#{hash}", deployment, revision: 1, replicas: 1, image: "example/other:9", owned: false)
    result = controller.plan(deployment, replicasets: [foreign], now: NOW)

    assert_empty result.creates
    assert_equal 1, result.status.fetch("collisionCount")
    assert_in_delta(0.0, result.requeue_after)

    retried = controller.plan(deployment.merge("status" => result.status), replicasets: [foreign], now: NOW)
    created = retried.creates.first.object

    assert_equal Support.pod_template_hash(deployment.dig("spec", "template"), 1), created.dig("metadata", "labels", "pod-template-hash")
  end

  def test_rollout_undo_reuses_the_old_replica_set_and_records_revision_history
    deployment = deployment(replicas: 2, image: "example/web:1", generation: 3)
    old_rs = replica_set("web-old", deployment, revision: 1, replicas: 0, image: "example/web:1")
    new_rs = replica_set("web-new", deployment, revision: 2, replicas: 2, image: "example/web:2", available: 2)
    result = controller.plan(deployment, replicasets: [old_rs, new_rs], now: NOW)

    assert_empty result.creates
    update = result.updates.find { |operation| operation.resource.kind == "ReplicaSet" }

    assert_equal "web-old", update.object.dig("metadata", "name")
    assert_equal "3", update.object.dig("metadata", "annotations", "deployment.kubernetes.io/revision")
    assert_equal "1", update.object.dig("metadata", "annotations", "deployment.kubernetes.io/revision-history")
  end

  def test_deprecated_rollback_annotation_copies_the_target_template_and_clears_itself
    deployment = deployment(replicas: 2, image: "example/web:2", generation: 3)
    deployment["metadata"]["annotations"] = {"deprecated.deployment.rollback.to" => "0", "deployment.kubernetes.io/revision" => "2"}
    old_rs = replica_set("web-old", deployment, revision: 1, replicas: 0, image: "example/web:1")
    new_rs = replica_set("web-new", deployment, revision: 2, replicas: 2, image: "example/web:2")
    result = controller.plan(deployment, replicasets: [old_rs, new_rs], now: NOW)

    update = result.updates.find { |operation| operation.resource.kind == "Deployment" }

    assert_equal "example/web:1", update.object.dig("spec", "template", "spec", "containers", 0, "image")
    refute update.object.dig("metadata", "annotations").key?("deprecated.deployment.rollback.to")
    assert_includes result.events.map { |event| event.fetch("reason") }, "DeploymentRollback"
  end

  def test_progress_deadline_exceeded_marks_progressing_false_and_requeues_before_the_deadline
    deployment = deployment(replicas: 1, progress_deadline_seconds: 100, generation: 2)
    stuck = replica_set("web-stuck", deployment, revision: 1, replicas: 1, image: "example/web:1", available: 0, status_replicas: 1)
    progressing = {"type" => "Progressing", "status" => "True", "reason" => "ReplicaSetUpdated", "message" => "x",
                   "lastUpdateTime" => (NOW - 40).iso8601(6), "lastTransitionTime" => (NOW - 40).iso8601(6)}
    available = {"type" => "Available", "status" => "False", "reason" => "MinimumReplicasUnavailable",
                 "message" => "Deployment does not have minimum availability.",
                 "lastUpdateTime" => (NOW - 40).iso8601(6), "lastTransitionTime" => (NOW - 40).iso8601(6)}
    deployment["status"] = {"observedGeneration" => 2, "replicas" => 1, "updatedReplicas" => 1, "unavailableReplicas" => 1,
                            "terminatingReplicas" => 0, "conditions" => [available, progressing]}
    deployment["metadata"]["annotations"] = {"deployment.kubernetes.io/revision" => "1"}
    waiting = controller.plan(deployment, replicasets: [stuck], now: NOW)

    assert_in_delta 61.0, waiting.requeue_after, 0.001
    assert_equal "ReplicaSetUpdated", waiting.status.fetch("conditions").find { |condition|
      condition.fetch("type") == "Progressing"
    }.fetch("reason")

    expired = controller.plan(deployment, replicasets: [stuck], now: NOW + 70)
    condition = expired.status.fetch("conditions").find { |candidate| candidate.fetch("type") == "Progressing" }

    assert_equal "False", condition.fetch("status")
    assert_equal "ProgressDeadlineExceeded", condition.fetch("reason")
    assert_equal "ReplicaSet \"web-stuck\" has timed out progressing.", condition.fetch("message")
  end

  def test_complete_rollout_sets_new_replica_set_available_and_minimum_availability
    deployment = deployment(replicas: 2, generation: 1)
    deployment["metadata"]["annotations"] = {"deployment.kubernetes.io/revision" => "1"}
    ready = replica_set("web-ready", deployment, revision: 1, replicas: 2, image: "example/web:1", available: 2, status_replicas: 2,
                                                 ready: 2)
    result = controller.plan(deployment, replicasets: [ready], now: NOW)
    reasons = result.status.fetch("conditions").to_h { |condition| [condition.fetch("type"), condition.fetch("reason")] }

    assert_equal({"Available" => "MinimumReplicasAvailable", "Progressing" => "NewReplicaSetAvailable"}, reasons)
    assert_equal 2, result.status.fetch("availableReplicas")
    assert_equal 2, result.status.fetch("readyReplicas")
    assert_equal 0, result.status.fetch("unavailableReplicas")
  end

  def test_paused_deployment_only_scales_and_records_paused_condition
    deployment = deployment(replicas: 3, image: "example/web:2", paused: true, generation: 2)
    old_rs = replica_set("web-old", deployment, revision: 1, replicas: 2, image: "example/web:1", available: 2, status_replicas: 2)
    result = controller.plan(deployment, replicasets: [old_rs], now: NOW)

    assert_empty result.creates, "no rollout while paused"
    scaled = result.updates.find { |operation| operation.resource.kind == "ReplicaSet" }

    assert_equal 3, scaled.object.dig("spec", "replicas"), "the single active ReplicaSet follows the deployment size"
    condition = result.status.fetch("conditions").find { |candidate| candidate.fetch("type") == "Progressing" }

    assert_equal(["Unknown", "DeploymentPaused", "Deployment is paused"], %w[status reason message].map { |key| condition.fetch(key) })
  end

  def test_min_ready_seconds_is_propagated_to_the_replica_set_and_gates_availability
    deployment = deployment(replicas: 1, min_ready_seconds: 30)
    created = controller.plan(deployment, replicasets: [], now: NOW).creates.first.object

    assert_equal 30, created.dig("spec", "minReadySeconds")

    rs = created.merge("metadata" => created.fetch("metadata").merge("uid" => "uid-rs"))
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "web-pod", "namespace" => "default", "uid" => "uid-pod",
                          "labels" => rs.dig("spec", "selector", "matchLabels"),
                          "ownerReferences" => [Support.owner_reference(rs)]},
           "spec" => {"nodeName" => "node-a"},
           "status" => {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => "True", "lastTransitionTime" => (NOW - 10).iso8601(6)}]}}
    rs_controller = Controller::ReplicaSetController.new(clock: -> { NOW })
    early = rs_controller.plan(rs, pods: [pod], now: NOW)

    assert_equal 1, early.status.fetch("readyReplicas")
    assert_equal 0, early.status.fetch("availableReplicas")
    assert_in_delta(30.0, early.requeue_after)
    late = rs_controller.plan(rs, pods: [pod], now: NOW + 31)

    assert_equal 1, late.status.fetch("availableReplicas")
  end

  def test_scaling_event_distributes_replicas_proportionally_across_active_replica_sets
    deployment = deployment(replicas: 10, image: "example/web:2", generation: 2)
    old_rs = replica_set("web-old", deployment, revision: 1, replicas: 3, image: "example/web:1", available: 3, status_replicas: 3,
                                                desired: 5, max: 7)
    new_rs = replica_set("web-new", deployment, revision: 2, replicas: 4, image: "example/web:2", available: 4, status_replicas: 4,
                                                desired: 5, max: 7)
    deployment["metadata"]["annotations"] = {"deployment.kubernetes.io/revision" => "2"}
    deployment["status"] = {"replicas" => 7}
    result = controller.plan(deployment, replicasets: [old_rs, new_rs], now: NOW)

    sizes = result.updates.select { |operation| operation.resource.kind == "ReplicaSet" }.to_h do |operation|
      [operation.object.dig("metadata", "name"), operation.object.dig("spec", "replicas")]
    end

    assert_equal 11, sizes.values.sum, "allowed size is replicas plus maxSurge"
    assert_equal({"web-new" => 6, "web-old" => 5}, sizes)
  end

  private

  def controller
    Controller::DeploymentController.new(clock: -> { NOW })
  end

  def deployment(replicas:, image: "example/web:1", generation: 1, progress_deadline_seconds: nil, paused: nil, min_ready_seconds: nil)
    spec = {"replicas" => replicas, "selector" => {"matchLabels" => {"app" => "web"}},
            "strategy" => {"type" => "RollingUpdate", "rollingUpdate" => {"maxSurge" => 1, "maxUnavailable" => 0}},
            "template" => {"metadata" => {"labels" => {"app" => "web"}},
                           "spec" => {"containers" => [{"name" => "web", "image" => image}]}}}
    spec["progressDeadlineSeconds"] = progress_deadline_seconds unless progress_deadline_seconds.nil?
    spec["paused"] = paused unless paused.nil?
    spec["minReadySeconds"] = min_ready_seconds unless min_ready_seconds.nil?
    {"apiVersion" => "apps/v1", "kind" => "Deployment",
     "metadata" => {"name" => "web", "namespace" => "default", "uid" => "uid-deployment", "generation" => generation},
     "spec" => spec}
  end

  def replica_set(name, owner, revision:, replicas:, image:, available: 0, status_replicas: nil, ready: nil, owned: true,
                  desired: nil, max: nil)
    hash = name.split("-").last
    annotations = {"deployment.kubernetes.io/revision" => revision.to_s}
    annotations["deployment.kubernetes.io/desired-replicas"] = desired.to_s unless desired.nil?
    annotations["deployment.kubernetes.io/max-replicas"] = max.to_s unless max.nil?
    metadata = {"name" => name, "namespace" => "default", "uid" => "uid-#{name}", "generation" => 1,
                "creationTimestamp" => (NOW - 3600 - revision).iso8601(6),
                "labels" => {"app" => "web", "pod-template-hash" => hash}, "annotations" => annotations}
    metadata["ownerReferences"] = [Support.owner_reference(owner)] if owned
    status = {"replicas" => status_replicas || replicas, "observedGeneration" => 1, "terminatingReplicas" => 0}
    status["availableReplicas"] = available if available.positive?
    status["readyReplicas"] = ready || available if (ready || available).positive?
    {"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "metadata" => metadata,
     "spec" => {"replicas" => replicas, "selector" => {"matchLabels" => {"app" => "web", "pod-template-hash" => hash}},
                "template" => {"metadata" => {"labels" => {"app" => "web", "pod-template-hash" => hash}},
                               "spec" => {"containers" => [{"name" => "web", "image" => image}]}}},
     "status" => status}
  end
end
