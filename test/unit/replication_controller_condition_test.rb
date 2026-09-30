# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# replica_set_utils.go calculateStatus publishes observedGeneration, readiness
# counts and a ReplicaFailure condition describing the last refused write.
# Ours published neither, so "[sig-apps] ReplicationController should surface a
# failure condition on a common issue like exceeded quota" -- which polls
# `generation > status.observedGeneration` before it even looks at the
# conditions -- waited a minute and reported
# `rc manager never added the failure condition`.
class ReplicationControllerConditionTest < Minitest::Test
  Controller = Rubernetes::Controller

  def setup
    Controller::ApplyFailures.reset!
  end

  def teardown
    Controller::ApplyFailures.reset!
  end

  def replication_controller(replicas: 3, generation: 4, conditions: nil)
    status = {"replicas" => 2}
    status["conditions"] = conditions if conditions
    {"apiVersion" => "v1", "kind" => "ReplicationController",
     "metadata" => {"name" => "condition-test", "namespace" => "rc-1", "uid" => "rc-uid",
                    "generation" => generation},
     "spec" => {"replicas" => replicas, "selector" => {"name" => "condition-test"},
                "template" => {"metadata" => {"labels" => {"name" => "condition-test"}},
                               "spec" => {"containers" => [{"name" => "c", "image" => "agnhost"}]}}},
     "status" => status}
  end

  def pod(name, ready: true)
    conditions = [{"type" => "Ready", "status" => ready ? "True" : "False"}]
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "rc-1", "uid" => "#{name}-uid",
                    "labels" => {"name" => "condition-test"},
                    "ownerReferences" => [{"apiVersion" => "v1", "kind" => "ReplicationController",
                                           "name" => "condition-test", "uid" => "rc-uid",
                                           "controller" => true}]},
     "spec" => {}, "status" => {"phase" => "Running", "conditions" => conditions}}
  end

  def controller = Controller::ReplicationControllerController.new(store: nil)

  # The manager records the failure under the name the result carries, which is
  # the controller's own name (result_for sets `controller: name`).
  def record_failure(message)
    Controller::ApplyFailures.record(controller.name, "rc-1/condition-test",
                                     Controller::StoreError.new(message))
  end

  def status_of(result) = result.status

  def condition(result)
    Array(result.status["conditions"]).find { |value| value["type"] == "ReplicaFailure" }
  end

  def test_the_generation_the_controller_acted_on_is_published
    result = controller.plan(replication_controller, pods: [pod("a"), pod("b")])

    assert_equal(4, status_of(result)["observedGeneration"])
  end

  def test_readiness_counts_are_published
    result = controller.plan(replication_controller(replicas: 2),
                             pods: [pod("a"), pod("b", ready: false)])

    assert_equal(1, status_of(result)["readyReplicas"])
    assert_equal(1, status_of(result)["availableReplicas"])
  end

  # A refused create is remembered by the manager and read here on the next
  # sync; the quota message itself is what upstream puts in the condition.
  def test_a_refused_create_becomes_a_failure_condition
    message = 'pods "condition-test-x" is forbidden: exceeded quota: condition-test, ' \
              "requested: pods=1, used: pods=2, limited: pods=2"
    record_failure(message)

    result = controller.plan(replication_controller, pods: [pod("a"), pod("b")])

    found = condition(result)

    refute_nil(found, "no ReplicaFailure condition: #{result.status.inspect}")
    assert_equal("True", found["status"])
    assert_equal("FailedCreate", found["reason"])
    assert_equal(message, found["message"])
  end

  # Too many Pods and a refused delete is the other direction.
  def test_a_refused_delete_is_reported_as_faileddelete
    record_failure("forbidden")

    result = controller.plan(replication_controller(replicas: 1),
                             pods: [pod("a"), pod("b"), pod("c")])

    assert_equal("FailedDelete", condition(result)["reason"])
  end

  def test_the_condition_is_removed_once_the_writes_succeed
    existing = [{"type" => "ReplicaFailure", "status" => "True", "reason" => "FailedCreate",
                 "message" => "exceeded quota"}]

    result = controller.plan(replication_controller(replicas: 2, conditions: existing),
                             pods: [pod("a"), pod("b")])

    assert_nil(condition(result))
  end

  # An existing condition keeps its original lastTransitionTime rather than
  # being restamped on every sync.
  def test_an_existing_condition_is_left_alone
    existing = [{"type" => "ReplicaFailure", "status" => "True", "reason" => "FailedCreate",
                 "message" => "first failure", "lastTransitionTime" => "2026-01-01T00:00:00Z"}]
    record_failure("second failure")

    result = controller.plan(replication_controller(conditions: existing), pods: [pod("a"), pod("b")])

    assert_equal("2026-01-01T00:00:00Z", condition(result)["lastTransitionTime"])
    assert_equal("first failure", condition(result)["message"])
  end

  # The status write has to reach the API before the write that fails, so it
  # gets a batch of its own ahead of the Pod operations.
  def test_the_status_write_is_its_own_first_batch
    result = controller.plan(replication_controller, pods: [pod("a"), pod("b")])

    assert_operator(result.batches.length, :>, 1)
    assert_equal(1, result.batches.first.length)
    assert_equal(:status_update, result.batches.first.first.action)
    assert(result.batches[1].any?(&:create?))
  end
end
