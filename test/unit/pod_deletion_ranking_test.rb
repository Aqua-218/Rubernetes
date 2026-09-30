# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# replica_set.go getPodsToDelete / ActivePodsWithRanks: which Pods a
# ReplicaSet scales down first.  Before this, the controller only looked at
# scheduling, the Pending phase and the creation time; pod-deletion-cost,
# readiness, doubled-up nodes and restarts were ignored.  The whole order is
# checked against upstream by tools/differential/pod_deletion_ranking_differential.rb.
class PodDeletionRankingTest < Minitest::Test
  Controller = Rubernetes::Controller
  Ranking = Controller::PodDeletionRanking
  NOW = Time.utc(2026, 9, 24, 5, 0, 0)

  def pod(name, node: "n1", ready: true, cost: nil, created: 3600, restarts: 0, owner: nil, uid: nil)
    metadata = {"name" => name, "namespace" => "ns", "uid" => uid || "uid-#{name}",
                "creationTimestamp" => (NOW - created).iso8601, "labels" => {"app" => "web"}}
    metadata["annotations"] = {Ranking::DELETION_COST_ANNOTATION => cost} if cost
    metadata["ownerReferences"] = [Controller::Support.owner_reference(owner)] if owner
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata,
     "spec" => {"nodeName" => node, "containers" => [{"name" => "app", "image" => "x"}]},
     "status" => {"phase" => "Running",
                  "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False",
                                    "lastTransitionTime" => (NOW - created).iso8601}],
                  "containerStatuses" => [{"name" => "app", "restartCount" => restarts}]}}
  end

  def names(pods) = pods.map { |entry| entry.dig("metadata", "name") }

  def test_the_deletion_cost_annotation_orders_otherwise_equal_pods
    pods = [pod("expensive", cost: "100"), pod("default"), pod("cheap", cost: "-5"), pod("invalid", cost: "+7")]

    assert_equal %w[cheap default invalid], names(Ranking.pods_to_delete(pods, 3, now: NOW)), "an invalid cost counts as 0"
  end

  def test_not_ready_then_doubled_up_then_restarts_go_first
    pods = [pod("ready-alone", node: "n2"), pod("ready-shared-a"), pod("ready-shared-b"), pod("not-ready", node: "n3", ready: false)]

    assert_equal %w[not-ready ready-shared-a ready-shared-b], names(Ranking.pods_to_delete(pods, 3, now: NOW))
    restarted = [pod("steady", node: "a"), pod("crashy", node: "b", restarts: 4)]

    assert_equal %w[crashy], names(Ranking.pods_to_delete(restarted, 1, now: NOW))
  end

  def test_ages_in_the_same_power_of_two_bucket_tie_on_the_uid
    # 3600 s and 3700 s ago fall in the same log2(ns) bucket: the lower UID
    # goes first, not the newer Pod.
    pods = [pod("newer", created: 3600, uid: "b"), pod("older", created: 3700, uid: "a")]

    assert_equal %w[older], names(Ranking.pods_to_delete(pods, 1, now: NOW))
    far = [pod("hour", created: 3600, uid: "a"), pod("day", created: 86_400, uid: "b")]

    assert_equal %w[hour], names(Ranking.pods_to_delete(far, 1, now: NOW)), "a different bucket: the newer goes"
  end

  def test_the_replicaset_counts_its_sibling_sets_pods_on_a_node
    deployment_ref = {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "web", "uid" => "dep-uid", "controller" => true}
    old_set = {"apiVersion" => "apps/v1", "kind" => "ReplicaSet",
               "metadata" => {"name" => "web-old", "namespace" => "ns", "uid" => "rs-old", "ownerReferences" => [deployment_ref]},
               "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "web"}}, "template" => {"metadata" => {"labels" => {"app" => "web"}}}}}
    new_set = Controller::Support.deep_copy(old_set)
    new_set["metadata"].merge!("name" => "web-new", "uid" => "rs-new")
    new_set["spec"]["replicas"] = 1
    adapter = Object.new
    adapter.define_singleton_method(:list) { |descriptor, **| descriptor.kind == "ReplicaSet" ? [old_set, new_set] : [] }
    # web-new's own Pods sit on n1 and n2; an old-set Pod shares n2, so the
    # new set's n2 Pod is the doubled-up one.
    pods = [pod("new-on-n1", node: "n1", owner: new_set), pod("new-on-n2", node: "n2", owner: new_set),
            pod("old-on-n2", node: "n2", owner: old_set)]
    result = Controller::ReplicaSetController.new.plan(new_set, store: adapter, pods: pods, now: NOW)

    assert_equal(%w[new-on-n2], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
  end
end
