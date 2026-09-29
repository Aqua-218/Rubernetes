# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# Score plugins as the v1.36.2 framework runs them (PreScore/Skip, Score,
# NormalizeScore over the feasible nodes); tools/differential/
# scheduler_pod_level_differential.rb checks the same plugins against the
# upstream scheduler itself.
class SchedulerUpstreamScoringTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler
  Scores = Scheduler::Scores

  def node(name, zone, taints: [])
    Scheduler::Node.new({"apiVersion" => "v1", "kind" => "Node",
                         "metadata" => {"name" => name, "labels" => {"topology.kubernetes.io/zone" => zone, "kubernetes.io/hostname" => name}},
                         "spec" => {"taints" => taints},
                         "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi", "pods" => "10"},
                                      "conditions" => [{"type" => "Ready", "status" => "True"}]}})
  end

  def pod(name, labels: {}, node: nil, affinity: nil, spread: nil, owner: nil)
    spec = {"containers" => [{"name" => "c", "image" => "i", "resources" => {"requests" => {"cpu" => "100m"}}}]}
    spec["nodeName"] = node if node
    spec["affinity"] = affinity if affinity
    spec["topologySpreadConstraints"] = spread if spread
    metadata = {"name" => name, "namespace" => "default", "uid" => "#{name}-uid", "labels" => labels}
    metadata["ownerReferences"] = [owner] if owner
    Scheduler::Pod.new({"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata, "spec" => spec})
  end

  def context(nodes, pods, **options)
    Scheduler::CycleContext.new(nodes: nodes, pods: pods, **options)
  end

  def test_taint_toleration_is_reversed_by_the_highest_count
    nodes = [node("a", "z1", taints: [{"key" => "x", "effect" => "PreferNoSchedule"}]),
             node("b", "z1", taints: [{"key" => "x", "effect" => "PreferNoSchedule"}, {"key" => "y", "effect" => "PreferNoSchedule"}])]
    scores = Scores::TaintToleration.new.score_nodes(pod("p"), nodes, context(nodes, []))
    # DefaultNormalizeScore(reverse): 100 - count * 100 / max, not a min-max range.
    assert_equal({"a" => 50, "b" => 0}, scores)
  end

  def test_node_affinity_and_balanced_allocation_skip
    nodes = [node("a", "z1")]
    assert_same Scores::SKIP, Scores::NodeAffinity.new.score_nodes(pod("p"), nodes, context(nodes, []))
    best_effort = Scheduler::Pod.new({"metadata" => {"name" => "be", "namespace" => "default"}, "spec" => {"containers" => [{"name" => "c"}]}})
    assert_same Scores::SKIP, Scores::NodeResourcesBalancedAllocation.new.score_nodes(best_effort, nodes, context(nodes, []))
  end

  def test_skipped_plugins_are_left_out_of_the_breakdown
    result = Scheduler.new.schedule(pod("p").to_h, [node("a", "z1").to_h])
    names = result.scores.first.plugins.map { |entry| entry["plugin"] }
    refute_includes names, "NodeAffinity"
    refute_includes names, "InterPodAffinity"
    refute_includes names, "PodTopologySpread"
    assert_includes names, "NodeResourcesFit"
  end

  def test_inter_pod_affinity_counts_existing_pods_terms_symmetrically
    nodes = [node("a", "z1"), node("b", "z2")]
    wants_web = {"podAffinity" => {"preferredDuringSchedulingIgnoredDuringExecution" => [
      {"weight" => 4, "podAffinityTerm" => {"labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "topology.kubernetes.io/zone"}}]}}
    existing = [pod("peer", node: "b", affinity: wants_web)]
    scores = Scores::InterPodAffinity.new.score_nodes(pod("web", labels: {"app" => "web"}), nodes, context(nodes, existing))
    assert_equal({"a" => 0, "b" => 100}, scores)
    # Nothing contributes: Skip.
    assert_same Scores::SKIP, Scores::InterPodAffinity.new.score_nodes(pod("other", labels: {"app" => "db"}), nodes, context(nodes, existing))
  end

  def test_inter_pod_affinity_equal_scores_normalize_to_zero
    nodes = [node("a", "z1"), node("b", "z1")]
    wants_web = {"podAffinity" => {"preferredDuringSchedulingIgnoredDuringExecution" => [
      {"weight" => 4, "podAffinityTerm" => {"labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "topology.kubernetes.io/zone"}}]}}
    existing = [pod("peer", node: "b", affinity: wants_web)]
    scores = Scores::InterPodAffinity.new.score_nodes(pod("web", labels: {"app" => "web"}), nodes, context(nodes, existing))
    assert_equal({"a" => 0, "b" => 0}, scores)
  end

  def test_system_default_spreading_uses_service_selectors
    nodes = [node("a", "z1"), node("b", "z2")]
    existing = [pod("w1", labels: {"app" => "web"}, node: "a"), pod("w2", labels: {"app" => "web"}, node: "a")]
    incoming = pod("w3", labels: {"app" => "web"})
    plugin = Scores::TopologySpread.new
    # Without Service/controller data there is nothing to spread by.
    assert_same Scores::SKIP, plugin.score_nodes(incoming, nodes, context(nodes, existing))
    selectors = {"services" => [{"namespace" => "default", "selector" => {"app" => "web"}}], "controllers" => {}}
    scores = plugin.score_nodes(incoming, nodes, context(nodes, existing, workload_selectors: selectors))
    assert_operator scores.fetch("b"), :>, scores.fetch("a")
    assert_equal 100, scores.fetch("b")
  end

  def test_system_default_spreading_uses_the_owning_replica_set
    nodes = [node("a", "z1"), node("b", "z2")]
    owner = {"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "name" => "rs", "controller" => true}
    existing = [pod("w1", labels: {"app" => "web"}, node: "b", owner: owner)]
    selectors = {"services" => [], "controllers" => {"ReplicaSet/default/rs" => {"matchLabels" => {"app" => "web"}}}}
    scores = Scores::TopologySpread.new.score_nodes(pod("w2", labels: {"app" => "web"}, owner: owner), nodes,
                                                    context(nodes, existing, workload_selectors: selectors))
    assert_operator scores.fetch("a"), :>, scores.fetch("b")
  end

  def test_soft_constraints_only
    nodes = [node("a", "z1"), node("b", "z2")]
    hard = [{"maxSkew" => 1, "topologyKey" => "topology.kubernetes.io/zone", "whenUnsatisfiable" => "DoNotSchedule",
             "labelSelector" => {"matchLabels" => {"app" => "web"}}}]
    assert_same Scores::SKIP, Scores::TopologySpread.new.score_nodes(pod("w", labels: {"app" => "web"}, spread: hard), nodes, context(nodes, []))
  end
end
