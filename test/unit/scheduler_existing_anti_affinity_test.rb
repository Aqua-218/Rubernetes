# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

class SchedulerExistingAntiAffinityTest < Minitest::Test
  S = Rubernetes::Scheduler
  REQUIRED = "requiredDuringSchedulingIgnoredDuringExecution"
  ZONE = "topology.kubernetes.io/zone"
  EXISTING_REASON = "node(s) didn't satisfy existing pods anti-affinity rules"

  def test_existing_required_term_rejects_the_unconstrained_pod_across_the_topology_domain
    owner = pod("owner", node: "a", terms: [term({"matchLabels" => {"app" => "web"}})])
    pending = pod("incoming", labels: {"app" => "web"})
    result = S.new(preemption: false).schedule(pending, [node("a", "east"), node("b", "east"), node("c", "west")], pods: [owner])

    assert_equal "c", result.node_name
    %w[a b].each do |name|
      rejected = result.filtered.fetch(name)

      assert_equal "InterPodAffinity", rejected.fetch("plugin")
      assert_equal EXISTING_REASON, rejected.fetch("reason")
    end
  end

  def test_existing_term_uses_the_owner_default_namespace_and_explicit_selector_union
    local = pod("incoming", namespace: "clients")
    candidate = node("target", "east")
    owner = pod("owner", node: "a", namespace: "owners", terms: [term({})])

    assert_equal true, filter(local, candidate, [owner])

    selector = {"matchLabels" => {"group" => "selected"}}
    expanded = pod("owner", node: "a", namespace: "owners", terms: [
                     term({}, "namespaceSelector" => selector, "namespaces" => ["partners"])
                   ])
    labels = {"clients" => {"group" => "selected"}, "owners" => {"group" => "different"}}

    assert_equal EXISTING_REASON, filter(local, candidate, [expanded], namespace_data: labels).reason
    assert_equal EXISTING_REASON, filter(pod("partner", namespace: "partners"), candidate, [expanded]).reason
    assert_equal true, filter(pod("outside", namespace: "outside"), candidate, [expanded], namespace_data: labels)
    assert_equal true, filter(local, node("missing", nil), [expanded], namespace_data: labels)
  end

  def test_nil_selector_matches_nothing_and_empty_selector_matches_every_pod_in_both_directions
    candidate = node("target", "east")
    pending = pod("incoming")
    absent = pod("owner", node: "a", terms: [term(nil)])
    everything = pod("owner", node: "a", terms: [term({})])
    assigned = pod("owner", node: "a")

    assert_equal true, filter(pending, candidate, [absent])
    assert_equal EXISTING_REASON, filter(pending, candidate, [everything]).reason
    assert_equal true, filter(pod("incoming", terms: [term(nil)]), candidate, [assigned])
    assert_equal "node violates required pod anti-affinity", filter(pod("incoming", terms: [term({})]), candidate, [assigned]).reason
  end

  def test_label_key_expressions_keep_the_values_admitted_when_the_owner_was_created
    candidate = node("target", "east")
    cases = [
      %w[matchLabelKeys In original],
      %w[mismatchLabelKeys NotIn edited]
    ]
    cases.each do |field, operator, pending_value|
      selector = {"matchExpressions" => [{"key" => "track", "operator" => operator, "values" => ["original"]}]}
      owner = pod("owner", node: "a", labels: {"track" => "edited"}, terms: [term(selector, field => ["track"])])
      pending = pod("incoming", labels: {"track" => pending_value})

      assert_equal EXISTING_REASON, filter(pending, candidate, [owner]).reason
      assert_equal selector, owner.pod_anti_affinity.fetch(REQUIRED).first.fetch("labelSelector")
    end

    # No requirement was merged if the key was absent when the Pod was created.
    owner = pod("owner", node: "a", labels: {"track" => "new"}, terms: [term({}, "matchLabelKeys" => ["track"])])

    assert_equal EXISTING_REASON, filter(pod("incoming", labels: {"track" => "other"}), candidate, [owner]).reason
  end

  def test_embedded_node_pods_are_placed_without_mutating_the_original_snapshot
    owner = pod("embedded", terms: [term({})])
    pending = pod("incoming")
    source = node("a", "east", pods: [owner])
    result = S.new(preemption: false).schedule(pending, [source, node("b", "west")])

    assert_equal "b", result.node_name
    assert_equal EXISTING_REASON, result.filtered.fetch("a").fetch("reason")
    assert_empty owner.node_name
  end

  def test_preemption_trials_remove_and_reinsert_the_existing_anti_affinity_owner
    owner = pod("owner", node: "a", priority: 1, terms: [term({})])
    other = pod("unrelated", node: "a", priority: 2)
    pending = pod("incoming", priority: 10)
    removed = []
    scheduler = S.new(async_preemption: false, delete_pod: ->(victim) { removed << victim.name })
    result = scheduler.schedule(pending, [node("a", "east")], pods: [owner, other])

    assert_predicate result, :unschedulable?
    assert_equal "a", result.nominated_node
    assert_equal ["owner"], result.victims.map(&:name)
    assert_equal ["owner"], removed
  end

  def test_topology_matches_are_calculated_once_and_not_reused_after_placement_changes
    nodes = [node("a", "east"), node("b", "east"), node("c", "west")]
    owner = pod("owner", node: "a", terms: [term({})])
    pending = pod("incoming")
    context = S::CycleContext.new(nodes: nodes, pods: [owner])
    filter = S::Filters::PodAntiAffinity.new
    helpers = S::Filters::Helpers
    evaluate = helpers.method(:forbidden_anti_affinity_domains)
    evaluations = []
    tracked = lambda do |*args|
      evaluations << true
      evaluate.call(*args)
    end

    helpers.stub(:forbidden_anti_affinity_domains, tracked) do
      assert_equal EXISTING_REASON, filter.call(pending, nodes[0], context).reason
      assert_equal EXISTING_REASON, filter.call(pending, nodes[1], context).reason
      assert_equal true, filter.call(pending, nodes[2], context)
      assert_equal true, filter.call(pending, nodes[0], context.with(pods: []))
    end

    assert_equal 1, evaluations.length
  end

  private

  def term(selector, **attributes)
    {"topologyKey" => ZONE, "labelSelector" => selector}.merge(attributes)
  end

  def node(name, zone, pods: nil)
    labels = {"kubernetes.io/hostname" => name}
    labels[ZONE] = zone if zone
    S::Node.new({"kind" => "Node", "metadata" => {"name" => name, "labels" => labels},
                 "ready" => true, "allocatable" => {"cpu" => "8", "memory" => "8Gi", "pods" => "100"}}, pods: pods)
  end

  def pod(name, namespace: "default", node: nil, labels: {}, priority: 0, terms: nil)
    spec = {"containers" => [{"name" => "app", "image" => "pause"}], "priority" => priority}
    spec["nodeName"] = node if node
    spec["affinity"] = {"podAntiAffinity" => {REQUIRED => terms}} if terms
    S::Pod.new("kind" => "Pod", "metadata" => {"name" => name, "namespace" => namespace, "uid" => name, "labels" => labels}, "spec" => spec)
  end

  def filter(pod, candidate, owners, namespace_data: {})
    context = S::CycleContext.new(nodes: [node("a", "east"), candidate], pods: owners, namespace_data: namespace_data)
    S::Filters::PodAntiAffinity.new.call(pod, candidate, context)
  end
end
