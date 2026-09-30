# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# An Eviction is checked against every PodDisruptionBudget that selects the Pod:
# a budget with no disruptions left refuses it with 429
# (pkg/registry/core/pod/storage/eviction.go:418-457) and a successful eviction
# spends one disruption.  None of it existed -- eviction was an unconditional
# delete -- so "[sig-apps] DisruptionController should block an eviction until
# the PDB is updated to allow it" could never pass.
class EvictionDisruptionBudgetTest < Minitest::Test
  Server = Rubernetes::API::Server

  class Store
    attr_reader :updates

    def initialize(budgets)
      @budgets = budgets
      @updates = []
    end

    def list(resource:, namespace: nil, **)
      return {"items" => []} unless resource.kind == "PodDisruptionBudget"

      {"items" => @budgets}
    end

    def update(resource:, namespace:, name:, object:, **)
      @updates << object
      object
    end
  end

  def budget(allowed:, name: "pdb", healthy: 3, desired: 2)
    {"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget",
     "metadata" => {"name" => name, "namespace" => "ns", "resourceVersion" => "1"},
     "spec" => {"selector" => {"matchLabels" => {"app" => "demo"}}},
     "status" => {"disruptionsAllowed" => allowed, "currentHealthy" => healthy,
                  "desiredHealthy" => desired}}
  end

  def pod(labels = {"app" => "demo"})
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "labels" => labels}}
  end

  def server_for(store)
    server = Server.allocate
    server.instance_variable_set(:@store, store)
    server.instance_variable_set(:@clock, -> { Time.at(0).utc })
    server
  end

  def test_an_eviction_is_allowed_when_the_budget_has_room
    store = Store.new([budget(allowed: 1)])
    server_for(store).send(:check_disruption_budgets!, "ns", pod)

    assert_equal 1, store.updates.length
    assert_equal 0, store.updates.first.dig("status", "disruptionsAllowed")
    assert store.updates.first.dig("status", "disruptedPods").key?("p")
  end

  def test_an_eviction_is_refused_when_the_budget_is_exhausted
    store = Store.new([budget(allowed: 0, healthy: 2, desired: 2)])
    error = assert_raises(Rubernetes::API::Status::TooManyRequests) do
      server_for(store).send(:check_disruption_budgets!, "ns", pod)
    end

    assert_includes error.message, "Cannot evict pod as it would violate the pod's disruption budget."
    assert_empty store.updates
  end

  def test_the_refusal_explains_which_budget_and_why
    store = Store.new([budget(allowed: 0, healthy: 1, desired: 3, name: "web-pdb")])
    error = assert_raises(Rubernetes::API::Status::TooManyRequests) do
      server_for(store).send(:check_disruption_budgets!, "ns", pod)
    end
    cause = error.details.fetch("causes").first

    assert_equal "DisruptionBudget", cause.fetch("reason")
    assert_includes cause.fetch("message"), "web-pdb"
    assert_includes cause.fetch("message"), "needs 3 healthy pods and has 1 currently"
  end

  # An empty LabelSelector selects every Pod in the namespace, which is how the
  # conformance specs write a budget that blocks everything.
  def test_a_budget_with_an_empty_selector_covers_every_pod
    store = Store.new([{"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget",
                        "metadata" => {"name" => "all", "namespace" => "ns", "resourceVersion" => "1"},
                        "spec" => {"selector" => {}},
                        "status" => {"disruptionsAllowed" => 0, "currentHealthy" => 1, "desiredHealthy" => 1}}])

    assert_raises(Rubernetes::API::Status::TooManyRequests) do
      server_for(store).send(:check_disruption_budgets!, "ns", pod("unrelated" => "label"))
    end
  end

  def test_a_matchexpression_budget_selects_by_operator
    budget = {"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget",
              "metadata" => {"name" => "expr", "namespace" => "ns", "resourceVersion" => "1"},
              "spec" => {"selector" => {"matchExpressions" => [{"key" => "app", "operator" => "In",
                                                                "values" => %w[demo other]}]}},
              "status" => {"disruptionsAllowed" => 0, "currentHealthy" => 1, "desiredHealthy" => 1}}

    assert_raises(Rubernetes::API::Status::TooManyRequests) do
      server_for(Store.new([budget])).send(:check_disruption_budgets!, "ns", pod)
    end
    store = Store.new([budget])
    server_for(store).send(:check_disruption_budgets!, "ns", pod("app" => "elsewhere"))

    assert_empty store.updates
  end

  def test_a_budget_that_does_not_select_the_pod_is_ignored
    store = Store.new([budget(allowed: 0)])
    server_for(store).send(:check_disruption_budgets!, "ns", pod("app" => "other"))

    assert_empty store.updates
  end

  def test_a_dry_run_never_spends_a_disruption
    store = Store.new([budget(allowed: 1)])
    server_for(store).send(:check_disruption_budgets!, "ns", pod, dry_run: true)

    assert_empty store.updates
  end

  def test_no_budgets_at_all_is_allowed
    store = Store.new([])
    server_for(store).send(:check_disruption_budgets!, "ns", pod)

    assert_empty store.updates
  end

  # client-go retries a 429 carrying Retry-After by itself, ten times: a refusal
  # from a budget with no room must carry no hint (eviction.go: 0), or every
  # refused eviction takes ten retry intervals.
  def test_an_exhausted_budget_refuses_without_a_retry_hint
    store = Store.new([budget(allowed: 0, healthy: 2, desired: 2)])
    error = assert_raises(Rubernetes::API::Status::TooManyRequests) do
      server_for(store).send(:check_disruption_budgets!, "ns", pod)
    end
    refute error.details.key?("retryAfterSeconds")
  end

  def test_a_budget_the_controller_has_not_processed_asks_to_retry
    pending = budget(allowed: 1)
    pending["metadata"]["generation"] = 2
    pending["status"]["observedGeneration"] = 1
    store = Store.new([pending])
    error = assert_raises(Rubernetes::API::Status::TooManyRequests) do
      server_for(store).send(:check_disruption_budgets!, "ns", pod)
    end
    assert_equal 10, error.details.fetch("retryAfterSeconds")
    assert_includes error.details.fetch("causes").first.fetch("message"), "still being processed"
    assert_empty store.updates
  end

  def test_a_negative_budget_is_forbidden
    store = Store.new([budget(allowed: -1)])
    assert_raises(Rubernetes::API::Status::Forbidden) do
      server_for(store).send(:check_disruption_budgets!, "ns", pod)
    end
  end
end
