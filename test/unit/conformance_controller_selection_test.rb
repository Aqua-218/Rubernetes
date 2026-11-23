# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/cluster"

# The conformance cluster derives its controller list from the corpus minus
# two exclusions.  One of them -- "the apiserver does not serve this kind" --
# silently dropped the garbage collector, whose kind is the controller-only
# marker "GarbageCollector" that no discovery document can ever contain.  The
# cluster therefore ran with no garbage collection at all: an EndpointSlice
# whose Service was deleted, a ReplicaSet whose Deployment was deleted and a
# CronJob's Jobs all stayed in the API for ever.
class ConformanceControllerSelectionTest < Minitest::Test
  Response = Struct.new(:body)

  def marker_kinds
    Rubernetes::Cluster::CONTROLLER_ONLY_KINDS
  end

  def test_the_garbage_collector_kind_is_treated_as_controller_only
    assert_includes(marker_kinds, "GarbageCollector")
  end

  # Every marker kind has to name a real corpus entry, otherwise the exemption
  # protects nothing and the controller is dropped again.
  def test_every_marker_kind_names_a_corpus_entry
    kinds = Rubernetes::Controller::BuiltinControllerCorpus::ENTRIES.map(&:kind).uniq

    marker_kinds.each { |kind| assert_includes(kinds, kind) }
  end

  # The selection expression must keep a marker kind even when discovery does
  # not list it, while still dropping a kind the apiserver genuinely lacks.
  def test_the_selection_keeps_marker_kinds_and_drops_unserved_ones
    served = %w[Pod Service]
    entries = Rubernetes::Controller::BuiltinControllerCorpus::ENTRIES
    selected = entries.reject do |entry|
      entry.cloud_provider || (!served.include?(entry.kind) && !marker_kinds.include?(entry.kind))
    end.map(&:name)

    assert_includes(selected, "garbage-collector-controller")
    assert_includes(selected, "pod-garbage-collector-controller")
    refute_includes(selected, "job-controller")
  end

  def test_selection_discovers_kinds_from_served_nonpreferred_versions
    api = Rubernetes::API
    group = "scheduling.k8s.io"
    registry = api::Registry.new
    registry.register(group: group, version: "v1", resource: "priorityclasses", kind: "PriorityClass")
    registry.register(group: group, version: "v1alpha2", resource: "podgroups", kind: "PodGroup", scope: :namespaced)
    cluster = Object.new.extend(Rubernetes::Cluster::Configs)
    [false, true].each do |enabled|
      server = api::Server.new(registry: registry, store: api::MemoryStore.new, runtime_config: {"#{group}/v1alpha2" => true},
                               feature_gates: {"GenericWorkload" => enabled})
      client = Object.new
      client.define_singleton_method(:raw) do |method, path|
        response = server.call(api::Request.new(method: method, path: path))
        Response.new(JSON.generate(response.body))
      end
      client.define_singleton_method(:close) { nil }
      cluster.define_singleton_method(:api_client) { |_kubeconfig| client }

      assert_equal enabled, cluster.selected_controllers("fixture").include?("podgroup-protection-controller")
    end
  end
end
