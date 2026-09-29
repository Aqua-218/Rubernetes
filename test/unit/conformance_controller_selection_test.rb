# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller/registry"

# The conformance cluster derives its controller list from the corpus minus
# two exclusions.  One of them -- "the apiserver does not serve this kind" --
# silently dropped the garbage collector, whose kind is the controller-only
# marker "GarbageCollector" that no discovery document can ever contain.  The
# cluster therefore ran with no garbage collection at all: an EndpointSlice
# whose Service was deleted, a ReplicaSet whose Deployment was deleted and a
# CronJob's Jobs all stayed in the API for ever.
class ConformanceControllerSelectionTest < Minitest::Test
  CLUSTER = File.expand_path("../../tools/conformance/cluster.rb", __dir__)

  def setup
    skip("tools/conformance/cluster.rb is not present") unless File.file?(CLUSTER)
    @source = File.read(CLUSTER)
  end

  def marker_kinds
    match = @source[/CONTROLLER_ONLY_KINDS\s*=\s*%w\[([^\]]*)\]/, 1]
    refute_nil(match, "cluster.rb no longer declares CONTROLLER_ONLY_KINDS")
    match.split
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
end
