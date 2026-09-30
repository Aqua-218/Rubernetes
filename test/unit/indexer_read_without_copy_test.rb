# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/watch"

# The informer cache stores deep-frozen private copies, yet every read deep-
# copied and re-froze each object again.  Controllers list the cache on every
# reconcile: a 3000-Pod list took 0.75 s, the endpointslice controller spent
# 1.06 s per Service, and "[sig-network] Service endpoints latency should not
# be very high" measured a 29 s median.  Reads now hand out the stored frozen
# value itself.
class IndexerReadWithoutCopyTest < Minitest::Test
  def pod(name, labels = {"app" => "a"})
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "labels" => labels}}
  end

  def indexer
    idx = Rubernetes::Watch::Indexer.new(indices: {"app" => ->(object) { object.dig("metadata", "labels", "app") }})
    idx.add(pod("p1"))
    idx.add(pod("p2"))
    idx
  end

  def test_repeated_reads_share_the_stored_frozen_object
    idx = indexer

    assert_same idx.list.first, idx.list.first
    assert_same idx.get("ns/p1"), idx.list.first
    assert_same idx.by_index("app", "a").last, idx.list.last
  end

  def test_what_a_reader_gets_cannot_change_the_cache
    idx = indexer
    object = idx.list.first

    assert_predicate object, :frozen?
    assert_predicate object.fetch("metadata").fetch("labels"), :frozen?
    assert_raises(FrozenError) { object["metadata"]["labels"]["app"] = "b" }
    assert_equal "a", idx.get("ns/p1").dig("metadata", "labels", "app")
  end

  def test_a_caller_mutating_its_input_after_add_does_not_reach_the_cache
    idx = Rubernetes::Watch::Indexer.new
    input = pod("p1")
    idx.add(input)
    input["metadata"]["labels"]["app"] = "changed"

    assert_equal "a", idx.get("ns/p1").dig("metadata", "labels", "app")
  end
end
