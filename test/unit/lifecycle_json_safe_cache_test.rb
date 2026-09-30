# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# Lifecycle::ConversionCache (the persist path's json_safe): identity-keyed
# conversions of frozen parts, bounded, alive across GC; mutable parts are
# never cached, so no #hash collision can ever serve a stale conversion.
class LifecycleJSONSafeCacheTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  # A Hash whose #hash never changes, so a mutation "collides" with itself.
  class StickyHash < Hash
    def hash = 42
  end

  def lifecycle = Lifecycle.new(runtime: Object.new)

  def convert(lifecycle, value) = JSON.generate(lifecycle.send(:json_safe, value))

  def test_two_hashes_with_equal_hash_and_different_content_convert_differently
    lc = lifecycle
    left = StickyHash.new.merge!(name: "left", status: {ready: true})
    right = StickyHash.new.merge!(name: "right", status: {ready: false})

    assert_equal left.hash, right.hash
    assert_equal %({"name":"left","status":{"ready":true}}), convert(lc, left)
    assert_equal %({"name":"right","status":{"ready":false}}), convert(lc, right)
    assert_equal %({"name":"left","status":{"ready":true}}), convert(lc, left), "identity keyed: no cross-object reuse"
  end

  def test_a_mutation_with_a_colliding_hash_is_not_served_stale
    lc = lifecycle
    entry = StickyHash.new.merge!(id: "c1", status: {"state" => "running", "restartCount" => 0})

    assert_equal %({"id":"c1","status":{"state":"running","restartCount":0}}), convert(lc, entry)
    entry[:status]["restartCount"] = 1

    assert_equal %({"id":"c1","status":{"state":"running","restartCount":1}}), convert(lc, entry)
    # Mutated back to the earlier content: still exactly the current content.
    entry[:status]["restartCount"] = 0

    assert_equal %({"id":"c1","status":{"state":"running","restartCount":0}}), convert(lc, entry)
    entry[:status] = {"state" => "terminated", "at" => Time.utc(2026, 9, 27, 12, 0, 0)}

    assert_equal %({"id":"c1","status":{"state":"terminated","at":"2026-09-27T12:00:00.000000Z"}}), convert(lc, entry)
  end

  def test_a_frozen_part_is_reused_across_gc_and_a_mutable_one_is_never_cached
    lc = lifecycle
    pod = Rubernetes::Node::Helpers.immutable({"metadata" => {"name" => "p"}, "spec" => {"containers" => []}})
    first = lc.send(:json_safe, pod)
    GC.start
    GC.start

    assert_same first, lc.send(:json_safe, pod), "frozen part: the same conversion after GC"
    entry = {id: "c1", status: {"ready" => true}}
    converted = lc.send(:json_safe, entry)

    refute_same converted, lc.send(:json_safe, entry), "mutable part: converted every time"
    entry[:status]["ready"] = false

    assert_equal({"id" => "c1", "status" => {"ready" => false}}, lc.send(:json_safe, entry))
  end

  def test_the_cache_is_bounded
    cache = Lifecycle::ConversionCache.new(limit: 5)
    values = Array.new(20) { |index| {"n" => index}.freeze }
    values.each { |value| cache.store(value, {"n" => value["n"]}.freeze) }

    assert_equal 5, cache.size
    assert_nil cache.fetch(values[0]), "the oldest was evicted"
    assert_equal({"n" => 19}, cache.fetch(values[19]))
    # A hit refreshes: the next eviction takes the least recently used.
    cache.fetch(values[15])
    cache.store({"n" => 99}.freeze, {"n" => 99}.freeze)

    assert_nil cache.fetch(values[16])
    assert_equal({"n" => 15}, cache.fetch(values[15]))
  end
end
