# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/storage/memory_store"

# Every object the store handed out -- a create's response, each list item,
# the event for each watcher -- was a fresh deep copy (a quarter of a
# millisecond for a Pod), so a write with twenty informers watching spent
# most of its time copying.  Objects the store has deep-frozen itself are now
# shared: callers could never mutate them anyway.  Anything else is still
# copied, so a caller's own hash is never aliased and a shallowly frozen hash
# is never mistaken for an immutable one.
class MemoryStoreFrozenSharingTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore
  Support = Rubernetes::Storage::MemoryStoreSupport

  def object(name)
    {"apiVersion" => "v1", "kind" => "Thing", "metadata" => {"name" => name, "namespace" => "ns", "labels" => {"a" => "b"}},
     "spec" => {"items" => [{"x" => 1}]}}
  end

  def test_store_results_are_shared_frozen_objects
    store = Store.new
    created = store.create("registry/things/ns/a", object("a"))
    fetched = store.get("registry/things/ns/a")
    listed = store.list("registry/things/").items.first

    assert created.frozen? && created["spec"]["items"].first.frozen?
    assert_same created, fetched
    assert_same created, listed
    assert_raises(FrozenError) { fetched["spec"]["new"] = 1 }
    assert_raises(FrozenError) { fetched["metadata"]["labels"]["a"] = "c" }
  end

  def test_a_watch_event_carries_the_stored_object_without_copying
    store = Store.new
    watcher = store.watch("registry/things/", since: store.revision)
    created = store.create("registry/things/ns/a", object("a"))
    event = watcher.next(timeout: 1.0)

    assert_equal "ADDED", event.type
    assert_same created, event.object
  end

  def test_the_callers_own_object_is_never_aliased
    store = Store.new
    mine = object("a")
    created = store.create("registry/things/ns/a", mine)

    refute_same mine, created
    mine["spec"]["items"] << {"y" => 2}

    assert_equal 1, store.get("registry/things/ns/a")["spec"]["items"].length
  end

  def test_a_shallowly_frozen_hash_is_still_copied
    shallow = {"metadata" => {"name" => "n"}, "list" => [1]}.freeze
    copy = Support.immutable_copy(shallow)

    refute_same shallow, copy
    assert_predicate copy["metadata"], :frozen?
    shallow["list"] << 2

    assert_equal [1], copy["list"]
  end

  def test_a_deep_frozen_object_is_returned_as_is
    frozen = Support.immutable_copy({"a" => {"b" => [1, "s"]}})

    assert Support.deep_frozen?(frozen)
    assert_same frozen, Support.immutable_copy(frozen)
  end

  def test_canonical_json_matches_the_generated_canonical_form
    value = {"b" => [1, 2.5, nil, true, "xé\n\"q\""], :a => {"z" => Time.at(0).utc, "y" => :sym, 1 => "one"},
             "dup" => {"k" => 1, :k => 2}, "empty" => {}, "list" => []}

    assert_equal JSON.generate(Support.canonical(value)), Support.canonical_json(value)
    assert_equal Digest::SHA256.hexdigest(JSON.generate(Support.canonical(value))), Support.digest(value)
  end
end

# Cycle detection walks with an identity-compared table.  Keying it by value
# instead would hash whole subtrees at every node -- quadratic on a deep
# object -- and would treat two equal-but-distinct subtrees as the same node.
class MemoryStoreCycleDetectionTest < Minitest::Test
  Support = Rubernetes::Storage::MemoryStoreSupport

  def test_equal_but_distinct_subtrees_are_both_copied
    shared_shape = ->(index) { {"name" => "same", "list" => [1, 2, {"deep" => index}]} }
    source = {"a" => shared_shape.call(0), "b" => shared_shape.call(0)}
    copy = Support.deep_dup(source)

    refute_same copy["a"], copy["b"], "two equal subtrees are distinct objects"
    assert_equal copy["a"], copy["b"]
    copy["a"]["list"] << 3

    assert_equal 3, copy["b"]["list"].length, "mutating one must not touch the other"
  end

  def test_a_shared_subtree_stays_shared_in_the_copy
    shared = {"k" => [1]}
    copy = Support.deep_dup({"a" => shared, "b" => shared})

    assert_same copy["a"], copy["b"]
  end

  def test_a_cycle_is_frozen_without_recursing_forever
    cyclic = {"name" => "x"}
    cyclic["self"] = cyclic
    Support.deep_freeze(cyclic)

    assert_predicate cyclic, :frozen?
    assert_same cyclic, cyclic["self"]
  end

  def test_freezing_a_deep_object_stays_linear
    deep = (1..9).reduce({"leaf" => Array.new(50) { |i| {"k" => i} }}) { |acc, i| {"l#{i}" => acc} }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    100.times { Support.deep_freeze(Support.deep_dup(deep)) }
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_operator elapsed, :<, 2.0, "freezing a deep object must not hash whole subtrees per node"
  end
end
