# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/storage/memory_store"

# The store remembers each request UID's result so a retry replays the same
# answer (S6).  It remembered them for ever: after a long run the replay
# table held every object ever written, and the heap behind it made GC
# pauses long enough to time out linearizable reads.  Replay memory now
# follows the history retention window: the periodic full compaction drops
# entries older than the compacted revision.
class MemoryStoreRequestMemoryRetentionTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore

  def object(name)
    {"apiVersion" => "v1", "kind" => "Thing", "metadata" => {"name" => name, "namespace" => "ns"}}
  end

  def test_replay_memory_is_dropped_by_the_full_compaction
    now = Time.at(1_000_000)
    store = Store.new(history_seconds: 60.0, clock: -> { now })
    first = store.create("registry/things/ns/a", object("a"), request_uid: "req-a")
    assert_same first, store.create("registry/things/ns/a", object("a"), request_uid: "req-a"), "a retry replays"
    assert_equal 1, store.export_state["requests"].length

    now += 61
    store.create("registry/things/ns/b", object("b"), request_uid: "req-b")
    remembered = store.export_state["requests"].keys
    refute_includes remembered, "req-a", "an entry older than the retention window is gone"
    assert_includes remembered, "req-b"
    # Without its replay memory the old request is an ordinary create again.
    assert_raises(Rubernetes::Storage::AlreadyExists) { store.create("registry/things/ns/a", object("a"), request_uid: "req-a") }
  end

  def test_a_per_key_compaction_keeps_replay_memory
    store = Store.new(history_revisions: 2, history_seconds: nil)
    store.create("registry/things/ns/a", object("a"), request_uid: "req-a")
    5.times { |index| store.guaranteed_update("registry/things/ns/a", request_uid: "upd-#{index}") { |current| current.merge("n" => index) } }
    assert_includes store.export_state["requests"].keys, "req-a"
  end
end
