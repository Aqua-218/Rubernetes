# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/consensus"

# A raft follower that installs a snapshot restores it into a NEW store and
# swaps it in.  Watches opened against the old store were never told: every
# later apply mutated the replacement, so they stayed open and silent until the
# client's 5-10 minute watch timeout.  Thread dumps taken during a conformance
# round caught it -- every controller-manager reflector blocked in
# IO#wait_readable, every apiserver watcher waiting on an empty queue -- while
# new namespaces got no default ServiceAccount and specs failed in
# [BeforeEach].  A restore now ends those watches with 410 Expired so clients
# relist.
class SnapshotRestoreExpiresWatchesTest < Minitest::Test
  StateMachine = Rubernetes::Consensus::KVStateMachine
  Storage = Rubernetes::Storage

  def test_a_watch_on_the_replaced_store_ends_with_expired_instead_of_going_silent
    source = StateMachine.new
    target = StateMachine.new
    watch = target.store.watch(resource: "configmaps", namespace: "default")

    target.restore(source.snapshot)

    error = assert_raises(Storage::WatchOverflow) { watch.next(timeout: 1) }
    assert_equal 410, error.status
    assert_equal "Expired", error.reason
  end

  def test_the_replacement_store_serves_new_watches
    source = StateMachine.new
    target = StateMachine.new
    old_store = target.store

    target.restore(source.snapshot)

    refute_same old_store, target.store
    assert_equal 0, old_store.watcher_count, "no watcher is left attached to the store that was replaced"
  end

  def test_expiring_watchers_leaves_a_store_usable
    store = Storage::MemoryStore.new
    first = store.watch(resource: "configmaps", namespace: "default")

    store.expire_watchers!

    assert_raises(Storage::WatchOverflow) { first.next(timeout: 1) }
    assert_equal 0, store.watcher_count
    store.watch(resource: "configmaps", namespace: "default")
    assert_equal 1, store.watcher_count
  end
end
