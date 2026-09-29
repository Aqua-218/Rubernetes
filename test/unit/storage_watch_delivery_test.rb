# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/storage/memory_store"

# A client that reads its informer cache right after a write (the e2e CRUD
# helper) raced the watch event and, losing, waited two seconds to look
# again.  A write's response now waits until the watchers it woke have sent
# the event -- bounded, and never for a watcher that is already behind.
class StorageWatchDeliveryTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore

  def store = @store ||= Store.new(history_revisions: nil, history_seconds: nil)

  def object(name) = {"metadata" => {"name" => name, "namespace" => "ns"}}

  def revision_of(result)
    Integer(result.dig("metadata", "resourceVersion"))
  end

  def test_an_unread_event_is_waited_for_until_the_timeout
    store.watch("/registry/pods/ns")
    created = store.create("/registry/pods/ns/a", object("a"))
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    refute store.await_watch_delivery(revision_of(created), timeout: 0.05)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :>=, 0.04
  end

  def test_the_wait_ends_when_the_consumer_comes_back_for_the_next_event
    watcher = store.watch("/registry/pods/ns")
    reader = Thread.new do
      watcher.next(timeout: 1)
      watcher.next(timeout: 0.3)
    end
    created = store.create("/registry/pods/ns/a", object("a"))
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    assert store.await_watch_delivery(revision_of(created), timeout: 1)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.25
  ensure
    reader&.join
  end

  def test_a_watcher_without_the_event_or_with_a_backlog_is_not_waited_for
    store.watch("/registry/configmaps/ns")
    backlogged = store.watch("/registry/pods/ns")
    4.times { |index| store.create("/registry/pods/ns/p#{index}", object("p#{index}")) }
    created = store.create("/registry/pods/ns/last", object("last"))
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    assert store.await_watch_delivery(revision_of(created), timeout: 0.5)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.1
    refute_nil backlogged
  end
end
