# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "tmpdir"

# Concurrent persist_state! calls share one write: each call returns only
# once a snapshot taken after its change is on disk.
class LifecyclePersistGroupCommitTest < Minitest::Test
  class SlowStore
    attr_reader :saves

    def initialize
      @saves = []
      @lock = Mutex.new
    end

    def save(snapshot)
      sleep 0.02
      @lock.synchronize { @saves << snapshot["records"].map { |record| record["uid"] }.sort }
    end
  end

  def lifecycle(store)
    subject = Rubernetes::Node::Lifecycle.allocate
    subject.instance_variable_set(:@state_store, store)
    subject.instance_variable_set(:@mutex, Monitor.new)
    subject.instance_variable_set(:@persist_mutex, Mutex.new)
    subject.instance_variable_set(:@persist_counter_mutex, Mutex.new)
    subject.instance_variable_set(:@persist_requested, 0)
    subject.instance_variable_set(:@persist_completed, 0)
    subject.instance_variable_set(:@records, {})
    subject.instance_variable_set(:@finished, {})
    subject
  end

  def test_concurrent_calls_coalesce_and_every_change_is_persisted_before_return
    store = SlowStore.new
    subject = lifecycle(store)
    records = subject.instance_variable_get(:@records)
    mutex = subject.instance_variable_get(:@mutex)
    persisted_after_return = Queue.new
    threads = Array.new(20) do |i|
      Thread.new do
        mutex.synchronize { records["uid-#{i}"] = {uid: "uid-#{i}", state: "Running"} }
        subject.send(:persist_state!)
        persisted_after_return << store.saves.any? { |uids| uids.include?("uid-#{i}") }
      end
    end
    threads.each(&:join)

    assert_equal [true] * 20, Array.new(20) { persisted_after_return.pop }
    assert_operator store.saves.length, :<, 20, "concurrent calls shared writes"
    assert_equal 20, store.saves.last.length
  end

  def test_sequential_calls_each_write
    store = SlowStore.new
    subject = lifecycle(store)
    3.times { subject.send(:persist_state!) }

    assert_equal 3, store.saves.length
  end
end

# Each record is re-encoded only when it changed; the file assembled from the
# cached encodings is the same document a full conversion produces.
class LifecyclePersistRecordCacheTest < Minitest::Test
  def lifecycle(store)
    subject = Rubernetes::Node::Lifecycle.allocate
    {state_store: store, mutex: Monitor.new, persist_mutex: Mutex.new, persist_counter_mutex: Mutex.new,
     persist_requested: 0, persist_completed: 0, records: {}, finished: {}}.each do |name, value|
      subject.instance_variable_set(:"@#{name}", value)
    end
    subject
  end

  def test_only_changed_records_are_re_encoded_and_the_file_round_trips
    Dir.mktmpdir do |dir|
      store = Rubernetes::Node::Lifecycle::StateStore.new(File.join(dir, "state.json"))
      subject = lifecycle(store)
      now = 100.0
      subject.define_singleton_method(:monotonic_clock) { -> { now } }
      records = subject.instance_variable_get(:@records)
      records["a"] = {uid: "a", state: "Running", at: Time.utc(2026, 9, 23), containers: [{name: "c", status: {"ready" => true}}]}
      records["b"] = {uid: "b", state: "Running", containers: []}
      encoded = []
      subject.define_singleton_method(:serializable_record) do |record|
        encoded << record[:uid]
        super(record)
      end

      subject.send(:persist_state!)

      assert_equal %w[a b], encoded.sort
      encoded.clear
      subject.send(:persist_state!)

      assert_empty encoded, "unchanged records are not converted again"

      # Lifecycle changes mark their record (#event, #update_status).
      records["b"][:state] = "Stopping"
      subject.send(:mark_dirty, records["b"])
      subject.send(:persist_state!)

      assert_equal %w[b], encoded

      # A change made without a mark is still picked up by the periodic sweep.
      encoded.clear
      records["a"][:containers][0][:status]["ready"] = false
      subject.send(:persist_state!)

      assert_empty encoded
      now += Rubernetes::Node::Lifecycle::FULL_CHECK_SECONDS
      subject.send(:persist_state!)

      assert_equal %w[a], encoded, "the sweep sees a change deep inside a mutable part"

      encoded.clear
      now += Rubernetes::Node::Lifecycle::FULL_CHECK_SECONDS
      subject.send(:persist_state!)

      assert_empty encoded, "the sweep re-encodes nothing that did not change"

      loaded = store.load

      assert_equal "rubernetes.node.lifecycle.v1", loaded["schema"]
      by_uid = loaded["records"].to_h { |record| [record["uid"], record] }

      assert_equal "Stopping", by_uid["b"]["state"]
      assert_equal "2026-09-23T00:00:00.000000Z", by_uid["a"]["at"]
      assert_equal false, by_uid["a"]["containers"][0]["status"]["ready"]
    end
  end
end
