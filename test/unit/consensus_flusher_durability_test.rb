# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"

# The leader's WAL fsync runs on the flusher thread with the node lock
# released.  What must hold: the lock is free while the disk is slow (reads
# and inbound messages proceed); nothing is acknowledged before its fsync;
# a failed fsync fails the node closed instead of acknowledging; and the
# WAL's split locks keep appends and syncs consistent.
class ConsensusFlusherDurabilityTest < Minitest::Test
  C = Rubernetes::Consensus

  # A device whose fsync can be slowed or failed after construction.
  class ControlledDevice
    class << self
      attr_accessor :fsync_delay, :fail_fsync, :fsyncs
    end

    def initialize(path)
      @inner = C::WAL::FileDevice.new(path)
    end

    def size = @inner.size
    def write(bytes) = @inner.write(bytes)
    def truncate(length) = @inner.truncate(length)
    def close = @inner.close

    def fsync
      self.class.fsyncs = (self.class.fsyncs || 0) + 1
      sleep(self.class.fsync_delay) if self.class.fsync_delay
      raise Errno::EIO, "injected fsync failure" if self.class.fail_fsync

      @inner.fsync
    end
  end

  def setup
    ControlledDevice.fsync_delay = nil
    ControlledDevice.fail_fsync = false
    ControlledDevice.fsyncs = 0
  end

  def start_cluster(root, device_factory: nil)
    ca, ca_key = C::Identity.generate_ca("fl")
    ids = %w[a b c]
    servers = ids.to_h do |id|
      bundle = C::Identity.issue_node(ca, ca_key, cluster_id: "fl", node_id: id)
      # Only replica "a" gets the controlled device; it is made leader.
      factory = id == "a" ? device_factory : nil
      [id, C::Server.new(id: id, cluster_id: "fl", data_directory: File.join(root, id), bundle: bundle, initial_voters: ids,
                         device_factory: factory)]
    end
    servers.each_value(&:start)
    servers.each_value { |server| servers.each { |peer_id, peer| server.add_peer(peer_id, peer.address) unless peer.equal?(server) } }
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    sleep 0.02 until servers.values.any?(&:leader?) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    sleep 0.2
    leader = servers.values.find(&:leader?)
    unless leader.equal?(servers["a"])
      leader.transfer_leadership("a")
      sleep 0.02 until servers["a"].leader? || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    end
    assert servers["a"].leader?, "replica a must lead"
    sleep 0.3
    servers
  end

  def command(key)
    {"type" => "create", "key" => key, "object" => {"metadata" => {"name" => key.split("/").last}}, "request_uid" => nil,
     "leader_time" => Time.now.to_f}
  end

  def test_a_slow_fsync_does_not_hold_the_node_lock
    Dir.mktmpdir("flusher") do |root|
      servers = start_cluster(root, device_factory: ->(path) { ControlledDevice.new(path) })
      leader = servers["a"]
      leader.propose(command("k/warm"))
      ControlledDevice.fsync_delay = 0.3
      writer = Thread.new { leader.propose(command("k/slow")) }
      sleep 0.05
      # A linearizable read needs the lock and a heartbeat round, not the
      # fsync in flight.
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      leader.read_index
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      assert_operator elapsed, :<, 0.15, "read_index waited behind the fsync: #{elapsed.round(3)} s"
      # A second proposal joins the next batch while the fsync runs and is
      # answered without an extra fsync cycle beyond its own.
      ControlledDevice.fsync_delay = nil
      assert writer.value["ok"]
      assert leader.propose(command("k/after"))["ok"]
      servers.each_value(&:stop)
    end
  end

  def test_nothing_is_acknowledged_before_the_leader_fsync_when_followers_are_slow
    Dir.mktmpdir("flusher") do |root|
      servers = start_cluster(root, device_factory: ->(path) { ControlledDevice.new(path) })
      leader = servers["a"]
      # Followers b and c cannot answer: the leader alone must not commit,
      # and its own vote only counts once the fsync is done.
      %w[b c].each { |id| servers[id].stop }
      ControlledDevice.fsync_delay = 0.2
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_raises(C::Timeout) { leader.propose(command("k/alone"), timeout: 0.6) }
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :>=, 0.5
      refute leader.store.list("k/").items.any? { |item| item["metadata"]["name"] == "alone" }, "never applied without a quorum"
      # The entry is durable on the leader though: the fsync ran.
      assert_operator ControlledDevice.fsyncs, :>=, 1
      leader.stop
    end
  end

  def test_a_failed_fsync_fails_the_node_closed_instead_of_acknowledging
    Dir.mktmpdir("flusher") do |root|
      servers = start_cluster(root, device_factory: ->(path) { ControlledDevice.new(path) })
      leader = servers["a"]
      leader.propose(command("k/before"))
      ControlledDevice.fail_fsync = true
      error = assert_raises(C::Error) { leader.propose(command("k/doomed"), timeout: 3.0) }
      assert leader.failed?, "the node is fail-closed after an fsync failure (#{error.class}: #{error.message})"
      assert_kind_of C::DurabilityError, leader.failure
      assert_raises(C::StorageFailed) { leader.propose(command("k/later")) }
      servers.each_value(&:stop)
    end
  end

  def test_wal_appends_proceed_during_a_sync_and_the_synced_size_is_exact
    Dir.mktmpdir("wal") do |dir|
      path = File.join(dir, "wal")
      wal = C::WAL.new(path, device_factory: ->(p) { ControlledDevice.new(p) })
      wal.append([C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => {"type" => "noop"}}], sync: false)
      size_before = wal.size
      ControlledDevice.fsync_delay = 0.2
      syncer = Thread.new { wal.sync }
      sleep 0.05
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      wal.append([C::WAL::TYPE_ENTRY, {"index" => 2, "term" => 1, "command" => {"type" => "noop"}}], sync: false)
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.1, "append waited for the fsync"
      syncer.join
      assert_equal size_before, wal.synced_size, "the first sync covers only what was written before it"
      wal.sync
      assert_equal wal.size, wal.synced_size
      ControlledDevice.fsync_delay = 0.1
      closer = Thread.new { wal.append([C::WAL::TYPE_ENTRY, {"index" => 3, "term" => 1, "command" => {"type" => "noop"}}], sync: false); wal.sync }
      sleep 0.02
      wal.close
      closer.join
      records, _report = C::WAL.read(path)
      assert_equal [1, 2, 3], records.map { |record| record.payload["index"] }
    end
  end
end
