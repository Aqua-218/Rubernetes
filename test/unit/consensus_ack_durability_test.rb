# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_write_client"

# Conformance round 79 (2026-09-22) answered 100 Pod creates with 201 and
# two of the Pods never existed afterwards.  Every path on which an
# acknowledged create could be lost between "the server answered" and "the
# entry is applied on every replica" is driven here with the deterministic
# simulation and a client that acknowledges exactly the way
# Consensus::Server#propose does.  The invariant in every scenario: an
# acknowledged create exists on every live replica that has applied past its
# index, the log still names it at the acknowledged position, and replicas at
# the same applied index hold byte-identical state.
class ConsensusAckDurabilityTest < Minitest::Test
  C = Rubernetes::Consensus
  IDS = %w[n1 n2 n3].freeze

  def build(seed:, timing: nil, ids: IDS)
    cluster = RaftSimulation::Cluster.new(ids, seed: seed, timing: timing)
    cluster.run(1.0)
    assert_equal 1, cluster.leader.length, "no leader after 1 s"
    client = RaftSimulation::WriteClient.new(cluster)
    [cluster, client]
  end

  def followers(cluster)
    leader = cluster.leader.first.id
    cluster.processes.keys - [leader]
  end

  def assert_invariants(cluster, client, deleted_keys: [])
    missing = client.missing_acked_creates(deleted_keys: deleted_keys)
    assert_empty missing, missing.join("\n")
    divergent = client.divergent_replicas
    assert_empty divergent, divergent.join("\n")
  end

  # Runs until every live replica has applied the same index, then checks
  # that they all hold the same state.
  def converge(cluster, client, timeout: 3.0)
    cluster.run_until(timeout: timeout) do
      live = cluster.processes.values.select(&:alive)
      live.map { |process| process.node.last_applied }.uniq.length == 1 &&
        live.all? { |process| process.node.last_applied == process.node.commit_index } &&
        cluster.leader.length == 1
    end
    applied = cluster.processes.values.select(&:alive).map { |process| process.node.last_applied }.uniq
    assert_equal 1, applied.length, "replicas did not converge: #{applied.inspect}"
    assert_invariants(cluster, client)
  end

  def test_a_leader_stepping_down_with_an_unflushed_batch_acknowledges_nothing_it_lost
    cluster, client = build(seed: 101)
    leader = cluster.leader.first
    others = followers(cluster)
    # Proposals sit in the leader's batch (no lone-proposer flush); before
    # the tick loop flushes them the leader is isolated.
    requests = 40.times.map { |i| client.create(leader.id, "k/#{i}", flush_now: false) }
    others.each { |other| cluster.network.cut(leader.id, other); cluster.network.cut(other, leader.id) }
    cluster.run(1.5)
    new_leader = cluster.leader.find { |node| node.id != leader.id }
    refute_nil new_leader, "the majority side must elect a leader"
    20.times { |i| client.create(new_leader.id, "k/new-#{i}") }
    cluster.run(0.3)
    cluster.network.heal
    client.settle
    converge(cluster, client)
    acked = client.acked.map(&:key)
    assert requests.none? { |request| request.acked? && !acked.include?(request.key) }
    # Whatever the old leader acknowledged before losing the majority must
    # be everywhere; what it could not commit must never have been acked.
    requests.select(&:acked?).each do |request|
      cluster.processes.each_value { |process| process.state_machine.store.get(request.key) }
    end
    assert_equal 20, client.acked.count { |request| request.key.start_with?("k/new-") }
  ensure
    cluster&.cleanup
  end

  def test_a_proposal_flushed_just_before_the_leader_steps_down_is_waited_for_not_proposed_again
    cluster, client = build(seed: 111)
    leader = cluster.leader.first
    other = followers(cluster).first
    # Left in the batch (no lone-proposer flush) ...
    request = client.create(leader.id, "k/raced", flush_now: false)
    assert_equal :awaiting_flush, request.state
    # ... flushed by the node (the tick loop in production) and replicated,
    # and the leader steps down before the proposer looks again: a vote
    # request for a higher term from a peer whose log is as new.
    leader.flush(cluster.now)
    cluster.route(leader.drain)
    vote = C::Messages::RequestVote.new(cluster_id: cluster.cluster_id, from: other, to: leader.id, term: leader.current_term + 1,
                                        request_id: "vote", last_log_index: leader.last_index, last_log_term: leader.log.last_term)
    cluster.route(leader.handle(vote, cluster.now))
    refute leader.leader?
    assert_equal :awaiting_flush, request.state
    client.settle
    converge(cluster, client)
    assert request.acked?, request.trace.inspect
    assert request.trace.any? { |event| event.first == :appended_before_step_down }, request.trace.inspect
    assert_equal 1, request.trace.count { |event| event.first == :proposed }, "proposed once: #{request.trace.inspect}"
    cluster.processes.each_value do |process|
      keys = process.node.log.entries.map { |entry| entry.command["key"] }
      assert_equal 1, keys.count("k/raced"), "#{process.id} holds the entry once: #{keys.inspect}"
    end
    assert_empty client.rejected
  ensure
    cluster&.cleanup
  end

  def test_forwarded_creates_survive_duplicated_reordered_and_dropped_delivery
    cluster, client = build(seed: 202)
    cluster.network.duplicate_rate = 0.3
    cluster.network.reorder_rate = 0.3
    cluster.network.drop_rate = 0.05
    origins = followers(cluster)
    100.times { |i| client.create(origins[i % origins.length], "k/#{i}") }
    client.settle(timeout: 15.0)
    cluster.network.drop_rate = 0.0
    converge(cluster, client)
    # Every key was proposed once.  The only legitimate rejection is the
    # unknown-outcome retry: the leader's answer was dropped, the 2 s
    # forward timeout passed, and the retry found the first copy already
    # committed.  A rejection without that timeout means the same command
    # was appended twice (a duplicated ForwardProposal joining the batch a
    # second time) and the forwarder was told 409 for its own create.
    assert_unknown_outcome_rejections_only(client)
    logs = cluster.processes.values.map { |process| process.node.log.entries.map { |entry| entry.command["key"] }.compact }
    logs.each do |keys|
      duplicates = keys.tally.select { |_key, count| count > 1 }
      assert_empty duplicates, "the same create was appended more than once: #{duplicates.inspect}"
    end
    assert_equal 100, client.acked.length + client.failed.length
    assert_operator client.acked.length, :>=, 95, client.failed.map { |request| [request.key, request.error, request.trace] }.inspect
  ensure
    cluster&.cleanup
  end

  def test_a_retried_forward_that_reaches_the_leader_while_its_first_copy_is_still_batched_is_appended_once
    cluster, client = build(seed: 203)
    leader = cluster.leader.first
    origin = followers(cluster).first
    command = {"type" => "create", "key" => "k/dup", "object" => {"metadata" => {"name" => "dup"}}, "request_uid" => nil,
               "leader_time" => 0.0}
    request_id = "dup:0123456789abcdef"
    forward = C::Messages::ForwardProposal.new(cluster_id: cluster.cluster_id, from: origin, to: leader.id, term: leader.current_term,
                                               request_id: request_id, command: command)
    # Two copies handled back to back, before any flush.
    leader.handle(forward, cluster.now)
    leader.handle(forward, cluster.now)
    leader.flush(cluster.now)
    responses = leader.drain.select { |message| message.is_a?(C::Messages::ForwardProposalResponse) }
    assert_equal 2, responses.length, "both copies are answered"
    assert_equal 1, responses.map { |message| [message.index, message.entry_term] }.uniq.length, "with one position"
    keys = leader.log.entries.map { |entry| entry.command["key"] }
    assert_equal 1, keys.count("k/dup"), "the command must be appended once: #{keys.inspect}"
    cluster.run(0.5)
    assert_equal 1, cluster.processes[origin].state_machine.store.list("k/").items.length
  ensure
    cluster&.cleanup
  end

  def test_an_isolated_leader_truncates_its_uncommitted_creates_and_none_of_them_was_acknowledged
    cluster, client = build(seed: 303)
    leader = cluster.leader.first
    others = followers(cluster)
    others.each { |other| cluster.network.cut(leader.id, other); cluster.network.cut(other, leader.id) }
    # Flushed at once: appended to the isolated leader's own log, never
    # replicated.
    isolated = 30.times.map { |i| client.create(leader.id, "k/isolated-#{i}", flush_now: true) }
    cluster.run(1.5)
    new_leader = cluster.leader.find { |node| node.id != leader.id }
    refute_nil new_leader
    50.times { |i| client.create(new_leader.id, "k/majority-#{i}") }
    cluster.run(0.5)
    assert_operator leader.last_index, :>, leader.commit_index, "the isolated leader holds uncommitted entries"
    cluster.network.heal
    client.settle
    converge(cluster, client)
    assert isolated.none?(&:acked?), "an uncommitted create was acknowledged: #{isolated.select(&:acked?).map(&:key)}"
    isolated.each do |request|
      cluster.processes.each_value do |process|
        assert_raises(Rubernetes::Storage::NotFound) { process.state_machine.store.get(request.key) }
      end
    end
    assert_equal 50, client.acked.count { |request| request.key.start_with?("k/majority-") }
  ensure
    cluster&.cleanup
  end

  def test_pipelined_batches_with_drops_keep_every_acknowledged_create
    timing = C::Node::Timing.default.with(batch_max_entries: 4, max_inflight_appends: 8, batch_flush_timeout: 0.001)
    cluster, client = build(seed: 404, timing: timing)
    cluster.network.drop_rate = 0.15
    cluster.network.reorder_rate = 0.2
    200.times { |i| client.create(IDS[i % 3], "k/#{i}") }
    client.settle(timeout: 20.0)
    cluster.network.drop_rate = 0.0
    converge(cluster, client, timeout: 5.0)
    assert_equal 200, client.acked.length + client.rejected.length, client.failed.map { |request| [request.key, request.error] }.inspect
    assert_unknown_outcome_rejections_only(client)
    assert_operator client.acked.length, :>=, 170
  ensure
    cluster&.cleanup
  end

  def test_the_leader_crashing_with_forwards_in_flight_and_restarting_loses_nothing_acknowledged
    cluster, client = build(seed: 505)
    leader = cluster.leader.first
    origins = followers(cluster)
    100.times { |i| client.create(origins[i % 2], "k/#{i}") }
    cluster.run(0.004)
    cluster.crash(leader.id)
    cluster.run(2.0)
    cluster.restart(leader.id)
    client.settle(timeout: 12.0)
    converge(cluster, client, timeout: 5.0)
    assert_operator client.acked.length, :>=, 1
  ensure
    cluster&.cleanup
  end

  def test_a_forwarded_write_whose_index_is_covered_by_an_installed_snapshot_fails_fast_and_is_not_lost
    timing = C::Node::Timing.default.with(snapshot_entries: 20, snapshot_min_interval: 0.01)
    cluster, client = build(seed: 606, timing: timing)
    leader = cluster.leader.first
    lagging = followers(cluster).first
    # The lagging follower can still talk to the leader (forwards and their
    # answers pass) but receives no log or snapshot traffic.
    cluster.network.filter = lambda do |message|
      !(message.to == lagging && (message.is_a?(C::Messages::AppendEntries) || message.is_a?(C::Messages::InstallSnapshot)))
    end
    request = client.create(lagging, "k/forwarded")
    cluster.run(0.05)
    assert_equal :waiting_apply, request.state, request.trace.inspect
    60.times { |i| client.create(leader.id, "k/fill-#{i}") }
    cluster.run(0.5)
    assert_operator leader.log.snapshot_index, :>=, request.index, "the leader compacted past the forwarded entry"
    cluster.network.filter = nil
    installed_at = cluster.now
    cluster.run_until(timeout: 3.0) { cluster.node(lagging).status["snapshot_installs"].positive? }
    assert_equal 1, cluster.node(lagging).status["snapshot_installs"]
    client.settle
    converge(cluster, client)
    # The write committed (it is in the snapshot) but the forwarder holds no
    # apply result for it: the outcome is unknown and reported at once.
    refute request.acked?
    assert_equal :failed, request.state, request.trace.inspect
    assert_equal :applied_through_snapshot, request.error, request.trace.inspect
    assert_operator request.acked_at - installed_at, :<, 1.0, "the unknown outcome must not wait for the 10 s deadline"
    cluster.processes.each_value { |process| process.state_machine.store.get("k/forwarded") }
  ensure
    cluster&.cleanup
  end

  def test_a_follower_restarting_over_a_format_1_wal_and_rotating_to_format_2_keeps_every_create
    timing = C::Node::Timing.default.with(snapshot_entries: 25, snapshot_min_interval: 0.01)
    cluster, client = build(seed: 707, timing: timing)
    victim = followers(cluster).first
    10.times { |i| client.create(IDS[i % 3], "k/#{i}") }
    client.settle
    converge(cluster, client)
    cluster.crash(victim)
    rewrite_wal_as_format_1(cluster.processes[victim].storage.wal_path)
    cluster.restart(victim)
    assert_equal 1, C::WAL.header_version(cluster.processes[victim].storage.wal_path)
    60.times { |i| client.create(IDS[i % 3], "k/after-#{i}") }
    client.settle
    converge(cluster, client)
    # Snapshot + rotation happened on the format-1 node: the rotated file is
    # format 2 and the log still replays.
    assert_operator cluster.node(victim).status["snapshot_index"], :>, 0
    assert_equal 2, C::WAL.header_version(cluster.processes[victim].storage.wal_path)
    cluster.crash(victim)
    cluster.restart(victim)
    cluster.run(0.5)
    converge(cluster, client)
    assert_equal 70, cluster.processes[victim].state_machine.store.list("k/").items.length
  ensure
    cluster&.cleanup
  end

  def test_a_torn_wal_tail_on_a_crashed_leader_loses_no_acknowledged_create
    cluster, client = build(seed: 808)
    leader = cluster.leader.first
    30.times { |i| client.create(IDS[i % 3], "k/#{i}") }
    client.settle
    converge(cluster, client)
    cluster.crash(leader.id)
    # A torn write: the last record loses its tail.  The entry it carried
    # was acknowledged only after a quorum stored it, so the restarted node
    # gets it back from the new leader.
    path = cluster.processes[leader.id].storage.wal_path
    File.open(path, "r+b") { |file| file.truncate(File.size(path) - 7) }
    cluster.run(1.5)
    cluster.restart(leader.id, recover_torn_tail: true)
    assert cluster.processes[leader.id].storage.recovery.any? { |report| report["truncated"] }, "the torn tail was recovered"
    30.times { |i| client.create(IDS[i % 3], "k/later-#{i}") }
    client.settle
    converge(cluster, client)
    assert_equal 60, client.acked.length
  ensure
    cluster&.cleanup
  end

  def test_a_follower_crashing_between_apply_and_snapshot_replays_from_the_wal_to_the_same_state
    timing = C::Node::Timing.default.with(snapshot_entries: 15, snapshot_min_interval: 0.01)
    cluster, client = build(seed: 909, timing: timing)
    victim = followers(cluster).first
    40.times { |i| client.create(IDS[i % 3], "k/#{i}") }
    client.settle
    converge(cluster, client)
    3.times do |round|
      cluster.crash(victim)
      10.times { |i| client.create(cluster.leader.first.id, "k/r#{round}-#{i}") }
      cluster.run(0.3)
      cluster.restart(victim)
      client.settle
      converge(cluster, client)
    end
    assert_equal 70, cluster.processes[victim].state_machine.store.list("k/").items.length
  ensure
    cluster&.cleanup
  end

  private

  def assert_unknown_outcome_rejections_only(client)
    client.rejected.each do |request|
      assert_equal "Rubernetes::Storage::AlreadyExists", request.result["error"]["class"], request.trace.inspect
      assert request.trace.any? { |event| event.first == :forward_timeout },
             "#{request.key} was rejected without an unknown-outcome retry: #{request.trace.inspect}"
      cluster_processes(client).each { |process| process.state_machine.store.get(request.key) }
    end
  end

  def cluster_processes(client)
    client.instance_variable_get(:@cluster).processes.values.select(&:alive)
  end

  # Re-encodes an existing WAL file as format 1 (CRC-32C) so the replay and
  # append paths for a pre-format-2 file are exercised.
  def rewrite_wal_as_format_1(path)
    records, _report = C::WAL.read(path)
    bytes = C::WAL.header_bytes(1) + records.map { |record| C::WAL.encode_record(record.type, record.payload, version: 1) }.join
    File.binwrite(path, bytes)
  end
end
