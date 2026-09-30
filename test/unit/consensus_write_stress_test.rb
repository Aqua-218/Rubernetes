# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_write_client"

# Randomised write stress on the deterministic simulation: every round fires
# 100 concurrent creates (plus updates and deletes) at random replicas while
# leaders crash and restart, followers crash, partitions open and heal, the
# leader hands leadership over, snapshots are forced, the network drops,
# duplicates and reorders, and clocks jump.  After every round the cluster
# is healed and converged and the write-path invariants are checked: every
# acknowledged create exists on every replica at its acknowledged position,
# and all replicas hold identical state at the same applied index.
#
# RAFT_STRESS_ROUNDS and RAFT_STRESS_SEED scale it up outside the suite
# (thousands of rounds run from the scratchpad, several seeds in parallel).
class ConsensusWriteStressTest < Minitest::Test
  C = Rubernetes::Consensus
  IDS = %w[n1 n2 n3].freeze
  ROUNDS = Integer(ENV.fetch("RAFT_STRESS_ROUNDS", 12))
  SEED = Integer(ENV.fetch("RAFT_STRESS_SEED", 2026))
  CREATES_PER_ROUND = 100
  EVENTS = %i[crash_leader crash_follower partition heal transfer_leadership force_snapshot flaky_network
              clean_network clock_jump restart_crashed nothing].freeze

  def test_concurrent_creates_survive_elections_forwards_and_snapshots
    timing = C::Node::Timing.default.with(snapshot_entries: 60, snapshot_min_interval: 0.05, batch_max_entries: 32,
                                          max_inflight_appends: 4)
    cluster = RaftSimulation::Cluster.new(IDS, seed: SEED, timing: timing)
    cluster.run(1.0)
    client = RaftSimulation::WriteClient.new(cluster)
    random = Random.new(SEED)
    crashed = []
    deleted_keys = []
    stats = Hash.new(0)
    ROUNDS.times do |round|
      live = IDS - crashed
      # Creates arrive in bursts over the first ~30 ms of the round.
      keys = CREATES_PER_ROUND.times.map { |i| "k/r#{round}-#{i}" }
      bursts = keys.each_slice(random.rand(5..40)).to_a
      events = random.rand(1..4).times.map { [random.rand * 0.6, EVENTS.sample(random: random)] }.sort_by(&:first)
      round_started = cluster.now
      bursts.each do |burst|
        live = IDS - crashed
        burst.each { |key| client.create(live.sample(random: random), key) }
        cluster.run(random.rand(0.001..0.010))
        fire_due_events(cluster, client, events, random, crashed, stats, round_started)
      end
      # Updates and deletes exercise preconditions computed from a replica's
      # own view -- the classic source of apply-time divergence.
      random.rand(5..20).times do
        live = IDS - crashed
        origin = live.sample(random: random)
        store = cluster.processes[origin].state_machine.store
        candidate = client.acked.select { |request| request.key.start_with?("k/") }.sample(random: random)
        next if candidate.nil?

        begin
          current = store.get(candidate.key)
        rescue Rubernetes::Storage::NotFound
          next
        end
        object = {"metadata" => {"name" => current["metadata"]["name"]}, "spec" => {"updated" => round}}
        client.update(origin, candidate.key, object: object, expected_resource_version: current["metadata"]["resourceVersion"])
      end
      random.rand(0..8).times do |i|
        live = IDS - crashed
        key = "d/r#{round}-#{i}"
        deleted_keys << key
        client.create(live.sample(random: random), key)
      end
      cluster.run(0.05)
      random.rand(0..8).times do |i|
        live = IDS - crashed
        client.delete(live.sample(random: random), "d/r#{round}-#{i}")
      end
      until events.empty?
        cluster.run(0.05)
        fire_due_events(cluster, client, events, random, crashed, stats, round_started)
      end
      # End of round: heal everything and converge.
      cluster.network.heal
      cluster.network.filter = nil
      cluster.network.drop_rate = 0.0
      cluster.network.duplicate_rate = 0.0
      cluster.network.reorder_rate = 0.0
      crashed.dup.each do |id|
        cluster.restart(id)
        crashed.delete(id)
      end
      client.settle(timeout: 12.0)
      converged = cluster.run_until(timeout: 6.0) do
        cluster.leader.length == 1 &&
          cluster.processes.values.map { |process| process.node.last_applied }.uniq.length == 1 &&
          cluster.processes.values.all? { |process| process.node.last_applied == process.node.commit_index }
      end

      assert converged, "round #{round}: replicas did not converge: #{cluster.processes.values.map do |process|
        [process.id, process.node.role, process.node.last_applied, process.node.commit_index]
      end}"
      missing = client.missing_acked_creates(deleted_keys: deleted_keys)

      assert_empty missing, "round #{round}: #{missing.join("\n")}"
      divergent = client.divergent_replicas

      assert_empty divergent, "round #{round}: #{divergent.join("\n")}"
      stuck = client.outstanding

      assert_empty stuck, "round #{round}: requests never settled: #{stuck.map do |request|
        [request.key, request.state, request.trace]
      end.inspect}"
      stats[:acked] = client.acked.length
      stats[:rejected] = client.rejected.length
      stats[:failed] = client.failed.length
    end
    stats[:failures_by_reason] = client.failed.map(&:error).tally
    stats[:terms] = cluster.leader.first.current_term
    stats[:snapshot_installs] = cluster.processes.values.sum { |process| process.node.status["snapshot_installs"] }
    warn "raft write stress seed=#{SEED} rounds=#{ROUNDS}: #{stats.inspect}" if ENV["RAFT_STRESS_VERBOSE"]

    assert_operator client.acked.length, :>, ROUNDS * CREATES_PER_ROUND / 2, "most creates must be acknowledged"
    # Every acknowledged create was created exactly once: no key was
    # acknowledged twice, and a rejected create of a key is only ever an
    # unknown-outcome retry of one that committed.
    acked_creates = client.acked.select { |request| request.command["type"] == "create" }.map(&:key)

    assert_equal acked_creates.uniq.length, acked_creates.length
    client.rejected.each do |request|
      next unless request.command["type"] == "create"
      next if request.trace.any? { |event| %i[forward_timeout forward_refused].include?(event.first) }

      flunk "#{request.key} rejected without an unknown-outcome retry: #{request.trace.inspect}\n#{describe_key(cluster, client,
                                                                                                                request.key)}"
    end
  ensure
    cluster&.cleanup
  end

  private

  # Everything the replicas know about one key, for a failure message.
  def describe_key(cluster, client, key)
    lines = client.requests.select { |request| request.key == key }.map do |request|
      "request #{request.id} origin=#{request.origin} state=#{request.state} index=#{request.index} term=#{request.term} " \
        "error=#{request.error} ok=#{request.result && request.result["ok"]} trace=#{request.trace.inspect}"
    end
    cluster.processes.each_value do |process|
      node = process.node
      entries = node.log.entries.select do |entry|
        entry.command.is_a?(Hash) && entry.command["key"] == key
      end.map { |entry| [entry.index, entry.term] }
      applied = process.applied.select { |item| item.command.is_a?(Hash) && item.command["key"] == key }
        .map { |item| [item.index, item.term, item.result && item.result["ok"], item.result&.dig("error", "class")] }
      stored = begin
        process.state_machine.store.get(key)["metadata"]["resourceVersion"]
      rescue Rubernetes::Storage::Error => error
        error.class.name
      end
      lines << "#{process.id} alive=#{process.alive} role=#{node.role} term=#{node.current_term} snapshot=#{node.log.snapshot_index} " \
               "applied=#{node.last_applied} commit=#{node.commit_index} installs=#{node.status["snapshot_installs"]} " \
               "log=#{entries.inspect} applied_for_key=#{applied.inspect} store_rv=#{stored}"
    end
    lines.join("\n")
  end

  def fire_due_events(cluster, client, events, random, crashed, stats, round_started)
    while events.any? && cluster.now - round_started >= events.first.first
      _at, event = events.shift
      stats[event] += 1
      apply_event(cluster, client, event, random, crashed)
    end
  end

  def apply_event(cluster, _client, event, random, crashed)
    leader = cluster.leader.first
    live = IDS - crashed
    case event
    when :crash_leader
      return if leader.nil? || live.length < 3

      cluster.crash(leader.id)
      crashed << leader.id
    when :crash_follower
      return if live.length < 3

      victim = (live - [leader&.id]).sample(random: random)
      cluster.crash(victim)
      crashed << victim
    when :restart_crashed
      return if crashed.empty?

      id = crashed.shift
      cluster.restart(id)
    when :partition
      a, b = live.sample(2, random: random)
      return if b.nil?

      cluster.network.cut(a, b)
      cluster.network.cut(b, a) if random.rand < 0.7
    when :heal
      cluster.network.heal
    when :transfer_leadership
      return if leader.nil?

      target = (live - [leader.id]).sample(random: random)
      return if target.nil?

      begin
        leader.transfer_leadership(target, now: cluster.now)
        cluster.route(leader.drain)
      rescue C::Error
        nil
      end
    when :force_snapshot
      return if leader.nil?

      begin
        leader.snapshot!(now: cluster.now, force: true)
      rescue C::Error
        nil
      end
    when :flaky_network
      # No duplication: the production transport is TCP, which never
      # delivers a frame twice (a retried forward is the realistic
      # duplicate, and the client models that).  Drops and reordering
      # happen across reconnects.
      cluster.network.drop_rate = random.rand(0.0..0.2)
      cluster.network.duplicate_rate = 0.0
      cluster.network.reorder_rate = random.rand(0.0..0.3)
    when :clean_network
      cluster.network.drop_rate = 0.0
      cluster.network.duplicate_rate = 0.0
      cluster.network.reorder_rate = 0.0
    when :clock_jump
      cluster.processes[live.sample(random: random)].clock_offset += random.rand(-1.0..3.0)
    when :nothing
      nil
    end
  end
end
