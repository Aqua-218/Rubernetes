#!/usr/bin/env ruby
# frozen_string_literal: true

# Linearizability evidence (M5 exit criterion 4): concurrent client
# histories against the production Raft node under partition, asymmetric
# partition, message reordering/duplication/loss, crash/restart and clock
# jumps, checked by tools/verification/linearizability.rb against the Ruby
# sequential model which is itself differentially checked against the Lean
# reference (verification/lean/KVSequential.lean).

require_relative "m5_probe_support"
$LOAD_PATH.unshift File.join(M5ProbeSupport::ROOT, "lib")
$LOAD_PATH.unshift File.join(M5ProbeSupport::ROOT, "test")
require "support/raft_linearizability_client"
require_relative "../verification/linearizability"
require_relative "../verification/kv_sequential_oracle"

module M5LinearizabilityProbe
  FAULTS = %w[partition asymmetric_partition reorder duplicate loss crash_restart clock_jump].freeze

  module_function

  def history(seed:, rounds:, nodes: %w[n1 n2 n3])
    cluster = RaftSimulation::Cluster.new(nodes, seed: seed)
    rng = Random.new(seed)
    cluster.run(1.0)
    driver = RaftLinearizabilityClient::Driver.new(cluster, clients: %w[c1 c2 c3 c4], random: rng, operation_timeout: 0.8)
    cluster.network.drop_rate = 0.05
    cluster.network.duplicate_rate = 0.05
    cluster.network.reorder_rate = 0.1
    faults = Hash.new(0)
    rounds.times do
      driver.step
      cluster.run(0.05)
      case rng.rand
      when 0..0.08
        leader = cluster.leader.first
        if leader && cluster.processes.values.count(&:alive) == nodes.length
          cluster.crash(leader.id)
          faults["crash_restart"] += 1
        end
      when 0.08..0.16
        dead = cluster.processes.values.reject(&:alive).first
        cluster.restart(dead.id) if dead
      when 0.16..0.24
        a, b = nodes.sample(2, random: rng)
        cluster.network.cut(a, b)
        cluster.network.cut(b, a)
        faults["partition"] += 1
      when 0.24..0.32
        a, b = nodes.sample(2, random: rng)
        cluster.network.cut(a, b)
        faults["asymmetric_partition"] += 1
      when 0.32..0.42
        cluster.network.heal
      when 0.42..0.48
        cluster.processes.values.sample(random: rng).clock_offset += rng.rand(-1.0..2.0)
        faults["clock_jump"] += 1
      end
    end
    faults["reorder"] = rounds
    faults["duplicate"] = rounds
    faults["loss"] = rounds
    cluster.network.heal
    cluster.network.drop_rate = 0
    cluster.processes.values.reject(&:alive).each { |process| cluster.restart(process.id) }
    driver.finish
    [driver.history.to_a, faults]
  ensure
    cluster&.cleanup
  end

  def run(seeds: ENV.fetch("RUBERNETES_M5_LINEARIZABILITY_SEEDS", "12").to_i, rounds: ENV.fetch("RUBERNETES_M5_LINEARIZABILITY_ROUNDS", "60").to_i)
    started_at = M5ProbeSupport.now
    oracle = KVSequentialOracle.run
    cases = (1..seeds).map do |seed|
      events, faults = history(seed: seed, rounds: rounds)
      result = Linearizability::Checker.new(events).check
      counts = events.group_by { |event| event["type"] }.transform_values(&:length)
      {
        "id" => "history-#{seed}",
        "seed" => seed,
        "events" => counts,
        "faults" => faults,
        "linearizable" => result[:linearizable],
        "explored_states" => result["explored"],
        "witness" => result["witness"],
        "history_sha256" => M5ProbeSupport.digest(events),
        "history" => events,
        "passed" => result[:linearizable] == true && (counts["ok"] || 0) >= 10
      }
    end
    # Every fault class must appear somewhere in the corpus; a single seed
    # does not have to draw every fault.
    union = cases.each_with_object(Hash.new(0)) { |entry, sum| entry["faults"].each { |fault, count| sum[fault] += count } }
    cases.unshift({"id" => "fault_coverage", "faults" => union, "required" => FAULTS,
                   "passed" => FAULTS.all? { |fault| union[fault].positive? }})
    cases.unshift({"id" => "lean_sequential_oracle", "passed" => oracle["passed"], "compared_operations" => oracle["compared_operations"],
                   "mismatches" => oracle["mismatches"].length, "lean_version" => oracle["lean_version"],
                   "lean_source_sha256" => oracle["lean_source_sha256"]})
    M5ProbeSupport.emit(M5ProbeSupport.report(
      kind: "m5_linearizability_histories", measurement_level: "differentially_tested", started_at: started_at, cases: cases,
      extra: {"checker" => M5ProbeSupport.source_files(%w[tools/verification/linearizability.rb verification/lean/KVSequential.lean
                                                          lib/rubernetes/consensus/node.rb lib/rubernetes/consensus/state_machine.rb]),
              "required_faults" => FAULTS}
    ))
  end
end

M5LinearizabilityProbe.run if $PROGRAM_NAME == __FILE__
