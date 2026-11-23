#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require_relative "lean_oracle"
require "tmpdir"
require_relative "../../lib/rubernetes/consensus"

module RaftLogOracle
  SOURCE = File.expand_path("../../verification/lean/RaftLog.lean", __dir__)
  CONSENSUS = Rubernetes::Consensus
  SEED = 20_260_918

  module_function

  def run(lean: LeanOracle.executable, seed: SEED)
    random = Random.new(seed)
    cases = Array.new(200) { input(random) }
    reference = LeanOracle.run(SOURCE, cases, lean: lean)

    mismatches = cases.each_with_index.filter_map do |test_case, index|
      actual = follower_result(test_case)
      expected = reference.fetch(index)
      {"input" => test_case, "ruby" => actual, "lean" => expected} unless actual == expected
    end
    {"passed" => mismatches.empty?, "seed" => seed, "cases" => cases.length,
     "source_sha256" => Digest::SHA256.file(SOURCE).hexdigest, "mismatches" => mismatches}
  end

  def input(random)
    prefix = entries(random, random.rand(0..12), 1)
    leader = prefix + entries(random, random.rand(0..12), 3)
    follower = prefix + entries(random, random.rand(0..12), 2)
    index = random.rand(0..leader.length)
    term = index.zero? ? 0 : leader.fetch(index - 1).fetch("term")
    term += 20 if random.rand(4).zero?
    {"follower" => follower, "prev_index" => index, "prev_term" => term,
     "committed" => random.rand(0..follower.length), "entries" => leader.drop(index).take(random.rand(0..12))}
  end

  def entries(random, count, term)
    Array.new(count) { {"term" => term, "value" => random.rand(1_000)} }
  end

  def log_entry(index, data)
    CONSENSUS::Log::Entry.new(index: index, term: data.fetch("term"), command: {"value" => data.fetch("value")})
  end

  def snapshot_log(log)
    log.entries.map { |entry| {"term" => entry.term, "value" => entry.command.fetch("value")} }
  end

  def follower_result(input)
    Dir.mktmpdir("rubernetes-raft-log-oracle-") do |directory|
      storage = CONSENSUS::Storage.new(directory, fsync: false)
      original = input.fetch("follower")
      storage.log.append(original.map.with_index(1) { |data, index| log_entry(index, data) })
      membership = CONSENSUS::Membership.simple(%w[leader follower])
      follower = CONSENSUS::Node.new(id: "follower", cluster_id: "oracle", log: storage.log, snapshot_store: storage.snapshots,
                                     state_machine: CONSENSUS::KVStateMachine.new, initial_membership: membership, clock: -> { 0.0 })
      follower.instance_variable_set(:@commit_index, input.fetch("committed"))

      anchor = input.fetch("prev_index")
      batch = input.fetch("entries").map.with_index(anchor + 1) { |data, index| log_entry(index, data).to_h }
      message = CONSENSUS::Messages::AppendEntries.new(cluster_id: "oracle", from: "leader", to: "follower", term: 5,
                                                       prev_log_index: anchor, prev_log_term: input.fetch("prev_term"),
                                                       entries: batch, leader_commit: 0, request_id: "batch")
      response = follower.handle(message).find { |sent| sent.is_a?(CONSENSUS::Messages::AppendEntriesResponse) }
      raise "AppendEntries has no response" unless response
      return snapshot_log(storage.log) if response.success

      raise "a rejected AppendEntries altered the log" unless snapshot_log(storage.log) == original

      nil
    rescue CONSENSUS::Error => error
      raise unless error.message.start_with?("leader attempted to overwrite committed entry ")

      raise "a rejected overwrite altered the committed log" unless snapshot_log(storage.log) == original

      nil
    ensure
      storage&.close
    end
  end
end

if $PROGRAM_NAME == __FILE__
  report = RaftLogOracle.run
  puts JSON.pretty_generate(report)
  exit(report.fetch("passed") ? 0 : 1)
end
