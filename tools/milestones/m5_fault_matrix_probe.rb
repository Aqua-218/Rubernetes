#!/usr/bin/env ruby
# frozen_string_literal: true

# M5 fault matrix with real OS processes (exit criteria 1, 2, 5):
#   * 3 nodes / 1 failure and 5 nodes / 2 failures: SIGKILL the leader (and a
#     follower for 5 nodes) while writes are acknowledged; every acknowledged
#     write survives (RPO 0) and the cluster resumes reads/writes within 60 s.
#   * membership change (joint consensus) with the leader killed while the
#     joint configuration is in flight; snapshot install to a fresh node with
#     the leader killed mid-transfer; zero split brain, zero lost commit.
# Every worker is a separate process running the production Server/RaftStore
# over TLS; the probe only talks to control sockets.

require_relative "m5_probe_support"
$LOAD_PATH.unshift M5ProbeSupport::ROOT
require "test/conformance/kubernetes/m5_raft_cluster/harness"

module M5FaultMatrixProbe
  TIMING = {"snapshot_entries" => 200, "snapshot_min_interval" => 0.5}.freeze

  module_function

  def write(worker, index, prefix: "k")
    worker.request({"op" => "create", "key" => "#{prefix}/#{index}", "object" => {"metadata" => {"name" => "#{prefix}-#{index}"}},
                    "request_uid" => "#{prefix}-#{index}"})
  end

  def acknowledged_keys(cluster, prefix: "k")
    worker = cluster.leader
    worker.request({"op" => "list", "prefix" => "#{prefix}/"})["items"].map { |item| item["metadata"]["name"] }
  end

  def wait_for_convergence(cluster, timeout: 60)
    deadline = M5ProbeSupport.monotonic + timeout
    loop do
      statuses = cluster.alive.map(&:status)
      leaders = statuses.select { |status| status["role"] == "leader" }
      commits = statuses.map { |status| status["commit_index"] }.uniq
      applied = statuses.map { |status| [status["commit_index"], status["last_applied"]] }
      return true if leaders.length == 1 && commits.length == 1 && applied.all? { |commit, done| commit == done }
      return false if M5ProbeSupport.monotonic > deadline

      sleep 0.05
    end
  end

  def failure_case(ids:, failures:)
    cluster = M5RaftCluster::Cluster.new(ids, timing: TIMING)
    cluster.start_all
    leader = cluster.leader
    acked = []
    120.times do |index|
      response = write(leader, index)
      acked << "k-#{index}" if response["ok"]
    end
    victims = [leader] + (cluster.alive - [leader]).first(failures - 1)
    kill_at = M5ProbeSupport.monotonic
    victims.each(&:kill!)
    new_leader = cluster.leader(timeout: 60)
    resumed_at = M5ProbeSupport.monotonic
    post = write(new_leader, 1000)
    rto = M5ProbeSupport.monotonic - kill_at
    survivors_keys = acknowledged_keys(cluster)
    lost = acked - survivors_keys
    # Restart the victims and check they converge to the same state.
    victims.each { |victim| cluster.start(victim.id) }
    converged = wait_for_convergence(cluster)
    final_keys = cluster.workers.values.map do |worker|
      worker.request({"op" => "list", "prefix" => "k/"})["items"].map do |item|
        item["metadata"]["name"]
      end.sort
    end.uniq
    terms = cluster.workers.values.map { |worker| worker.status["term"] }.uniq
    {
      "id" => "#{ids.length}_nodes_#{failures}_failures",
      "nodes" => ids.length,
      "failures" => failures,
      "acknowledged_writes" => acked.length,
      "lost_acknowledged_writes" => lost.length,
      "lost_keys" => lost.first(5),
      "write_after_recovery_ok" => post["ok"] == true,
      "leader_reelection_seconds" => (resumed_at - kill_at).round(3),
      "rto_seconds" => rto.round(3),
      "converged_after_restart" => converged,
      "replica_state_identical" => final_keys.length == 1,
      "terms" => terms,
      "measurement_source" => "real_processes_sigkill",
      "passed" => lost.empty? && post["ok"] == true && rto < 60 && converged && final_keys.length == 1
    }
  ensure
    cluster&.cleanup
  end

  def membership_case
    cluster = M5RaftCluster::Cluster.new(%w[a b c], timing: TIMING)
    cluster.start_all
    leader = cluster.leader
    60.times { |index| write(leader, index, prefix: "m") }
    %w[d e].each { |id| cluster.add_worker(id, voters: %w[a b c]) }
    %w[d e].each { |id| cluster.start(id) }
    # Start the joint change, then kill the leader before it can complete.
    change = Thread.new do
      leader.request({"op" => "membership", "voters" => %w[a b c d e]}, timeout: 5)
    rescue StandardError
      nil
    end
    sleep 0.05
    leader.kill!
    change.join
    new_leader = cluster.leader(timeout: 60)
    deadline = M5ProbeSupport.monotonic + 60
    membership = nil
    loop do
      membership = new_leader.status["membership"]
      break if membership["voters"] == %w[a b c d e] && !membership.key?("old_voters")
      raise "membership change did not complete: #{membership.inspect}" if M5ProbeSupport.monotonic > deadline

      sleep 0.1
      new_leader = cluster.leader
    end
    60.times { |index| write(new_leader, 100 + index, prefix: "m") }
    cluster.start("a")
    converged = wait_for_convergence(cluster)
    leaders_per_term = Hash.new { |hash, key| hash[key] = [] }
    cluster.alive.each do |worker|
      status = worker.status
      leaders_per_term[status["term"]] << worker.id if status["role"] == "leader"
    end
    split_brain = leaders_per_term.values.any? { |ids| ids.length > 1 }
    keys = cluster.alive.map { |worker| worker.request({"op" => "list", "prefix" => "m/"})["items"].length }.uniq
    {
      "id" => "membership_change_leader_loss",
      "final_membership" => membership,
      "converged" => converged,
      "split_brain" => split_brain,
      "replica_key_counts" => keys,
      "expected_keys" => 120,
      "measurement_source" => "real_processes_sigkill",
      "passed" => converged && !split_brain && keys == [120]
    }
  ensure
    cluster&.cleanup
  end

  def snapshot_install_case
    cluster = M5RaftCluster::Cluster.new(%w[a b c], timing: TIMING)
    cluster.start_all
    leader = cluster.leader
    450.times { |index| write(leader, index, prefix: "s") }
    leader.request({"op" => "snapshot"})
    # A fresh member must be brought up to date by InstallSnapshot.
    cluster.add_worker("d", voters: %w[a b c])
    cluster.start("d")
    leader = cluster.leader
    change = Thread.new do
      leader.request({"op" => "membership", "voters" => %w[a b c d]}, timeout: 30)
    rescue StandardError
      nil
    end
    sleep 0.2
    leader.kill!
    change.join
    new_leader = cluster.leader(timeout: 60)
    deadline = M5ProbeSupport.monotonic + 60
    loop do
      status = cluster.workers["d"].status
      break if status["last_applied"] >= 450 && status["snapshot_installs"].to_i.positive?
      if M5ProbeSupport.monotonic > deadline
        raise "fresh node did not receive a snapshot: #{status.slice("last_applied",
                                                                     "snapshot_installs")}"
      end

      sleep 0.1
    end
    cluster.start("a")
    converged = wait_for_convergence(cluster)
    keys = cluster.alive.map { |worker| worker.request({"op" => "list", "prefix" => "s/"})["items"].length }.uniq
    installs = cluster.workers["d"].status["snapshot_installs"]
    {
      "id" => "snapshot_install_leader_loss",
      "snapshot_installs_on_new_node" => installs,
      "converged" => converged,
      "replica_key_counts" => keys,
      "new_leader" => new_leader.id,
      "measurement_source" => "real_processes_sigkill",
      "passed" => converged && keys == [450] && installs.positive?
    }
  ensure
    cluster&.cleanup
  end

  def run
    started_at = M5ProbeSupport.now
    cases = []
    cases << failure_case(ids: %w[a b c], failures: 1)
    cases << failure_case(ids: %w[a b c d e], failures: 2)
    cases << membership_case
    cases << snapshot_install_case
    M5ProbeSupport.emit(M5ProbeSupport.report(
      kind: "m5_fault_matrix", measurement_level: "integration_tested", started_at: started_at, cases: cases,
      extra: {"worker" => M5ProbeSupport.source_files(%w[test/conformance/kubernetes/m5_raft_cluster/worker.rb
                                                         test/conformance/kubernetes/m5_raft_cluster/harness.rb
                                                         lib/rubernetes/consensus/server.rb lib/rubernetes/consensus/node.rb])}
    ))
  end
end

M5FaultMatrixProbe.run if $PROGRAM_NAME == __FILE__
