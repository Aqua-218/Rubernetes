#!/usr/bin/env ruby
# frozen_string_literal: true

# Raft write/read latency on three in-process replicas with the production
# transport (mutual TLS over loopback) and real WAL fsyncs.
#
#   bundle exec ruby -Ilib benchmarks/consensus/raft_write_bench.rb [--dir DIR] [--rounds N] [--json]
#
# Reports, in milliseconds: a lone proposal on the leader; 8 and 32
# concurrent proposals (group commit); a proposal forwarded through a
# follower; and a linearizable read barrier on the leader and through a
# follower.  Use the same --dir (a real disk, not tmpfs) for before/after
# comparisons: the fsync cost is the point.

require "optparse"
require "tmpdir"
require "json"
require "securerandom"
require "rubernetes/consensus"

options = {dir: nil, rounds: 200, json: false, timing: "default", processes: false}
OptionParser.new do |parser|
  parser.on("--dir DIR") { |value| options[:dir] = value }
  parser.on("--rounds N", Integer) { |value| options[:rounds] = value }
  parser.on("--json") { options[:json] = true }
  parser.on("--production-timing") { options[:timing] = "production" }
  # One replica per process, as in production: the in-process variant
  # serialises all three replicas behind one GVL and overstates contention.
  parser.on("--processes") { options[:processes] = true }
end.parse!

C = Rubernetes::Consensus

def percentile(samples, fraction)
  sorted = samples.sort
  sorted[[(sorted.length * fraction).ceil - 1, 0].max]
end

def summarize(samples)
  ms = samples.map { |seconds| seconds * 1000.0 }
  {p50: percentile(ms, 0.5).round(2), p90: percentile(ms, 0.9).round(2), p99: percentile(ms, 0.99).round(2), n: ms.length}
end

def timed
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  yield
  Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
end

def command(key)
  {"type" => "create", "key" => key, "object" => {"metadata" => {"name" => key.split("/").last, "namespace" => "bench",
                                                                 "labels" => {"app" => "bench"}},
                                                  "spec" => {"containers" => [{"name" => "c", "image" => "pause:3.9"}]}},
   "request_uid" => nil, "leader_time" => Time.now.to_f}
end

root = options[:dir] || Dir.mktmpdir("raft-bench")
FileUtils.rm_rf(Dir.children(root).map { |child| File.join(root, child) })
timing = options[:timing] == "production" ? C::Node::Timing.production : C::Node::Timing.default
ca, ca_key = C::Identity.generate_ca("bench")
ids = %w[a b c]
bundles = ids.to_h { |id| [id, C::Identity.issue_node(ca, ca_key, cluster_id: "bench", node_id: id)] }
rounds = options[:rounds]
results = {}
children = []

def free_port
  socket = TCPServer.new("127.0.0.1", 0)
  port = socket.addr[1]
  socket.close
  port
end

if options[:processes]
  require "socket"
  ports = ids.to_h { |id| [id, free_port] }
  addresses = ports.transform_values { |port| "127.0.0.1:#{port}" }
  # This process hosts replica "a" and starts first so it wins the first
  # election; the children host "b" and "c".
  local = C::Server.new(id: "a", cluster_id: "bench", data_directory: File.join(root, "a"), bundle: bundles["a"],
                        initial_voters: ids, timing: timing, port: ports["a"], peers: addresses.reject { |id, _| id == "a" })
  local.start
  children = %w[b c].map do |id|
    fork do
      server = C::Server.new(id: id, cluster_id: "bench", data_directory: File.join(root, id), bundle: bundles[id],
                             initial_voters: ids, timing: timing, port: ports[id], peers: addresses.reject { |peer, _| peer == id })
      server.start
      sleep
    end
  end
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
  sleep 0.02 until local.leader? || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
  abort("replica a did not become leader") unless local.leader?
  sleep 0.5
  leader = local
  follower = nil
  servers = {"a" => local}
else
  servers = ids.to_h do |id|
    [id,
     C::Server.new(id: id, cluster_id: "bench", data_directory: File.join(root, id), bundle: bundles[id], initial_voters: ids,
                   timing: timing)]
  end
  servers.each_value(&:start)
  servers.each_value { |server| servers.each { |peer_id, peer| server.add_peer(peer_id, peer.address) unless peer.equal?(server) } }
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
  sleep 0.02 until servers.values.any?(&:leader?) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
  sleep 0.3
  leader = servers.values.find(&:leader?) or abort("no leader")
  follower = servers.values.find { |server| !server.leader? }
end

# Warm up TLS connections and the JIT-less interpreter.
20.times { |i| leader.propose(command("registry/pods/bench/warm-#{i}")) }

samples = Array.new(rounds) { |i| timed { leader.propose(command("registry/pods/bench/lone-#{i}")) } }
results[:propose_lone_leader] = summarize(samples)

phase_sums = Hash.new { |hash, key| hash[key] = Hash.new(0.0) }
[8, 32].each do |concurrency|
  per_thread = [rounds / concurrency, 10].max
  queue = Queue.new
  wall = timed do
    threads = Array.new(concurrency) do |thread_index|
      Thread.new do
        per_thread.times do |i|
          phases = Thread.current[:rubernetes_request_phases] = {}
          queue << timed { leader.propose(command("registry/pods/bench/c#{concurrency}-#{thread_index}-#{i}")) }
          phases.each { |name, seconds| phase_sums[concurrency][name] += seconds }
        end
      end
    end
    threads.each(&:join)
  end
  latencies = Array.new(queue.length) { queue.pop }
  results[:"propose_concurrent_#{concurrency}"] = summarize(latencies).merge(throughput_per_s: (latencies.length / wall).round(0))
  results[:"propose_concurrent_#{concurrency}"][:phases_ms] = phase_sums[concurrency].transform_values do |seconds|
    (seconds * 1000.0 / latencies.length).round(2)
  end
end

samples = Array.new(rounds) { timed { leader.read_index } }
results[:read_index_leader] = summarize(samples)

if options[:processes]
  # Hand leadership to a child so this process measures the follower paths.
  leader.transfer_leadership("b")
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
  sleep 0.02 while (leader.leader? || leader.leader_id.nil?) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
  abort("leadership transfer failed") if leader.leader?
  sleep 0.3
  follower = leader
end

samples = Array.new(rounds) { |i| timed { follower.propose(command("registry/pods/bench/fwd-#{i}")) } }
results[:propose_forwarded] = summarize(samples)
samples = Array.new(rounds) { timed { follower.read_index } }
results[:read_index_forwarded] = summarize(samples)

queue = Queue.new
threads = Array.new(16) { Thread.new { (rounds / 16).times { queue << timed { follower.read_index } } } }
threads.each(&:join)
results[:read_index_forwarded_concurrent_16] = summarize(Array.new(queue.length) { queue.pop })

servers.each_value(&:stop)
children.each { |pid| Process.kill("TERM", pid)
Process.wait(pid) }
FileUtils.rm_rf(root) unless options[:dir]

if options[:json]
  puts JSON.pretty_generate(results)
else
  puts format("%-36s %8s %8s %8s %6s %s", "case", "p50 ms", "p90 ms", "p99 ms", "n", "")
  results.each do |name, stats|
    extra = stats[:throughput_per_s] ? "#{stats[:throughput_per_s]}/s" : ""
    puts format("%-36s %8.2f %8.2f %8.2f %6d %s", name, stats[:p50], stats[:p90], stats[:p99], stats[:n], extra)
    next unless stats[:phases_ms]

    puts format("%-36s mean phases: %s", "", stats[:phases_ms].sort_by { |_n, v|
      -v
    }.map { |n, v| "#{n}=#{v}" }.join(" "))
  end
end
