# frozen_string_literal: true

# Spawns real worker processes and drives them through their control sockets.

require "fileutils"
require "json"
require "socket"
require "timeout"
require "tmpdir"
require "rbconfig"

$LOAD_PATH.unshift File.expand_path("../../../../lib", __dir__)
require "rubernetes/consensus"

module M5RaftCluster
  WORKER = File.expand_path("worker.rb", __dir__)

  class Worker
    attr_reader :id, :pid, :address, :data, :control, :journal

    def initialize(id:, cluster:, root:, pki:, voters:, timing:)
      @id = id
      @cluster = cluster
      @root = root
      @pki = pki
      @voters = voters
      @timing = timing
      @data = File.join(root, "data", id)
      @control = File.join(root, "ctl-#{id}.sock")
      @journal = File.join(root, "journal-#{id}.jsonl")
      @address = nil
      @pid = nil
      @generation = 0
    end

    def start(peers: {})
      @generation += 1
      command = [RbConfig.ruby, WORKER, "--id", @id, "--cluster", @cluster, "--data", @data, "--pki", File.join(@pki, @id),
                 "--listen", "127.0.0.1:0", "--voters", @voters.join(","), "--control", @control, "--journal", @journal,
                 "--timing", JSON.generate(@timing)]
      command.push("--peers", peers.map { |id, address| "#{id}=#{address}" }.join(",")) unless peers.empty?
      reader, writer = IO.pipe
      @pid = Process.spawn(*command, out: writer, err: File.join(@root, "worker-#{@id}.log"))
      writer.close
      line = begin
        Timeout.timeout(60) { reader.gets }
      rescue Timeout::Error
        nil
      end
      if line.nil?
        log = File.exist?(File.join(@root, "worker-#{@id}.log")) ? File.read(File.join(@root, "worker-#{@id}.log")).lines.last(20).join : ""
        raise "worker #{@id} did not become ready: #{log}"
      end

      ready = JSON.parse(line)
      @address = ready.fetch("address")
      @port = Integer(@address.rpartition(":")[2])
      reader.close
      self
    end

    def alive?
      return false if @pid.nil?

      Process.kill(0, @pid)
      Process.waitpid(@pid, Process::WNOHANG).nil?
    rescue Errno::ESRCH, Errno::ECHILD
      false
    end

    def kill!(signal = "KILL")
      return unless @pid

      Process.kill(signal, @pid)
      Process.waitpid(@pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    ensure
      @pid = nil
    end

    def request(payload, timeout: 15)
      Timeout.timeout(timeout) do
        UNIXSocket.open(@control) do |socket|
          socket.puts(JSON.generate(payload))
          line = socket.gets
          raise "worker #{@id} closed the control socket" if line.nil?

          JSON.parse(line)
        end
      end
    end

    def status
      request({"op" => "status"})["status"]
    end

    def leader?
      status["role"] == "leader"
    rescue StandardError
      false
    end
  end

  class Cluster
    attr_reader :workers, :root, :cluster_id

    def initialize(ids, root: nil, timing: {}, cluster_id: "m5-cluster")
      @cluster_id = cluster_id
      @root = root || Dir.mktmpdir("m5-raft")
      @owns_root = root.nil?
      @timing = timing
      @ids = ids
      @pki = File.join(@root, "pki")
      ca, ca_key = Rubernetes::Consensus::Identity.generate_ca(cluster_id)
      Rubernetes::Consensus::Identity.write_ca(File.join(@pki, "ca"), ca, ca_key)
      @workers = ids.to_h do |id|
        bundle = Rubernetes::Consensus::Identity.issue_node(ca, ca_key, cluster_id: cluster_id, node_id: id)
        Rubernetes::Consensus::Identity.write_bundle(File.join(@pki, id), bundle)
        [id, Worker.new(id: id, cluster: cluster_id, root: @root, pki: @pki, voters: ids, timing: timing)]
      end
    end

    def add_worker(id, voters:)
      ca, ca_key = Rubernetes::Consensus::Identity.read_ca(File.join(@pki, "ca"))
      bundle = Rubernetes::Consensus::Identity.issue_node(ca, ca_key, cluster_id: @cluster_id, node_id: id)
      Rubernetes::Consensus::Identity.write_bundle(File.join(@pki, id), bundle)
      @workers[id] = Worker.new(id: id, cluster: @cluster_id, root: @root, pki: @pki, voters: voters, timing: @timing)
    end

    def start_all
      @workers.each_value(&:start)
      connect_peers
      self
    end

    def start(id)
      worker = @workers.fetch(id)
      worker.start(peers: peer_map(id))
      connect_peers
      worker
    end

    def connect_peers
      @workers.each_value do |worker|
        next unless worker.alive?

        peer_map(worker.id).each do |peer_id, address|
          worker.request({"op" => "add_peer", "id" => peer_id, "address" => address})
        rescue StandardError
          nil
        end
      end
    end

    def peer_map(id)
      @workers.reject { |peer_id, worker| peer_id == id || worker.address.nil? }.transform_values(&:address)
    end

    def leader(timeout: 30)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      loop do
        leaders = @workers.values.select(&:alive?).select(&:leader?)
        return leaders.first if leaders.length == 1
        raise "no leader within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        sleep 0.05
      end
    end

    def leaders
      @workers.values.select(&:alive?).select(&:leader?)
    end

    def alive
      @workers.values.select(&:alive?)
    end

    def kill_all
      @workers.each_value { |worker| worker.kill! if worker.alive? }
    end

    def cleanup
      kill_all
      FileUtils.rm_rf(@root) if @owns_root
    end
  end
end
