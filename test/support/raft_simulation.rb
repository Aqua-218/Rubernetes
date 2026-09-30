# frozen_string_literal: true

# Deterministic discrete-event simulation of Raft nodes.  Every node runs the
# production Consensus::Node over a real WAL/snapshot directory (or an
# in-memory device with failure injection) and a simulated network that can
# partition, drop, delay, reorder and duplicate messages.  Time is virtual:
# the scheduler advances a global clock and each node sees its own offset
# (so clock jumps can be modelled per node).

require "tmpdir"
require "fileutils"

require "rubernetes/consensus"

module RaftSimulation
  class Network
    Packet = Struct.new(:deliver_at, :sequence, :message)

    attr_accessor :drop_rate, :duplicate_rate, :min_delay, :max_delay, :reorder_rate
    # A proc(message) -> boolean; false drops the message.  Lets a scenario
    # cut one message type in one direction (say, AppendEntries to a peer
    # while its forwarded proposals still get through).
    attr_accessor :filter
    attr_reader :delivered, :dropped

    def initialize(random:)
      @random = random
      @queue = []
      @sequence = 0
      @partitions = Set.new
      @drop_rate = 0.0
      @duplicate_rate = 0.0
      @reorder_rate = 0.0
      @min_delay = 0.001
      @max_delay = 0.005
      @delivered = 0
      @dropped = 0
    end

    # Block delivery from `from` to `to` (asymmetric).  Pass both directions
    # for a symmetric partition.
    def cut(from, to)
      @partitions << [from, to]
    end

    def heal(from = nil, to = nil)
      if from.nil?
        @partitions.clear
      else
        @partitions.delete([from, to])
      end
    end

    def cut?(from, to)
      @partitions.include?([from, to])
    end

    def send(message, now)
      return @dropped += 1 if cut?(message.from, message.to)
      return @dropped += 1 if @filter && !@filter.call(message)
      return @dropped += 1 if @drop_rate.positive? && @random.rand < @drop_rate

      copies = @duplicate_rate.positive? && @random.rand < @duplicate_rate ? 2 : 1
      copies.times do
        delay = @min_delay + (@random.rand * (@max_delay - @min_delay))
        delay += @random.rand * @max_delay * 4 if @reorder_rate.positive? && @random.rand < @reorder_rate
        @sequence += 1
        @queue << Packet.new(now + delay, @sequence, message)
      end
    end

    def next_delivery_time
      @queue.map(&:deliver_at).min
    end

    def pop_due(now)
      due, @queue = @queue.partition { |packet| packet.deliver_at <= now }
      due.sort_by { |packet| [packet.deliver_at, packet.sequence] }.map(&:message)
    end

    def pending
      @queue.length
    end

    def clear_to(node_id)
      @queue.reject! { |packet| packet.message.to == node_id }
    end
  end

  # One simulated process hosting a Node.  `alive` false means crashed: it
  # neither ticks nor receives; its durable directory survives for restart.
  class Process
    attr_reader :id, :directory, :node, :storage, :state_machine, :applied
    attr_accessor :clock_offset, :alive
    # Client-side hooks that survive a restart (the node is rebuilt, so a
    # listener registered on it alone would be lost with the crash).
    attr_accessor :applied_hook, :role_hook
    # Incremented by every (re)start: a client that submitted to an earlier
    # generation lost its connection with the crash.
    attr_reader :generation

    def initialize(id:, cluster_id:, directory:, membership:, random:, timing:, sim:, device_factory: nil)
      @id = id
      @cluster_id = cluster_id
      @directory = directory
      @membership = membership
      @random = random
      @timing = timing
      @sim = sim
      @device_factory = device_factory
      @clock_offset = 0.0
      @alive = false
      @applied = []
      start
    end

    def start(recover_torn_tail: false)
      @generation = (@generation || 0) + 1
      @storage = Rubernetes::Consensus::Storage.new(@directory, recover_torn_tail: recover_torn_tail,
                                                                device_factory: @device_factory, fsync: false)
      @state_machine = Rubernetes::Consensus::KVStateMachine.new
      wall = @sim
      offset_reader = -> { @clock_offset }
      @node = Rubernetes::Consensus::Node.new(
        id: @id, cluster_id: @cluster_id, log: @storage.log, snapshot_store: @storage.snapshots,
        state_machine: @state_machine, initial_membership: @membership,
        clock: -> { wall.now + offset_reader.call }, random: Random.new(@random.rand(2**31)),
        timing: @timing, wal_size: -> { @storage.wal_size },
        wall_clock: -> { Time.at(wall.now).utc }
      )
      @node.on_applied { |applied| @applied << applied }
      process = self
      @node.on_applied { |applied| process.applied_hook&.call(process, applied) }
      @node.on_role_change { |previous, current| process.role_hook&.call(process, previous, current) }
      @alive = true
      self
    end

    def crash
      @alive = false
      @storage.close
      @node.stop
    end

    def restart(recover_torn_tail: true)
      @applied = []
      start(recover_torn_tail: recover_torn_tail)
    end

    def now
      @sim.now + @clock_offset
    end
  end

  class Cluster
    # Messages a Consensus::Server answers itself rather than handing to the
    # node (ForwardProposalResponse, ReadIndexResponse) go to this handler
    # when one is set; without it they are dropped like the node would.
    attr_accessor :client_handler

    def initialize(node_ids, seed: 1, timing: nil, root: nil, device_factory: nil)
      @random = Random.new(seed)
      @cluster_id = "sim-cluster"
      @root = root || Dir.mktmpdir("raft-sim")
      @owns_root = root.nil?
      @now = 0.0
      @network = Network.new(random: @random)
      @timing = timing || Rubernetes::Consensus::Node::Timing.default
      @device_factory = device_factory
      membership = Rubernetes::Consensus::Membership.simple(node_ids)
      @processes = node_ids.to_h do |id|
        [id, Process.new(id: id, cluster_id: @cluster_id, directory: File.join(@root, id), membership: membership,
                         random: @random, timing: @timing, sim: self, device_factory: device_factory)]
      end
      @trace = []
      @step_hooks = []
    end

    # Called after every simulation step with the virtual time, so a client
    # layer can drive timeouts and retries on the same clock.
    def add_step_hook(&block)
      @step_hooks << block
      self
    end

    CLIENT_MESSAGES = [Rubernetes::Consensus::Messages::ForwardProposalResponse,
                       Rubernetes::Consensus::Messages::ReadIndexResponse].freeze

    attr_reader :processes, :network, :random, :cluster_id, :root, :now

    def node(id)
      @processes.fetch(id).node
    end

    def alive?(id)
      @processes.fetch(id).alive
    end

    def add_process(id, membership:)
      @processes[id] = Process.new(id: id, cluster_id: @cluster_id, directory: File.join(@root, id), membership: membership,
                                   random: @random, timing: @timing, sim: self, device_factory: @device_factory)
    end

    def crash(id)
      @processes.fetch(id).crash
      @network.clear_to(id)
    end

    def restart(id, recover_torn_tail: true)
      @processes.fetch(id).restart(recover_torn_tail: recover_torn_tail)
    end

    def leader
      @processes.values.select { |process| process.alive && process.node.leader? }.map(&:node)
    end

    def leaders_in_term
      leader.group_by(&:current_term)
    end

    # Advance virtual time in fixed steps, delivering due messages and
    # ticking every live node.
    def run(seconds, step: 0.001)
      deadline = @now + seconds
      while @now < deadline
        @now += step
        deliver_due
        @processes.each_value do |process|
          next unless process.alive

          route(process.node.tick(process.now))
        end
        @step_hooks.each { |hook| hook.call(@now) }
      end
      self
    end

    def run_until(timeout:, step: 0.001)
      deadline = @now + timeout
      while @now < deadline
        return true if yield

        run(step, step: step)
      end
      yield
    end

    def deliver_due
      @network.pop_due(@now).each do |message|
        process = @processes[message.to]
        next unless process&.alive

        if @client_handler && CLIENT_MESSAGES.any? { |klass| message.is_a?(klass) }
          @client_handler.call(message)
          next
        end

        begin
          route(process.node.handle(message, process.now))
        rescue Rubernetes::Consensus::ProtocolError
          next
        end
      end
    end

    def route(messages)
      messages.each { |message| @network.send(message, @now) }
    end

    def cleanup
      FileUtils.rm_rf(@root) if @owns_root
    end
  end
end
