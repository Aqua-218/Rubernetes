# frozen_string_literal: true

require "securerandom"

require_relative "errors"
require_relative "node"
require_relative "storage"
require_relative "state_machine"
require_relative "transport"
require_relative "identity"
require_relative "messages"

module Rubernetes
  module Consensus
    # Runs one Raft node on real time: a ticker thread drives timers, the
    # transport delivers inbound RPCs, and client operations block until the
    # proposal is applied.  All node access is serialized by one mutex; the
    # node itself never blocks on I/O other than its WAL fsync.
    class Server
      Future = Struct.new(:mutex, :condition, :value, :error, :done) do
        def resolve(value = nil, error = nil)
          mutex.synchronize do
            return if done

            self.value = value
            self.error = error
            self.done = true
            condition.broadcast
          end
        end

        def wait(timeout)
          mutex.synchronize do
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            until done
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              raise Timeout, "operation timed out after #{timeout}s" if remaining <= 0

              condition.wait(mutex, remaining)
            end
            raise error if error

            value
          end
        end
      end

      DEFAULT_TIMEOUT = 10.0
      TICK_INTERVAL = 0.001

      def initialize(id:, cluster_id:, data_directory:, bundle:, initial_voters:, peers: {}, host: "127.0.0.1", port: 0,
                     timing: Node::Timing.default, logger: nil, recover_torn_tail: true, device_factory: nil,
                     history_revisions: nil, history_seconds: nil, pre_vote: true)
        @id = id
        @cluster_id = cluster_id
        @data_directory = data_directory
        @logger = logger
        @timing = timing
        @storage = Storage.new(data_directory, recover_torn_tail: recover_torn_tail, device_factory: device_factory)
        # history_seconds is kube-apiserver's --etcd-compaction-interval: how
        # much history the datastore keeps before compacting it away.
        @state_machine = KVStateMachine.new(
          history_revisions: history_revisions || Rubernetes::Storage::MemoryStore::DEFAULT_HISTORY_REVISIONS,
          history_seconds: history_seconds || Rubernetes::Storage::MemoryStore::DEFAULT_HISTORY_SECONDS,
          logger: logger
        )
        @mutex = Monitor.new
        @node = Node.new(id: id, cluster_id: cluster_id, log: @storage.log, snapshot_store: @storage.snapshots,
                         state_machine: @state_machine, initial_membership: Membership.simple(initial_voters),
                         clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, timing: timing,
                         wal_size: -> { @storage.wal_size }, pre_vote: pre_vote, logger: logger,
                         snapshot_writer: ->(capture) { write_snapshot_async(capture) })
        @transport = Transport::Endpoint.new(node_id: id, cluster_id: cluster_id, bundle: bundle, host: host, port: port,
                                             peers: peers, logger: logger)
        @transport.on_message { |message, _identity| inbound(message) }
        @pending = {}
        # Every linearizable read waits for the state machine to catch up to
        # its read index.  Polling for that re-acquired this monitor a thousand
        # times a second per waiter, and this monitor is the same one the apply
        # loop and every proposal need -- so under a conformance run's read
        # load the barrier starved the very apply loop it was waiting for, and
        # each slow apply added more spinning waiters.  Reads then blocked for
        # 10 s a try, three tries, and the apiserver answered informers with
        # "503 read index timed out".
        # Proposal waiters and the applied-index condition have a lock of
        # their own.  The apply thread runs the state machine under the
        # node's apply lock and then notifies them, so if notifying took the
        # node lock it could meet a thread that holds the node lock and is
        # waiting for the apply lock (a snapshot capture).  Nothing on this
        # lock ever takes another.
        @applied_mutex = Mutex.new
        @applied_condition = ConditionVariable.new
        @flushed_condition = @mutex.new_cond
        @flushed_last_index = nil
        @arrivals = Mutex.new
        @waiting_proposers = 0
        @forward_waiters = {}
        @read_waiters = {}
        @applied_listeners = []
        @node.on_applied { |applied| applied_hook(applied) }
        @node.on_role_change { |previous, current| role_hook(previous, current) }
        @running = false
        @failure = nil
      end

      def start
        @transport.start
        @running = true
        # The state machine runs on its own thread, outside the lock that
        # proposals, read barriers and inbound messages share: applying an
        # AppendEntries worth of entries inline held that lock for
        # milliseconds and that is where a write burst's latency went.  The
        # node signals this thread whenever the commit index advances.
        @apply_signal_mutex = Mutex.new
        @apply_condition = ConditionVariable.new
        @apply_pending = false
        if self.class.async_apply?
          @node.async_apply = -> { signal_apply }
          @apply_thread = Thread.new { apply_loop }
          @apply_thread.name = "raft-apply-#{@id}"
        end
        # The leader's batches are made durable by one thread: it appends
        # and sends under the node lock, fsyncs with the lock released, and
        # confirms the durable index.  Proposers, inbound messages and the
        # tick loop only ask it to run.  Before this, every flush fsynced
        # under the monitor that every proposal, read barrier and inbound
        # message needs, and under a write burst the tick thread that was
        # supposed to flush batches at their deadline got the monitor only
        # every 4 ms typical, 25 ms worst.
        @flush_mutex = Mutex.new
        @flush_condition = ConditionVariable.new
        @flush_requested = false
        @node.external_sync = true
        @flusher = Thread.new { flush_loop }
        @flusher.name = "raft-flush-#{@id}"
        @ticker = Thread.new { tick_loop }
        @ticker.name = "raft-tick-#{@id}"
        self
      end

      # Wake the flusher; returns at once.
      def request_flush
        @flush_mutex.synchronize do
          @flush_requested = true
          @flush_condition.signal
        end
      end

      # Whether the state machine runs on its own thread.  Moving it off the
      # raft lock shortens the critical section a write burst queues behind,
      # but it also puts a thread hand-off in the path of every single
      # proposal, which costs more than it saves when several nodes share one
      # interpreter (the deterministic benchmarks) or when writes arrive one
      # at a time.  RUBERNETES_RAFT_ASYNC_APPLY=1 turns it on.
      def self.async_apply?
        return @async_apply unless @async_apply.nil?

        @async_apply = ENV["RUBERNETES_RAFT_ASYNC_APPLY"].to_s == "1"
      end

      class << self
        attr_writer :async_apply
      end

      # Called by the node while it holds the node lock: wake the apply
      # thread and return at once.
      def signal_apply
        @apply_signal_mutex.synchronize do
          @apply_pending = true
          @apply_condition.signal
        end
      end

      def address
        @transport.address
      end

      def add_peer(node_id, address)
        @transport.add_peer(node_id, address)
      end

      def stop
        @running = false
        if @apply_thread
          signal_apply
          @apply_thread.join(5)
        end
        if @flusher
          request_flush
          @flusher.join(5)
        end
        @ticker&.join(1)
        @snapshot_thread&.join(30)
        @transport.stop
        @mutex.synchronize do
          @node.stop
          @storage.close
        end
        fail_all(NotReady.new("server stopped"))
        self
      end

      def failed?
        !@failure.nil?
      end

      attr_reader :node, :storage, :state_machine, :transport, :id, :cluster_id, :data_directory, :failure, :logger

      def leader?
        @mutex.synchronize { @node.leader? }
      end

      def leader_id
        @mutex.synchronize { @node.leader_id }
      end

      def quorum_available?
        @mutex.synchronize { @node.quorum_available? }
      end

      def status
        @mutex.synchronize { @node.status.merge("failure" => @failure&.message, "transport" => @transport.stats) }
      end

      def on_applied(&block)
        @applied_listeners << block
        self
      end

      # Propose a command and wait for it to be applied.  Followers forward to
      # the leader; a lost response is handled by the caller retrying with the
      # same request_id, which the state machine deduplicates.
      #
      # Group commit: a proposer that finds no other proposer waiting for the
      # monitor flushes its batch itself, so a lone write pays no extra
      # latency.  One that sees others queued behind it leaves the batch for
      # the tick loop, which flushes everything that has accumulated within
      # a millisecond -- one WAL fsync and one AppendEntries for all of them.
      # Flushing every proposal on its own held the monitor for a sync per
      # write and eight concurrent writes took eight times as long as one.
      def propose(command, request_id: SecureRandom.uuid, timeout: DEFAULT_TIMEOUT)
        check_failure!
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          raise Timeout, "proposal #{request_id} timed out" if remaining <= 0

          @arrivals.synchronize { @waiting_proposers += 1 }
          entered = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          position, leader = @mutex.synchronize do
            record_phase("propose.monitor", Process.clock_gettime(Process::CLOCK_MONOTONIC) - entered)
            @arrivals.synchronize { @waiting_proposers -= 1 }
            if @node.leader?
              timed_phase("propose.append") { @node.propose(command, request_id: request_id) }
              position = @node.proposal_position(request_id)
              unless position
                request_flush
                position = await_batch_flush(request_id, remaining)
              end
              [position, nil]
            else
              [nil, @node.leader_id]
            end
          end
          if position
            record_phase("propose.flush", Process.clock_gettime(Process::CLOCK_MONOTONIC) - entered)
            record_position(position[:index], position[:term], :local)
            applied_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            begin
              return wait_for(position[:index], position[:term], request_id, remaining)
            ensure
              record_phase("propose.apply", Process.clock_gettime(Process::CLOCK_MONOTONIC) - applied_started)
            end
          elsif leader && leader != @id
            forward_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            result = begin
              forward(leader, command, request_id, [remaining, 2.0].min)
            ensure
              record_phase("propose.forward", Process.clock_gettime(Process::CLOCK_MONOTONIC) - forward_started)
            end
            return result unless result.nil?
          else
            sleep(0.02)
          end
        end
      end

      # Linearizable read barrier: returns the read index once confirmed.
      def read_index(timeout: DEFAULT_TIMEOUT)
        check_failure!
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          raise Timeout, "read index timed out" if remaining <= 0

          future = Future.new(Mutex.new, ConditionVariable.new, nil, nil, false)
          leader = @mutex.synchronize do
            if @node.leader?
              begin
                @node.read_index { |index, error| future.resolve(index, error) }
                flush_outbox
                :self
              rescue NotReady
                nil
              end
            else
              @node.leader_id
            end
          end
          if leader == :self
            begin
              index = future.wait([remaining, 2.0].min)
              wait_applied(index, remaining)
              return index
            rescue NotLeader, Timeout
              next
            end
          elsif leader && leader != @id
            index = forward_read(leader, [remaining, 2.0].min)
            unless index.nil?
              wait_applied(index, remaining)
              return index
            end
          else
            sleep(0.02)
          end
        end
      end

      def propose_membership(new_voters, learners: [], timeout: DEFAULT_TIMEOUT)
        position = @mutex.synchronize do
          raise NotLeader.new(leader_id: @node.leader_id) unless @node.leader?

          result = @node.propose_membership(new_voters, learners: learners)
          flush_outbox
          result
        end
        wait_for(position[:index], position[:term], nil, timeout)
        # Wait for the final configuration to commit as well.
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          done = @mutex.synchronize { !@node.membership.joint? && @node.pending_membership_change.nil? }
          return @mutex.synchronize { @node.membership.to_h } if done
          raise Timeout, "membership change did not finish" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

          sleep(0.01)
        end
      end

      def transfer_leadership(target)
        @mutex.synchronize do
          @node.transfer_leadership(target)
          flush_outbox
        end
      end

      def snapshot!(force: true)
        @mutex.synchronize { @node.snapshot!(force: force) }
      end

      def membership
        @mutex.synchronize { @node.membership }
      end

      def store
        @state_machine.store
      end

      def synchronize(&)
        @mutex.synchronize(&)
      end

      private

      def check_failure!
        raise StorageFailed, "node is fail-closed: #{@failure.message}" if @failure
      end

      # Called by the node under @mutex with a captured state document.  The
      # encode (seconds for a large store) and the fsync happen on this thread
      # with the lock released, so heartbeats keep flowing; only the log
      # compaction goes back under the lock.
      def write_snapshot_async(capture)
        @snapshot_thread = Thread.new do
          state = KVStateMachine.encode_snapshot(capture.document)
          metadata = @storage.snapshots.write(state: state, index: capture.index, term: capture.term,
                                              membership: capture.membership, created_at: capture.created_at)
          @mutex.synchronize { @node.complete_snapshot!(capture, metadata) }
          @logger&.info("consensus.snapshot_written", index: capture.index, term: capture.term, bytes: metadata.bytes,
                                                      seconds: (Process.clock_gettime(Process::CLOCK_MONOTONIC) - capture.started_at).round(3))
        rescue DurabilityError, CorruptionError => error
          fail_closed!(error)
        rescue StandardError => error
          @mutex.synchronize { @node.abandon_snapshot!(capture, error) }
          @logger&.error("consensus.snapshot_failed", index: capture.index, error: "#{error.class}: #{error.message}")
        end
        @snapshot_thread.name = "raft-snapshot-#{@id}"
        @snapshot_thread
      end

      # Applies committed entries outside the node lock, then takes it only
      # to settle what the new applied index unblocks.  A pending flag set
      # under this thread's own mutex means a signal that arrives mid-apply
      # is never lost.
      def apply_loop
        while @running
          begin
            @apply_signal_mutex.synchronize do
              @apply_condition.wait(@apply_signal_mutex, 0.05) unless @apply_pending
              @apply_pending = false
            end
            next unless @running

            applied, configuration_entries = @node.apply_pending!
            next unless applied || !configuration_entries.empty?

            @mutex.synchronize do
              @node.after_async_apply(configuration_entries)
              route(@node.drain)
            end
          rescue DurabilityError, CorruptionError => error
            fail_closed!(error)
          rescue StandardError => error
            @logger&.error("consensus.apply_error", error: "#{error.class}: #{error.message}",
                                                    backtrace: error.backtrace&.first(5))
            sleep(0.01)
          end
        end
      end

      def tick_loop
        while @running
          begin
            @mutex.synchronize do
              route(@node.tick)
              signal_flushed
              request_flush if @node.batch_pending?
            end
          rescue DurabilityError, CorruptionError => error
            fail_closed!(error)
          rescue StandardError => error
            @logger&.error("consensus.tick_error", error: "#{error.class}: #{error.message}", backtrace: error.backtrace&.first(5))
          end
          sleep(TICK_INTERVAL)
        end
      end

      def inbound(message)
        return if @failure

        @mutex.synchronize do
          case message
          when Messages::ForwardProposalResponse then resolve_forward(message)
          when Messages::ReadIndexResponse then resolve_forward_read(message)
          else
            route(@node.handle(message))
            # A forwarded proposal joins the next batch, flushed at once.
            request_flush if @node.batch_pending?
          end
        end
      rescue DurabilityError, CorruptionError => error
        fail_closed!(error)
      rescue ProtocolError => error
        @logger&.warn("consensus.protocol_error", error: error.message)
      end

      def route(messages)
        messages.each { |message| @transport.send(message) }
      end

      def flush_outbox
        route(@node.drain)
      end

      def flush_loop
        while @running
          begin
            @flush_mutex.synchronize do
              @flush_condition.wait(@flush_mutex, 0.05) unless @flush_requested
              @flush_requested = false
            end
            next unless @running

            flush_batches
          rescue DurabilityError, CorruptionError => error
            fail_closed!(error)
            return
          rescue StandardError => error
            @logger&.error("consensus.flush_error", error: "#{error.class}: #{error.message}", backtrace: error.backtrace&.first(5))
            sleep(0.01)
          end
        end
      end

      # Flushes batches until none is pending.  Each round: under the node
      # lock append the batch without its fsync and send the AppendEntries
      # (Node#flush defer_sync:), so replication overlaps the fsync; with
      # the lock released, fsync; under the lock again, count the durable
      # prefix toward the commit.  Proposals arriving during the fsync form
      # the next batch -- etcd's batching, sized by the disk rather than by
      # a timer.
      def flush_batches
        loop do
          through = @mutex.synchronize do
            next nil unless @node.leader? && @node.batch_pending?

            @node.flush(defer_sync: true)
            signal_flushed
            flush_outbox
            @storage.log.last_index
          end
          return if through.nil?

          @storage.log.sync
          @mutex.synchronize do
            @node.confirm_local_sync!(through)
            flush_outbox
          end
        end
      end

      def timed_phase(name)
        return yield unless Thread.current[:rubernetes_request_phases]

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          yield
        ensure
          record_phase(name, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        end
      end

      # A durability or corruption failure makes the node stop participating:
      # it never acknowledges again from a state it cannot trust.
      def fail_closed!(error)
        @failure ||= error
        @logger&.error("consensus.fail_closed", error: "#{error.class}: #{error.message}")
        @mutex.synchronize { @node.stop }
        fail_all(StorageFailed.new("node is fail-closed: #{error.message}"))
      end

      def fail_all(error)
        pending = @applied_mutex.synchronize { @pending.values.tap { @pending.clear } }
        pending.each { |future| future.resolve(nil, error) }
      end

      # Where the proposal the calling thread is waiting on landed, for the
      # caller's trace (RaftStore#submit): the thread-local is only written
      # when the caller asked for it by setting it.
      POSITION_KEY = :rubernetes_raft_position

      def record_position(index, term, via)
        position = Thread.current[POSITION_KEY]
        return unless position

        position[:index] = index
        position[:term] = term
        position[:via] = via
        position[:node] = @id
      end

      # Per-request phase accounting (API::Server request tracing): the time a
      # proposal spends getting into the log (monitor wait, batch flush) and
      # the time until the quorum has applied it.
      def record_phase(name, seconds)
        phases = Thread.current[:rubernetes_request_phases]
        return unless phases

        phases[name] = phases.fetch(name, 0.0) + seconds
      end

      # Wake proposers waiting for the group-commit batch that holds their
      # entry.  Called with the monitor held after every tick.
      def signal_flushed
        last_index = @storage.log.last_index
        return if last_index == @flushed_last_index

        @flushed_last_index = last_index
        @flushed_condition.broadcast
      end

      # How long a proposal left for the tick loop waits before flushing the
      # batch itself: several ticks of slack.
      BATCH_FLUSH_SLACK = 0.010

      # A proposal left for group commit has no position until the batch is
      # flushed (normally by the flusher thread within a millisecond).  Waits
      # on the monitor's condition -- releasing it so the flusher can run --
      # and flushes itself if the flusher is late.  Returns nil if
      # leadership was lost meanwhile; the caller then forwards or retries.
      def await_batch_flush(request_id, timeout)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          # The batch may have been flushed by the flusher and this node
          # stepped down before the proposer woke: its entry is in the log
          # under the old term, and the proposer waits for that entry's
          # outcome.  Only an entry that never left the batch is proposed
          # again.
          return @node.appended_position(request_id) unless @node.leader?

          position = @node.proposal_position(request_id)
          return position if position

          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          raise Timeout, "proposal #{request_id} was not flushed in time" if remaining <= 0

          if @flusher&.alive?
            # The flusher takes the batch as soon as its current fsync is
            # done.  Flushing here instead would fsync under the monitor
            # behind that fsync -- during a 300 ms disk stall the tick loop
            # sent no heartbeats and the followers elected a new leader.
            request_flush
          else
            @node.flush
            flush_outbox
            next
          end
          @flushed_condition.wait([remaining, BATCH_FLUSH_SLACK].min)
        end
      end

      def wait_for(index, term, _request_id, timeout)
        future = @applied_mutex.synchronize do
          applied = @applied_by_index && @applied_by_index[index]
          if applied && applied[:term] == term
            raise AppliedThroughSnapshot, "entry #{index} was applied through a snapshot; outcome unknown" if applied[:snapshot]

            return applied[:result]
          end
          # A follower whose forwarded entry was covered by an installed
          # snapshot before it applied the entry itself holds no result for
          # it and never will.  Waiting registered a future nothing could
          # resolve: the forward timed out, the retry got the same position
          # from the leader, and the write was reported 503 only after the
          # whole 10 s deadline.
          if @snapshot_applied_index && index <= @snapshot_applied_index
            raise AppliedThroughSnapshot, "entry #{index} was applied through a snapshot at #{@snapshot_applied_index}; outcome unknown"
          end

          @pending[[index, term]] ||= Future.new(Mutex.new, ConditionVariable.new, nil, nil, false)
        end
        future.wait(timeout)
      end

      # The bounded wait is belt and braces: the apply hook signals, and a
      # missed signal costs 50 ms rather than a hang.
      APPLIED_WAIT_SECONDS = 0.05

      def wait_applied(index, timeout)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        @applied_mutex.synchronize do
          loop do
            return if @node.last_applied >= index

            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise Timeout, "read index #{index} was not applied in time" if remaining <= 0

            @applied_condition.wait(@applied_mutex, [remaining, APPLIED_WAIT_SECONDS].min)
          end
        end
      end

      def applied_hook(applied)
        resolved = []
        @applied_mutex.synchronize do
          # Wake the read barriers waiting on this index.
          @applied_condition.broadcast
          @applied_by_index ||= {}
          command = applied.respond_to?(:command) ? applied.command : nil
          snapshot = command.is_a?(Hash) && command["type"] == "snapshot"
          @applied_by_index[applied.index] = {term: applied.term, result: applied.result, snapshot: snapshot}
          @applied_by_index.shift while @applied_by_index.length > 8192
          @snapshot_applied_index = applied.index if snapshot
          future = @pending.delete([applied.index, applied.term])
          if future && snapshot
            # The waiter's entry is the last one the snapshot covers: it
            # committed, but this node never applied it individually and
            # has no result.  Answering with the snapshot's nil result made
            # the API return 500 ("consensus returned no result") for a
            # write that had succeeded.
            resolved << [future, nil, AppliedThroughSnapshot.new("entry #{applied.index} was applied through a snapshot; outcome unknown")]
          elsif future
            resolved << [future, applied.result, nil]
          end
          # Any waiter for the same index in a different term lost its entry.
          @pending.keys.select { |(index, term)| index == applied.index && term != applied.term }.each do |key|
            resolved << [@pending.delete(key), nil, ProposalDropped.new("entry #{applied.index} was overwritten by term #{applied.term}")]
          end
          @pending.keys.select { |(index, _term)| index < applied.index }.each do |key|
            error = if snapshot
                      # Covered by the snapshot: committed, outcome unknown here.
                      AppliedThroughSnapshot.new("entry #{key[0]} was applied through a snapshot at #{applied.index}; outcome unknown")
                    else
                      ProposalDropped.new("entry #{key[0]} was overwritten")
                    end
            resolved << [@pending.delete(key), nil, error]
          end
        end
        resolved.each { |future, value, error| future.resolve(value, error) }
        @applied_listeners.each do |listener|
          listener.call(applied)
        rescue StandardError => error
          @logger&.warn("consensus.applied_listener_error", error: "#{error.class}: #{error.message}")
        end
      end

      def role_hook(previous, current)
        # Every role change is an election somewhere, and elections are what
        # stall reads and forwarded proposals.  Without this line the only
        # evidence of an election storm was a term number that happened to
        # appear in some other message.
        @logger&.info("consensus.role_change", from: previous.to_s, to: current.to_s,
                                               term: @node.current_term, leader: @node.leader_id)
        return unless previous == :leader && current != :leader

        pending = @applied_mutex.synchronize { @pending.values.tap { @pending.clear } }
        pending.each do |future|
          future.resolve(nil, NotLeader.new("leadership lost before the entry was applied", leader_id: @node.leader_id))
        end
      end

      def forward(leader, command, request_id, timeout)
        future = Future.new(Mutex.new, ConditionVariable.new, nil, nil, false)
        @mutex.synchronize { @forward_waiters[request_id] = future }
        sent_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        @transport.send(Messages::ForwardProposal.new(cluster_id: @cluster_id, from: @id, to: leader, term: @node.current_term,
                                                      request_id: request_id, command: command))
        response = future.wait(timeout)
        return nil unless response.accepted

        record_phase("propose.forward.leader", Process.clock_gettime(Process::CLOCK_MONOTONIC) - sent_at)
        record_position(response.index, response.entry_term, leader)
        wait_for(response.index, response.entry_term, request_id, timeout)
      rescue Timeout
        nil
      rescue AppliedThroughSnapshot
        # Retrying would get the same position from the leader and the same
        # answer here: report the unknown outcome now.
        raise
      rescue ProposalDropped
        nil
      ensure
        @mutex.synchronize { @forward_waiters.delete(request_id) }
      end

      def resolve_forward(message)
        @forward_waiters[message.request_id]&.resolve(message)
      end

      def forward_read(leader, timeout)
        request_id = SecureRandom.uuid
        future = Future.new(Mutex.new, ConditionVariable.new, nil, nil, false)
        @mutex.synchronize { @read_waiters[request_id] = future }
        @transport.send(Messages::ReadIndex.new(cluster_id: @cluster_id, from: @id, to: leader, term: @node.current_term,
                                                request_id: request_id))
        response = future.wait(timeout)
        response.accepted ? response.read_index : nil
      rescue Timeout
        # Nothing else records a forwarded read the leader never answered, and
        # that is what a follower's stalled reads look like from here.
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        if @logger && (@last_forward_timeout_report.nil? || now - @last_forward_timeout_report >= 5.0)
          @last_forward_timeout_report = now
          @logger.warn("consensus.forward_read_timeout", leader: leader, timeout: timeout,
                                                         term: @node.current_term, pending: @read_waiters.length)
        end
        nil
      ensure
        @mutex.synchronize { @read_waiters.delete(request_id) }
      end

      def resolve_forward_read(message)
        @read_waiters[message.request_id]&.resolve(message)
      end
    end
  end
end
