# frozen_string_literal: true

require "securerandom"

require_relative "errors"
require_relative "canonical"
require_relative "log"
require_relative "membership"
require_relative "messages"
require_relative "snapshot"

module Rubernetes
  module Consensus
    # Raft consensus core (Ongaro & Ousterhout) with joint-consensus
    # membership changes, pipelined AppendEntries, batched proposals,
    # pre-vote, ReadIndex reads and snapshot transfer.
    #
    # The node is driven by two entry points: #tick(now) for timers and
    # #handle(message) for inbound RPCs.  Both append outbound messages to an
    # outbox that the caller drains and delivers through a transport.  Every
    # persistent state change (currentTerm, votedFor, log entries) is fsynced
    # through the Log/WAL before any response leaves the node (spec 5.3.2).
    # The core never touches sockets or threads, so a deterministic
    # simulation can drive it through partitions, reorderings and clock jumps.
    class Node
      Timing = Data.define(:election_timeout_min, :election_timeout_max, :heartbeat_interval,
                           :batch_max_entries, :batch_max_bytes, :batch_flush_timeout,
                           :snapshot_entries, :snapshot_wal_bytes, :snapshot_min_interval,
                           :max_inflight_appends, :snapshot_chunk_bytes) do
        # snapshot_entries follows etcd 3.6's --snapshot-count (10,000): every
        # entry since the last snapshot stays in memory, so 100k entries of
        # whole objects kept each replica's log alone at hundreds of MB.
        def self.default
          new(election_timeout_min: 0.150, election_timeout_max: 0.300, heartbeat_interval: 0.050,
              batch_max_entries: 256, batch_max_bytes: 1024 * 1024, batch_flush_timeout: 0.002,
              snapshot_entries: 10_000, snapshot_wal_bytes: 128 * 1024 * 1024, snapshot_min_interval: 30.0,
              max_inflight_appends: 8, snapshot_chunk_bytes: 1024 * 1024)
        end

        # Timing for real processes.  The default above is tuned for the
        # deterministic simulation, where a node never pauses.  An apiserver
        # replica is a Ruby process with a multi-GB heap: a GC pause or a
        # busy GVL easily outlasts a 150 ms election timeout.  With it, the
        # followers called an election every time the leader paused -- term
        # 124 two hours into a conformance round.  Every election stalled
        # reads and forwarded proposals, and the stalls compounded into
        # minutes during which nothing reconciled.  These are etcd's defaults
        # (--heartbeat-interval 100ms, --election-timeout 1000ms), with the
        # upper bound doubled for randomization.
        def self.production
          default.with(election_timeout_min: 1.0, election_timeout_max: 2.0, heartbeat_interval: 0.100)
        end

        def validate!
          if election_timeout_min + 1e-9 < heartbeat_interval * 3
            raise ArgumentError,
                  "election timeout must be at least 3x the heartbeat interval"
          end
          raise ArgumentError, "election timeout range is inverted" if election_timeout_max < election_timeout_min

          self
        end
      end

      Applied = Data.define(:index, :term, :command, :result)

      ROLES = %i[follower pre_candidate candidate leader].freeze
      NOOP_COMMAND = {"type" => "noop"}.freeze
      CONFIG_COMMAND_TYPE = "config"
      MAX_REMEMBERED_REQUESTS = 4096

      attr_reader :id, :cluster_id, :role, :leader_id, :commit_index, :last_applied, :log, :membership,
                  :timing, :snapshot_store, :state_machine, :pending_membership_change, :durable_index

      # When set, a server thread makes the leader's deferred batches
      # durable (#flush defer_sync: true, then Log#sync outside the node's
      # lock, then #confirm_local_sync!), so #tick and #handle do not sync
      # inline while this node leads.  Every role transition still syncs
      # inline: a follower must never vouch for an entry it has not made
      # durable.
      attr_accessor :external_sync

      def initialize(id:, cluster_id:, log:, snapshot_store:, state_machine:, initial_membership:,
                     clock:, random: Random.new, timing: Timing.default, wal_size: -> { 0 },
                     wall_clock: -> { Time.now.utc }, pre_vote: true, logger: nil, snapshot_writer: nil)
        @id = String(id)
        @cluster_id = String(cluster_id)
        @log = log
        @snapshot_store = snapshot_store
        @state_machine = state_machine
        @clock = clock
        @wall_clock = wall_clock
        @random = random
        @timing = timing.validate!
        @wal_size = wal_size
        @pre_vote = pre_vote
        @logger = logger
        @role = :follower
        @leader_id = nil
        @commit_index = 0
        @last_applied = 0
        @apply_mutex = Mutex.new
        @async_apply = nil
        @outbox = []
        @applied_listeners = []
        @role_listeners = []
        @votes = Set.new
        @pre_votes = Set.new
        @next_index = {}
        @match_index = {}
        @inflight = Hash.new { |hash, key| hash[key] = {} }
        @sent_epochs = Hash.new { |hash, key| hash[key] = {} }
        @send_epoch = 0
        @peer_ack_epoch = Hash.new(0)
        @peer_last_ack = {}
        @read_waiters = []
        @queued_reads = []
        @pending_batch = []
        @pending_batch_ids = Set.new
        @pending_batch_bytes = 0
        @batch_deadline = nil
        @remembered_proposals = {}
        @snapshot_transfer = {}
        @incoming_snapshot = nil
        @last_snapshot_at = nil
        # Encoding a snapshot takes seconds for a store of a few thousand
        # objects, and the node is driven under one lock with its heartbeats:
        # every 10,000 entries the leader went silent for the encode, the
        # followers' election timeout (1-2 s) fired, and the term changed --
        # four snapshots, four elections in one conformance round.  With a
        # snapshot_writer the node only captures the state document under the
        # lock; the writer encodes and persists it elsewhere and reports back
        # through #complete_snapshot! / #abandon_snapshot!.
        @snapshot_writer = snapshot_writer
        @snapshot_in_flight = nil
        @pending_membership_change = nil
        @snapshot_installs = 0
        @election_deadline = nil
        @heartbeat_deadline = nil
        @stopped = false
        @external_sync = false
        restore_from_snapshot!
        @durable_index = @log.last_index
        @membership = membership_from_log(initial_membership)
        @last_heartbeat_from_leader = nil
        reset_election_timer(@clock.call)
      end

      # ----------------------------------------------------------------- API

      def on_applied(&block)
        @applied_listeners << block
        self
      end

      def on_role_change(&block)
        @role_listeners << block
        self
      end

      def current_term
        @log.current_term
      end

      def leader?
        @role == :leader
      end

      def drain
        messages = @outbox
        @outbox = []
        messages
      end

      def peers
        @membership.peers_of(@id)
      end

      def voters
        @membership.voters.to_a.sort
      end

      def stopped?
        @stopped
      end

      # Whether this node can currently serve linearizable operations: a
      # leader that heard from a quorum within the election timeout, or a
      # follower that heard from its leader within the election timeout.
      # Candidates and isolated nodes are not ready.
      def quorum_available?(now = @clock.call)
        return false if @stopped

        window = @timing.election_timeout_max
        case @role
        when :leader
          acked = Set.new([@id])
          @peer_last_ack.each { |peer, at| acked << peer if now - at <= window }
          @membership.quorum?(acked)
        when :follower
          !@leader_id.nil? && !@last_heartbeat_from_leader.nil? && now - @last_heartbeat_from_leader <= window
        else
          false
        end
      end

      def stop
        @stopped = true
      end

      def last_index
        @log.last_index
      end

      # Position of an appended proposal in the current term, or nil.
      def proposal_position(request_id)
        position = @remembered_proposals[request_id]
        position && position[:term] == current_term ? position.dup : nil
      end

      # Position of an appended proposal in whatever term it was appended.
      # A proposer that left its entry in the batch, saw the batch flushed
      # and this node step down in between, must wait for that entry's fate
      # (applied, or overwritten by the new leader) rather than propose it
      # again: the re-proposal was appended a second time under the new
      # term and answered AlreadyExists for a create the first entry had
      # already made.
      def appended_position(request_id)
        position = @remembered_proposals[request_id]
        position&.dup
      end

      # Propose a client command.  Returns {index:, term:} once the entry has
      # been appended to the local log (after the batch flush).  The caller
      # learns the outcome through #on_applied.  A proposal with a request_id
      # that was already appended in this term returns the original position.
      def propose(command, request_id: SecureRandom.uuid, now: @clock.call)
        raise NotLeader.new(leader_id: @leader_id) unless leader?
        raise InvalidCommand, "command must be a Hash" unless command.is_a?(Hash)

        remembered = @remembered_proposals[request_id]
        return remembered if remembered && remembered[:term] == current_term
        # A retried proposal whose first copy is still waiting in the batch
        # (a follower re-forwards after 2 s; a duplicated frame) must not be
        # appended twice: the second entry applied as AlreadyExists and the
        # forwarder, whose remembered position was that second entry, was
        # told 409 for a create that had succeeded.
        return {index: nil, term: current_term, pending: true, request_id: request_id} if @pending_batch_ids.include?(request_id)

        # Canonical.encode is JSON of the normalised form; normalising once
        # serves both the size check and the batch.
        normalized = Canonical.normalize(command)
        encoded = JSON.generate(normalized)
        raise InvalidCommand, "command exceeds #{@timing.batch_max_bytes} bytes" if encoded.bytesize > @timing.batch_max_bytes

        @pending_batch << [request_id, normalized]
        @pending_batch_ids << request_id
        @pending_batch_bytes += encoded.bytesize
        @batch_deadline ||= now + @timing.batch_flush_timeout
        flush_batch(now) if @pending_batch.length >= @timing.batch_max_entries || @pending_batch_bytes >= @timing.batch_max_bytes
        position = @remembered_proposals[request_id]
        position || {index: nil, term: current_term, pending: true, request_id: request_id}
      end

      # Force the pending batch to disk and to the peers.
      #
      # +defer_sync: true+ appends the batch without its fsync and leaves the
      # AppendEntries in the outbox: the caller sends them (#drain) and then
      # calls #sync_local!, so the leader's own fsync overlaps the followers'
      # receive-append-fsync instead of preceding it -- what etcd does.  The
      # leader does not count itself toward the commit quorum until the sync;
      # every other entry point syncs first, so no response ever vouches for
      # an entry this node has not made durable.
      def flush(now = @clock.call, defer_sync: false)
        flush_batch(now, defer_sync: defer_sync)
      end

      def local_sync_pending?
        @local_sync_pending == true
      end

      # Makes a deferred batch durable and lets it count toward the commit.
      def sync_local!
        return false unless @local_sync_pending

        @log.sync
        @local_sync_pending = false
        @durable_index = @log.last_index
        @match_index[@id] = @log.last_index if leader?
        advance_commit_index
        true
      end

      # The server synced the WAL through +through+ outside the lock: count
      # that prefix toward the commit.  Entries appended since stay pending.
      def confirm_local_sync!(through)
        @durable_index = through if through > @durable_index
        @local_sync_pending = @log.last_index > @durable_index
        return unless leader?

        @match_index[@id] = @durable_index if @durable_index > @match_index.fetch(@id, 0)
        advance_commit_index
      end

      # Proposals appended but not yet flushed to the log and the peers.
      def batch_pending?
        !@pending_batch.empty?
      end

      # A pending batch whose flush timeout has passed.  The tick loop
      # flushes it, but under a write burst the tick thread waits its turn
      # for the lock behind the proposers and the inbound threads (measured:
      # a 1 ms tick ran every 4 ms typical, 25 ms worst), so whoever holds
      # the lock when the batch is due flushes it.
      def batch_due?(now = @clock.call)
        !@pending_batch.empty? && !@batch_deadline.nil? && now >= @batch_deadline
      end

      # Linearizable read: yields the read index to the block once a quorum
      # has confirmed this node is still leader.  Returns a waiter token; the
      # block is invoked from #handle when the confirmation arrives.
      # Reads are batched the way etcd batches them: a read arriving while a
      # heartbeat round for earlier reads is still unacknowledged waits for
      # the next round, which goes out as soon as that one settles, and every
      # read queued meanwhile shares it.  A heartbeat round per read meant
      # two messages sent and two acknowledgements handled, under the node's
      # lock, for every GET a follower forwarded -- most of the leader's
      # message traffic under a conformance run's informer load.
      def read_index(now: @clock.call, &block)
        raise ArgumentError, "read_index requires a block" unless block
        raise NotLeader.new(leader_id: @leader_id) unless leader?
        raise NotReady, "leader has not committed an entry in its term" unless leader_committed_current_term?

        waiter = {epoch: nil, index: @commit_index, block: block, registered_at: now}
        if peers.empty?
          waiter[:epoch] = @send_epoch
          @read_waiters << waiter
          settle_read_waiters
        elsif read_round_in_flight?
          @queued_reads << waiter
        else
          @queued_reads << waiter
          broadcast_heartbeat(now)
        end
        waiter
      end

      # A read round is in flight while some read waiter's epoch has not yet
      # been acknowledged by a quorum.
      def read_round_in_flight?
        @read_waiters.any? { |waiter| !epoch_quorum_acked?(waiter[:epoch]) }
      end

      def epoch_quorum_acked?(epoch)
        acked = Set.new([@id])
        @peer_ack_epoch.each { |peer, acked_epoch| acked << peer if acked_epoch >= epoch }
        @membership.quorum?(acked)
      end

      # Queued reads join the heartbeat round about to be sent to every peer:
      # its epoch is the next send epoch, and the read index is the commit
      # index now, which is at or past the one when each read arrived.
      def attach_queued_reads
        return if @queued_reads.empty?

        epoch = @send_epoch + 1
        @queued_reads.each do |waiter|
          waiter[:epoch] = epoch
          waiter[:index] = @commit_index if @commit_index > waiter[:index]
          @read_waiters << waiter
        end
        @queued_reads.clear
      end

      # Joint-consensus membership change.  The joint configuration is
      # appended immediately and used for quorum decisions from then on; the
      # final configuration is appended when the joint entry commits.
      def propose_membership(new_voters, learners: [], request_id: SecureRandom.uuid, now: @clock.call)
        raise NotLeader.new(leader_id: @leader_id) unless leader?
        raise MembershipError, "a membership change is already in progress" if @membership.joint? || @pending_membership_change
        raise NotReady, "leader has not committed an entry in its term" unless leader_committed_current_term?

        joint = @membership.enter_joint(new_voters, learners: learners)
        @pending_membership_change = {request_id: request_id, target: joint.leave_joint.to_h}
        propose({"type" => CONFIG_COMMAND_TYPE, "membership" => joint.to_h}, request_id: request_id, now: now)
        flush_batch(now)
        @remembered_proposals[request_id]
      end

      def transfer_leadership(target, now: @clock.call)
        raise NotLeader.new(leader_id: @leader_id) unless leader?
        raise MembershipError, "#{target} is not a voter" unless @membership.voter?(String(target))

        flush_batch(now)
        send(Messages::TimeoutNow.new(cluster_id: @cluster_id, from: @id, to: String(target), term: current_term,
                                      request_id: SecureRandom.uuid))
      end

      # Take a snapshot of the state machine, persist it and compact the log.
      # Everything a snapshot needs, captured at one applied index.  The
      # document is a Hash of frozen objects and fresh containers, so it is
      # safe to encode after the lock is released.
      SnapshotCapture = Struct.new(:document, :index, :term, :membership, :created_at, :started_at, keyword_init: true)

      def snapshot!(now: @clock.call, force: false)
        capture = capture_snapshot(now, force: force)
        return nil if capture.nil?

        state = @state_machine.class.encode_snapshot(capture.document)
        metadata = @snapshot_store.write(state: state, index: capture.index, term: capture.term,
                                         membership: capture.membership, created_at: capture.created_at)
        finish_snapshot(capture, metadata)
      end

      # nil when there is nothing new to snapshot or the interval has not
      # passed; otherwise the state to persist, taken under the caller's lock.
      # Taken under the apply lock as well: the applied index and the state
      # machine must not move while the capture reads them.
      def capture_snapshot(now = @clock.call, force: false)
        return nil if !force && @last_snapshot_at && now - @last_snapshot_at < @timing.snapshot_min_interval

        @apply_mutex.synchronize do
          next nil if @last_applied <= @log.snapshot_index

          term = @log.term_at(@last_applied)
          raise Error, "cannot determine term of applied index #{@last_applied}" if term.nil?

          SnapshotCapture.new(document: @state_machine.snapshot_document, index: @last_applied, term: term,
                              membership: membership_at(@last_applied).to_h,
                              created_at: @wall_clock.call.iso8601(6), started_at: now)
        end
      end

      # The writer persisted the capture: compact the log behind it.  A
      # snapshot that overtook this one (a forced snapshot for a lagging
      # follower, or a snapshot installed from a new leader) leaves nothing to
      # compact, and the entries the capture covers were all applied, hence
      # committed, so no later leader can have overwritten them.
      def complete_snapshot!(capture, metadata)
        @snapshot_in_flight = nil if @snapshot_in_flight.equal?(capture)
        return metadata if capture.index <= @log.snapshot_index

        finish_snapshot(capture, metadata)
      end

      # The writer failed: the next due tick tries again.
      def abandon_snapshot!(capture, error = nil)
        @snapshot_in_flight = nil if @snapshot_in_flight.equal?(capture)
        @logger&.warn("consensus.snapshot_abandoned", index: capture.index, error: error && "#{error.class}: #{error.message}")
        nil
      end

      def snapshot_in_flight?
        !@snapshot_in_flight.nil?
      end

      def status
        {
          "id" => @id,
          "cluster_id" => @cluster_id,
          "role" => @role.to_s,
          "term" => current_term,
          "voted_for" => @log.voted_for,
          "leader_id" => @leader_id,
          "commit_index" => @commit_index,
          "last_applied" => @last_applied,
          "last_index" => @log.last_index,
          "last_term" => @log.last_term,
          "snapshot_index" => @log.snapshot_index,
          "snapshot_term" => @log.snapshot_term,
          "membership" => @membership.to_h,
          "pending_membership_change" => @pending_membership_change&.fetch(:target),
          "match_index" => leader? ? @match_index.dup : nil,
          "next_index" => leader? ? @next_index.dup : nil,
          "snapshot_installs" => @snapshot_installs
        }
      end

      # ---------------------------------------------------------------- Timers

      def tick(now = @clock.call)
        return [] if @stopped

        sync_local! unless @external_sync && leader?

        case @role
        when :leader
          flush_batch(now) if !@external_sync && @batch_deadline && now >= @batch_deadline
          broadcast_heartbeat(now) if @heartbeat_deadline.nil? || now >= @heartbeat_deadline
          maybe_snapshot(now)
          report_stuck_read_waiters(now)
        else
          # A follower compacts on its own, like an etcd member: without
          # this only the leader ever snapshotted, and a follower's log and
          # WAL grew by every entry of a conformance round until it either
          # restarted or won an election.
          maybe_snapshot(now) if @role == :follower
          if @election_deadline && now >= @election_deadline && @membership.voter?(@id)
            if @pre_vote && @membership.voters.length > 1
              start_pre_vote(now)
            else
              start_election(now)
            end
          end
        end
        drain
      end

      # --------------------------------------------------------------- Inbound

      def handle(message, now = @clock.call)
        return [] if @stopped

        sync_local! unless @external_sync && leader?
        raise ProtocolError, "message for cluster #{message.cluster_id} received by #{@cluster_id}" unless message.cluster_id == @cluster_id
        raise ProtocolError, "message for node #{message.to} received by #{@id}" unless message.to == @id

        if message.term > current_term && !message.is_a?(Messages::PreVote) && !message.is_a?(Messages::PreVoteResponse)
          become_follower(message.term, leader: nil, now: now)
        end

        case message
        when Messages::PreVote then handle_pre_vote(message, now)
        when Messages::PreVoteResponse then handle_pre_vote_response(message, now)
        when Messages::RequestVote then handle_request_vote(message, now)
        when Messages::RequestVoteResponse then handle_request_vote_response(message, now)
        when Messages::AppendEntries then handle_append_entries(message, now)
        when Messages::AppendEntriesResponse then handle_append_entries_response(message, now)
        when Messages::InstallSnapshot then handle_install_snapshot(message, now)
        when Messages::InstallSnapshotResponse then handle_install_snapshot_response(message, now)
        when Messages::ForwardProposal then handle_forward_proposal(message, now)
        when Messages::ReadIndex then handle_read_index(message, now)
        when Messages::TimeoutNow then handle_timeout_now(message, now)
        else
          raise ProtocolError, "unhandled message #{message.type}"
        end
        drain
      end

      private

      # ---------------------------------------------------------- Role changes

      def become_follower(term, leader:, now:)
        previous = @role
        # A deferred batch is made durable before this node can vouch for
        # any entry as a follower.
        sync_local!
        @log.save_hard_state(term: term, voted_for: nil) if term > current_term
        @role = :follower
        @leader_id = leader
        @votes.clear
        @pre_votes.clear
        clear_leader_state(reason: "stepped down") if previous == :leader
        reset_election_timer(now)
        notify_role(previous) if previous != :follower
      end

      def start_pre_vote(now)
        previous = @role
        @role = :pre_candidate
        @pre_votes = Set.new([@id])
        reset_election_timer(now)
        notify_role(previous) if previous != :pre_candidate
        if @membership.quorum?(@pre_votes)
          start_election(now)
          return
        end
        voters_except_self.each do |peer|
          send(Messages::PreVote.new(cluster_id: @cluster_id, from: @id, to: peer, term: current_term + 1,
                                     request_id: SecureRandom.uuid, last_log_index: @log.last_index, last_log_term: @log.last_term))
        end
      end

      def start_election(now)
        previous = @role
        sync_local!
        term = current_term + 1
        @log.save_hard_state(term: term, voted_for: @id)
        @role = :candidate
        @leader_id = nil
        @votes = Set.new([@id])
        @pre_votes.clear
        reset_election_timer(now)
        notify_role(previous) if previous != :candidate
        if @membership.quorum?(@votes)
          become_leader(now)
          return
        end
        voters_except_self.each do |peer|
          send(Messages::RequestVote.new(cluster_id: @cluster_id, from: @id, to: peer, term: term, request_id: SecureRandom.uuid,
                                         last_log_index: @log.last_index, last_log_term: @log.last_term))
        end
      end

      def become_leader(now)
        previous = @role
        sync_local!
        @role = :leader
        @leader_id = @id
        @votes.clear
        @next_index = {}
        @match_index = {@id => @log.last_index}
        @inflight.clear
        @sent_epochs.clear
        @peer_ack_epoch.clear
        @peer_last_ack.clear
        @read_waiters.clear
        @queued_reads.clear
        @pending_batch.clear
        @pending_batch_ids.clear
        @pending_batch_bytes = 0
        @batch_deadline = nil
        # Remembered positions are kept across terms: #proposal_position
        # filters by term, and #appended_position lets a proposer whose
        # entry was appended in an earlier term wait for it.
        @snapshot_transfer.clear
        peers.each do |peer|
          @next_index[peer] = @log.last_index + 1
          @match_index[peer] = 0
        end
        @election_deadline = nil
        notify_role(previous)
        # A leader must commit an entry from its own term before it can
        # safely advance commitIndex or serve reads (section 5.4.2).
        append_local([[SecureRandom.uuid, NOOP_COMMAND.dup]])
        # A partially completed membership change carried in the log must be
        # finished by the new leader.
        @pending_membership_change = {request_id: SecureRandom.uuid, target: @membership.leave_joint.to_h} if @membership.joint?
        advance_commit_index
        broadcast_append(now)
        @heartbeat_deadline = now + @timing.heartbeat_interval
      end

      def clear_leader_state(reason:)
        Array(@forwarded_pending).each { |_request_id, response| send(response.call(accepted: false)) }
        @forwarded_pending = []
        @pending_batch.clear
        @pending_batch_ids.clear
        @pending_batch_bytes = 0
        @batch_deadline = nil
        (@read_waiters + @queued_reads).each do |waiter|
          safe_call(waiter[:block], nil, NotLeader.new("leadership lost: #{reason}", leader_id: @leader_id))
        end
        @read_waiters.clear
        @queued_reads.clear
        @inflight.clear
        @sent_epochs.clear
        @snapshot_transfer.clear
        @heartbeat_deadline = nil
        @pending_membership_change = nil
      end

      def notify_role(previous)
        @role_listeners.each { |listener| safe_call(listener, previous, @role) }
      end

      # ----------------------------------------------------------- Elections

      def handle_pre_vote(message, now)
        # A pre-vote is granted when we would grant a real vote for that term
        # and we have not heard from a live leader recently.
        granted = message.term > current_term &&
                  @log.up_to_date?(message.last_log_index, message.last_log_term) &&
                  !recent_leader_contact?(now)
        send(Messages::PreVoteResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                           request_id: message.request_id, granted: granted))
      end

      def handle_pre_vote_response(message, now)
        return unless @role == :pre_candidate
        return unless message.granted

        @pre_votes << message.from
        start_election(now) if @membership.quorum?(@pre_votes)
      end

      def handle_request_vote(message, now)
        granted = false
        if message.term == current_term && (@log.voted_for.nil? || @log.voted_for == message.from) &&
           @log.up_to_date?(message.last_log_index, message.last_log_term) && @role != :leader
          # Persist the vote before answering (spec 5.3.2).
          @log.save_hard_state(term: current_term, voted_for: message.from)
          granted = true
          reset_election_timer(now)
        end
        send(Messages::RequestVoteResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                               request_id: message.request_id, granted: granted))
      end

      def handle_request_vote_response(message, now)
        return unless @role == :candidate && message.term == current_term
        return unless message.granted && @membership.voter?(message.from)

        @votes << message.from
        become_leader(now) if @membership.quorum?(@votes)
      end

      def handle_timeout_now(message, now)
        return unless message.term == current_term && @membership.voter?(@id)

        start_election(now)
      end

      # ---------------------------------------------------------- Replication

      def handle_append_entries(message, now)
        if message.term < current_term
          send(append_response(message, success: false, match_index: 0, conflict_index: 0, conflict_term: 0))
          return
        end
        become_follower(message.term, leader: message.from, now: now) unless @role == :follower && @leader_id == message.from
        @leader_id = message.from
        @last_heartbeat_from_leader = now
        reset_election_timer(now)

        unless @log.matches?(message.prev_log_index, message.prev_log_term)
          conflict_index, conflict_term = conflict_hint(message.prev_log_index)
          send(append_response(message, success: false, match_index: 0, conflict_index: conflict_index, conflict_term: conflict_term))
          return
        end

        new_entries = message.entries.map { |entry| Log::Entry.from_h(entry) }
        first_conflict = nil
        new_entries.each do |entry|
          next if entry.index <= @log.snapshot_index

          existing = @log.term_at(entry.index)
          # Past the end of our log every remaining entry is a plain append.
          # Counting "no entry here" as a term conflict sent EVERY append down
          # the truncation path, whose membership refresh rescans the whole
          # log -- a quarter of a follower apiserver's CPU once the log had
          # grown over a conformance round.
          break if existing.nil?
          next if existing == entry.term

          first_conflict = entry
          break
        end
        if first_conflict
          raise Error, "leader attempted to overwrite committed entry #{first_conflict.index}" if first_conflict.index <= @commit_index

          @log.truncate_from(first_conflict.index) if first_conflict.index <= @log.last_index
          to_append = new_entries.select { |entry| entry.index >= first_conflict.index }
          @log.append(to_append)
          refresh_membership
        else
          to_append = new_entries.select { |entry| entry.index > @log.last_index }
          unless to_append.empty?
            @log.append(to_append)
            refresh_membership(to_append)
          end
        end

        last_new = message.prev_log_index + new_entries.length
        if message.leader_commit > @commit_index
          @commit_index = [message.leader_commit, [last_new, @log.last_index].min].min
          apply_committed
        end
        send(append_response(message, success: true, match_index: last_new, conflict_index: 0, conflict_term: 0))
      end

      def conflict_hint(prev_index)
        if prev_index > @log.last_index
          [@log.last_index + 1, 0]
        else
          term = @log.term_at(prev_index)
          return [@log.snapshot_index + 1, 0] if term.nil?

          first = prev_index
          first -= 1 while first > @log.first_index && @log.term_at(first - 1) == term
          [first, term]
        end
      end

      def append_response(message, success:, match_index:, conflict_index:, conflict_term:)
        Messages::AppendEntriesResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                            request_id: message.request_id, success: success, match_index: match_index,
                                            conflict_index: conflict_index, conflict_term: conflict_term)
      end

      def handle_append_entries_response(message, now)
        return unless leader? && message.term == current_term

        peer = message.from
        inflight = @inflight[peer].delete(message.request_id)
        # A response proves the follower accepted this leader when the request
        # was sent, however late it arrives.  The in-flight record may already
        # be gone -- expire_inflight drops records after election_timeout_min so
        # pipelining cannot wedge -- so the epoch is kept apart from it.
        # Counting only responses whose record survived meant that once every
        # follower answered in more than 150 ms no heartbeat ever proved
        # leadership, and every linearizable read hung while writes committed.
        epoch = @sent_epochs[peer].delete(message.request_id)
        epoch ||= inflight[:epoch] if inflight
        @peer_ack_epoch[peer] = [@peer_ack_epoch[peer], epoch].max if epoch
        @peer_last_ack[peer] = now
        if message.success
          @match_index[peer] = [@match_index.fetch(peer, 0), message.match_index].max
          @next_index[peer] = [@next_index.fetch(peer, 1), message.match_index + 1].max
          @inflight[peer].delete_if { |_id, record| record[:last_index] <= message.match_index }
          advance_commit_index
          settle_read_waiters
        else
          # Fast log backtracking using the follower's conflict hint.
          @next_index[peer] = if message.conflict_term.positive?
                                leader_last_of_term = last_index_of_term(message.conflict_term)
                                leader_last_of_term ? leader_last_of_term + 1 : [message.conflict_index, 1].max
                              else
                                [message.conflict_index, 1].max
                              end
          @inflight[peer].clear
        end
        replicate_to(peer, now)
      end

      def last_index_of_term(term)
        index = @log.last_index
        while index > @log.snapshot_index
          entry_term = @log.term_at(index)
          return index if entry_term == term
          break if entry_term < term

          index -= 1
        end
        nil
      end

      def advance_commit_index
        return unless leader?

        @match_index[@id] = @log.last_index unless @local_sync_pending
        candidate = @membership.committed_index(@match_index)
        return if candidate <= @commit_index
        # Only entries from the leader's current term are committed by
        # counting replicas (section 5.4.2).
        return unless @log.term_at(candidate) == current_term

        @commit_index = candidate
        apply_committed
        settle_read_waiters
        # Followers learn the new commit index immediately instead of waiting
        # for the next heartbeat; the empty AppendEntries also doubles as a
        # leadership confirmation for pending ReadIndex waiters.
        peers.each { |peer| send_append(peer, heartbeat: true, now: @clock.call) unless @snapshot_transfer.key?(peer) }
      end

      # Applying a committed entry means running it through the state machine
      # -- a store write, with its copies and its watcher fan-out -- and that
      # was done while holding the lock that every proposal, every read
      # barrier and every inbound message also needs.  One AppendEntries
      # carrying seven entries held it for about seven milliseconds, which is
      # where a write burst's latency went.  A server that drives an apply
      # loop (#async_apply=) instead has this hand the work to that loop;
      # without one the entries are applied inline exactly as before, which
      # is what the deterministic simulation drives.
      def apply_committed
        return signal_apply if @async_apply

        apply_up_to_commit_index { |entry| finish_membership_change(entry) if config_entry?(entry) }
      end

      attr_accessor :async_apply

      # Installed by the server before it starts its apply loop.  The
      # callback is invoked while this node's lock is held, so it must do no
      # more than wake the loop.

      def apply_pending?
        @apply_mutex.synchronize { @last_applied < @commit_index }
      end

      # Runs the state machine outside this node's lock, under the apply
      # lock alone.  Configuration entries are handed back rather than acted
      # on here: appending the next configuration and broadcasting it needs
      # the node's lock, which this must never take while applying.
      def apply_pending!
        configuration_entries = []
        applied = @apply_mutex.synchronize do
          # Only configuration entries go back to the server: handing every
          # entry over made #after_async_apply read "membership" out of a
          # create on the leader, raise KeyError, and the apply loop's error
          # path slept 10 ms -- after every single apply.  That is why the
          # async apply loop measured 10 ms per lone proposal and stayed off.
          apply_up_to_commit_index { |entry| configuration_entries << entry if config_entry?(entry) }
        end
        [applied, configuration_entries]
      end

      # Called by the server under its lock once #apply_pending! has run.
      def after_async_apply(configuration_entries)
        configuration_entries.each { |entry| finish_membership_change(entry) }
        settle_read_waiters
      end

      # Serialises with the apply loop: a snapshot install or capture must not
      # race entries being applied.  Callers hold the node's lock, and the
      # apply loop never takes that lock while holding this one, so the two
      # orders never meet.
      def with_apply_lock(&)
        @apply_mutex.synchronize(&)
      end

      def signal_apply
        @async_apply.call if @async_apply
        nil
      end

      # Applies every committed entry that has not been applied yet, yielding
      # each configuration entry.  Returns whether anything was applied.
      def apply_up_to_commit_index
        applied_any = false
        while @last_applied < @commit_index
          index = @last_applied + 1
          entry = @log.entry_at(index)
          raise Error, "committed entry #{index} is missing from the log" if entry.nil?

          result = apply_entry(entry)
          @last_applied = index
          applied_any = true
          applied = Applied.new(index: entry.index, term: entry.term, command: entry.command, result: result)
          @applied_listeners.each { |listener| safe_call(listener, applied) }
          yield entry if block_given?
        end
        applied_any
      end

      # The server drives the apply loop from outside, so these are the one
      # part of the apply path it may call.
      public :async_apply, :async_apply=, :apply_pending?, :apply_pending!, :after_async_apply, :with_apply_lock

      def apply_entry(entry)
        command = entry.command
        return nil if command.nil? || command["type"] == "noop" || command["type"] == CONFIG_COMMAND_TYPE

        @state_machine.apply(entry.index, command)
      end

      def config_entry?(entry)
        entry.command.is_a?(Hash) && entry.command["type"] == CONFIG_COMMAND_TYPE
      end

      def finish_membership_change(entry)
        return unless leader?

        committed = Membership.from_h(entry.command.fetch("membership"))
        if committed.joint?
          # Joint entry committed: append the final configuration.
          final = committed.leave_joint
          @pending_membership_change ||= {request_id: SecureRandom.uuid, target: final.to_h}
          append_local([[@pending_membership_change[:request_id] + ":final", {"type" => CONFIG_COMMAND_TYPE, "membership" => final.to_h}]])
          broadcast_append(@clock.call)
        else
          @pending_membership_change = nil
          # A leader removed by the new configuration steps down once the
          # final configuration is committed (Raft section 6).
          unless committed.voter?(@id)
            previous = @role
            sync_local!
            @role = :follower
            @leader_id = nil
            clear_leader_state(reason: "removed from configuration")
            reset_election_timer(@clock.call)
            notify_role(previous)
          end
        end
      end

      # Append entries to the local log as leader (the leader's own WAL fsync
      # counts as its replication acknowledgement).
      def append_local(batch, sync: true)
        start = @log.last_index + 1
        term = current_term
        entries = batch.each_with_index.map do |(_request_id, command), offset|
          Log::Entry.new(index: start + offset, term: term, command: command)
        end
        @log.append(entries, sync: sync)
        batch.each_with_index do |(request_id, _command), offset|
          remember_proposal(request_id, index: start + offset, term: term)
        end
        if sync
          unless @local_sync_pending
            @durable_index = @log.last_index
            @match_index[@id] = @log.last_index
          end
        else
          @local_sync_pending = true
        end
        refresh_membership(entries)
        entries
      end

      def remember_proposal(request_id, index:, term:)
        @remembered_proposals[request_id] = {index: index, term: term}
        @remembered_proposals.shift while @remembered_proposals.length > MAX_REMEMBERED_REQUESTS
      end

      def flush_batch(now, defer_sync: false)
        return unless leader?
        return if @pending_batch.empty?

        sync_local! unless defer_sync

        batch = @pending_batch
        @pending_batch = []
        @pending_batch_ids = Set.new
        @pending_batch_bytes = 0
        @batch_deadline = nil
        append_local(batch, sync: !defer_sync)
        answer_forwarded_proposals
        advance_commit_index
        broadcast_append(now)
      end

      def broadcast_append(now)
        peers.each { |peer| replicate_to(peer, now) }
        @heartbeat_deadline = now + @timing.heartbeat_interval
      end

      def broadcast_heartbeat(now)
        attach_queued_reads
        peers.each do |peer|
          expire_inflight(peer, now)
          transfer = @snapshot_transfer[peer]
          if transfer && transfer[:request_id]
            # A snapshot chunk whose response was lost is retransmitted at
            # heartbeat cadence; chunks are offset-addressed and idempotent.
            if now - transfer[:sent_at] >= @timing.heartbeat_interval * 2
              transfer[:request_id] = nil
              send_snapshot(peer, now)
            end
            next
          end
          send_append(peer, heartbeat: true, now: now)
          replicate_to(peer, now)
        end
        @heartbeat_deadline = now + @timing.heartbeat_interval
      end

      # Bounded per peer: a request whose response never comes is forgotten
      # once this many newer ones have been sent.
      MAX_REMEMBERED_SENT_EPOCHS = 1024

      def remember_sent_epoch(peer, request_id, epoch)
        sent = @sent_epochs[peer]
        sent[request_id] = epoch
        sent.shift while sent.length > MAX_REMEMBERED_SENT_EPOCHS
      end

      # Outstanding AppendEntries older than the minimum election timeout are
      # considered lost so pipelining can never wedge on a dropped response.
      def expire_inflight(peer, now)
        stale = @inflight[peer].select { |_id, record| now - record[:sent_at] >= @timing.election_timeout_min }
        return if stale.empty?

        stale.each_key { |request_id| @inflight[peer].delete(request_id) }
        @next_index[peer] = [@match_index.fetch(peer, 0) + 1, 1].max
      end

      # Pipelined replication: keep up to max_inflight_appends outstanding
      # AppendEntries per follower, each covering the next slice of the log.
      def replicate_to(peer, now)
        return unless leader?

        next_index = @next_index.fetch(peer) { @next_index[peer] = @log.last_index + 1 }
        if next_index <= @log.snapshot_index
          send_snapshot(peer, now)
          return
        end
        send_append(peer, heartbeat: false, now: now) while @inflight[peer].length < @timing.max_inflight_appends && @next_index.fetch(peer) <= @log.last_index
      end

      def send_append(peer, heartbeat:, now:)
        next_index = @next_index.fetch(peer) { @next_index[peer] = @log.last_index + 1 }
        if next_index <= @log.snapshot_index
          send_snapshot(peer, now)
          return
        end
        prev_index = next_index - 1
        prev_term = @log.term_at(prev_index)
        if prev_term.nil?
          send_snapshot(peer, now)
          return
        end
        entries = heartbeat ? [] : @log.entries_from(next_index, max_count: @timing.batch_max_entries, max_bytes: @timing.batch_max_bytes)
        request_id = SecureRandom.uuid
        @send_epoch += 1
        @inflight[peer][request_id] = {epoch: @send_epoch, last_index: prev_index + entries.length, sent_at: now}
        remember_sent_epoch(peer, request_id, @send_epoch)
        @next_index[peer] = prev_index + entries.length + 1 unless entries.empty?
        send(Messages::AppendEntries.new(cluster_id: @cluster_id, from: @id, to: peer, term: current_term, request_id: request_id,
                                         prev_log_index: prev_index, prev_log_term: prev_term, leader_commit: @commit_index,
                                         entries: entries.map(&:to_h)))
      end

      def send_snapshot(peer, now = @clock.call)
        transfer = @snapshot_transfer[peer]
        if transfer.nil?
          snapshot, _rejected = @snapshot_store.latest(strict: true)
          if snapshot.nil? || snapshot.index < @log.snapshot_index
            # The log was compacted but no matching snapshot exists yet; take
            # one from the current applied state.
            snapshot!(force: true)
            snapshot, _rejected = @snapshot_store.latest(strict: true)
            raise Error, "no snapshot available for follower #{peer}" if snapshot.nil?
          end
          bytes = @snapshot_store.read_bytes(snapshot.path)
          transfer = {bytes: bytes, offset: 0, index: snapshot.index, term: snapshot.term, request_id: nil}
          @snapshot_transfer[peer] = transfer
        end
        return if transfer[:request_id]

        chunk = transfer[:bytes].byteslice(transfer[:offset], @timing.snapshot_chunk_bytes) || "".b
        done = transfer[:offset] + chunk.bytesize >= transfer[:bytes].bytesize
        request_id = SecureRandom.uuid
        transfer[:request_id] = request_id
        transfer[:sent_at] = now
        send(Messages::InstallSnapshot.new(cluster_id: @cluster_id, from: @id, to: peer, term: current_term, request_id: request_id,
                                           last_included_index: transfer[:index], last_included_term: transfer[:term],
                                           offset: transfer[:offset], data: [chunk].pack("m0"), done: done,
                                           total_bytes: transfer[:bytes].bytesize))
      end

      def handle_install_snapshot(message, now)
        if message.term < current_term
          send(Messages::InstallSnapshotResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                                     request_id: message.request_id, success: false, last_included_index: @log.snapshot_index))
          return
        end
        become_follower(message.term, leader: message.from, now: now) unless @role == :follower && @leader_id == message.from
        @leader_id = message.from
        @last_heartbeat_from_leader = now
        reset_election_timer(now)

        chunk = message.data.unpack1("m0")
        if message.offset.zero?
          @incoming_snapshot = {index: message.last_included_index, term: message.last_included_term, buffer: "".b,
                                total: message.total_bytes}
        end
        incoming = @incoming_snapshot
        success = false
        if incoming && incoming[:index] == message.last_included_index && incoming[:buffer].bytesize == message.offset &&
           incoming[:total] == message.total_bytes && incoming[:buffer].bytesize + chunk.bytesize <= SnapshotStore::MAX_SNAPSHOT_BYTES
          incoming[:buffer] << chunk
          success = true
          if message.done
            @incoming_snapshot = nil
            # Raft figure 13 / etcd raft restore(): a snapshot this follower
            # has already passed is ignored, not refused, and the reply still
            # goes out so the leader stops streaming it and returns to
            # AppendEntries.  Comparing against our own snapshot index alone
            # missed a follower that had applied far past its last snapshot
            # through the log: install_snapshot_bytes raised, the inbound
            # thread died without replying, and the leader re-sent the same
            # snapshot for ever -- 3561 times in one conformance round, with
            # that apiserver lagging and answering "503 read index timed out".
            if message.last_included_index > [@log.snapshot_index, @last_applied].max
              begin
                install_snapshot_bytes(incoming[:buffer], expected_index: message.last_included_index,
                                                          expected_term: message.last_included_term)
              rescue Error => error
                # A snapshot that cannot be installed is answered, never
                # silently dropped with the connection.
                success = false
                @logger&.warn("raft.snapshot_install_refused", index: message.last_included_index, error: error.message)
              end
            end
          end
        else
          @incoming_snapshot = nil
        end
        send(Messages::InstallSnapshotResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                                   request_id: message.request_id, success: success, last_included_index: @log.snapshot_index))
      end

      # Replacing the state machine wholesale must not race the apply loop,
      # so the switch happens under the apply lock.  Callers hold the node's
      # lock; the apply loop never takes it while applying, so the two
      # orders never meet.
      def install_snapshot_bytes(bytes, expected_index:, expected_term:)
        snapshot = SnapshotStore.decode(bytes)
        unless snapshot.index == expected_index && snapshot.term == expected_term
          raise SnapshotCorruption,
                "snapshot index/term differ from the leader's announcement"
        end
        raise Error, "refusing to install a snapshot below committed and applied state" if snapshot.index < @last_applied

        # Verify, persist, then switch state: a corrupt snapshot never
        # replaces the running state machine.
        @snapshot_store.install(bytes)
        @apply_mutex.synchronize do
          if !(@log.term_at(snapshot.index) == snapshot.term && snapshot.index <= @log.last_index) && (@log.last_index > @log.snapshot_index)
            @log.truncate_from(@log.snapshot_index + 1)
          end
          @log.compact_to(index: snapshot.index, term: snapshot.term)
          @log.rotate! if @log.respond_to?(:rotate!)
          @state_machine.restore(snapshot.state)
          @commit_index = [@commit_index, snapshot.index].max
          @last_applied = snapshot.index
        end
        @snapshot_installs += 1
        @membership = membership_from_log(Membership.from_h(snapshot.membership))
        @snapshot_store.prune(keep: 2)
        @applied_listeners.each do |listener|
          safe_call(listener, Applied.new(index: snapshot.index, term: snapshot.term, command: {"type" => "snapshot"}, result: nil))
        end
      end

      def handle_install_snapshot_response(message, now)
        return unless leader? && message.term == current_term

        peer = message.from
        transfer = @snapshot_transfer[peer]
        return unless transfer && transfer[:request_id] == message.request_id

        transfer[:request_id] = nil
        if message.success
          sent_bytes = [transfer[:offset] + @timing.snapshot_chunk_bytes, transfer[:bytes].bytesize].min
          transfer[:offset] = sent_bytes
          if transfer[:offset] >= transfer[:bytes].bytesize
            @snapshot_transfer.delete(peer)
            @match_index[peer] = [@match_index.fetch(peer, 0), transfer[:index]].max
            @next_index[peer] = transfer[:index] + 1
            replicate_to(peer, now)
          else
            send_snapshot(peer, now)
          end
        else
          @snapshot_transfer.delete(peer)
          @next_index[peer] = message.last_included_index + 1
          replicate_to(peer, now)
        end
      end

      # ------------------------------------------------------ Forwarded ops

      def handle_forward_proposal(message, _now)
        response = lambda do |accepted:, index: 0, entry_term: 0|
          Messages::ForwardProposalResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                                request_id: message.request_id, accepted: accepted, index: index,
                                                entry_term: entry_term, leader_id: @leader_id || "")
        end
        unless leader?
          send(response.call(accepted: false))
          return
        end
        begin
          position = propose(message.command, request_id: message.request_id)
          if position[:pending]
            # Forwarded proposals take part in group commit too: the answer
            # waits for the batch, which the tick loop or a local proposer
            # flushes within a millisecond or two, instead of forcing a WAL
            # fsync per forwarded message.
            (@forwarded_pending ||= []) << [message.request_id, response]
            return
          end
          send(response.call(accepted: true, index: position[:index], entry_term: position[:term]))
        rescue InvalidCommand
          send(response.call(accepted: false))
        end
      end

      # Answer the forwarded proposals whose batch has just been appended.
      def answer_forwarded_proposals
        return if @forwarded_pending.nil? || @forwarded_pending.empty?

        pending = @forwarded_pending
        @forwarded_pending = []
        pending.each do |request_id, response|
          position = @remembered_proposals[request_id]
          if position && position[:term] == current_term
            send(response.call(accepted: true, index: position[:index], entry_term: position[:term]))
          else
            send(response.call(accepted: false))
          end
        end
      end

      def handle_read_index(message, now)
        unless leader?
          send(Messages::ReadIndexResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                               request_id: message.request_id, read_index: 0, accepted: false))
          return
        end
        begin
          read_index(now: now) do |index, error|
            send(Messages::ReadIndexResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                                 request_id: message.request_id, read_index: index || 0, accepted: error.nil?))
          end
        rescue NotReady
          send(Messages::ReadIndexResponse.new(cluster_id: @cluster_id, from: @id, to: message.from, term: current_term,
                                               request_id: message.request_id, read_index: 0, accepted: false))
        end
      end

      # A linearizable read that has not settled within a second is the
      # symptom behind multi-minute control-plane stalls, and nothing else
      # records WHY it is waiting.  Report what settling depends on: which
      # peers have acknowledged the read's epoch, whether this leader has
      # applied up to the read index, and which peers are mid snapshot or
      # carrying in-flight appends.  At most once every five seconds.
      STUCK_READ_SECONDS = 1.0
      STUCK_READ_REPORT_INTERVAL = 5.0

      def report_stuck_read_waiters(now)
        return if @logger.nil? || (@read_waiters.empty? && @queued_reads.empty?)
        return if @last_stuck_read_report && now - @last_stuck_read_report < STUCK_READ_REPORT_INTERVAL

        oldest = (@read_waiters + @queued_reads).min_by { |waiter| waiter[:registered_at] || now }
        age = now - (oldest[:registered_at] || now)
        return if age < STUCK_READ_SECONDS

        @last_stuck_read_report = now
        @logger.warn("consensus.read_index_stuck",
                     waiters: @read_waiters.length, queued: @queued_reads.length, oldest_seconds: age.round(3),
                     waiter_epoch: oldest[:epoch], send_epoch: @send_epoch,
                     waiter_index: oldest[:index], last_applied: @last_applied, commit_index: @commit_index,
                     peer_ack_epoch: peers.to_h { |peer| [peer, @peer_ack_epoch[peer]] },
                     peer_last_ack_age: peers.to_h { |peer| [peer, @peer_last_ack[peer] ? (now - @peer_last_ack[peer]).round(3) : nil] },
                     inflight: peers.to_h { |peer| [peer, @inflight[peer].length] },
                     snapshot_transfer: @snapshot_transfer.keys)
      rescue StandardError
        nil
      end

      def settle_read_waiters
        unless @read_waiters.empty?
          @read_waiters.reject! do |waiter|
            next false unless epoch_quorum_acked?(waiter[:epoch])
            next false if @last_applied < waiter[:index]

            safe_call(waiter[:block], waiter[:index], nil)
            true
          end
        end
        # The round settled (or nothing is in flight): reads that queued up
        # meanwhile get their own round now.
        broadcast_heartbeat(@clock.call) if leader? && !@queued_reads.empty? && !read_round_in_flight?
      end

      def leader_committed_current_term?
        @commit_index.positive? && @log.term_at(@commit_index) == current_term
      end

      # ------------------------------------------------------------ Helpers

      def maybe_snapshot(now)
        return if @snapshot_in_flight
        return if @last_applied - @log.snapshot_index < @timing.snapshot_entries && @wal_size.call < @timing.snapshot_wal_bytes

        return snapshot!(now: now) if @snapshot_writer.nil?

        capture = capture_snapshot(now)
        return if capture.nil?

        @snapshot_in_flight = capture
        begin
          @snapshot_writer.call(capture)
        rescue StandardError
          @snapshot_in_flight = nil
          raise
        end
      end

      def finish_snapshot(capture, metadata)
        @log.compact_to(index: capture.index, term: capture.term)
        @log.rotate! if @log.respond_to?(:rotate!)
        @snapshot_store.prune(keep: 2)
        @last_snapshot_at = capture.started_at
        metadata
      end

      def restore_from_snapshot!
        snapshot, _rejected = @snapshot_store.latest(strict: true)
        return if snapshot.nil?

        @log.compact_to(index: snapshot.index, term: snapshot.term) if snapshot.index > @log.snapshot_index
        @state_machine.restore(snapshot.state)
        @commit_index = snapshot.index
        @last_applied = snapshot.index
        @restored_membership = Membership.from_h(snapshot.membership)
      end

      def membership_from_log(fallback)
        base = @restored_membership || fallback
        latest = base
        @log.entries.each do |entry|
          latest = Membership.from_h(entry.command.fetch("membership")) if config_entry?(entry)
        end
        latest
      end

      def membership_at(index)
        latest = @restored_membership || @membership
        @log.entries.each do |entry|
          break if entry.index > index

          latest = Membership.from_h(entry.command.fetch("membership")) if config_entry?(entry)
        end
        latest
      end

      # Membership changes only when a configuration entry is appended, so an
      # append is asked to check just the entries it added.  Rescanning the
      # whole log instead -- which also duplicated the entries array under the
      # log's mutex -- cost O(log length) on every append, and the log keeps
      # ten thousand entries: it was the apiserver's largest single CPU frame
      # under a write burst.  A truncation can remove a configuration entry,
      # so that path still rescans (it happens once per conflicting append).
      def refresh_membership(appended = nil)
        previous = @membership
        @membership = if appended.nil?
                        membership_from_log(@restored_membership || previous)
                      else
                        latest = previous
                        appended.each do |entry|
                          latest = Membership.from_h(entry.command.fetch("membership")) if config_entry?(entry)
                        end
                        latest
                      end
        return if previous == @membership
        return unless leader?

        @membership.peers_of(@id).each do |peer|
          @next_index[peer] ||= @log.last_index + 1
          @match_index[peer] ||= 0
        end
      end

      def voters_except_self
        @membership.voters.to_a.sort - [@id]
      end

      def recent_leader_contact?(now)
        @leader_id && @last_heartbeat_from_leader && now - @last_heartbeat_from_leader < @timing.election_timeout_min
      end

      def reset_election_timer(now)
        span = @timing.election_timeout_max - @timing.election_timeout_min
        @election_deadline = now + @timing.election_timeout_min + (@random.rand * span)
      end

      def send(message)
        @outbox << message
      end

      def safe_call(callable, *)
        callable.call(*)
      rescue StandardError => error
        @logger&.warn("consensus.listener_error", error: "#{error.class}: #{error.message}")
        nil
      end
    end
  end
end
