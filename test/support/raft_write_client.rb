# frozen_string_literal: true

# A client layer for the deterministic Raft simulation that behaves exactly
# like Consensus::Server#propose does for an API request: it proposes on the
# node it is connected to, forwards to the leader when that node is a
# follower, retries a forward with the SAME request id after a 2 s answer
# timeout, waits for the entry (index, term) to be applied on the node it is
# connected to, and acknowledges the caller with that node's apply result.
# A ProposalDropped on a forwarded write is retried; on a local write it is
# a failure (503), as is a NotLeader raised by a role change.
#
# What this exists to check: an acknowledged create (ok: true) must exist on
# every replica for ever after, and every replica must hold the same state at
# the same applied index.  The round-79 conformance failure ("100 POST 201,
# 98 Pods") is exactly a violation of the first invariant somewhere between
# the API layer and the store, and these mirrors of the server's ack path
# are what the fault-injection scenarios and the stress test drive.

require "securerandom"
require "digest"

require_relative "raft_simulation"

module RaftSimulation
  class WriteClient
    C = Rubernetes::Consensus

    ACK_TIMEOUT = 10.0
    FORWARD_TIMEOUT = 2.0
    BATCH_FLUSH_SLACK = 0.010
    NOT_LEADER_SLEEP = 0.02
    APPLIED_MEMORY = 8192

    Request = Struct.new(:id, :request_id, :key, :command, :origin, :state, :index, :term, :deadline,
                         :forward_deadline, :flush_deadline, :retry_at, :flush_now, :result, :error,
                         :acked_at, :acked_index, :acked_term, :acked_on, :trace, :generation, keyword_init: true) do
      def done?
        %i[acked rejected failed].include?(state)
      end

      def acked?
        state == :acked
      end
    end

    attr_reader :requests, :acked, :rejected, :failed

    def initialize(cluster, random: cluster.random)
      @cluster = cluster
      @random = random
      @requests = []
      @active = {}
      @by_request_id = {}
      @pending = Hash.new { |hash, node_id| hash[node_id] = {} }
      @applied_by_index = Hash.new { |hash, node_id| hash[node_id] = {} }
      @acked = []
      @rejected = []
      @failed = []
      @sequence = 0
      cluster.processes.each_value { |process| attach(process) }
      cluster.client_handler = ->(message) { handle(message) }
      cluster.add_step_hook { |now| step(now) }
    end

    def attach(process)
      process.applied_hook = ->(proc, applied) { applied_hook(proc, applied) }
      process.role_hook = ->(proc, previous, current) { role_hook(proc, previous, current) }
    end

    # Submit a create of +key+ through node +origin+.  +flush_now+ mirrors the
    # lone-proposer path (Server flushes at once when no other proposer is
    # queued); otherwise the batch waits for the tick loop / the slack.
    def create(origin, key, object: nil, request_uid: nil, flush_now: nil)
      command = {"type" => "create", "key" => key,
                 "object" => object || {"metadata" => {"name" => key.split("/").last}, "spec" => {"origin" => origin}},
                 "request_uid" => request_uid, "leader_time" => @cluster.now}
      submit(origin, key, command, flush_now: flush_now)
    end

    def update(origin, key, object:, expected_resource_version:, request_uid: nil, flush_now: nil)
      command = {"type" => "update", "key" => key, "object" => object, "expected_resource_version" => expected_resource_version,
                 "client_precondition" => expected_resource_version, "request_uid" => request_uid, "leader_time" => @cluster.now}
      submit(origin, key, command, flush_now: flush_now)
    end

    def delete(origin, key, expected_resource_version: nil, request_uid: nil, flush_now: nil)
      command = {"type" => "delete", "key" => key, "expected_resource_version" => expected_resource_version,
                 "request_uid" => request_uid, "leader_time" => @cluster.now}
      submit(origin, key, command, flush_now: flush_now)
    end

    def submit(origin, key, command, flush_now: nil)
      @sequence += 1
      # RaftStore#submit: "<uid or uuid>:<16 hex of the command digest>".
      request_id = "#{command["request_uid"] || SecureRandom.uuid}:#{C::Canonical.digest(command)[0, 16]}"
      request = Request.new(id: @sequence, request_id: request_id, key: key, command: command, origin: String(origin),
                            state: :new, deadline: @cluster.now + ACK_TIMEOUT,
                            generation: @cluster.processes.fetch(String(origin)).generation,
                            flush_now: flush_now.nil? ? @random.rand < 0.5 : flush_now, trace: [])
      @requests << request
      @active[request.id] = request
      @by_request_id[request_id] = request
      drive(request, @cluster.now)
      request
    end

    def outstanding
      @active.values
    end

    def outstanding?
      !@active.empty?
    end

    # Run the simulation until every request is acknowledged, rejected or
    # failed (or the timeout passes).
    def settle(timeout: ACK_TIMEOUT + 1.0)
      @cluster.run_until(timeout: timeout) { !outstanding? }
    end

    # ----------------------------------------------------------- invariants

    # Every acknowledged create must be present, with the acknowledged
    # position still in the log (or below the snapshot), on every live
    # replica that has applied past it.  Returns a list of violation strings.
    def missing_acked_creates(deleted_keys: [])
      violations = []
      @acked.each do |request|
        next unless request.command["type"] == "create"
        next if deleted_keys.include?(request.key)

        @cluster.processes.each_value do |process|
          next unless process.alive
          next if process.node.last_applied < request.acked_index

          store = process.state_machine.store
          begin
            store.get(request.key)
          rescue Rubernetes::Storage::NotFound
            violations << "#{process.id}: acked create #{request.key} (index #{request.acked_index} term #{request.acked_term}, " \
                          "acked on #{request.acked_on}) is missing at applied #{process.node.last_applied}"
          end
          entry = process.node.log.entry_at(request.acked_index)
          if entry && (entry.term != request.acked_term || entry.command["key"] != request.key)
            violations << "#{process.id}: log entry #{request.acked_index} is #{entry.command["key"]}@#{entry.term}, " \
                          "acked #{request.key}@#{request.acked_term}"
          end
        end
      end
      violations
    end

    # Every live replica at the same applied index must hold the same state.
    def divergent_replicas
      live = @cluster.processes.values.select(&:alive)
      by_index = live.group_by { |process| process.node.last_applied }
      violations = []
      by_index.each do |index, processes|
        next if processes.length < 2

        digests = processes.to_h { |process| [process.id, state_digest(process)] }
        next if digests.values.uniq.length == 1

        violations << "applied #{index}: #{digests.inspect}"
      end
      violations
    end

    def state_digest(process)
      Digest::SHA256.hexdigest(C::Canonical.encode(process.state_machine.store.export_state))
    end

    private

    # -------------------------------------------------------------- driving

    def step(now)
      @active.values.each { |request| drive(request, now) }
    end

    def drive(request, now)
      return if request.done?
      return fail(request, :timeout, now) if now >= request.deadline

      process = @cluster.processes[request.origin]
      # A crash, even one followed by a restart before this step, ends the
      # connection the request came in on.
      return fail(request, :connection_lost, now) unless process&.alive && process.generation == request.generation

      node = process.node
      case request.state
      when :new, :retry
        return if request.retry_at && now < request.retry_at

        if node.leader?
          begin
            position = node.propose(request.command, request_id: request.request_id, now: process.now)
            request.trace << [:proposed, now, node.current_term, position[:pending] ? :pending : position[:index]]
          rescue C::NotLeader
            request.state = :retry
            request.retry_at = now + NOT_LEADER_SLEEP
            return
          end
          @cluster.route(node.drain)
          if position[:pending] && request.flush_now
            # Server#flush_overlapped: append, send, then sync locally.
            node.flush(process.now, defer_sync: true)
            @cluster.route(node.drain)
            @cluster.route(node.drain) if node.sync_local!
            position = node.proposal_position(request.request_id)
          end
          if position && !position[:pending]
            request.trace << [:appended, now, position[:index], position[:term]]
            wait_for(request, node, position[:index], position[:term], now, local: true)
          else
            request.state = :awaiting_flush
            request.flush_deadline = now + BATCH_FLUSH_SLACK
          end
        elsif node.leader_id && node.leader_id != request.origin
          leader = node.leader_id
          request.state = :forwarded
          request.forward_deadline = now + [request.deadline - now, FORWARD_TIMEOUT].min
          request.trace << [:forwarded, now, leader]
          @cluster.network.send(C::Messages::ForwardProposal.new(cluster_id: @cluster.cluster_id, from: request.origin, to: leader,
                                                                 term: node.current_term, request_id: request.request_id,
                                                                 command: request.command), now)
        else
          request.state = :retry
          request.retry_at = now + NOT_LEADER_SLEEP
        end
      when :awaiting_flush
        # Server#await_batch_flush: give up when leadership is lost, take
        # the position once the batch is flushed, flush ourselves when the
        # tick loop is late.
        unless node.leader?
          # Server#await_batch_flush: an entry the batch flush appended
          # before the step-down is waited for; only an unflushed one is
          # proposed again.
          appended = node.appended_position(request.request_id)
          if appended
            request.trace << [:appended_before_step_down, now, appended[:index], appended[:term]]
            wait_for(request, node, appended[:index], appended[:term], now, local: true)
          else
            request.trace << [:leadership_lost_before_flush, now, node.current_term]
            request.state = :retry
          end
          return
        end
        position = node.proposal_position(request.request_id)
        if position.nil? && now >= request.flush_deadline
          node.flush(process.now)
          @cluster.route(node.drain)
          position = node.proposal_position(request.request_id)
          if position.nil?
            request.trace << [:flush_found_nothing, now, node.current_term]
            request.state = :retry
            return
          end
        end
        return if position.nil?

        request.trace << [:appended, now, position[:index], position[:term]]
        wait_for(request, node, position[:index], position[:term], now, local: true)
      when :forwarded
        if now >= request.forward_deadline
          request.trace << [:forward_timeout, now]
          request.state = :retry
          drive(request, now)
        end
      when :waiting_apply
        nil
      end
    end

    # Server#wait_for: an already applied index with the same term answers
    # at once, otherwise register for the apply.
    def wait_for(request, node, index, term, now, local:)
      request.index = index
      request.term = term
      applied = @applied_by_index[node.id][index]
      if applied && applied[:term] == term
        resolve(request, applied[:result], now)
      elsif node.last_applied >= index && !applied
        # The entry was applied through a snapshot on this node: no result
        # exists here.  The production server fails fast with
        # ProposalDropped so the client sees an unknown outcome (503) at
        # once instead of a hang until the deadline.
        request.trace << [:applied_through_snapshot, now, index]
        fail(request, :applied_through_snapshot, now)
      else
        request.state = :waiting_apply
        @pending[node.id][[index, term]] = request
      end
    end

    def handle(message)
      return unless message.is_a?(C::Messages::ForwardProposalResponse)

      request = @by_request_id[message.request_id]
      return if request.nil? || request.state != :forwarded || request.origin != message.to

      now = @cluster.now
      process = @cluster.processes[request.origin]
      return unless process&.alive

      if message.accepted
        request.trace << [:forward_accepted, now, message.index, message.entry_term]
        wait_for(request, process.node, message.index, message.entry_term, now, local: false)
      else
        request.trace << [:forward_refused, now, message.leader_id]
        request.state = :retry
        request.retry_at = now + NOT_LEADER_SLEEP
      end
    end

    # ------------------------------------------------------------ callbacks

    def applied_hook(process, applied)
      node_id = process.id
      memory = @applied_by_index[node_id]
      memory[applied.index] = {term: applied.term, result: applied.result}
      memory.shift while memory.length > APPLIED_MEMORY
      pending = @pending[node_id]
      now = @cluster.now
      snapshot = applied.command.is_a?(Hash) && applied.command["type"] == "snapshot"
      if (request = pending.delete([applied.index, applied.term])) && !request.done?
        if snapshot
          # Server#applied_hook: the entry at exactly the snapshot index has
          # no result on this node.
          request.trace << [:applied_through_snapshot, now, applied.index]
          fail(request, :applied_through_snapshot, now)
        else
          resolve(request, applied.result, now)
        end
      end
      pending.keys.each do |(index, term)|
        next unless index < applied.index || (index == applied.index && term != applied.term)

        request = pending.delete([index, term])
        next if request.done?

        if snapshot && index < applied.index
          request.trace << [:covered_by_snapshot, now, applied.index]
          fail(request, :applied_through_snapshot, now)
        else
          request.trace << [:overwritten, now, applied.index, applied.term]
          dropped(request, now, local: request.trace.none? { |event| event.first == :forward_accepted })
        end
      end
    end

    def role_hook(process, previous, current)
      return unless previous == :leader && current != :leader

      pending = @pending[process.id]
      pending.values.each { |request| fail(request, :not_leader, @cluster.now) unless request.done? }
      pending.clear
    end

    def dropped(request, now, local:)
      fail(request, :dropped, now) if local

      # Server#forward rescues ProposalDropped and the propose loop retries
      # with the same request id.
      request.state = :retry
    end

    def finish(request)
      @active.delete(request.id)
      @pending[request.origin].delete([request.index, request.term]) if request.index
    end

    def resolve(request, result, now)
      finish(request)
      request.result = result
      request.acked_index = request.index
      request.acked_term = request.term
      request.acked_on = request.origin
      request.acked_at = now
      if result.is_a?(Hash) && result["ok"]
        request.state = :acked
        @acked << request
      else
        request.state = :rejected
        @rejected << request
      end
    end

    def fail(request, error, now)
      finish(request)
      request.state = :failed
      request.error = error
      request.acked_at = now
      @failed << request
    end
  end
end
