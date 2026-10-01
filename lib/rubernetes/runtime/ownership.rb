# frozen_string_literal: true

# Durable ownership and lifecycle primitives shared by the Native runtime and
# the node agent.  The implementation is deliberately independent of Linux:
# all kernel/VMM work is injected through a small observer/cleaner contract.

require "digest"
require "fileutils"
require "json"
require "securerandom"
require "time"

require_relative "common/strict_json"

module Rubernetes
  module Runtime
    class Error < StandardError; end
    class JournalCorruption < Error; end
    class OwnershipConflict < Error; end
    class InvalidTransition < Error; end
    class RecoveryRequired < Error; end

    # Append-only, hash chained JSON-lines journal.  A record is considered
    # durable only after flush + fsync succeeds.  The hash chain makes a torn
    # write or an edited middle record observable during startup reconciliation.
    class RollbackJournal
      Record = Data.define(:sequence, :operation_id, :event, :payload, :timestamp, :previous_digest, :digest) do
        def to_h
          {
            "sequence" => sequence,
            "operation_id" => operation_id,
            "event" => event,
            "payload" => payload,
            "timestamp" => timestamp,
            "previous_digest" => previous_digest,
            "digest" => digest
          }
        end
      end

      EMPTY_DIGEST = "0" * 64
      DIGEST_PATTERN = /\A[0-9a-f]{64}\z/
      MAX_RECORD_BYTES = StrictJSON::DEFAULT_MAX_BYTES
      MAX_RECORD_DEPTH = StrictJSON::DEFAULT_MAX_DEPTH

      def initialize(path, clock: -> { Time.now.utc }, fsync: true)
        @path = File.expand_path(path)
        @clock = clock
        @fsync = fsync
        @mutex = Mutex.new
        FileUtils.mkdir_p(File.dirname(@path))
        # Replay validation returns an immutable view; the live journal must
        # still accept durable records after a process restart.
        @records = load_records.dup
      end

      attr_reader :path

      def append(operation_id:, event:, payload: {}, timestamp: nil)
        operation_id = normalize_id(operation_id, "operation_id")
        event = normalize_id(event, "event")
        payload = deep_copy(payload)
        @mutex.synchronize do
          sequence = @records.length + 1
          previous_digest = @records.empty? ? EMPTY_DIGEST : @records.last.digest
          timestamp = (timestamp || @clock.call).utc.iso8601(6)
          body = {
            "sequence" => sequence,
            "operation_id" => operation_id,
            "event" => event,
            "payload" => canonical(payload),
            "timestamp" => timestamp,
            "previous_digest" => previous_digest
          }
          digest = Digest::SHA256.hexdigest(JSON.generate(body))
          record = Record.new(**body, digest: digest)
          line = JSON.generate(record.to_h) << "\n"
          File.open(@path, File::WRONLY | File::CREAT | File::APPEND, 0o600) do |file|
            file.flock(File::LOCK_EX)
            file.write(line)
            file.flush
            file.fsync if @fsync
            file.flock(File::LOCK_UN)
          end
          @records << record
          record
        end
      rescue SystemCallError => error
        raise Error, "journal append failed for #{operation_id}: #{error.message}"
      end

      def records
        @mutex.synchronize { @records.map(&:to_h).freeze }
      end

      alias entries records

      def each(&block)
        return enum_for(__method__) unless block

        @mutex.synchronize { @records.each(&block) }
        self
      end

      def last
        @mutex.synchronize { @records.last }
      end

      def empty?
        @mutex.synchronize { @records.empty? }
      end

      # Rewrites the journal using an atomic sibling and a directory fsync.
      # Compaction is only safe when the caller supplies a complete snapshot;
      # this method never silently drops records.
      def compact!(records)
        normalized = Array(records).map { |record| normalize_record(record) }
        validate_records!(normalized)
        @mutex.synchronize { write_records!(normalized) }
        true
      end

      COMPACTION_EVENT = "journal_compacted"
      COMPACTION_ID = "journal"

      # Drops every record the block rejects and rewrites the journal as a
      # fresh hash chain: one compaction marker (what was dropped, how many
      # times this journal has been compacted, and the tail digest of the
      # chain it replaces) followed by the kept records in their original
      # order with new sequence numbers.  Operation ids, events, payloads and
      # timestamps are kept verbatim, so replay sees the same history for
      # everything that is still live.  Earlier markers are folded into the
      # new one.  The rewrite happens under the append lock, so a concurrent
      # append lands after it.  Returns the number of records dropped.
      def rewrite!
        raise ArgumentError, "rewrite! needs a keep predicate" unless block_given?

        @mutex.synchronize do
          previous_marker = @records.find { |record| record.event == COMPACTION_EVENT }
          generation = previous_marker ? Integer(previous_marker.payload["generation"]) + 1 : 1
          kept = @records.reject { |record| record.event == COMPACTION_EVENT || !yield(record) }
          dropped = @records.length - kept.length - (previous_marker ? 1 : 0)
          marker = {operation_id: COMPACTION_ID, event: COMPACTION_EVENT, timestamp: @clock.call.utc.iso8601(6),
                    payload: {"generation" => generation, "dropped_records" => dropped,
                              "previous_records" => @records.length,
                              "previous_tail_digest" => @records.empty? ? EMPTY_DIGEST : @records.last.digest,
                              "retained_records" => kept.length}}
          entries = [marker] + kept.map do |record|
            {operation_id: record.operation_id, event: record.event, payload: record.payload, timestamp: record.timestamp}
          end
          previous_digest = EMPTY_DIGEST
          chain = entries.each_with_index.map do |entry, index|
            body = {
              "sequence" => index + 1,
              "operation_id" => entry[:operation_id],
              "event" => entry[:event],
              "payload" => canonical(entry[:payload]),
              "timestamp" => entry[:timestamp],
              "previous_digest" => previous_digest
            }
            previous_digest = Digest::SHA256.hexdigest(JSON.generate(body))
            Record.new(**body, digest: previous_digest)
          end
          write_records!(chain.freeze)
          dropped
        end
      end

      def size
        @mutex.synchronize { @records.length }
      end

      private

      def write_records!(records)
        temporary = "#{@path}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          records.each { |record| file.write(JSON.generate(record.to_h) << "\n") }
          file.flush
          file.fsync if @fsync
        end
        File.rename(temporary, @path)
        fsync_directory
        @records = records.dup
      rescue StandardError
        File.delete(temporary) if temporary && File.exist?(temporary)
        raise
      end

      def load_records
        return [] unless File.exist?(@path)

        records = []
        File.open(@path, "rb") do |file|
          file.each_line.with_index(1) do |line, line_number|
            raise JournalCorruption, "journal line #{line_number} is not newline terminated" unless line.end_with?("\n")

            begin
              records << normalize_record(StrictJSON.parse(line, max_bytes: MAX_RECORD_BYTES, max_depth: MAX_RECORD_DEPTH,
                                                                 require_newline: true))
            rescue StrictJSON::Error, JSON::ParserError, KeyError, TypeError, ArgumentError => error
              raise JournalCorruption, "journal line #{line_number} is invalid: #{error.message}"
            end
          end
        end
        validate_records!(records)
        records
      rescue Errno::ENOENT
        []
      end

      def normalize_record(value)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        Record.new(
          sequence: Integer(hash.fetch("sequence")),
          operation_id: normalize_id(hash.fetch("operation_id"), "operation_id"),
          event: normalize_id(hash.fetch("event"), "event"),
          payload: canonical(hash.fetch("payload")),
          timestamp: Time.iso8601(String(hash.fetch("timestamp"))).utc.iso8601(6),
          previous_digest: String(hash.fetch("previous_digest")),
          digest: String(hash.fetch("digest"))
        )
      end

      def validate_records!(records)
        previous = EMPTY_DIGEST
        records.each_with_index do |record, index|
          expected_sequence = index + 1
          unless record.sequence == expected_sequence
            raise JournalCorruption,
                  "journal sequence #{record.sequence} expected #{expected_sequence}"
          end
          raise JournalCorruption, "journal previous digest mismatch at #{record.sequence}" unless record.previous_digest == previous
          raise JournalCorruption, "journal digest is invalid at #{record.sequence}" unless record.digest.match?(DIGEST_PATTERN)

          body = {
            "sequence" => record.sequence,
            "operation_id" => record.operation_id,
            "event" => record.event,
            "payload" => canonical(record.payload),
            "timestamp" => record.timestamp,
            "previous_digest" => record.previous_digest
          }
          expected = Digest::SHA256.hexdigest(JSON.generate(body))
          raise JournalCorruption, "journal hash mismatch at #{record.sequence}" unless expected == record.digest

          previous = record.digest
        end
        records.freeze
      end

      def fsync_directory
        directory = File.open(File.dirname(@path), File::RDONLY)
        directory.fsync if @fsync
      rescue SystemCallError
        # Directory fsync is unavailable on some test filesystems.  The file
        # itself is still fsynced; production profiles gate this capability.
        nil
      ensure
        directory&.close
      end

      def normalize_id(value, name)
        value = String(value)
        raise ArgumentError, "#{name} must not be empty" if value.empty? || value.include?("\0")

        value
      end

      def deep_copy(value)
        case value
        when Hash then value.to_h { |key, child| [String(key), deep_copy(child)] }
        when Array then value.map { |child| deep_copy(child) }
        else value
        end
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |key, output|
            source = value.key?(key) ? key : value.keys.find { |candidate| candidate.to_s == key }
            output[key] = canonical(value.fetch(source))
          end
        when Array then value.map { |child| canonical(child) }
        when Time then value.utc.iso8601(6)
        else value
        end
      end
    end

    # Durable owner ledger.  A resource can only be claimed once for a stable
    # identity and is released only after the owning operation has stopped.
    class OwnershipLedger
      STATES = %w[New Validated ImagePinned WorkspaceAllocated IsolationCreated ResourcesAttached WorkloadStopped Running Stopping Stopped
                  Removed RollingBack CleanupPending StateUnknown].freeze
      Resource = Data.define(:kind, :id, :identity, :owner, :state, :metadata)
      Operation = Data.define(:id, :owner, :state, :from, :to, :config_digest, :resources, :request_id)
      # Request records are separate from lifecycle operations.  A container
      # create/start/stop/remove request may be retried without advancing the
      # sandbox state machine, but the effect point still needs a durable
      # decision before the first kernel side effect.  Keeping these records in
      # the same hash-chained journal makes response-loss recovery fail closed
      # instead of repeating a non-idempotent operation.
      # owner names the lifecycle operation (sandbox) a request belongs to,
      # so the request records go when that operation is forgotten; nil on
      # records written before the field existed.
      Request = Data.define(:id, :operation, :config_digest, :state, :result, :error, :owner) do
        def to_h
          {
            "id" => id,
            "operation" => operation,
            "config_digest" => config_digest,
            "state" => state,
            "result" => result,
            "error" => error,
            "owner" => owner
          }
        end
      end

      # A finished (Removed) operation whose resources are all Released and
      # whose requests are all answered carries no recovery obligation: the
      # kernel holds nothing of it and nothing will be retried against it
      # except an immediate idempotent replay.  The most recent finished
      # operations stay for that replay; older ones are forgotten, and once
      # the forgotten records outnumber the live ones the journal is
      # rewritten without them (RollbackJournal#rewrite!).  Kept for ever,
      # a worker's journal reached 34 MB after one conformance round (323
      # of 324 operations Removed): 3.8 s to load and verify at every agent
      # start, 300 MB resident, and every claim scanning thousands of dead
      # resources.
      RETAINED_FINISHED_OPERATIONS = 16
      COMPACTION_MIN_DROPPED_RECORDS = 256
      COMPACTION_EVENT = "journal_compacted"

      def initialize(journal:, clock: -> { Time.now.utc })
        @journal = journal
        @clock = clock
        @mutex = Mutex.new
        @resources = {}
        @operations = {}
        @requests = {}
        # owner => {resource key => true}: resources(owner:) is asked on
        # every claim and release.
        @owner_keys = Hash.new { |hash, owner| hash[owner] = {} }
        # Removed operations in the order they finished.
        @finished = []
        # journal records per operation/request id, live records in all,
        # and the ids whose records are dropped but not yet compacted away.
        @record_counts = Hash.new(0)
        @live_records = 0
        @forgotten = {}
        @dropped_records = 0
        replay!
        @mutex.synchronize do
          reconcile_inert_operations_locked!
          forget_finished_locked!
        end
      end

      attr_reader :journal

      def begin_operation(operation_id:, owner:, config_digest:, request_id: operation_id)
        @mutex.synchronize do
          existing = @operations[operation_id]
          if existing
            unless existing.config_digest == String(config_digest) && existing.request_id == String(request_id)
              raise OwnershipConflict, "operation #{operation_id} was replayed with a different request"
            end

            return existing
          end

          operation = Operation.new(
            id: String(operation_id), owner: String(owner), state: "New", from: nil, to: "New",
            config_digest: String(config_digest), resources: [], request_id: String(request_id)
          )
          append!(operation.id, "operation_started", operation.to_h)
          @operations[operation.id] = operation
        end
      end

      def claim(operation_id:, kind:, id:, identity:, metadata: {})
        @mutex.synchronize do
          operation = operation!(operation_id)
          key = resource_key(kind, id)
          previous = @resources[key]
          existing = previous
          # A Released record is a tombstone, not an owner: the resource it
          # described was given up (a rolled-back effect, a completed cleanup).
          # Treating it as a conflicting holder makes any retry of the same
          # deterministic resource -- a sandbox rebuilding its veth after a
          # failed start -- permanently unclaimable.
          existing = nil if existing && existing.state == "Released"
          if existing
            unless existing.identity == String(identity) && existing.owner == operation.owner
              # Which of the two differs decides whether this is reuse by
              # another owner or the same owner reading back a different
              # identity; a message that says neither cannot be acted on.
              raise OwnershipConflict,
                    "resource #{key} is already owned or identity changed " \
                    "(held by owner=#{existing.owner.inspect} identity=#{existing.identity.inspect}; " \
                    "claim owner=#{operation.owner.inspect} identity=#{String(identity).inspect})"
            end
            # A resource can acquire additional kernel proof after the first
            # effect (for example, OverlayFS mount-table readback).  Refresh
            # the durable metadata under the same identity instead of
            # treating that proof update as a conflicting second owner.
            return existing if existing.state != "Released" && existing.metadata == immutable_copy(metadata)
          end
          resource = Resource.new(
            kind: String(kind), id: String(id), identity: String(identity), owner: operation.owner,
            state: "Owned", metadata: immutable_copy(metadata)
          )
          append!(operation.id, "resource_claimed", resource.to_h)
          index_resource!(key, previous, resource)
          @operations[operation.id] = operation_with_resources(operation, key)
          resource
        end
      end

      def transition(operation_id:, to:, from: nil, resources: nil, state: nil)
        @mutex.synchronize do
          operation = operation!(operation_id)
          from ||= operation.state
          to = String(to)
          validate_transition!(from, to)
          raise InvalidTransition, "state #{state.inspect} disagrees with transition target #{to.inspect}" if state && String(state) != to

          keys = if resources
                   Array(resources).map do |resource|
                     resource_key(resource.fetch(:kind), resource.fetch(:id))
                   end
                 else
                   operation.resources
                 end
          keys.each { |key| raise OwnershipConflict, "resource #{key} is not owned" unless @resources.key?(key) }
          next_operation = Operation.new(**operation.to_h, from: from, to: to, state: to, resources: keys)
          append!(operation.id, "state_transition", next_operation.to_h)
          @operations[operation.id] = next_operation
          if to == "Removed"
            @finished << operation.id unless @finished.include?(operation.id)
            forget_finished_locked!
          end
          next_operation
        end
      end

      # force is the teardown path.  Releasing a resource this operation no
      # longer holds is what a repeated teardown looks like -- the entry was
      # released by an earlier attempt, or its kernel name (a veth is named
      # from a hash, and names are reused) has since been claimed by a later
      # sandbox.  Neither is a failure, and neither may touch an entry this
      # operation does not own: refusing both left the Pod in CleanupPending,
      # so the node never issued its final delete and the Pod stayed
      # Terminating in the API for ever.  Outside teardown the check stays
      # strict, because there a mismatch really is a bug.
      def release(operation_id:, kind:, id:, identity:, force: false)
        @mutex.synchronize do
          operation = operation!(operation_id)
          key = resource_key(kind, id)
          resource = @resources[key]
          unless resource
            raise OwnershipConflict, "resource #{key} is not owned" unless force

            return nil
          end
          unless resource.owner == operation.owner && resource.identity == String(identity)
            raise OwnershipConflict, "resource #{key} identity or owner mismatch" unless force

            return nil
          end
          unless force || %w[Stopped Removed RollingBack CleanupPending StateUnknown].include?(operation.state)
            raise InvalidTransition, "cannot release #{key} while operation is #{operation.state}"
          end

          # A tombstone only says which owner gave up which identity; the
          # claim's kernel proof (a container's whole spec and security plan,
          # 25 KB) has no reader once released and doubled the journal.
          released = Resource.new(**resource.to_h, state: "Released", metadata: {}.freeze)
          append!(operation.id, "resource_released", released.to_h)
          @resources[key] = released
          released
        end
      end

      def finish(operation_id:, state: "Removed")
        transition(operation_id: operation_id, to: state)
      end

      def operation(operation_id)
        @mutex.synchronize { @operations[String(operation_id)] }
      end

      def operations
        @mutex.synchronize { @operations.values.map(&:to_h).freeze }
      end

      def resources(owner: nil, include_released: false)
        @mutex.synchronize do
          values = if owner
                     keys = @owner_keys.key?(owner.to_s) ? @owner_keys[owner.to_s].keys : []
                     keys.map { |key| @resources.fetch(key) }
                   else
                     @resources.values
                   end
          values = values.reject { |resource| resource.state == "Released" } unless include_released
          values.map(&:to_h).freeze
        end
      end

      def owned?(kind:, id:, identity:, owner: nil)
        @mutex.synchronize do
          resource = @resources[resource_key(kind, id)]
          resource && resource.identity == String(identity) && (owner.nil? || resource.owner == String(owner)) && resource.state != "Released"
        end
      end

      def recovery_candidates
        @mutex.synchronize do
          @operations.values.filter_map do |operation|
            next unless %w[RollingBack CleanupPending StateUnknown].include?(operation.state)

            operation.to_h
          end
        end
      end

      # Begin a request durably before executing its first effect.  A pending
      # request is intentionally not replayable: the caller must reconcile
      # kernel state before deciding whether the operation completed.
      def begin_request(request_id:, operation:, config_digest:, owner: nil)
        request = normalize_request_id(request_id)
        operation_name = normalize_request_id(operation)
        digest = String(config_digest)
        owner = owner.nil? ? nil : String(owner)
        @mutex.synchronize do
          existing = @requests[request]
          if existing
            unless existing.config_digest == digest && existing.operation == operation_name
              raise OwnershipConflict, "request #{request} was replayed with different intent"
            end

            return existing
          end

          record = Request.new(id: request, operation: operation_name, config_digest: digest,
                               state: "Pending", result: nil, error: nil, owner: owner)
          append!(request, "request_started", record.to_h)
          @requests[request] = record
        end
      end

      # Persist a terminal request response after the effect and its durable
      # ownership update have completed.  The response is canonicalized by the
      # journal and is safe to return to an idempotent retry.
      def complete_request(request_id:, state:, result: nil, error: nil)
        request = normalize_request_id(request_id)
        terminal = String(state)
        unless %w[Completed Failed CleanupPending].include?(terminal)
          raise ArgumentError, "request terminal state must be Completed, Failed, or CleanupPending"
        end

        @mutex.synchronize do
          existing = @requests.fetch(request) { raise OwnershipConflict, "unknown request #{request}" }
          record = Request.new(id: existing.id, operation: existing.operation,
                               config_digest: existing.config_digest, state: terminal,
                               result: immutable_copy(result), error: immutable_copy(error), owner: existing.owner)
          append!(request, "request_completed", record.to_h)
          @requests[request] = record
        end
      end

      def request(request_id)
        @mutex.synchronize { @requests[normalize_request_id(request_id)] }
      end

      def requests
        @mutex.synchronize { @requests.values.map(&:to_h).freeze }
      end

      # Used by runtime replay paths to avoid scanning all lifecycle
      # operations and accidentally matching a request id embedded in a
      # workload spec.
      def operation_for_request(request_id)
        request = normalize_request_id(request_id)
        @mutex.synchronize do
          @operations.values.find { |operation| operation.request_id == request }
        end
      end

      private

      def replay!
        @journal.each do |record|
          payload = record.payload
          next if record.event == COMPACTION_EVENT

          @record_counts[record.operation_id] += 1
          @live_records += 1
          case record.event
          when "operation_started"
            operation = Operation.new(**symbolize_operation(payload))
            @operations[operation.id] = operation
          when "resource_claimed"
            resource = Resource.new(**symbolize_resource(payload))
            key = resource_key(resource.kind, resource.id)
            index_resource!(key, @resources[key], resource)
            operation = @operations.fetch(record.operation_id) { raise JournalCorruption, "resource references unknown operation" }
            @operations[operation.id] = operation_with_resources(operation, key)
          when "state_transition"
            operation = Operation.new(**symbolize_operation(payload))
            @operations[operation.id] = operation
            @finished << operation.id if (operation.state == "Removed") && !@finished.include?(operation.id)
          when "resource_released"
            resource = Resource.new(**symbolize_resource(payload))
            key = resource_key(resource.kind, resource.id)
            index_resource!(key, @resources[key], resource)
          when "request_started"
            request = Request.new(**symbolize_request(payload))
            @requests[request.id] = request
          when "request_completed"
            request = Request.new(**symbolize_request(payload))
            @requests[request.id] = request
          end
        end
      end

      def append!(operation_id, event, payload)
        @journal.append(operation_id: operation_id, event: event, payload: payload, timestamp: @clock.call)
        @record_counts[operation_id] += 1
        @live_records += 1
      end

      def index_resource!(key, previous, resource)
        @owner_keys[previous.owner].delete(key) if previous && previous.owner != resource.owner
        @owner_keys[resource.owner][key] = true
        @resources[key] = resource
      end

      # Load-time reconciliation.  An operation that never left New but
      # whose every claimed resource is already Released -- the network
      # ledger wrote thousands of those before Interface finished its
      # operations -- holds nothing in the kernel and answers no retry, yet
      # counted as live for ever and kept the journal from ever compacting.
      # It is closed here (one recorded transition to Removed) and forgotten
      # at once; an operation holding a live resource, one with a pending
      # request, or one that never claimed anything is left as it is.
      def reconcile_inert_operations_locked!
        inert = @operations.values.select do |operation|
          operation.state == "New" && !operation.resources.empty? && forgettable?(operation)
        end
        inert.each do |operation|
          closed = Operation.new(**operation.to_h, from: "New", to: "Removed", state: "Removed")
          append!(operation.id, "state_transition", closed.to_h)
          @operations[operation.id] = closed
          forget_operation_locked!(closed)
        end
        compact_locked! if @dropped_records >= COMPACTION_MIN_DROPPED_RECORDS && @dropped_records >= @live_records
      end

      # --- forgetting finished operations (called under @mutex)

      def forget_finished_locked!
        return if @finished.length <= RETAINED_FINISHED_OPERATIONS

        @finished[0...(@finished.length - RETAINED_FINISHED_OPERATIONS)].each do |operation_id|
          operation = @operations[operation_id]
          if operation.nil?
            @finished.delete(operation_id)
            next
          end
          next unless operation.state == "Removed" && forgettable?(operation)

          forget_operation_locked!(operation)
          @finished.delete(operation_id)
        end
        compact_locked! if @dropped_records >= COMPACTION_MIN_DROPPED_RECORDS && @dropped_records >= @live_records
      end

      def forgettable?(operation)
        operation.resources.all? do |key|
          resource = @resources[key]
          resource.nil? || resource.owner != operation.owner || resource.state == "Released"
        end && requests_of(operation).none? { |request| request.state == "Pending" }
      end

      def forget_operation_locked!(operation)
        operation.resources.each do |key|
          resource = @resources[key]
          next unless resource && resource.owner == operation.owner && resource.state == "Released"

          @resources.delete(key)
          @owner_keys[resource.owner].delete(key)
          @owner_keys.delete(resource.owner) if @owner_keys[resource.owner].empty?
        end
        requests_of(operation).each do |request|
          @requests.delete(request.id)
          drop_records!(request.id)
        end
        @operations.delete(operation.id)
        drop_records!(operation.id)
      end

      # Requests name their operation since the owner field exists; the
      # runtime's own request ids ("start:<sandbox>:<container>") identify
      # older records.
      def requests_of(operation)
        @requests.each_value.select do |request|
          if request.owner.nil?
            request.id.include?(":#{operation.id}:") || request.id.end_with?(":#{operation.id}")
          else
            request.owner == operation.id
          end
        end
      end

      def drop_records!(id)
        count = @record_counts.delete(id) || 0
        @dropped_records += count
        @live_records -= count
        @forgotten[id] = true
      end

      def compact_locked!
        return unless @journal.respond_to?(:rewrite!)

        forgotten = @forgotten
        @journal.rewrite! { |record| !forgotten.key?(record.operation_id) }
        @forgotten = {}
        @dropped_records = 0
      end

      def operation!(operation_id)
        @operations.fetch(String(operation_id)) { raise OwnershipConflict, "unknown operation #{operation_id}" }
      end

      def operation_with_resources(operation, key)
        return operation if operation.resources.include?(key)

        Operation.new(**operation.to_h, resources: (operation.resources + [key]).uniq)
      end

      def resource_key(kind, id)
        "#{kind}:#{id}"
      end

      def validate_transition!(from, to)
        return if from == to

        allowed = {
          "New" => %w[Validated RollingBack StateUnknown],
          "Validated" => %w[ImagePinned RollingBack StateUnknown],
          "ImagePinned" => %w[WorkspaceAllocated RollingBack StateUnknown],
          "WorkspaceAllocated" => %w[IsolationCreated RollingBack StateUnknown],
          "IsolationCreated" => %w[ResourcesAttached RollingBack StateUnknown],
          "ResourcesAttached" => %w[WorkloadStopped RollingBack StateUnknown],
          "WorkloadStopped" => %w[Running RollingBack StateUnknown],
          "Running" => %w[Stopping StateUnknown],
          "Stopping" => %w[Stopped RollingBack StateUnknown],
          "Stopped" => %w[Removed RollingBack CleanupPending],
          "Removed" => [],
          "RollingBack" => %w[Stopped CleanupPending],
          "CleanupPending" => %w[RollingBack StateUnknown],
          "StateUnknown" => %w[Stopping RollingBack CleanupPending]
        }
        return if allowed.fetch(from, []).include?(to)

        raise InvalidTransition, "invalid runtime transition #{from} -> #{to}"
      end

      def symbolize_operation(value)
        {
          id: value.fetch("id"), owner: value.fetch("owner"), state: value.fetch("state"),
          from: value["from"], to: value["to"], config_digest: value.fetch("config_digest"),
          resources: Array(value.fetch("resources")).map(&:to_s), request_id: value.fetch("request_id")
        }
      end

      def symbolize_resource(value)
        {
          kind: value.fetch("kind"), id: value.fetch("id"), identity: value.fetch("identity"),
          owner: value.fetch("owner"), state: value.fetch("state"), metadata: immutable_copy(value.fetch("metadata", {}))
        }
      end

      def immutable_copy(value)
        copied = case value
                 when Hash then value.to_h { |key, child| [String(key), immutable_copy(child)] }
                 when Array then value.map { |child| immutable_copy(child) }
                 else value
                 end
        copied.freeze
      end

      def symbolize_request(value)
        {
          id: normalize_request_id(value.fetch("id")),
          operation: normalize_request_id(value.fetch("operation")),
          config_digest: String(value.fetch("config_digest")),
          state: String(value.fetch("state")),
          result: immutable_copy(value["result"]),
          error: immutable_copy(value["error"]),
          owner: value["owner"].nil? ? nil : String(value["owner"])
        }
      end

      def normalize_request_id(value)
        request = String(value)
        raise ArgumentError, "request id must not be empty" if request.empty? || request.include?("\0")

        request
      end
    end

    ResourceLedger = OwnershipLedger

    # Reconciles durable ownership with an externally observed resource map.
    # Unknown identities are never guessed into ownership and therefore cannot
    # be deleted by recovery.  Cleanup is restricted to resources explicitly
    # marked dead by a trusted adapter and always runs in dependency order.
    class Recovery
      Result = Data.define(:ledger_only, :kernel_only, :identity_mismatch, :orphans,
                           :released, :cleaned_orphans, :errors, :audit) do
        def to_h
          {
            "ledger_only" => ledger_only,
            "kernel_only" => kernel_only,
            "identity_mismatch" => identity_mismatch,
            "orphans" => orphans,
            "released" => released,
            "cleaned_orphans" => cleaned_orphans,
            "errors" => errors,
            "audit" => audit
          }
        end
      end

      CLEANUP_ORDER = {"process" => 4, "cgroup" => 3, "namespace" => 2, "workspace" => 1}.freeze
      TRUSTED_MANAGERS = %w[rubernetes-native rubernetes].freeze

      def initialize(ledger:, observer:, cleaner: nil, orphan_predicate: nil, audit: nil)
        @ledger = ledger
        @observer = observer
        @cleaner = cleaner
        @orphan_predicate = orphan_predicate || method(:default_orphan?)
        @audit = audit
      end

      def reconcile
        ledger_resources = normalize_observed(@ledger.resources(include_released: false))
        observed = normalize_observed(@observer.call)
        ledger_by_key = index_resources(ledger_resources, "ledger")
        observed_by_key = index_resources(observed, "observed")
        ledger_only = ledger_by_key.keys - observed_by_key.keys
        kernel_only = observed_by_key.keys - ledger_by_key.keys
        mismatched = (ledger_by_key.keys & observed_by_key.keys).filter_map do |resource_key|
          expected = ledger_by_key.fetch(resource_key)
          actual = observed_by_key.fetch(resource_key)
          next if expected.fetch("identity") == actual.fetch("identity") && expected.fetch("owner") == actual.fetch("owner")

          {"resource" => resource_key, "ledger" => expected, "observed" => actual}
        end
        # A process whose pid now belongs to another program (start time or
        # executable differ) is proof that ours exited: the claim is released
        # and nothing is signalled.  Path-like reuse stays fatal to cleanup.
        pid_reused, identity_mismatch = mismatched.partition { |entry| entry.fetch("ledger").fetch("kind") == "process" }
        orphans = kernel_only.map do |resource_key|
          observed_by_key.fetch(resource_key)
        end.select { |resource| @orphan_predicate.call(resource) }
        errors = []
        released = []
        cleaned_orphans = []
        audit = []

        ledger_only.each do |resource_key|
          resource = ledger_by_key.fetch(resource_key)
          audit << audit_entry("ledger_only", resource_key)
          begin
            operation = operation_for_resource(resource)
            raise RecoveryRequired, "ledger resource #{resource_key} has no owning operation" unless operation

            @ledger.release(operation_id: operation.id, kind: resource.fetch("kind"), id: resource.fetch("id"),
                            identity: resource.fetch("identity"), force: true)
            released << resource_key
          rescue StandardError => error
            errors << error_entry(resource_key, error)
            mark_recovery_failure(operation_for_resource(resource), error)
          end
        end

        kernel_only.each do |resource_key|
          audit << audit_entry(orphans.any? do |entry|
            key(entry) == resource_key
          end ? "orphan" : "kernel_only", resource_key)
        end
        identity_mismatch.each { |entry| audit << audit_entry("identity_mismatch", entry.fetch("resource")) }
        pid_reused.each do |entry|
          resource = entry.fetch("ledger")
          resource_key = entry.fetch("resource")
          audit << audit_entry("pid_reused", resource_key)
          begin
            operation = operation_for_resource(resource)
            raise RecoveryRequired, "ledger resource #{resource_key} has no owning operation" unless operation

            @ledger.release(operation_id: operation.id, kind: resource.fetch("kind"), id: resource.fetch("id"),
                            identity: resource.fetch("identity"), force: true)
            released << resource_key
          rescue StandardError => error
            errors << error_entry(resource_key, error)
            mark_recovery_failure(operation_for_resource(resource), error)
          end
        end

        cleanup_in_dependency_order(orphans).each do |resource|
          resource_key = key(resource)
          begin
            raise RecoveryRequired, "no trusted cleaner is configured for orphan #{resource_key}" unless @cleaner

            response = @cleaner.call(resource)
            raise Error, "cleanup returned false for #{resource_key}" if response == false

            cleaned_orphans << resource_key
          rescue StandardError => error
            errors << error_entry(resource_key, error)
            mark_recovery_failure(operation_for_resource(resource), error)
          end
        end

        recover_pending_operations(ledger_by_key, observed_by_key, identity_mismatch, released, errors, audit)
        emit_audit(audit)
        remaining_ledger_only = ledger_only.reject { |resource_key| released.include?(resource_key) }
        Result.new(ledger_only: remaining_ledger_only.freeze, kernel_only: kernel_only.freeze,
                   identity_mismatch: identity_mismatch.freeze, orphans: orphans.freeze,
                   released: released.freeze, cleaned_orphans: cleaned_orphans.freeze,
                   errors: errors.freeze, audit: audit.freeze)
      end

      alias recover reconcile

      private

      def index_resources(resources, source)
        Array(resources).each_with_object({}) do |resource, result|
          resource_key = key(resource)
          raise RecoveryRequired, "#{source} inventory contains duplicate #{resource_key}" if result.key?(resource_key)

          result[resource_key] = resource
        end
      end

      def recover_pending_operations(_ledger_by_key, observed_by_key, identity_mismatch, released, errors, audit)
        mismatch_keys = identity_mismatch.map { |entry| entry.fetch("resource") }
        @ledger.recovery_candidates.each do |candidate|
          candidate_hash = candidate.respond_to?(:to_h) ? candidate.to_h : candidate
          operation = @ledger.operation(candidate_hash.fetch("id") { candidate_hash.fetch(:id) })
          operation_resources = normalize_observed(@ledger.resources(owner: operation.owner, include_released: false))
          operation_errors = []
          operation_resources.sort_by do |resource|
            [-CLEANUP_ORDER.fetch(resource["kind"], 0), -resource["id"].length, key(resource)]
          end.each do |resource|
            resource_key = key(resource)
            next if released.include?(resource_key)
            next if mismatch_keys.include?(resource_key)

            observed = observed_by_key[resource_key]
            begin
              if observed.nil?
                @ledger.release(operation_id: operation.id, kind: resource.fetch("kind"), id: resource.fetch("id"),
                                identity: resource.fetch("identity"), force: true)
                released << resource_key
                audit << audit_entry("released_missing", resource_key)
              elsif observed.fetch("metadata", {})["live"] == false
                raise RecoveryRequired, "no trusted cleaner is configured for #{resource_key}" unless @cleaner

                response = @cleaner.call(observed)
                raise Error, "cleanup returned false for #{resource_key}" if response == false

                @ledger.release(operation_id: operation.id, kind: resource.fetch("kind"), id: resource.fetch("id"),
                                identity: resource.fetch("identity"), force: true)
                released << resource_key
                audit << audit_entry("cleaned_and_released", resource_key)
              else
                raise RecoveryRequired, "resource #{resource_key} is live or liveness is unknown"
              end
            rescue StandardError => error
              operation_errors << error
              errors << error_entry(resource_key, error)
            end
          end
          finalize_operation(operation, operation_errors, released)
        end
      end

      def finalize_operation(operation, operation_errors, _released)
        current = @ledger.operation(operation.id)
        return unless current

        remaining = @ledger.resources(owner: current.owner, include_released: false)
        if operation_errors.empty? && remaining.empty?
          @ledger.transition(operation_id: current.id, to: "RollingBack") if %w[CleanupPending StateUnknown].include?(current.state)
          current = @ledger.operation(current.id)
          @ledger.transition(operation_id: current.id, to: "Stopped") if current.state == "RollingBack"
        elsif operation_errors.any?
          if current.state == "RollingBack"
            @ledger.transition(operation_id: current.id, to: "CleanupPending")
          elsif current.state != "StateUnknown" && !%w[Stopped Removed].include?(current.state)
            @ledger.transition(operation_id: current.id, to: "StateUnknown")
          end
        end
      rescue InvalidTransition
        # A concurrent cleanup may have advanced the durable state.  The
        # resource errors remain in the report, so recovery still fails closed.
        nil
      end

      def mark_recovery_failure(operation, _error)
        return unless operation

        current = @ledger.operation(operation.id)
        return unless current

        if current.state == "RollingBack"
          @ledger.transition(operation_id: current.id, to: "CleanupPending")
        elsif current.state != "StateUnknown" && !%w[Stopped Removed].include?(current.state)
          @ledger.transition(operation_id: current.id, to: "StateUnknown")
        end
      rescue InvalidTransition
        nil
      end

      def operation_for_resource(resource)
        values = @ledger.operations.find do |operation|
          values = operation.respond_to?(:to_h) ? operation.to_h : operation
          Array(values["resources"] || values[:resources]).include?(key(resource))
        end
        return unless values

        operation_hash = values.respond_to?(:to_h) ? values.to_h : values
        @ledger.operation(operation_hash["id"] || operation_hash[:id])
      end

      def cleanup_in_dependency_order(resources)
        Array(resources).sort_by do |resource|
          [-CLEANUP_ORDER.fetch(resource.fetch("kind"), 0), -resource.fetch("id").length, key(resource)]
        end
      end

      def default_orphan?(resource)
        metadata = resource.fetch("metadata", {})
        return false unless resource.fetch("owner", "").to_s != "" &&
                            TRUSTED_MANAGERS.include?(metadata["managed_by"].to_s) && metadata["live"] == false
        return true if metadata["ownership_verified"] == true

        owner = resource.fetch("owner")
        return false unless owner.match?(/\Asandbox:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}:[0-9a-f]{16}\z/)

        identity = resource.fetch("identity")
        id = resource.fetch("id")
        case resource.fetch("kind")
        when "workspace"
          identity.match?(/\Aworkspace:#{Regexp.escape(id)}:sha256:[0-9a-f]{64}\z/)
        when "namespace"
          identity == "namespace:#{id}"
        when "cgroup"
          identity == "cgroup:#{id}" || identity.start_with?("cgroup:#{id}:")
        when "process"
          parent = metadata["parent"]
          container = metadata["container_id"]
          pid = metadata["workload_pid"] || metadata["pid"]
          start_time = metadata["workload_start_time"] || metadata["start_time"]
          executable_digest = metadata["workload_executable_digest"] || metadata["executable_digest"]
          parent && container && pid && start_time && executable_digest &&
            identity == "process:#{parent}:#{container}:#{pid}:#{start_time}:#{executable_digest}"
        else
          false
        end
      end

      def audit_entry(kind, resource)
        {"kind" => kind, "resource" => resource, "at" => Time.now.utc.iso8601(6)}.freeze
      end

      def error_entry(resource, error)
        {"resource" => resource, "error" => "#{error.class}: #{error.message}"}.freeze
      end

      def emit_audit(entries)
        entries.each { |entry| @audit.call(entry) } if @audit
      end

      def normalize_observed(value)
        Array(value).map do |resource|
          hash = resource.respond_to?(:to_h) ? resource.to_h : resource
          {
            "kind" => String(hash.fetch("kind") { hash.fetch(:kind) }),
            "id" => String(hash.fetch("id") { hash.fetch(:id) }),
            "identity" => String(hash.fetch("identity") { hash.fetch(:identity) }),
            "owner" => String(hash.fetch("owner", hash.fetch(:owner, ""))),
            "metadata" => normalize_metadata(hash)
          }
        end
      end

      def normalize_metadata(hash)
        metadata = (hash["metadata"] || hash[:metadata] || {}).to_h.transform_keys(&:to_s)
        metadata["managed_by"] ||= hash["managed_by"] || hash[:managed_by]
        metadata["live"] = hash["live"] if hash.key?("live")
        metadata["live"] = hash[:live] if hash.key?(:live)
        metadata["path"] ||= hash["path"] || hash[:path]
        metadata.delete("path") if metadata["path"].nil?
        metadata.delete("managed_by") if metadata["managed_by"].nil?
        metadata
      end

      def key(resource)
        "#{resource.fetch("kind")}:#{resource.fetch("id")}"
      end
    end

    StartupReconciler = Recovery
  end
end
