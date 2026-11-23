# frozen_string_literal: true

require "zlib"

require_relative "errors"
require_relative "canonical"
require_relative "../storage/memory_store"

module Rubernetes
  module Consensus
    # Replicated state machine over the MVCC MemoryStore.  Commands carry
    # everything the replica needs to apply them deterministically: the final
    # object computed by the leader, the precondition, the request UID and the
    # leader's wall-clock timestamp used for time-based history compaction.
    #
    # The Raft node supplies committed commands and manages snapshots.
    # Reads go straight to #store after the serving node confirms its read index.
    class KVStateMachine
      COMMAND_TYPES = %w[create update delete compact noop].freeze
      EFFECT_TYPES = %w[create update delete].freeze

      # Apply-side invariant checking.  Every replica applies the same log,
      # so at the same applied index every replica must hold the same
      # number of live objects and the same running digest of (index, type,
      # key, outcome, revision); and the live object count must equal the
      # successful creates minus the successful deletes since the store was
      # empty.  Conformance round 79 answered two Pod creates with 201 whose
      # Pods never existed afterwards, and nothing in the logs could say
      # whether the store had lost them, a replica had diverged, or the
      # acknowledgement was wrong.  Every +checkpoint_interval+ applies each
      # replica logs "consensus.apply_checkpoint" (compare across replicas
      # with tools/consensus/checkpoint_compare.rb) and any breach of the
      # count invariant is logged as "consensus.apply_invariant_violation".
      # RUBERNETES_TRACE_RAFT=1 additionally logs every apply.
      DEFAULT_CHECKPOINT_INTERVAL = Integer(ENV.fetch("RUBERNETES_RAFT_CHECKPOINT_ENTRIES", 1000))
      TRACE = ENV["RUBERNETES_TRACE_RAFT"].to_s == "1"

      attr_reader :store, :applied_index, :effects, :violations

      def initialize(store: nil, history_revisions: Rubernetes::Storage::MemoryStore::DEFAULT_HISTORY_REVISIONS,
                     history_retention_policy: Rubernetes::Storage::MemoryStore::DEFAULT_HISTORY_POLICY,
                     history_seconds: Rubernetes::Storage::MemoryStore::DEFAULT_HISTORY_SECONDS_BY_POLICY[history_retention_policy],
                     logger: nil, checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL, trace: TRACE)
        @history_options = {history_revisions: history_revisions, history_seconds: history_seconds,
                            history_retention_policy: history_retention_policy}
        @clock_value = 0.0
        @store = store || build_store
        @applied_index = 0
        @results = {}
        @logger = logger
        @checkpoint_interval = checkpoint_interval
        @trace = trace
        @effects = {"create" => 0, "update" => 0, "delete" => 0, "rejected" => 0}
        @digest = 0
        @since_checkpoint = 0
        @violations = 0
      end

      # The first committed leader no-op seeds the shared signing key.
      # Snapshot metadata preserves it across elections and restores without
      # including it in a portable datastore export.
      def leadership_command
        command = {"type" => "noop"}
        command["continue_token_secret"] = SecureRandom.hex(32) unless @continue_token_secret
        command
      end

      def apply_leadership_metadata(command)
        secret = command["continue_token_secret"]
        return if @continue_token_secret || !secret.is_a?(String) || !secret.match?(/\A[0-9a-f]{64}\z/)

        @continue_token_secret = secret.dup.freeze
        @store.use_continue_token_secret(@continue_token_secret)
        nil
      end

      # Deterministic application.  Returns {"ok" => true, "object" => ...}
      # or {"ok" => false, "error" => {...}} — errors are results too, so a
      # replayed request (S6) converges to the same answer on every replica.
      def apply(index, command)
        raise InvalidCommand, "command must be a Hash" unless command.is_a?(Hash)
        raise InvalidCommand, "command #{index} applied out of order after #{@applied_index}" unless index > @applied_index

        @clock_value = Float(command["leader_time"]) if command.key?("leader_time")
        revision_before = @store.revision
        result = begin
          case command["type"]
          when "create"
            key = command.fetch("key")
            object = @store.create(key, decode_object(command.fetch("object"), key),
                                   request_uid: command["request_uid"], related_versions: command["related_versions"])
            {"ok" => true, "object" => object}
          when "update"
            expected = command["expected_resource_version"]
            key = command.fetch("key")
            object = apply_update(key, prec: expected, request_uid: command["request_uid"],
                                       replay_precondition: command["client_precondition"], related_versions: command["related_versions"]) do
              decode_object(command.fetch("object"), key)
            end
            {"ok" => true, "object" => object}
          when "delete"
            expected = command["expected_resource_version"]
            object = @store.delete(command.fetch("key"), prec: expected, request_uid: command["request_uid"],
                                                         delete_corrupt: command["delete_corrupt"] == true, related_versions: command["related_versions"])
            {"ok" => true, "object" => object}
          when "compact"
            @store.compact!(revision: command.fetch("revision"))
            {"ok" => true}
          when "noop"
            {"ok" => true}
          else
            raise InvalidCommand, "unknown command type #{command["type"].inspect}"
          end
        rescue Rubernetes::Storage::Error => error
          {"ok" => false, "error" => error_document(error)}
        end
        @applied_index = index
        record_effect(index, command, result, revision_before)
        result
      end

      # The running digest of every apply so far: equal on every replica at
      # the same applied index, or the replicas have diverged.
      def digest
        format("%08x", @digest)
      end

      # Live objects in the store: what the invariant compares against the
      # effect counters.
      def live_objects
        @store.is_a?(Rubernetes::Storage::MemoryStore) ? @store.live_object_count : @store.list("").items.length
      end

      # Checks the count invariant now and logs the checkpoint.  Returns the
      # checkpoint fields; a breach is counted in #violations and logged as
      # an error, never raised: the replica keeps serving, the log names the
      # index at which the state stopped adding up.
      def checkpoint!(reason: "interval")
        @since_checkpoint = 0
        live = live_objects
        expected = @effects["create"] - @effects["delete"]
        fields = {index: @applied_index, revision: @store.revision, objects: live, expected_objects: expected,
                  creates: @effects["create"], updates: @effects["update"], deletes: @effects["delete"],
                  rejected: @effects["rejected"], digest: digest, reason: reason}
        if live == expected
          @logger&.info("consensus.apply_checkpoint", **fields)
        else
          @violations += 1
          @logger&.error("consensus.apply_invariant_violation", **fields)
        end
        fields
      end

      # Complete state: objects, version history, request memory and revision
      # counters, so a restored replica answers exactly like the original.
      def snapshot
        self.class.encode_snapshot(snapshot_document)
      end

      # The state to snapshot, as a document that stays valid after this call:
      # export_state builds fresh arrays and hashes around the store's frozen
      # objects, so later applies never reach into it.  Taking it costs
      # milliseconds; encoding it is what costs seconds (a 60 MB canonical
      # document takes ~9 s), and the Raft node must not hold its lock for
      # that -- see Node#maybe_snapshot.
      def snapshot_document
        @store.export_state.merge("applied_index" => @applied_index, "clock_value" => @clock_value,
                                  "effects" => @effects.dup, "digest" => @digest, "continue_token_secret" => @continue_token_secret)
      end

      def self.encode_snapshot(document)
        encoded_objects = {}.compare_by_identity
        encoded = transform_snapshot_objects(document) do |object, _key, _revision|
          if object.is_a?(Rubernetes::Storage::CBORRecord::Unreadable)
            object.encoded
          elsif object.is_a?(Rubernetes::Storage::CBORRecord::Object)
            encoded_objects[object] ||= Rubernetes::Storage::CBORRecord.encode(object)
          else
            object
          end
        end
        Zlib::Deflate.deflate(Canonical.encode(encoded), Zlib::BEST_SPEED)
      end

      def self.transform_snapshot_objects(document)
        versions = document.fetch("versions").to_h do |key, entries|
          [key, entries.map { |revision, object| [revision, yield(object, key, revision)] }]
        end
        history = document.fetch("history").map do |entry|
          key = entry.fetch("key")
          entry.merge("object" => yield(entry["object"], key, entry["revision"]), "old_object" => yield(entry["old_object"], key, nil))
        end
        requests = document.fetch("requests").transform_values do |entry|
          entry.merge("result" => yield(entry["result"], entry.fetch("key"), entry["revision"]))
        end
        document.merge("versions" => versions, "history" => history, "requests" => requests)
      end
      private_class_method :transform_snapshot_objects

      def restore(bytes)
        inflated = Zlib::Inflate.inflate(bytes)
        document = Canonical.decode(inflated, max_bytes: SnapshotStore::MAX_SNAPSHOT_BYTES)
        raise SnapshotCorruption, "snapshot state must be an object" unless document.is_a?(Hash)

        applied = document.delete("applied_index")
        @clock_value = Float(document.delete("clock_value") || 0.0)
        effects = document.delete("effects")
        digest = document.delete("digest")
        @continue_token_secret = document.delete("continue_token_secret")&.freeze
        document = self.class.send(:transform_snapshot_objects, document) do |object, key, revision|
          decode_object(object, key, revision: revision)
        end
        replacement = build_store
        replacement.import_state(document)
        previous = @store
        @store = replacement
        @applied_index = Integer(applied)
        # A snapshot from before the counters existed carries none: start
        # the invariant from what the snapshot holds.
        @effects = if effects.is_a?(Hash)
                     @effects.merge(effects.slice(*@effects.keys).transform_values do |value|
                       Integer(value)
                     end)
                   else
                     {"create" => live_objects, "update" => 0, "delete" => 0, "rejected" => 0}
                   end
        @digest = digest.is_a?(Integer) ? digest : 0
        @since_checkpoint = 0
        # The watches opened against the old store would never see another
        # event: every later apply mutates the replacement.  A replica that
        # installed a snapshot therefore served silent watches for up to the
        # clients' 5-10 minute watch timeout -- the controller manager watched
        # through it, its informers went deaf, new namespaces got no default
        # ServiceAccount, and specs failed in [BeforeEach] (captured with
        # thread dumps: every reflector in IO#wait_readable, every apiserver
        # watcher waiting on an empty queue).  Expire them so clients relist.
        previous.expire_watchers! if previous && !previous.equal?(replacement) && previous.respond_to?(:expire_watchers!)
        self
      rescue Zlib::Error => error
        raise SnapshotCorruption, "snapshot state is not valid compressed data: #{error.message}"
      rescue Schema::Codec::Error => error
        raise SnapshotCorruption, "snapshot contains an invalid CBOR object: #{error.message}"
      end

      private

      def apply_update(key, **, &)
        return @store.apply_update(key, **, &) if @store.is_a?(Rubernetes::Storage::MemoryStore)

        @store.guaranteed_update(key, **, max_retries: 0, &)
      end

      def decode_object(object, key, revision: nil)
        object.is_a?(String) ? Rubernetes::Storage::CBORRecord.decode_record(object, key: key, revision: revision) : object
      end

      # Counts only effects that changed the store: a request-UID replay
      # returns the remembered result without a new revision.
      def record_effect(index, command, result, revision_before)
        type = command["type"]
        ok = result["ok"] == true
        revision = ok && result["object"].is_a?(Hash) ? result["object"].dig("metadata", "resourceVersion") : nil
        if ok && EFFECT_TYPES.include?(type) && @store.revision > revision_before
          @effects[type] += 1
        elsif !ok
          @effects["rejected"] += 1
        end
        @digest = Zlib.crc32("#{index}|#{type}|#{command["key"]}|#{ok ? 1 : 0}|#{revision}", @digest)
        if @trace && @logger
          @logger.info("consensus.trace.apply", index: index, type: type, key: command["key"], ok: ok, revision: revision,
                                                error: ok ? nil : result.dig("error", "class"), digest: digest)
        end
        @since_checkpoint += 1
        checkpoint! if @checkpoint_interval && @since_checkpoint >= @checkpoint_interval
      end

      def build_store
        Rubernetes::Storage::MemoryStore.new(
          **@history_options,
          clock: -> { @clock_value },
          sleeper: ->(_seconds) {},
          token_secret: @continue_token_secret,
          legacy_token_secret: "raft-replica"
        )
      end

      def error_document(error)
        {
          "class" => error.class.name,
          "message" => error.message,
          "status" => error.status,
          "reason" => error.reason,
          "key" => error.key,
          "resource_version" => error.resource_version,
          "details" => error.details,
          "causes" => error.causes,
          "compacted_revision" => (error.respond_to?(:compacted_revision) ? error.compacted_revision : nil),
          "request_uid" => (error.respond_to?(:request_uid) ? error.request_uid : nil)
        }
      end
    end
  end
end
