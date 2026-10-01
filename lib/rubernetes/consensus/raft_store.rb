# frozen_string_literal: true

require "securerandom"

require_relative "errors"
require_relative "canonical"
require_relative "server"
require_relative "../storage/memory_store"

module Rubernetes
  module Consensus
    # Durable Store implementation (spec 5.2) backed by a Raft Server.  Reads
    # are linearizable by default (ReadIndex barrier before reading the local
    # replica); a caller that supplies an explicit non-zero resourceVersion
    # gets the same historical read semantics as MemoryStore.  Writes are
    # replicated commands; the leader computes the final object so every
    # replica applies byte-identical mutations.
    class RaftStore
      Error = Rubernetes::Storage::Error
      NotFound = Rubernetes::Storage::NotFound
      AlreadyExists = Rubernetes::Storage::AlreadyExists
      Conflict = Rubernetes::Storage::Conflict
      Gone = Rubernetes::Storage::Gone
      WatchOverflow = Rubernetes::Storage::WatchOverflow
      Unavailable = Rubernetes::Storage::Unavailable

      # Consensus outcomes that say "not now" rather than "not valid": the
      # caller may retry, and the API layer turns them into a 503.
      TRANSIENT_CONSENSUS_ERRORS = [
        Rubernetes::Consensus::NotLeader,
        Rubernetes::Consensus::Timeout,
        Rubernetes::Consensus::NotReady,
        Rubernetes::Consensus::ProposalDropped
      ].freeze

      ERROR_CLASSES = {
        "Rubernetes::Storage::NotFound" => NotFound,
        "Rubernetes::Storage::AlreadyExists" => AlreadyExists,
        "Rubernetes::Storage::Conflict" => Conflict,
        "Rubernetes::Storage::RequestUIDConflict" => Rubernetes::Storage::RequestUIDConflict,
        "Rubernetes::Storage::Gone" => Gone,
        "Rubernetes::Storage::InvalidResourceVersion" => Rubernetes::Storage::InvalidResourceVersion
      }.freeze

      DEFAULT_UPDATE_RETRIES = Rubernetes::Storage::MemoryStore::DEFAULT_UPDATE_RETRIES
      MIN_BACKOFF_SECONDS = Rubernetes::Storage::MemoryStore::MIN_BACKOFF_SECONDS
      MAX_BACKOFF_SECONDS = Rubernetes::Storage::MemoryStore::MAX_BACKOFF_SECONDS

      attr_reader :server

      def initialize(server, timeout: Server::DEFAULT_TIMEOUT, clock: -> { Time.now.utc }, sleeper: ->(seconds) { Kernel.sleep(seconds) },
                     random: Random.new, journal: nil)
        @server = server
        @timeout = timeout
        @clock = clock
        @sleeper = sleeper
        @random = random
        @journal = journal
      end

      # The API server's registry: passed on to the local replica (which may
      # be replaced by a snapshot install) and used for the read barrier.
      attr_reader :metrics

      def metrics=(registry)
        @metrics = registry
        store = @server.store
        store.metrics = registry if store.respond_to?(:metrics=)
        register_storage_size(registry) if registry
      end

      # apiserver_storage_size_bytes (etcd3 metrics' monitorCollector): the
      # space the storage database physically occupies -- here the raft
      # data directory (WAL segments and snapshots), in allocated blocks as
      # etcd's DbSize is -- one series per storage cluster, "etcd-0".
      def register_storage_size(registry)
        registry.register("apiserver_storage_size_bytes", type: :gauge) unless registry.registered?("apiserver_storage_size_bytes")
        registry.add_collector do |metrics|
          size = self.class.allocated_bytes(@server.data_directory)
          metrics.set("apiserver_storage_size_bytes", size, {"storage_cluster_id" => "etcd-0"}) if size
        end
      end

      def self.allocated_bytes(directory)
        return nil unless directory && File.directory?(directory)

        Dir.glob(File.join(directory, "**", "*"), File::FNM_DOTMATCH).sum do |path|
          stat = File.lstat(path)
          stat.file? ? stat.blocks.to_i * 512 : 0
        rescue SystemCallError
          0
        end
      end

      def local_store
        store = @server.store
        store.metrics = @metrics if @metrics && store.respond_to?(:metrics=) && !store.metrics
        store
      end

      def revision
        local_store.revision
      end
      alias resource_version revision
      alias current_revision revision

      def compacted_revision
        local_store.compacted_revision
      end

      # Local view, like #revision: the replica's applied state.
      def revision_under(prefix)
        local_store.revision_under(prefix)
      end

      def resource_version_string
        revision.to_s
      end

      def resourceVersion
        resource_version_string
      end

      def leader?
        @server.leader?
      end

      def get(key, out: nil, resource_version: nil, **options)
        read_barrier(key) unless historical?(resource_version, options)
        local_store.get(key, out: out, resource_version: resource_version, **options)
      end

      def list(prefix = "", resource_version: nil, resource_version_match: nil, **options)
        read_barrier(prefix) unless historical?(resource_version,
                                                options) ||
                                    (resource_version_match.to_s == "NotOlderThan" && !resource_version.nil? && resource_version.to_s != "0")
        local_store.list(prefix, resource_version: resource_version, resource_version_match: resource_version_match, **options)
      end

      def watch(prefix = "", *positional, **)
        local_store.watch(prefix, *positional, **)
      end

      def await_watch_delivery(revision, timeout:)
        store = local_store
        store.respond_to?(:await_watch_delivery) ? store.await_watch_delivery(revision, timeout: timeout) : true
      end

      def create(key, object, request_uid: nil, request_id: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        body = options.delete(:body)
        object_keyword = options.delete(:object)
        resource_keyword = options.delete(:resource)
        object ||= body || object_keyword || (resource_keyword.is_a?(Hash) ? resource_keyword : nil)
        discard(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown create options: #{options.keys.join(", ")}" unless options.empty?
        raise ArgumentError, "create requires an API object Hash" unless object.is_a?(Hash)

        normalized_key = normalize_key(key)
        command = {"type" => "create", "key" => normalized_key, "object" => object, "request_uid" => request_uid && String(request_uid),
                   "leader_time" => @clock.call.to_f}
        submit(command, effect: "create", key: normalized_key)
      end

      def guaranteed_update(key, prec: nil, precondition: nil, resource_version: nil, request_uid: nil, request_id: nil,
                            max_retries: DEFAULT_UPDATE_RETRIES, **options, &block)
        request_uid ||= request_id || options.delete(:uid)
        allow_nil_result = options.delete(:allow_nil_result) { false }
        raise ArgumentError, "unknown guaranteed_update options: #{options.keys.join(", ")}" unless options.empty?
        raise ArgumentError, "guaranteed_update requires a block" unless block

        expected = if prec.nil?
                     precondition.nil? ? resource_version : precondition
                   else
                     prec
                   end
        normalized_key = normalize_key(key)
        request_uid &&= String(request_uid)
        attempt = 0
        loop do
          barrier
          current = local_store.get(normalized_key)
          check_precondition!(normalized_key, current, expected)
          current_version = current.dig("metadata", "resourceVersion")
          candidate = yield(Rubernetes::Storage::MemoryStoreSupport.deep_dup(current))
          candidate = current if candidate.nil? && allow_nil_result
          raise ArgumentError, "guaranteed_update block must return an API object Hash" unless candidate.is_a?(Hash)

          # `expected_resource_version` is re-observed on every attempt, so it
          # identifies the attempt, not the client's request. `client_precondition`
          # carries what the caller actually asked for (nil when it asked for
          # none) so a replayed request UID still matches its first attempt.
          command = {"type" => "update", "key" => normalized_key, "object" => candidate, "expected_resource_version" => current_version,
                     "client_precondition" => expected,
                     "request_uid" => request_uid, "leader_time" => @clock.call.to_f}
          begin
            return submit(command, effect: "update", key: normalized_key)
          rescue Conflict => error
            raise error if attempt >= max_retries || (!expected.nil? && precondition_conflict?(error, expected))

            sleep_for_retry(attempt)
            attempt += 1
          end
        end
      end

      def update(key, object = nil, prec: nil, precondition: nil, resource_version: nil, request_uid: nil, request_id: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        body = options.delete(:body)
        object_keyword = options.delete(:object)
        resource_keyword = options.delete(:resource)
        object ||= body || object_keyword || (resource_keyword.is_a?(Hash) ? resource_keyword : nil)
        discard(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown update options: #{options.keys.join(", ")}" unless options.empty?
        raise ArgumentError, "update requires an API object Hash" unless object.is_a?(Hash)

        expected = if prec.nil?
                     precondition.nil? ? resource_version : precondition
                   else
                     prec
                   end
        guaranteed_update(key, prec: expected, request_uid: request_uid) { |_current| object }
      end
      alias replace update

      def delete(key, prec: nil, precondition: nil, resource_version: nil, request_uid: nil, request_id: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        discard(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown delete options: #{options.keys.join(", ")}" unless options.empty?

        expected = if prec.nil?
                     precondition.nil? ? resource_version : precondition
                   else
                     prec
                   end
        normalized_key = normalize_key(key)
        expected_version = expected.is_a?(Hash) ? (expected[:resourceVersion] || expected["resourceVersion"]) : expected
        command = {"type" => "delete", "key" => normalized_key, "expected_resource_version" => expected_version.nil? ? nil : String(expected_version),
                   "request_uid" => request_uid && String(request_uid), "leader_time" => @clock.call.to_f}
        submit(command, effect: "delete", key: normalized_key)
      end

      def compact!(revision: nil, **_options)
        target = revision || local_store.revision
        submit({"type" => "compact", "revision" => Integer(target), "leader_time" => @clock.call.to_f}, effect: "compact", key: "")
        local_store.compacted_revision
      end
      alias compact compact!

      def watcher_count
        local_store.watcher_count
      end

      def object_counts
        local_store.object_counts
      end

      def close
        local_store.close
        self
      end

      # Linearizable read barrier.
      #
      # A read index is idempotent: it confirms leadership and returns a
      # commit index, changing nothing.  Under load the confirmation can miss
      # its deadline (a busy leader, a slow peer round trip), and answering
      # the client with 500 turns a momentary stall into a failed request
      # that upstream would simply have retried.  The barrier is retried for
      # a bounded number of attempts before the timeout is reported.
      BARRIER_ATTEMPTS = 3

      SLOW_BARRIER_SECONDS = 1.0

      # One linearizable barrier per API request.  Every store read inside
      # the block after the first reuses that first read index: admission
      # alone reads the store fourteen times for a Pod create (quotas, limit
      # ranges, the namespace, the ServiceAccount, webhook configurations,
      # policies ...), and each read paid its own ReadIndex round trip -- on
      # a follower, a network hop to the leader -- so a Pod create cost
      # 200-300 ms of barriers while a ConfigMap create cost almost nothing,
      # and a ReplicationController needed 19 s to create 100 Pods.  A write
      # inside the block re-arms the barrier so a read after it still sees
      # what it wrote.  kube-apiserver's admission reads informer caches,
      # which are staler than this.
      BARRIER_SCOPE_KEY = :rubernetes_raft_read_barrier_scope

      def with_read_barrier
        return yield if Thread.current[BARRIER_SCOPE_KEY]

        Thread.current[BARRIER_SCOPE_KEY] = {taken: false}
        begin
          yield
        ensure
          Thread.current[BARRIER_SCOPE_KEY] = nil
        end
      end

      # Reads in the block use this replica's state without a ReadIndex round
      # trip -- kube-apiserver's GuaranteedUpdate starting from its watch
      # cache's copy (cachedExistingObject).  Only for reads whose staleness
      # the write that follows detects: the proposal carries the
      # resourceVersion read here and the state machine refuses it if the
      # object has moved on.  Outside a request's barrier scope it changes
      # nothing.
      def cached_read
        scope = Thread.current[BARRIER_SCOPE_KEY]
        return yield unless scope

        previous = scope[:cached]
        scope[:cached] = true
        begin
          yield
        ensure
          scope[:cached] = previous
        end
      end

      # The barrier ahead of a read of +key+.  When it ran, the replica has
      # just been brought up to the leader's commit index: the watch cache
      # waiting to be fresh (apiserver_watch_cache_read_wait_seconds), which
      # etcd answers with a progress notification (etcd_bookmark_total --
      # the raft log has no watch stream, the read index is its "you are
      # current up to revision N"), after which the resource's cache is at
      # the current revision.
      def read_barrier(key)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        record_read_barrier(key, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) if barrier && @metrics
      end

      def record_read_barrier(key, elapsed)
        group, resource = Rubernetes::Storage::MemoryStore.group_resource(key)
        labels = {"group" => group, "resource" => resource}
        @metrics.observe("apiserver_watch_cache_read_wait_seconds", elapsed, labels)
        # (etcd_bookmark_counts, its deprecated twin, is hidden in 1.36.)
        @metrics.increment("etcd_bookmark_total", labels)
        @metrics.set("apiserver_watch_cache_resource_version", local_store.revision % 1_000_000_000_000_000, labels)
      rescue StandardError
        nil
      end

      # true when a read index was taken, false when the request's barrier
      # already covers this read.
      def barrier
        scope = Thread.current[BARRIER_SCOPE_KEY]
        return false if scope && (scope[:taken] || scope[:cached])

        attempts = 0
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          @server.read_index(timeout: @timeout)
          scope[:taken] = true if scope
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
          record_phase("barrier", elapsed)
          # A linearizable read that waited this long is the whole story of a
          # slow GET; nothing else on the request path logs it.
          if elapsed >= SLOW_BARRIER_SECONDS && @server.respond_to?(:logger) && @server.logger
            @server.logger.warn("consensus.barrier_slow", seconds: elapsed.round(3), attempts: attempts + 1, leader: @server.leader?)
          end
          true
        rescue Rubernetes::Consensus::Timeout
          attempts += 1
          # Still a momentary condition after the retries: 503 + Retry-After.
          # Not Storage::Unavailable: Rubernetes::Consensus::Storage is a class
          # of its own and shadows Rubernetes::Storage here, so that spelling
          # raised NameError instead of the 503 this path exists to produce.
          raise Unavailable, "read index timed out" if attempts >= BARRIER_ATTEMPTS

          sleep(0.05 * attempts)
          retry
        end
      end

      private

      def historical?(resource_version, options)
        value = options.key?(:at_revision) ? options[:at_revision] : resource_version
        !(value.nil? || value == "" || value == 0 || value == "0")
      end

      # Per-request phase accounting (API::Server request tracing).
      def record_phase(name, seconds)
        phases = Thread.current[:rubernetes_request_phases]
        return unless phases

        phases[name] = phases.fetch(name, 0.0) + seconds
      end

      # RUBERNETES_TRACE_RAFT=1 logs every write this store acknowledges
      # with the position it was applied at ("consensus.trace.ack"), so a
      # write can be followed from the API request through the log to every
      # replica's "consensus.trace.apply".
      TRACE = KVStateMachine::TRACE

      def submit(command, effect:, key:)
        # A read after this write must observe it: take a fresh barrier.
        Thread.current[BARRIER_SCOPE_KEY]&.store(:taken, false)
        proposal_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        # The proposal id identifies one exact command; the store-level
        # request UID (S6) is what deduplicates retries with the same intent.
        # A different command reusing a UID must reach the state machine so
        # it can reject it as a UID conflict instead of being absorbed here.
        request_id = "#{command["request_uid"] || SecureRandom.uuid}:#{Canonical.digest(command)[0, 16]}"
        @journal&.record_request(request_id: request_id, effect: effect, key: key, command: command)
        position = Thread.current[Server::POSITION_KEY] = {}
        result = begin
          @server.propose(command, request_id: request_id, timeout: @timeout)
        rescue Rubernetes::Consensus::Error => error
          @journal&.record_outcome(request_id: request_id, state: "unknown", error: error)
          raise Unavailable.new(error.message) if TRANSIENT_CONSENSUS_ERRORS.any? { |klass| error.is_a?(klass) }

          raise
        ensure
          Thread.current[Server::POSITION_KEY] = nil
          record_phase("propose", Process.clock_gettime(Process::CLOCK_MONOTONIC) - proposal_started)
        end
        @journal&.record_outcome(request_id: request_id, state: result["ok"] ? "applied" : "rejected", result: result)
        raise ArgumentError, "consensus returned no result" unless result.is_a?(Hash)

        verify_acknowledgement(request_id, effect, key, result, position)
        return result["object"] if result["ok"]

        raise map_error(result.fetch("error"))
      end

      # The acknowledgement invariant, checked at the moment of the ack: a
      # create or update the state machine reported as applied at revision
      # R must be readable at revision R on this replica right now.  It is
      # one keyed lookup under the store's monitor.  A breach is logged with
      # everything needed to find the entry ("consensus.ack_without_object");
      # the caller still gets the result the state machine produced.
      def verify_acknowledgement(request_id, effect, key, result, position)
        logger = @server.respond_to?(:logger) ? @server.logger : nil
        ok = result["ok"] == true
        revision = ok && result["object"].is_a?(Hash) ? result["object"].dig("metadata", "resourceVersion") : nil
        if TRACE && logger
          logger.info("consensus.trace.ack", request_id: request_id, effect: effect, key: key, ok: ok, revision: revision,
                                             index: position[:index], term: position[:term], via: position[:via].to_s,
                                             error: ok ? nil : result.dig("error", "class"))
        end
        return unless ok && revision && %w[create update].include?(effect)

        begin
          local_store.get(key, resource_version: revision)
        rescue Rubernetes::Storage::NotFound, Rubernetes::Storage::InvalidResourceVersion => error
          # NotFound: the key does not exist as of the acknowledged revision.
          # InvalidResourceVersion: the store has not even reached that
          # revision, so the entry cannot have been applied here.
          logger&.error("consensus.ack_without_object", request_id: request_id, effect: effect, key: key, revision: revision,
                                                        index: position[:index], term: position[:term], via: position[:via].to_s,
                                                        store_revision: local_store.revision, last_applied: @server.node.last_applied,
                                                        error: "#{error.class}: #{error.message}")
        rescue Rubernetes::Storage::Error
          # Compacted away: not a missing object.
          nil
        end
      end

      def map_error(document)
        klass = ERROR_CLASSES.fetch(document["class"], Error)
        case klass.name
        when "Rubernetes::Storage::NotFound", "Rubernetes::Storage::AlreadyExists"
          klass.new(document["key"], document["message"])
        when "Rubernetes::Storage::Conflict"
          klass.new(document["key"], document["message"], resource_version: document["resource_version"])
        when "Rubernetes::Storage::RequestUIDConflict"
          # Keep the server's UID and message: reconstructing with a
          # blank UID hides which request actually collided.
          klass.new(document["request_uid"], document["key"], document["message"])
        when "Rubernetes::Storage::Gone"
          klass.new(document["resource_version"], document["compacted_revision"])
        when "Rubernetes::Storage::InvalidResourceVersion"
          klass.new(document["message"])
        else
          Error.new(document["message"], status: document["status"], reason: document["reason"], key: document["key"],
                                         resource_version: document["resource_version"], details: document["details"], causes: document["causes"])
        end
      end

      def check_precondition!(key, object, expected)
        return if expected.nil?

        expected_version, expected_uid = if expected.is_a?(Hash)
                                           [expected[:resourceVersion] || expected["resourceVersion"], expected[:uid] || expected["uid"]]
                                         else
                                           [expected, nil]
                                         end
        current_version = object.dig("metadata", "resourceVersion")
        if !expected_version.nil? && String(expected_version) != current_version.to_s
          raise Conflict.new(key, "expected resourceVersion #{expected_version.inspect}, current is #{current_version.inspect}",
                             resource_version: current_version)
        end

        current_uid = object.dig("metadata", "uid")
        return unless !expected_uid.nil? && String(expected_uid) != current_uid.to_s

        raise Conflict.new(key, "expected uid #{expected_uid.inspect}, current is #{current_uid.inspect}",
                           resource_version: current_version)
      end

      def precondition_conflict?(error, expected)
        expected_version = expected.is_a?(Hash) ? (expected[:resourceVersion] || expected["resourceVersion"]) : expected
        !expected_version.nil? && error.resource_version.to_s != String(expected_version)
      end

      def sleep_for_retry(attempt)
        ceiling = [MIN_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS].min
        @sleeper.call(@random.rand * ceiling)
      end

      def normalize_key(key)
        value = String(key)
        raise ArgumentError, "key must not be empty" if value.empty?

        value
      end

      def discard(options, *names)
        names.each do |name|
          options.delete(name)
          options.delete(name.to_s)
        end
      end
    end
  end
end
