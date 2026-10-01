# frozen_string_literal: true

require "json"

require_relative "../cleanup"
require_relative "status"
require_relative "pod_worker"

module Rubernetes
  module Node
    # Event-driven Pod synchronizer with a periodic full resync.  The source
    # adapter may be an API watch, a static-Pod source, or a deterministic test
    # double; the loop only relies on list/watch/close capabilities.
    class SyncLoop
      # How long a stop waits for in-flight Pod work before leaving it behind
      # (PodWorker#stop); the kubelet waits for none.  Bounded so SIGTERM
      # always ends the agent within the operator's restart window.
      STOP_DRAIN_TIMEOUT = Float(ENV.fetch("RUBERNETES_AGENT_STOP_DRAIN_SECONDS", 20))

      DEFAULT_RESYNC_PERIOD_SECONDS = 60
      # kubelet's syncLoop runs a housekeeping pass on a short timer that
      # re-syncs every Pod it knows about, from its own cache, without asking
      # the API server for anything.  That pass is what drives probes, restart
      # backoffs and retried starts; without it a Pod only ever reconciles when
      # its API object changes, so a container in CrashLoopBackOff waited for
      # the next watch event -- tens of seconds -- to be restarted, and a
      # liveness probe ran at the watch's cadence instead of its own period.
      DEFAULT_HOUSEKEEPING_PERIOD_SECONDS = 4

      Event = Data.define(:type, :object, :resource_version, :raw) do
        def to_h
          {
            "type" => type,
            "object" => Helpers.deep_copy(object),
            "resourceVersion" => resource_version
          }
        end
      end

      def initialize(source_value = nil, source: nil, api: nil, reconcile: nil, worker_pool: nil,
                     workers: nil, node_name: nil,
                     resync_period: DEFAULT_RESYNC_PERIOD_SECONDS,
                     housekeeping_period: DEFAULT_HOUSEKEEPING_PERIOD_SECONDS,
                     watch_timeout: 30, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     sleeper: ->(seconds) { sleep(seconds) }, error_handler: nil,
                     removed: nil, auto_start: false, &block)
        @source = source || api || source_value
        raise ArgumentError, "source or api is required" unless @source

        @reconcile = reconcile || block
        # Told at once, from the watch thread, when a Pod leaves the API --
        # before its worker gets to the DELETED (it may be busy killing it).
        @removed = removed
        raise ArgumentError, "reconcile callback or worker_pool is required" unless @reconcile || worker_pool || workers

        @node_name = node_name&.to_s
        @resync_period = Float(resync_period)
        raise ArgumentError, "resync_period must be positive" unless @resync_period.positive?

        @housekeeping_period = Float(housekeeping_period)
        raise ArgumentError, "housekeeping_period must be positive" unless @housekeeping_period.positive?

        @watch_timeout = Float(watch_timeout)
        @clock = clock
        @sleeper = sleeper
        @error_handler = error_handler
        @workers = worker_pool || workers || PodWorkerPool.new(reconcile: @reconcile, error_handler: error_handler)
        @mutex = Mutex.new
        @cache = {}
        @resource_version = nil
        @last_resync_at = nil
        @last_watch_at = nil
        @errors = []
        @running = false
        @stopping = false
        @thread = nil
        @housekeeping_thread = nil
        @last_housekeeping_at = nil
        @watcher = nil
        @started = false
        @stop_cleanup_pending = false
        start if auto_start
      end

      attr_reader :resource_version, :last_resync_at, :last_watch_at

      def start
        @mutex.synchronize do
          return self if @running
          raise "SyncLoop is stopped" if @stopping

          @running = true
          @started = true
        end
        @workers.start if @workers.respond_to?(:start)
        @thread = Thread.new { run_loop }
        @housekeeping_thread = Thread.new { housekeeping_loop }
        self
      end

      # Re-enqueue every Pod this node already knows about.  No API call: the
      # point is a steady local cadence that does not depend on the API server
      # producing an event.
      def housekeep(now: nil)
        timestamp = time_value(now)
        pods = @mutex.synchronize { @cache.values }
        pods.each { |pod| enqueue_pod(pod, action: "SYNC") }
        @mutex.synchronize { @last_housekeeping_at = timestamp }
        pods.length
      rescue StandardError => error
        record_error(error, event: "housekeeping")
        0
      end

      def housekeeping_due?(now = time_value(nil))
        @mutex.synchronize do
          @last_housekeeping_at.nil? || (now.to_f - @last_housekeeping_at.to_f >= @housekeeping_period)
        end
      end

      def stop(join: true)
        thread = nil
        watcher = @mutex.synchronize do
          return self unless @running || @thread || @stop_cleanup_pending

          @running = false
          @stopping = true
          thread = @thread
          @watcher
        end
        close_errors = []
        [watcher, @source].compact.uniq.each do |handle|
          next unless handle.respond_to?(:close)

          begin
            handle.close
          rescue StandardError => error
            # Continue closing every owned handle so one broken response does
            # not leave another stream blocking the watcher thread forever.
            close_errors.concat(Array(error.respond_to?(:cleanup_errors) ? error.cleanup_errors : error))
          end
        end
        housekeeping = @mutex.synchronize { @housekeeping_thread }
        begin
          if join && housekeeping && housekeeping != Thread.current
            housekeeping.kill
            housekeeping.join
          end
        rescue StandardError
          nil
        ensure
          @mutex.synchronize { @housekeeping_thread = nil if join }
        end
        begin
          thread.join if join && thread && thread != Thread.current
        rescue StandardError => error
          close_errors.concat(Array(error.respond_to?(:cleanup_errors) ? error.cleanup_errors : error))
        ensure
          @mutex.synchronize do
            @thread = nil if join && thread && @thread.equal?(thread) && !thread.alive?
            # Retain failed ownership handles for the next stop attempt. A
            # close failure is transient cleanup state, not proof that the
            # watcher was released.
            @watcher = nil if @watcher.equal?(watcher) && close_errors.empty?
          end
        end
        if @workers.respond_to?(:stop)
          begin
            @workers.stop(drain: true, join: join, timeout: STOP_DRAIN_TIMEOUT)
          rescue StandardError => error
            close_errors.concat(Array(error.respond_to?(:cleanup_errors) ? error.cleanup_errors : error))
          end
        end
        aggregate = Rubernetes::Cleanup.aggregate(close_errors, operation: "SyncLoop stop")
        @mutex.synchronize { @stop_cleanup_pending = !close_errors.empty? }
        raise aggregate if aggregate

        self
      end

      alias close stop

      def join
        @thread&.join
        self
      end

      def running?
        @mutex.synchronize { @running }
      end

      # A stopping loop clears its acceptance flag before joining the watcher
      # thread. Expose the actual thread liveness so shutdown callers can
      # distinguish "no new work" from "fully joined" and fail closed on a
      # leaked watcher.
      def thread_alive?
        @mutex.synchronize { !!@thread&.alive? }
      end

      def started?
        @mutex.synchronize { @started }
      end

      def cache
        @mutex.synchronize { @cache.transform_values { |pod| Helpers.immutable(pod) }.freeze }
      end

      def pods
        cache.values
      end

      def errors
        @mutex.synchronize { Helpers.deep_copy(@errors).freeze }
      end

      # Process one source watch batch and perform a resync when due.  This is
      # intentionally synchronous and is the preferred deterministic test API.
      def run_once(events: nil, now: nil, resync: true)
        timestamp = time_value(now)
        source_events = events || read_watch_batch
        Array(source_events).each { |event| process_event(event) }
        self.resync(now: timestamp) if resync && resync_due?(timestamp)
        self
      end

      alias tick run_once
      alias watch_once run_once

      def process_event(event)
        normalized = normalize_event(event)
        type = normalized.type
        if type == "ERROR"
          handle_watch_error(normalized)
          return normalized
        end
        if type == "BOOKMARK"
          update_resource_version(normalized.resource_version)
          return normalized
        end
        return normalized unless %w[ADDED MODIFIED DELETED].include?(type)

        pod = normalized.object
        uid = pod_uid(pod)
        previous = @mutex.synchronize { @cache[uid] }
        in_scope = pod_in_scope?(pod)
        if (type == "DELETED" && (in_scope || previous)) || (!in_scope && previous)
          @mutex.synchronize { @cache.delete(uid) }
          notify_removed(uid)
          enqueue_pod(previous || pod, action: "DELETED", request_id: normalized.resource_version)
        elsif in_scope
          @mutex.synchronize { @cache[uid] = Helpers.immutable(pod) }
          enqueue_pod(pod, action: type, request_id: normalized.resource_version)
        end
        update_resource_version(normalized.resource_version)
        normalized
      rescue StandardError => error
        record_error(error, event: event)
        raise
      end

      alias handle process_event
      alias dispatch process_event

      # List all Pods addressed to this node and reconcile additions, updates,
      # and disappeared objects.  A list is authoritative only for this sync;
      # an API watch remains the source of causally ordered changes.
      def resync(now: nil)
        timestamp = time_value(now)
        listed, listed_rv = list_pods
        current = {}
        Array(listed).each do |pod|
          next unless pod_in_scope?(pod)

          normalized = Helpers.immutable(pod)
          uid = pod_uid(normalized)
          current[uid] = normalized
          previous = @mutex.synchronize { @cache[uid] }
          action = previous.nil? ? "ADDED" : "MODIFIED"
          # kubelet's periodic sync visits every Pod, changed or not: that is
          # what retries a failed start, re-runs probes and re-publishes
          # status.  An unchanged Pod is still reconciled, only labelled as
          # a resync so the worker can coalesce it.
          enqueue_pod(normalized, action: action, request_id: listed_rv)
        end
        stale = @mutex.synchronize { @cache.keys - current.keys }
        stale.each do |uid|
          pod = @mutex.synchronize { @cache.fetch(uid) }
          enqueue_pod(pod, action: "DELETED", request_id: listed_rv)
        end
        # Keep the worker-owned cache mutable: freezing `current` after
        # assigning it would make the next watch ADDED/MODIFIED event fail
        # with FrozenError. The returned snapshot remains immutable without
        # freezing the live cache used by process_event.
        @mutex.synchronize { @cache = current.dup }
        update_resource_version(listed_rv)
        @mutex.synchronize { @last_resync_at = timestamp }
        current.freeze
      rescue StandardError => error
        record_error(error, event: "resync")
        raise
      end

      def resync_due?(now = time_value(nil))
        @mutex.synchronize do
          @last_resync_at.nil? || (now.to_f - @last_resync_at.to_f >= @resync_period)
        end
      end

      def notify_removed(uid)
        @removed&.call(uid)
      rescue StandardError => error
        record_error(error, event: "removed_hook")
      end

      def enqueue_pod(pod, action:, request_id: nil)
        if @workers.respond_to?(:enqueue)
          @workers.enqueue(pod, action: action, request_id: request_id)
        elsif @workers.respond_to?(:submit)
          @workers.submit(pod, action: action, request_id: request_id)
        else
          raise ArgumentError, "worker pool must implement enqueue or submit"
        end
      end

      private

      def housekeeping_loop
        while running?
          @sleeper.call(@housekeeping_period)
          break unless running?

          housekeep(now: time_value(nil))
        end
      rescue StandardError => error
        record_error(error, event: "housekeeping_loop")
      end

      # A failed resync is recorded and retried on the next pass; it must
      # not end the loop.  It did: the trailing resync ran outside the
      # per-watch rescue, so one failed list (a connection the server had
      # dropped) unwound to the outer rescue and the thread returned.  The
      # node then never heard of another Pod -- three DaemonSet Pods sat
      # Pending for five minutes with nothing in the agent's log, because the
      # error handler logs at debug.
      def run_loop
        # Initial list closes the startup gap between registration and watch.
        guarded_resync
        loop do
          break unless running?

          begin
            watcher = open_watcher
            accepted = @mutex.synchronize do
              next false unless @running

              @watcher = watcher
              @last_watch_at = time_value(nil)
              true
            end
            unless accepted
              watcher.close if watcher.respond_to?(:close)
              break
            end
            consume_watcher(watcher)
          rescue StandardError => error
            record_error(error, event: "watch")
            @sleeper.call([@resync_period, 1].min) if running?
          ensure
            @mutex.synchronize { @watcher = nil }
          end
          break unless running?

          guarded_resync
        end
      rescue StandardError => error
        record_error(error, event: "loop")
        @error_handler&.call(error)
      end

      def guarded_resync
        resync(now: time_value(nil)) if resync_due?
      rescue StandardError
        # Already recorded by resync; the next watch or pass retries.
        @sleeper.call([@resync_period, 1].min) if running?
      end

      def consume_watcher(watcher)
        return if watcher.nil?

        if watcher.respond_to?(:next)
          loop do
            break unless running?

            event = next_watch_event(watcher)
            break if event.nil?

            process_event(event)
            resync(now: time_value(nil)) if resync_due?
          end
        elsif watcher.respond_to?(:each)
          watcher.each do |event|
            break unless running?

            process_event(event)
            resync(now: time_value(nil)) if resync_due?
          end
        else
          raise ArgumentError, "watch must return an Enumerable or next-capable object"
        end
      ensure
        watcher.close if watcher.respond_to?(:close)
      end

      def read_watch_batch
        watcher = open_watcher
        return [] if watcher.nil?

        events = if watcher.respond_to?(:to_a)
                   watcher.to_a
                 elsif watcher.respond_to?(:next)
                   event = next_watch_event(watcher)
                   event.nil? ? [] : [event]
                 elsif watcher.respond_to?(:each)
                   watcher.each.to_a
                 else
                   raise ArgumentError, "watch must return an Enumerable or next-capable object"
                 end
        @mutex.synchronize { @last_watch_at = time_value(nil) }
        events
      ensure
        watcher.close if watcher && watcher.respond_to?(:close)
      end

      def open_watcher
        if @source.respond_to?(:watch)
          return @source.watch(node_name: @node_name, resource_version: @resource_version,
                               timeout: @watch_timeout)
        end
        if @source.respond_to?(:watch_pods)
          return @source.watch_pods(node_name: @node_name, resource_version: @resource_version,
                                    timeout: @watch_timeout)
        end

        nil
      rescue ArgumentError => error
        raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

        @source.respond_to?(:watch) ? @source.watch : @source.watch_pods
      end

      def next_watch_event(watcher)
        watcher.next(timeout: @watch_timeout)
      rescue ArgumentError => error
        raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

        watcher.next
      end

      def list_pods
        result = if @source.respond_to?(:list)
                   begin
                     @source.list(node_name: @node_name, resource_version: @resource_version)
                   rescue ArgumentError => error
                     raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

                     @source.list
                   end
                 elsif @source.respond_to?(:list_pods)
                   @source.list_pods(node_name: @node_name, resource_version: @resource_version)
                 else
                   raise ArgumentError, "source must implement list or list_pods"
                 end
        if result.respond_to?(:items)
          [result.items, result.respond_to?(:resource_version) ? result.resource_version : nil]
        elsif result.is_a?(Hash)
          [Helpers.key(result, "items", []),
           Helpers.key(Helpers.key(result, "metadata", {}), "resourceVersion", Helpers.key(result, "resourceVersion", nil))]
        else
          [Array(result), nil]
        end
      end

      def normalize_event(event)
        return event if event.is_a?(Event)

        raw = event
        raw = JSON.parse(event) if event.is_a?(String)
        if event.respond_to?(:type) && event.respond_to?(:object)
          type = event.type
          object = event.object
          rv = event.respond_to?(:resource_version) ? event.resource_version : nil
        else
          value = Helpers.string_keys(raw || {})
          type = Helpers.key(value, "type", "")
          object = Helpers.key(value, "object", value)
          metadata = Helpers.key(object, "metadata", {})
          rv = Helpers.key(value, "resourceVersion", Helpers.key(metadata, "resourceVersion", nil))
        end
        Event.new(type: type.to_s.upcase, object: Helpers.string_keys(object || {}),
                  resource_version: rv&.to_s, raw: raw).freeze
      rescue JSON::ParserError => error
        raise ArgumentError, "watch event is not valid JSON: #{error.message}"
      end

      def handle_watch_error(event)
        code = Helpers.key(event.object, "code", nil)
        reason = Helpers.key(event.object, "reason", nil)
        # A compacted watch must restart from a fresh list; preserving an
        # invalid resourceVersion would make every reconnect fail again.
        if code.to_i == 410 || reason.to_s == "Gone"
          @mutex.synchronize { @resource_version = nil }
          resync(now: time_value(nil))
        end
        record_error(RuntimeError.new("watch error #{reason || code || "unknown"}"), event: event.to_h)
      end

      def update_resource_version(value)
        return if value.nil? || value.to_s.empty?

        @mutex.synchronize { @resource_version = value.to_s }
      end

      def pod_in_scope?(pod)
        return true if @node_name.nil? || @node_name.empty?

        spec = Helpers.key(pod, "spec", {})
        Helpers.key(spec, "nodeName", nil).to_s == @node_name
      end

      def pod_uid(pod)
        return pod.to_s unless pod.is_a?(Hash)

        metadata = Helpers.key(pod, "metadata", {})
        uid = Helpers.key(metadata, "uid", nil)
        return uid.to_s unless uid.nil? || uid.to_s.empty?

        "#{Helpers.key(metadata, "namespace", "default")}/#{Helpers.key(metadata, "name", "")}"
      end

      def canonical_digest(value)
        require "digest"
        Digest::SHA256.hexdigest(Marshal.dump(value))
      end

      def record_error(error, event: nil)
        serialized = {"class" => error.class.name, "message" => error.message}
        serialized["event"] = Helpers.deep_copy(event) unless event.nil?
        @mutex.synchronize { @errors << serialized }
        @error_handler&.call(error, event)
      end

      def time_value(value)
        return value if value.is_a?(Numeric)
        return value.to_f if value.respond_to?(:to_f) && !value.nil?

        sampled = @clock.call
        sampled.respond_to?(:to_f) ? sampled.to_f : Float(sampled)
      end

      def close_watcher
        return unless @watcher && @watcher.respond_to?(:close)

        @watcher.close
      end
    end
  end
end
