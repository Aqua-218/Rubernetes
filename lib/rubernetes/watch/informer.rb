# frozen_string_literal: true

require "thread"
require_relative "delta_fifo"
require_relative "indexer"
require_relative "work_queue"
require_relative "reflector"

module Rubernetes
  module Watch
    # Shared list/watch cache pipeline:
    # Reflector -> DeltaFIFO -> immutable Indexer -> handlers -> WorkQueue.
    class Informer
      DEFAULT_RESYNC_PERIOD = 600.0
      EVENT_TYPES = %i[add update delete sync].freeze

      attr_reader :indexer, :queue, :reflector, :resync_period, :fifo

      def initialize(client:, resource:, namespace: :all, selector: nil, key_func: nil,
                     resync_period: DEFAULT_RESYNC_PERIOD,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     sleeper: ->(seconds) { sleep(seconds) }, indexer: nil, queue: nil,
                     error_handler: nil, name: nil)
        raise ArgumentError, "client is required" unless client
        raise ArgumentError, "resource is required" if resource.nil? || resource.to_s.empty?
        raise ArgumentError, "clock must respond to call" unless clock.respond_to?(:call)
        raise ArgumentError, "sleeper must respond to call" unless sleeper.respond_to?(:call)
        raise ArgumentError, "error_handler must respond to call" if error_handler && !error_handler.respond_to?(:call)

        @clock = clock
        @sleeper = sleeper
        @resource_name = resource.respond_to?(:kind) ? resource.kind.to_s : resource.to_s
        @metric_labels = informer_metric_labels(resource, name)
        @handler_stats = {seconds: 0.0, events: 0, max: 0.0}
        @resync_period = Float(resync_period)
        raise ArgumentError, "resync_period must be non-negative" if @resync_period.negative? || !@resync_period.finite?
        @indexer = indexer || Indexer.new(key_func: key_func)
        @queue = queue || WorkQueue.new(clock: clock, sleeper: sleeper)
        raise ArgumentError, "indexer must implement upsert, get, delete, and each" unless
          %i[upsert get delete each].all? { |method| @indexer.respond_to?(method) }
        raise ArgumentError, "queue must implement add, get, done, and shutdown" unless
          %i[add get done shutdown].all? { |method| @queue.respond_to?(method) }
        @fifo = DeltaFIFO.new(key_func: key_func, clock: clock)
        @handlers = EVENT_TYPES.to_h { |event| [event, []] }
        # The reflector is where a watch actually breaks, so the caller's
        # error handler has to reach it; without this the handler only ever
        # saw delta-processing failures and a dead watch stayed silent.
        @reflector = Reflector.new(client: client, fifo: @fifo, resource: resource, namespace: namespace,
                                   selector: selector, clock: clock, sleeper: sleeper, key_func: key_func,
                                   error_handler: error_handler)
        @error_handler = error_handler
        @mutex = Mutex.new
        @running = false
        @stopping = false
        @thread = nil
        @last_resync = @clock.call
        @last_error = nil
        @last_versions = {}
      end

      def on(event = nil, &handler)
        raise ArgumentError, "event handler block is required" unless handler

        events = event.nil? ? EVENT_TYPES : Array(event).map { |value| value.to_sym }
        unknown = events.reject { |name| EVENT_TYPES.include?(name) }
        raise ArgumentError, "unknown informer event #{unknown.first.inspect}" unless unknown.empty?
        @mutex.synchronize { events.each { |name| @handlers.fetch(name) << handler } }
        self
      end

      alias add_event_handler on

      # Perform one deterministic list/watch/drain cycle.  This API is useful
      # for tests and embedded control loops that own their scheduling thread.
      def run_once
        @reflector.list! if @reflector.resource_version.nil?
        drain_fifo
        maybe_resync
        @reflector.watch_once
        drain_fifo
        maybe_resync
        self
      end

      # Run until stop.  The Reflector owns reconnect backoff in its own thread;
      # this thread only drains deltas and schedules periodic resyncs.
      def run
        start(thread: false)
      end

      def start(thread: true)
        unless thread
          @mutex.synchronize do
            return self if @running
            raise RuntimeError, "Informer is stopped" if @stopping

            @running = true
          end
          return run_loop
        end

        @mutex.synchronize do
          return self if @running
          raise RuntimeError, "Informer is stopped" if @stopping

          @running = true
          begin
            @thread = Thread.new { run_loop }
          rescue StandardError
            @running = false
            @stopping = true
            raise
          end
        end
        self
      end

      def stop(join: true)
        thread = @mutex.synchronize do
          @running = false
          @stopping = true
          @thread
        end
        @reflector.stop
        @queue.shutdown
        @fifo.shutdown
        thread.join if join && thread && thread != Thread.current
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

      def last_error
        @mutex.synchronize { @last_error }
      end

      def sync(object)
        @fifo.sync(object)
        drain_fifo
        self
      end

      # Force all currently cached objects back through the Sync handler and
      # queue.  Updating the timestamp after enqueueing prevents a failed
      # resync from pretending that the cache was refreshed.
      def resync!
        @indexer.each { |object| @fifo.sync(object) }
        drain_fifo
        @mutex.synchronize { @last_resync = @clock.call }
        self
      end

      alias resync resync!

      private

      # How long an idle informer blocks waiting for its next delta before
      # looping to re-check resync and shutdown.
      FIFO_WAIT_SECONDS = 0.25

      def run_loop
        return unless running?

        begin
          return unless running?
          @reflector.list! if @reflector.resource_version.nil?
          drain_fifo
        rescue StandardError => error
          report_error(error)
        end
        begin
          @reflector.start(thread: true) if running?
        rescue StandardError => error
          report_error(error)
          return self
        end
        # An idle informer waits for its next delta rather than polling for
        # it.  Polling every millisecond costs a wakeup per informer per
        # millisecond -- with one informer per watched resource that is tens
        # of thousands of wakeups a second on an idle control plane, and the
        # reconcile loop competes with it for the interpreter.  The bounded
        # wait still lets the resync deadline be checked regularly.
        while running?
          begin
            drain_fifo(wait: FIFO_WAIT_SECONDS)
            maybe_resync
          rescue StandardError => error
            report_error(error)
          end
        end
      ensure
        @reflector.stop
        @queue.shutdown
        @fifo.shutdown
        @mutex.synchronize { @running = false }
      end

      # Returns how many keys were processed.  `wait` is how long the first
      # pop may block for the next delta; the rest of the batch is drained
      # without waiting.
      def drain_fifo(wait: 0)
        processed = 0
        first = true
        loop do
          item = @fifo.pop(timeout: first ? wait : 0)
          first = false
          break unless item

          key, deltas = item
          begin
            deltas.each { |delta| process_delta(delta) }
          rescue StandardError
            @fifo.requeue(key, deltas)
            raise
          else
            @fifo.done(key)
            processed += 1
          end
        end
        processed
      end

      def process_delta(delta)
        return if stale_delta?(delta)

        case delta.type
        when :add, :sync
          @indexer.upsert(delta.object)
          notify(delta.type, delta.object, delta.old_object)
        when :update
          previous = delta.old_object || @indexer.get(delta.key)
          @indexer.upsert(delta.object)
          notify(:update, delta.object, previous)
        when :delete
          previous = @indexer.delete(delta.key) || delta.object
          notify(:delete, previous, nil)
        else
          raise ArgumentError, "unknown delta type #{delta.type.inspect}"
        end
        remember_version(delta)
        @queue.add(delta.key)
      end

      def stale_delta?(delta)
        candidate = delta.resource_version || Support.resource_version(delta.object)
        return false if candidate.nil?

        # Only versions THIS informer delivered count as seen.  The indexer
        # is also written through by the controller manager's store adapter
        # right after a create, so the object's own ADDED event arrived with
        # the version already in the cache, was judged stale and dropped, and
        # no handler ran: a ReplicaSet the deployment controller had just
        # created was never reconciled, and four Deployments sat at 0 Pods for
        # five minutes ("rollover", "RecreateDeployment", the session-affinity
        # and admission-webhook BeforeEach deployments).
        previous = @mutex.synchronize { @last_versions[delta.key] }
        return false if previous.nil?

        candidate_number = Support.numeric_version(candidate)
        previous_number = Support.numeric_version(previous)
        return candidate_number < previous_number if delta.type == :sync && !candidate_number.nil? && !previous_number.nil?
        return candidate_number <= previous_number unless candidate_number.nil? || previous_number.nil?

        delta.type == :sync ? false : candidate.to_s == previous.to_s
      end

      def remember_version(delta)
        candidate = delta.resource_version || Support.resource_version(delta.object)
        return if candidate.nil?

        @mutex.synchronize do
          previous = @last_versions[delta.key]
          if previous.nil? || Support.version_newer?(candidate.to_s, previous.to_s)
            @last_versions[delta.key] = candidate.to_s.freeze
          end
        end
      end

      def notify(type, object, old_object)
        handlers = @mutex.synchronize { @handlers.fetch(type == :sync ? :sync : type).dup }
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        handlers.each do |handler|
          # A handler that takes a third parameter also learns the event type
          # (:add, :update, :delete, :sync); client-go hands controllers
          # separate Add/Update/Delete funcs, and some -- the quota
          # controller -- must act differently per type.
          if handler.arity == 3 || handler.arity < -2 || handler.parameters.length >= 3
            handler.call(object, type == :update ? old_object : nil, type)
          elsif type == :update
            handler.call(object, old_object)
          else
            handler.call(object)
          end
        end
      ensure
        if started
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
          @mutex.synchronize do
            @handler_stats[:seconds] += elapsed
            @handler_stats[:events] += 1
            @handler_stats[:max] = elapsed if elapsed > @handler_stats[:max]
          end
        end
      end

      # Events waiting in the FIFO and the time handlers took since the last
      # call.  Every event of a kind is delivered by one thread, so one slow
      # handler delays all of them: the controller manager's Pod informer was
      # found delivering events three minutes late, and nothing but these
      # numbers says which informer has fallen behind.
      # Public: the controller manager's status line reads it.  It sat below
      # `private`, so respond_to? was false, the status monitor never read a
      # single informer, and informers_behind was [] through every stall.
      public def take_delivery_stats
        stats = @mutex.synchronize do
          taken = @handler_stats
          @handler_stats = {seconds: 0.0, events: 0, max: 0.0}
          taken
        end
        {resource: @resource_name, backlog: @fifo.length, events: stats[:events],
         handler_seconds: stats[:seconds].round(3), handler_max: stats[:max].round(3)}
      end

      def maybe_resync
        return if @resync_period.zero?

        now = @clock.call
        previous = @mutex.synchronize { @last_resync }
        return if now - previous < @resync_period

        resync!
      end

      def report_error(error)
        @mutex.synchronize { @last_error = error }
        return unless @error_handler

        @error_handler.call(error)
      rescue StandardError => handler_error
        @mutex.synchronize { @last_error = handler_error }
      end
    end
  end
end
