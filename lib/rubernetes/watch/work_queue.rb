# frozen_string_literal: true

module Rubernetes
  module Watch
    # Deduplicating, dirty-key aware work queue.  A key is represented at most
    # once in the waiting set; a write while it is processing marks it dirty so
    # completion schedules exactly one follow-up reconciliation.
    class WorkQueue
      DEFAULT_BASE_DELAY = 0.005
      DEFAULT_MAX_DELAY = 1_000.0
      MIN_BASE_DELAY = 0.005
      MAX_RETRY_DELAY = 1_000.0
      DEFAULT_BUCKET_CAPACITY = 100.0
      DEFAULT_BUCKET_RATE = 10.0

      def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     sleeper: ->(seconds) { sleep(seconds) }, base_delay: DEFAULT_BASE_DELAY,
                     max_delay: DEFAULT_MAX_DELAY, bucket_capacity: DEFAULT_BUCKET_CAPACITY,
                     bucket_rate: DEFAULT_BUCKET_RATE, name: nil)
        raise ArgumentError, "clock must respond to call" unless clock.respond_to?(:call)
        raise ArgumentError, "sleeper must respond to call" unless sleeper.respond_to?(:call)

        @clock = clock
        @sleeper = sleeper
        @base_delay = positive_float(base_delay, "base_delay")
        raise ArgumentError, "base_delay must be at least #{MIN_BASE_DELAY} seconds" if @base_delay < MIN_BASE_DELAY

        @max_delay = Float(max_delay)
        raise ArgumentError, "max_delay must be at least base_delay" if @max_delay < @base_delay
        raise ArgumentError, "max_delay must not exceed #{MAX_RETRY_DELAY} seconds" if @max_delay > MAX_RETRY_DELAY
        raise ArgumentError, "max_delay must be finite" unless @max_delay.finite?

        @bucket_capacity = positive_float(bucket_capacity, "bucket_capacity")
        @bucket_rate = positive_float(bucket_rate, "bucket_rate")
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @queue = []
        @queued = {}
        # Keys whose current queue entry came from add_after: scheduled work
        # (a timed resync or progress deadline), distinct from a retry.
        @timed = {}
        @processing = {}
        @dirty = {}
        @requeues = Hash.new(0)
        @ready_at = {}
        @tokens = @bucket_capacity
        @last_refill = @clock.call
        @next_token_at = @last_refill
        @closed = false
        # How long keys sat waiting before a worker picked them up.  A control
        # loop that has fallen behind and one that is idle look identical from
        # queue depth alone -- depth stays low when the keys arrive slowly and
        # each one waits a long time -- so the wait itself has to be measured.
        @wait_total = 0.0
        @wait_max = 0.0
        @wait_count = 0
        # workqueue metrics (client-go util/workqueue metrics.go) under this
        # queue's name; an unnamed queue reports nothing.
        @name = name&.to_s
        @added_at = {}
        @started_at = {}
        register_metrics if @name
      end

      attr_reader :base_delay, :max_delay, :bucket_capacity, :bucket_rate, :name

      # ExponentialBuckets(10e-9, 10, 12).
      # component-base/metrics/prometheus/workqueue: ExponentialBuckets(10e-9,
      # 10, 10) -- ten bounds, each the previous times ten in floating point
      # (so 9.999999999999999e-06, not 1e-05).
      DURATION_BUCKETS = Array.new(10).each_with_object([]) { |_, bounds| bounds << (bounds.empty? ? 1e-8 : bounds.last * 10) }.freeze

      def add(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @timed.delete(normalized) }
        enqueue(normalized, ready_at: @clock.call)
      end

      def add_after(key, delay)
        normalized_delay = non_negative_float(delay, "delay")
        normalized = normalize_key(key)
        @mutex.synchronize do
          raise IOError, "WorkQueue is shut down" if @closed

          already_queued = @queued.key?(normalized) && !@timed.key?(normalized)
          enqueue_locked(normalized, ready_at: @clock.call + normalized_delay)
          # An immediate entry already waiting keeps its immediate nature.
          @timed[normalized] = true unless already_queued
          @condition.broadcast
        end
        self
      end

      # Combine per-key exponential backoff with a process-wide token bucket.
      # The token is consumed for every retry, including calls made by
      # concurrent workers, so a hot failing key cannot exhaust upstream.
      def add_rate_limited(key)
        normalized = normalize_key(key)
        delay = @mutex.synchronize do
          raise IOError, "WorkQueue is shut down" if @closed

          now = @clock.call
          @timed.delete(normalized)
          metric(:increment, "workqueue_retries_total", {"name" => @name}) if @name
          count = @requeues[normalized] += 1
          exponential = [@base_delay * (2**[count - 1, 30].min), @max_delay].min
          token_delay = reserve_token_locked(now)
          enqueue_locked(normalized, ready_at: now + exponential + token_delay)
          @condition.broadcast
          [exponential + token_delay, exponential, token_delay]
        end
        delay.first
      end

      def get(timeout: nil)
        timeout_value = timeout.nil? ? nil : non_negative_float(timeout, "timeout")
        deadline = timeout_value.nil? ? nil : @clock.call + timeout_value
        wall_deadline = timeout_value.nil? ? nil : Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_value
        @mutex.synchronize do
          loop do
            return [nil, true] if @closed

            key = ready_key_locked
            if key
              @queue.delete_at(@queue.index(key) || 0)
              @queued.delete(key)
              @timed.delete(key)
              ready = @ready_at.delete(key)
              record_wait_locked(ready)
              @processing[key] = true
              metrics_get_locked(key)
              return [key, false]
            end

            return [nil, false] if deadline && (@clock.call >= deadline || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= wall_deadline)

            wait_for_work_locked(deadline, wall_deadline)
          end
        end
      end

      def done(key)
        normalized = normalize_key(key)
        @mutex.synchronize do
          @processing.delete(normalized)
          metrics_done_locked(normalized)
          if @closed
            @dirty.delete(normalized)
            @ready_at.delete(normalized)
          elsif @dirty.delete(normalized)
            enqueue_locked(normalized, ready_at: @ready_at.delete(normalized) || @clock.call)
          else
            @ready_at.delete(normalized)
          end
          @condition.broadcast
        end
        self
      end

      def forget(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @requeues.delete(normalized) }
        self
      end

      def num_requeues(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @requeues.fetch(normalized, 0) }
      end

      alias requeue_count num_requeues

      def dirty?(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @dirty.key?(normalized) }
      end

      def processing?(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @processing.key?(normalized) }
      end

      def queued?(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @queued.key?(normalized) }
      end

      # {count:, average:, max:} since the last call, then reset -- a gauge a
      # status loop can log without accumulating for ever.
      def take_wait_stats
        @mutex.synchronize do
          stats = {count: @wait_count,
                   average: @wait_count.zero? ? 0.0 : (@wait_total / @wait_count),
                   max: @wait_max}
          @wait_total = 0.0
          @wait_max = 0.0
          @wait_count = 0
          stats
        end
      end

      def ready_at(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @ready_at[normalized] }
      end

      def shut_down
        shutdown
      end

      def shutdown
        @mutex.synchronize do
          @closed = true
          @queue.clear
          @queued.clear
          @dirty.clear
          @ready_at.clear
          @requeues.clear
          @condition.broadcast
        end
        self
      end

      alias close shutdown

      def shutdown?
        @mutex.synchronize { @closed }
      end

      alias shut_down? shutdown?

      def length
        @mutex.synchronize { @queue.length + @processing.length }
      end

      alias size length

      def depth
        @mutex.synchronize { @queue.length }
      end

      # True when +key+ is queued for a future ready time rather than
      # immediately runnable.
      def delayed?(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @queued.key?(normalized) && @timed.key?(normalized) }
      end

      # Keys waiting for a future ready time (add_after / rate-limited
      # backoff); they are queued but not yet runnable.
      def delayed_length
        @mutex.synchronize { @queue.count { |key| @timed.key?(key) } }
      end

      def empty?
        length.zero?
      end

      def keys
        @mutex.synchronize { (@queue + @processing.keys).uniq.freeze }
      end

      private

      def enqueue(key, ready_at:)
        @mutex.synchronize do
          raise IOError, "WorkQueue is shut down" if @closed

          enqueue_locked(key, ready_at: ready_at)
          @condition.broadcast
        end
        self
      end

      def enqueue_locked(key, ready_at:)
        if @processing.key?(key)
          metrics_add_locked(key) unless @dirty.key?(key)
          @dirty[key] = true
          @ready_at[key] ||= ready_at
        elsif !@queued.key?(key)
          metrics_add_locked(key)
          @queued[key] = true
          @ready_at[key] = ready_at
          @queue << key
        elsif ready_at < @ready_at.fetch(key, ready_at)
          @ready_at[key] = ready_at
        end
      end

      # FIFO among the keys whose delay has elapsed.  client-go's workqueue
      # pops q.queue[0] -- the oldest item -- and nothing else
      # (util/workqueue/queue.go Type.Get); a delayed item only joins the queue
      # once its time has come.  Ordering by the key STRING instead made the
      # queue unfair in a way that shows up only under load: with keys
      # arriving faster than they drain, a key late in the alphabet is
      # overtaken by every new key that sorts before it.  A new namespace
      # called "lat1-24438" waited 38 seconds for its default ServiceAccount
      # while "conformance/..." and "endpointslice-..." keys went first.
      def ready_key_locked
        now = @clock.call
        @queue.find { |key| @ready_at.fetch(key, now) <= now }
      end

      def registry
        return nil unless defined?(Rubernetes::Observability::Metrics)

        Rubernetes::Observability::Metrics.global
      end

      def metric(action, name, labels, value = nil)
        registry = self.registry
        return unless registry

        if action == :observe
          registry.observe(name, value,
                           labels)
        else
          registry.public_send(action, name, labels, **(value ? {by: value} : {}))
        end
      rescue StandardError
        nil
      end

      def register_metrics
        registry = self.registry
        return unless registry

        {"workqueue_adds_total" => [:counter, "Total number of adds handled by workqueue"],
         "workqueue_depth" => [:gauge, "Current depth of workqueue"],
         "workqueue_retries_total" => [:counter, "Total number of retries handled by workqueue"],
         "workqueue_unfinished_work_seconds" => [:gauge,
                                                 "How many seconds of work has done that is in progress and hasn't been observed by work_duration. Large values indicate stuck threads. One can deduce the number of stuck threads by observing the rate at which this increases."],
         "workqueue_longest_running_processor_seconds" => [:gauge,
                                                           "How many seconds has the longest running processor for workqueue been running."]}.each do |metric_name, (type, help)|
          registry.register(metric_name, type: type, help: help)
        end
        registry.register("workqueue_queue_duration_seconds", type: :histogram, buckets: DURATION_BUCKETS,
                                                              help: "How long in seconds an item stays in workqueue before being requested.")
        registry.register("workqueue_work_duration_seconds", type: :histogram, buckets: DURATION_BUCKETS,
                                                             help: "How long in seconds processing an item from workqueue takes.")
        registry.set("workqueue_depth", 0, {"name" => @name})
        queue = self
        registry.add_collector { |metrics| queue.send(:collect_processing, metrics) }
      end

      # queueMetrics.add / get / done.
      def metrics_add_locked(key)
        return unless @name

        @added_at[key] ||= Process.clock_gettime(Process::CLOCK_MONOTONIC)
        metric(:increment, "workqueue_adds_total", {"name" => @name})
        metric(:increment, "workqueue_depth", {"name" => @name})
      end

      def metrics_get_locked(key)
        return unless @name

        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        metric(:increment, "workqueue_depth", {"name" => @name}, -1)
        added = @added_at.delete(key)
        metric(:observe, "workqueue_queue_duration_seconds", {"name" => @name}, now - added) if added
        @started_at[key] = now
      end

      def metrics_done_locked(key)
        return unless @name

        started = @started_at.delete(key)
        return unless started

        metric(:observe, "workqueue_work_duration_seconds", {"name" => @name},
               Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
      end

      # updateUnfinishedWork: the in-flight processing, at scrape time.
      def collect_processing(metrics)
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        running = @mutex.synchronize { @started_at.values.map { |started| now - started } }
        metrics.set("workqueue_unfinished_work_seconds", running.sum, {"name" => @name})
        metrics.set("workqueue_longest_running_processor_seconds", running.max || 0, {"name" => @name})
      end

      def record_wait_locked(ready)
        return if ready.nil?

        waited = @clock.call - ready
        return if waited.negative?

        @wait_total += waited
        @wait_max = waited if waited > @wait_max
        @wait_count += 1
      end

      def wait_for_work_locked(deadline, wall_deadline)
        now = @clock.call
        next_ready = @queue.map { |key| @ready_at.fetch(key, now) }.min
        wait_for = next_ready && [next_ready - now, 0].max
        wait_for = deadline - now if deadline && wait_for.nil?
        wait_for = [wait_for, deadline - now].min if deadline && wait_for
        wall_wait = wall_deadline && (wall_deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC))
        wait_for = wall_wait if wait_for.nil? && wall_wait
        wait_for = [wait_for, wall_wait].min if wall_wait && wait_for
        return if wait_for && wait_for <= 0

        @condition.wait(@mutex, wait_for)
      end

      def reserve_token_locked(now)
        elapsed = now - @last_refill
        if elapsed.positive?
          @tokens = [@bucket_capacity, @tokens + (elapsed * @bucket_rate)].min
          @last_refill = now
        end
        if @tokens >= 1.0 && @next_token_at <= now
          @tokens -= 1.0
          @next_token_at = now
          return 0.0
        end

        interval = 1.0 / @bucket_rate
        token_ready_at = now + ([1.0 - @tokens, 0.0].max / @bucket_rate)
        slot = [token_ready_at, @next_token_at].max
        @tokens = 0.0
        @last_refill = slot
        @next_token_at = slot + interval
        slot - now
      end

      def normalize_key(key)
        normalized = String(key)
        raise ArgumentError, "work queue key must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "work queue key must be coercible to String"
      end

      def positive_float(value, name)
        number = Float(value)
        raise ArgumentError, "#{name} must be positive" unless number.positive? && number.finite?

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a positive finite number"
      end

      def non_negative_float(value, name)
        number = Float(value)
        raise ArgumentError, "#{name} must be non-negative" if number.negative? || !number.finite?

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a non-negative finite number"
      end
    end
  end
end
