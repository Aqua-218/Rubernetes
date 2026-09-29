# frozen_string_literal: true

require "thread"

module Rubernetes
  module Scheduler
    # QueueSort implementation corresponding to Kubernetes' PrioritySort
    # plugin.  Creation time is the first stable tie-breaker, while identity
    # remains a deterministic fallback for synthetic Pods without timestamps.
    class PrioritySort
      def name
        "PrioritySort"
      end

      def less(left, right)
        left_key = sort_key(pod_for(left))
        right_key = sort_key(pod_for(right))
        left_key < right_key
      end

      def compare(left, right)
        left_key = sort_key(pod_for(left))
        right_key = sort_key(pod_for(right))
        left_key <=> right_key
      end

      private

      def pod_for(value)
        value.respond_to?(:pod) ? value.pod : value.is_a?(Pod) ? value : Pod.new(value)
      end

      def sort_key(pod)
        [-pod.priority, Support.timestamp_key(pod), pod.namespace, pod.name, pod.uid]
      end
    end

    # A deterministic priority queue for pending Pods.  Insertion sequence is
    # used only after priority and identity, which makes retries and replayed
    # watch events stable without consulting wall-clock time.
    class SchedulingQueue
      QueueItem = Struct.new(:pod, :priority, :sequence, :reason, :unschedulable, keyword_init: true) do
        def initialize(pod:, priority:, sequence:, reason:, unschedulable:)
          super
          self.reason = reason&.to_s&.freeze
          freeze
        end

        def key
          typed = pod.is_a?(Pod) ? pod : Pod.new(pod)
          [typed.namespace, typed.name, typed.uid]
        end

        def to_h
          {"pod" => pod.to_h, "priority" => priority, "sequence" => sequence,
           "reason" => reason, "unschedulable" => unschedulable}
        end
      end

      # kube-scheduler's podInitialBackoffDuration / podMaxBackoffDuration.  A
      # Pod that fails to bind is retried with exponential backoff instead of
      # re-entering the active queue immediately: without this a single item
      # that always fails is popped on every scheduling tick, and because
      # PrioritySort orders by creation time it stays ahead of every Pod
      # created after it, starving the whole queue.
      INITIAL_BACKOFF_SECONDS = 1.0
      MAX_BACKOFF_SECONDS = 10.0
      # Safety valve: an item that keeps failing this many times leaves the
      # active rotation entirely and waits in the unschedulable queue, which
      # the periodic flush drains.  It is never dropped, only parked.
      MAX_ACTIVE_ATTEMPTS = 30

      attr_reader :capacity, :queue_sort_name, :queue_sort_weight,
                  :initial_backoff_seconds, :max_backoff_seconds, :max_active_attempts

      def initialize(capacity: nil, queue_sort: nil, queue_sort_name: nil, queue_sort_weight: 1,
                     initial_backoff_seconds: INITIAL_BACKOFF_SECONDS,
                     max_backoff_seconds: MAX_BACKOFF_SECONDS,
                     max_active_attempts: MAX_ACTIVE_ATTEMPTS, clock: nil)
        @capacity = if capacity.nil?
                      nil
                    elsif capacity.is_a?(Integer)
                      capacity
                    elsif capacity.is_a?(String) && capacity.match?(/\A\+?\d+\z/)
                      Integer(capacity, 10)
                    else
                      raise ValidationError, "queue capacity must be a positive integer"
                    end
        raise ValidationError, "queue capacity must be positive" if @capacity && !@capacity.positive?

        @mutex = Mutex.new
        @sequence = 0
        @pending = {}
        @unschedulable = {}
        @backoff = {}
        @attempts = {}
        @clock = clock
        @initial_backoff_seconds = normalize_duration(initial_backoff_seconds, "initial backoff")
        @max_backoff_seconds = normalize_duration(max_backoff_seconds, "maximum backoff")
        if @max_backoff_seconds < @initial_backoff_seconds
          raise ValidationError, "maximum backoff cannot be shorter than the initial backoff"
        end
        @max_active_attempts = if max_active_attempts.nil?
                                 nil
                               elsif max_active_attempts.is_a?(Integer) && max_active_attempts.positive?
                                 max_active_attempts
                               else
                                 raise ValidationError, "maximum active attempts must be a positive integer"
                               end
        @queue_sort = queue_sort || PrioritySort.new
        @queue_sort_name = (queue_sort_name || queue_sort_name_for(@queue_sort)).to_s.freeze
        @queue_sort_weight = normalize_sort_weight(queue_sort_weight)
        # pkg/scheduler/metrics bookkeeping: pops per Pod (its Attempts),
        # the time of its first pop (InitialAttemptTimestamp), whether an
        # unschedulable entry is gated, and the plugins that rejected it.
        @metrics = nil
        @pops = {}
        @first_pop = {}
        @gated = {}
        @rejecting_plugins = {}
      end

      # The Scheduler::Metrics observer (scheduler_queue_incoming_pods_total
      # and the pending-pod gauges); nil records nothing.
      attr_accessor :metrics

      # queue events as framework.ClusterEvent.Label() spells them.
      EVENT_POD_ADD = "PodAdd"
      EVENT_POD_UPDATE = "PodUpdate"
      EVENT_ATTEMPT_FAILURE = "ScheduleAttemptFailure"
      EVENT_BACKOFF_COMPLETE = "BackoffComplete"
      EVENT_FORCE_ACTIVATE = "ForceActivate"
      EVENT_UNSCHEDULABLE_TIMEOUT = "UnschedulableTimeout"

      # Replace the comparator used by every pending-queue ordering operation.
      # Framework instances install a registry-backed wrapper here so the
      # configured plugin, rather than a hard-coded fallback, owns queue order.
      # The standalone queue defaults to PrioritySort for compatibility with
      # callers that use SchedulingQueue directly.
      def configure_sort(sorter = nil, name: nil, weight: 1, &block)
        comparator = sorter || block
        raise ValidationError, "queue sort comparator is required" unless comparator
        unless comparator.respond_to?(:call) || comparator.respond_to?(:compare)
          raise ValidationError, "queue sort comparator must implement #call or #compare"
        end

        normalized_name = (name || queue_sort_name_for(comparator)).to_s
        raise ValidationError, "queue sort plugin name cannot be empty" if normalized_name.empty?

        normalized_weight = normalize_sort_weight(weight)
        @mutex.synchronize do
          @queue_sort = comparator
          @queue_sort_name = normalized_name.freeze
          @queue_sort_weight = normalized_weight
        end
        self
      end

      alias configure_queue_sort configure_sort

      def queue_sort
        @mutex.synchronize { @queue_sort }
      end

      def enqueue(pod, reason: nil, event: nil)
        typed = pod.is_a?(Pod) ? pod : Pod.new(pod)
        @mutex.synchronize do
          key = identity_key(typed)
          event ||= known_locked?(key) ? EVENT_POD_UPDATE : EVENT_POD_ADD
          @sequence += 1
          item = QueueItem.new(pod: typed, priority: typed.priority, sequence: @sequence,
                               reason: reason, unschedulable: false)
          store_pending_locked(item)
          incoming(event, "active")
          item
        end
      end

      alias requeue enqueue
      alias push enqueue

      # +gated+: rejected by a PreEnqueue plugin (never attempted);
      # +plugins+: the Filter/PostFilter plugins that found it unschedulable
      # (scheduler_unschedulable_pods); +event+: what moved it.
      def enqueue_unschedulable(pod, reason:, gated: false, plugins: [], event: EVENT_ATTEMPT_FAILURE)
        typed = pod.is_a?(Pod) ? pod : Pod.new(pod)
        key = identity_key(typed)
        item = @mutex.synchronize do
          @sequence += 1
          QueueItem.new(pod: typed, priority: typed.priority, sequence: @sequence,
                        reason: String(reason), unschedulable: true).tap do |entry|
            @pending.delete(key)
            @unschedulable[key] = entry
            gated ? @gated[key] = true : @gated.delete(key)
            @rejecting_plugins[key] = Array(plugins).map(&:to_s).uniq.freeze
            incoming(event, "unschedulable")
          end
        end
        item
      end

      alias add_unschedulable enqueue_unschedulable

      # Re-admit a Pod whose scheduling attempt failed.  The Pod waits out an
      # exponential backoff before it can be popped again, so one permanently
      # failing item costs at most one attempt per MAX_BACKOFF_SECONDS instead
      # of one per scheduling tick.
      def enqueue_backoff(pod, reason: nil)
        typed = pod.is_a?(Pod) ? pod : Pod.new(pod)
        key = identity_key(typed)
        @mutex.synchronize do
          attempts = (@attempts[key] = @attempts.fetch(key, 0) + 1)
          @sequence += 1
          parked = @max_active_attempts && attempts >= @max_active_attempts
          item = QueueItem.new(pod: typed, priority: typed.priority, sequence: @sequence,
                               reason: reason, unschedulable: parked ? true : false)
          @pending.delete(key)
          if parked
            @backoff.delete(key)
            @unschedulable[key] = item
            @gated.delete(key)
            incoming(EVENT_ATTEMPT_FAILURE, "unschedulable")
          else
            @unschedulable.delete(key)
            @backoff[key] = [item, now_seconds + backoff_delay(attempts)]
            incoming(EVENT_ATTEMPT_FAILURE, "backoff")
          end
          item
        end
      end

      alias requeue_with_backoff enqueue_backoff

      # Remove a Pod and forget its failure history.  Used when the Pod is gone
      # (a delete event, or an API request that reports it no longer exists):
      # such an item must never be re-admitted, because nothing will ever
      # deliver another delete event for it.
      def drop(pod, reason: nil)
        _ = reason
        delete(pod)
      end

      # Consecutive failure count for a Pod, for tests and status reporting.
      def attempts(pod)
        key = identity_key(pod)
        @mutex.synchronize { @attempts.fetch(key, 0) }
      end

      # Clear a Pod's failure history without removing it from the queue.
      def forget(pod)
        key = identity_key(pod)
        @mutex.synchronize do
          @attempts.delete(key)
          @pops.delete(key)
          @first_pop.delete(key)
          @gated.delete(key)
          @rejecting_plugins.delete(key)
        end
        self
      end

      # How many times the Pod was popped (queuedPodInfo.Attempts).
      def pop_attempts(pod)
        @mutex.synchronize { @pops.fetch(identity_key(pod), 0) }
      end

      # Seconds since the Pod's first pop (InitialAttemptTimestamp), nil when
      # it was never popped.
      def seconds_since_first_attempt(pod)
        first = @mutex.synchronize { @first_pop[identity_key(pod)] }
        first && [now_seconds - first, 0.0].max
      end

      # Unschedulable entries a PreEnqueue plugin gated.
      def gated_size
        @mutex.synchronize { @unschedulable.keys.count { |key| @gated[key] } }
      end

      # plugin name => number of unschedulable (not gated) Pods it rejected.
      def unschedulable_plugins
        @mutex.synchronize do
          @unschedulable.keys.reject { |key| @gated[key] }.each_with_object(Hash.new(0)) do |key, counts|
            @rejecting_plugins.fetch(key, []).each { |plugin| counts[plugin] += 1 }
          end
        end
      end

      # Move every Pod whose backoff has expired back into the active queue.
      def flush_backoff(now = nil)
        @mutex.synchronize { flush_backoff_locked(now || now_seconds) }
      end

      def pop(trace: nil)
        @mutex.synchronize do
          now = now_seconds
          flush_backoff_locked(now)
          key, item = ordered(@pending, trace: trace).first
          return nil unless item

          @pending.delete(key)
          @pops[key] = @pops.fetch(key, 0) + 1
          @first_pop[key] ||= now
          item
        end
      end

      def next(trace: nil)
        pop(trace: trace)
      end

      def dequeue(trace: nil)
        pop(trace: trace)
      end

      def pop_unschedulable
        @mutex.synchronize do
          key, item = @unschedulable.min_by { |identity, entry| [entry.sequence, identity] }
          return nil unless item

          @unschedulable.delete(key)
          item
        end
      end

      def delete(pod)
        key = identity_key(pod)
        @mutex.synchronize do
          @attempts.delete(key)
          @pops.delete(key)
          @first_pop.delete(key)
          @gated.delete(key)
          @rejecting_plugins.delete(key)
          backed_off = @backoff.delete(key)
          @pending.delete(key) || @unschedulable.delete(key) || (backed_off && backed_off.first)
        end
      end

      def include?(pod)
        key = identity_key(pod)
        @mutex.synchronize { @pending.key?(key) || @unschedulable.key?(key) || @backoff.key?(key) }
      end

      def pending?
        @mutex.synchronize { !@pending.empty? }
      end

      def empty?
        !pending?
      end

      def size
        @mutex.synchronize { @pending.length }
      end

      def unschedulable_size
        @mutex.synchronize { @unschedulable.length }
      end

      def backoff_size
        @mutex.synchronize { @backoff.length }
      end

      def backoff_q
        @mutex.synchronize do
          @backoff.values.map(&:first).sort_by { |item| [item.sequence, item.key] }.dup.freeze
        end
      end

      def unschedulable_q
        @mutex.synchronize { @unschedulable.values.sort_by { |item| [item.sequence, item.key] }.dup.freeze }
      end

      def pending
        @mutex.synchronize { ordered(@pending).map(&:last).freeze }
      end

      def snapshot
        @mutex.synchronize do
          {
            "pending" => ordered(@pending).map { |_key, item| item.to_h },
            "backoffQ" => @backoff.values.map(&:first).sort_by { |item| [item.sequence, item.key] }.map(&:to_h),
            "unschedulableQ" => @unschedulable.values.sort_by { |item| [item.sequence, item.key] }.map(&:to_h)
          }.then { |value| Support.snapshot(value) }
        end
      end

      # framework.Handle#Activate: move one Pod waiting in the unschedulable
      # pool or in backoff straight to the active queue (an asynchronous
      # preemption finished for it).  A Pod not waiting there is left alone.
      def activate(pod)
        key = identity_key(pod)
        @mutex.synchronize do
          item = @unschedulable.delete(key) || @backoff.delete(key)&.first
          next nil unless item
          next item if @pending.key?(key)

          @pending[key] = item
          @gated.delete(key)
          enforce_capacity!
          incoming(EVENT_FORCE_ACTIVATE, "active")
          item
        end
      end

      # +event+: the cluster change that moves the Pods (a node add, a Pod
      # delete, the periodic UnschedulableTimeout flush).
      def promote_unschedulable(event: EVENT_UNSCHEDULABLE_TIMEOUT)
        items = @mutex.synchronize do
          result = ordered(@unschedulable).map(&:last)
          @unschedulable.clear
          result.each do |item|
            key = identity_key(item.pod)
            @gated.delete(key)
            next if @pending.key?(key)

            @pending[key] = item
          end
          enforce_capacity!
          result
        end
        items
      end

      private

      def identity_key(pod)
        typed = pod.is_a?(Pod) ? pod : Pod.new(pod)
        uid = typed.uid
        uid.empty? ? [typed.namespace, typed.name] : ["uid", uid, typed.namespace, typed.name]
      end

      def store_pending_locked(item)
        key = identity_key(item.pod)
        @unschedulable.delete(key)
        @backoff.delete(key)
        @pending[key] = item
        enforce_capacity!
      end

      # Pods whose backoff has expired return to the active queue.  Ordering is
      # left to the queue sort: a flushed item competes on its own merits.
      # Failure counts outlive their Pods when a delete event is missed.  The
      # scheduler is a process that runs for weeks, so the bookkeeping is
      # pruned against the live queues rather than growing without bound.
      ATTEMPT_PRUNE_THRESHOLD = 1024

      def prune_attempts_locked
        return if @attempts.length <= ATTEMPT_PRUNE_THRESHOLD

        @attempts.keys.each do |key|
          next if @pending.key?(key) || @backoff.key?(key) || @unschedulable.key?(key)

          @attempts.delete(key)
        end
      end

      def flush_backoff_locked(now)
        prune_attempts_locked
        return [] if @backoff.empty?

        ready = @backoff.select { |_key, (_item, ready_at)| ready_at <= now }
        return [] if ready.empty?

        ready.each do |key, (item, _ready_at)|
          @backoff.delete(key)
          next if @pending.key?(key)

          @pending[key] = item
        end
        enforce_capacity!
        ready.map { |_key, (item, _ready_at)| item }
      end

      # Exponential backoff capped at the configured maximum, mirroring
      # kube-scheduler's backoffQ (1s doubling to 10s).
      def backoff_delay(attempts)
        exponent = attempts - 1
        return @max_backoff_seconds if exponent > 32

        delay = @initial_backoff_seconds * (2**exponent)
        delay > @max_backoff_seconds ? @max_backoff_seconds : delay
      end

      def now_seconds
        if @clock.respond_to?(:call)
          value = @clock.call
          return value.to_f
        end
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def normalize_duration(value, label)
        seconds = case value
                  when Integer, Float then value.to_f
                  when String then (Float(value) if value.strip.match?(/\A\+?\d+(\.\d+)?\z/))
                  end
        raise ValidationError, "#{label} must be a non-negative number of seconds" unless seconds && seconds >= 0

        seconds
      end

      def enforce_capacity!
        return unless @capacity

        while @pending.length > @capacity
          key, = ordered(@pending).last
          @pending.delete(key)
        end
      end

      def ordered(collection, trace: nil)
        collection.to_a.sort do |left, right|
          left_key, left_item = left
          right_key, right_item = right
          comparison = compare_items(left_item, right_item, trace: trace)
          comparison = [left_item.key, left_item.sequence, left_key] <=>
                       [right_item.key, right_item.sequence, right_key] if comparison.zero?
          comparison
        end
      end

      def compare_items(left_item, right_item, trace: nil)
        comparator = @queue_sort
        left_pod = left_item.respond_to?(:pod) ? left_item.pod : left_item
        right_pod = right_item.respond_to?(:pod) ? right_item.pod : right_item
        output = if comparator.respond_to?(:compare)
                   comparator.compare(left_pod, right_pod)
                 elsif comparator.respond_to?(:call)
                   arity = comparator.respond_to?(:arity) ? comparator.arity : comparator.method(:call).arity
                   if arity.negative? || arity >= 3
                     comparator.call(left_pod, right_pod, trace)
                   else
                     comparator.call(left_pod, right_pod)
                   end
                 else
                   raise ValidationError, "queue sort comparator must implement #call or #compare"
                 end
        unless output.is_a?(Integer) && !output.is_a?(TrueClass) && !output.is_a?(FalseClass)
          raise PluginError, "queue sort plugin #{@queue_sort_name} must return an integer comparator result"
        end

        normalized = output <=> 0
        trace&.record(plugin: @queue_sort_name, phase: :queue_sort, weight: @queue_sort_weight,
                      input: {"left" => left_pod.to_h, "right" => right_pod.to_h}, output: normalized)
        normalized
      end

      def queue_sort_name_for(comparator)
        if comparator.respond_to?(:name)
          value = comparator.name.to_s
          return value unless value.empty?
        end
        comparator.class.name.to_s.split("::").last
      end

      def normalize_sort_weight(value)
        weight = if value.is_a?(Integer)
                   value
                 elsif value.is_a?(String) && value.strip.match?(/\A\+?\d+\z/)
                   Integer(value, 10)
                 end
        raise ValidationError, "queue sort plugin weight must be a positive integer" unless weight&.positive?

        weight
      end
    end

    UnschedulableQueue = SchedulingQueue unless const_defined?(:UnschedulableQueue, false)
  end
end
