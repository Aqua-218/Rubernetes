# frozen_string_literal: true

require_relative "status"

module Rubernetes
  module Node
    # Serial execution lane for one Pod.  A worker owns no runtime resources;
    # it only guarantees that reconcile calls for its key cannot overlap.
    class PodWorker
      Task = Data.define(:pod, :action, :request_id)

      # A worker whose queue stays empty this long lets its thread exit; the
      # next enqueue starts a fresh one.  kubelet's pod workers are goroutines
      # that end with the Pod; ours were threads that lived as long as the
      # process, so a node that had run a few hundred Pods carried a few
      # hundred idle threads, each pinning a malloc arena (4 GB resident on a
      # conformance node) and each stalling every fork the agent made.
      DEFAULT_IDLE_TIMEOUT = 60.0

      def initialize(identifier = nil, pod_uid: nil, key: nil, reconcile: nil, executor: nil,
                     error_handler: nil, auto_start: true, idle_timeout: DEFAULT_IDLE_TIMEOUT, on_idle: nil, &block)
        @pod_uid = (identifier || pod_uid || key).to_s
        raise ArgumentError, "pod_uid is required" if @pod_uid.empty?

        @reconcile = reconcile || block
        raise ArgumentError, "reconcile callback is required" unless @reconcile

        @executor = executor
        @error_handler = error_handler
        @idle_timeout = idle_timeout.nil? ? nil : Float(idle_timeout)
        raise ArgumentError, "idle_timeout must be positive" if @idle_timeout && !@idle_timeout.positive?

        @on_idle = on_idle
        @queue = Queue.new
        @mutex = Mutex.new
        @run_mutex = Mutex.new
        @condition = ConditionVariable.new
        @thread = nil
        @pending = nil
        @stopping = false
        @active = false
        @processed = 0
        @failures = []
        @results = []
        start if auto_start
      end

      attr_reader :pod_uid, :processed
      alias key pod_uid

      def start
        @mutex.synchronize do
          return self if @thread&.alive?
          raise "PodWorker is stopping" if @stopping

          @thread = Thread.new { run_loop }
        end
        self
      end

      def enqueue(pod, action: nil, request_id: nil, **_options)
        task = Task.new(
          pod: Helpers.immutable(pod),
          action: action || Helpers.key(pod, "event", "SYNC"),
          request_id: request_id || Helpers.key(Helpers.key(pod, "metadata", {}), "resourceVersion", nil)
        ).freeze
        @mutex.synchronize { raise "PodWorker is stopped" if @stopping }
        # kubelet's pod worker keeps ONE pending update per Pod and replaces it
        # with the newest one (pkg/kubelet/pod_workers.go pendingUpdate): a
        # sync that arrives while the previous one is still running describes
        # the same Pod, so queueing both only makes the worker fall further
        # behind.  Without this the periodic housekeeping sync -- which
        # enqueues every Pod on a short timer -- outran a slow reconcile and
        # the backlog grew without bound, so a Pod could sit Pending for
        # minutes with its worker replaying stale syncs.
        enqueue_coalesced(task)
        start unless @thread&.alive?
        task
      end

      # A plain sync is superseded by any newer task; a terminal action
      # (DELETED) is never dropped for one.
      def enqueue_coalesced(task)
        @mutex.synchronize do
          if coalescable?(task)
            replaced = !@pending.nil?
            @pending = task
            # One wake-up per pending slot: a replacement reuses the token the
            # first enqueue already posted.
            @queue << :__work__ unless replaced
          else
            @pending = nil
            @queue << task
          end
        end
        task
      end

      def coalescable?(task)
        !task.nil? && task.action.to_s.upcase != "DELETED"
      end

      def take_pending
        @mutex.synchronize do
          task = @pending
          @pending = nil
          task
        end
      end

      alias submit enqueue

      # Synchronous entry point useful for an already-running worker pool and
      # for callers that need a result immediately.
      def process(pod, action: nil, request_id: nil)
        task = Task.new(
          pod: Helpers.immutable(pod),
          action: action || Helpers.key(pod, "event", "SYNC"),
          request_id: request_id || Helpers.key(Helpers.key(pod, "metadata", {}), "resourceVersion", nil)
        ).freeze
        execute(task)
      end

      alias reconcile process
      alias run process

      # A stop drains the queued work first, but never for ever: a worker
      # blocked in a reconcile that cannot finish (an init container that
      # never exits, a pull that hangs) kept the whole agent from exiting on
      # SIGTERM -- agent-worker-0 sat in PodWorkerPool#stop for minutes while
      # a Cilium init container ran, and the operator's restart timed out.
      # Past +timeout+ the drain is abandoned, the stop marker is queued and
      # the thread is given the same time to notice before it is left behind
      # (the kubelet itself exits on SIGTERM without waiting for any Pod).
      def stop(drain: true, join: true, timeout: nil)
        if drain
          drain(timeout: timeout)
        else
          clear_queue
        end
        @mutex.synchronize do
          return self if @stopping

          @stopping = true
          @queue << :__stop__
        end
        @thread&.join(timeout) if join
        self
      end

      alias close stop

      def join
        @thread&.join
        self
      end

      def drain(timeout: nil)
        deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout.to_f)
        @mutex.synchronize do
          loop do
            break if @queue.empty? && @pending.nil? && !@active

            remaining = deadline && (deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC))
            return false if remaining && remaining <= 0

            @condition.wait(@mutex, remaining)
          end
        end
        true
      end

      def running?
        @mutex.synchronize { !!@thread&.alive? }
      end

      def busy?
        @mutex.synchronize { @active || !@queue.empty? || !@pending.nil? }
      end

      # No thread, nothing queued: the worker can be dropped from its pool.
      def retired?
        @mutex.synchronize { @thread.nil? && !@active && @queue.empty? && @pending.nil? }
      end

      def failures
        @mutex.synchronize { Helpers.deep_copy(@failures).freeze }
      end

      def results
        @mutex.synchronize { @results.dup.freeze }
      end

      private

      def run_loop
        idle = false
        loop do
          task = @idle_timeout ? @queue.pop(timeout: @idle_timeout) : @queue.pop
          if task.nil?
            # Decide under the lock: an enqueue that raced the timeout has
            # either already pushed (we keep running) or will see @thread nil
            # and start a new thread.
            @mutex.synchronize do
              next unless @queue.empty? && @pending.nil? && !@stopping

              @thread = nil
              idle = true
            end
            break if idle

            next
          end
          break if task == :__stop__

          task = take_pending if task == :__work__
          next if task.nil?

          execute(task)
        end
        @on_idle&.call(self) if idle
      rescue StandardError => error
        # A worker thread must report an unexpected fatal exception to its
        # owner; otherwise a dead lane would silently stop reconciling a Pod.
        @mutex.synchronize { @failures << serialize_error(error) }
        @error_handler&.call(@pod_uid, error)
        raise
      ensure
        @mutex.synchronize do
          @condition.broadcast
        end
      end

      def execute(task)
        @run_mutex.synchronize { execute_once(task) }
      end

      def execute_once(task)
        @mutex.synchronize { @active = true }
        result = if @executor
                   @executor.call(@reconcile, task.pod, action: task.action, request_id: task.request_id)
                 else
                   invoke_reconcile(task)
                 end
        @mutex.synchronize do
          @processed += 1
          @results << result
        end
        result
      rescue StandardError => error
        @mutex.synchronize do
          @processed += 1
          @failures << serialize_error(error)
        end
        @error_handler&.call(@pod_uid, error)
        raise if Thread.current == Thread.main

        nil
      ensure
        @mutex.synchronize do
          @active = false
          @condition.broadcast
        end
      end

      def invoke_reconcile(task)
        @reconcile.call(task.pod, action: task.action, request_id: task.request_id)
      rescue ArgumentError => error
        raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

        @reconcile.call(task.pod)
      end

      def drain_queue
        drain
      end

      def clear_queue
        @queue.pop until @queue.empty?
      end

      def serialize_error(error)
        {"class" => error.class.name, "message" => error.message}
      end
    end

    # Collection of PodWorkers.  Each Pod has one serial lane, while lanes for
    # different Pods are allowed to run concurrently.
    class PodWorkerPool
      def initialize(reconcile: nil, worker_factory: nil, error_handler: nil,
                     auto_start: true, idle_timeout: PodWorker::DEFAULT_IDLE_TIMEOUT, &block)
        @reconcile = reconcile || block
        raise ArgumentError, "reconcile callback is required" unless @reconcile || worker_factory

        @worker_factory = worker_factory
        @error_handler = error_handler
        @auto_start = auto_start
        @idle_timeout = idle_timeout
        @mutex = Mutex.new
        @workers = {}
      end

      def worker(pod_or_uid)
        uid = pod_uid(pod_or_uid)
        @mutex.synchronize do
          @workers[uid] ||= build_worker(uid)
        end
      end

      # Look-up and enqueue happen under one lock so a worker retiring at the
      # same moment cannot be dropped between the two (which would leave two
      # workers, and two threads, for one Pod).
      def enqueue(pod, action: nil, request_id: nil)
        uid = pod_uid(pod)
        @mutex.synchronize do
          worker = (@workers[uid] ||= build_worker(uid))
          worker.enqueue(pod, action: action, request_id: request_id)
        end
      end

      alias submit enqueue

      def process(pod, action: nil, request_id: nil)
        worker(pod).process(pod, action: action, request_id: request_id)
      end

      alias reconcile process

      def start
        @mutex.synchronize { @workers.values.each(&:start) }
        self
      end

      # +timeout+ bounds the whole pool: every worker shares one deadline.
      def stop(drain: true, join: true, timeout: nil)
        workers = @mutex.synchronize { @workers.values.dup }
        workers.each { |worker| worker.stop(drain: drain, join: join) }
        self
      end

      alias close stop

      def drain(timeout: nil)
        workers = @mutex.synchronize { @workers.values.dup }
        deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout.to_f)
        workers.all? do |worker|
          remaining = deadline && [deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0].max
          worker.drain(timeout: remaining)
        end
      end

      def workers
        @mutex.synchronize { @workers.dup.freeze }
      end

      def [](pod_or_uid)
        uid = pod_uid(pod_or_uid)
        @mutex.synchronize { @workers[uid] }
      end

      private

      def build_worker(uid)
        if @worker_factory
          @worker_factory.call(uid)
        else
          PodWorker.new(pod_uid: uid, reconcile: @reconcile, error_handler: @error_handler, auto_start: @auto_start,
                        idle_timeout: @idle_timeout, on_idle: method(:retire))
        end
      end

      # Called by a worker whose thread has exited idle.  It is dropped only
      # if it is still the pool's worker for that Pod and still has nothing to
      # do; an enqueue that arrived meanwhile restarted its thread.
      def retire(worker)
        @mutex.synchronize do
          uid = worker.pod_uid
          @workers.delete(uid) if @workers[uid].equal?(worker) && worker.retired?
        end
      end

      def pod_uid(value)
        return value.to_s unless value.is_a?(Hash)

        metadata = Helpers.key(value, "metadata", {})
        uid = Helpers.key(metadata, "uid", nil)
        return uid.to_s unless uid.nil? || uid.to_s.empty?

        "#{Helpers.key(metadata, "namespace", "default")}/#{Helpers.key(metadata, "name", "")}"
      end
    end
  end
end
