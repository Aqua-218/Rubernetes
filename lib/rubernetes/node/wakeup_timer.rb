# frozen_string_literal: true

module Rubernetes
  module Node
    # One thread that fires per-Pod wake-ups at their time: the end of a
    # restart backoff, a probe that is due.  kubelet drives each probe from
    # its own ticker and each backoff from the next pod sync; the agent's
    # sync loop only resyncs between watches, so without these a probe ran
    # whenever some unrelated event happened to reconcile its Pod.
    #
    # A key holds at most one pending wake-up, the earliest asked for.
    class WakeupTimer
      def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, &fire)
        raise ArgumentError, "a fire block is required" unless fire

        @clock = clock
        @fire = fire
        @pending = {}
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @running = false
        @thread = nil
      end

      def schedule(key, delay)
        due = @clock.call + [Float(delay), 0.0].max
        @mutex.synchronize do
          existing = @pending[key]
          next if existing && existing <= due

          @pending[key] = due
          @condition.signal
        end
        start
        self
      end

      def cancel(key)
        @mutex.synchronize { @pending.delete(key) }
      end

      def pending
        @mutex.synchronize { @pending.dup }
      end

      def start
        @mutex.synchronize do
          return self if @running

          @running = true
          @thread = Thread.new { run }
          @thread.name = "pod-wakeups"
        end
        self
      end

      def stop
        thread = @mutex.synchronize do
          @running = false
          @condition.signal
          @thread
        end
        thread&.join(1)
        self
      end

      private

      def run
        loop do
          due = @mutex.synchronize do
            break nil unless @running

            now = @clock.call
            ready = @pending.select { |_key, time| time <= now }.keys
            if ready.empty?
              next_time = @pending.values.min
              @condition.wait(@mutex, next_time ? [next_time - now, 0.001].max : nil)
              []
            else
              ready.each { |key| @pending.delete(key) }
              ready
            end
          end
          break if due.nil?

          due.each do |key|
            @fire.call(key)
          rescue StandardError
            next
          end
        end
      end
    end
  end
end
