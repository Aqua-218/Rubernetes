# frozen_string_literal: true

module Rubernetes
  module Client
    # client-go's flowcontrol.NewTokenBucketRateLimiter: +qps+ requests per
    # second on average, at most +burst+ at once.  #wait takes one token,
    # sleeping until there is one, and returns how long it slept.
    class RateLimiter
      attr_reader :qps, :burst

      def initialize(qps:, burst:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, sleeper: ->(seconds) { sleep(seconds) })
        @qps = Float(qps)
        @burst = Integer(burst)
        raise ArgumentError, "qps must be positive" unless @qps.positive?
        raise ArgumentError, "burst must be at least 1" unless @burst >= 1

        @clock = clock
        @sleeper = sleeper
        @mutex = Mutex.new
        @tokens = @burst.to_f
        @refilled_at = @clock.call
      end

      def wait(_path = nil)
        delay = @mutex.synchronize { reserve }
        @sleeper.call(delay) if delay.positive?
        delay
      end

      private

      # Takes a token now; a negative balance is the queue of callers already
      # promised one, so each later caller waits behind them.
      def reserve
        now = @clock.call
        @tokens = [@burst.to_f, @tokens + ((now - @refilled_at) * @qps)].min
        @refilled_at = now
        @tokens -= 1
        @tokens.negative? ? -@tokens / @qps : 0.0
      end

      # A zero-QPS clientset lets each versioned REST client apply its own
      # defaults. Discovery requests share a separate bucket.
      class ByAPIVersion
        API_VERSION = %r{\A/?(api/[^/]+|apis/[^/]+/[^/]+)/[^/]}

        def initialize(qps:, burst:)
          @qps = qps
          @burst = burst
          @buckets = {}
          @mutex = Mutex.new
        end

        def wait(path)
          version = path[API_VERSION, 1]
          bucket = @mutex.synchronize { @buckets[version] ||= RateLimiter.new(qps: @qps, burst: @burst) }
          bucket.wait
        end
      end
    end
  end
end
