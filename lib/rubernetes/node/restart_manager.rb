# frozen_string_literal: true

require "time"

require_relative "status"

module Rubernetes
  module Node
    # Applies Pod restartPolicy and keeps per-container exponential backoff.
    # Time and sleeping are injected so restart decisions remain deterministic
    # in property tests and do not couple the agent to a scheduler.
    class RestartManager
      BASE_DELAY_SECONDS = 10
      MAX_DELAY_SECONDS = 300
      RESET_AFTER_SECONDS = 600
      POLICIES = %w[Always OnFailure Never].freeze

      Attempt = Data.define(
        :key, :policy, :failure_count, :delay_seconds, :state,
        :last_failure_at, :running_since, :restart_count
      ) do
        def to_h
          {
            "key" => key,
            "policy" => policy,
            "failureCount" => failure_count,
            "delaySeconds" => delay_seconds,
            "state" => state,
            "lastFailureAt" => last_failure_at,
            "runningSince" => running_since,
            "restartCount" => restart_count
          }
        end
      end

      def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     sleeper: ->(seconds) { sleep(seconds) },
                     base_delay: BASE_DELAY_SECONDS, max_delay: MAX_DELAY_SECONDS,
                     reset_after: RESET_AFTER_SECONDS, policy: "Always")
        @clock = clock
        @sleeper = sleeper
        @base_delay = Integer(base_delay)
        @max_delay = Integer(max_delay)
        @reset_after = Float(reset_after)
        @default_policy = normalize_policy(policy)
        raise ArgumentError, "base_delay must be positive" unless @base_delay.positive?
        raise ArgumentError, "max_delay must be at least base_delay" if @max_delay < @base_delay
        raise ArgumentError, "reset_after must be positive" unless @reset_after.positive?

        @mutex = Mutex.new
        @attempts = {}
      end

      attr_reader :base_delay, :max_delay, :reset_after

      def normalize_policy(policy)
        value = policy.to_s
        value = "Always" if value.empty?
        return value if POLICIES.include?(value)

        raise ArgumentError, "restartPolicy must be Always, OnFailure, or Never (got #{policy.inspect})"
      end

      def should_restart?(policy: @default_policy, exit_code: 0, reason: nil,
                          liveness_failure: false, startup_failure: false, rules: nil)
        normalized = normalize_policy(policy)
        # container.restartPolicyRules wins over the container/Pod policy for
        # the exit codes it names (types.go ContainerRestartRule): a matching
        # rule with action Restart restarts the container whatever the policy
        # says.  The field was validated by the API server and read by nobody.
        matched = matching_restart_rule(rules, exit_code)
        return true if matched && !liveness_failure && !startup_failure

        return false if normalized == "Never"
        return true if liveness_failure || startup_failure
        return true if normalized == "Always"

        !Integer(exit_code).zero? || %w[Error OOMKilled Failed].include?(reason.to_s)
      end

      RESTART_RULE_ACTIONS = %w[Restart RestartAllContainers].freeze

      # The first rule whose exit-code requirement the exit satisfies.
      def matching_restart_rule(rules, exit_code)
        Array(rules).find do |rule|
          value = rule.respond_to?(:to_h) ? rule.to_h : rule
          action = (value["action"] || value[:action]).to_s
          next false unless RESTART_RULE_ACTIONS.include?(action)

          codes = value["exitCodes"] || value[:exitCodes]
          next false unless codes.is_a?(Hash)

          operator = (codes["operator"] || codes[:operator]).to_s
          values = Array(codes["values"] || codes[:values]).map do |item|
            Integer(item)
          rescue StandardError
            nil
          end.compact
          case operator
          when "In" then values.include?(Integer(exit_code))
          when "NotIn" then !values.include?(Integer(exit_code))
          else false
          end
        end
      rescue ArgumentError, TypeError
        nil
      end

      alias restart? should_restart?

      # Mark a process as running.  A ten-minute uninterrupted run clears the
      # old failure streak when the next exit is observed.
      def record_start(key, policy: @default_policy, at: nil, container_id: nil)
        identifier = normalize_key(key, container_id: container_id)
        timestamp = time_value(at)
        normalized = normalize_policy(policy)
        @mutex.synchronize do
          current = @attempts[identifier]
          count = current && reset_due?(current, timestamp) ? 0 : current&.failure_count.to_i
          restart_count = current&.restart_count.to_i
          @attempts[identifier] = Attempt.new(
            key: identifier,
            policy: normalized,
            failure_count: count,
            delay_seconds: delay_for(count),
            state: "Running",
            last_failure_at: current&.last_failure_at,
            running_since: timestamp,
            restart_count: restart_count
          )
        end
      end

      alias started record_start

      # Record a termination and return the new immutable attempt state.  The
      # caller decides whether to execute the restart after checking policy.
      def record_exit(key, exit_code: 0, reason: nil, policy: @default_policy,
                      at: nil, liveness_failure: false, startup_failure: false,
                      container_id: nil)
        identifier = normalize_key(key, container_id: container_id)
        timestamp = time_value(at)
        normalized = normalize_policy(policy)
        @mutex.synchronize do
          current = @attempts[identifier]
          current ||= initial_attempt(identifier, normalized)
          current = reset_attempt(current, timestamp) if current.running_since && timestamp - current.running_since >= @reset_after
          should_restart = should_restart?(
            policy: normalized,
            exit_code: exit_code,
            reason: reason,
            liveness_failure: liveness_failure,
            startup_failure: startup_failure
          )
          count = should_restart ? current.failure_count + 1 : current.failure_count
          delay = should_restart ? delay_for(count) : 0
          state = if should_restart
                    delay >= @max_delay ? "CrashLoopBackOff" : "WaitingForRestart"
                  elsif Integer(exit_code).zero?
                    "Terminated"
                  else
                    "Failed"
                  end
          @attempts[identifier] = Attempt.new(
            key: identifier,
            policy: normalized,
            failure_count: count,
            delay_seconds: delay,
            state: state,
            last_failure_at: timestamp,
            running_since: nil,
            restart_count: current.restart_count + (should_restart ? 1 : 0)
          )
        end
      end

      alias record_failure record_exit
      alias record_termination record_exit

      def attempt(key, container_id: nil)
        identifier = normalize_key(key, container_id: container_id)
        @mutex.synchronize { @attempts[identifier] }
      end

      def state(key, container_id: nil)
        attempt(key, container_id: container_id)&.state
      end

      def failure_count(key, container_id: nil)
        attempt(key, container_id: container_id)&.failure_count.to_i
      end

      def restart_count(key, container_id: nil)
        attempt(key, container_id: container_id)&.restart_count.to_i
      end

      def backoff(key, container_id: nil)
        attempt(key, container_id: container_id)&.delay_seconds.to_i
      end

      alias delay backoff

      def crash_loop_backoff?(key, container_id: nil)
        state(key, container_id: container_id) == "CrashLoopBackOff"
      end

      # RestartAllContainers removes every container of the Pod and starts
      # them again: each one's restartCount moves on without a failure being
      # counted against its backoff (kubelet convertToAPIContainerStatuses
      # sets oldStatus.RestartCount + 1 for a container it reset).
      def advance_restart_count(key, to:, container_id: nil)
        identifier = normalize_key(key, container_id: container_id)
        @mutex.synchronize do
          current = @attempts[identifier] || initial_attempt(identifier, @default_policy)
          @attempts[identifier] = current.with(restart_count: [current.restart_count.to_i, Integer(to)].max)
        end
      end

      def reset!(key, container_id: nil)
        identifier = normalize_key(key, container_id: container_id)
        @mutex.synchronize do
          current = @attempts[identifier]
          return nil unless current

          @attempts[identifier] = reset_attempt(current, time_value(nil))
        end
      end

      # True once the recorded backoff for this key has elapsed on the
      # manager's own clock.  The restart itself is driven by the node's sync
      # loop, so the wait has to be a question the loop can ask rather than a
      # sleep it has to sit through.
      def restart_ready?(key, container_id: nil, now: nil)
        current = attempt(key, container_id: container_id)
        return true if current.nil?
        return true unless current.delay_seconds.to_f.positive?
        return true if current.last_failure_at.nil?

        time_value(now) - current.last_failure_at.to_f >= current.delay_seconds.to_f
      end

      # Sleep for the current delay, unless the attempt has no pending restart.
      # Returning the delay makes this method useful to a fake scheduler too.
      def wait(key, container_id: nil, sleeper: @sleeper)
        seconds = backoff(key, container_id: container_id)
        return 0 unless seconds.positive?

        sleeper.call(seconds)
        seconds
      end

      def all
        @mutex.synchronize { @attempts.values.map(&:to_h).freeze }
      end

      # kubelet drops a Pod's backoff entries once the Pod is gone
      # (flowcontrol.Backoff GC).  Keys are "<pod uid>/<container name>", so a
      # Pod is forgotten by its uid.  Without this every container the node had
      # ever run stayed in the durable snapshot, which is rewritten in full on
      # every state transition of every Pod.
      def forget_pod(uid)
        prefix = "#{uid}/"
        @mutex.synchronize do
          @attempts.delete_if { |key, _| key.to_s.start_with?(prefix) }
        end
        self
      end

      def snapshot
        all
      end

      def restore(values)
        @mutex.synchronize do
          @attempts = {}
          Array(values).each do |value|
            item = value.respond_to?(:to_h) ? value.to_h : value
            item = item.transform_keys(&:to_s)
            key = normalize_key(item.fetch("key"))
            @attempts[key] = Attempt.new(
              key: key,
              policy: normalize_policy(item.fetch("policy", @default_policy)),
              failure_count: Integer(item.fetch("failureCount", item.fetch("failure_count", 0))),
              delay_seconds: Integer(item.fetch("delaySeconds", item.fetch("delay_seconds", 0))),
              state: String(item.fetch("state", "New")),
              last_failure_at: item["lastFailureAt"] || item["last_failure_at"],
              running_since: item["runningSince"] || item["running_since"],
              restart_count: Integer(item.fetch("restartCount", item.fetch("restart_count", 0)))
            )
          end
        end
        self
      rescue ArgumentError, KeyError, TypeError => error
        raise ArgumentError, "invalid persisted restart state: #{error.message}"
      end

      private

      def normalize_key(key, container_id: nil)
        value = container_id || key
        value = Helpers.key(value, "id", Helpers.key(value, "name", nil)) if value.is_a?(Hash)
        value = value.to_s
        raise ArgumentError, "container key must not be empty" if value.empty?

        value
      end

      def time_value(value)
        return value.to_f if value.is_a?(Numeric)
        # nil answers respond_to?(:to_f) with true and converts to 0.0, so an
        # omitted timestamp silently became the epoch: every recorded failure
        # shared one instant, the "has it been running long enough to reset"
        # window never opened, and a backoff deadline could never elapse.
        return value.to_f if !value.nil? && value.respond_to?(:to_f)

        sampled = @clock.call
        return sampled.to_f if sampled.respond_to?(:to_f)

        Float(sampled)
      end

      def initial_attempt(identifier, policy)
        Attempt.new(
          key: identifier, policy: policy, failure_count: 0,
          delay_seconds: 0, state: "New", last_failure_at: nil,
          running_since: nil, restart_count: 0
        )
      end

      def reset_due?(attempt, timestamp)
        attempt.running_since && timestamp - attempt.running_since >= @reset_after
      end

      def reset_attempt(attempt, timestamp)
        Attempt.new(
          key: attempt.key, policy: attempt.policy, failure_count: 0,
          delay_seconds: 0, state: "Reset", last_failure_at: attempt.last_failure_at,
          running_since: timestamp, restart_count: attempt.restart_count
        )
      end

      # kubelet restarts a container that failed for the first time at once
      # and only backs off from the second failure: doBackOff asks
      # IsInBackOffSince before calling Next, so the first failure finds no
      # backoff entry.  The delays are 0, base, 2*base, ... capped at max.
      # Starting at base put every crash-looping Pod one step behind kubelet
      # -- "restart count should be monotonically increasing" took 258 s
      # where kubelet takes 146 s.
      def delay_for(failure_count)
        return 0 unless failure_count > 1

        [@base_delay * (2**(failure_count - 2)), @max_delay].min
      end
    end
  end
end
