# frozen_string_literal: true

require "time"
require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "store_adapter"

require "timeout"

module Rubernetes
  module Controller
    # Kubernetes Lease based leader election.  Every transition is an
    # optimistic compare-and-update, so two managers cannot both observe a
    # successful acquisition for the same resource version.
    class LeaseElector
      DEFAULT_NAMESPACE = "kube-system".freeze
      DEFAULT_NAME = "rubernetes-controller-manager".freeze
      DEFAULT_LEASE_DURATION_SECONDS = 15.0
      DEFAULT_RENEW_DEADLINE_SECONDS = 10.0
      DEFAULT_RETRY_PERIOD_SECONDS = 2.0

      attr_reader :identity, :namespace, :name, :lease_duration_seconds,
                  :renew_deadline_seconds, :retry_period_seconds, :state,
                  :last_error

      def initialize(store:, identity:, namespace: DEFAULT_NAMESPACE, name: DEFAULT_NAME,
                     lease_duration_seconds: DEFAULT_LEASE_DURATION_SECONDS,
                     renew_deadline_seconds: DEFAULT_RENEW_DEADLINE_SECONDS,
                     retry_period_seconds: DEFAULT_RETRY_PERIOD_SECONDS,
                     clock: -> { Time.now.utc })
        @store = store
        @adapter = store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store)
        @identity = identity.to_s
        raise ArgumentError, "leader identity must not be empty" if @identity.empty?
        @namespace = namespace.to_s
        @name = name.to_s
        @lease_duration_seconds = Float(lease_duration_seconds)
        @renew_deadline_seconds = Float(renew_deadline_seconds)
        @retry_period_seconds = Float(retry_period_seconds)
        unless @lease_duration_seconds.positive? && @renew_deadline_seconds.positive? &&
               @retry_period_seconds.positive? && @renew_deadline_seconds < @lease_duration_seconds
          raise ArgumentError, "lease duration must exceed renew deadline and all election periods must be positive"
        end
        @clock = clock
        @state = :follower
        @last_error = nil
        @last_observed = nil
        @last_renew_time = nil
        @last_step_time = nil
        @last_step_result = nil
        @leader_transitions = 0
      end

      def lease_descriptor
        ResourceDescriptor.parse("Lease")
      end

      def lease_key
        "#{lease_descriptor.api_version}/#{lease_descriptor.resource}/#{namespace}/#{name}"
      end

      def leader?
        @state == :leader
      end

      alias leading? leader?

      def follower?
        !leader?
      end

      def lost?
        @state == :lost
      end

      def current
        @adapter.find(lease_descriptor, name: name, namespace: namespace)
      end

      # client-go's leader elector touches the API once per retry period, not
      # once per reconcile: a caller that steps on every pass of a 50ms loop
      # would otherwise renew the lease twenty times a second, and every
      # renewal is a write through consensus.  Between those touches the
      # cached decision is returned, which is what `IsLeader()` reports
      # upstream.  `force: true` steps regardless, for a caller that must
      # observe the lease right now.
      def step(force: false)
        now = normalize_time(@clock.call)
        if !force && @last_step_time && !lost? && (now - @last_step_time) < retry_period_seconds
          return @last_step_result || (leader? ? :renewed : :follower)
        end

        @last_step_time = now
        @last_step_result = step_now(now)
      end

      alias run_once step
      alias reconcile step

      # leaderelection's tryAcquireOrRenew: a leader renews from its cached
      # record first (the fast path, one UPDATE); a conflict there means the
      # record moved under it, so the slow path re-reads the Lease and
      # decides again -- leader_election_slowpath_total counts those.
      private def step_now(now)
        if leader? && @last_observed && (fast = fast_path_renew(now))
          return fast
        end

        begin
          lease = current
        rescue StandardError => error
          raise unless transient_error?(error)

          # The API server is unreachable.  A leader keeps leading until its
          # renew deadline passes; anyone else simply has nothing to observe.
          @last_error = error
          if leader? && @last_renew_time && (now - @last_renew_time) > renew_deadline_seconds
            @state = :lost
            return :lost
          end
          return :unavailable
        end
        if lease.nil?
          candidate = build_lease(now, acquire_time: now, leader_transitions: 1)
          begin
            @adapter.create(candidate, descriptor: lease_descriptor)
            become_leader(now, candidate)
            return :acquired
          rescue StandardError => error
            if transient_error?(error) && !contention_error?(error)
              @last_error = error
              @state = :follower
              return :unavailable
            end
            raise unless contention_error?(error)

            @last_error = error
            @state = :follower
            return :contended
          end
        end

        @last_observed = Support.immutable_copy(lease)
        holder = Support.value(Support.spec(lease), "holderIdentity", nil).to_s
        renew_time = Support.parse_time(Support.value(Support.spec(lease), "renewTime", nil))
        expired = renew_time.nil? || (now - renew_time) >= lease_duration_seconds
        if holder == identity
          # A leader whose renewal missed the renew deadline steps down (see
          # #renew).  The lease still names this identity, so the next step
          # re-acquires it the way client-go's acquire loop does: immediately,
          # without waiting for the lease to expire and without counting a
          # leader transition, because the holder did not change.
          return renew(now, lease) if leader?

          return acquire(now, lease, same_holder: true)
        end
        if expired
          return acquire(now, lease)
        end

        @state = :follower
        :follower
      rescue StandardError => error
        @last_error = error
        @state = :follower
        raise
      end

      public def renew(now = normalize_time(@clock.call), lease = current)
        return :follower unless lease
        holder = Support.value(Support.spec(lease), "holderIdentity", nil).to_s
        return lose_leadership unless holder == identity
        last_renew = Support.parse_time(Support.value(Support.spec(lease), "renewTime", nil))
        if last_renew && (now - last_renew) > renew_deadline_seconds
          @state = :lost
          return :lost
        end
        candidate = Support.deep_copy(lease)
        candidate["spec"] ||= {}
        candidate["spec"]["renewTime"] = now.utc.iso8601(6)
        candidate["spec"]["leaseDurationSeconds"] = lease_duration_seconds.to_i
        begin
          @adapter.update(candidate, descriptor: lease_descriptor, existing: lease)
        rescue StandardError => error
          if transient_error?(error) && !contention_error?(error)
            # Leadership is kept: the renew deadline, checked above, decides
            # when this identity actually loses it.
            @last_error = error
            return :renew_failed
          end
          raise unless contention_error?(error)

          @last_error = error
          @state = :follower
          return :contended
        end
        become_leader(now, candidate)
        @last_renew_time = now
        :renewed
      end

      def acquire(now = normalize_time(@clock.call), lease = current, same_holder: false)
        return :follower unless lease
        candidate = Support.deep_copy(lease)
        candidate["spec"] ||= {}
        candidate["spec"]["holderIdentity"] = identity
        candidate["spec"]["acquireTime"] = now.utc.iso8601(6)
        candidate["spec"]["renewTime"] = now.utc.iso8601(6)
        candidate["spec"]["leaseDurationSeconds"] = lease_duration_seconds.to_i
        unless same_holder
          candidate["spec"]["leaderTransitions"] = Support.integer(Support.value(candidate["spec"], "leaderTransitions", 0), 0) + 1
        end
        begin
          @adapter.update(candidate, descriptor: lease_descriptor, existing: lease)
        rescue StandardError => error
          if transient_error?(error) && !contention_error?(error)
            @last_error = error
            @state = :follower
            return :unavailable
          end
          raise unless contention_error?(error)

          @last_error = error
          @state = :follower
          return :contended
        end
        @leader_transitions = candidate["spec"]["leaderTransitions"]
        become_leader(now, candidate)
        :acquired
      end

      def release
        lease = current
        return :not_leader unless lease && Support.value(Support.spec(lease), "holderIdentity", nil).to_s == identity

        candidate = Support.deep_copy(lease)
        candidate["spec"] ||= {}
        candidate["spec"]["holderIdentity"] = ""
        candidate["spec"]["renewTime"] = nil
        @adapter.update(candidate, descriptor: lease_descriptor, existing: lease)
        @state = :follower
        @last_step_time = nil
        @last_step_result = nil
        :released
      end

      def build_lease(now = normalize_time(@clock.call), acquire_time: nil, leader_transitions: 0)
        {
          "apiVersion" => "coordination.k8s.io/v1",
          "kind" => "Lease",
          "metadata" => {"name" => name, "namespace" => namespace},
          "spec" => {
            "holderIdentity" => identity,
            "leaseDurationSeconds" => lease_duration_seconds.to_i,
            "acquireTime" => (acquire_time || now).utc.iso8601(6),
            "renewTime" => now.utc.iso8601(6),
            "leaderTransitions" => Integer(leader_transitions)
          }
        }
      end

      private

      def become_leader(now, lease)
        @state = :leader
        @last_observed = Support.immutable_copy(lease)
        @last_renew_time = now
        @last_error = nil
      end

      def lose_leadership
        @state = :lost
        :lost
      end

      def normalize_time(value)
        parsed = Support.parse_time(value)
        return parsed if parsed
        raise ArgumentError, "clock must return Time or RFC3339 value"
      end

      def contention_error?(error)
        return true if error.respond_to?(:status) && error.status.to_i == 409

        error.class.name.to_s.split("::").last.match?(/\A(?:AlreadyExists|Conflict|LeaseConflict)\z/)
      end

      # client-go's leader election retries a failed renewal until the renew
      # deadline and only then steps down; it never turns one unavailable API
      # server into a component crash.  A 5xx, a timeout or a dropped
      # connection is that kind of failure.
      TRANSIENT_ERROR_NAMES = /\A(?:Timeout|ServerTimeout|ServiceUnavailable|InternalError|TooManyRequests|
                               APIError|ConnectionError|IOError|Errno::[A-Z]+)\z/x.freeze

      def transient_error?(error)
        status = error.respond_to?(:status) ? error.status.to_i : nil
        # An answer from the API server is transient only as a 5xx or 429; a
        # 403 or 422 is not going away on retry and must be seen (a refused
        # renewal was silently retried forever as "unavailable").
        return status >= 500 || status == 429 if status&.positive?
        return true if error.is_a?(IOError) || error.is_a?(SystemCallError) || error.is_a?(Timeout::Error)

        message = error.message.to_s
        return true if message.match?(/HTTP 5\d\d|timed out|timeout|connection reset|broken pipe|refused/i)

        TRANSIENT_ERROR_NAMES.match?(error.class.name.to_s.split("::").last)
      end
    end
  end
end
