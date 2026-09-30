# frozen_string_literal: true

require "digest"
require_relative "../identity"

module Rubernetes
  module Security
    module Authentication
      # kube-apiserver wraps its bearer-token authenticators in tokencache
      # (pkg/kubeapiserver/authenticator/config.go: TokenSuccessCacheTTL 10s,
      # TokenFailureCacheTTL 0): a token that authenticated is not verified
      # again for ten seconds.  Without it every request re-verified the JWT
      # and looked its ServiceAccount (and bound Pod) up in the store -- about
      # 2 ms, most of a GET.  Only successes are cached; a token this
      # authenticator does not recognise, or rejects, is asked again.
      class TokenCache
        DEFAULT_SUCCESS_TTL = 10.0
        DEFAULT_MAX_ENTRIES = 4096

        attr_reader :inner

        def initialize(inner, success_ttl: DEFAULT_SUCCESS_TTL, max_entries: DEFAULT_MAX_ENTRIES,
                       clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @inner = inner
          @success_ttl = Float(success_ttl)
          @max_entries = Integer(max_entries)
          @clock = clock
          @entries = {}
          @mutex = Mutex.new
        end

        def authenticate(context)
          token = context.respond_to?(:bearer_token) ? context.bearer_token : nil
          return @inner.authenticate(context) if token.nil? || @success_ttl <= 0

          cached(token, nil) { @inner.authenticate(context) }
        end

        def authenticate_token(token, audiences = nil)
          return nil unless @inner.respond_to?(:authenticate_token)
          return @inner.authenticate_token(token, audiences) if @success_ttl <= 0

          cached(token, audiences) { @inner.authenticate_token(token, audiences) }
        end

        # Everything else (a ServiceAccount token issuer's #issue, ...) is the
        # wrapped authenticator's.
        def method_missing(name, ...)
          return super unless @inner.respond_to?(name)

          @inner.public_send(name, ...)
        end

        def respond_to_missing?(name, include_private = false)
          @inner.respond_to?(name, include_private) || super
        end

        private

        def cached(token, audiences, &)
          key = [Digest::SHA256.digest(token.to_s), audiences.nil? ? nil : Array(audiences).map(&:to_s).sort].freeze
          now = @clock.call
          hit = @mutex.synchronize { @entries[key] }
          if hit && hit.last > now
            self.class.observe_request("hit", 0.0)
            return hit.first
          end

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = fetch(&)
          if result
            @mutex.synchronize do
              @entries.delete(key)
              @entries.shift while @entries.length >= @max_entries
              @entries[key] = [result, now + @success_ttl].freeze
            end
          end
          self.class.observe_request("miss", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          result
        end

        # One authenticator call behind a miss: authentication_token_cache_
        # fetch_total{status="ok"|"error"} and, while it runs,
        # active_fetch_count{status="in_flight"} (there is no singleflight
        # here, so nothing is ever "blocked").
        def fetch
          self.class.active_fetch(1)
          result = yield
          self.class.observe_fetch("ok")
          result
        rescue StandardError
          self.class.observe_fetch("error")
          raise
        ensure
          self.class.active_fetch(-1)
        end

        # k8s.io/apiserver/pkg/authentication/token/cache metrics, on the
        # process-wide registry every component serves.
        class << self
          ACTIVE_FETCH_LOCK = Mutex.new

          def registry
            return nil unless defined?(Rubernetes::Observability::Metrics)

            Rubernetes::Observability::Metrics.global
          end

          def observe_request(status, seconds)
            metrics = registry
            return unless metrics

            ensure_registered(metrics)
            metrics.increment("authentication_token_cache_request_total", {"status" => status})
            metrics.observe("authentication_token_cache_request_duration_seconds", seconds, {"status" => status})
          rescue StandardError
            nil
          end

          def observe_fetch(status)
            metrics = registry
            return unless metrics

            ensure_registered(metrics)
            metrics.increment("authentication_token_cache_fetch_total", {"status" => status})
          rescue StandardError
            nil
          end

          def active_fetch(delta)
            metrics = registry
            return unless metrics

            ensure_registered(metrics)
            ACTIVE_FETCH_LOCK.synchronize do
              @active_fetches = [(@active_fetches || 0) + delta, 0].max
              metrics.set("authentication_token_cache_active_fetch_count", @active_fetches, {"status" => "in_flight"})
              metrics.set("authentication_token_cache_active_fetch_count", 0, {"status" => "blocked"})
            end
          rescue StandardError
            nil
          end

          def ensure_registered(metrics)
            {"authentication_token_cache_request_total" => :counter, "authentication_token_cache_request_duration_seconds" => :histogram,
             "authentication_token_cache_fetch_total" => :counter, "authentication_token_cache_active_fetch_count" => :gauge}.each do |name, type|
              metrics.register(name, type: type) unless metrics.registered?(name)
            end
          end
        end
      end
    end
  end
end
