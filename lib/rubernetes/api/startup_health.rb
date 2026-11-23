# frozen_string_literal: true

module Rubernetes
  module API
    # Post-start checks are installed by the production service and remain
    # pending until the work tracked by each check is running or complete.
    class StartupHealth
      HOOKS = %w[
        start-apiserver-admission-initializer generic-apiserver-start-informers
        start-apiextensions-informers start-apiextensions-controllers crd-informer-synced
        bootstrap-controller start-system-namespaces-controller start-service-ip-repair-controllers
        scheduling/bootstrap-system-priority-classes start-cluster-authentication-info-controller
        start-kube-aggregator-informers apiservice-registration-controller
        apiservice-status-local-available-controller apiservice-status-remote-available-controller
        kube-apiserver-autoregistration apiservice-openapi-controller
      ].freeze
      LOG_PROBE_INTERVAL_SECONDS = 60
      LOG_HEALTH_WINDOW_SECONDS = 120

      def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @checks = HOOKS.to_h { |name| ["poststarthook/#{name}", false] }
        @checks["autoregister-completion"] = false
        @informer_sync = false
        @clock = clock
        @mutex = Mutex.new
      end

      def monitor_log(&flush)
        @last_log_flush = @clock.call
        @log_monitor = Thread.new do
          loop do
            probe_log(flush)
            sleep(LOG_PROBE_INTERVAL_SECONDS)
          end
        end
        @log_monitor.name = "apiserver-log-health"
      end

      def stop_log_monitor
        @log_monitor&.kill&.join
      end

      def log_healthy?
        last_flush = @mutex.synchronize { @last_log_flush }
        last_flush.nil? || @clock.call - last_flush < LOG_HEALTH_WINDOW_SECONDS
      end

      def complete(*hooks)
        @mutex.synchronize { hooks.each { |name| @checks["poststarthook/#{name}"] = true } }
      end

      def dynamic_apis_synced
        @mutex.synchronize { @informer_sync = true }
      end

      def autoregistration_complete
        @mutex.synchronize { @checks["autoregister-completion"] = true }
      end

      def checks(readyz:)
        @mutex.synchronize do
          readyz ? @checks.merge("informer-sync" => @informer_sync) : @checks.dup
        end
      end

      private

      def probe_log(flush)
        flush.call
        @mutex.synchronize { @last_log_flush = @clock.call }
      rescue IOError, SystemCallError
        # A broken sink leaves the last successful probe unchanged.
      end
    end
  end
end
