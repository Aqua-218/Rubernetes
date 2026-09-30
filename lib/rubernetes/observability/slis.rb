# frozen_string_literal: true

require_relative "metrics"

module Rubernetes
  module Observability
    # component-base/metrics/prometheus/slis: the registry a component serves
    # on /metrics/slis -- kubernetes_healthcheck (1 healthy, 0 not) and
    # kubernetes_healthchecks_total by check name, endpoint type (healthz,
    # livez, readyz) and status, plus process_start_time_seconds.  The root
    # health handlers record every check they run (healthz.handleRootHealth);
    # a single check's own path (/readyz/etcd) records nothing.
    class HealthcheckSLIs
      ROOT_PATHS = {"/healthz" => "healthz", "/livez" => "livez", "/readyz" => "readyz"}.freeze

      def initialize
        @registry = Metrics.new(apiserver: false, process: false)
        @registry.register("kubernetes_healthcheck", type: :gauge)
        @registry.register("kubernetes_healthchecks_total", type: :counter)
        @registry.register("process_start_time_seconds", type: :gauge,
                                                         help: "[ALPHA] Start time of the process since unix epoch in seconds.")
        start = @registry.send(:process_start_time)
        @registry.set("process_start_time_seconds", start) if start
      end

      attr_reader :registry

      # The endpoint type of a root health path, nil for anything else.
      def self.type_for(path) = ROOT_PATHS[path.to_s]

      # slis.ObserveHealthcheck.
      def observe(name, type, success)
        @registry.set("kubernetes_healthcheck", success ? 1 : 0, {"name" => name.to_s, "type" => type.to_s})
        @registry.increment("kubernetes_healthchecks_total",
                            {"name" => name.to_s, "type" => type.to_s, "status" => success ? "success" : "error"})
        self
      end

      def render = @registry.render_own

      # metrics.HandlerWithReset: every health check series dropped.
      def reset
        @registry.reset("kubernetes_healthcheck")
        @registry.reset("kubernetes_healthchecks_total")
        self
      end
    end
  end
end
