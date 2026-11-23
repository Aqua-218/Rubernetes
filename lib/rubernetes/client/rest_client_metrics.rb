# frozen_string_literal: true

require_relative "exec_credential"

module Rubernetes
  module Client
    # client-go's rest_client metrics (tools/metrics, registered by
    # component-base/metrics/prometheus/restclient): requests by code, host
    # and method; latency and body sizes by host and verb.
    module RestClientMetrics
      LATENCY_BUCKETS = [0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0].freeze
      SIZE_BUCKETS = [64, 256, 512, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304, 16_777_216].freeze
      CERT_ROTATION_BUCKETS = [600, 1800, 3600, 14_400, 86_400, 604_800, 2_592_000, 7_776_000, 15_552_000, 31_104_000, 124_416_000].freeze

      module_function

      def registry
        return nil unless defined?(Rubernetes::Observability::Metrics)

        @registry ||= Rubernetes::Observability::Metrics.global.tap do |metrics|
          metrics.register("rest_client_requests_total", type: :counter,
                                                         help: "Number of HTTP requests, partitioned by status code, method, and host.")
          metrics.register("rest_client_request_duration_seconds", type: :histogram, buckets: LATENCY_BUCKETS,
                                                                   help: "Request latency in seconds. Broken down by verb, and host.")
          metrics.register("rest_client_request_size_bytes", type: :histogram, buckets: SIZE_BUCKETS,
                                                             help: "Request size in bytes. Broken down by verb and host.")
          metrics.register("rest_client_response_size_bytes", type: :histogram, buckets: SIZE_BUCKETS,
                                                              help: "Response size in bytes. Broken down by verb and host.")
          metrics.register("rest_client_request_retries_total", type: :counter,
                                                                help: "Number of request retries, partitioned by status code, verb, and host.")
          metrics.register("rest_client_transport_create_calls_total", type: :counter,
                                                                       help: "Number of calls to get a new transport, partitioned by the result of the " \
                                                                             "operation hit: obtained from the cache, miss: created and added to the cache, " \
                                                                             "uncacheable: created and not cached")
          metrics.register("rest_client_rate_limiter_duration_seconds", type: :histogram, buckets: LATENCY_BUCKETS,
                                                                        help: "Client side rate limiter latency in seconds. Broken down by verb, and host.")
          metrics.register("rest_client_exec_plugin_call_total", type: :counter,
                                                                 help: "Number of calls to an exec plugin, partitioned by the type of event encountered " \
                                                                       "(no_error, plugin_execution_error, plugin_not_found_error, client_internal_error) " \
                                                                       "and an optional exit code. The exit code will be set to 0 if and only if the " \
                                                                       "plugin call was successful.")
          metrics.register("rest_client_exec_plugin_ttl_seconds", type: :gauge,
                                                                  help: "Gauge of the shortest TTL (time-to-live) of the client certificate(s) managed by " \
                                                                        "the auth exec plugin. The value is in seconds until certificate expiry (negative " \
                                                                        "if already expired). If auth exec plugins are unused or manage no TLS " \
                                                                        "certificates, the value will be +INF.")
          metrics.register_exec_plugin_ttl
          metrics.register("rest_client_exec_plugin_certificate_rotation_age", type: :histogram, buckets: CERT_ROTATION_BUCKETS, labels: [])
          metrics.register("rest_client_exec_plugin_policy_call_total", type: :counter, labels: %w[allowed denied])
          metrics.register("rest_client_transport_cache_entries", type: :gauge, help: "Number of transport entries in the internal cache.")
        end
      end

      # rest_client_dns_resolution_duration_seconds{host}: one name lookup
      # before a new connection.
      def dns_resolution(uri, seconds)
        metrics = registry
        return unless metrics

        name = "rest_client_dns_resolution_duration_seconds"
        metrics.register(name, type: :histogram) unless metrics.registered?(name)
        metrics.observe(name, seconds, {"host" => host_of(uri)})
      end

      def record(method, uri, code, seconds, request_size, response_size)
        attempt(method, uri, code, request_size, false)
        latency(method, uri, seconds, response_size)
      end

      # One attempt: rest_client_requests_total and the request size, and
      # rest_client_request_retries_total when it is not the first.
      def attempt(method, uri, code, request_size, retried)
        metrics = registry
        return unless metrics

        host = host_of(uri)
        verb = method.to_s.upcase
        metrics.increment("rest_client_requests_total", {"code" => code.to_s, "host" => host, "method" => verb})
        metrics.increment("rest_client_request_retries_total", {"code" => code.to_s, "host" => host, "verb" => verb}) if retried
        metrics.observe("rest_client_request_size_bytes", request_size.to_i, {"host" => host, "verb" => verb})
      end

      # The whole request: rest_client_request_duration_seconds, and the
      # final response's size.
      def latency(method, uri, seconds, response_size)
        metrics = registry
        return unless metrics

        host = host_of(uri)
        verb = method.to_s.upcase
        metrics.observe("rest_client_request_duration_seconds", seconds, {"host" => host, "verb" => verb})
        metrics.observe("rest_client_response_size_bytes", response_size.to_i, {"host" => host, "verb" => verb}) if response_size
      end

      def rate_limiter(method, uri, seconds)
        registry&.observe("rest_client_rate_limiter_duration_seconds", seconds, {"host" => host_of(uri), "verb" => method.to_s.upcase})
      end

      # One exec plugin run: +status+ as client-go names it, +code+ the
      # plugin's exit status.
      def exec_plugin_call(status, code)
        registry&.increment("rest_client_exec_plugin_call_total", {"call_status" => status, "code" => code.to_s})
      end

      def exec_plugin_rotation_age(seconds)
        registry&.observe("rest_client_exec_plugin_certificate_rotation_age", seconds)
      end

      def exec_plugin_policy(allowed)
        registry&.increment("rest_client_exec_plugin_policy_call_total", {"allowed" => allowed.to_s, "denied" => (!allowed).to_s})
      end

      def host_of(uri) = uri.host ? "#{uri.host}:#{uri.port}" : ""

      # tlsTransportCache.get: rest_client_transport_create_calls_total
      # ("miss" for a new TLS configuration, "hit" for a known one) and
      # rest_client_transport_cache_entries.
      def transport_created(key)
        metrics = registry
        return unless metrics

        @transport_keys_mutex ||= Mutex.new
        result, size = @transport_keys_mutex.synchronize do
          @transport_keys ||= Set.new
          hit = !@transport_keys.add?(key)
          [hit ? "hit" : "miss", @transport_keys.size]
        end
        metrics.increment("rest_client_transport_create_calls_total", {"result" => result})
        metrics.set("rest_client_transport_cache_entries", size)
      end
    end
  end
end

Rubernetes::Client::ExecCredential.observer = Rubernetes::Client::RestClientMetrics.method(:exec_plugin_call)
Rubernetes::Client::ExecCredential.policy_observer = Rubernetes::Client::RestClientMetrics.method(:exec_plugin_policy)
Rubernetes::Client::ExecCredential.rotation_observer = Rubernetes::Client::RestClientMetrics.method(:exec_plugin_rotation_age)
