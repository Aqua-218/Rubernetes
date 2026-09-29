# frozen_string_literal: true

require "json"
require_relative "../observability/metrics"
require_relative "../observability/slis"
require_relative "../observability/zpages"
require_relative "../transport/http_server"

module Rubernetes
  module Bootstrap
    # The kube-scheduler / kube-controller-manager serving endpoints
    # (upstream --secure-port 10259 / 10257): /healthz, /livez, /readyz,
    # /metrics, /configz, /statusz and /flagz.  Opt-in (`serving.enabled`):
    # the upstream ports are the host's own control plane's on a machine
    # that also runs one, and like the node's streaming endpoint it listens
    # on loopback only, having no authorizer of its own.
    class ComponentServer
      KEYS = %w[enabled bind_address port].freeze
      LOOPBACK = %w[127.0.0.1 ::1 localhost].freeze
      PATHS = %w[/configz /flagz /healthz /livez /metrics /metrics/slis /readyz].freeze

      attr_reader :metrics

      # nil unless serving.enabled.
      # +extra_paths+: path => callable returning the body, served as text
      # exposition (kube-scheduler's /metrics/resources).  +health+: a
      # callable answering [status, message] for /healthz and /livez
      # (kube-proxy's proxier health), nil for the plain ping.
      def self.from_config(component:, config:, metrics:, ready: -> { true }, logger: nil, extra_paths: {}, health: nil)
        serving = (config || {})["serving"] || {}
        return nil unless serving["enabled"] == true

        new(component: component, config: config, metrics: metrics, ready: ready, logger: logger,
            host: serving.fetch("bind_address", "127.0.0.1").to_s, port: Integer(serving.fetch("port")),
            extra_paths: extra_paths, health: health)
      end

      def initialize(component:, config:, metrics:, host:, port:, ready: -> { true }, logger: nil)
        unless LOOPBACK.include?(host)
          raise Config::Error, "#{component} serving.bind_address #{host.inspect} is not loopback: the component endpoints have no authorizer"
        end

        @component = component
        @config = config
        @metrics = metrics
        @ready = ready
        @flags = Observability::ZPages.flags_from(arguments: ARGV.dup, config: config.to_h)
        @started_at = Observability::ZPages.process_start_time
        @slis = Observability::HealthcheckSLIs.new
        @server = Transport::HTTPServer.new(method(:call), host: host, port: port, logger: logger)
      end

      def start
        @server.start(background: true)
        self
      end

      def stop
        @server.stop
        self
      rescue StandardError
        self
      end

      def port = @server.port

      def call(request)
        path = request.path.to_s
        # SLIMetricsWithReset: DELETE /metrics/slis resets the registry.
        if path == "/metrics/slis" && request.method.to_s.upcase == "DELETE"
          @slis.reset
          return [200, {"content-type" => "text/plain; charset=utf-8"}, ["metrics reset\n"]]
        end
        return text(405, "method not allowed") unless %w[GET HEAD].include?(request.method.to_s.upcase)

        case path
        when "/healthz", "/livez" then observed_health(path, true) { text(200, "ok") }
        when "/readyz"
          ready = ready?
          observed_health(path, ready) { ready ? text(200, "ok") : text(500, "[-]leaderElection failed: not ready") }
        when "/metrics" then [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [@metrics.render]]
        when "/metrics/slis" then [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [@slis.render]]
        when "/configz" then [200, {"content-type" => "application/json"}, [JSON.generate("componentconfig" => @config)]]
        when "/statusz", "/flagz" then zpage(path, request)
        else text(404, "404 page not found")
        end
      end

      attr_reader :slis

      private

      # The checks each root health handler runs: ping, and on /readyz the
      # leader election gate.
      def observed_health(path, ready)
        type = Observability::HealthcheckSLIs.type_for(path)
        @slis.observe("ping", type, true)
        @slis.observe("leaderElection", type, ready) if type == "readyz"
        yield
      end

      def ready?
        @ready.call != false
      rescue StandardError
        false
      end

      def zpage(path, request)
        accept = request.respond_to?(:header) ? request.header("accept") : nil
        version = Observability::ZPages::KUBERNETES_VERSION
        status, headers, body = if path == "/statusz"
                                  Observability::ZPages.statusz(component: @component, start_time: @started_at, binary_version: version,
                                                                emulation_version: version.split(".").first(2).join("."),
                                                                paths: PATHS, accept: accept)
                                else
                                  Observability::ZPages.flagz(component: @component, flags: @flags, accept: accept)
                                end
        [status, headers, [body]]
      end

      def text(status, message) = [status, {"content-type" => "text/plain; charset=utf-8"}, ["#{message}\n"]]
    end
  end
end
