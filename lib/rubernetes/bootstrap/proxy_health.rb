# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    module ProxyHealth
      AUTOSCALER_DELETION_TAINT = "ToBeDeletedByClusterAutoscaler"
      NODE_ZONE_LABEL = "topology.kubernetes.io/zone"
      ZERO_HEALTH_TIME = "0001-01-01T00:00:00Z"

      private

      def health_check_bind_error(service_key, address, port, error)
        namespace, name = service_key.split("/", 2)
        reason = "FailedToStartServiceHealthcheck"
        message = "node #{@proxy.local_node} failed to start healthcheck for #{service_key} on #{address} port #{port}: #{error.message}"
        log(:warn, "proxy.healthcheck_bind_failed", service: service_key, message: message)
        return unless @client

        @health_events ||= Node::EventRecorder.new(
          client: Node::EventSink.new(client: @client), reporting_component: "kube-proxy",
          reporting_instance: @proxy.local_node, clock: @clock, spam_filter: true
        )
        @health_events.record(involved_object: {"apiVersion" => "v1", "kind" => "Service", "namespace" => namespace, "name" => name},
                              reason: reason, message: message, type: "Warning", action: "Listen", namespace: namespace)
      rescue StandardError => publication_error
        log(:warn, "proxy.event_failed", message: publication_error.message)
      end

      def start_proxy_health
        serving = @config["serving"] || {}
        return unless serving["enabled"] == true

        health_port = serving["healthz_port"]
        @component_server = ComponentServer.from_config(component: "kube-proxy", config: @config, metrics: @metrics,
                                                        ready: -> { started? }, logger: @logger,
                                                        health: health_port ? nil : method(:proxier_health), proxy_mode: @proxy.method(:backend_name))
        @component_server.start
        return unless health_port

        host = serving.fetch("healthz_bind_address") { serving.fetch("bind_address", "127.0.0.1") }
        @proxy_health_server = Transport::HTTPServer.new(method(:proxy_health_request), host: host, port: health_port, logger: @logger)
        @proxy_health_server.start(background: true)
      end

      def start_proxy_node_informer
        node_name = @proxy.local_node.to_s
        return if node_name.empty?

        descriptor = Controller::ResourceDescriptor.parse("Node")
        source = resource_source_for(descriptor, optional: true, field_selector: "metadata.name=#{node_name}")
        return unless source

        @proxy_node_informer = Watch::Informer.new(
          client: source, resource: descriptor, resync_period: 0,
          error_handler: ->(error) { log(:warn, "proxy.node_watch_error", message: error.message) }
        )
        @proxy_node_informer.on do |node, _previous, event|
          next unless Controller::Support.name(node) == node_name

          zone = Controller::Support.value(Controller::Support.labels(node), NODE_ZONE_LABEL) unless event == :delete
          @proxy.update_node_zone(zone)
        end
        @proxy_node_informer.start
      end

      def stop_proxy_health
        @proxy_health_server&.stop
      ensure
        @proxy_health_server = nil
        @component_server&.stop
        @component_server = nil
      end

      def proxy_health_request(request)
        path = request.path.to_s
        return proxier_health(path) if %w[/healthz /livez].include?(path)

        [404, {"content-type" => "text/plain; charset=utf-8", "x-content-type-options" => "nosniff"}, ["404 page not found\n"]]
      end

      def stop_proxy_node_informer
        @proxy_node_informer&.stop
        @proxy_node_informer = nil
      end

      # proxy_health.go: HTTP readiness also checks Node eligibility. The
      # JSON healthy field describes dataplane syncs on both endpoints.
      def proxier_health(path)
        health = @proxy_metrics.health
        eligible = proxy_node_eligible? if path == "/healthz"
        code = health.fetch(:healthy) && eligible != false ? 200 : 503
        @proxy_metrics.public_send(path == "/healthz" ? :healthz : :livez, code)
        payload = {"lastUpdated" => proxy_health_time(code == 200 ? health.fetch(:current_time) : health[:last_updated]),
                   "currentTime" => proxy_health_time(health.fetch(:current_time))}
        payload["nodeEligible"] = eligible unless eligible.nil?
        payload["healthy"] = health.fetch(:healthy)
        status = health.fetch(:status).transform_values do |family|
          {"lastUpdated" => proxy_health_time(family.fetch(:last_updated)), "healthy" => family.fetch(:healthy)}
        end
        payload["status"] = status unless status.empty?
        [code, {"content-type" => "application/json", "x-content-type-options" => "nosniff"}, [JSON.generate(payload)]]
      end

      def proxy_node_eligible?
        node = @proxy_node_informer&.indexer&.get(@proxy.local_node)
        return false unless node

        support = Controller::Support
        deletion = support.value(support.metadata(node), "deletionTimestamp")
        return false unless deletion.nil? || deletion == ZERO_HEALTH_TIME

        Array(support.value(support.spec(node), "taints")).none? { |taint| support.value(taint, "key") == AUTOSCALER_DELETION_TAINT }
      end

      def proxy_health_time(seconds)
        return ZERO_HEALTH_TIME if seconds.nil?

        Time.at(seconds).utc.iso8601(9).sub(/\.?0+Z\z/, "Z")
      end
    end
  end
end
