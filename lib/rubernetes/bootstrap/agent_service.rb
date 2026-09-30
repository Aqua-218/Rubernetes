# frozen_string_literal: true

require "socket"

require_relative "../node"
require_relative "../image"
require_relative "../runtime/native"
require "openssl"
require "securerandom"

module Rubernetes
  module Bootstrap
    # Wires the node runtime, startup reconciliation, sync loop, and
    # subresource services into the agent process lifecycle.  Concrete runtime
    # and sync-loop implementations are injected so this bootstrap boundary
    # remains testable without requiring a privileged kernel.
    class AgentService
      class Error < StandardError; end

      class StopError < Error
        attr_reader :errors

        def initialize(errors)
          @errors = errors.freeze
          super("agent stop failed: #{errors.map { |error| error.message }.join("; ")}")
        end
      end

      # Keeps the executable's side-effect-free default usable until a native
      # runtime is assembled.  It does not pretend to execute workloads.
      class NullRuntime
        def start
          true
        end

        def reconcile
          true
        end

        def stop(**_options)
          true
        end

        def logs(*_args, **_options)
          "".b
        end

        def exec(*_args, **_options)
          raise Node::RuntimeUnavailable, "native runtime is not configured for exec"
        end

        def attach(*_args, **_options)
          raise Node::RuntimeUnavailable, "native runtime is not configured for attach"
        end

        def port_forward(*_args, **_options)
          raise Node::RuntimeUnavailable, "native runtime is not configured for port-forward"
        end
      end

      class NullSyncLoop
        def start
          true
        end

        def stop(**_options)
          true
        end
      end

      attr_reader :config, :logger, :runtime, :api_adapter, :node_agent, :sync_loop, :log_service, :exec_service,
                  :attach_service, :port_forward_service, :recovery_report, :node_resolver

      def initialize(config:, logger:, runtime: nil, runtime_adapter: nil, sync_loop: nil, node_agent: nil, authorizer: nil,
                     trusted_subresources: false,
                     log_service: nil, exec_service: nil, attach_service: nil, port_forward_service: nil,
                     subresources: nil, api_adapter: nil, runtime_observer: nil, runtime_cleaner: nil,
                     node_resolver: nil, dns_service: nil,
                     runtime_adapters: {},
                     request_id_generator: -> { SecureRandom.uuid },
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @config = immutable_config(config)
        @logger = logger
        @runtime = runtime || runtime_adapter || Runtime::Native.new(profile: :pure, adapters: runtime_adapters)
        @api_adapter = api_adapter
        @node_agent = node_agent
        @node_resolver = node_resolver
        @dns_service = dns_service
        @node_name = @config["node_name"]&.to_s
        @node_endpoint_registered = false
        @runtime_observer = runtime_observer
        @runtime_cleaner = runtime_cleaner
        @sync_loop = sync_loop || node_agent || NullSyncLoop.new
        service_options = {
          runtime: @runtime,
          authorizer: authorizer,
          trusted: trusted_subresources == true,
          request_id_generator: request_id_generator,
          clock: clock
        }
        subresources ||= {}
        @service_options = service_options
        @log_service = log_service || subresources[:logs] || subresources["logs"] || Node::LogService.new(**service_options)
        @exec_service = exec_service || subresources[:exec] || subresources["exec"] || Node::ExecService.new(**service_options)
        @attach_service = attach_service || subresources[:attach] || subresources["attach"] || Node::AttachService.new(**service_options)
        @port_forward_service = port_forward_service || subresources[:portforward] || subresources[:port_forward] ||
                                subresources["portforward"] || subresources["port-forward"] || Node::PortForwardService.new(**service_options)
        @mutex = Mutex.new
        @started = false
      end

      def start
        @mutex.synchronize do
          raise "rubernetes-agent is already started" if @started

          begin
            reclaim_abandoned_image_stages!
            invoke_lifecycle(@runtime, :start, config: @config)
            recovery_options = {}
            recovery_options[:observer] = @runtime_observer if @runtime_observer
            recovery_options[:cleaner] = @runtime_cleaner if @runtime_cleaner
            if @node_agent&.respond_to?(:recover)
              @recovery_report = invoke_lifecycle(@node_agent, :recover, **recovery_options)
              ensure_recovery_ready!(@recovery_report)
            elsif @runtime.respond_to?(:recover)
              @recovery_report = invoke_lifecycle(@runtime, :recover, **recovery_options)
              ensure_recovery_ready!(@recovery_report)
            elsif @runtime.respond_to?(:reconcile)
              @recovery_report = invoke_lifecycle(@runtime, :reconcile)
              ensure_recovery_ready!(@recovery_report)
            end
            invoke_lifecycle(
              @sync_loop,
              :start,
              runtime: @runtime,
              config: @config,
              lease_thread: @node_agent && @sync_loop.equal?(@node_agent)
            )
            register_node_endpoint
            start_streaming_server!
            start_dns_service!
            start_certificate_rotation!
            start_server_certificate_rotation!
            @started = true
          rescue StandardError
            unregister_node_endpoint
            @certificate_manager&.stop
            @serving_certificate_manager&.stop
            stop_dns_service!
            stop_streaming_server!
            @started = false
            safely_stop(@sync_loop)
            safely_close(@api_adapter)
            safely_stop(@runtime)
            raise
          end
        end
        ready_fields = {subresources: %w[logs exec attach portforward], ready: ready?,
                        streaming_port: @streaming_server&.port}
        if @node_agent&.respond_to?(:startup_error) && (error = @node_agent.startup_error)
          ready_fields[:node_startup_deferred] = error
        end
        log(:info, "process.ready", **ready_fields)
        self
      end

      def stop(reason:)
        should_stop = @mutex.synchronize do
          next false unless @started

          @started = false
          true
        end
        return self unless should_stop

        errors = []
        unregister_node_endpoint
        @certificate_manager&.stop
        @serving_certificate_manager&.stop
        stop_dns_service!
        stop_streaming_server!
        [@sync_loop, @api_adapter, @runtime].compact.uniq.each do |component|
          operation = component.respond_to?(:stop) ? :stop : :close
          invoke_lifecycle(component, operation, reason: reason)
        rescue StandardError => error
          errors << error
          log(:error, "process.stop_failed", component: component.class.name, error: error)
        end
        log(:info, "process.stopped", reason: reason)
        raise StopError, errors if errors.any?

        self
      end

      def started?
        @mutex.synchronize { @started }
      end

      def ready?
        return false unless started?
        return false if @node_agent&.respond_to?(:ready?) && !@node_agent.ready?

        report = @recovery_report
        return true unless report.is_a?(Hash)

        Array(report["errors"] || report[:errors]).empty? &&
          Array(report["blocked"] || report[:blocked]).empty? &&
          report.fetch("ready", report.fetch(:ready, true)) == true
      end

      alias logs log_service
      alias exec exec_service
      alias attach attach_service
      alias port_forward port_forward_service

      def subresource(name)
        case name.to_s
        when "logs", "log"
          log_service
        when "exec"
          exec_service
        when "attach"
          attach_service
        when "portforward", "port-forward", "port_forward"
          port_forward_service
        else
          raise KeyError, "unknown node subresource #{name.inspect}"
        end
      end

      private

      def invoke_lifecycle(component, operation, **options)
        return true unless component.respond_to?(operation)

        callable = component.method(operation)
        parameters = callable.parameters
        filtered = if parameters.any? { |kind, _| kind == :keyrest }
                     options
                   else
                     accepted = parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
                     options.select { |key, _| accepted.include?(key) }
                   end
        result = callable.call(**filtered)
        raise Error, "#{component.class}##{operation} returned false" if result == false

        result
      end

      def safely_stop(component)
        return unless component.respond_to?(:stop)

        invoke_lifecycle(component, :stop, reason: "startup_failed")
      rescue StandardError => error
        log(:error, "process.rollback_failed", component: component.class.name, error: error)
      end

      def safely_close(component)
        return unless component.respond_to?(:close)

        invoke_lifecycle(component, :close)
      rescue StandardError => error
        log(:error, "process.rollback_failed", component: component.class.name, error: error)
      end

      def immutable_config(value)
        copy = deep_copy(value)
        deep_freeze(copy)
      end

      def deep_copy(value)
        case value
        when Hash
          value.to_h { |key, child| [String(key), deep_copy(child)] }
        when Array
          value.map { |child| deep_copy(child) }
        else
          value
        end
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each do |key, child|
            key.freeze
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end

      def log(level, event, **fields)
        return unless logger.respond_to?(level)

        logger.public_send(level, event, **fields)
      end

      def ensure_recovery_ready!(report)
        value = if report.respond_to?(:to_h)
                  report.to_h
                elsif report.is_a?(Hash)
                  report
                elsif report == true
                  {"ready" => true, "errors" => [], "blocked" => []}
                elsif report == false
                  {"ready" => false, "errors" => ["recovery returned false"], "blocked" => []}
                elsif report.nil?
                  {"ready" => false, "errors" => ["recovery returned no report"], "blocked" => []}
                else
                  {"ready" => false, "errors" => ["recovery returned an invalid report"], "blocked" => []}
                end
        errors = Array(value["errors"] || value[:errors]).map(&:to_s)
        errors.concat(Array(value["identity_mismatch"] || value[:identity_mismatch]).map do |entry|
          "resource identity mismatch: #{recovery_resource_key(entry)}"
        end)
        cleaned_orphans = Array(value["cleaned_orphans"] || value[:cleaned_orphans]).map(&:to_s)
        unresolved_orphans = Array(value["orphans"] || value[:orphans]).filter_map do |entry|
          key = recovery_resource_key(entry)
          key unless cleaned_orphans.include?(key)
        end
        errors.concat(unresolved_orphans.map { |key| "unresolved orphan resource: #{key}" })
        blocked = Array(value["blocked"] || value[:blocked]).map(&:to_s)
        ready = value.key?("ready") ? value["ready"] : value.fetch(:ready, true)
        return true if ready == true && errors.empty? && blocked.empty?

        detail = (errors + blocked.map { |entry| "#{entry} is pending" }).join("; ")
        raise Error, "agent recovery is not complete#{": #{detail}" unless detail.empty?}"
      end

      def recovery_resource_key(entry)
        return entry.to_s unless entry.is_a?(Hash)

        kind = entry["kind"] || entry[:kind]
        id = entry["id"] || entry[:id]
        return entry.to_s if kind.nil? || id.nil?

        "#{kind}:#{id}"
      end

      # The kubelet-style streaming endpoint.  Without it the API server has
      # nowhere to proxy `kubectl logs`/`exec` to, so it is a startup failure
      # rather than a silent degradation when it is configured but cannot bind.
      # Staging directories left by a previous agent on this node can no longer
      # be released by anyone: their owner is gone and the state that named
      # them went with it.  Reclaiming them at startup is what keeps a node
      # that restarts from filling its own disk.
      def reclaim_abandoned_image_stages!
        staging_root = (@config["image"] || {}).to_h["staging_root"]
        Image::Resolver.reclaim_abandoned_stages(staging_root: staging_root, logger: method(:log))
      rescue StandardError => error
        log(:warn, "image.stage_reclaim_failed", error: error.class.name, message: error.message)
      end

      def start_streaming_server!
        options = (@config["streaming"] || {}).to_h
        return if options["enabled"] == false

        host = options.fetch("host", "127.0.0.1").to_s
        loopback = %w[127.0.0.1 ::1 localhost].include?(host)
        auth = streaming_auth(options)
        if !loopback && auth.nil?
          raise Config::Error,
                "rubernetes-agent.streaming.host #{host.inspect} is not loopback: the streaming endpoint trusts the " \
                "API server's authorization, so it must not be reachable off-host without its own authorizer"
        end

        # The API server authenticates and runs a SubjectAccessReview before it
        # proxies here, and the listener is loopback-only, so this surface takes
        # the API server as its authorization boundary rather than re-deciding
        # with no identity to decide on.
        @streaming_server = Node::StreamingServer.new(
          log_service: Node::LogService.new(**@service_options, trusted: true),
          lifecycle: @node_agent.respond_to?(:lifecycle) ? @node_agent.lifecycle : nil,
          exec_service: Node::ExecService.new(**@service_options, trusted: true),
          attach_service: Node::AttachService.new(**@service_options, trusted: true),
          port_forward_service: Node::PortForwardService.new(**@service_options, trusted: true),
          # /stats/summary and /metrics/resource.
          stats_provider: @node_agent.respond_to?(:stats_provider) ? @node_agent.stats_provider : nil,
          # kubelet enableSystemLogHandler (default on) / enableSystemLogQuery
          # (default off): /logs/ serves the node's log directory.
          system_logs: if options.fetch("enable_system_log_handler", true) == false
                         nil
                       else
                         Node::SystemLogs.new(log_dir: options.fetch("system_log_dir", "/var/log").to_s,
                                              query_enabled: options.fetch("enable_system_log_query", false) == true)
                       end,
          flags: Observability::ZPages.flags_from(arguments: ARGV.dup, config: @config.to_h),
          # kubelet <root>/checkpoints, beside this node's sandbox root.
          checkpoint_dir: options["checkpoint_dir"] ||
                          (@config["sandbox_root"] ? File.join(File.dirname(@config["sandbox_root"].to_s), "checkpoints") : nil),
          host: host,
          port: Integer(options.fetch("port", 10_250)),
          auth: auth,
          tls: streaming_tls(options),
          log_level_setter: ->(level) { @logger.level = level if @logger.respond_to?(:level=) },
          kubelet_metrics: @node_agent.respond_to?(:kubelet_metrics) ? @node_agent.kubelet_metrics : nil,
          # The node's own configuration, with the resolver its Pods get.
          configz: lambda do
            Node::KubeletConfigz.build(@config,
                                       cluster_dns: @dns_service.respond_to?(:bind_addresses) ? Array(@dns_service.bind_addresses) : [],
                                       cluster_domain: (@config["dns"] || {}).to_h["cluster_domain"] || @config["cluster_domain"] || "cluster.local")
          end
        )
        @streaming_server.start(background: true)
      end

      # kubelet --tls-cert-file / --tls-private-key-file and the client CA
      # client certificates are verified against.
      def streaming_tls(options)
        tls = (options["tls"] || {}).to_h
        return nil if tls.empty?

        result = {cert_file: tls.fetch("cert_file"), key_file: tls.fetch("key_file")}
        if tls["client_ca_file"]
          result[:request_client_certificates] = true
          result[:client_ca_certificates] = File.read(tls["client_ca_file"])
            .scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m)
            .map { |pem| OpenSSL::X509::Certificate.new(pem) }
        end
        result
      end

      # KubeletConfiguration authentication / authorization: webhook
      # authentication and Webhook authorization through the API server.
      # Unset keeps the loopback-only endpoint that trusts the API server.
      def streaming_auth(options)
        authentication = (options["authentication"] || {}).to_h
        authorization = (options["authorization"] || {}).to_h
        return nil if authentication.empty? && authorization.empty?

        client = @node_agent.respond_to?(:api) && @node_agent.api.respond_to?(:client) ? @node_agent.api.client : nil
        raise Config::Error, "rubernetes-agent.streaming.authentication requires an API client" if client.nil?

        Node::KubeletAuth.new(
          client: client, node_name: @node_name,
          client_ca: (options["tls"] || {}).to_h["client_ca_file"],
          anonymous: authentication.fetch("anonymous", false) == true,
          webhook: authentication.fetch("webhook", true) != false,
          authorization_mode: authorization.fetch("mode", "Webhook"),
          fine_grained: authorization.fetch("fine_grained", true) != false
        )
      end

      # RotateKubeletClientCertificate: renew the node's client certificate in
      # the background; after each renewal the client reconnects so the next
      # handshake presents the new certificate.
      def start_certificate_rotation!
        return unless @config["rotate_certificates"] == true

        client = @node_agent.respond_to?(:api) && @node_agent.api.respond_to?(:client) ? @node_agent.api.client : nil
        return log(:warn, "certificate.rotation_disabled", reason: "no API client") if client.nil?

        kubeconfig = @config["kubeconfig"].to_s
        cert_dir = @config["cert_dir"] || File.join(File.dirname(File.expand_path(kubeconfig)), "pki")
        @certificate_manager = Node::ClientCertificateManager.new(
          node_name: @node_name, cert_dir: cert_dir,
          logger: ->(level, event, **fields) { log(level, event, **fields) }
        )
        metrics = @node_agent.respond_to?(:kubelet_metrics) ? @node_agent.kubelet_metrics : nil
        if metrics.respond_to?(:client_certificate_source=)
          manager = @certificate_manager
          metrics.client_certificate_source = -> { manager.current_certificate }
          @certificate_manager.on_renew_failure = -> { metrics.client_certificate_renew_failed }
        end
        @certificate_manager.start(client: client, on_rotate: lambda do |_certificate|
          client.rest_client.reset_connections! if client.respond_to?(:rest_client) && client.rest_client.respond_to?(:reset_connections!)
        end)
      end

      # serverTLSBootstrap: the streaming server's certificate comes from a
      # kubelet-serving CertificateSigningRequest and is rotated; the static
      # tls.cert_file stays the fallback until the first one is issued.
      def start_server_certificate_rotation!
        return unless @config["server_tls_bootstrap"] == true

        client = @node_agent.respond_to?(:api) && @node_agent.api.respond_to?(:client) ? @node_agent.api.client : nil
        return log(:warn, "serving_certificate.rotation_disabled", reason: "no API client") if client.nil?

        kubeconfig = @config["kubeconfig"].to_s
        cert_dir = @config["cert_dir"] || File.join(File.dirname(File.expand_path(kubeconfig)), "pki")
        addresses = lambda do
          listed = @node_agent.respond_to?(:node_addresses) ? Array(@node_agent.node_addresses) : []
          if listed.empty?
            listed = Socket.ip_address_list.reject do |address|
              address.ipv4_loopback? || address.ipv6_loopback? || address.ipv6_linklocal?
            end.map(&:ip_address)
          end
          listed
        end
        @serving_certificate_manager = Node::ServingCertificateManager.new(
          node_name: @node_name, cert_dir: cert_dir, addresses: addresses,
          logger: ->(level, event, **fields) { log(level, event, **fields) }
        )
        manager = @serving_certificate_manager
        metrics = @node_agent.respond_to?(:kubelet_metrics) ? @node_agent.kubelet_metrics : nil
        if metrics.respond_to?(:server_certificate_source=)
          metrics.server_certificate_source = -> { manager.current_certificate }
          manager.on_renew_failure = -> { metrics.server_certificate_renew_failed }
        end
        install = lambda do |certificate, previous|
          key = manager.current_private_key
          server = @streaming_server.respond_to?(:server) ? @streaming_server.server : nil
          server.reload_tls!(certificate: certificate, private_key: key) if server.respond_to?(:reload_tls!) && certificate && key
          metrics.server_certificate_rotated(previous) if metrics.respond_to?(:server_certificate_rotated)
        end
        current = manager.current_certificate
        install.call(current, nil) if current && manager.valid?(current)
        previous_holder = [current]
        manager.start(client: client, on_rotate: lambda do |certificate|
          install.call(certificate, previous_holder[0])
          previous_holder[0] = certificate
        end)
      end

      def stop_streaming_server!
        @streaming_server&.stop
        @streaming_server = nil
      rescue StandardError
        @streaming_server = nil
      end

      # The node-local cluster DNS server (spec §5.9.7).  Its bind address is
      # what every Pod's resolv.conf names, so a failure to start it is a
      # readiness failure, not a warning.
      def start_dns_service!
        return unless @dns_service

        @dns_service.start
        log(:info, "dns.started", endpoints: @dns_service.endpoints)
      end

      def stop_dns_service!
        @dns_service&.stop
      rescue StandardError => error
        log(:error, "dns.stop_failed", error: error)
      end

      attr_reader :dns_service

      def register_node_endpoint
        return unless @node_resolver&.respond_to?(:register)
        return if @node_name.nil? || @node_name.empty?

        @node_resolver.register(@node_name, self)
        @node_endpoint_registered = true
      end

      def unregister_node_endpoint
        return unless @node_endpoint_registered
        return unless @node_resolver&.respond_to?(:unregister)

        begin
          @node_resolver.unregister(@node_name, endpoint: self)
        rescue ArgumentError
          # Compatibility with a resolver exposing only unregister(name).
          @node_resolver.unregister(@node_name)
        end
      ensure
        @node_endpoint_registered = false
      end
    end
  end
end
