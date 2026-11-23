# frozen_string_literal: true

require_relative "../support/object_tree"

require "socket"

require_relative "../node"
require_relative "../node/kernel_tunables"
require_relative "../node/kubelet_healthz"
require_relative "../node/kubelet_tls_files"
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
          super("agent stop failed: #{errors.map(&:message).join("; ")}")
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
                     node_resolver: nil, dns_service: nil, policy_lifecycle: nil,
                     image_staging_root: nil, live_image_roots: -> { [] },
                     runtime_adapters: {}, kernel_tunables: Node::KernelTunables.new,
                     request_id_generator: -> { SecureRandom.uuid },
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @config = immutable_config(config)
        @logger = logger
        @runtime = runtime || runtime_adapter || Runtime::Native.new(profile: :pure, adapters: runtime_adapters)
        @image_staging_root = image_staging_root || @config.dig("image", "staging_root")
        @live_image_roots = live_image_roots
        @kernel_tunables = kernel_tunables
        @api_adapter = api_adapter
        @node_agent = node_agent
        @node_resolver = node_resolver
        @dns_service = dns_service
        @policy_lifecycle = policy_lifecycle
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
          raise "rubernetes-agent is already started" if @started || @stopping

          begin
            setup_kernel_tunables!
            invoke_lifecycle(@runtime, :start, config: @config)
            recovery_options = {}
            recovery_options[:observer] = @runtime_observer if @runtime_observer
            recovery_options[:cleaner] = @runtime_cleaner if @runtime_cleaner
            if @node_agent.respond_to?(:recover)
              @recovery_report = invoke_lifecycle(@node_agent, :recover, **recovery_options)
              ensure_recovery_ready!(@recovery_report)
            elsif @runtime.respond_to?(:recover)
              @recovery_report = invoke_lifecycle(@runtime, :recover, **recovery_options)
              ensure_recovery_ready!(@recovery_report)
            elsif @runtime.respond_to?(:reconcile)
              @recovery_report = invoke_lifecycle(@runtime, :reconcile)
              ensure_recovery_ready!(@recovery_report)
            end
            reclaim_abandoned_image_stages!
            invoke_lifecycle(@runtime, :start_log_rotation)
            @policy_lifecycle&.start_policy(@node_agent.lifecycle, runtime: @runtime)
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
            start_healthz_server!
            @started = true
          rescue StandardError
            unregister_node_endpoint
            @certificate_manager&.stop
            @serving_certificate_manager&.stop
            @healthz_server&.stop
            stop_dns_service!
            stop_streaming_server!
            @started = false
            safely_stop(@sync_loop)
            stop_policy_lifecycle
            safely_close(@api_adapter)
            safely_stop(@runtime)
            raise
          end
        end
        ready_fields = {subresources: %w[logs exec attach portforward], ready: ready?,
                        streaming_port: @streaming_server&.port}
        if @node_agent.respond_to?(:startup_error) && (error = @node_agent.startup_error)
          ready_fields[:node_startup_deferred] = error
        end
        log(:info, "process.ready", **ready_fields)
        self
      end

      def stop(reason:)
        should_stop = @mutex.synchronize do
          next false if !@started || @stopping

          @stopping = true
        end
        return self unless should_stop

        # The local health check disappearing signals that it is safe to stop
        # the runtime externally. Quiesce Pod mutation before dropping it.
        sync_error = stop_component(@sync_loop, reason)
        @mutex.synchronize { @started = false }
        unregister_node_endpoint
        @certificate_manager&.stop
        @serving_certificate_manager&.stop
        @healthz_server&.stop
        stop_dns_service!
        stop_streaming_server!
        errors = [sync_error, stop_policy_lifecycle].compact
        [@api_adapter, @runtime].compact.uniq.each do |component|
          next if component.equal?(@sync_loop)

          error = stop_component(component, reason)
          errors << error if error
        end
        log(:info, "process.stopped", reason: reason)
        raise StopError, errors if errors.any?

        self
      ensure
        @mutex.synchronize { @stopping = false } if should_stop
      end

      def started?
        @mutex.synchronize { @started }
      end

      def ready?
        return false unless started?
        return false if @policy_lifecycle && !@policy_lifecycle.policy_ready?
        return false if @node_agent.respond_to?(:ready?) && !@node_agent.ready?

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

      def stop_policy_lifecycle
        @policy_lifecycle&.stop_policy
        nil
      rescue StandardError => error
        log(:error, "network.policy.stop_failed", error: error)
        error
      end

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
        invoke_lifecycle(component, :stop_log_rotation) if component.equal?(@runtime)
        return unless component.respond_to?(:stop)

        invoke_lifecycle(component, :stop, reason: "startup_failed")
      rescue StandardError => error
        log(:error, "process.rollback_failed", component: component.class.name, error: error)
      end

      def stop_component(component, reason)
        return unless component

        invoke_lifecycle(component, :stop_log_rotation) if component.equal?(@runtime)

        operation = component.respond_to?(:stop) ? :stop : :close
        invoke_lifecycle(component, operation, reason: reason)
        nil
      rescue StandardError => error
        log(:error, "process.stop_failed", component: component.class.name, error: error)
        error
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

      def setup_kernel_tunables!
        profile = @config.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_")
        return unless %w[host_integration kernel_isolation l3].include?(profile)

        @kernel_tunables.apply!(protect_defaults: @config["protect_kernel_defaults"],
                                allow_user_namespace: @config.dig("feature_gates", Node::SystemOOMWatcher::GATE) == true)
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

      def deep_freeze(value) = ObjectTree.deep_freeze(value, nested_keys: false)

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
        # A Pod whose cleanup is still pending is that Pod's problem: the
        # lifecycle retries it (retry_pending_cleanups) and kubelet never
        # refuses to start over one.  Only runtime-level errors keep the
        # node down.
        return true if ready == true && errors.empty?

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

      def reclaim_abandoned_image_stages!
        return unless @image_staging_root

        Image::Resolver.reclaim_abandoned_stages(staging_root: @image_staging_root, protected_roots: @live_image_roots.call,
                                                 logger: method(:log))
      rescue StandardError => error
        log(:warn, "image.stage_reclaim_failed", error: error.class.name, message: error.message)
      end

      # The API server needs this kubelet-style endpoint to proxy logs and exec.
      def start_streaming_server!
        options = (@config["streaming"] || {}).to_h
        hosts = [options.fetch("host", "127.0.0.1"), *options.fetch("additional_hosts", [])].map(&:to_s).uniq
        start_read_only_servers!(options, hosts)
        return if options["enabled"] == false

        auth = streaming_auth(options)
        if auth.nil? && hosts.any? { |host| !%w[127.0.0.1 ::1 localhost].include?(host) }
          raise Config::Error,
                "rubernetes-agent.streaming requires authentication and authorization on non-loopback addresses"
        end

        common = streaming_server_options(options, auth)
        port = Integer(options.fetch("port", 10_250))
        @streaming_servers = []
        hosts.each do |host|
          server = Node::StreamingServer.new(**common, host: host, port: port)
          @streaming_servers << server
          start_streaming_listener(server)
          port = server.port
        end
        @streaming_server = @streaming_servers.first
        start_tls_file_reload!(options, auth)
      end

      def start_read_only_servers!(options, hosts)
        port = @config.fetch("read_only_port", 0)
        return if port.zero?

        settings = streaming_server_options(options.except("tls"), nil).merge(read_only: true)
        @read_only_servers = []
        hosts.each do |host|
          server = Node::StreamingServer.new(**settings, host: host, port: port)
          @read_only_servers << server
          start_streaming_listener(server)
        end
      end

      def start_streaming_listener(server)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
        begin
          server.start(background: true)
        rescue Transport::ConfigurationError => error
          # A new IPv6 bridge address remains tentative until DAD completes.
          raise unless error.cause.is_a?(Errno::EADDRNOTAVAIL) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

          sleep(0.05)
          retry
        end
      end

      def start_healthz_server!
        return unless @node_agent || @config.key?("healthz_port")

        node = Node::KubeletHealthz
        port = @config.fetch("healthz_port", node::DEFAULT_PORT)
        return if port.zero?

        host = @config.fetch("healthz_bind_address", node::DEFAULT_HOST)
        @healthz_server = node.new(host: host, port: port, ready: method(:ready?), logger: @logger)
        @healthz_server.start
      end

      def streaming_server_options(options, auth)
        {
          log_service: Node::LogService.new(**@service_options, trusted: true),
          split_log_streams: @config.dig("feature_gates", "PodLogsQuerySplitStreams") == true,
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
          flags: Observability::ZPages.flags_from(arguments: ARGV.dup, config: @config.to_h.except("static_pod_url_header")),
          # kubelet <root>/checkpoints, beside this node's sandbox root.
          checkpoint_dir: options["checkpoint_dir"] ||
            (@config["sandbox_root"] ? File.join(File.dirname(@config["sandbox_root"].to_s), "checkpoints") : nil),
          auth: auth,
          tls: streaming_tls(options),
          log_level_setter: ->(level) { @logger.level = level if @logger.respond_to?(:level=) },
          kubelet_metrics: @node_agent.respond_to?(:kubelet_metrics) ? @node_agent.kubelet_metrics : nil,
          # The node's own configuration, with the resolver its Pods get.
          configz: lambda do
            configz
          end
        }
      end

      def configz
        dns = (@config["dns"] || {}).to_h
        cluster_dns = Array(dns["cluster_dns"])
        cluster_dns = Array(@dns_service.bind_addresses) if cluster_dns.empty? && @dns_service.respond_to?(:bind_addresses)
        cluster_domain = @config["cluster_domain"] || dns["cluster_domain"] || "cluster.local"
        Node::KubeletConfigz.build(@config, cluster_dns: cluster_dns, cluster_domain: cluster_domain, streaming_port: @streaming_server&.port)
      end

      # kubelet --tls-cert-file / --tls-private-key-file and the client CA
      # client certificates are verified against.
      def streaming_tls(options)
        tls = (options["tls"] || {}).to_h
        return nil if tls.empty?

        result = {cert_file: tls.fetch("cert_file"), key_file: tls.fetch("key_file")}
        if tls["client_ca_file"]
          result[:request_client_certificates] = true
          result[:client_ca_certificates] = Node::KubeletTLSFiles.certificates(tls["client_ca_file"])
        end
        result
      end

      def start_tls_file_reload!(options, auth)
        tls = options["tls"]
        return if tls.nil? || tls.empty?

        gates = @config.fetch("feature_gates", {})
        serving = tls.values_at("cert_file", "key_file") if !rotating_serving_certificate? && gates["ReloadKubeletServerCertificateFile"] != false
        client_ca = tls["client_ca_file"] if gates["ReloadKubeletClientCAFile"] != false
        return unless serving || client_ca

        install = lambda do |**material|
          @streaming_servers.each { |listener| listener.server.reload_tls!(**material) }
          authorities = material[:client_ca_certificates]
          auth&.reload_client_ca!(authorities) if authorities
        end
        @tls_file_reloader = Node::KubeletTLSFiles.new(serving: serving, client_ca: client_ca, install: install, logger: method(:log))
        @tls_file_reloader.start
      end

      def rotating_serving_certificate?
        @config["server_tls_bootstrap"] == true && @config.dig("feature_gates", "RotateKubeletServerCertificate") != false
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
        return unless rotating_serving_certificate?

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
          Array(@streaming_servers).each { |listener| listener.server.reload_tls!(certificate: certificate, private_key: key) } if certificate && key
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
        @tls_file_reloader&.stop
        @tls_file_reloader = nil
        (Array(@streaming_servers) + Array(@read_only_servers)).each do |server|
          server.stop
        rescue StandardError => error
          log(:error, "streaming.stop_failed", error: error)
        end
        @streaming_servers = nil
        @read_only_servers = nil
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
        return unless @node_resolver.respond_to?(:register)
        return if @node_name.nil? || @node_name.empty?

        @node_resolver.register(@node_name, self)
        @node_endpoint_registered = true
      end

      def unregister_node_endpoint
        return unless @node_endpoint_registered
        return unless @node_resolver.respond_to?(:unregister)

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
