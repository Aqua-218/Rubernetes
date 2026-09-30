# frozen_string_literal: true

require "ipaddr"

require_relative "config"
require_relative "container"
require_relative "daemon_service"
require_relative "api_server_service"
require_relative "agent_service"
require_relative "control_plane_services"
require_relative "shutdown"
require_relative "structured_logger"
require_relative "../client"
require_relative "../image"
require_relative "../node"
require_relative "../network"
require_relative "../runtime/native"
require_relative "../volume"

module Rubernetes
  module Bootstrap
    # Node::Lifecycle deliberately calls its network port with only the
    # sandbox identity during cleanup.  Network::Interface requires an
    # explicit stop proof before releasing an address, so this narrow adapter
    # supplies that proof only after Lifecycle has stopped the workload.
    class LifecycleNetworkAdapter
      attr_reader :interface

      def initialize(interface, policy_engine: nil)
        @interface = interface
        @policy_engine = policy_engine
        @policy_pods = {}
        @policy_mutex = Mutex.new
      end

      def add(sandbox, config = nil, **options)
        result = @interface.add(sandbox, config, **options)
        return result unless @policy_engine

        sandbox_id = sandbox_id_for(sandbox)
        @policy_mutex.synchronize do
          previous = @policy_pods.dup
          @policy_pods[sandbox_id] = policy_pod(config, result)
          begin
            @policy_engine.sync_pods(@policy_pods.values)
          rescue StandardError => policy_error
            @policy_pods = previous
            cleanup_errors = []
            begin
              @policy_engine.sync_pods(@policy_pods.values)
            rescue StandardError => restore_error
              cleanup_errors << "policy restore failed: #{restore_error.message}"
            end
            begin
              @interface.delete(sandbox, config, stopped: true)
            rescue StandardError => cleanup_error
              cleanup_errors << "network rollback failed: #{cleanup_error.message}"
            end
            detail = cleanup_errors.empty? ? "" : "; #{cleanup_errors.join('; ')}"
            raise Network::PolicyRevisionError,
                  "Pod network policy publication failed for #{sandbox_id}: #{policy_error.message}#{detail}"
          end
        end
        result
      end

      def delete(sandbox, config = nil, **options)
        options = options.dup
        options.delete(:stopped)
        options.delete(:process_stopped)
        options.delete(:confirm_stopped)
        return @interface.delete(sandbox, config, stopped: true, **options) unless @policy_engine

        sandbox_id = sandbox_id_for(sandbox)
        @policy_mutex.synchronize do
          previous = @policy_pods.dup
          @policy_pods.delete(sandbox_id)
          @policy_engine.sync_pods(@policy_pods.values)
          begin
            @interface.delete(sandbox, config, stopped: true, **options)
          rescue StandardError => network_error
            @policy_pods = previous
            begin
              @policy_engine.sync_pods(@policy_pods.values)
            rescue StandardError => restore_error
              raise Network::PolicyRevisionError,
                    "Pod network delete failed for #{sandbox_id} and policy restoration failed: " \
                    "#{network_error.message}; #{restore_error.message}"
            end
            raise
          end
        end
      end

      def check(*arguments, **options)
        @interface.check(*arguments, **options)
      end

      def recover(*arguments, **options)
        @interface.recover(*arguments, **options)
      end

      def method_missing(name, *arguments, **options, &block)
        return super unless @interface.respond_to?(name)

        @interface.public_send(name, *arguments, **options, &block)
      end

      def respond_to_missing?(name, include_private = false)
        @interface.respond_to?(name, include_private) || super
      end

      private

      def sandbox_id_for(value)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        candidate = if hash.is_a?(Hash)
                      hash["sandbox_id"] || hash[:sandbox_id] || hash["id"] || hash[:id]
                    else
                      value
                    end
        Network::Support.identifier(candidate, "sandbox_id")
      end

      def policy_pod(pod, network_result)
        hash = pod.respond_to?(:to_h) ? pod.to_h : (pod || {})
        metadata = hash["metadata"] || hash[:metadata] || {}
        spec = hash["spec"] || hash[:spec] || {}
        ports = Array(spec["containers"] || spec[:containers]).flat_map do |container|
          Array(container["ports"] || container[:ports]).filter_map do |port|
            name = port["name"] || port[:name]
            number = port["containerPort"] || port[:containerPort] || port["port"] || port[:port]
            name && number ? {"name" => name, "port" => number} : nil
          end
        end
        result = network_result.respond_to?(:to_h) ? network_result.to_h : {}
        {
          "namespace" => metadata["namespace"] || metadata[:namespace] || "default",
          "name" => metadata["name"] || metadata[:name] || metadata["uid"] || metadata[:uid],
          "labels" => metadata["labels"] || metadata[:labels] || {},
          "ips" => Array(result["ips"] || result[:ips] || result["ip"] || result[:ip]).compact,
          "ports" => ports,
          "interface" => result["interface"] || result[:interface]
        }
      end
    end

    class Assembler
      Assembly = Data.define(:config, :logger, :shutdown, :service)

      def initialize(process_name:, config_path: nil, log_io: $stderr, clock: -> { Time.now.utc }, runtime_adapters: {})
        @process_name = process_name
        @config_path = config_path
        @log_io = log_io
        @clock = clock
        @runtime_adapters = runtime_adapters.to_h.dup.freeze
      end

      def build
        container = Container.new
        container.register(:config) { Config.load(process_name: @process_name, path: @config_path) }
        container.register(:logger) do |dependencies|
          config = dependencies.resolve(:config)
          StructuredLogger.new(
            io: @log_io,
            process_name: @process_name,
            level: config.logging_level,
            clock: @clock
          )
        end
        container.register(:shutdown) { Shutdown.new }
        if @process_name == "rubernetes-agent"
          container.register(:api_client) do |dependencies|
            build_api_client(dependencies.resolve(:config).process)
          end
          container.register(:api_adapter) do |dependencies|
            process = dependencies.resolve(:config).process
            lease = process.fetch("lease", {})
            Node::APIClientAdapter.new(
              client: dependencies.resolve(:api_client),
              node_name: process.fetch("node_name"),
              lease_namespace: lease.fetch("namespace", Node::Agent::NODE_LEASE_NAMESPACE)
            )
          end
          container.register(:runtime) do |dependencies|
            process = dependencies.resolve(:config).process
            build_runtime(
              process,
              adapters: @runtime_adapters,
              image_resolver: dependencies.resolve(:image_resolver)
            )
          end
          container.register(:image_resolver) do |dependencies|
            injected = @runtime_adapters[:image_resolver] || @runtime_adapters["image_resolver"]
            next injected if injected

            # KubeletEnsureSecretPulledImages (Beta, on): the pull records and
            # the configured verification policy.
            process = dependencies.resolve(:config).process
            gates = (process["feature_gates"] || {}).to_h
            section = (process["image_pull_credentials"] || {}).to_h
            records = if gates["KubeletEnsureSecretPulledImages"] == false
                        nil
                      else
                        state_dir = section["state_dir"] ||
                                    (process["kubeconfig"] ? File.join(File.dirname(File.expand_path(process["kubeconfig"].to_s)), "image_manager") : nil)
                        Image::PullRecords.new(policy: section.fetch("verification_policy", Image::PullRecords::NEVER_VERIFY_PRELOADED),
                                               allowlist: section.fetch("preloaded_images_verification_allowlist", []))
                      end
            Image::Resolver.new(pull_records: records)
          end
          container.register(:runtime_observer) do |dependencies|
            injected = @runtime_adapters[:observer] || @runtime_adapters["observer"]
            next injected if injected

            runtime = dependencies.resolve(:runtime)
            pure = runtime.respond_to?(:config) && runtime.config.respond_to?(:pure_profile?) && runtime.config.pure_profile?
            # Pure/fake profiles own only in-process resources, so their
            # inventory is the complete observer for this process and can be
            # used to reconcile the ephemeral journal at bootstrap. Host and
            # kernel-isolation profiles must never downgrade to this callback:
            # a restart needs an independently collected kernel inventory, so
            # they get the KernelObserver, which re-reads /proc and the
            # filesystem for every durable ownership claim.
            unless pure
              ledger = runtime.respond_to?(:ledger) ? runtime.ledger : nil
              next Runtime::Native::KernelObserver.new(ledger: ledger) if ledger
            end

            observer = -> { runtime.resource_inventory }
            observer.define_singleton_method(:external_observer?) { pure }
            observer
          end
          container.register(:runtime_cleaner) do |dependencies|
            runtime = dependencies.resolve(:runtime)
            ->(resource) { runtime.cleanup_resource(resource) }
          end
          container.register(:volume) do |dependencies|
            process = dependencies.resolve(:config).process
            # Projected ServiceAccount tokens are issued through the API server,
            # so the volume manager needs the same client the agent uses.
            client = begin
              dependencies.resolve(:api_client)
            rescue StandardError
              nil
            end
            build_volume(process, adapters: @runtime_adapters, client: client)
          end
          container.register(:network) do |dependencies|
            process = dependencies.resolve(:config).process
            build_network(process, adapters: @runtime_adapters, logger: dependencies.resolve(:logger))
          end
          container.register(:node_agent) do |dependencies|
            process = dependencies.resolve(:config).process
            sync = process.fetch("sync", {})
            lease = process.fetch("lease", {})
            paths = process.fetch("runtime_paths", process.fetch("runtime", {})) || {}
            journal_path = process.fetch("journal_path", paths.fetch("journal_path", Runtime::Native::Configuration::DEFAULT_JOURNAL_PATH))
            runtime = dependencies.resolve(:runtime)
            adapter = dependencies.resolve(:api_adapter)
            logger = dependencies.resolve(:logger)
            raw_network = dependencies.resolve(:network)
            network = raw_network
            network = LifecycleNetworkAdapter.new(network, policy_engine: network.policy_engine) if network.is_a?(Network::Interface)
            native = native_agent_profile?(process)
            gateways = native && raw_network.is_a?(Network::Interface) ? node_gateway_addresses(raw_network, process) : []
            resource_reader = native ? Node::ResourceReader.new(client: adapter, logger: ->(level, event, **fields) { logger.public_send(level, event, **fields) }) : nil
            # CRI pulls carry the Pod's imagePullSecrets the way native pulls do.
            if resource_reader && runtime.respond_to?(:backends)
              runtime.backends.each_value do |backend|
                next unless backend.respond_to?(:credential_provider=)

                backend.credential_provider = lambda do |pod, image|
                  keyring = Node::ImageCredentials.for_pod(pod, reader: resource_reader)
                  keyring.empty? ? nil : keyring.lookup(image)
                end
              end
            end
            Node::Agent.new(
              node_name: process.fetch("node_name"),
              api: adapter,
              runtime: runtime,
              volume: dependencies.resolve(:volume),
              network: network,
              source: adapter,
              reporter: adapter,
              node_namespace: lease.fetch("namespace", Node::Agent::NODE_LEASE_NAMESPACE),
              lease_duration_seconds: lease.fetch("duration_seconds", Node::Agent::DEFAULT_LEASE_DURATION_SECONDS),
              lease_renew_fraction: lease.fetch("renew_fraction", Node::Agent::DEFAULT_LEASE_RENEW_FRACTION),
              sync_period: sync.fetch("period_seconds", Node::SyncLoop::DEFAULT_RESYNC_PERIOD_SECONDS),
              watch_timeout: sync.fetch("watch_timeout_seconds", 30),
              allowed_unsafe_sysctls: Array(process["allowed_unsafe_sysctls"]),
              feature_gates: (process["feature_gates"] || {}).to_h,
              eviction: (process["eviction"] || {}).to_h,
              image_gc: (process["image_gc"] || {}).to_h,
              dra: (process["dra"] || {}).to_h,
              system_reserved: (process["system_reserved"] || {}).to_h,
              kube_reserved: (process["kube_reserved"] || {}).to_h,
              # kubelet cgroupsPerQOS / enforceNodeAllocatable ([pods] by
              # default): the Pods' root cgroup and the QoS classes' weights.
              qos_cgroups: native ? qos_cgroups(process) : nil,
              reserved_system_cpus: process["reserved_system_cpus"],
              cpu_manager: (process["cpu_manager"] || {}).to_h,
              memory_manager: (process["memory_manager"] || {}).to_h,
              topology_manager: (process["topology_manager"] || {}).to_h,
              shutdown: (process["shutdown"] || {}).to_h,
              image_resolver: dependencies.resolve(:image_resolver),
              state_store: "#{journal_path}.node-state.json",
              runtime_class_resolver: runtime_class_resolver(process, reader: resource_reader),
              streaming_port: streaming_options(process)["port"],
              addresses: node_addresses(process, gateways: gateways),
              # The API server dials the streaming endpoint at the address the
              # agent actually listens on, which is not the node's InternalIP
              # unless the agent has an authorizer of its own.
              node_annotations: (process["node_annotations"] || {}).to_h.merge(
                API::NodeEndpointResolver::STREAMING_ADDRESS_ANNOTATION =>
                  streaming_options(process).fetch("advertise_address").to_s
              ),
              # A sync loop or lease error is the only trace of a node that
              # stopped hearing about Pods; debug never reached the log.
              error_handler: lambda { |error, *event|
                # `event` is the logger's own field (the record's name).
                logger.warn("node.agent_error", error: error.class.name, message: error.message.to_s[0, 300],
                                                during: event.first.to_s)
              },
              lifecycle_logger: ->(level, event, **fields) { logger.public_send(level, event, **fields) },
              # kubelet-side translation (env, security context, volumes,
              # /etc files) only for profiles that run real workloads; the
              # pure profile hands Pods straight to the fake runtime.
              pod_root: native ? pod_root(process, journal_path) : nil,
              resource_reader: resource_reader,
              host_ip: node_addresses(process, gateways: gateways).find { |entry| entry["type"] == "InternalIP" }&.fetch("address", nil),
              cluster_domain: cluster_domain(process),
              # HTTP and TCP probes are executed inside the Pod's own network
              # namespace by the runtime connector, the way a CRI runtime
              # probes: the node's root namespace may have no route to a Pod
              # address at all (a host firewall, a foreign CNI), and a probe
              # that cannot reach a healthy container would mark it unready
              # forever.  gRPC has no namespace connector, so it keeps the
              # node-local client.
              probe_connectors: native ? {grpc: Node::ProbeConnectors::GRPC.new} : nil,
              pod_files: native ? Node::PodFiles.new(cluster_dns: gateways, cluster_domain: cluster_domain(process),
                                                     resolv_conf: dns_options(process)["resolv_conf"]) : nil,
              detect_host_resources: native,
              max_pods: process.fetch("max_pods", Node::HostResources::DEFAULT_MAX_PODS),
              crash_loop_back_off_max: (process["crash_loop_back_off"] || {})["max_container_restart_period_seconds"],
              static_pod_path: process["static_pod_path"],
              # devicemanager: opt-in, because /var/lib/kubelet/device-plugins
              # is the host kubelet's (k3s) on a machine that runs one.
              device_plugin_dir: (process["device_plugins"] || {})["directory"],
              # kubelet podresources (opt-in for the same reason).
              pod_resources_dir: (process["pod_resources"] || {})["directory"],
              # --image-credential-provider-config / -bin-dir.
              image_credential_provider: process["image_credential_provider"]
            )
          end
          container.register(:dns_service) do |dependencies|
            process = dependencies.resolve(:config).process
            options = dns_options(process)
            next nil if options["enabled"] == false || !native_agent_profile?(process)

            network = dependencies.resolve(:network)
            addresses = Array(options["bind_addresses"])
            addresses = node_gateway_addresses(network, process) if addresses.empty? && network.is_a?(Network::Interface)
            next nil if addresses.empty?

            client = if options["kubeconfig"]
                       Client::KubernetesClient.from_kubeconfig(path: options["kubeconfig"])
                     else
                       dependencies.resolve(:api_client)
                     end
            Node::DNSService.new(
              client: client,
              bind_addresses: addresses,
              port: options["port"],
              cluster_domain: cluster_domain(process),
              upstreams: options["upstreams"],
              resolv_conf: options["resolv_conf"],
              logger: dependencies.resolve(:logger),
              positive_ttl: options["positive_ttl"],
              negative_ttl: options["negative_ttl"]
            )
          end
        end
        container.register(:service) do |dependencies|
          config = dependencies.resolve(:config).process
          logger = dependencies.resolve(:logger)
          if @process_name == "rubernetes-apiserver"
            APIServerService.new(
              config: config,
              logger: logger,
              subresource_bridge: adapter_for(:api_subresource_bridge, :subresource_bridge),
              node_resolver: adapter_for(:api_node_resolver, :node_resolver),
              authorizer: adapter_for(:api_authorizer, :authorizer),
              identity_resolver: adapter_for(:api_identity_resolver, :identity_resolver),
              trusted_subresources: adapter_for(:trusted_subresources)
            )
          elsif @process_name == "rubernetes-agent"
            AgentService.new(
              config: config,
              logger: logger,
              runtime: dependencies.resolve(:runtime),
              api_adapter: dependencies.resolve(:api_adapter),
              node_agent: dependencies.resolve(:node_agent),
              runtime_observer: dependencies.resolve(:runtime_observer),
              runtime_cleaner: dependencies.resolve(:runtime_cleaner),
              node_resolver: adapter_for(:node_resolver, :api_node_resolver),
              dns_service: dependencies.resolve(:dns_service)
            )
          elsif @process_name == "rubernetes-controller-manager"
            ControllerManagerService.new(
              config: config,
              logger: logger,
              client: @runtime_adapters[:controller_client] || @runtime_adapters["controller_client"],
              client_factory: -> { build_api_client(config) },
              store: @runtime_adapters[:controller_store] || @runtime_adapters["controller_store"],
              manager: @runtime_adapters[:controller_manager] || @runtime_adapters["controller_manager"],
              registry: @runtime_adapters[:controller_registry] || @runtime_adapters["controller_registry"],
              informers: @runtime_adapters[:controller_informers] || @runtime_adapters["controller_informers"],
              resource_sources: @runtime_adapters[:controller_resource_sources] || @runtime_adapters["controller_resource_sources"] || {},
              runtime_adapters: @runtime_adapters
            )
          elsif @process_name == "rubernetes-scheduler"
            SchedulerService.new(
              config: config,
              logger: logger,
              client: @runtime_adapters[:scheduler_client] || @runtime_adapters["scheduler_client"],
              client_factory: -> { build_api_client(config) },
              store: @runtime_adapters[:scheduler_store] || @runtime_adapters["scheduler_store"],
              framework: @runtime_adapters[:scheduler_framework] || @runtime_adapters["scheduler_framework"],
              node_informer: @runtime_adapters[:scheduler_node_informer] || @runtime_adapters["scheduler_node_informer"],
              pod_informer: @runtime_adapters[:scheduler_pod_informer] || @runtime_adapters["scheduler_pod_informer"],
              resource_sources: @runtime_adapters[:scheduler_resource_sources] || @runtime_adapters["scheduler_resource_sources"] || {},
              runtime_adapters: @runtime_adapters
            )
          elsif @process_name == "rubernetes-proxy"
            ProxyService.new(
              config: config,
              logger: logger,
              client: @runtime_adapters[:proxy_client] || @runtime_adapters["proxy_client"],
              client_factory: -> { build_api_client(config) },
              proxy: @runtime_adapters[:proxy] || @runtime_adapters["proxy"],
              resource_sources: @runtime_adapters[:proxy_resource_sources] || @runtime_adapters["proxy_resource_sources"] || {},
              runtime_adapters: @runtime_adapters
            )
          else
            DaemonService.new(process_name: @process_name, config: config, logger: logger)
          end
        end
        container.seal!

        Assembly.new(
          config: container.resolve(:config),
          logger: container.resolve(:logger),
          shutdown: container.resolve(:shutdown),
          service: container.resolve(:service)
        )
      end

      private

      def adapter_for(*names)
        names.each do |name|
          return @runtime_adapters[name] if @runtime_adapters.key?(name)
          string_name = name.to_s
          return @runtime_adapters[string_name] if @runtime_adapters.key?(string_name)
        end
        nil
      end

      def build_api_client(process)
        kubeconfig = process["kubeconfig"]
        context = process["context"]
        bootstrap_client_certificate!(process) if process["bootstrap_kubeconfig"] && kubeconfig
        if kubeconfig || context
          Client::KubernetesClient.from_kubeconfig(path: kubeconfig, context: context)
        else
          api_server = process["api_server"]
          raise Config::Error, "control-plane process requires api_server or kubeconfig/context" if api_server.to_s.empty?

          Client::KubernetesClient.new(server: api_server)
        end
      end

      # kubelet --bootstrap-kubeconfig: the node's client certificate is
      # requested with the bootstrap credentials (a bootstrap token) and the
      # kubeconfig written to use it, unless it already holds a valid one.
      def bootstrap_client_certificate!(process)
        bootstrap = Client::KubernetesClient.from_kubeconfig(path: process["bootstrap_kubeconfig"])
        context = bootstrap.context
        client_certificate_manager(process).bootstrap!(
          kubeconfig_path: process["kubeconfig"], bootstrap_client: bootstrap,
          server: context.respond_to?(:server) ? context.server : context[:server],
          ca_file: context.respond_to?(:ca_file) ? context.ca_file : context[:ca_file]
        )
      end

      def client_certificate_manager(process)
        cert_dir = process["cert_dir"] || File.join(File.dirname(File.expand_path(process.fetch("kubeconfig"))), "pki")
        Node::ClientCertificateManager.new(node_name: process.fetch("node_name"), cert_dir: cert_dir)
      end

      def build_volume(process, adapters: {}, client: nil)
        injected = adapters[:volume] || adapters["volume"]
        return injected if injected

        options = process["volume"]
        return nil unless options

        config = options.to_h
        runtime_profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
        volume_profile = config["profile"]&.to_s&.downcase&.tr("-", "_")
        native_profile = %i[host_integration kernel_isolation l3].include?(runtime_profile) || volume_profile == "native"
        if native_profile && %w[test fake_io].include?(volume_profile)
          raise Config::Error, "native runtime profiles require the native volume profile"
        end

        mount_adapter = adapters[:mount_adapter] || adapters["mount_adapter"]
        device_adapter = adapters[:device_adapter] || adapters["device_adapter"]
        volume_adapter = adapters[:volume_adapter] || adapters["volume_adapter"]
        if !native_profile && volume_profile.nil? && runtime_profile != :fake_io &&
           [mount_adapter, device_adapter, volume_adapter].all?(&:nil?)
          raise Config::Error, "volume.profile must explicitly select test for the fake volume adapter"
        end
        if native_profile
          uuid_resolver = adapters[:filesystem_uuid_resolver] || adapters["filesystem_uuid_resolver"]
          uuid_resolver ||= Volume::FilesystemUuidResolver.new
          mount_adapter ||= Volume::NativeMountAdapter.new(filesystem_uuid_resolver: uuid_resolver)
          device_adapter ||= Volume::NativeDeviceAdapter.new
          volume_adapter ||= mount_adapter
        end
        csi = build_volume_csi(config["csi"], adapters: adapters)
        resolver = adapters[:volume_resolver] || adapters["volume_resolver"]
        path_security = adapters[:volume_path_security] || adapters["volume_path_security"]
        path_security ||= if resolver
                            Volume::PathSecurity.new(
                              root: config.fetch("root", File.join(config.fetch("data_dir"), "volumes")),
                              resolver: resolver
                            )
                          else
                            unless defined?(Rubernetes::Platform::Linux::Openat2)
                              raise Config::Error, "volume path security requires the Linux openat2 resolver"
                            end
                            openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
                            Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
                          end

        Volume::Manager.new(
          data_dir: config.fetch("data_dir"),
          root: config.fetch("root", File.join(config.fetch("data_dir"), "volumes")),
          adapter: volume_adapter,
          mount_adapter: mount_adapter,
          device_adapter: device_adapter,
          path_security: path_security,
          csi: csi,
          secret_resolver: adapters[:csi_secret_resolver] || adapters["csi_secret_resolver"],
          token_provider: adapters[:volume_token_provider] || adapters["volume_token_provider"] ||
                          (client && Volume::ServiceAccountTokenProvider.new(client: client)),
          require_real_readback: native_profile,
          fsync: config.fetch("fsync", true)
        )
      end

      def build_volume_csi(config, adapters: {})
        injected = adapters[:csi] || adapters["csi"]
        return injected unless config

        options = config.to_h
        csi = injected || Volume::CSIBridge.new(
          socket: options.fetch("socket"),
          timeout: options.fetch("timeout", 30),
          expected_socket_uid: options.fetch("socket_uid", Process.euid),
          expected_socket_gid: options.fetch("socket_gid", Process.egid),
          expected_socket_mode: options["socket_mode"],
          expected_peer_uid: options.fetch("peer_uid", Process.euid),
          expected_peer_gid: options.fetch("peer_gid", Process.egid)
        )

        identity = normalize_csi_identity(csi.identity)
        expected = options["identity"]
        if expected
          expected_name = expected.fetch("name")
          expected_vendor = expected["vendor_version"] || expected["vendorVersion"]
          unless identity.name == expected_name && (!expected_vendor || identity.vendor_version == expected_vendor)
            actual = "#{identity.name}@#{identity.vendor_version}"
            wanted = expected_vendor ? "#{expected_name}@#{expected_vendor}" : expected_name
            raise Config::Error, "CSI identity mismatch: expected #{wanted}, got #{actual}"
          end
        end

        if options.fetch("probe", true)
          ready = if csi.respond_to?(:ready?)
                    csi.ready?
                  elsif csi.respond_to?(:probe)
                    result = csi.probe
                    result.respond_to?(:fetch) ? result.fetch("ready", result.fetch(:ready, true)) == true : result == true
                  else
                    raise Config::Error, "configured CSI adapter does not implement probe/ready?"
                  end
          raise Config::Error, "CSI plugin #{identity.name} is not ready" unless ready
        end
        csi
      rescue Config::Error
        raise
      rescue StandardError => error
        socket = options && options["socket"]
        raise Config::Error.new("CSI startup validation failed for #{socket || "injected adapter"}: #{error.message}"), cause: error
      end

      def normalize_csi_identity(value)
        return value if value.respond_to?(:name) && value.respond_to?(:vendor_version)

        hash = value.respond_to?(:to_h) ? value.to_h : {}
        name = hash["name"] || hash[:name] || hash["pluginName"] || hash[:pluginName]
        vendor = hash["vendorVersion"] || hash[:vendorVersion] || hash["vendor_version"] || hash[:vendor_version]
        raise Config::Error, "CSI identity response must include name and vendor version" if name.to_s.empty? || vendor.to_s.empty?

        Volume::Identity.new(name: name, vendor_version: vendor)
      end

      def build_network(process, adapters: {}, logger: nil)
        injected = adapters[:network] || adapters["network"]
        return injected if injected

        options = process["network"]
        return nil unless options

        config = options.to_h
        runtime_profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
        native_profile = %i[host_integration kernel_isolation l3].include?(runtime_profile) || config["profile"].to_s == "native"
        adapter = adapters[:network_adapter] || adapters["network_adapter"]
        netlink = adapters[:netlink] || adapters["netlink"]
        netlink ||= Network::Netlink.new if adapter.nil?
        # IPAM takes keyword arguments and collects anything unrecognised into
        # **_options.  A configuration read from YAML has String keys, so
        # splatting it verbatim drops every CIDR into that catch-all and leaves
        # the keywords nil -- the agent then fails with "at least one cluster
        # CIDR is required" while the config plainly sets one.
        ipam_options = config.slice("cluster_cidr", "ipv4_cidr", "ipv6_cidr", "node_subnet_prefix",
                                    "ipv4_node_prefix", "ipv6_node_prefix")
                             .transform_keys(&:to_sym)
        state_path = config.fetch("state_path")
        ipam = Network::IPAM.new(**ipam_options, state_path: "#{state_path}.ipam.json", fsync: config.fetch("fsync", true))
        observer = adapters[:network_observer] || adapters["network_observer"]
        observer ||= Network::NativeObserver.new(netlink: netlink) if native_profile && netlink
        ledger = adapters[:network_ledger] || adapters["network_ledger"]
        journal = nil
        if native_profile && ledger.nil?
          journal_path = config.fetch("ledger_path", "#{state_path}.ledger.wal")
          journal = Runtime::Native::RollbackJournal.new(journal_path, fsync: config.fetch("fsync", true))
          ledger = Runtime::Native::OwnershipLedger.new(journal: journal, clock: @clock)
        end
        sysctl_manager = adapters[:network_sysctl_manager] || adapters["network_sysctl_manager"]
        if native_profile && sysctl_manager.nil?
          sysctl_manager = Network::SysctlManager.new(state_path: "#{state_path}.sysctl.json", journal: journal,
                                                       fsync: config.fetch("fsync", true))
        end
        policy_engine = build_network_policy(config, native_profile: native_profile, adapters: adapters)
        bridge_manager = adapters[:network_bridge_manager] || adapters["network_bridge_manager"] ||
          Network::BridgeManager.new(netlink: netlink, adapter: adapter)
        topology = adapters[:network_topology] || adapters["network_topology"] ||
          Network::Topology.new(netlink: netlink, adapter: adapter,
                                bridge_name: config.fetch("bridge_name", Network::Topology::DEFAULT_BRIDGE),
                                mtu: config.fetch("mtu", 1500), bridge_manager: bridge_manager, clock: @clock)
        interface = Network::Interface.new(
          ipam: ipam,
          topology: topology,
          netlink: netlink,
          adapter: adapter,
          ledger: ledger,
          observer: observer,
          policy_engine: policy_engine,
          bridge_manager: bridge_manager,
          sysctl_manager: sysctl_manager,
          state_path: state_path,
          bridge_name: config.fetch("bridge_name", Network::Topology::DEFAULT_BRIDGE),
          mtu: config.fetch("mtu", 1500),
          # Attaching one Pod's network persists its operation about twenty
          # times, and two fsyncs apiece put every concurrent Pod start on the
          # node behind the disk.  The rename still leaves a whole state on
          # disk; only the durability barrier is coalesced, exactly as the
          # node's lifecycle state already does.  "fsync": false in the config
          # still means no barrier at all.
          fsync: config.fetch("fsync", true) == false ? false : :deferred,
          require_observer: native_profile,
          # The cluster-wide Pod CIDRs, not this node's slice: the host has to
          # forward to every node's Pods, not only its own.
          cluster_cidrs: ipam_options.values_at(:cluster_cidr, :ipv4_cidr, :ipv6_cidr).flatten.compact,
          logger: logger
        )
        # A node agent is one Ruby process on one interpreter lock; the
        # network attach work runs in a worker process of its own so it uses
        # another core (see Network::Worker).  "worker": false keeps it in
        # the agent.
        return interface unless native_profile && config.fetch("worker", true) != false

        Network::Worker.fork_for(interface, logger: logger)
      end

      def build_network_policy(config, native_profile:, adapters:)
        injected_engine = adapters[:network_policy_engine] || adapters["network_policy_engine"]
        return injected_engine if injected_engine

        policy_adapter = adapters[:network_policy_adapter] || adapters["network_policy_adapter"]
        backend = config["policy_backend"]&.to_s&.downcase
        backend ||= "nftables" if native_profile && policy_adapter.nil?
        return nil if backend == "disabled" || (backend.nil? && policy_adapter.nil?)

        policy_adapter ||= case backend
                           when "ebpf"
                             Network::EBPFPolicyAdapter.new
                           when "nftables"
                             Network::NftablesPolicyAdapter.new(
                               table_name: config.fetch("policy_table", "rubernetes_policy"),
                               instance_identity: config["policy_instance_identity"]
                             )
                           else
                             raise Config::Error, "network.policy_backend must select ebpf or nftables"
                           end
        packet_matrix = adapters[:network_policy_packet_matrix] || adapters["network_policy_packet_matrix"]
        policy_adapter.verify_packet_matrix!(matrix: packet_matrix) if packet_matrix && policy_adapter.respond_to?(:verify_packet_matrix!)
        Network::PolicyEngine.new(adapter: policy_adapter, clock: @clock)
      end

      def build_runtime(process, adapters: {}, image_resolver: nil)
        profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
        privileged = process.fetch("privileged", false) == true
        if privileged && %i[pure fake_io].include?(profile)
          raise Runtime::Native::CapabilityError, "privileged agent runtime requires an explicit host-capable profile"
        end

        paths = process.fetch("runtime_paths", process.fetch("runtime", {})) || {}
        sandbox_root = process.fetch("sandbox_root", paths.fetch("sandbox_root", Runtime::Native::Configuration::DEFAULT_SANDBOX_ROOT))
        cgroup_root = process.fetch("cgroup_root", paths.fetch("cgroup_root", Runtime::Native::Configuration::DEFAULT_CGROUP_ROOT))
        runtime_adapters = adapters.to_h
        if %i[host_integration kernel_isolation l3].include?(profile)
          runtime_adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
            profile: profile,
            sandbox_root: sandbox_root,
            cgroup_root: cgroup_root,
            architecture: process["architecture"]
          ).merge(runtime_adapters)
        end
        runtime = Runtime::Native.new(
          adapters: runtime_adapters,
          image_resolver: image_resolver,
          profile: profile,
          sandbox_root: sandbox_root,
          cgroup_root: cgroup_root,
          log_root: process.fetch("log_root", paths.fetch("log_root", Runtime::Native::Configuration::DEFAULT_LOG_ROOT)),
          journal_path: process.fetch("journal_path", paths.fetch("journal_path", Runtime::Native::Configuration::DEFAULT_JOURNAL_PATH)),
          l3: process.fetch("l3", false),
          security_context: {"privileged" => privileged},
          # kubelet: Localhost seccomp profiles live under <root-dir>/seccomp.
          seccomp_root: process.fetch("seccomp_root", File.join(File.dirname(process.fetch("journal_path", paths.fetch("journal_path", Runtime::Native::Configuration::DEFAULT_JOURNAL_PATH))), "seccomp"))
        )
        if privileged && !privileged_capabilities_available?(runtime)
          raise Runtime::Native::CapabilityError, "privileged agent runtime capabilities are unavailable"
        end
        wrap_microvm_backends(runtime, process)
      end

      # When the microvm section is enabled the node serves three runtime
      # handlers; the multiplexer routes each Pod to the backend of its
      # RuntimeClass handler and remembers the owner of every sandbox.
      def wrap_microvm_backends(native, process)
        section = process["microvm"]
        backends = {"rubernetes-native" => native}
        backends.merge!(microvm_backends(section)) if section.is_a?(Hash) && section["enabled"] == true
        backends.merge!(cri_backends(process["cri"])) if process["cri"].is_a?(Hash) && process["cri"]["enabled"] == true
        return native if backends.length == 1

        Runtime::Multiplexer.new(backends: backends)
      end

      # One CRI backend per handler, sharing the runtime connection.
      def cri_backends(section)
        require "rubernetes/runtime/cri"
        client = Runtime::CRI::Client.new(endpoint: section.fetch("endpoint"), timeout: section.fetch("timeout_seconds", 60))
        # kubelet containerLogMaxSize (10Mi) / containerLogMaxFiles (5).
        log_manager = Runtime::CRI::LogManager.new(
          client: client, max_files: section.fetch("container_log_max_files", 5),
          max_size: Schema::Quantity.from_json(section.fetch("container_log_max_size", "10Mi").to_s).value.to_i
        )
        handlers = section.fetch("handlers", {"cri" => ""})
        handlers.to_h do |name, handler|
          [name.to_s, Runtime::CRI::Backend.new(client: client, handler: handler.to_s, log_manager: log_manager,
                                                log_root: section.fetch("log_root", "/var/log/pods"),
                                                # Beside the native hierarchy, never in it: the
                                                # native runtime's cgroup scan must not meet CRI Pods.
                                                cgroup_parent: section.fetch("cgroup_parent", "/rubernetes-cri"))]
        end
      end

      def microvm_backends(section)
        require "rubernetes/runtime/microvm"
        options = {
          data_dir: section.fetch("data_dir", "/var/lib/rubernetes/microvm"),
          chroot_base: section.fetch("chroot_base", Runtime::MicroVM::DEFAULT_CHROOT_BASE),
          netns_root: section.fetch("netns_root", Runtime::MicroVM::DEFAULT_NETNS_ROOT),
          run_root: section.fetch("run_root", Runtime::MicroVM::DEFAULT_RUN_ROOT),
          parent_cgroup: section.fetch("parent_cgroup", Runtime::MicroVM::DEFAULT_PARENT_CGROUP),
          machine: {"vcpu_count" => section.fetch("vcpu_count", 1), "mem_size_mib" => section.fetch("mem_size_mib", 512)},
          use_base_snapshot: section.fetch("use_base_snapshot", true),
          artifacts_lock: section["artifacts_lock"]
        }.compact
        {
          "rubernetes-firecracker" => Runtime::MicroVM.new(**options.merge(data_dir: File.join(options[:data_dir], "firecracker"))),
          "rubernetes-firecracker-restricted" => Runtime::MicroVMRestricted.new(**options.merge(data_dir: File.join(options[:data_dir], "restricted")))
        }
      end

      # RuntimeClass name -> handler resolver for the node lifecycle.
      DEFAULT_STREAMING_PORT = 10_250

      # The node's kubelet-style streaming endpoint: where the API server
      # proxies logs/exec/attach/port-forward to.
      def qos_cgroups(process)
        paths = process.fetch("runtime_paths", process.fetch("runtime", {})) || {}
        {"enabled" => process.fetch("cgroups_per_qos", true) != false,
         "root" => process.fetch("cgroup_root", paths.fetch("cgroup_root", Runtime::Native::Configuration::DEFAULT_CGROUP_ROOT)),
         "hierarchy" => Rubernetes::Platform::Linux::CgroupV2::HIERARCHY_PREFIX,
         "enforce_node_allocatable" => process.fetch("enforce_node_allocatable", ["pods"]),
         "system_reserved_cgroup" => process["system_reserved_cgroup"],
         "kube_reserved_cgroup" => process["kube_reserved_cgroup"]}.compact
      end

      def native_agent_profile?(process)
        profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
        %i[host_integration kernel_isolation l3].include?(profile)
      end

      def pod_root(process, journal_path)
        process["pod_root"] || File.join(File.dirname(journal_path), "pods")
      end

      def cluster_domain(process)
        (process["cluster_domain"] || dns_options(process)["cluster_domain"] || "cluster.local").to_s
      end

      DEFAULT_DNS_PORT = 53

      def dns_options(process)
        options = (process["dns"] || {}).to_h
        {
          "enabled" => options.fetch("enabled", true) != false,
          "port" => Integer(options.fetch("port", DEFAULT_DNS_PORT)),
          "bind_addresses" => Array(options["bind_addresses"]),
          "upstreams" => Array(options["upstreams"]),
          "cluster_domain" => options["cluster_domain"],
          "resolv_conf" => options["resolv_conf"] || process["resolv_conf"] || "/etc/resolv.conf",
          "positive_ttl" => options.fetch("positive_ttl", 5),
          "negative_ttl" => options.fetch("negative_ttl", 5),
          # The resolver's own identity (the cluster DNS add-on's, CoreDNS
          # running as its service account): it watches every Service,
          # EndpointSlice and Pod, which a node identity may not.
          "kubeconfig" => options["kubeconfig"]
        }
      end

      # The node's bridge addresses double as the Pods' DNS server; creating
      # the bridge here means the address exists before the first Pod.
      def node_gateway_addresses(network, process)
        @node_gateways ||= {}
        key = process.fetch("node_name").to_s
        @node_gateways[key] ||= begin
          gateways = network.ensure_node_bridge(owner: "node:#{key}")
          gateways.values.map { |entry| entry.fetch("address") }
        rescue StandardError => error
          raise Config::Error, "node bridge could not be prepared for cluster DNS: #{error.message}"
        end
      end

      def streaming_options(process)
        options = (process["streaming"] || {}).to_h
        {
          "enabled" => options.fetch("enabled", true) != false,
          "host" => options.fetch("host", "127.0.0.1"),
          "port" => Integer(options.fetch("port", DEFAULT_STREAMING_PORT)),
          "advertise_address" => options["advertise_address"] || options["address"] || options.fetch("host", "127.0.0.1")
        }
      end

      # The API server resolves the streaming endpoint from the Node's own
      # status.addresses, so the agent has to publish one.
      #
      # A loopback address is not a node address.  kubelet refuses one outright
      # -- "--node-ip cannot be a loopback address" (pkg/kubelet/kubelet.go) --
      # because everything that dials a node by its InternalIP does so from
      # somewhere else: another node, a Pod, the API server.  Publishing
      # 127.0.0.1 sent every one of those callers to its own loopback instead,
      # so a HostPort listener was unreachable from the Pod that was meant to
      # reach it.  With nothing better configured the node's own Pod bridge
      # address is the address its Pods and this host share.
      def node_addresses(process, gateways: [])
        configured = Array(process["addresses"])
        return configured unless configured.empty?

        advertised = streaming_options(process).fetch("advertise_address").to_s
        advertised = routable_node_address(gateways) || advertised if loopback_address?(advertised)
        [{"type" => "InternalIP", "address" => advertised},
         {"type" => "Hostname", "address" => process.fetch("node_name")}]
      end

      def loopback_address?(value)
        address = IPAddr.new(value.to_s)
        address.loopback? || value.to_s == "0.0.0.0" || value.to_s == "::"
      rescue StandardError
        false
      end

      def routable_node_address(gateways)
        Array(gateways).map(&:to_s).find { |address| !address.empty? && !loopback_address?(address) }
      end

      # kubelet's runtimeclass manager: a Pod's RuntimeClass object names its
      # handler (read through the node's cached reader); the node's own table
      # (native, microVM, CRI handlers, configured runtime_classes) serves
      # the names the API does not know.
      def runtime_class_resolver(process, reader: nil)
        require "rubernetes/runtime/microvm/runtime_classes"
        # A CRI handler is served under its own name as a RuntimeClass too.
        cri = process["cri"].is_a?(Hash) && process["cri"]["enabled"] == true ? process["cri"].fetch("handlers", {"cri" => ""}) : {}
        table = Runtime::MicroVMRuntimeClasses.handler_table(cri.keys.to_h { |name| [name, name] }.merge(process["runtime_classes"] || {}))
        lambda do |pod|
          name = pod.dig("spec", "runtimeClassName") || pod.dig(:spec, :runtimeClassName)
          next nil if name.nil? || name.to_s.empty?

          handler = runtime_class_handler(reader, name.to_s)
          next handler if handler

          table.fetch(name.to_s) { raise Node::Lifecycle::LifecycleError, "runtime class #{name.inspect} is not provided by this node" }
        end
      end

      def runtime_class_handler(reader, name)
        return nil if reader.nil?

        handler = reader.get("runtimeclass", name)&.dig("handler").to_s
        handler.empty? ? nil : handler
      rescue StandardError
        # Unreadable now (not found, API unavailable): the node's table.
        nil
      end

      def privileged_capabilities_available?(runtime)
        probe = runtime.security.probe
        %w[SYS_ADMIN SYS_CHROOT SETUID SETGID].all? { |name| probe.capability?(name) }
      rescue NoMethodError
        false
      end
    end
  end
end
