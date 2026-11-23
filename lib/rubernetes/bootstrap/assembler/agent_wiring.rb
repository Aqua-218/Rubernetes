# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Assembler
      # The rubernetes-agent process: its API adapter, runtime, image
      # resolver, volume manager, network and DNS, and the Node::Agent built
      # from them and from the process configuration.
      module AgentWiring
        private

        def register_agent(container)
          container.register(:api_client) { |dependencies| build_api_client(dependencies.resolve(:config).process) }
          container.register(:api_adapter) { |dependencies| build_api_adapter(dependencies) }
          container.register(:image_pull_limiter) { |dependencies| Image::PullLimiter.from_config(dependencies.resolve(:config).process) }
          container.register(:runtime) do |dependencies|
            process = dependencies.resolve(:config).process
            build_runtime(process, adapters: @runtime_adapters, image_resolver: dependencies.resolve(:image_resolver),
                                   pull_limiter: dependencies.resolve(:image_pull_limiter))
          end
          container.register(:image_resolver) do |dependencies|
            build_image_resolver(dependencies.resolve(:config).process, pull_limiter: dependencies.resolve(:image_pull_limiter))
          end
          container.register(:runtime_observer) { |dependencies| build_runtime_observer(dependencies.resolve(:runtime)) }
          container.register(:runtime_cleaner) do |dependencies|
            runtime = dependencies.resolve(:runtime)
            ->(resource) { runtime.cleanup_resource(resource) }
          end
          container.register(:volume) do |dependencies|
            # Projected ServiceAccount tokens are issued through the API server,
            # so the volume manager needs the same client the agent uses.
            build_volume(dependencies.resolve(:config).process, adapters: @runtime_adapters, client: dependencies.resolve(:api_client))
          end
          container.register(:network) do |dependencies|
            build_network(dependencies.resolve(:config).process, adapters: @runtime_adapters, logger: dependencies.resolve(:logger))
          end
          container.register(:lifecycle_network) { |dependencies| lifecycle_network(dependencies) }
          container.register(:node_agent) { |dependencies| build_node_agent(dependencies) }
          container.register(:dns_service) { |dependencies| build_dns_service(dependencies) }
        end

        def build_api_adapter(dependencies)
          process = dependencies.resolve(:config).process
          lease = process.fetch("lease", {})
          client = dependencies.resolve(:api_client)
          Node::APIClientAdapter.new(
            client: client,
            **agent_heartbeat_and_event_clients(client),
            node_name: process.fetch("node_name"),
            external_cloud_provider: process["cloud_provider"] == "external",
            feature_gates: process["feature_gates"] || {},
            lease_namespace: lease.fetch("namespace", Node::Agent::NODE_LEASE_NAMESPACE)
          )
        end

        def agent_heartbeat_and_event_clients(client)
          rest = client.rest_client
          return {} unless rest.is_a?(Client::HTTPClient)

          {
            heartbeat_client: Client::KubernetesClient.new(context: rest.context),
            event_client: Client::KubernetesClient.new(context: rest.context, qps: 50, burst: 100)
          }
        end

        def build_image_resolver(process, pull_limiter:)
          injected(:image_resolver) || Image::Resolver.new(pull_records: image_pull_records(process),
                                                           staging_root: image_staging_root(process),
                                                           public_blob_source: public_image_blob_source(process), pull_limiter: pull_limiter)
        end

        def public_image_blob_source(process)
          path = process.dig("image", "public_blob_source")
          return unless path

          require_relative "../../image/public_blob_source"
          Image::PublicBlobSource.new(path, scratch: [image_staging_root(process), Dir.tmpdir].compact)
        end

        def image_staging_root(process)
          configured = process.dig("image", "staging_root")
          return configured if configured

          profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_")
          return nil if %w[pure fake_io].include?(profile)

          paths = process.fetch("runtime_paths", process.fetch("runtime", {})) || {}
          journal = process.fetch("journal_path", paths.fetch("journal_path", Runtime::Native::Configuration::DEFAULT_JOURNAL_PATH))
          "#{journal}.images"
        end

        def native_image_roots(runtime)
          Image::StagingLease.runtime_roots(native_runtime(runtime).ledger)
        end

        def native_runtime(runtime)
          multiplexer?(runtime) ? runtime.backend_for(Runtime::Multiplexer::DEFAULT_HANDLER) : runtime
        end

        # KubeletEnsureSecretPulledImages (Beta, on): the pull records and
        # the configured verification policy.
        def image_pull_records(process)
          gates = (process["feature_gates"] || {}).to_h
          return nil if gates["KubeletEnsureSecretPulledImages"] == false

          section = (process["image_pull_credentials"] || {}).to_h
          state_dir = section["state_dir"] ||
                      (File.join(File.dirname(File.expand_path(process["kubeconfig"].to_s)), "image_manager") if process["kubeconfig"])
          Image::PullRecords.new(policy: section.fetch("verification_policy", Image::PullRecords::NEVER_VERIFY_PRELOADED),
                                 allowlist: section.fetch("preloaded_images_verification_allowlist", []),
                                 directory: state_dir)
        end

        # Pure/fake profiles own only in-process resources, so their
        # inventory is the complete observer for this process and can be
        # used to reconcile the ephemeral journal at bootstrap. Host and
        # kernel-isolation profiles must never downgrade to this callback:
        # a restart needs an independently collected kernel inventory, so
        # they get the KernelObserver, which re-reads /proc and the
        # filesystem for every durable ownership claim.
        def build_runtime_observer(runtime)
          given = injected(:observer)
          return given if given

          native = native_runtime(runtime)
          pure = native.config.pure_profile?
          return Runtime::Native::KernelObserver.new(ledger: native.ledger) if !pure && native.ledger

          observer = -> { native.resource_inventory }
          observer.define_singleton_method(:external_observer?) { pure }
          observer
        end

        def build_node_agent(dependencies)
          process = dependencies.resolve(:config).process
          runtime = dependencies.resolve(:runtime)
          adapter = dependencies.resolve(:api_adapter)
          logger = dependencies.resolve(:logger)
          network = dependencies.resolve(:network)
          native = native_agent_profile?(process)
          gateways = native && network.is_a?(Network::Interface) ? node_gateway_addresses(network, process) : []
          resource_reader = node_resource_reader(adapter, logger) if native
          pod_options = agent_pod_options(process, native: native, gateways: gateways)
          if pod_options[:pod_root]
            kubelet_root = File.dirname(File.expand_path(pod_options[:pod_root]))
            pod_options[:node_image_config] = Node::ImageCredentials::NodeConfig.new(root: kubelet_root)
          end
          share_image_credentials(runtime, resource_reader, pod_options[:node_image_config]) if resource_reader
          agent = Node::Agent.new(
            node_name: process.fetch("node_name"), api: adapter, runtime: runtime, source: adapter, reporter: adapter,
            volume: dependencies.resolve(:volume), network: dependencies.resolve(:lifecycle_network),
            image_resolver: dependencies.resolve(:image_resolver), resource_reader: resource_reader,
            runtime_class_resolver: runtime_class_resolver(process, reader: resource_reader),
            **agent_sync_options(process), **agent_kubelet_options(process, native: native),
            **agent_node_options(process, gateways), **pod_options,
            **agent_logging_options(logger)
          )
          configure_memory_qos_allocatable(runtime, agent.allocatable["memory"]) if process.dig("feature_gates", "MemoryQoS") == true
          agent
        end

        def configure_memory_qos_allocatable(runtime, quantity)
          return if quantity.nil?

          bytes = Schema::Quantity.from_json(quantity).value.to_i
          backends = multiplexer?(runtime) ? runtime.backends.values : [runtime]
          backends.each do |backend|
            backend.memory_qos_allocatable = bytes if backend.is_a?(Runtime::Native) ||
                                                      (defined?(Runtime::CRI::Backend) && backend.is_a?(Runtime::CRI::Backend))
          end
        end

        def node_resource_reader(adapter, logger)
          Node::ResourceReader.new(client: adapter, logger: ->(level, event, **fields) { logger.public_send(level, event, **fields) })
        end

        # CRI uses the same Pod secrets and node keyring as native pulls.
        def share_image_credentials(runtime, resource_reader, node_config)
          return unless multiplexer?(runtime)

          runtime.backends.each_value do |backend|
            next unless pulls_with_credentials?(backend)

            backend.credential_provider = lambda do |pod, image|
              keyring = Node::ImageCredentials.for_pod(pod, reader: resource_reader, node_config: node_config)
              keyring.empty? ? nil : keyring.lookup(image)
            end
          end
        end

        def lifecycle_network(dependencies)
          network = dependencies.resolve(:network)
          return network unless network.is_a?(Network::Interface)

          process = dependencies.resolve(:config).process
          engine = network.policy_engine
          policy = network_policy_sync(dependencies, process, engine) if engine && native_agent_profile?(process)
          LifecycleNetworkAdapter.new(network, policy_engine: engine, policy_sync: policy)
        end

        def network_policy_sync(dependencies, process, engine)
          kubeconfig = process.dig("network", "policy_kubeconfig")
          client = kubeconfig ? Client::KubernetesClient.from_kubeconfig(path: kubeconfig, **api_rate(process)) : dependencies.resolve(:api_client)
          NetworkPolicySync.new(client: client, engine: engine, node_name: process.fetch("node_name"),
                                logger: dependencies.resolve(:logger), own_client: !kubeconfig.nil?)
        end

        def agent_sync_options(process)
          sync = process.fetch("sync", {})
          lease = process.fetch("lease", {})
          {
            node_namespace: lease.fetch("namespace", Node::Agent::NODE_LEASE_NAMESPACE),
            lease_duration_seconds: lease.fetch("duration_seconds", Node::Agent::DEFAULT_LEASE_DURATION_SECONDS),
            lease_renew_fraction: lease.fetch("renew_fraction", Node::Agent::DEFAULT_LEASE_RENEW_FRACTION),
            sync_period: sync.fetch("period_seconds", Node::SyncLoop::DEFAULT_RESYNC_PERIOD_SECONDS),
            watch_timeout: sync.fetch("watch_timeout_seconds", 30),
            node_status_update_frequency: sync.fetch("node_status_update_frequency_seconds", Node::Agent::NODE_STATUS_UPDATE_FREQUENCY_SECONDS),
            node_status_report_frequency: sync.fetch("node_status_report_frequency_seconds", Node::Agent::NODE_STATUS_REPORT_FREQUENCY_SECONDS)
          }
        end

        # The KubeletConfiguration-style sections, passed through.
        def agent_kubelet_options(process, native:)
          {
            allowed_unsafe_sysctls: Array(process["allowed_unsafe_sysctls"]),
            feature_gates: (process["feature_gates"] || {}).to_h,
            stats_system_cgroups: {"kubelet" => process["kubelet_cgroups"], "runtime" => process["runtime_cgroups"],
                                   "misc" => process["system_cgroups"]}.compact,
            volume_stats_agg_period: process.fetch("volume_stats_agg_period_seconds", Node::KubeletConfigz::DEFAULT_VOLUME_STATS_AGG_PERIOD_SECONDS),
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
            detect_host_resources: native,
            max_pods: process.fetch("max_pods", Node::HostResources::DEFAULT_MAX_PODS), pods_per_core: process.fetch("pods_per_core", 0),
            node_status_max_images: process.fetch("node_status_max_images", Node::StatusImages::MAX_IMAGES),
            crash_loop_back_off_max: (process["crash_loop_back_off"] || {})["max_container_restart_period_seconds"],
            static_pod_path: process["static_pod_path"],
            file_check_frequency: process.fetch("file_check_frequency_seconds", Node::StaticPods::DEFAULT_INTERVAL),
            static_pod_url: process["static_pod_url"], static_pod_url_header: process["static_pod_url_header"] || {},
            http_check_frequency: process.fetch("http_check_frequency_seconds", Node::StaticPods::DEFAULT_INTERVAL),
            # devicemanager: opt-in, because /var/lib/kubelet/device-plugins
            # is the host kubelet's (k3s) on a machine that runs one.
            device_plugin_dir: (process["device_plugins"] || {})["directory"],
            # kubelet podresources (opt-in for the same reason).
            pod_resources_dir: (process["pod_resources"] || {})["directory"],
            pods_api_directory: process["pods_api_directory"],
            # --image-credential-provider-config / -bin-dir.
            image_credential_provider: process["image_credential_provider"]
          }
        end

        # What the Node object says about where to reach this node.
        def agent_node_options(process, gateways)
          addresses = node_addresses(process, gateways: gateways)
          node_ips = addresses.filter_map { |entry| entry.fetch("address") if entry["type"] == "InternalIP" }
          annotations = (process["node_annotations"] || {}).to_h.dup
          external_cloud_provider = process["cloud_provider"] == "external"
          if external_cloud_provider && !Array(process["addresses"]).empty? && !node_ips.empty?
            annotations["alpha.kubernetes.io/provided-node-ip"] = node_ips.join(",")
          end
          {
            streaming_port: streaming_options(process)["port"],
            addresses: addresses,
            external_cloud_provider: external_cloud_provider,
            provider_id: process["provider_id"],
            register_node: process.fetch("register_node", true),
            register_with_taints: process.fetch("register_with_taints", []),
            # The API server dials the streaming endpoint at the address the
            # agent actually listens on, which is not the node's InternalIP
            # unless the agent has an authorizer of its own.
            node_annotations: annotations.merge(
              API::NodeEndpointResolver::STREAMING_ADDRESS_ANNOTATION => streaming_options(process).fetch("advertise_address").to_s
            ),
            host_ips: node_ips,
            cluster_domain: cluster_domain(process)
          }
        end

        # kubelet-side translation (env, security context, volumes,
        # /etc files) only for profiles that run real workloads; the
        # pure profile hands Pods straight to the fake runtime.
        def agent_pod_options(process, native:, gateways:)
          paths = process.fetch("runtime_paths", process.fetch("runtime", {})) || {}
          journal_path = process.fetch("journal_path", paths.fetch("journal_path", Runtime::Native::Configuration::DEFAULT_JOURNAL_PATH))
          options = {state_store: "#{journal_path}.node-state.json", pod_root: nil, probe_connectors: nil, pod_files: nil}
          return options unless native

          dns = dns_options(process)
          cluster_dns = dns["cluster_dns"]
          # If the embedded server is disabled, only explicit clusterDNS addresses
          # are resolvers. The Pod then falls back to the host when none are set.
          if cluster_dns.empty? && dns["enabled"]
            cluster_dns = dns["bind_addresses"].empty? ? gateways : dns["bind_addresses"]
          end
          options.merge(
            pod_root: pod_root(process, journal_path),
            # Native and CRI probe connectors dial the resolved Pod address
            # from the sandbox network namespace. The node-local gRPC client
            # serves runtimes that do not supply a gRPC health operation.
            probe_connectors: {grpc: Node::ProbeConnectors::GRPC.new},
            pod_files: Node::PodFiles.new(cluster_dns: cluster_dns, cluster_domain: cluster_domain(process), resolv_conf: dns["resolv_conf"])
          )
        end

        def agent_logging_options(logger)
          {
            # A sync loop or lease error is the only trace of a node that
            # stopped hearing about Pods; debug never reached the log.
            error_handler: lambda { |error, *event|
              # `event` is the logger's own field (the record's name).
              logger.warn("node.agent_error", error: error.class.name, message: error.message.to_s[0, 300],
                                              during: event.first.to_s)
            },
            lifecycle_logger: ->(level, event, **fields) { logger.public_send(level, event, **fields) }
          }
        end

        def build_dns_service(dependencies)
          process = dependencies.resolve(:config).process
          options = dns_options(process)
          return nil if options["enabled"] == false || !native_agent_profile?(process)

          network = dependencies.resolve(:network)
          addresses = Array(options["bind_addresses"])
          addresses = node_gateway_addresses(network, process) if addresses.empty? && network.is_a?(Network::Interface)
          if options["nat64_prefix"] && addresses.none? { |address| IPAddr.new(address).ipv6? }
            raise Config::Error, "rubernetes-agent.dns.nat64_prefix requires an IPv6 DNS bind address"
          end
          return nil if addresses.empty?

          client = if options["kubeconfig"]
                     Client::KubernetesClient.from_kubeconfig(path: options["kubeconfig"])
                   else
                     dependencies.resolve(:api_client)
                   end
          # An empty kubelet clusterDomain disables Pod search suffixes. The
          # embedded DNS addon still serves its own configured/default zone.
          zone = cluster_domain(process)
          zone = options["cluster_domain"].to_s if zone.empty?
          zone = Network::DNS::Resolver::DEFAULT_DOMAIN if zone.empty?
          Node::DNSService.new(
            client: client, bind_addresses: addresses, port: options["port"], cluster_domain: zone,
            upstreams: options["upstreams"], resolv_conf: options["resolv_conf"], logger: dependencies.resolve(:logger),
            positive_ttl: options["positive_ttl"], negative_ttl: options["negative_ttl"], hosts: options["hosts"],
            nat64_prefix: options["nat64_prefix"]
          )
        end
      end
    end
  end
end
