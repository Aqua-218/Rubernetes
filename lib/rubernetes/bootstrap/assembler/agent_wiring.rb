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
          container.register(:runtime) do |dependencies|
            build_runtime(dependencies.resolve(:config).process, adapters: @runtime_adapters,
                                                                 image_resolver: dependencies.resolve(:image_resolver))
          end
          container.register(:image_resolver) { |dependencies| build_image_resolver(dependencies.resolve(:config).process) }
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
          container.register(:node_agent) { |dependencies| build_node_agent(dependencies) }
          container.register(:dns_service) { |dependencies| build_dns_service(dependencies) }
        end

        def build_api_adapter(dependencies)
          process = dependencies.resolve(:config).process
          lease = process.fetch("lease", {})
          Node::APIClientAdapter.new(
            client: dependencies.resolve(:api_client),
            node_name: process.fetch("node_name"),
            lease_namespace: lease.fetch("namespace", Node::Agent::NODE_LEASE_NAMESPACE)
          )
        end

        def build_image_resolver(process)
          injected(:image_resolver) || Image::Resolver.new(pull_records: image_pull_records(process))
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

          # The native runtime's profile and ledger (a multiplexer answers
          # with those of its default, native, backend).
          pure = runtime.config.pure_profile?
          return Runtime::Native::KernelObserver.new(ledger: runtime.ledger) if !pure && runtime.ledger

          observer = -> { runtime.resource_inventory }
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
          share_image_credentials(runtime, resource_reader) if resource_reader
          Node::Agent.new(
            node_name: process.fetch("node_name"), api: adapter, runtime: runtime, source: adapter, reporter: adapter,
            volume: dependencies.resolve(:volume), network: lifecycle_network(network),
            image_resolver: dependencies.resolve(:image_resolver), resource_reader: resource_reader,
            runtime_class_resolver: runtime_class_resolver(process, reader: resource_reader),
            **agent_sync_options(process), **agent_kubelet_options(process, native: native),
            **agent_node_options(process, gateways), **agent_pod_options(process, native: native, gateways: gateways),
            **agent_logging_options(logger)
          )
        end

        def node_resource_reader(adapter, logger)
          Node::ResourceReader.new(client: adapter, logger: ->(level, event, **fields) { logger.public_send(level, event, **fields) })
        end

        # CRI pulls carry the Pod's imagePullSecrets the way native pulls do.
        def share_image_credentials(runtime, resource_reader)
          return unless multiplexer?(runtime)

          runtime.backends.each_value do |backend|
            next unless pulls_with_credentials?(backend)

            backend.credential_provider = lambda do |pod, image|
              keyring = Node::ImageCredentials.for_pod(pod, reader: resource_reader)
              keyring.empty? ? nil : keyring.lookup(image)
            end
          end
        end

        def lifecycle_network(network)
          network.is_a?(Network::Interface) ? LifecycleNetworkAdapter.new(network, policy_engine: network.policy_engine) : network
        end

        def agent_sync_options(process)
          sync = process.fetch("sync", {})
          lease = process.fetch("lease", {})
          {
            node_namespace: lease.fetch("namespace", Node::Agent::NODE_LEASE_NAMESPACE),
            lease_duration_seconds: lease.fetch("duration_seconds", Node::Agent::DEFAULT_LEASE_DURATION_SECONDS),
            lease_renew_fraction: lease.fetch("renew_fraction", Node::Agent::DEFAULT_LEASE_RENEW_FRACTION),
            sync_period: sync.fetch("period_seconds", Node::SyncLoop::DEFAULT_RESYNC_PERIOD_SECONDS),
            watch_timeout: sync.fetch("watch_timeout_seconds", 30)
          }
        end

        # The KubeletConfiguration-style sections, passed through.
        def agent_kubelet_options(process, native:)
          {
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
          }
        end

        # What the Node object says about where to reach this node.
        def agent_node_options(process, gateways)
          addresses = node_addresses(process, gateways: gateways)
          {
            streaming_port: streaming_options(process)["port"],
            addresses: addresses,
            # The API server dials the streaming endpoint at the address the
            # agent actually listens on, which is not the node's InternalIP
            # unless the agent has an authorizer of its own.
            node_annotations: (process["node_annotations"] || {}).to_h.merge(
              API::NodeEndpointResolver::STREAMING_ADDRESS_ANNOTATION => streaming_options(process).fetch("advertise_address").to_s
            ),
            host_ip: addresses.find { |entry| entry["type"] == "InternalIP" }&.fetch("address", nil),
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

          options.merge(
            pod_root: pod_root(process, journal_path),
            # HTTP and TCP probes are executed inside the Pod's own network
            # namespace by the runtime connector, the way a CRI runtime
            # probes: the node's root namespace may have no route to a Pod
            # address at all (a host firewall, a foreign CNI), and a probe
            # that cannot reach a healthy container would mark it unready
            # forever.  gRPC has no namespace connector, so it keeps the
            # node-local client.
            probe_connectors: {grpc: Node::ProbeConnectors::GRPC.new},
            pod_files: Node::PodFiles.new(cluster_dns: gateways, cluster_domain: cluster_domain(process),
                                          resolv_conf: dns_options(process)["resolv_conf"])
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
          return nil if addresses.empty?

          client = if options["kubeconfig"]
                     Client::KubernetesClient.from_kubeconfig(path: options["kubeconfig"])
                   else
                     dependencies.resolve(:api_client)
                   end
          Node::DNSService.new(
            client: client, bind_addresses: addresses, port: options["port"], cluster_domain: cluster_domain(process),
            upstreams: options["upstreams"], resolv_conf: options["resolv_conf"], logger: dependencies.resolve(:logger),
            positive_ttl: options["positive_ttl"], negative_ttl: options["negative_ttl"], hosts: options["hosts"]
          )
        end
      end
    end
  end
end
