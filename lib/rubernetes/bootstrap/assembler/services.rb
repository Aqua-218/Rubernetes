# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Assembler
      # The service object of each process.  Tests and probes inject
      # collaborators through +runtime_adapters+; a process started from its
      # configuration builds them itself.
      module Services
        private

        def build_service(dependencies)
          config = dependencies.resolve(:config).process
          logger = dependencies.resolve(:logger)
          case @process_name
          when "rubernetes-apiserver" then api_server_service(config, logger)
          when "rubernetes-agent" then agent_service(dependencies, config, logger)
          when "rubernetes-controller-manager" then controller_manager_service(config, logger)
          when "rubernetes-scheduler" then scheduler_service(config, logger)
          when "rubernetes-proxy" then proxy_service(config, logger)
          else DaemonService.new(process_name: @process_name, config: config, logger: logger)
          end
        end

        def adapter_for(*names)
          names.each do |name|
            return @runtime_adapters[name] if @runtime_adapters.key?(name)

            string_name = name.to_s
            return @runtime_adapters[string_name] if @runtime_adapters.key?(string_name)
          end
          nil
        end

        # An injected collaborator under its Symbol or String name.
        def injected(name)
          @runtime_adapters[name] || @runtime_adapters[name.to_s]
        end

        def api_server_service(config, logger)
          APIServerService.new(
            config: config,
            logger: logger,
            subresource_bridge: adapter_for(:api_subresource_bridge, :subresource_bridge),
            node_resolver: adapter_for(:api_node_resolver, :node_resolver),
            authorizer: adapter_for(:api_authorizer, :authorizer),
            identity_resolver: adapter_for(:api_identity_resolver, :identity_resolver),
            trusted_subresources: adapter_for(:trusted_subresources)
          )
        end

        def agent_service(dependencies, config, logger)
          runtime = dependencies.resolve(:runtime)
          node_agent = dependencies.resolve(:node_agent)
          network = dependencies.resolve(:lifecycle_network)
          AgentService.new(
            config: config,
            logger: logger,
            runtime: runtime,
            image_staging_root: image_staging_root(config),
            live_image_roots: -> { native_image_roots(runtime) + node_agent.lifecycle.image_roots_in_use },
            api_adapter: dependencies.resolve(:api_adapter),
            node_agent: node_agent,
            policy_lifecycle: network.is_a?(LifecycleNetworkAdapter) ? network : nil,
            runtime_observer: dependencies.resolve(:runtime_observer),
            runtime_cleaner: dependencies.resolve(:runtime_cleaner),
            node_resolver: adapter_for(:node_resolver, :api_node_resolver),
            dns_service: dependencies.resolve(:dns_service)
          )
        end

        def controller_manager_service(config, logger)
          ControllerManagerService.new(
            config: config,
            logger: logger,
            client: injected(:controller_client),
            client_factory: -> { build_api_client(config) },
            store: injected(:controller_store),
            manager: injected(:controller_manager),
            registry: injected(:controller_registry),
            informers: injected(:controller_informers),
            resource_sources: injected(:controller_resource_sources) || {},
            runtime_adapters: @runtime_adapters
          )
        end

        def scheduler_service(config, logger)
          SchedulerService.new(
            config: config,
            logger: logger,
            client: injected(:scheduler_client),
            client_factory: -> { build_api_client(config) },
            store: injected(:scheduler_store),
            framework: injected(:scheduler_framework),
            node_informer: injected(:scheduler_node_informer),
            pod_informer: injected(:scheduler_pod_informer),
            resource_sources: injected(:scheduler_resource_sources) || {},
            runtime_adapters: @runtime_adapters
          )
        end

        def proxy_service(config, logger)
          ProxyService.new(
            config: config,
            logger: logger,
            client: injected(:proxy_client),
            client_factory: -> { build_api_client(config) },
            proxy: injected(:proxy),
            resource_sources: injected(:proxy_resource_sources) || {},
            runtime_adapters: @runtime_adapters
          )
        end
      end
    end
  end
end
