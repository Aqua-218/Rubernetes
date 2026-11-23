# frozen_string_literal: true

require "ipaddr"

require_relative "config"
require_relative "container"
require_relative "daemon_service"
require_relative "api_server_service"
require_relative "agent_service"
require_relative "control_plane_services"
require_relative "network_policy_sync"
require_relative "shutdown"
require_relative "structured_logger"
require_relative "../client"
require_relative "../image"
require_relative "../node"
require_relative "../network"
require_relative "../runtime/native"
require_relative "../volume"

require_relative "assembler/services"
require_relative "assembler/client_builder"
require_relative "assembler/agent_wiring"
require_relative "assembler/node_options"
require_relative "assembler/runtime_builder"
require_relative "assembler/volume_builder"
require_relative "assembler/network_builder"

module Rubernetes
  module Bootstrap
    # Node::Lifecycle deliberately calls its network port with only the
    # sandbox identity during cleanup.  Network::Interface requires an
    # explicit stop proof before releasing an address, so this narrow adapter
    # supplies that proof only after Lifecycle has stopped the workload.
    class LifecycleNetworkAdapter
      attr_reader :interface

      def initialize(interface, policy_engine: nil, policy_sync: nil)
        @interface = interface
        @policy_engine = policy_sync || policy_engine
        @policy_sync = policy_sync
        @policy_pods = {}
        @policy_mutex = Mutex.new
      end

      def start_policy(lifecycle, runtime: nil)
        return unless @policy_sync

        @policy_mutex.synchronize do
          @policy_pods = recover_policy_pods(lifecycle, runtime)
          @policy_sync.start(pods: @policy_pods.values)
        end
      end

      def stop_policy
        @policy_sync&.stop
      end

      def policy_ready?
        !@policy_sync || @policy_sync.ready?
      end

      def add(sandbox, config = nil, **)
        result = @interface.add(sandbox, config, **)
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
            detail = cleanup_errors.empty? ? "" : "; #{cleanup_errors.join("; ")}"
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
          begin
            @policy_engine.sync_pods(@policy_pods.values)
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

      def check(*, **)
        @interface.check(*, **)
      end

      def recover(*, **)
        @interface.recover(*, **)
      end

      def method_missing(name, ...)
        return super unless @interface.respond_to?(name)

        @interface.public_send(name, ...)
      end

      def respond_to_missing?(name, include_private = false)
        @interface.respond_to?(name, include_private) || super
      end

      private

      def recover_policy_pods(lifecycle, runtime)
        lifecycle.records.values.filter_map do |record|
          sandbox = record[:sandbox_id]
          stored = record[:network]
          next unless sandbox && stored && stored["state"] == "committed" && !Array(stored["ips"] || stored["ip"]).empty?
          next if record.fetch(:cleanup_completed, {}).key?("network:#{sandbox}")

          # A sandbox the runtime no longer knows has no network namespace
          # left to enforce policy on.  Lifecycle recovery sees the same
          # condition as SandboxGone and finishes the Pod's cleanup; failing
          # here instead would keep the whole agent from starting.
          next if sandbox_lost?(runtime, sandbox)

          pod = record.fetch(:pod)
          operation = @interface.operation(stored.fetch("operation_id"))
          result = operation.fetch("result")
          unless operation["state"] == "committed" && result && result["sandbox_id"] == sandbox &&
                 verified_attachment?(runtime, sandbox, pod)
            # kubelet does not refuse to start over one Pod.  The Pod is
            # treated as a changed sandbox: left out of the policy set and
            # rebuilt by the first sync, so its policy is programmed against
            # an attachment this agent made itself.
            unless lifecycle.replace_sandbox(sandbox, message: "network attachment could not be confirmed after restart")
              raise Network::OwnershipError, "cannot confirm recovered policy attachment for sandbox #{sandbox}"
            end

            next
          end

          [sandbox, policy_pod(pod, result)]
        end.to_h
      end

      def sandbox_lost?(runtime, sandbox)
        runtime.network_sandbox_context(sandbox)
        false
      rescue StandardError => error
        raise unless error.message.to_s.include?("unknown sandbox")

        true
      end

      def verified_attachment?(runtime, sandbox, pod)
        # The operation's old namespace FD was local to a former worker.
        # Resolve the recovered holder and verify its live kernel resources.
        context = runtime.network_sandbox_context(sandbox)
        namespace = context.fetch("netns")
        pidfd = Platform::Linux::Pidfd.new.open(pid: namespace.fetch("pid"), resource_id: "policy-attachment:#{sandbox}")
        @interface.check(context.merge("netns" => namespace.merge("pidfd" => pidfd)), pod)
      ensure
        IO.for_fd(pidfd).close if pidfd
      end

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
        result = network_result.respond_to?(:to_h) ? network_result.to_h : {}
        {
          "namespace" => metadata["namespace"] || metadata[:namespace] || "default",
          "name" => metadata["name"] || metadata[:name] || metadata["uid"] || metadata[:uid],
          "uid" => metadata["uid"] || metadata[:uid],
          "labels" => metadata["labels"] || metadata[:labels] || {},
          "ips" => Array(result["ips"] || result[:ips] || result["ip"] || result[:ip]).compact,
          "ports" => NetworkPolicySync.ports(spec),
          "local" => true,
          "interface" => result["interface"] || result[:interface]
        }
      end
    end

    # Builds one process from its configuration: the config, the logger, the
    # shutdown coordinator and the process's service, registered in a
    # dependency container so each is built once and only when asked for.
    #
    # This file is the entry point; what each process is made of lives in
    # the modules included below (lib/rubernetes/bootstrap/assembler/).
    class Assembler
      Assembly = Data.define(:config, :logger, :shutdown, :service)

      DEFAULT_STREAMING_PORT = 10_250
      DEFAULT_DNS_PORT = 53

      include Services        # the service of each process, injected collaborators
      include ClientBuilder   # the Kubernetes client, the node's client certificate
      include AgentWiring     # the agent's dependencies and its Node::Agent
      include NodeOptions     # the agent's configuration sections, defaults applied
      include RuntimeBuilder  # native runtime, microVM and CRI handlers, RuntimeClass
      include VolumeBuilder   # volume manager and CSI plugin
      include NetworkBuilder  # Pod network and NetworkPolicy engine

      def initialize(process_name:, config_path: nil, kubelet_config_path: nil, log_io: $stderr, clock: -> { Time.now.utc }, runtime_adapters: {})
        @process_name = process_name
        @config_path = config_path
        @kubelet_config_path = kubelet_config_path
        @log_io = log_io
        @clock = clock
        @runtime_adapters = runtime_adapters.to_h.dup.freeze
      end

      def build
        container = Container.new
        container.register(:config) { Config.load(process_name: @process_name, path: @config_path, kubelet_config_path: @kubelet_config_path) }
        container.register(:logger) { |dependencies| build_logger(dependencies.resolve(:config)) }
        container.register(:shutdown) { Shutdown.new }
        register_agent(container) if @process_name == "rubernetes-agent"
        container.register(:service) { |dependencies| build_service(dependencies) }
        container.seal!

        Assembly.new(
          config: container.resolve(:config),
          logger: container.resolve(:logger),
          shutdown: container.resolve(:shutdown),
          service: container.resolve(:service)
        )
      end

      private

      def build_logger(config)
        StructuredLogger.new(
          io: @log_io,
          process_name: @process_name,
          level: config.logging_level,
          clock: @clock
        ).tap { |logger| Observability::Metrics.logger = logger }
      end

      # --- The only places that tell the runtimes behind the agent apart.

      # Several runtime handlers behind one runtime, as opposed to the
      # native runtime alone.
      def multiplexer?(runtime)
        runtime.respond_to?(:backends)
      end

      # A CRI backend hands the credentials to the remote runtime; the
      # native and microVM backends pull through the node's own resolver.
      def pulls_with_credentials?(backend)
        backend.respond_to?(:credential_provider=)
      end

      # The handler a RuntimeClass object names, read through the node's
      # cached reader.
      def runtime_class_handler(reader, name)
        return nil if reader.nil?

        handler = reader.get("runtimeclass", name)&.dig("handler").to_s
        handler.empty? ? nil : handler
      rescue StandardError
        # Unreadable now (not found, API unavailable): the node's table.
        nil
      end
    end
  end
end
