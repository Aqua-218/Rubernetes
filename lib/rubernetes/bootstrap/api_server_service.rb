# frozen_string_literal: true

require_relative "../api"
require_relative "../api/peer_proxy"
require_relative "../schema/catalog"
require_relative "../storage/memory_store"
require_relative "../consensus"
require "json"
require "openssl"
require "socket"
require_relative "../runtime/microvm/runtime_classes"

require_relative "../transport"
require_relative "../extension/resource"
require_relative "security_assembly"
require_relative "api_server_bootstrap_objects"
require_relative "api_server_startup_hooks"
require_relative "kubernetes_service_reconciler"
require_relative "peer_directory"
require_relative "cluster_authentication_trust"
require_relative "coordinated_leader_election"
require File.expand_path("../../../generated/ruby/kubernetes_types", __dir__)

module Rubernetes
  module Bootstrap
    # Wires the generated Kubernetes catalog to the in-process API core and
    # the HTTP transport. Construction is side-effect free; the listening
    # socket is opened only by #start.
    class APIServerService
      include APIServerBootstrapObjects
      include APIServerStartupHooks

      # Presents generated Definition validation/defaulting through the small
      # schema contract consumed by API::Server.
      class SchemaContract
        def initialize(definition)
          @definition = definition
        end

        # Exposed so the API server can ask which fields the request carried
        # that the schema does not declare (`?fieldValidation=`).
        def validator
          @definition.validator
        end

        def defaulting = @definition.defaulting

        # +old+: the stored object an update replaces (Defaulting#apply).
        def default(object, unknown_fields: :preserve, old: nil)
          # This contract is used at the API admission boundary. Include the
          # procedural defaults installed by Kubernetes strategies (PodSpec,
          # Container, workload specs), not only declarative OpenAPI defaults.
          # `unknown_fields:` carries the request's field-validation directive:
          # Kubernetes drops undeclared fields in every directive.
          @definition.defaulting.apply(
            object,
            unknown_fields: unknown_fields,
            kubernetes_admission_defaults: old ? :update : :create,
            old: old
          )
        end

        # Causes are rendered the way apimachinery's field.Error reaches the
        # wire (Schema::ValidationIssue#to_cause).
        def validate(object, operation: :create, **_options)
          @definition.validator.errors(object, unknown_fields: :preserve, operation: operation).map do |issue|
            issue.to_cause(object)
          end
        end
      end

      def initialize(config:, logger:, catalog: nil, store: nil, http_server_class: Transport::HTTPServer,
                     subresource_bridge: nil, node_resolver: nil, authorizer: nil,
                     identity_resolver: nil, trusted_subresources: false)
        @config = config
        @logger = logger
        @node_resolver = node_resolver
        @authorizer = authorizer
        @identity_resolver = identity_resolver
        @catalog = catalog || Schema::Catalog.default
        @registry = build_registry(@catalog)
        @raft_server = nil
        @store = store || build_store(@config)
        @store = encrypt_store(@store, @config)
        if (egress_path = @config["egress_selector_config_file"])
          Security::Egress.selector = Security::Egress::Selector.load(egress_path)
        end
        @security = build_security(@config)
        # kube-apiserver --proxy-client-cert-file / --proxy-client-key-file:
        # the client certificate the aggregator (and webhook calls) present,
        # which extension API servers trust through requestheader-client-ca.
        @proxy_certificate, @proxy_key = load_proxy_client(@config["proxy_client"])
        identity = @raft_server ? @raft_server.id : "#{advertise_address}:#{@config.fetch("port")}"
        @peer_directory = build_peer_directory(identity)
        @peer_proxy = build_peer_proxy
        @openapi = API::OpenAPIRepository.new
        @crd_manager = API::CRD::Manager.new(registry: @registry, store: @store, openapi: @openapi,
                                             cel: Security::CEL::Evaluator.new, logger: @logger,
                                             webhook_client: conversion_webhook_client)
        # kube-aggregator dials a ready endpoint of the APIService's Service
        # (ServiceResolver), never the cluster DNS name: the API server's own
        # resolver has no route to `<svc>.<ns>.svc`, which is why the wardle
        # sample API server was never Available.
        @aggregator = API::Aggregator.new(client_certificate: @proxy_certificate || @security&.tls_options&.dig(:front_proxy_certificate),
                                          client_key: @proxy_key || @security&.tls_options&.dig(:front_proxy_key),
                                          service_resolver: service_endpoint_resolver)
        @api_server = API::Server.new(
          logger: @logger,
          namespace_lifecycle: true,
          ready: -> { datastore_ready? },
          defer_system_namespaces: !@raft_server.nil?,
          registry: @registry,
          store: @store,
          subresource_bridge: subresource_bridge,
          # Without a resolver the API server cannot reach any node, so every
          # streaming subresource answers "Pod node routing is not configured".
          # Default to resolving the endpoint the agent advertises on its Node.
          node_resolver: node_resolver || default_node_resolver,
          authorizer: authorizer,
          identity_resolver: identity_resolver,
          trusted_subresources: trusted_subresources,
          security: @security&.pipeline,
          feature_gates: @security ? @security.feature_gates : {},
          service_account_issuer: @security&.service_account_issuer,
          api_audiences: (@security&.service_account_issuer&.api_audiences unless @security&.service_account_issuer&.api_audiences.to_a.empty?),
          openapi_repository: @openapi,
          crd_manager: @crd_manager,
          aggregator: @aggregator,
          runtime_config: @config.fetch("runtime_config", {}),
          peer_proxy: @peer_proxy,
          service_cidrs: service_cidrs,
          node_port_range: node_port_range
        )
        @startup_health = API::StartupHealth.new
        @api_server.startup_health = @startup_health
        # /flagz: this process's command line and its (flattened) configuration.
        @api_server.component_flags = Observability::ZPages.flags_from(arguments: ARGV.dup, config: @config.to_h)
        @kubernetes_service = KubernetesServiceReconciler.new(
          api_server: @api_server, logger: @logger, advertise_address: advertise_address,
          secure_port: @config.fetch("port"), service_cidrs: service_cidrs, identity: identity,
          peer_directory: @peer_directory, on_storage_versions_ready: -> { install_serving_bootstrap_objects }
        )
        API::CRD.metrics = @api_server.metrics if @api_server.respond_to?(:metrics)
        # JWT authenticator metrics carry this server's ID (hashed); they
        # exist only when a JWT authenticator is configured, as upstream.
        if @config.dig("security", "authentication", "jwt")
          Security::Authentication::JWTAuthenticator.api_server_id = KubernetesServiceReconciler.apiserver_id(identity)
          Security::Authentication::JWTAuthenticator.metrics = @api_server.metrics if @api_server.respond_to?(:metrics)
        end
        # apiserver_externaljwt_*: only with --service-account-signing-endpoint.
        if @config.dig("security", "authentication", "service_account", "signing_endpoint") && @api_server.respond_to?(:metrics)
          Security::Authentication::ExternalJWTSigner.metrics = @api_server.metrics
        end
        @authentication_trust = if @security&.authentication_info
                                  ClusterAuthenticationTrust.new(api_server: @api_server, authentication_info: @security.authentication_info,
                                                                 logger: @logger,
                                                                 uid_headers: @security.feature_gates.fetch("RemoteRequestHeaderUID", true) != false)
                                end
        http_options = serving_http_options
        @http_server = http_server_class.new(@api_server, **http_options)
        install_tls_handshake_metric
        @started = false
      end

      private def serving_http_options
        http_options = {
          host: @config.fetch("bind_address"),
          port: @config.fetch("port"),
          max_body_bytes: @config.fetch("max_body_bytes"),
          logger: @logger
        }
        if @config["tls"]
          http_options[:cert_file] = @config["tls"]["cert_file"]
          http_options[:key_file] = @config["tls"]["key_file"]
          http_options.merge!(@security.tls_options) if @security
        end
        http_options
      end

      def install_tls_handshake_metric
        metrics = @api_server.respond_to?(:metrics) ? @api_server.metrics : @api_server.instance_variable_get(:@metrics)
        return unless metrics && @http_server.respond_to?(:on_tls_handshake_error=)

        metrics.register("apiserver_tls_handshake_errors_total", type: :counter,
                                                                 help: "Number of requests dropped with 'TLS handshake error from' error")
        @http_server.on_tls_handshake_error = -> { metrics.increment("apiserver_tls_handshake_errors_total") }
      end

      def start
        raise "rubernetes-apiserver is already started" if @started

        if @raft_server
          @raft_server.start
          @logger.info("datastore.raft.started", node_id: @raft_server.id, cluster_id: @raft_server.cluster_id,
                                                 address: @raft_server.address, voters: @raft_server.membership.voters.to_a.sort)
          @system_namespace_thread = Thread.new { ensure_system_namespaces_when_available }
          @system_namespace_thread.name = "apiserver-system-namespaces"
        else
          @startup_health.complete("start-system-namespaces-controller")
        end
        install_serving_bootstrap_objects unless @api_server.storage_version_reporting?
        @security&.flow_control_configuration&.start
        bootstrap_dynamic_apis
        start_dynamic_api_reconciler
        bootstrap_service_cidr
        start_allocation_repair
        if @encryption_reload
          Security::Encryption.metrics = @api_server.metrics if @api_server.respond_to?(:metrics)
          Security::Encryption.apiserver_id = @config["identity"] || Socket.gethostname
          @encryption_reload.start
        end
        Security::Egress.metrics = @api_server.metrics if Security::Egress.selector && @api_server.respond_to?(:metrics)
        if @security&.node_graph_populator
          Security::Authorization::NodeGraph.metrics = @api_server.metrics if @api_server.respond_to?(:metrics)
          @security.node_graph_populator.start
        end
        Array(@security&.reload_controllers).each do |controller|
          controller.metrics = @api_server.metrics if @api_server.respond_to?(:metrics)
          controller.note_loaded
          controller.start
        end
        @startup_health.complete("start-apiserver-admission-initializer")
        @startup_health.monitor_log { @logger.flush } if @logger.is_a?(StructuredLogger)
        @http_server.start
        @peer_directory&.assign_default_port(@http_server.port)
        @kubernetes_service.start
        @startup_health.complete("bootstrap-controller")
        @peer_proxy&.start
        @authentication_trust&.start
        @startup_health.complete("start-cluster-authentication-info-controller")
        start_registration_hooks
        start_coordinated_leader_election
        @started = true
        @logger.info(
          "process.ready",
          endpoint: @http_server.endpoint,
          gvk_count: @catalog.gvk_count,
          gvr_count: @catalog.gvr_count,
          datastore: @raft_server ? "raft" : "memory"
        )
        self
      end

      def stop(reason:)
        return self unless @started

        @http_server.stop
        @stopping = true
        @kubernetes_service&.stop
        @peer_proxy&.stop
        @authentication_trust&.stop
        @coordinated_leader_election&.stop
        @system_namespace_thread&.join(1)
        @dynamic_api_thread&.join(2)
        @registration_thread&.join(1)
        @startup_health.stop_log_monitor
        @api_server.stop_apiservice_availability_loop
        @security&.flow_control_configuration&.stop
        @repair_thread&.kill
        @encryption_reload&.stop
        Array(@security&.reload_controllers).each(&:stop)
        @security&.external_jwt_signer&.stop
        @security&.node_graph_populator&.stop
        @store.close if @store.respond_to?(:close)
        @raft_server&.stop
        @logger.info("process.stopped", reason: reason)
        @started = false
        self
      end

      private def install_serving_bootstrap_objects
        install_bootstrap_objects if @security
        install_bootstrap_object(Extension::CRD) if extensions_enabled?
      end

      private def start_coordinated_leader_election
        return unless @security&.feature_gates&.fetch(CoordinatedLeaderElection::GATE, false)

        @coordinated_leader_election = CoordinatedLeaderElection.new(
          api_server: @api_server, logger: @logger, identity: @config["identity"] || Socket.gethostname
        )
        @coordinated_leader_election.start
      end

      def build_peer_directory(identity)
        gates = @security ? @security.feature_gates : {}
        return unless @config["tls"] && gates.fetch("UnknownVersionInteroperabilityProxy", true) && gates.fetch("APIServerIdentity", true)

        host = @config["peer_advertise_ip"]
        port = @config["peer_advertise_port"]
        unless host && port
          host = advertise_address
          port = @config.fetch("port")
        end
        PeerDirectory.new(store: @store, registry: @registry, identity: KubernetesServiceReconciler.apiserver_id(identity),
                          host: host, port: port)
      rescue IPAddr::InvalidAddressError
        raise Config::Error, "peer proxy requires an IP address for peer advertisement" if @config["peer_ca_file"]
      end

      def build_peer_proxy
        ca = @config["peer_ca_file"]
        return unless ca && @peer_directory

        unless @proxy_certificate && @proxy_key && @security&.authentication_info&.dig(:request_header)
          raise Config::Error, "peer proxy requires a proxy client certificate and request_header authentication"
        end

        transport = API::PeerTransport.new(ca_file: ca, certificate: @proxy_certificate, key: @proxy_key)
        API::PeerProxy.new(transport: transport, directory: @peer_directory, logger: @logger)
      end
      private :build_peer_directory, :build_peer_proxy

      # Whether the datastore can serve requests: a Raft-backed server is
      # ready only once its node is a member with a known leader.
      # Resolves a node name to the streaming endpoint that node advertised in
      # its own status; a node that has published none is simply unavailable.
      def default_node_resolver
        # A kubelet client certificate that cannot be read is a configuration
        # error, not a node resolver to do without.
        build_node_resolver(kubelet_client_tls)
      end

      def kubelet_client_tls
        kubelet_client = (@config["kubelet_client"] || {}).to_h
        return nil if kubelet_client.empty?

        API::NodeEndpointResolver::KubeletClientTLS.load(cert_file: kubelet_client.fetch("cert_file"),
                                                         key_file: kubelet_client.fetch("key_file"),
                                                         ca_file: kubelet_client["ca_file"])
      end

      def build_node_resolver(tls)
        descriptor = @registry.resources.find do |candidate|
          candidate.kind.to_s == "Node" && candidate.group.to_s.empty?
        end
        return nil unless descriptor

        # The raw datastore takes a positional key; the API storage adapter is
        # what understands resource/namespace/name.
        adapter = @store.is_a?(API::StoreAdapter) ? @store : API::StoreAdapter.new(@store)
        API::NodeEndpointResolver.new(store: adapter, resource: descriptor, tls: tls)
      rescue StandardError
        nil
      end

      def datastore_ready?
        return true unless @raft_server

        !@raft_server.failed? && @raft_server.quorum_available?
      end

      attr_reader :api_server, :catalog, :http_server, :registry, :store, :node_resolver, :authorizer, :identity_resolver, :raft_server,
                  :security

      private

      # Key layout shared with API::StoreAdapter: registry/<gvr>/<namespace|_cluster>/<name>.
      def store_key_for
        lambda do |group, version, resource, namespace, name|
          gvr = API::GVR.new(group: group.to_s, version: version.to_s, resource: resource.to_s)
          prefix = "registry/#{gvr}"
          # A nil namespace with a name addresses a cluster-scoped object;
          # a nil namespace without a name is the cross-namespace prefix.
          scope = if namespace == :cluster || (namespace.nil? && !name.nil?) || (!namespace.nil? && namespace.to_s.empty?)
                    "_cluster"
                  else
                    namespace&.to_s
                  end
          prefix = "#{prefix}/#{scope}" if scope
          name.nil? ? "#{prefix.delete_suffix("/")}/" : "#{prefix}/#{name}"
        end
      end

      # Webhooks (admission, CRD conversion) dial a Service's ready endpoint
      # directly; the API server host has no cluster DNS for *.svc names.
      def service_endpoint_resolver
        lambda do |namespace, name, port|
          @api_server.respond_to?(:service_endpoint_address) ? @api_server.service_endpoint_address(namespace, name, port) : nil
        end
      end

      def conversion_webhook_client
        Security::Admission::Plugins::WebhookClient.new(client_certificate: @proxy_certificate || @security&.tls_options&.dig(:front_proxy_certificate),
                                                        client_key: @proxy_key || @security&.tls_options&.dig(:front_proxy_key),
                                                        service_resolver: service_endpoint_resolver)
      rescue NameError
        nil
      end

      def load_proxy_client(section)
        return [nil, nil] unless section.is_a?(Hash)

        [OpenSSL::X509::Certificate.new(File.read(section.fetch("cert_file"))), OpenSSL::PKey.read(File.read(section.fetch("key_file")))]
      end

      def build_security(config)
        return nil unless config["security"]

        SecurityAssembly.new(config: config["security"], store: @store, key_for: store_key_for, logger: @logger,
                             extensions: extensions_enabled?,
                             namespace_creator: method(:create_namespace_from_admission),
                             apiserver_id: config["identity"] || Socket.gethostname,
                             service_resolver: service_endpoint_resolver,
                             resource_resolver: lambda { |group, kind|
                               resource = @registry.resources.find { |candidate| candidate.group == group && candidate.kind == kind }
                               resource&.resource
                             },
                             scope_resolver: lambda { |group, plural|
                               resource = @registry.resources.find { |candidate| candidate.group == group && candidate.resource == plural }
                               resource && resource.scope == :cluster
                             },
                             # The API server's structured-merge-diff types
                             # (a MutatingAdmissionPolicy's ApplyConfiguration).
                             type_resolver: lambda { |group, version, kind|
                               @api_server&.field_managers&.then { |managers| managers.type_converter(group, version)&.type_for(group, version, kind) }
                             },
                             # The scheme defaulter a MutatingAdmissionPolicy
                             # runs over each patched object.
                             defaulter: lambda { |group, version, kind, object|
                               resource = @registry.resources.find do |candidate|
                                 candidate.group == group && candidate.kind == kind && (!candidate.respond_to?(:version) || candidate.version == version)
                               end
                               next object unless resource && @api_server

                               # A mutable copy: schema application hands back frozen members.
                               Marshal.load(Marshal.dump(@api_server.send(:apply_defaults_only, resource, object)))
                             })
      end

      def create_namespace_from_admission(name)
        namespace = {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => name}}
        response = @api_server.call(method: "POST", path: "/api/v1/namespaces", body: namespace,
                                    headers: {"Content-Type" => "application/json"},
                                    identity: {"username" => "system:apiserver", "groups" => ["system:masters"]})
        return if response.status == 201
        return if response.status == 409 && response.body["reason"] == "AlreadyExists"

        raise API::Status::Error.new(message: response.body.fetch("message"), code: response.status,
                                     reason: response.body.fetch("reason"), details: response.body["details"])
      end

      # Re-establish CustomResourceDefinitions and APIServices already in the
      # store (restart or a replica joining) before serving.
      # --service-cluster-ip-range as ServiceCIDR objects; deferred like the
      # system namespaces while the datastore has no quorum.
      def bootstrap_service_cidr
        @api_server.service_allocator.bootstrap!
      rescue Consensus::Error, Storage::Error => error
        @logger.warn("service_cidr.bootstrap_deferred", error: "#{error.class}: #{error.message}")
        Thread.new do
          until @stopping
            begin
              @api_server.service_allocator.bootstrap!
              break
            rescue Consensus::Error, Storage::Error
              sleep(0.5)
            end
          end
        end
      end

      def service_cidrs
        value = @config.fetch("service_cluster_ip_range", API::ServiceAllocator::DEFAULT_SERVICE_CIDRS)
        value.is_a?(String) ? [value] : Array(value)
      end

      def node_port_range
        value = @config["node_port_range"]
        return API::ServiceAllocator::DEFAULT_NODE_PORT_RANGE if value.nil?

        low, high = value.split("-").map(&:to_i)
        low..high
      end

      # The address other components and Pods use to reach this API server:
      # the configured advertise address, else the bind address unless that
      # is a wildcard, else the host's first non-loopback address.
      def advertise_address
        configured = @config["advertise_address"].to_s
        return configured unless configured.empty?

        bind = @config.fetch("bind_address").to_s
        return bind unless %w[0.0.0.0 :: [::]].include?(bind) || bind.empty?

        entry = Socket.ip_address_list.find { |candidate| candidate.ipv4? && !candidate.ipv4_loopback? && !candidate.ipv4_multicast? }
        entry ? entry.ip_address : "127.0.0.1"
      end

      def bootstrap_dynamic_apis
        crd_resource = @registry.find_gvr(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions")
        apiservice_resource = @registry.find_gvr(group: "apiregistration.k8s.io", version: "v1", resource: "apiservices")
        adapter = API::StoreAdapter.new(@store)
        crds = crd_resource ? adapter.list(resource: crd_resource, namespace: :all, selectors: nil).items : []
        @crd_manager.bootstrap!(crds)
        apiservices = apiservice_resource ? adapter.list(resource: apiservice_resource, namespace: :all, selectors: nil).items : []
        apiservices.each do |apiservice|
          @aggregator.sync(apiservice)
          @api_server.schedule_apiservice_availability(apiservice.dig("metadata", "name"))
        end
        @logger.info("dynamic_apis.bootstrapped", crds: crds.length, apiservices: apiservices.length)
      rescue Consensus::Error, Storage::Error => error
        # The datastore may not have quorum yet; the CRD hooks re-sync on the
        # next write and the background namespace thread retries readiness.
        @logger.warn("dynamic_apis.bootstrap_deferred", error: "#{error.class}: #{error.message}")
      end

      # Every kube-apiserver runs its own CRD and APIService informers, so a
      # definition written through one replica is served by all of them.
      # Here only the replica that handled the write registered it (the
      # after_commit hook): in-cluster clients reach a random replica through
      # the kubernetes Service and got 404 for a resource another replica had
      # just established.  The reconciler lists, then watches from that
      # revision, and relists periodically or after any watch failure.
      DYNAMIC_API_RELIST_SECONDS = 30

      def start_dynamic_api_reconciler
        @dynamic_api_thread = Thread.new do
          until @stopping
            begin
              reconcile_dynamic_apis
            rescue StandardError => error
              @logger.warn("dynamic_apis.reconcile_failed", error: "#{error.class}: #{error.message}")
              sleep(1) unless @stopping
            end
          end
        end
        @dynamic_api_thread.name = "apiserver-dynamic-apis"
      end

      def reconcile_dynamic_apis
        adapter = API::StoreAdapter.new(@store)
        kinds = {
          crd: @registry.find_gvr(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions"),
          apiservice: @registry.find_gvr(group: "apiregistration.k8s.io", version: "v1", resource: "apiservices")
        }.compact
        streams = kinds.to_h do |kind, resource|
          listed = adapter.list(resource: resource, namespace: :all, selectors: nil)
          apply_dynamic_snapshot(kind, listed.items)
          [kind, adapter.watch(resource: resource, namespace: :all, selectors: nil, resource_version: listed.resource_version.to_s)]
        end
        @api_server.start_apiservice_availability_loop if streams.key?(:apiservice)
        dynamic_api_hooks_ready
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + DYNAMIC_API_RELIST_SECONDS
        until @stopping || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          idle = true
          streams.each do |kind, stream|
            while (event = stream.next(timeout: 0.05))
              idle = false
              apply_dynamic_event(kind, event)
            end
          end
          sleep(0.05) if idle
        end
      ensure
        streams&.each_value { |stream| stream.close if stream.respond_to?(:close) }
      end

      def apply_dynamic_snapshot(kind, items)
        names = items.map { |item| item.dig("metadata", "name") }
        if kind == :crd
          items.each do |item|
            @crd_manager.sync(item)
            if item.dig("metadata", "deletionTimestamp") && Array(item.dig("metadata", "finalizers")).include?(API::CRD::Manager::CLEANUP_FINALIZER)
              @api_server.schedule_crd_finalizer(item.dig("metadata", "name"))
            end
          end
          (@crd_manager.served_names - names).each { |name| @crd_manager.withdraw(name) }
        else
          items.each do |item|
            @aggregator.sync(item)
            @api_server.schedule_apiservice_availability(item.dig("metadata", "name"))
          end
          (@aggregator.backend_names - names).each { |name| @aggregator.remove(name) }
        end
      end

      def apply_dynamic_event(kind, event)
        type = event.type.to_s
        object = event.object
        return unless object.is_a?(Hash) && %w[ADDED MODIFIED DELETED].include?(type)

        name = object.dig("metadata", "name")
        if kind == :crd
          type == "DELETED" ? @crd_manager.withdraw(name) : @crd_manager.sync(object)
        elsif type == "DELETED"
          @aggregator.remove(name)
        else
          @aggregator.sync(object)
          @api_server.schedule_apiservice_availability(name)
        end
      end

      # Makes the datastore's voters `voters`, reaching the new ones at
      # `peers` (id => host:port).  Raft does it in two steps (joint
      # consensus), so the cluster keeps a quorum throughout; this returns
      # when the new configuration is committed.  Only the leader can.
      def reconfigure_datastore(voters:, peers: {}, removed: [])
        raise Config::Error, "this API server has no raft datastore" unless @raft_server

        peers.each { |id, address| @raft_server.add_peer(id, address) }
        membership = @raft_server.propose_membership(voters, timeout: 60)
        removed.each { |id| @raft_server.remove_peer(id) }
        membership
      end
      public :reconfigure_datastore

      # Writes everything the in-memory datastore holds to `path`, for
      # Consensus::Seed to start a raft datastore from (`rubectl cluster
      # seed`). For a cutover, pause writes at the snapshot boundary until the
      # source is stopped or the migration is abandoned.
      def export_datastore(path, pause_writes: false)
        raise Config::Error, "this API server runs the raft datastore; there is nothing to migrate" if @raft_server
        raise Config::Error, "this API server's datastore cannot be exported" unless @store.is_a?(Storage::MemoryStore)

        state = @store.export_state(write_pause: (path if pause_writes))
        begin
          File.write(path, JSON.generate(state), perm: 0o600)
        rescue StandardError
          resume_datastore_writes(path) if pause_writes
          raise
        end
        {"keys" => state.fetch("known_keys").length, "revision" => state.fetch("revision")}
      end
      public :export_datastore

      def resume_datastore_writes(path)
        @store.resume_writes!(write_pause: path) if @store.is_a?(Storage::MemoryStore)
      end
      public :resume_datastore_writes

      def extensions_enabled?
        @config.dig("extensions", "enabled") == true
      end

      # The system namespaces need a quorum; keep trying in the background
      # until the cluster has a leader instead of failing process start when
      # this node comes up before its peers.
      def ensure_system_namespaces_when_available
        until @stopping
          begin
            @api_server.ensure_system_namespaces!
            @startup_health.complete("start-system-namespaces-controller")
            @logger.info("datastore.system_namespaces.ready")
            return
          rescue Consensus::Error, Storage::Error, API::Status::Error => error
            @logger.debug("datastore.system_namespaces.retry", error: "#{error.class}: #{error.message}")
            sleep(0.5)
          end
        end
      end

      # The ClusterIP / NodePort repair controllers (RunUntil every 3
      # minutes upstream): each API server sweeps allocations against the
      # Services and IPAddresses and repairs leaks.
      def start_allocation_repair
        allocator = @api_server.service_allocator
        interval = Float(ENV.fetch("RUBERNETES_ALLOCATION_REPAIR_INTERVAL", API::ServiceAllocator::REPAIR_INTERVAL_SECONDS))
        @repair_thread = Thread.new do
          Thread.current.name = "apiserver-allocation-repair"
          delay = 0.25
          until @stopping
            delay = interval if @api_server.ready? && repair_allocations(allocator)
            sleep(delay)
          end
        end
      end

      def repair_allocations(allocator)
        report = allocator.repair!(raise_on_error: true)
        @startup_health.complete("start-service-ip-repair-controllers")
        findings = report["ip_errors"].values.sum + report["port_errors"].values.sum
        @logger.info("allocation.repair", **report) if findings.positive?
        true
      rescue StandardError => error
        @logger.warn("allocation.repair.failed", error: error.class.name, message: error.message)
        false
      end

      # --encryption-provider-config: the EncryptionConfiguration wraps the
      # store so the listed resources are sealed at rest, and its reload
      # controller re-reads the file as it changes.
      def encrypt_store(store, config)
        path = config["encryption_config_file"]
        return store unless path

        require_relative "../security/encryption"
        configuration = Security::Encryption::Configuration.load(path)
        wrapped = configuration.wrap(store, corrupt_deletion: config.dig("security", "feature_gates", "AllowUnsafeMalformedObjectDeletion") == true)
        interval = Float(config.fetch("encryption_config_reload_interval_seconds", Security::Encryption::ReloadController::POLL_INTERVAL))
        @encryption_reload = Security::Encryption::ReloadController.new(path: path, wrapped: wrapped, interval: interval,
                                                                        logger: lambda { |level, event, **fields|
                                                                          @logger.public_send(level, event, **fields)
                                                                        })
        @encryption_reload.note_loaded(configuration)
        @logger.info("encryption.config.loaded", hash: configuration.hash, groups: configuration.groups.map(&:names))
        wrapped
      end

      def build_store(config)
        datastore = config["datastore"] || {}
        policy = datastore.fetch("history_retention_policy", Storage::MemoryStore::DEFAULT_HISTORY_POLICY)
        history = {history_revisions: config.fetch("watch_history_limit"), history_retention_policy: policy}
        compaction_seconds = datastore["compaction_interval_seconds"]
        if compaction_seconds || (policy == Storage::MemoryStore::LONGER_HISTORY_POLICY && datastore.key?("compaction_interval_seconds"))
          history[:history_seconds] = compaction_seconds
        end
        return Storage::MemoryStore.new(**history) if (datastore["type"] || "memory") == "memory"

        timing = Consensus::Node::Timing.production
        timing = timing.with(**datastore.fetch("timing").transform_keys(&:to_sym)) if datastore["timing"]
        bundle = Consensus::Identity.read_bundle(datastore.fetch("pki_dir"))
        @raft_server = Consensus::Server.new(
          id: datastore.fetch("node_id"),
          cluster_id: datastore.fetch("cluster_id"),
          data_directory: datastore.fetch("data_dir"),
          bundle: bundle,
          initial_voters: datastore.fetch("voters"),
          peers: datastore.fetch("peers", {}),
          host: datastore.fetch("listen_address"),
          port: datastore.fetch("listen_port"),
          timing: timing,
          logger: @logger,
          **history
        )
        gates = config.dig("security", "feature_gates") || {}
        Consensus::RaftStore.new(@raft_server, cbor_storage: gates["CBORServingAndStorage"] == true,
                                               corrupt_deletion: gates["AllowUnsafeMalformedObjectDeletion"] == true)
      end

      def build_registry(source)
        conversion_options = multi_version_options(source.resources)
        resources = source.resources.map do |entry|
          # events.k8s.io/v1 Events and core/v1 Events are two wire shapes over
          # one stored object upstream (pkg/apis/events/v1/conversion.go), and
          # conformance crosses between them.
          alias_options = API::EventConversion.alias_options_for(entry.group, entry.version, entry.resource)
          alias_options = conversion_options.fetch([entry.group.to_s, entry.resource.to_s], {}) if alias_options.empty?
          API::Resource.new(
            group: entry.group,
            version: entry.version,
            resource: entry.resource,
            kind: entry.kind,
            scope: entry.scope,
            short_names: entry.short_names,
            categories: entry.categories,
            verbs: entry.verbs,
            list_kind: entry.list_kind,
            singular_name: entry.singular,
            merge_keys: entry.merge_keys,
            patch_strategy: entry.patch_strategy || :merge,
            subresources: entry.subresources,
            schema: schema_contract(entry),
            **alias_options
          )
        end
        API::Registry.new(resources: resources, defaults: false)
      end

      # A built-in resource served in more than one version is stored once
      # and converted (API::BuiltinConversion).
      def multi_version_options(entries)
        served = API::Server::DEFAULT_SERVED_GROUP_VERSIONS
        entries.group_by do |entry|
          [entry.group.to_s, entry.resource.to_s]
        end.each_with_object({}) do |((group, resource), versions), options|
          names = versions.map { |entry| entry.version.to_s }.uniq
          next if names.length < 2

          default_served = if served
                             ->(version) { served.include?(group.empty? ? version : "#{group}/#{version}") }
                           end
          storage = API::BuiltinConversion.storage_version(group, resource, names, default_served: default_served)
          options[[group, resource]] = {
            storage_version: storage, storage_key_version: storage, storage_key_versions: names,
            converter: API::BuiltinConversion::Converter.new(group: group, resource: resource)
          }
        end
      end

      def schema_contract(entry)
        generated = Rubernetes::Generated.const_get(entry.type.ruby_constant, false)
        definition = generated.const_get(:DEFINITION, false)
        SchemaContract.new(definition)
      rescue NameError
        raise Schema::Catalog::MissingSchemaError,
              "generated Definition is missing for #{entry.type.schema_name.inspect}"
      end
    end
  end
end
