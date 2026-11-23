# frozen_string_literal: true

require "cgi"
require_relative "../security/egress"
require "digest"
require "json"
require "strscan"
# openssl first: net/http only defines its TLS accessors (use_ssl=) when
# OpenSSL::SSL is already defined at load time.
require "openssl"
require "socket"
require "net/http"
require "net/https"
require "securerandom"
require "time"
require "yaml"

require_relative "../security"
require_relative "../observability/metrics"
require_relative "../observability/slis"
require_relative "service_allocator"
require_relative "long_running_body"
require_relative "lifecycle"
require_relative "../observability/zpages"
require_relative "field_manager_registry"

# The server's responsibilities, one module per file.
# A request, from transport input to response:
require_relative "server/request_pipeline"
require_relative "server/dispatch"
require_relative "server/request_identity"
require_relative "server/request_decoding"
require_relative "server/response_encoding"
require_relative "server/request_metrics"
# What every write goes through:
require_relative "server/admission_glue"
require_relative "server/write_options"
require_relative "server/schema_application"
require_relative "server/csi_driver_strategy"
require_relative "server/object_helpers"
# The verbs on a stored resource:
require_relative "server/read_handlers"
require_relative "server/create_handler"
require_relative "server/update_identity"
require_relative "server/update_handler"
require_relative "server/subresource_updates"
require_relative "server/patch_handler"
require_relative "server/delete_handler"
require_relative "server/garbage_collection"
# Subresources and resources served by a handler rather than storage:
require_relative "server/scale_subresource"
require_relative "server/review_endpoints"
require_relative "server/token_request"
require_relative "server/pod_binding_eviction"
require_relative "server/proxy_subresource"
# The server describing itself, and the APIs added at run time:
require_relative "server/discovery"
require_relative "server/storage_versions"
require_relative "server/openapi_documents"
require_relative "server/diagnostics"
require_relative "server/dynamic_apis"

module Rubernetes
  module API
    # HTTP-independent Kubernetes API handler. A transport adapter only needs
    # to convert its input into Request and its output from Response.
    #
    # This file is the entry point: the constants several responsibilities
    # share, the constructor, the public interface, and the few places where
    # the server has to ask an injected collaborator what it can do.  The
    # handlers themselves are the modules required above.
    class Server
      include RequestPipeline
      include Dispatch
      include RequestIdentity
      include RequestDecoding
      include ResponseEncoding
      include RequestMetrics
      include AdmissionGlue
      include WriteOptions
      include SchemaApplication
      include ObjectHelpers
      include ReadHandlers
      include CSIDriverStrategy
      include CreateHandler
      include UpdateIdentity
      include UpdateHandler
      include SubresourceUpdates
      include PatchHandler
      include DeleteHandler
      include GarbageCollection
      include ScaleSubresource
      include ReviewEndpoints
      include TokenRequest
      include PodBindingAndEviction
      include ProxySubresource
      include Discovery
      include StorageVersions
      include OpenAPIDocuments
      include Diagnostics
      include DynamicAPIs

      DEFAULT_VERSION = {
        "major" => "1",
        "minor" => "36",
        "gitVersion" => "v1.36.2",
        "gitCommit" => "",
        "gitTreeState" => "clean",
        "buildDate" => "",
        "goVersion" => "",
        "compiler" => "ruby",
        "platform" => Rubernetes.go_platform
      }.freeze

      DEFAULT_GENERATE_NAME_SUFFIX_LENGTH = 5

      # The generated schema registry intentionally contains every upstream
      # type, including API versions which are compiled but not served by the
      # default v1.36.2 apiserver profile. Keep the registry complete while
      # making the live REST/discovery surface follow the upstream defaults
      # (Discovery holds the rules that apply these gates).
      DEFAULT_FEATURE_GATES = {
        "AllowUnsafeMalformedObjectDeletion" => false,
        "CBORServingAndStorage" => false,
        "APIServerIdentity" => true,
        "UnknownVersionInteroperabilityProxy" => true,
        "MutatingAdmissionPolicy" => true,
        "ClusterTrustBundle" => false,
        "PodCertificateRequest" => false,
        "HostnameOverride" => true,
        "ContainerStopSignals" => false,
        "CoordinatedLeaderElection" => false,
        "MultiCIDRServiceAllocator" => true,
        "DynamicResourceAllocation" => true,
        "GenericWorkload" => false,
        "VolumeAttributesClass" => true,
        "StorageVersionMigrator" => false,
        "StorageVersionAPI" => false,
        "StorageVersionHash" => true
      }.freeze

      DEFAULT_API_AUDIENCES = %w[https://kubernetes.default.svc].freeze

      SYSTEM_NAMESPACES = %w[default kube-system kube-public kube-node-lease].freeze

      # RUBERNETES_TRACE_REQUESTS=<regexp on the path> logs, for every matching
      # request, how its time divided between security, admission (per
      # plugin), each store call, raft barriers and proposals.  A Pod create
      # that costs 250 ms while a ConfigMap create costs nothing is otherwise
      # a guess between admission reads, schema work and consensus.
      TRACE_REQUESTS = (pattern = ENV["RUBERNETES_TRACE_REQUESTS"].to_s).empty? ? nil : Regexp.new(pattern)
      REQUEST_PHASES_KEY = :rubernetes_request_phases
      # The admission webhooks' time within the request (WebhookClient adds to it).
      WEBHOOK_SECONDS_KEY = :rubernetes_webhook_seconds
      # The audit event of the request this thread serves, for the
      # annotations admission adds to it (audit.AddAuditAnnotations).
      AUDIT_KEY = :rubernetes_request_audit
      # Fiber-locals the handler reads or writes; carried over to the
      # request thread and back.
      REQUEST_THREAD_LOCALS = [REQUEST_PHASES_KEY, WEBHOOK_SECONDS_KEY, :rubernetes_request_phases].freeze
      # kube-apiserver's LongRunningFunc: watch, and these subresources.
      LONG_RUNNING_SUBRESOURCES = %w[attach exec proxy log portforward].freeze

      # A write is answered once the watchers it woke have sent its event (or
      # after WATCH_DELIVERY_TIMEOUT): kube-apiserver's clients usually see
      # the event in their informer before the response, and the e2e CRUD
      # helper relies on it -- it reads its informer cache right after each
      # write and, on a miss, waits two seconds to look again ("[DRA] CRUD
      # Tests ResourceClaim" 12.7 s, upstream 0.2).  Slow watchers are not
      # waited for (Watcher#await_delivered).
      WATCH_DELIVERY_TIMEOUT = 0.02

      # The finalizer of a foreground deletion: DeleteHandler keeps it across
      # a retried mark, GarbageCollection decides who gets it.
      FOREGROUND_FINALIZER = "foregroundDeletion"

      attr_accessor :trace_requests
      attr_reader :service_allocator, :registry, :store, :router, :feature_gates, :subresource_bridge, :metrics, :field_managers
      # /flagz: the process's command-line flags and flattened configuration
      # (the service that runs this server sets them).
      attr_writer :component_flags

      def initialize(registry: Registry.new, store: MemoryStore.new, version_info: {}, clock: -> { Time.now.utc },
                     ready: true, feature_gates: {}, openapi_root: OpenAPIRepository::DEFAULT_ROOT,
                     openapi_repository: nil, uid_generator: -> { SecureRandom.uuid },
                     name_generator: nil, subresource_bridge: nil, node_resolver: nil, authorizer: nil,
                     # (authorizer is also consulted directly for impersonation)
                     identity_resolver: nil, trusted_subresources: false, namespace_lifecycle: false,
                     system_namespaces: nil, api_audiences: nil,
                     component_health_checker: nil, defer_system_namespaces: false, security: nil,
                     service_account_issuer: nil, crd_manager: nil, aggregator: nil, runtime_config: {},
                     service_allocator: nil, service_cidrs: nil, node_port_range: nil, metrics: nil, logger: nil,
                     peer_proxy: nil)
        configure_features(feature_gates, metrics, peer_proxy)
        # Slow-request and request-trace lines go here; without a logger the
        # API server's request.slow warning could never fire.
        @logger = logger
        @registry = registry.is_a?(RegistryAdapter) ? registry : RegistryAdapter.new(registry)
        @store = store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store)
        @store.metrics = @metrics
        @metrics.storage_source = -> { storage_object_counts }
        @clock = clock
        @service_allocator = service_allocator || default_service_allocator(service_cidrs, node_port_range)
        @service_allocator.metrics = @metrics
        @router = Router.new(@registry)
        @openapi = openapi_repository || OpenAPIRepository.new(root: openapi_root)
        @openapi_encoded = {}
        @openapi_encoded_mutex = Mutex.new
        @field_managers = FieldManagerRegistry.new(openapi: @openapi, clock: -> { @clock.call })
        @version_info = DEFAULT_VERSION.merge(stringify_keys(version_info)).freeze
        @uid_generator = uid_generator
        @name_generator = name_generator || ->(_prefix) { SecureRandom.alphanumeric(DEFAULT_GENERATE_NAME_SUFFIX_LENGTH).downcase }
        # `ready` may be a boolean or a callable evaluated per request so a
        # durable datastore can gate /readyz on quorum availability.
        @ready = ready.respond_to?(:call) ? ready : !!ready
        configure_runtime(runtime_config)
        # NamespaceLifecycle admission and the system namespaces it relies on
        # are enabled together: the rubernetes-apiserver process and the
        # evidence probes turn them on; a bare Server used as a library
        # component leaves them off (system_namespaces is the legacy alias).
        @namespace_lifecycle = system_namespaces.nil? ? namespace_lifecycle == true : system_namespaces == true
        # ServiceAccount token issuer used by the serviceaccounts/token
        # subresource and the OpenID discovery endpoints.
        @service_account_issuer = service_account_issuer
        # CustomResourceDefinition serving and API aggregation are optional
        # extensions of the core; when present they are kept in sync from the
        # commit paths of their configuration resources.
        @crd_manager = crd_manager
        @crd_finalizers_lock = Mutex.new
        @crd_finalizers = {}
        @aggregator = aggregator
        @api_audiences = (api_audiences.nil? || Array(api_audiences).empty? ? DEFAULT_API_AUDIENCES : Array(api_audiences)).map(&:to_s).freeze
        @component_health_checker = component_health_checker
        @node_resolver = node_resolver
        bridge_authorizer = adopt_security(security, authorizer, identity_resolver)
        @subresource_bridge = subresource_bridge_for(subresource_bridge, node_resolver, bridge_authorizer, trusted_subresources)
        # A durable (Raft) store has no quorum before the process starts;
        # the service then calls ensure_system_namespaces! itself once the
        # datastore is available.
        ensure_system_namespaces! if @namespace_lifecycle && !defer_system_namespaces
      end

      # --runtime-config selects served group versions independently of feature
      # gates. Register the write barrier against that resource set.
      private def configure_runtime(runtime_config)
        @runtime_config = stringify_keys(runtime_config || {}).freeze
        initialize_storage_version_barrier
      end

      private def configure_features(feature_gates, metrics, peer_proxy)
        gates = stringify_keys(feature_gates)
        raise ArgumentError, "DeclarativeValidation is locked to true in Kubernetes v1.36.2" if gates["DeclarativeValidation"] == false
        raise ArgumentError, "StorageVersionAPI requires APIServerIdentity" if gates["StorageVersionAPI"] == true && gates["APIServerIdentity"] == false

        @feature_gates = DEFAULT_FEATURE_GATES.merge(gates).freeze
        @metrics = metrics.nil? ? Observability::Metrics.new(feature_gates: gates) : metrics
        register_sharded_watch_metrics if feature_gate_enabled?(ShardSelector::GATE)
        @peer_proxy = peer_proxy if feature_gate_enabled?("UnknownVersionInteroperabilityProxy") && feature_gate_enabled?("APIServerIdentity")
        @peer_proxy.metrics = @metrics if @peer_proxy
      end

      # kube-apiserver's system namespaces controller creates these at start.
      # Idempotent: concurrent API servers on the same store race safely.
      def ensure_system_namespaces!
        return unless @namespace_lifecycle

        namespaces = namespaces_resource
        return if namespaces.nil?

        SYSTEM_NAMESPACES.each do |name|
          begin
            @store.get(resource: namespaces, namespace: :cluster, name: name)
            next
          rescue MemoryStore::NotFound
            nil
          end
          object = {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => name},
                    "spec" => {"finalizers" => ["kubernetes"]}, "status" => {"phase" => "Active"}}
          object = apply_schema(namespaces, object, operation: :create)
          object = prepare_created_metadata(object, resource: namespaces)
          begin
            @store.create(resource: namespaces, namespace: :cluster, object: object)
          rescue MemoryStore::AlreadyExists
            nil
          end
        end
        true
      end

      def ready?
        basic_datastore_ready? && storage_version_registered?
      end

      private def basic_datastore_ready?
        @ready.respond_to?(:call) ? @ready.call == true : @ready
      end

      def local_group_versions
        enabled_resources.reject(&:custom?).map { |resource| [resource.group, resource.version] }.uniq
      end

      # Every answered request is counted -- the ones that end in a raised
      # Status too, which the handler below turns into their response --
      # and in flight while it is served, as kube-apiserver's
      # endpoints/metrics and maxinflight filter count them.
      #
      # A long-running request (a watch, logs, exec...) is recorded when its
      # stream ends, and counted in apiserver_longrunning_requests meanwhile.
      def call(input)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        metric = {}
        kind = mutating_input?(input) ? "mutating" : "readOnly"
        @metrics&.inflight(kind, 1)
        Thread.current[WEBHOOK_SECONDS_KEY] = 0.0
        response = call_unmetered(input, metric)
        await_watch_delivery(response) if kind == "mutating"
        Thread.current[REQUEST_PHASES_KEY] = metric[:phases]
        webhook_seconds = Thread.current[WEBHOOK_SECONDS_KEY].to_f
        long_running = best_effort { long_running_response(metric[:request], metric[:route], response, started, webhook_seconds) }
        return long_running if long_running

        best_effort { record_request_metric(metric[:request], metric[:route], response, started, webhook_seconds: webhook_seconds) }
        response
      ensure
        Thread.current[REQUEST_PHASES_KEY] = nil
        Thread.current[WEBHOOK_SECONDS_KEY] = nil
        @metrics&.inflight(kind, -1) if kind
      end

      alias handle call

      # Return a decoded body for callers that do not use a Response object.
      def call_json(input)
        call(input).body
      end

      # [address, port] of one ready endpoint behind a Service port, for
      # callers (conversion/admission webhooks) that must dial the endpoint
      # directly: the API server host has no cluster DNS for *.svc names.
      # nil when the Service, its port or a ready endpoint cannot be found.
      def service_endpoint_address(namespace, name, port)
        best_effort do
          descriptor = @registry.find_gvr(group: "", version: "v1", resource: "services")
          next nil if descriptor.nil?

          service = @store.get(resource: descriptor, namespace: namespace, name: name)
          endpoint = ready_endpoint_for(namespace, name, select_service_port(service, port))
          endpoint && [endpoint.fetch(:address), endpoint.fetch(:port)]
        end
      end

      # ---- what the backing store can do ----------------------------------
      # The store behind the adapter is a MemoryStore, a Storage::MemoryStore
      # or a RaftStore.  Only some of them deliver watch events synchronously,
      # serve cached reads, share a read barrier or count their objects, so
      # these four are asked for here and nowhere else.

      def await_watch_delivery(response)
        return unless response && response.status.between?(200, 299)

        backing = @store.store
        return unless backing.respond_to?(:await_watch_delivery)

        # The write is committed; a watcher that cannot be waited for must
        # not turn its answer into a failure.
        best_effort do
          revision = response.body.is_a?(Hash) ? response.body.dig("metadata", "resourceVersion") : nil
          backing.await_watch_delivery(revision, timeout: WATCH_DELIVERY_TIMEOUT) unless revision.to_s.empty?
        end
      end

      # RaftStore#cached_read, or the block as is for a store without it.
      def cached_store_read(&)
        backing = @store.store
        return backing.cached_read(&) if backing.respond_to?(:cached_read)

        yield
      end

      # A request's reads share one linearizable barrier (RaftStore
      # #with_read_barrier); a store without the notion runs the block as is.
      def with_request_read_barrier(&)
        backing = @store.store
        return backing.with_read_barrier(&) if backing.respond_to?(:with_read_barrier)

        yield
      end

      private

      def default_service_allocator(service_cidrs, node_port_range)
        # Service ClusterIP/NodePort allocation (pkg/registry/core/service):
        # every API server shares the same IPAddress-backed allocator state.
        ServiceAllocator.new(
          store: @store, registry: @registry, clock: @clock,
          metadata_preparer: ->(object) { prepare_created_metadata(object) },
          service_cidrs: service_cidrs || ServiceAllocator::DEFAULT_SERVICE_CIDRS,
          node_port_range: node_port_range || ServiceAllocator::DEFAULT_NODE_PORT_RANGE
        )
      end

      # The security pipeline (request ID, authentication, authorization,
      # flow control, admission, audit) is optional so the in-process API
      # core stays usable as a library; when present it also serves the
      # review endpoints and the streaming subresource authorizer.
      #
      # Returns the authorizer the streaming subresource bridge is given.
      def adopt_security(security, authorizer, identity_resolver)
        @security = security
        @identity_resolver = identity_resolver
        @authorizer = authorizer
        @impersonation_authorizer = authorizer
        return authorizer if security.nil?

        # The pipeline's authentication / authorization / impersonation
        # metrics go to this server's registry.
        security.impersonation.metrics = @metrics if security.impersonation
        security.metrics = @metrics
        # The review endpoints (SubjectAccessReview, SelfSubjectRulesReview)
        # answer with the pipeline's authorizer unless one is given.  Without
        # this fallback a production server, which is given only the
        # pipeline, answered every SubjectAccessReview "allowed".
        @authorizer ||= security.review_adapter
        @impersonation_authorizer ||= security.authorizer
        @identity_resolver ||= lambda(&:identity)
        @authorizer
      end

      # `false` turns the Pod streaming subresources off; nil builds the
      # default bridge.
      def subresource_bridge_for(given, node_resolver, authorizer, trusted_subresources)
        return nil if given == false

        given || SubresourceBridge.new(node_resolver: node_resolver, authorizer: authorizer, trusted_mode: trusted_subresources,
                                       split_log_streams: feature_gate_enabled?("PodLogsQuerySplitStreams"))
      end

      # The one place this class swallows an error.  It is for work whose
      # failure must not change the answer already decided: recording a
      # metric or a log line about a request, a background loop's next turn,
      # and a question to an injected collaborator whose every failure means
      # "no answer".  The block's value, or nil when it raised.
      def best_effort
        yield
      rescue StandardError
        nil
      end

      # UpdateStoreStats: the stored objects of every served group/resource
      # (0 for none), asked by Metrics at scrape time, at most once a minute.
      def storage_object_counts
        raw = @store.store
        return [] unless raw.respond_to?(:object_counts)

        counts = raw.object_counts
        sizes = raw.respond_to?(:object_sizes) ? raw.object_sizes : {}
        @registry.resources.each_with_object({}) do |resource, result|
          key = [resource.group.to_s, resource.resource.to_s]
          next if result.key?(key)

          gvr = resource.storage_gvr
          versions = ([gvr.version] + resource.storage_key_versions).uniq
          prefixes = versions.map { |version| "registry/#{GVR.new(group: gvr.group, version: version, resource: gvr.resource)}" }
          result[key] = [prefixes.sum { |prefix| counts.fetch(prefix, 0) }, prefixes.sum { |prefix| sizes.fetch(prefix, 0) }]
        end.map { |(group, name), (count, bytes)| [group, name, count, bytes] }
      end

      # ---- what an injected collaborator can do ----------------------------
      # Request, Response, Route, Resource and the security pipeline have one
      # shape each and are simply called.  The collaborators below are handed
      # in by whoever builds the server and come in several shapes; each
      # question about a shape is asked once, here.

      # A response marked as a stream whose body yields its chunks or events
      # (a watch stream, an Enumerator), as opposed to a complete String.
      def streaming_body?(response)
        response.stream? && !response.body.is_a?(String) && response.body.respond_to?(:each)
      end

      # The node resolver is a NodeEndpointResolver in the API server process
      # and a plain {node name => agent} map in in-process setups; only the
      # former knows how the kubelet is dialled.  The same scheme and client
      # credentials exec and logs dial the kubelet with.
      def kubelet_scheme
        @node_resolver.respond_to?(:scheme) ? @node_resolver.scheme.to_s : "https"
      end

      def kubelet_client_tls
        @node_resolver.respond_to?(:tls) ? @node_resolver.tls : nil
      end

      # The review authorizer is the pipeline's ReviewAdapter, whatever was
      # given as `authorizer:` (possibly a bare callable, which answers
      # neither question), or nil -- AlwaysAllow.
      def authorizer_lists_rules?
        @authorizer.respond_to?(:rules_for)
      end

      def authorizer_reviews_access?
        @authorizer.respond_to?(:authorize)
      end

      # The identity resolver is an object with #authenticate, a Proc or
      # Method, or anything else with #call; it is given the request, or the
      # keywords it declares.
      def invoke_identity_resolver(request)
        callable = if @identity_resolver.respond_to?(:authenticate)
                     @identity_resolver.method(:authenticate)
                   elsif @identity_resolver.is_a?(Proc) || @identity_resolver.is_a?(Method)
                     @identity_resolver
                   elsif @identity_resolver.respond_to?(:call)
                     @identity_resolver.method(:call)
                   else
                     raise Status::ServiceUnavailable.new("request identity resolver is invalid")
                   end
        parameters = callable.parameters
        keyword_parameters = parameters.select { |kind, _| %i[key keyreq keyrest].include?(kind) }
        unless keyword_parameters.empty?
          values = {request: request, headers: request.headers, remote_address: nil}
          return callable.call(**values) if keyword_parameters.any? { |kind, _| kind == :keyrest }

          accepted = keyword_parameters.filter_map { |_kind, name| name }
          return callable.call(**values.select { |key, _| accepted.include?(key) })
        end
        return callable.call if parameters.empty?

        callable.call(request)
      end

      # TokenReview: the identity behind a bearer token, nil when no
      # authenticator knows it (an authenticator that raises does not).
      def authenticate_token(token, audiences = @api_audiences)
        identity = identity_resolver_authenticate(token, audiences)
        return identity if identity

        # The ServiceAccount authenticator lives in the security pipeline, not
        # in @identity_resolver (which is cert-based); TokenReview must reach it.
        authenticator = @security&.authenticator
        return nil unless authenticator.respond_to?(:authenticate_token)

        best_effort { authenticator.authenticate_token(token, audiences) }
      end

      def identity_resolver_authenticate(token, audiences)
        return nil unless @identity_resolver.respond_to?(:authenticate_token)

        best_effort do
          if @identity_resolver.method(:authenticate_token).arity == 1
            @identity_resolver.authenticate_token(token)
          else
            @identity_resolver.authenticate_token(token, audiences)
          end
        end
      end

      # What an authenticator answered with: a Hash, a UserInfo, or an
      # AuthenticationResult that wraps the UserInfo and names the audiences
      # the token matched.
      def authenticated_user(identity)
        identity.respond_to?(:user) && !identity.is_a?(Hash) ? identity.user : identity
      end

      def identity_attribute(identity, name)
        if identity.is_a?(Hash)
          identity[name] || identity[name.to_sym]
        elsif identity.respond_to?(name)
          identity.public_send(name)
        end
      end

      def identity_audiences(identity)
        identity.respond_to?(:audiences) ? Array(identity.audiences).map(&:to_s) : []
      end

      # request.identity as a Hash of fields: the pipeline's is one already,
      # a UserInfo converts, and a bare user name (REMOTE_USER) has none.
      def identity_fields(identity)
        identity = identity.to_h if identity.respond_to?(:to_h) && !identity.is_a?(Hash)
        identity.is_a?(Hash) ? identity : nil
      end

      # Adapts the server's authorizer (an Authorizer, a callable, or nil for
      # AlwaysAllow) to the Decision interface the impersonation filter uses.
      class ImpersonationAuthorizer
        def initialize(authorizer)
          @authorizer = authorizer
        end

        def authorize(attributes)
          return Security::Authorization::Decision.allow if @authorizer.nil?

          verdict = @authorizer.respond_to?(:authorize) ? @authorizer.authorize(attributes) : @authorizer.call(attributes)
          return verdict if verdict.is_a?(Security::Authorization::Decision)

          allowed = verdict == true || (verdict.respond_to?(:allowed?) && verdict.allowed?) ||
                    (verdict.is_a?(Hash) && (verdict["allowed"] || verdict[:allowed]))
          allowed ? Security::Authorization::Decision.allow : Security::Authorization::Decision.deny
        rescue StandardError
          Security::Authorization::Decision.deny
        end
      end

      # ---- a resource's schema contract -------------------------------------
      # resource.schema is nil for a bare registry entry, a generated
      # Definition (#validator, #defaulting), the API server process's
      # SchemaContract (#validator, #default) or a CRD's Contract (#default,
      # #validate, #unknown_fields).  SchemaApplication and WriteOptions ask
      # which of those they have through these.

      # The generated Defaulting of a Definition, which defaults a Hash in
      # one pass.
      def schema_hash_defaulting(schema)
        defaulting = schema.respond_to?(:defaulting) ? schema.defaulting : nil
        defaulting if defaulting.respond_to?(:apply_hash)
      end

      def schema_defaults?(schema)
        schema.respond_to?(:default)
      end

      # Whatever validates for this schema: its #validator, else the schema
      # itself; nil when neither validates.
      def schema_validator(schema)
        candidate = schema.respond_to?(:validator) ? schema.validator : schema
        candidate if candidate.respond_to?(:validate)
      end

      # Whatever reports strict-decoding issues for this schema, likewise.
      def schema_issue_reporter(schema)
        candidate = schema.respond_to?(:validator) ? schema.validator : schema
        candidate if candidate.respond_to?(:errors)
      end

      # The field paths a CRD's structural schema would prune; none for a
      # schema that does not prune, or that cannot walk this object.
      def schema_unknown_fields(schema, object)
        return [] unless schema.respond_to?(:unknown_fields)

        best_effort { Array(schema.unknown_fields(object)) } || []
      end

      # A validator reports a cause as a ready Hash, as a
      # Schema::ValidationIssue rendered against the object, or as a message.
      def validation_cause(cause, object)
        if cause.is_a?(Hash) then cause.transform_keys(&:to_s)
        elsif cause.respond_to?(:to_cause) then cause.to_cause(object)
        else {"message" => cause.to_s}
        end
      end
    end

    APIServer = Server
    Handler = Server
  end
end
