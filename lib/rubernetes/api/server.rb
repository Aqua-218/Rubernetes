# frozen_string_literal: true

require "cgi"
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
require "set"
require "yaml"

require_relative "../security"
require_relative "../observability/metrics"
require_relative "../observability/slis"
require_relative "service_allocator"
require_relative "long_running_body"
require_relative "lifecycle"
require_relative "../observability/zpages"
require_relative "field_manager_registry"

module Rubernetes
  module API
    # HTTP-independent Kubernetes API handler. A transport adapter only needs
    # to convert its input into Request and its output from Response.
    class Server
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

      MAX_GENERATE_NAME_ATTEMPTS = 8
      DEFAULT_GENERATE_NAME_SUFFIX_LENGTH = 5

      # Kubernetes publishes APIGroup versions in an upstream-defined order.
      # Do not derive preferredVersion from lexical sorting: v1beta1 would win
      # over v1 on a lexical comparison even though it is not the preferred
      # served version.  This table is pinned to the v1.36.2 corpus shipped by
      # this project; unknown/added versions remain deterministic after the
      # pinned entries.
      PINNED_VERSION_PRIORITY = {
        "admissionregistration.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "apps" => %w[v1],
        "authentication.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "authorization.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "autoscaling" => %w[v2 v1],
        "batch" => %w[v1 v1beta1],
        "certificates.k8s.io" => %w[v1 v1beta1 v1alpha1],
        "coordination.k8s.io" => %w[v1 v1beta1 v1alpha2],
        "discovery.k8s.io" => %w[v1 v1beta1],
        "events.k8s.io" => %w[v1 v1beta1],
        "flowcontrol.apiserver.k8s.io" => %w[v1 v1beta3 v1beta2 v1beta1],
        "networking.k8s.io" => %w[v1 v1beta1],
        "node.k8s.io" => %w[v1 v1alpha1],
        "policy" => %w[v1 v1beta1],
        "rbac.authorization.k8s.io" => %w[v1 v1beta1],
        "resource.k8s.io" => %w[v1 v1beta2 v1beta1 v1alpha3],
        "scheduling.k8s.io" => %w[v1 v1alpha2],
        "storage.k8s.io" => %w[v1 v1beta1],
        "storagemigration.k8s.io" => %w[v1beta1],
        "internal.apiserver.k8s.io" => %w[v1alpha1],
        "apiregistration.k8s.io" => %w[v1 v1beta1],
        "auditregistration.k8s.io" => %w[v1alpha1],
        "metrics.k8s.io" => %w[v1beta1]
      }.transform_values(&:freeze).freeze

      # The generated schema registry intentionally contains every upstream
      # type, including API versions which are compiled but not served by the
      # default v1.36.2 apiserver profile. Keep the registry complete while
      # making the live REST/discovery surface follow the upstream defaults.
      DEFAULT_FEATURE_GATES = {
        "MutatingAdmissionPolicy" => true,
        "ClusterTrustBundle" => false,
        "PodCertificateRequest" => false,
        "CoordinatedLeaderElection" => false,
        "MultiCIDRServiceAllocator" => true,
        "DynamicResourceAllocation" => true,
        "GenericWorkload" => false,
        "VolumeAttributesClass" => true,
        "StorageVersionMigrator" => false,
        "StorageVersionAPI" => false
      }.freeze
      DEFAULT_DISABLED_GATES_BY_GVR = {
        ["admissionregistration.k8s.io", "v1alpha1", "mutatingadmissionpolicies"] => "MutatingAdmissionPolicy",
        ["admissionregistration.k8s.io", "v1alpha1", "mutatingadmissionpolicybindings"] => "MutatingAdmissionPolicy",
        ["admissionregistration.k8s.io", "v1beta1", "mutatingadmissionpolicies"] => "MutatingAdmissionPolicy",
        ["admissionregistration.k8s.io", "v1beta1", "mutatingadmissionpolicybindings"] => "MutatingAdmissionPolicy",
        ["certificates.k8s.io", "v1alpha1", "clustertrustbundles"] => "ClusterTrustBundle",
        ["certificates.k8s.io", "v1beta1", "clustertrustbundles"] => "ClusterTrustBundle",
        ["certificates.k8s.io", "v1beta1", "podcertificaterequests"] => "PodCertificateRequest",
        ["coordination.k8s.io", "v1alpha2", "leasecandidates"] => "CoordinatedLeaderElection",
        ["coordination.k8s.io", "v1beta1", "leasecandidates"] => "CoordinatedLeaderElection",
        ["networking.k8s.io", "v1beta1", "ipaddresses"] => "MultiCIDRServiceAllocator",
        ["networking.k8s.io", "v1beta1", "servicecidrs"] => "MultiCIDRServiceAllocator",
        ["resource.k8s.io", "v1alpha3", "devicetaintrules"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1alpha3", "resourcepoolstatusrequests"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta1", "deviceclasses"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta1", "resourceclaims"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta1", "resourceclaimtemplates"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta1", "resourceslices"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta2", "deviceclasses"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta2", "devicetaintrules"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta2", "resourceclaims"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta2", "resourceclaimtemplates"] => "DynamicResourceAllocation",
        ["resource.k8s.io", "v1beta2", "resourceslices"] => "DynamicResourceAllocation",
        ["scheduling.k8s.io", "v1alpha2", "podgroups"] => "GenericWorkload",
        ["scheduling.k8s.io", "v1alpha2", "workloads"] => "GenericWorkload",
        ["storage.k8s.io", "v1beta1", "volumeattributesclasses"] => "VolumeAttributesClass",
        ["storagemigration.k8s.io", "v1beta1", "storageversionmigrations"] => "StorageVersionMigrator"
      }.freeze

      attr_reader :service_allocator

      def initialize(registry: Registry.new, store: MemoryStore.new, version_info: {}, clock: -> { Time.now.utc },
                     ready: true, feature_gates: {}, openapi_root: OpenAPIRepository::DEFAULT_ROOT,
                     openapi_repository: nil, uid_generator: -> { SecureRandom.uuid },
                     name_generator: nil,
                     subresource_bridge: nil, node_resolver: nil, authorizer: nil,
                     # (authorizer is also consulted directly for impersonation)
                     identity_resolver: nil, trusted_subresources: false, namespace_lifecycle: false,
                     system_namespaces: nil, api_audiences: nil,
                     component_health_checker: nil, defer_system_namespaces: false, security: nil,
                     service_account_issuer: nil, crd_manager: nil, aggregator: nil, runtime_config: {},
                     service_allocator: nil, service_cidrs: nil, node_port_range: nil, metrics: nil, logger: nil)
        @metrics = metrics.nil? ? Observability::Metrics.new(feature_gates: stringify_keys(feature_gates)) : metrics
        # Slow-request and request-trace lines go here; without a logger the
        # API server's request.slow warning could never fire.
        @logger = logger
        @registry = registry.is_a?(RegistryAdapter) ? registry : RegistryAdapter.new(registry)
        @store = store.is_a?(StoreAdapter) ? store : StoreAdapter.new(store)
        @store.metrics = @metrics if @store.respond_to?(:metrics=)
        @metrics.storage_source = -> { storage_object_counts } if @metrics.respond_to?(:storage_source=)
        # Service ClusterIP/NodePort allocation (pkg/registry/core/service):
        # every API server shares the same IPAddress-backed allocator state.
        @service_allocator = service_allocator || ServiceAllocator.new(
          store: @store, registry: @registry, clock: clock,
          metadata_preparer: ->(object) { prepare_created_metadata(object) },
          service_cidrs: service_cidrs || ServiceAllocator::DEFAULT_SERVICE_CIDRS,
          node_port_range: node_port_range || ServiceAllocator::DEFAULT_NODE_PORT_RANGE
        )
        @service_allocator.metrics = @metrics if @service_allocator.respond_to?(:metrics=)
        @router = Router.new(@registry)
        @openapi = openapi_repository || OpenAPIRepository.new(root: openapi_root)
        @field_managers = FieldManagerRegistry.new(openapi: @openapi, clock: -> { @clock.call })
        @version_info = DEFAULT_VERSION.merge(stringify_keys(version_info)).freeze
        @clock = clock
        @uid_generator = uid_generator
        @name_generator = name_generator || ->(_prefix) { SecureRandom.alphanumeric(DEFAULT_GENERATE_NAME_SUFFIX_LENGTH).downcase }
        # `ready` may be a boolean or a callable evaluated per request so a
        # durable datastore can gate /readyz on quorum availability.
        @ready = ready.respond_to?(:call) ? ready : !!ready
        @feature_gates = DEFAULT_FEATURE_GATES.merge(stringify_keys(feature_gates)).freeze
        # --runtime-config: which group/versions are served.  Beta and alpha
        # API versions are off by default in kube-apiserver even when their
        # feature gate is on; "api/all" or "<group>/<version>" turns them on.
        @runtime_config = stringify_keys(runtime_config || {}).freeze
        # NamespaceLifecycle admission and the system namespaces it relies on
        # are enabled together: the rubernetes-apiserver process and the
        # evidence probes turn them on; a bare Server used as a library
        # component leaves them off (system_namespaces is the legacy alias).
        @namespace_lifecycle = system_namespaces.nil? ? namespace_lifecycle == true : system_namespaces == true
        @identity_resolver = identity_resolver
        # The security pipeline (request ID, authentication, authorization,
        # flow control, admission, audit) is optional so the in-process API
        # core stays usable as a library; when present it also serves the
        # review endpoints and the streaming subresource authorizer.
        @security = security
        # The pipeline's authentication / authorization / impersonation
        # metrics go to this server's registry.
        @security.impersonation.metrics = @metrics if @security.respond_to?(:impersonation) && @security.impersonation
        @security.metrics = @metrics if @security.respond_to?(:metrics=)
        # The review endpoints (SubjectAccessReview, SelfSubjectRulesReview)
        # answer with the pipeline's authorizer unless one is given.  Without
        # this fallback a production server, which is given only the
        # pipeline, answered every SubjectAccessReview "allowed".
        @authorizer = authorizer || (security.review_adapter if security.respond_to?(:review_adapter))
        @impersonation_authorizer = authorizer || (security.authorizer if security.respond_to?(:authorizer))
        # ServiceAccount token issuer used by the serviceaccounts/token
        # subresource and the OpenID discovery endpoints.
        @service_account_issuer = service_account_issuer
        # CustomResourceDefinition serving and API aggregation are optional
        # extensions of the core; when present they are kept in sync from the
        # commit paths of their configuration resources.
        @crd_manager = crd_manager
        @openapi_encoded = {}
        @openapi_encoded_mutex = Mutex.new
        @aggregator = aggregator
        if @security
          @identity_resolver ||= lambda do |request|
            request.identity
          end
          authorizer ||= @security.respond_to?(:review_adapter) ? @security.review_adapter : nil
        end
        @api_audiences = (api_audiences.nil? || Array(api_audiences).empty? ? DEFAULT_API_AUDIENCES : Array(api_audiences)).map(&:to_s).freeze
        @component_health_checker = component_health_checker
        @node_resolver = node_resolver
        @subresource_bridge = if subresource_bridge == false
                                nil
                              elsif subresource_bridge
                                subresource_bridge
                              else
                                SubresourceBridge.new(
                                  node_resolver: node_resolver,
                                  authorizer: authorizer,
                                  trusted_mode: trusted_subresources
                                )
                              end
        # A durable (Raft) store has no quorum before the process starts;
        # the service then calls ensure_system_namespaces! itself once the
        # datastore is available.
        ensure_system_namespaces! if @namespace_lifecycle && !defer_system_namespaces
      end

      attr_reader :registry, :store, :service_allocator, :router, :feature_gates, :subresource_bridge, :metrics

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
          object = prepare_created_metadata(object)
          begin
            @store.create(resource: namespaces, namespace: :cluster, object: object)
          rescue MemoryStore::AlreadyExists
            nil
          end
        end
        true
      end


      def ready?
        @ready.respond_to?(:call) ? @ready.call == true : @ready
      end
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
      # kube-apiserver's LongRunningFunc: watch, and these subresources.
      LONG_RUNNING_SUBRESOURCES = %w[attach exec proxy log portforward].freeze
      # endpoints/metrics validConnectRequests: reported as CONNECT.
      CONNECT_SUBRESOURCES = %w[log exec portforward attach proxy].freeze
      APPLY_PATCH_TYPE = "application/apply-patch+yaml"

      attr_accessor :trace_requests
      attr_reader :field_managers
      # /flagz: the process's command-line flags and flattened configuration
      # (the service that runs this server sets them).
      attr_writer :component_flags

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
        long_running = long_running_response(metric[:request], metric[:route], response, started, webhook_seconds)
        return long_running if long_running

        record_request_metric(metric[:request], metric[:route], response, started, webhook_seconds: webhook_seconds)
        response
      ensure
        Thread.current[REQUEST_PHASES_KEY] = nil
        Thread.current[WEBHOOK_SECONDS_KEY] = nil
        @metrics&.inflight(kind, -1) if kind
      end

      def mutating_input?(input)
        method = input.respond_to?(:method) && !input.is_a?(Hash) ? input.method : (input["REQUEST_METHOD"] || input[:method] if input.respond_to?(:[]))
        !%w[GET HEAD OPTIONS].include?(method.to_s.upcase)
      rescue StandardError
        false
      end

      def call_unmetered(input, metric)
        request = nil
        route = nil
        request = normalize_request(input)
        metric[:request] = request
        route = @router.route(request)
        metric[:route] = route
        pattern = @trace_requests.nil? ? TRACE_REQUESTS : @trace_requests
        Thread.current[REQUEST_PHASES_KEY] = {} if pattern && pattern.match?(request.path.to_s)
        response = with_request_read_barrier do
          route = catch_up_dynamic_route(request, route)
          if @security
            secured_call(request, route)
          else
            note_deprecated_api(request, route, nil)
            finalize_response(request, dispatch(request, route), route: route)
          end
        end
        metric[:route] = route
        response
      rescue Status::Error => error
        finalize_response(request, error_response(error))
      rescue MemoryStore::NotFound => error
        finalize_response(request, error_response(Status::NotFound.new(error.message)))
      rescue MemoryStore::AlreadyExists => error
        finalize_response(request, error_response(Status::AlreadyExists.new(error.message)))
      rescue MemoryStore::Conflict => error
        finalize_response(request, error_response(Status::Conflict.new(error.message)))
      rescue MemoryStore::Gone => error
        finalize_response(request, error_response(Status::Expired.new(error.message, details: error.respond_to?(:details) ? error.details : nil)))
      rescue MemoryStore::InvalidSelector, MemoryStore::InvalidContinueToken,
             MemoryStore::InvalidResourceVersion, MemoryStore::InvalidLimit => error
        details = error.respond_to?(:details) ? error.details : nil
        details ||= {"causes" => [{"reason" => "FieldValueInvalid",
                                    "message" => error.message,
                                    "field" => error.class.name.split("::").last}]}
        finalize_response(request, error_response(Status::BadRequest.new(error.message, details: details)))
      rescue MemoryStore::Error => error
        finalize_response(request, error_response(Status::Error.new(message: error.message, code: error.code,
                                         reason: error.reason, details: error.details)))
      rescue JSON::ParserError => error
        finalize_response(request, error_response(Status::BadRequest.new("request body is not valid JSON: #{error.message}")))
      rescue Psych::Exception => error
        finalize_response(request, error_response(Status::BadRequest.new("request body is not valid YAML: #{error.message}")))
      rescue JSON::GeneratorError, EncodingError, ArgumentError => error
        finalize_response(request, error_response(Status::BadRequest.new("request could not be processed: #{safe_error_message(error)}")))
      ensure
        # The request trace is logged with the metric, after this returns.
        metric[:phases] = Thread.current[REQUEST_PHASES_KEY]
        Thread.current[REQUEST_PHASES_KEY] = nil
      end

      # A write is answered once the watchers it woke have sent its event (or
      # after WATCH_DELIVERY_TIMEOUT): kube-apiserver's clients usually see
      # the event in their informer before the response, and the e2e CRUD
      # helper relies on it -- it reads its informer cache right after each
      # write and, on a miss, waits two seconds to look again ("[DRA] CRUD
      # Tests ResourceClaim" 12.7 s, upstream 0.2).  Slow watchers are not
      # waited for (Watcher#await_delivered).
      WATCH_DELIVERY_TIMEOUT = 0.02

      def await_watch_delivery(response)
        return unless response.respond_to?(:status) && response.status.to_i.between?(200, 299)

        body = response.body
        revision = body.is_a?(Hash) ? body.dig("metadata", "resourceVersion") : nil
        return if revision.to_s.empty?

        backing = @store.respond_to?(:store) ? @store.store : @store
        return unless backing.respond_to?(:await_watch_delivery)

        backing.await_watch_delivery(revision, timeout: WATCH_DELIVERY_TIMEOUT)
      rescue StandardError
        nil
      end

      def phase(name)
        phases = Thread.current[REQUEST_PHASES_KEY]
        return yield unless phases

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          yield
        ensure
          phases[name] = phases.fetch(name, 0.0) + (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        end
      end

      # RaftStore#cached_read, or the block as is for a store without it.
      def cached_store_read(&block)
        backing = @store.respond_to?(:store) ? @store.store : @store
        return backing.cached_read(&block) if backing.respond_to?(:cached_read)

        yield
      end

      # A request's reads share one linearizable barrier (RaftStore
      # #with_read_barrier); a store without the notion runs the block as is.
      def with_request_read_barrier(&block)
        backing = @store.respond_to?(:store) ? @store.store : @store
        return backing.with_read_barrier(&block) if backing.respond_to?(:with_read_barrier)

        yield
      end

      # Each apiserver installs a CustomResourceDefinition from its own
      # watch, so a custom resource request that reaches a peer right after
      # the CRD was created elsewhere answered 404 until that watch caught up
      # (the e2e client balances across apiservers through the kubernetes
      # Service).  A path under /apis/<group>/ that no served resource
      # matches re-reads the definitions of that group -- after this
      # request's read barrier, so it sees every committed CRD -- and
      # installs any this server has not yet before routing again.
      def catch_up_dynamic_route(request, route)
        return route if @crd_manager.nil? || route.kind == :resource

        segments = route.path.to_s.split("/").reject(&:empty?)
        return route unless segments.first == "apis" && segments.length >= 2

        group = segments[1]
        return route unless %i[unknown api_group resource_list].include?(route.kind)
        return route if route.kind != :unknown && enabled_resources.any? { |resource| resource.group == group && (route.version.nil? || resource.version == route.version.to_s) }

        crd_resource = @registry.find_gvr(group: CRD_GVR[0], version: CRD_GVR[1], resource: CRD_GVR[2])
        return route if crd_resource.nil?

        served = @crd_manager.served_names
        pending = @store.list(resource: crd_resource, namespace: :all, selectors: nil).items.select do |crd|
          crd.dig("spec", "group") == group && !served.include?(crd.dig("metadata", "name")) && crd.dig("metadata", "deletionTimestamp").nil?
        end
        return route if pending.empty?

        pending.each { |crd| @crd_manager.sync(crd) }
        @router.route(request)
      rescue MemoryStore::Error, Status::Error
        route
      end

      # Error text shown to clients never carries Ruby class names, paths or
      # object dumps.
      def safe_error_message(error)
        error.message.to_s.gsub(/#<[^>]*>/, "").gsub(%r{/[^\s]+\.rb:\d+}, "").strip[0, 200]
      end

      alias handle call

      # Pipeline order per spec 5.1.1: request ID, authentication,
      # authorization, flow control, then routing/decode/admission/store, and
      # audit at the end.  Security failures are rendered as Status objects
      # without leaking internals; the audit ResponseComplete stage always
      # runs, including on 401/403/429.
      def secured_call(request, route)
        entry = nil
        response = nil
        error = nil
        begin
          entry = phase("security") { @security.enter(request, route) }
        rescue Security::Pipeline::Unauthorized => unauthorized
          return finalize_response(request, error_response(Status::Unauthorized.new("Unauthorized")))
        rescue Security::Pipeline::BadRequest => bad_request
          return finalize_response(request, error_response(Status::BadRequest.new(bad_request.message)))
        rescue Security::Pipeline::Forbidden => forbidden
          if (status_error = forbidden.status_error)
            return finalize_response(request, error_response(Status::Forbidden.new(status_error.message, details: status_error.details)))
          end

          message = forbidden_message(forbidden, request, route)
          return finalize_response(request, error_response(Status::Forbidden.new(message, details: forbidden_details(route))))
        rescue Security::FlowControl::RejectedError => rejected
          record_request_termination(request, route, 429)
          return finalize_response(request, error_response(Status::TooManyRequests.new("too many requests, please try again later", retry_after_seconds: rejected.retry_after)))
        end
        secured = entry.request
        note_deprecated_api(secured, route, entry)
        previous_audit = Thread.current[AUDIT_KEY]
        Thread.current[AUDIT_KEY] = entry.audit
        begin
          response = begin
            dispatched = dispatch(secured, route)
            phase("finalize") { finalize_response(secured, dispatched, route: route) }
          rescue Status::Error => status_error
            finalize_response(secured, error_response(status_error))
          rescue MemoryStore::Error, JSON::ParserError, Psych::Exception => store_error
            finalize_response(secured, translate_store_error(store_error))
          rescue JSON::GeneratorError, EncodingError, ArgumentError => encoding_error
            finalize_response(secured, error_response(Status::BadRequest.new("request could not be processed: #{safe_error_message(encoding_error)}")))
          end
          response = response.with_header("audit-id", entry.request.request_id) if response.respond_to?(:with_header) && entry.request.request_id
          response
        rescue StandardError => unexpected
          error = unexpected
          raise
        ensure
          Thread.current[AUDIT_KEY] = previous_audit
          phase("security.exit") do
            @security.exit(entry, response, error: error, response_object: response&.body.is_a?(Hash) ? response.body : nil,
                           request_object: entry.attributes.resource_request? && request.body.is_a?(String) && !request.body.empty? ? safe_json(request.body) : nil)
          end
        end
      end

      # endpoints/deprecation + installer: a request to a deprecated built-in
      # kind carries the Warning, sets apiserver_requested_deprecated_apis and
      # the k8s.io/deprecated audit annotations; a deprecated CRD version
      # carries its deprecationWarning.
      def note_deprecated_api(request, route, entry)
        return unless route.respond_to?(:resource_route?) && route.resource_route? && route.resource

        resource = route.resource
        group = resource.respond_to?(:group) ? resource.group.to_s : ""
        version = resource.respond_to?(:version) ? resource.version.to_s : ""
        if resource.respond_to?(:custom?) && resource.custom?
          warning = @crd_manager.respond_to?(:deprecation_warning) ? @crd_manager.deprecation_warning(group, version, resource.resource) : nil
          request_warnings(request) << warning if warning && !warning.empty?
          return
        end

        deprecation = Lifecycle.deprecation(group, version, resource.kind)
        return unless deprecation

        request_warnings(request) << deprecation.message
        unless @deprecated_metric_registered
          @metrics&.register("apiserver_requested_deprecated_apis", type: :gauge,
                                                                   help: "Gauge of deprecated APIs that have been requested, broken out by API group, version, resource, subresource, and removed_release.")
          @deprecated_metric_registered = true
        end
        @metrics&.set("apiserver_requested_deprecated_apis", 1,
                      {"group" => group, "version" => version, "resource" => resource.resource.to_s,
                       "subresource" => route.subresource.to_s, "removed_release" => deprecation.removed_release})
        audit = entry&.audit
        audit&.annotate("k8s.io/deprecated", "true")
        audit&.annotate("k8s.io/removed-release", deprecation.removed_release) unless deprecation.removed_release.empty?
      rescue StandardError
        nil
      end

      # ---- dynamic API surface: CRDs and aggregation --------------------------

      CRD_GVR = ["apiextensions.k8s.io", "v1", "customresourcedefinitions"].freeze
      APISERVICE_GVR = ["apiregistration.k8s.io", "v1", "apiservices"].freeze

      def crd_resource?(resource)
        [resource.group, resource.version, resource.resource] == CRD_GVR
      end

      def apiservice_resource?(resource)
        [resource.group, resource.version, resource.resource] == APISERVICE_GVR
      end

      # Called after a CRD / APIService object is committed (create, update,
      # patch, delete).  CRD status conditions are written back through the
      # store so the served state is observable; a deleted CRD first removes
      # its custom resources (the customresourcecleanup finalizer), then is
      # withdrawn from the registry and OpenAPI.
      def after_commit(resource, object, deleted: false)
        if @crd_manager && crd_resource?(resource)
          sync_crd(object, deleted: deleted)
        elsif @aggregator && apiservice_resource?(resource)
          if deleted
            @aggregator.remove(metadata_value(object, "name"))
          else
            @aggregator.sync(object)
            schedule_apiservice_availability(metadata_value(object, "name"))
          end
        end
      end

      # kube-aggregator's available controller: the APIService status
      # Available condition is recomputed when the object is written and
      # then periodically, off the request path.
      APISERVICE_AVAILABILITY_INTERVAL = 5

      def schedule_apiservice_availability(name)
        start_apiservice_availability_loop
        thread = Thread.new { refresh_apiservice_availability(name) }
        thread.name = "apiservice-availability-#{name}"
        thread
      end

      def refresh_apiservice_availability(name)
        return if @aggregator.nil?

        resource = @registry.find_gvr(group: APISERVICE_GVR[0], version: APISERVICE_GVR[1], resource: APISERVICE_GVR[2])
        return if resource.nil?

        current = @store.get(resource: resource, namespace: :cluster, name: name)
        backend = @aggregator.backend(name)
        condition = if backend.nil?
                      {"type" => "Available", "status" => "True", "reason" => "Local", "message" => "Local APIServices are always available",
                       "lastTransitionTime" => @clock.call.utc.iso8601}
                    else
                      @aggregator.availability_condition(backend, service: lookup_service(backend), endpoint_slices: lookup_endpoint_slices(backend))
                    end
        @aggregator.mark_available(name, condition["status"] == "True") if backend
        existing = Array(current.dig("status", "conditions"))
        previous = existing.find { |entry| entry["type"] == "Available" }
        observe_apiservice_availability(name, previous, condition)
        return if previous && previous.values_at("status", "reason", "message") == condition.values_at("status", "reason", "message")

        condition["lastTransitionTime"] = previous["lastTransitionTime"] if previous && previous["status"] == condition["status"] && previous["lastTransitionTime"]
        status = (current["status"] || {}).merge("conditions" => existing.reject { |entry| entry["type"] == "Available" } + [condition])
        @store.update(resource: resource, namespace: :cluster, name: name, object: current.merge("status" => status),
                      resource_version: metadata_value(current, "resourceVersion"))
      rescue MemoryStore::NotFound, MemoryStore::Conflict, Status::Error
        nil
      end

      # kube-aggregator available controller metrics: the gauge on every
      # sync, the counter when an APIService turns unavailable.
      def observe_apiservice_availability(name, previous, condition)
        return unless @metrics

        unless @aggregator_metrics_registered
          @metrics.register("aggregator_unavailable_apiservice", type: :gauge,
                                                                 help: "Gauge of APIServices which are marked as unavailable broken down by APIService name.")
          @metrics.register("aggregator_unavailable_apiservice_total", type: :counter,
                                                                       help: "Counter of APIServices which are marked as unavailable broken down by APIService name and reason.")
          @aggregator_metrics_registered = true
        end
        available = condition["status"] == "True"
        @metrics.set("aggregator_unavailable_apiservice", available ? 0 : 1, {"name" => name.to_s})
        was_available = previous && previous["status"] == "True"
        # setUnavailableCounter: only a change from available (an absent
        # condition is Unknown, not available).
        return if available || !was_available

        @metrics.increment("aggregator_unavailable_apiservice_total", {"name" => name.to_s, "reason" => (condition["reason"] || "UnknownReason").to_s})
      rescue StandardError
        nil
      end

      def start_apiservice_availability_loop
        return if @apiservice_availability_thread&.alive?

        @apiservice_availability_thread = Thread.new do
          loop do
            sleep APISERVICE_AVAILABILITY_INTERVAL
            @aggregator.backends.each { |backend| refresh_apiservice_availability(backend.name) }
          rescue StandardError
            nil
          end
        end
        @apiservice_availability_thread.name = "apiservice-availability"
      end

      def lookup_service(backend)
        services = @registry.find_gvr(group: "", version: "v1", resource: "services")
        return nil if services.nil?

        @store.get(resource: services, namespace: backend.service_namespace.to_s, name: backend.service_name.to_s)
      rescue MemoryStore::NotFound, Status::Error
        nil
      end

      def lookup_endpoint_slices(backend)
        slices = @registry.find_gvr(group: "discovery.k8s.io", version: "v1", resource: "endpointslices")
        return [] if slices.nil?

        selectors = Selectors.new(label_selector: "kubernetes.io/service-name=#{backend.service_name}")
        @store.list(resource: slices, namespace: backend.service_namespace.to_s, selectors: selectors).items
      rescue MemoryStore::NotFound, Status::Error
        []
      end

      def sync_crd(object, deleted:)
        if deleted
          @crd_manager.withdraw(metadata_value(object, "name"))
          return
        end
        conditions = @crd_manager.sync(object)
        return if conditions.empty?

        established = conditions.any? { |condition| condition["type"] == "Established" && condition["status"] == "True" }
        accepted = conditions.find { |condition| condition["type"] == "NamesAccepted" }
        status = (object["status"] || {}).merge(
          "conditions" => conditions,
          "acceptedNames" => accepted && accepted["status"] == "True" ? (object.dig("spec", "names") || {}) : (object.dig("status", "acceptedNames") || {}),
          "storedVersions" => established ? ((object.dig("status", "storedVersions") || []) | Array(object.dig("spec", "versions")).select { |version| version["storage"] }.map { |version| version["name"] }) : Array(object.dig("status", "storedVersions"))
        )
        return if status == object["status"]

        crd_resource = @registry.find_gvr(group: CRD_GVR[0], version: CRD_GVR[1], resource: CRD_GVR[2])
        begin
          @store.update(resource: crd_resource, namespace: :cluster, name: metadata_value(object, "name"),
                        object: object.merge("status" => status), resource_version: metadata_value(object, "resourceVersion"))
        rescue MemoryStore::Conflict, MemoryStore::NotFound
          nil
        end
      end

      # Deleting a CRD: finalize by deleting every custom resource, then let
      # the delete proceed once the finalizer is gone.
      def mark_crd_terminating(route, existing, namespace)
        object = deep_copy(existing)
        object["metadata"]["deletionTimestamp"] ||= @clock.call.utc.iso8601(6)
        finalizers = Array(object["metadata"]["finalizers"])
        object["metadata"]["finalizers"] = finalizers | [CRD::Manager::CLEANUP_FINALIZER]
        object["status"] = set_crd_condition(object["status"] || {}, "Terminating", "True", "InstanceDeletionPending",
                                             "CustomResourceDefinition marked for deletion; CustomResource deletion will begin soon")
        @store.update(resource: route.resource, namespace: namespace, name: route.name, object: object,
                      resource_version: metadata_value(existing, "resourceVersion"))
      end

      def set_crd_condition(status, type, value, reason, message)
        conditions = Array(status["conditions"]).reject { |condition| condition["type"] == type }
        previous = Array(status["conditions"]).find { |condition| condition["type"] == type }
        transition = previous && previous["status"] == value ? previous["lastTransitionTime"] : @clock.call.utc.iso8601
        status.merge("conditions" => conditions + [{"type" => type, "status" => value, "lastTransitionTime" => transition, "reason" => reason, "message" => message}])
      end

      # apiextensions crd_finalizer controller: delete every custom resource,
      # then drop the cleanup finalizer so the CRD object disappears.
      def schedule_crd_finalizer(name)
        thread = Thread.new do
          begin
            finalize_crd(name)
          rescue StandardError
            nil
          end
        end
        thread.name = "crd-finalizer-#{name}"
        thread
      end

      def finalize_crd(name)
        crd_resource = @registry.find_gvr(group: CRD_GVR[0], version: CRD_GVR[1], resource: CRD_GVR[2])
        existing = @store.get(resource: crd_resource, namespace: :cluster, name: name)
        return unless metadata_value(existing, "deletionTimestamp")

        in_progress = deep_copy(existing)
        in_progress["status"] = set_crd_condition(in_progress["status"] || {}, "Terminating", "True", "InstanceDeletionInProgress",
                                                  "CustomResource deletion is in progress")
        existing = @store.update(resource: crd_resource, namespace: :cluster, name: name, object: in_progress,
                                 resource_version: metadata_value(existing, "resourceVersion"))
        finalize_crd_resources(existing)
        remaining = Array(metadata_value(existing, "finalizers")) - [CRD::Manager::CLEANUP_FINALIZER]
        if remaining.empty?
          @store.delete(resource: crd_resource, namespace: :cluster, name: name, resource_version: metadata_value(existing, "resourceVersion"))
          after_commit(crd_resource, existing, deleted: true)
        else
          released = deep_copy(existing)
          released["metadata"]["finalizers"] = remaining
          released["status"] = set_crd_condition(released["status"] || {}, "Terminating", "True", "InstanceDeletionCompleted",
                                                 "removed all instances")
          @store.update(resource: crd_resource, namespace: :cluster, name: name, object: released,
                        resource_version: metadata_value(existing, "resourceVersion"))
        end
      rescue MemoryStore::NotFound, MemoryStore::Conflict
        nil
      end

      def finalize_crd_resources(existing)
        spec = existing["spec"] || {}
        storage_version = Array(spec["versions"]).find { |version| version["storage"] == true }&.fetch("name")
        return if storage_version.nil?

        custom = @registry.find_gvr(group: spec["group"], version: storage_version, resource: spec.dig("names", "plural"))
        return if custom.nil?

        @crd_manager.cleanup_resources(existing) do |object|
          namespace = metadata_value(object, "namespace")
          @store.delete(resource: custom, namespace: namespace.nil? || namespace.to_s.empty? ? :cluster : namespace, name: metadata_value(object, "name"),
                        resource_version: metadata_value(object, "resourceVersion"))
        rescue MemoryStore::NotFound, MemoryStore::Conflict
          nil
        end
      end

      # Requests for a group/version that no registered resource serves are
      # proxied when an APIService claims them; discovery for such groups is
      # merged from the backend.
      def aggregated_response(request, route)
        return nil unless @aggregator

        group = route.group.to_s
        version = route.version.to_s
        case route.kind
        when :resource, :resource_list
          return nil if route.kind == :resource && route.resource && !(route.resource.custom? == false && false)
          return nil if route.kind == :resource && route.resource
          return nil if group.empty?
          return nil unless @aggregator.claims?(group, version)

          if route.kind == :resource_list
            document = @aggregator.resource_list(group, version)
            return document ? json_response(document) : @aggregator.unavailable_response
          end
          @aggregator.proxy(request, group: group, version: version)
        when :unknown
          segments = route.path.to_s.split("/").reject(&:empty?)
          return nil unless segments.first == "apis" && segments.length >= 3 && @aggregator.claims?(segments[1], segments[2])

          @aggregator.proxy(request, group: segments[1], version: segments[2])
        end
      end

      # Admission runs between decode and strategy validation (mutating) and
      # after validation (validating).  Rejections become 4xx Status objects.
      def admit_mutating(request, route, operation, object, old_object, namespace, name: nil)
        chain = admission_chain
        return object unless chain

        # Mutating plugins edit the object in place.  Schema application and the
        # store both hand back structures with frozen members, so the chain must
        # be given a mutable copy -- otherwise the first plugin that touches a
        # defaulted sub-object raises FrozenError and the request 500s.
        attributes = admission_attributes(request, route, operation, deep_copy(object), old_object, namespace, name: name)
        begin
          phase("admit") { chain.admit(attributes) }
        ensure
          record_admission_annotations(attributes)
        end
        attributes.warnings.each { |warning| request_warnings(request) << warning }
        attributes.object
      rescue Security::Admission::Rejected => rejected
        raise admission_status(rejected, route)
      end

      def admit_validating(request, route, operation, object, old_object, namespace, name: nil)
        chain = admission_chain
        return true unless chain

        attributes = admission_attributes(request, route, operation, object, old_object, namespace, name: name)
        begin
          phase("validate_admission") { chain.validate(attributes) }
        ensure
          record_admission_annotations(attributes)
        end
        attributes.warnings.each { |warning| request_warnings(request) << warning }
        true
      rescue Security::Admission::Rejected => rejected
        raise admission_status(rejected, route)
      end

      # pods/exec, pods/attach and pods/portforward are CREATE requests that go
      # through admission upstream: a webhook registered for the subresource is
      # handed the options object built from the query string and can deny the
      # connection.  Skipping admission let a denied attach open the stream and
      # hang until the client gave up -- "[sig-api-machinery] AdmissionWebhook
      # should be able to deny attaching pod" reported a kubectl timeout rather
      # than the webhook's message.
      STREAMING_ADMISSION_KINDS = {
        "exec" => "PodExecOptions", "attach" => "PodAttachOptions",
        "portforward" => "PodPortForwardOptions"
      }.freeze

      # Upstream hands these to admission as CONNECT (admission.Connect), not
      # CREATE: the e2e webhook for attach is registered for
      # Operations: [CONNECT], so a CREATE matched no rule and the attach went
      # ahead.  And kubectl 1.36 opens exec/attach over a WebSocket, which is a
      # GET, so admitting POST alone skipped every modern client.
      STREAMING_ADMISSION_METHODS = %w[GET POST].freeze

      def admit_streaming_subresource(request, route)
        kind = STREAMING_ADMISSION_KINDS[route.subresource.to_s]
        return if kind.nil? || !STREAMING_ADMISSION_METHODS.include?(request.method.to_s.upcase)

        options = streaming_options(request, kind)
        admit_mutating(request, route, :connect, options, nil, route.namespace, name: route.name)
        admit_validating(request, route, :connect, options, nil, route.namespace, name: route.name)
      end

      # The options a streaming request carries as query parameters are the
      # object admission sees (pkg/registry/core/pod/rest/subresources.go).
      def streaming_options(request, kind)
        options = {"kind" => kind, "apiVersion" => "v1"}
        if kind == "PodPortForwardOptions"
          ports = Array(request.query_values("ports")).flat_map { |value| value.to_s.split(",") }
          options["ports"] = ports.filter_map { |port| Integer(port, 10) rescue nil }
          return options
        end

        %w[stdin stdout stderr tty].each do |field|
          value = query(request, field)
          options[field] = truthy?(value) unless value.nil? || value.to_s.empty?
        end
        container = query(request, "container").to_s
        options["container"] = container unless container.empty?
        options["command"] = Array(request.query_values("command")).map(&:to_s) if kind == "PodExecOptions"
        options
      end

      def admission_chain
        @security&.admission
      end

      def admission_attributes(request, route, operation, object, old_object, namespace, name: nil)
        user = request.identity ? Security::UserInfo.from_h(request.identity) : Security::UserInfo.anonymous
        dry_run = query(request, "dryRun").to_s == "All"
        Security::Admission::Attributes.new(operation: operation, user: user, group: route.resource.group, version: route.resource.version,
                                            resource: route.resource.resource, kind: route.resource.kind, subresource: route.subresource,
                                            namespace: namespace, name: name || route.name || metadata_value(object || old_object || {}, "name"),
                                            object: object, old_object: old_object, dry_run: dry_run)
      end

      def admission_status(rejected, route)
        details = (rejected.details || {}).merge(resource_details(route)) { |_key, left, _right| left }
        case rejected.code
        when 400 then Status::BadRequest.new(rejected.message, details: details)
        when 409 then Status::Conflict.new(rejected.message, details: details)
        when 422 then Status::Invalid.new(rejected.message, details: details)
        when 500 then Status::Error.new(message: rejected.message, code: 500, reason: "InternalError", details: details)
        when 503 then Status::ServiceUnavailable.new(rejected.message, details: details)
        else Status::Forbidden.new(rejected.message, details: details)
        end
      end

      # Annotations an admission plugin added (PodSecurity's enforce-policy
      # and audit-violations, a webhook's) go onto the request's audit
      # event, rejected requests included.
      def record_admission_annotations(attributes)
        audit = Thread.current[AUDIT_KEY]
        return unless audit && attributes.respond_to?(:annotations)

        attributes.annotations.each { |key, value| audit.annotate(key, value) }
      rescue StandardError
        nil
      end

      def request_warnings(request)
        @request_warnings ||= Hash.new { |hash, key| hash[key] = [] }
        @request_warnings[request.object_id]
      end

      # Admission warnings reach the client as RFC 7234 Warning headers with
      # kube-apiserver's `299 - "text"` rendering.
      def with_warning_headers(request, response)
        warnings = @request_warnings&.delete(request.object_id)
        return response if warnings.nil? || warnings.empty? || !response.respond_to?(:with_header)

        rendered = warnings.map { |warning| "299 - #{warning.to_s.gsub(/[\r\n]+/, " ").inspect}" }
        existing = response.header("warning")
        response.with_header("warning", [existing, *rendered].compact.join(", "))
      end

      def translate_store_error(error)
        case error
        when MemoryStore::NotFound then error_response(Status::NotFound.new(error.message))
        when MemoryStore::AlreadyExists then error_response(Status::AlreadyExists.new(error.message))
        when MemoryStore::Conflict then error_response(Status::Conflict.new(error.message))
        when MemoryStore::Gone then error_response(Status::Expired.new(error.message))
        when JSON::ParserError then error_response(Status::BadRequest.new("request body is not valid JSON: #{error.message}"))
        when Psych::Exception then error_response(Status::BadRequest.new("request body is not valid YAML: #{error.message}"))
        else error_response(Status::Error.new(message: error.message, code: error.respond_to?(:code) ? error.code : 500, reason: error.respond_to?(:reason) ? error.reason : "InternalError"))
        end
      end

      def safe_json(body)
        JSON.parse(body)
      rescue JSON::ParserError, EncodingError, ArgumentError
        nil
      end

      # kube-apiserver forbidden message shape:
      #   pods is forbidden: User "alice" cannot list resource "pods" in API group "" in the namespace "ns"
      def forbidden_message(forbidden, request, route)
        identity = forbidden.user&.name
        identity ||= request.identity.is_a?(Hash) ? request.identity["username"] : nil
        identity ||= Security::UserInfo::ANONYMOUS_NAME
        if route.respond_to?(:resource_route?) && route.resource_route? && route.resource
          resource = route.resource
          target = route.subresource.to_s.empty? ? resource.resource : "#{resource.resource}/#{route.subresource}"
          verb = Security::Authorization::Attributes.verb_for(method: request.method, collection: route.collection,
                                                               watch: watch_request?(request), name_present: !route.name.to_s.empty?)
          scope = route.namespace.to_s.empty? ? " at the cluster scope" : " in the namespace \"#{route.namespace}\""
          "#{target} is forbidden: User \"#{identity}\" cannot #{verb} resource \"#{target}\" in API group \"#{resource.group}\"#{scope}"
        else
          "forbidden: User \"#{identity}\" cannot #{request.method.downcase} path \"#{request.path}\""
        end
      end

      def forbidden_details(route)
        return nil unless route.respond_to?(:resource_route?) && route.resource_route? && route.resource

        {"name" => route.name.to_s, "group" => route.resource.group, "kind" => route.resource.resource}.reject { |_key, value| value.to_s.empty? }
      end

      # Return a decoded body for callers that do not use a Response object.
      def call_json(input)
        call(input).body
      end

      private

      def normalize_request(input)
        return input if input.is_a?(Request)
        return Request.from_env(input) if input.is_a?(Hash) && input.keys.any? { |key| key.to_s == "REQUEST_METHOD" }
        return Request.new(**symbolize_keys(input)) if input.is_a?(Hash)

        raise ArgumentError, "server input must be Request or request attributes"
      end

      def dispatch(request, route)
        aggregated = aggregated_response(request, route)
        return aggregated if aggregated

        case route.kind
        when :version then json_response(version_payload)
        when :api_versions
          aggregated_discovery?(request) ? aggregated_discovery_response(core_only: true) : json_response(api_versions_payload)
        when :api_groups
          aggregated_discovery?(request) ? aggregated_discovery_response(core_only: false) : json_response(api_groups_payload)
        when :api_group then api_group_response(route)
        when :resource_list then resource_list_response(route)
        when :health then health_response(route.path)
        when :metrics then route.path == "/metrics/slis" ? slis_response : metrics_response
        when :statusz then zpage_response(:statusz, request)
        when :flagz then zpage_response(:flagz, request)
        when :openapi then openapi_response(request, route)
        when :openid then openid_response(request, route)
        when :resource then resource_response(request, route)
        else
          unknown_path_response(route)
        end
      end

      # kube-apiserver registers one go-restful web service per served
      # group/version; a miss inside one of them is rendered as a Status,
      # while every other path falls through to the generic HTTP mux and its
      # plain-text "404 page not found".
      def unknown_path_response(route)
        segments = route.path.to_s.split("/").reject(&:empty?)
        group_version = if segments.first == "api" && segments.length >= 2
                          ["", segments[1]]
                        elsif segments.first == "apis" && segments.length >= 3
                          [segments[1], segments[2]]
                        end
        return discovery_not_found_response if group_version.nil?

        served = enabled_resources.any? { |resource| resource.group == group_version[0] && resource.version == group_version[1] }
        return discovery_not_found_response unless served

        error_response(Status::NotFound.new("the server could not find the requested resource", details: {}))
      end

      def resource_response(request, route)
        resource = route.resource
        raise Status::NotFound.new("the requested API path #{route.path.inspect} was not found") unless resource_enabled?(resource)
        api_verb = api_verb_for(request, route)
        allowed_verbs = route.subresource ? resource.subresource_verbs(route.subresource) : resource.verbs
        # A proxy subresource is a Connecter: upstream's ProxyREST accepts
        # every method (GET POST PUT PATCH DELETE HEAD OPTIONS) and relays it,
        # whatever discovery lists as verbs.  "[sig-network] Proxy version v1
        # A set of valid responses are returned for both pod and service
        # Proxy" sends OPTIONS.
        proxy = route.subresource.to_s == "proxy"
        unless proxy || allowed_verbs.empty? || allowed_verbs.include?(api_verb)
          target = route.subresource ? "#{resource.resource}/#{route.subresource}" : resource.resource
          raise Status::MethodNotAllowed.new("verb #{request.method} is not supported for #{target}")
        end

        if @subresource_bridge&.handles?(route)
          bridged_request = authenticate_request(request)
          pod = await_scheduled_pod(route, request)
          admit_streaming_subresource(bridged_request, route)
          record_pod_logs_usage(request) if route.subresource.to_s == "log"
          begin
            return @subresource_bridge.call(bridged_request, route, pod: pod)
          rescue Status::Error => error
            record_pod_logs_tls_failure(error) if route.subresource.to_s == "log"
            # Streaming clients frequently crash on a log error rather than
            # reporting it, so the reason has to be recoverable from the
            # server's own log.
            warn("subresource.failed subresource=#{route.subresource} " \
                 "pod=#{route.namespace}/#{route.name} node=#{pod.dig("spec", "nodeName").inspect} " \
                 "error=#{error.class}: #{error.message}")
            raise
          end
        end

        virtual = virtual_resource_response(request, route)
        return virtual if virtual

        if watch_request?(request)
          return watch_response(request, route)
        end

        case request.method
        when "GET", "HEAD"
          route.collection ? list_response(request, route) : get_response(route)
        when "POST"
          require_collection!(route)
          create_response(request, route)
        when "PUT"
          require_member!(route)
          update_response(request, route)
        when "PATCH"
          require_member!(route)
          patch_response(request, route)
        when "DELETE"
          route.collection ? delete_collection_response(request, route) : delete_response(request, route)
        else
          raise Status::MethodNotAllowed.new("method #{request.method} is not supported for #{route.path}")
        end
      end

      # ---- virtual REST resources ------------------------------------------
      # These kinds are served by REST handlers rather than storage in
      # kube-apiserver: token/subject reviews, pod eviction, and component
      # status.  Each handler mirrors its upstream registry counterpart.

      DEFAULT_API_AUDIENCES = %w[https://kubernetes.default.svc].freeze
      COMPONENT_STATUS_SERVERS = [
        {"name" => "scheduler", "url" => "https://127.0.0.1:10259/healthz"},
        {"name" => "controller-manager", "url" => "https://127.0.0.1:10257/healthz"},
        {"name" => "etcd-0", "url" => nil}
      ].freeze

      def virtual_resource_response(request, route)
        resource = route.resource
        group = resource.group.to_s
        if route.subresource == "eviction" && resource.resource == "pods" && group.empty?
          return eviction_response(request, route)
        end
        if route.subresource == "binding" && resource.resource == "pods" && group.empty?
          return binding_response(request, route)
        end
        if route.subresource == "proxy" && group.empty? && %w[pods services nodes].include?(resource.resource)
          return proxy_response(request, route)
        end
        if resource.resource == "componentstatuses" && group.empty? && route.subresource.nil?
          return %w[GET HEAD].include?(request.method) ? component_status_response(request, route) : nil
        end
        if route.subresource == "token" && resource.resource == "serviceaccounts" && group.empty?
          return request.method == "POST" ? token_request_response(request, route) : nil
        end
        return nil unless route.collection && route.subresource.nil?

        case [group, resource.resource]
        when ["authentication.k8s.io", "tokenreviews"]
          request.method == "POST" ? token_review_response(request, route) : nil
        when ["authentication.k8s.io", "selfsubjectreviews"]
          request.method == "POST" ? self_subject_review_response(request, route) : nil
        when ["authorization.k8s.io", "selfsubjectrulesreviews"]
          request.method == "POST" ? self_subject_rules_review_response(request, route) : nil
        when ["authorization.k8s.io", "subjectaccessreviews"], ["authorization.k8s.io", "selfsubjectaccessreviews"],
             ["authorization.k8s.io", "localsubjectaccessreviews"]
          request.method == "POST" ? subject_access_review_response(request, route) : nil
        end
      end

      # The object a review handler receives: decoded, defaulted and validated
      # exactly like a stored object, without the storage metadata pass.
      def review_request_object(request, route)
        object = normalize_object(request, route)
        object = apply_schema(route.resource, object, operation: :create)
        validate_object!(route.resource, object)
        object
      end

      def review_response_object(request, route, object, sections)
        result = {"kind" => route.resource.kind, "apiVersion" => route.resource.api_version}
        metadata = object["metadata"].is_a?(Hash) ? deep_copy(object["metadata"]) : {}
        managed_fields = record_managed_update(request, route, nil, object)
        managed_fields.nil? ? metadata.delete("managedFields") : metadata["managedFields"] = managed_fields
        result["metadata"] = metadata
        sections.each { |key, value| result[key] = value }
        result
      end

      def request_identity(request)
        identity = authenticate_request(request).identity
        identity.nil? ? {"username" => "system:anonymous", "groups" => %w[system:unauthenticated]} : identity
      end

      def user_info(identity)
        # An authenticator returns an AuthenticationResult wrapping the
        # UserInfo, not the UserInfo itself.  Reading username/uid/groups off
        # the wrapper found nothing, so TokenReview answered
        # `authenticated: true` with an EMPTY user -- no username, no groups.
        # Upstream's TokenReview status carries the full UserInfo
        # (pkg/registry/authentication/tokenreview/storage.go), which is what
        # [sig-auth] ServiceAccounts "should mount an API token into pods"
        # checks at service_accounts.go:132, and what every authenticating
        # webhook client relies on.
        identity = identity.user if identity.respond_to?(:user) && !identity.is_a?(Hash)
        read = lambda do |name|
          if identity.is_a?(Hash)
            identity[name] || identity[name.to_sym]
          elsif identity.respond_to?(name)
            identity.public_send(name)
          end
        end
        info = {}
        username = read.call("username") || read.call("name")
        info["username"] = username.to_s unless username.to_s.empty?
        uid = read.call("uid")
        info["uid"] = uid.to_s unless uid.to_s.empty?
        groups = Array(read.call("groups")).map(&:to_s)
        info["groups"] = groups unless groups.empty?
        extra = read.call("extra")
        info["extra"] = stringify_keys(extra) if extra.is_a?(Hash) && !extra.empty?
        info
      end

      # pkg/registry/authentication/tokenreview/storage.go: the handler rejects
      # an empty token before any schema validation of the request object.
      def token_review_response(request, route)
        raw = request_body(request)
        raw_token = raw.is_a?(Hash) ? stringify_keys(raw).dig("spec", "token").to_s : ""
        raise Status::BadRequest.new("token is required for TokenReview in authentication") if raw_token.empty?

        object = review_request_object(request, route)
        spec = object["spec"].is_a?(Hash) ? object["spec"] : {}
        token = spec["token"].to_s

        identity = authenticate_token(token)
        status = if identity
                   requested = Array(spec["audiences"]).map(&:to_s)
                   matched = identity.respond_to?(:audiences) ? Array(identity.audiences).map(&:to_s) : []
                   audiences = if !matched.empty?
                                 requested.empty? ? matched : (requested & matched)
                               elsif requested.empty?
                                 @api_audiences.dup
                               else
                                 requested & @api_audiences
                               end
                   {"authenticated" => true, "user" => user_info(identity), "audiences" => audiences}
                 else
                   {"user" => {}, "error" => "invalid bearer token"}
                 end
        json_response(review_response_object(request, route, object, "spec" => deep_copy(spec), "status" => status), status: 201)
      end

      def authenticate_token(token)
        identity = identity_resolver_authenticate(token)
        return identity if identity

        # The ServiceAccount authenticator lives in the security pipeline, not
        # in @identity_resolver (which is cert-based); TokenReview must reach it.
        authenticator = @security.respond_to?(:authenticator) ? @security.authenticator : nil
        return nil unless authenticator.respond_to?(:authenticate_token)

        authenticator.authenticate_token(token, @api_audiences)
      rescue StandardError
        nil
      end

      def identity_resolver_authenticate(token)
        return nil unless @identity_resolver.respond_to?(:authenticate_token)

        if @identity_resolver.method(:authenticate_token).arity == 1
          @identity_resolver.authenticate_token(token)
        else
          @identity_resolver.authenticate_token(token, @api_audiences)
        end
      rescue StandardError
        nil
      end

      # pkg/registry/authentication/selfsubjectreview/rest.go
      def self_subject_review_response(request, route)
        object = review_request_object(request, route)
        identity = request_identity(request)
        response = review_response_object(request, route, object, "status" => {"userInfo" => user_info(identity)})
        response["metadata"]["creationTimestamp"] = @clock.call.utc.iso8601
        json_response(response, status: 201)
      end

      # pkg/registry/authorization/selfsubjectrulesreview/rest.go with the
      # AlwaysAllow authorization mode (every verb on every resource and path).
      def self_subject_rules_review_response(request, route)
        object = review_request_object(request, route)
        namespace = object.dig("spec", "namespace").to_s
        raise Status::BadRequest.new("no namespace on request") if namespace.empty?

        rules = if @authorizer.respond_to?(:rules_for)
                  @authorizer.rules_for(request_identity(request), namespace)
                else
                  {"resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"]}],
                   "nonResourceRules" => [{"verbs" => ["*"], "nonResourceURLs" => ["*"]}], "incomplete" => false}
                end
        json_response({"kind" => route.resource.kind, "apiVersion" => route.resource.api_version,
                       "metadata" => {}, "spec" => {}, "status" => rules}, status: 201)
      end

      # pkg/registry/authorization/{subjectaccessreview,selfsubjectaccessreview,localsubjectaccessreview}
      def subject_access_review_response(request, route)
        object = review_request_object(request, route)
        decision = if @authorizer.respond_to?(:authorize)
                     @authorizer.authorize(request_identity(request), object["spec"])
                   else
                     {"allowed" => true}
                   end
        response = review_response_object(request, route, object, "spec" => deep_copy(object["spec"] || {}), "status" => decision)
        json_response(response, status: 201)
      end

      # pkg/registry/core/serviceaccount/storage/token.go: TokenRequest on the
      # serviceaccounts/token subresource.  The service account must exist,
      # a bound object must exist with the given UID, and the issuer signs a
      # bound token whose expiration is returned in status.
      def token_request_response(request, route)
        raise Status::NotFound.new("the server could not find the requested resource") if @service_account_issuer.nil?

        namespace = storage_namespace(route, operation: :get)
        account = @store.get(resource: route.resource, namespace: namespace, name: route.name)
        body = request_body(request)
        raise Status::BadRequest.new("request body must be a TokenRequest") unless body.is_a?(Hash) && (body["kind"].nil? || body["kind"] == "TokenRequest")

        # TokenRequestServiceAccountUIDValidation (Beta, on): a request for
        # another incarnation of the ServiceAccount is a conflict.
        requested_uid = body.dig("metadata", "uid").to_s
        account_uid = metadata_value(account, "uid").to_s
        if !requested_uid.empty? && requested_uid != account_uid
          raise Status::Conflict.new(%(Operation cannot be fulfilled on TokenRequest.authentication.k8s.io "#{route.name}": ) +
                                     "the UID in the token request (#{requested_uid}) does not match the UID of the service account (#{account_uid})")
        end

        spec = body["spec"] || {}
        bound = spec["boundObjectRef"]
        bound_object = nil
        if bound.is_a?(Hash) && !bound["name"].to_s.empty?
          kind = bound["kind"].to_s
          raise Status::BadRequest.new("cannot bind token to object of type #{kind}") unless %w[Pod Secret Node].include?(kind)

          bound_resource = @registry.find_gvk(group: "", version: "v1", kind: kind)
          object = begin
            @store.get(resource: bound_resource, namespace: kind == "Node" ? :cluster : namespace, name: bound["name"])
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("#{kind.downcase}s #{bound["name"].inspect} not found")
          end
          if bound["uid"] && !bound["uid"].to_s.empty? && metadata_value(object, "uid").to_s != bound["uid"].to_s
            raise Status::Conflict.new("the UID in the bound object reference (#{bound["uid"]}) does not match the UID in record. The object might have been deleted and then recreated")
          end
          bound_object = {"kind" => kind, "name" => bound["name"], "uid" => metadata_value(object, "uid").to_s}
          # A pod-bound token also names the pod's node, with its UID when the
          # node still exists (pkg/registry/core/serviceaccount/storage/
          # token.go), so TokenReview can report authentication.kubernetes.io/
          # node-name and node-uid.
          node_name = kind == "Pod" ? object.dig("spec", "nodeName").to_s : ""
          unless node_name.empty?
            node = begin
              @store.get(resource: @registry.find_gvk(group: "", version: "v1", kind: "Node"), namespace: :cluster, name: node_name)
            rescue MemoryStore::NotFound
              nil
            end
            bound_object["node"] = {"name" => node_name, "uid" => node && metadata_value(node, "uid").to_s}.compact
          end
        end
        begin
          token, expiration = @service_account_issuer.issue(namespace: namespace, service_account_name: route.name,
                                                            service_account_uid: metadata_value(account, "uid").to_s,
                                                            audiences: spec["audiences"], expiration_seconds: spec["expirationSeconds"],
                                                            bound_object: bound_object)
        rescue ArgumentError => error
          raise Status::Invalid.new("TokenRequest is invalid: #{error.message}")
        end
        response = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest",
                    "metadata" => {"name" => route.name, "namespace" => namespace, "creationTimestamp" => @clock.call.utc.iso8601},
                    "spec" => {"audiences" => Array(spec["audiences"]).empty? ? @service_account_issuer.api_audiences : Array(spec["audiences"]),
                               "expirationSeconds" => spec["expirationSeconds"] || Security::Authentication::ServiceAccount::DEFAULT_EXPIRATION_SECONDS,
                               "boundObjectRef" => bound_object && {"kind" => bound_object["kind"], "apiVersion" => "v1", "name" => bound_object["name"], "uid" => bound_object["uid"]}}.compact,
                    "status" => {"token" => token, "expirationTimestamp" => expiration.iso8601}}
        json_response(response, status: 201)
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("serviceaccounts #{route.name.inspect} not found", details: resource_details(route))
      end

      # OpenID discovery for service account tokens
      # (pkg/serviceaccount/openidmetadata.go).
      def openid_response(_request, route)
        raise Status::NotFound.new("the requested API path #{route.path.inspect} was not found") if @service_account_issuer.nil?

        document = route.path == "/openid/v1/jwks" ? @service_account_issuer.jwks : @service_account_issuer.openid_configuration
        content_type = route.path == "/openid/v1/jwks" ? "application/jwk-set+json" : "application/json"
        Response.new(status: 200, headers: {"content-type" => content_type, "cache-control" => "public, max-age=3600"}, body: JSON.generate(document))
      end

      # pkg/registry/core/{pod,service,node}/rest: the `proxy` subresource
      # relays a request to a Pod, a Service endpoint or a node's kubelet.
      # The name may carry a scheme and a port ("https:name:8443"), and every
      # path segment after `proxy` belongs to the proxied request.
      PROXY_HOP_HEADERS = %w[connection keep-alive proxy-authenticate proxy-authorization te trailer
                             transfer-encoding upgrade host content-length authorization].freeze
      PROXY_TIMEOUT_SECONDS = Float(ENV.fetch("RUBERNETES_PROXY_TIMEOUT", "30"))
      PROXY_MAX_BODY_BYTES = 32 * 1024 * 1024

      def proxy_response(request, route)
        # apimachinery's proxy handler answers GET/HEAD on the bare proxy root
        # (".../proxy", no trailing slash) with 301 to ".../proxy/" so the
        # backend's relative links resolve; "[sig-network] Proxy version v1 A
        # set of valid responses" checks that 301 for pods and services.
        # request.path has had its trailing slash stripped, so it says "/proxy"
        # for both ".../proxy" and ".../proxy/" and redirecting on it sent
        # ".../proxy/" to itself for ever.  The client's own spelling decides.
        raw_path = (request.respond_to?(:raw_path) ? request.raw_path : request.path).to_s.split("?", 2).first.to_s
        if %w[GET HEAD].include?(request.method.to_s) && raw_path.end_with?("/proxy")
          location = "#{raw_path}/"
          query = request.respond_to?(:query) && request.query.is_a?(Hash) ? request.query : {}
          location = "#{location}?#{URI.encode_www_form(query.flat_map { |key, value| Array(value).map { |item| [key.to_s, item.to_s] } })}" unless query.empty?
          return Response.new(status: 301, headers: {"location" => location, "content-type" => "text/html; charset=utf-8"},
                              body: "<a href=\"#{location}\">Moved Permanently</a>.\n\n")
        end
        scheme, name, port = split_scheme_name_port(route.name)
        target = case route.resource.resource
                 when "pods" then pod_proxy_target(route, name, port)
                 when "services" then service_proxy_target(route, name, port)
                 else node_proxy_target(route, name, port)
                 end
        scheme ||= target[:scheme]
        uri = URI("#{scheme}://#{format_proxy_host(target.fetch(:host))}:#{target.fetch(:port)}")
        uri.path = "/#{route.subresource_path.to_s.delete_prefix("/")}"
        uri.path = "/" if uri.path == "/"
        query = request.respond_to?(:query) && request.query.is_a?(Hash) ? request.query.reject { |key, _| key == "path" } : {}
        uri.query = URI.encode_www_form(query.flat_map { |key, value| Array(value).map { |item| [key.to_s, item.to_s] } }) unless query.empty?
        perform_proxy(request, uri, prefix: proxy_path_prefix(request, route), tls: target[:tls])
      end

      # Everything in the request path up to and including "/proxy": the prefix
      # the proxied server's own absolute links have to be rewritten with.  It
      # is the request path minus the part that was forwarded, because a
      # namespace may itself be called "proxy" and searching the path for the
      # word would find that one.
      def proxy_path_prefix(request, route)
        path = request.path.to_s.split("?", 2).first.to_s
        remainder = route.subresource_path.to_s.delete_prefix("/")
        unless remainder.empty?
          suffix = "/#{remainder}"
          path = path[0, path.length - suffix.length] if path.end_with?(suffix)
        end
        path = path.chomp("/") if path.length > 1
        path
      end

      def split_scheme_name_port(value)
        parts = value.to_s.split(":")
        case parts.length
        when 1 then [nil, parts[0], nil]
        when 2
          # "name:port" or "scheme:name"; a numeric or named port is the
          # second form only when it is not a known scheme.
          %w[http https].include?(parts[0]) ? [parts[0], parts[1], nil] : [nil, parts[0], parts[1]]
        else [parts[0], parts[1], parts[2]]
        end
      end

      def format_proxy_host(host)
        host.to_s.include?(":") ? "[#{host}]" : host.to_s
      end

      def pod_proxy_target(route, name, port)
        pod = begin
          @store.get(resource: route.resource, namespace: storage_namespace(route, operation: :get), name: name)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("pods #{name.inspect} not found", details: resource_details(route))
        end
        address = pod.dig("status", "podIP").to_s
        raise Status::ServiceUnavailable.new("pod #{name.inspect} has no IP address") if address.empty?

        {host: address, port: resolve_pod_port(pod, port), scheme: "http"}
      end

      def resolve_pod_port(pod, port)
        if port.nil? || port.to_s.empty?
          # pod.ResourceLocation: no port means the first port the first
          # container that declares one exposes, and only then plain :80.
          first = Array(pod.dig("spec", "containers")).lazy.flat_map { |container| Array(container["ports"]) }.first
          return first && first["containerPort"] ? Integer(first["containerPort"]) : 80
        end
        return Integer(port) if port.to_s.match?(/\A\d+\z/)

        containers = Array(pod.dig("spec", "containers")) + Array(pod.dig("spec", "initContainers"))
        entry = containers.flat_map { |container| Array(container["ports"]) }.find { |value| value["name"].to_s == port.to_s }
        raise Status::BadRequest.new("pod port #{port.inspect} was not found") if entry.nil?

        Integer(entry["containerPort"])
      end

      # A Service proxies to one of its ready endpoints, not to the ClusterIP:
      # the API server has no kube-proxy datapath of its own.
      # [address, port] of one ready endpoint behind a Service port, for
      # callers (conversion/admission webhooks) that must dial the endpoint
      # directly: the API server host has no cluster DNS for *.svc names.
      public def service_endpoint_address(namespace, name, port)
        descriptor = @registry.find_gvr(group: "", version: "v1", resource: "services")
        return nil if descriptor.nil?

        service = @store.get(resource: descriptor, namespace: namespace, name: name)
        endpoint = ready_endpoint_for(namespace, name, select_service_port(service, port))
        endpoint && [endpoint.fetch(:address), endpoint.fetch(:port)]
      rescue StandardError
        nil
      end

      private def service_proxy_target(route, name, port)
        namespace = storage_namespace(route, operation: :get)
        service = begin
          @store.get(resource: route.resource, namespace: namespace, name: name)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("services #{name.inspect} not found", details: resource_details(route))
        end
        service_port = select_service_port(service, port)
        endpoint = ready_endpoint_for(namespace, name, service_port)
        raise Status::ServiceUnavailable.new("no endpoints available for service #{name.inspect}") if endpoint.nil?

        {host: endpoint.fetch(:address), port: endpoint.fetch(:port), scheme: endpoint.fetch(:scheme)}
      end

      def select_service_port(service, port)
        ports = Array(service.dig("spec", "ports"))
        return ports.first || {} if port.nil? || port.to_s.empty?

        match = if port.to_s.match?(/\A\d+\z/)
                  ports.find { |entry| entry["port"].to_i == port.to_i }
                else
                  ports.find { |entry| entry["name"].to_s == port.to_s }
                end
        raise Status::BadRequest.new("service port #{port.inspect} was not found") if match.nil?

        match
      end

      def ready_endpoint_for(namespace, service_name, service_port)
        descriptor = @registry.find_gvr(group: "discovery.k8s.io", version: "v1", resource: "endpointslices")
        return nil if descriptor.nil?

        # StoreAdapter#list requires `selectors:`; without it the call raised
        # ArgumentError, every Service resolved to "no endpoints", and every
        # webhook fell back to a *.svc name the host cannot resolve.
        slices = @store.list(resource: descriptor, namespace: namespace, selectors: nil)
        items = if slices.respond_to?(:items)
                  Array(slices.items)
                elsif slices.is_a?(Hash)
                  Array(slices["items"])
                else
                  Array(slices)
                end
        items = items.select { |slice| slice.dig("metadata", "labels", "kubernetes.io/service-name").to_s == service_name.to_s }
        port_name = service_port["name"].to_s
        items.each do |slice|
          numbers = Array(slice["ports"]).select { |entry| port_name.empty? || entry["name"].to_s == port_name }
                                         .filter_map { |entry| entry["port"] }
          next if numbers.empty?

          address = Array(slice["endpoints"]).find { |endpoint| endpoint.dig("conditions", "ready") != false }
          next if address.nil?

          value = Array(address["addresses"]).first
          next if value.to_s.empty?

          return {address: value, port: Integer(numbers.first), scheme: "http"}
        end
        nil
      end

      def node_proxy_target(route, name, port)
        node = begin
          @store.get(resource: route.resource, namespace: :cluster, name: name)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("nodes #{name.inspect} not found", details: resource_details(route))
        end
        # The node proxy dials the kubelet where exec and logs do: the
        # agent-published streaming address wins over status.addresses, which
        # may name an interface the kubelet does not listen on.
        announced = node.dig("metadata", "annotations", NodeEndpointResolver::STREAMING_ADDRESS_ANNOTATION).to_s
        addresses = Array(node.dig("status", "addresses"))
        entry = %w[InternalIP ExternalIP Hostname].filter_map do |type|
          addresses.find { |address| address["type"] == type && !address["address"].to_s.empty? }
        end.first
        entry = {"address" => announced} unless announced.empty?
        raise Status::ServiceUnavailable.new("node #{name.inspect} has no address") if entry.nil?

        # "Port" is v1.DaemonEndpoint's actual JSON field name; the lowercase
        # spelling is accepted for a Node written by an older agent.
        endpoint = node.dig("status", "daemonEndpoints", "kubeletEndpoint")
        endpoint = {} unless endpoint.is_a?(Hash)
        advertised = (endpoint["Port"] || endpoint["port"]).to_i
        default_port = advertised.positive? ? advertised : 10_250
        # A request for the well-known kubelet port reaches the port this
        # kubelet advertises: several agents share one host here, so none of
        # them can own 10250, and clients (the e2e framework's node dumps)
        # hardcode it.
        requested = port.to_s.empty? || port.to_s == "10250" ? default_port : port
        # The same scheme exec and logs dial the kubelet with.
        scheme = @node_resolver.respond_to?(:scheme) ? @node_resolver.scheme.to_s : "https"
        {host: entry["address"], port: Integer(requested), scheme: scheme,
         tls: @node_resolver.respond_to?(:tls) ? @node_resolver.tls : nil}.compact
      end

      # The exchange is written directly on a socket rather than through
      # Net::HTTP: the proxy must forward one request verbatim, including
      # methods and headers a higher-level client would rewrite, and the
      # upgrade path already speaks to node endpoints this way.
      def perform_proxy(request, uri, prefix: "", tls: nil)
        socket = open_proxy_socket(uri, tls: tls)
        begin
          socket.write(proxy_request_bytes(request, uri))
          socket.flush if socket.respond_to?(:flush)
          status, headers, leftover = read_proxy_head(socket)
          body = read_proxy_body(socket, headers, leftover)
          forwarded = {}
          headers.each do |name, values|
            next if PROXY_HOP_HEADERS.include?(name)

            forwarded[name] = values.length == 1 ? values.first : values
          end
          forwarded["content-type"] ||= "application/octet-stream"
          forwarded["location"] = rewrite_proxy_url(forwarded["location"], prefix) if forwarded["location"]
          body = rewrite_proxy_html(body, forwarded["content-type"], prefix)
          forwarded["content-length"] = body.bytesize.to_s if forwarded.key?("content-length")
          Response.new(status: status, headers: forwarded, body: body, stream: false)
        ensure
          begin
            socket.close unless socket.closed?
          rescue IOError, SystemCallError
            nil
          end
        end
      rescue Status::Error
        raise
      rescue Errno::ETIMEDOUT, Timeout::Error
        raise Status::ServiceUnavailable.new("proxy request to #{uri} timed out")
      rescue SystemCallError, IOError, OpenSSL::SSL::SSLError, EOFError => error
        raise Status::ServiceUnavailable.new("proxy request to #{uri} failed: #{error.message}")
      end

      # The API server rewrites the absolute links a proxied server returns so
      # that a client following them stays inside the proxy
      # (apimachinery util/proxy/transport.go Transport.RoundTrip: "rewrite
      # URLs in the body of the response").  A server behind
      # /api/v1/namespaces/ns/pods/name/proxy has no idea it is being proxied
      # and answers with href="/rewriteme"; without the rewrite that link
      # points at the API server's own root, which is what "[sig-network] Proxy
      # version v1 should proxy through a service and a pod" checks.
      #
      # Only the attributes that carry a URL are touched, and only in a
      # text/html response, exactly as upstream's atomsToAttrs table does.
      PROXY_REWRITE_ATTRIBUTES = {
        "a" => %w[href], "applet" => %w[codebase], "area" => %w[href], "audio" => %w[src],
        "base" => %w[href], "blockquote" => %w[cite], "body" => %w[background],
        "button" => %w[formaction], "command" => %w[icon], "del" => %w[cite], "embed" => %w[src],
        "form" => %w[action], "frame" => %w[longdesc src], "head" => %w[profile],
        "html" => %w[manifest], "iframe" => %w[longdesc src], "img" => %w[longdesc src usemap],
        "input" => %w[src usemap formaction], "ins" => %w[cite], "link" => %w[href],
        "object" => %w[classid codebase data usemap], "q" => %w[cite], "script" => %w[src],
        "source" => %w[src], "video" => %w[poster src]
      }.freeze

      def rewrite_proxy_html(body, content_type, prefix)
        return body if prefix.to_s.empty? || body.nil? || body.empty?
        return body unless content_type.to_s.split(";", 2).first.to_s.strip.downcase == "text/html"

        text = body.dup.force_encoding(Encoding::UTF_8)
        return body unless text.valid_encoding?

        text.gsub(/<\s*([A-Za-z][A-Za-z0-9]*)((?:\s+[^<>]*?)?)(\/?)>/m) do
          tag = Regexp.last_match(1)
          attributes = Regexp.last_match(2)
          closing = Regexp.last_match(3)
          names = PROXY_REWRITE_ATTRIBUTES[tag.downcase]
          next Regexp.last_match(0) if names.nil? || attributes.empty?

          rewritten = attributes.gsub(/(\s)([A-Za-z-]+)(\s*=\s*)(["'])(.*?)\4/m) do
            space = Regexp.last_match(1)
            attribute = Regexp.last_match(2)
            equals = Regexp.last_match(3)
            quote = Regexp.last_match(4)
            value = Regexp.last_match(5)
            next Regexp.last_match(0) unless names.include?(attribute.downcase)

            "#{space}#{attribute}#{equals}#{quote}#{rewrite_proxy_url(value, prefix)}#{quote}"
          end
          "<#{tag}#{rewritten}#{closing}>"
        end.b
      end

      # transport.go rewriteURL: only a same-host, absolute path is rewritten.
      # A relative link already resolves against the proxied path, and a link
      # to another host is not ours to redirect.
      def rewrite_proxy_url(value, prefix)
        target = value.to_s
        return target if target.empty? || prefix.to_s.empty?

        parsed = begin
          URI.parse(target)
        rescue URI::InvalidURIError
          return target
        end
        return target unless parsed.host.nil? || parsed.host.empty?
        return target unless parsed.path.to_s.start_with?("/")
        return target if parsed.path.to_s == prefix || parsed.path.to_s.start_with?("#{prefix}/")

        trailing = parsed.path.end_with?("/") && parsed.path != "/"
        joined = File.join(prefix, parsed.path)
        joined = "#{joined}/" if trailing && !joined.end_with?("/")
        parsed.path = joined
        parsed.to_s
      end

      # +tls+: the kubelet client credentials for a node proxy.
      def open_proxy_socket(uri, tls: nil)
        # URI#host keeps the brackets of an IPv6 literal ("[fd00::2]"), which
        # getaddrinfo does not resolve; URI#hostname is the bare address.
        # Every pods/services/nodes proxy to an IPv6 target answered 500
        # ("[sig-network] Proxy version v1 A set of valid responses ...").
        tcp = Socket.tcp(uri.hostname, uri.port, connect_timeout: PROXY_TIMEOUT_SECONDS)
        tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        return tcp unless uri.scheme == "https"

        ssl = OpenSSL::SSL::SSLSocket.new(tcp, NodeEndpointResolver::KubeletClientTLS.context(tls))
        ssl.hostname = uri.hostname unless uri.hostname.to_s.match?(/\A[\d.:]+\z/)
        ssl.sync_close = true
        ssl.connect
        ssl
      end

      def proxy_request_bytes(request, uri)
        lines = ["#{request.method} #{uri.request_uri} HTTP/1.1", "Host: #{uri.host}:#{uri.port}"]
        request.headers.each do |name, _value|
          key = name.to_s.downcase
          next if PROXY_HOP_HEADERS.include?(key)

          values = request.headers.respond_to?(:raw_values) ? request.headers.raw_values(name) : [request.header(name)]
          values.each { |value| lines << "#{name}: #{value}" }
        end
        body = request_raw_body(request).to_s
        lines << "Content-Length: #{body.bytesize}"
        lines << "Connection: close"
        "#{lines.join("\r\n")}\r\n\r\n#{body}".b
      end

      PROXY_MAX_HEAD_BYTES = 64 * 1024

      def read_proxy_head(socket)
        buffer = "".b
        until (index = buffer.index("\r\n\r\n"))
          chunk = socket.readpartial(4096)
          buffer << chunk
          raise Status::ServiceUnavailable.new("proxied response head is too large") if buffer.bytesize > PROXY_MAX_HEAD_BYTES
        end
        head = buffer.byteslice(0, index)
        leftover = buffer.byteslice(index + 4..) || "".b
        lines = head.split("\r\n")
        status = lines.shift.to_s.split(" ", 3)[1].to_i
        headers = Hash.new { |hash, key| hash[key] = [] }
        lines.each do |line|
          name, _, value = line.partition(":")
          next if value.empty? && !line.include?(":")

          headers[name.strip.downcase] << value.strip
        end
        [status, headers, leftover]
      end

      def read_proxy_body(socket, headers, leftover)
        length = headers["content-length"].first
        body = leftover.dup
        if length
          limit = Integer(length)
          raise Status::ServiceUnavailable.new("proxied response exceeds #{PROXY_MAX_BODY_BYTES} bytes") if limit > PROXY_MAX_BODY_BYTES

          while body.bytesize < limit
            chunk = socket.read(limit - body.bytesize)
            break if chunk.nil? || chunk.empty?

            body << chunk
          end
        else
          while (chunk = socket.read(65_536))
            body << chunk
            raise Status::ServiceUnavailable.new("proxied response exceeds #{PROXY_MAX_BODY_BYTES} bytes") if body.bytesize > PROXY_MAX_BODY_BYTES
          end
          body = decode_chunked_body(body) if headers["transfer-encoding"].any? { |value| value.downcase.include?("chunked") }
        end
        body
      rescue EOFError
        body || "".b
      end

      def decode_chunked_body(raw)
        result = "".b
        offset = 0
        loop do
          line_end = raw.index("\r\n", offset)
          break if line_end.nil?

          size = raw.byteslice(offset, line_end - offset).split(";").first.to_s.strip.to_i(16)
          break if size.zero?

          result << raw.byteslice(line_end + 2, size).to_s
          offset = line_end + 2 + size + 2
        end
        result
      end

      def request_raw_body(request)
        value = request.respond_to?(:body) ? request.body : nil
        return nil if value.nil?

        value.is_a?(String) ? value : value.to_s
      end

      # pkg/registry/core/pod/storage/storage.go BindingREST: the scheduler
      # assigns a node by POSTing a Binding; the pod's nodeName is set once
      # (a second binding conflicts) and PodScheduled=True is recorded.
      def binding_response(request, route)
        raise Status::MethodNotAllowed.new("verb #{request.method} is not supported for pods/binding") unless request.method == "POST"

        body = request_body(request)
        raise Status::BadRequest.new("request body must be a JSON object") unless body.is_a?(Hash)

        object = stringify_keys(body)
        kind = object["kind"].to_s
        raise Status::BadRequest.new("expected a Binding, got #{kind.inspect}") unless kind.empty? || kind == "Binding"

        name = object.dig("metadata", "name").to_s
        raise Status::BadRequest.new("name in URL does not match name in Binding object") if !name.empty? && name != route.name.to_s

        target = object["target"]
        raise Status::BadRequest.new("target is required") unless target.is_a?(Hash)

        target_kind = target["kind"].to_s
        raise Status::BadRequest.new("target.kind #{target_kind.inspect} is not supported (expected Node)") unless target_kind.empty? || target_kind == "Node"

        node_name = target["name"].to_s
        raise Status::BadRequest.new("target.name is required") if node_name.empty?

        namespace = storage_namespace(route, operation: :update)
        existing = begin
          @store.get(resource: route.resource, namespace: namespace, name: route.name)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
        end
        assigned = existing.dig("spec", "nodeName").to_s
        unless assigned.empty?
          raise Status::Conflict.new("Operation cannot be fulfilled on pods/binding #{route.name.to_s.inspect}: " \
                                     "pod #{route.name} is already assigned to node #{assigned.inspect}")
        end

        candidate = deep_copy(existing)
        candidate["spec"] ||= {}
        candidate["spec"]["nodeName"] = node_name
        annotations = object.dig("metadata", "annotations")
        if annotations.is_a?(Hash) && !annotations.empty?
          candidate["metadata"]["annotations"] = (candidate["metadata"]["annotations"] || {}).merge(stringify_keys(annotations))
        end
        # setPodNodeAndMetadata: the Binding's labels (PodTopologyLabels puts
        # the Node's zone and region there) overwrite the Pod's.
        labels = object.dig("metadata", "labels")
        if labels.is_a?(Hash) && !labels.empty?
          candidate["metadata"]["labels"] = (candidate["metadata"]["labels"] || {}).merge(stringify_keys(labels))
        end
        candidate["status"] ||= {}
        # ClearingNominatedNodeNameAfterBinding (Beta, on).
        candidate["status"].delete("nominatedNodeName")
        now = @clock.call.utc.iso8601
        conditions = Array(candidate["status"]["conditions"]).reject { |condition| condition["type"] == "PodScheduled" }
        conditions << {"type" => "PodScheduled", "status" => "True", "lastProbeTime" => nil, "lastTransitionTime" => now}
        candidate["status"]["conditions"] = conditions
        updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                object: candidate, resource_version: metadata_value(existing, "resourceVersion"))
        after_commit(route.resource, updated)
        json_response({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Success", "code" => 201},
                      status: 201)
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
      end

      # pkg/registry/core/pod/storage/eviction.go: an Eviction deletes the pod
      # through the delete options it carries once those options validate.
      def eviction_response(request, route)
        raise Status::MethodNotAllowed.new("verb #{request.method} is not supported for pods/eviction") unless request.method == "POST"

        body = request_body(request)
        raise Status::BadRequest.new("request body must be a JSON object") unless body.is_a?(Hash)

        object = stringify_keys(body)
        kind = object["kind"].to_s
        raise Status::BadRequest.new("expected an Eviction, got #{kind.inspect}") unless kind.empty? || kind == "Eviction"

        name = object.dig("metadata", "name").to_s
        raise Status::BadRequest.new("name in URL does not match name in Eviction object") if !name.empty? && name != route.name.to_s

        delete_options = object["deleteOptions"]
        if delete_options.is_a?(Hash)
          issues = Schema::KubernetesValidator.delete_options_errors(delete_options)
          unless issues.empty?
            causes = issues.map { |issue| delete_options_cause(delete_options, issue) }
            rendered = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }
            summary = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
            raise Status::Invalid.new("DeleteOptions.meta.k8s.io \"\" is invalid: #{summary}",
                                      details: {"group" => "meta.k8s.io", "kind" => "DeleteOptions", "causes" => causes})
          end
        end
        namespace = storage_namespace(route, operation: :delete)
        existing = begin
          @store.get(resource: route.resource, namespace: namespace, name: route.name)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("pods #{route.name.to_s.inspect} not found", details: resource_details(route))
        end
        # An Eviction is checked against every PodDisruptionBudget that selects
        # the Pod: a budget with no disruptions left refuses it with 429
        # (pkg/registry/core/pod/storage/eviction.go:418-457), and a successful
        # eviction spends one disruption.  None of that existed, so eviction
        # was an unconditional delete and
        # "[sig-apps] DisruptionController should block an eviction until the
        # PDB is updated to allow it" could never pass.
        dry_run = delete_options.is_a?(Hash) && !Array(delete_options["dryRun"]).empty?
        check_disruption_budgets!(namespace, existing, dry_run: dry_run)
        # eviction.go addConditionAndDeletePod: a resourceVersion precondition
        # the CALLER set is checked against the Pod before the DisruptionTarget
        # condition is written and then moved to the version that write
        # produced; an eviction without one pins nothing.  Pinning the delete
        # to our own condition write's version instead made any writer that
        # slipped in between (the node publishing status for the Pod it had
        # just seen change) fail the eviction with "expected resourceVersion
        # N, current is N+1" ("DisruptionController should block an eviction
        # until the PDB is updated to allow it").
        caller_version = delete_options.is_a?(Hash) ? delete_options.dig("preconditions", "resourceVersion") : nil
        if caller_version && caller_version.to_s != metadata_value(existing, "resourceVersion").to_s
          raise Status::Conflict.new("the ResourceVersion in the precondition (#{caller_version}) does not match the ResourceVersion in record (#{metadata_value(existing, "resourceVersion")}). The object might have been modified")
        end
        existing = mark_evicted(route.resource, namespace, route.name, existing) unless dry_run
        pin_version = !caller_version.nil?
        if delete_options.is_a?(Hash) && Array(delete_options["dryRun"]).empty?
          if orphan_deletion?(delete_options)
            orphan_dependents(route.resource, namespace, existing)
          else
            cascade_delete_dependents(existing)
          end
          delete_one(route.resource, namespace, route.name, existing, pin_version: pin_version)
        elsif !delete_options.is_a?(Hash)
          delete_one(route.resource, namespace, route.name, existing, pin_version: false)
        end
        json_response({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Success", "code" => 201}, status: 201)
      end

      # eviction.go addConditionAndDeletePod: an evicted Pod is told that it is
      # going away because something evicted it, before it is deleted, so that
      # a controller can tell an involuntary disruption from the Pod's own
      # failure.  We deleted it silently, so a Job whose podFailurePolicy
      # ignores failures matching DisruptionTarget had nothing to match and
      # counted every eviction as a real failure ("[sig-apps] Job should allow
      # to use a pod failure policy to ignore failure matching on
      # DisruptionTarget condition").
      def mark_evicted(resource, namespace, name, existing)
        candidate = deep_copy(existing)
        candidate["status"] ||= {}
        conditions = Array(candidate["status"]["conditions"]).reject { |condition| condition["type"] == "DisruptionTarget" }
        conditions << {"type" => "DisruptionTarget", "status" => "True",
                       "reason" => "EvictionByEvictionAPI", "message" => "Eviction API: evicting",
                       "lastProbeTime" => nil, "lastTransitionTime" => @clock.call.utc.iso8601}
        candidate["status"]["conditions"] = conditions
        updated = @store.update(resource: resource, namespace: namespace, name: name, object: candidate,
                                resource_version: metadata_value(existing, "resourceVersion"))
        after_commit(resource, updated)
        updated
      rescue MemoryStore::NotFound, MemoryStore::Conflict
        # Something else is already changing this Pod; the eviction itself is
        # what matters and still has to go through.
        existing
      end

      PDB_RESOURCE = "poddisruptionbudgets"
      DISRUPTION_BUDGET_CAUSE = "DisruptionBudget"

      def check_disruption_budgets!(namespace, pod, dry_run: false)
        budgets = disruption_budgets_for(namespace, pod)
        return if budgets.empty?

        budgets.each do |budget|
          status = budget["status"] || {}
          name = budget.dig("metadata", "name")
          # eviction.go checkAndDecrement: only a budget the controller has
          # not caught up with yet carries a retry hint.  A budget that simply
          # allows no disruption answers 429 with retryAfterSeconds 0: client-go
          # retries a 429 that has Retry-After on its own, ten times, so the
          # 10 s hint we sent made every refused eviction take 100 s
          # ("DisruptionController should block an eviction until the PDB is
          # updated to allow it": 209 s against kube-apiserver's 8 s).
          if status["observedGeneration"].to_i < budget.dig("metadata", "generation").to_i
            raise Status::TooManyRequests.new(
              "Cannot evict pod as it would violate the pod's disruption budget.",
              retry_after_seconds: 10,
              details: {"causes" => [{"reason" => DISRUPTION_BUDGET_CAUSE,
                                      "message" => "The disruption budget #{name} is still being processed by the server."}]}
            )
          end
          allowed = status["disruptionsAllowed"].to_i
          if allowed.negative?
            raise Status::Forbidden.new("poddisruptionbudgets.policy #{name.to_s.inspect} is forbidden: pdb disruptions allowed is negative")
          end
          next if allowed.positive?

          message = if status["currentHealthy"].to_i <= status["desiredHealthy"].to_i
                      "The disruption budget #{name} needs #{status["desiredHealthy"].to_i} healthy pods " \
                        "and has #{status["currentHealthy"].to_i} currently"
                    else
                      "The disruption budget #{name} does not allow evicting pods currently"
                    end
          raise Status::TooManyRequests.new(
            "Cannot evict pod as it would violate the pod's disruption budget.",
            retry_after_seconds: 0,
            details: {"causes" => [{"reason" => DISRUPTION_BUDGET_CAUSE, "message" => message}]}
          )
        end
        return if dry_run

        budgets.each { |budget| spend_disruption(namespace, budget, pod) }
      end

      def disruption_budgets_for(namespace, pod)
        descriptor = disruption_budget_descriptor
        return [] if descriptor.nil?

        list = @store.list(resource: descriptor, namespace: namespace, selectors: nil)
        items = list.respond_to?(:items) ? list.items : Array(list.is_a?(Hash) ? list["items"] : list)
        labels = pod.dig("metadata", "labels") || {}
        items.select { |budget| budget_selects?(budget, labels) }
      rescue MemoryStore::Error, Status::Error
        []
      end

      # A PodDisruptionBudget with an empty selector matches every Pod in its
      # namespace (apis/policy/validation: an empty LabelSelector selects all),
      # which is exactly how the conformance specs write the "block everything"
      # budget.
      def budget_selects?(budget, labels)
        selector = budget.dig("spec", "selector")
        return false if selector.nil?

        match = selector["matchLabels"] || {}
        return false unless match.all? { |key, value| labels[key.to_s].to_s == value.to_s }

        Array(selector["matchExpressions"]).all? do |expression|
          key = expression["key"].to_s
          values = Array(expression["values"]).map(&:to_s)
          present = labels.key?(key)
          case expression["operator"].to_s
          when "In" then present && values.include?(labels[key].to_s)
          when "NotIn" then !present || !values.include?(labels[key].to_s)
          when "Exists" then present
          when "DoesNotExist" then !present
          else false
          end
        end
      end

      # The registry's own entry, not a synthesised descriptor: StoreAdapter
      # keys storage off it and requires `selectors:`.  Passing neither raised
      # ArgumentError into the blanket rescue around the lookup, so every Pod
      # looked unprotected and eviction never respected a budget.
      def disruption_budget_descriptor
        registry = @registry if defined?(@registry)
        found = registry.find_gvr(group: "policy", version: "v1", resource: "poddisruptionbudgets") if registry.respond_to?(:find_gvr)
        found || Controller::ResourceDescriptor.parse("PodDisruptionBudget")
      end

      def spend_disruption(namespace, budget, pod)
        descriptor = disruption_budget_descriptor
        return nil if descriptor.nil?

        updated = deep_copy(budget)
        status = updated["status"] ||= {}
        status["disruptionsAllowed"] = [status["disruptionsAllowed"].to_i - 1, 0].max
        disrupted = status["disruptedPods"] ||= {}
        disrupted[pod.dig("metadata", "name").to_s] = @clock.call.utc.iso8601(6)
        @store.update(resource: descriptor, namespace: namespace,
                      name: updated.dig("metadata", "name"), object: updated,
                      resource_version: metadata_value(budget, "resourceVersion"))
      rescue StandardError
        nil
      end

      # apimachinery field.Error rendering for a DeleteOptions issue: the
      # value is quoted like field.Error.ErrorBody and the reason follows
      # errors.NewInvalid's cause mapping.
      def delete_options_cause(options, issue)
        reason, includes_value = {
          required: ["FieldValueRequired", false], unsupported: ["FieldValueNotSupported", true],
          forbidden: ["FieldValueForbidden", false], duplicate: ["FieldValueDuplicate", true]
        }.fetch(issue.code, ["FieldValueInvalid", true])
        value = issue.path.reduce(options) { |current, segment| current.is_a?(Hash) ? current[segment.to_s] : nil }
        rendered_value = value.is_a?(String) ? value.inspect : JSON.generate(value)
        type = issue.kubernetes_error_type
        detail = issue.message.to_s
        message = includes_value ? "#{type}: #{rendered_value}" : type
        message = "#{message}: #{detail}" unless detail.empty?
        {"reason" => reason, "message" => message, "field" => issue.kubernetes_field}
      end

      # pkg/registry/core/componentstatus/rest.go: the fixed server inventory
      # of the legacy endpoint, probed the way kube-apiserver probes it.
      COMPONENT_STATUS_DEPRECATION_WARNING = "299 - \"v1 ComponentStatus is deprecated in v1.19+\"".freeze

      def component_status_response(_request, route)
        statuses = COMPONENT_STATUS_SERVERS.map { |server| component_status(server) }
        response = if route.collection
                     json_response({"kind" => "ComponentStatusList", "apiVersion" => "v1", "metadata" => {}, "items" => statuses})
                   else
                     status = statuses.find { |entry| entry.dig("metadata", "name") == route.name.to_s }
                     unless status
                       raise Status::NotFound.new("componentstatus #{route.name.to_s.inspect} not found",
                                                  details: {"name" => route.name.to_s, "kind" => "componentstatus"})
                     end
                     json_response({"kind" => "ComponentStatus", "apiVersion" => "v1"}.merge(status))
                   end
        # kube-apiserver marks the resource deprecated on every response.
        Response.new(status: response.status, headers: response.headers.merge("warning" => COMPONENT_STATUS_DEPRECATION_WARNING),
                     body: response.body)
      end

      def component_status(server)
        healthy, message, error = component_health(server)
        condition = {"type" => "Healthy", "status" => healthy ? "True" : "False", "message" => message}
        condition["error"] = error unless error.to_s.empty?
        {"metadata" => {"name" => server.fetch("name")}, "conditions" => [condition]}
      end

      def component_health(server)
        if @component_health_checker.respond_to?(:call)
          result = @component_health_checker.call(server)
          return result if result.is_a?(Array)
        end
        return [true, "ok", nil] if server.fetch("url").nil?

        uri = URI(server.fetch("url"))
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 2
        http.read_timeout = 2
        response = http.start { |connection| connection.get(uri.request_uri) }
        body = response.body.to_s
        if response.code.to_i == 200 && body.strip == "ok"
          [true, "ok", nil]
        else
          [false, "HTTP probe failed with statuscode: #{response.code}", body]
        end
      rescue Errno::ECONNREFUSED
        [false, "Get #{uri.to_s.inspect}: dial tcp #{uri.host}:#{uri.port}: connect: connection refused", nil]
      rescue StandardError => error
        [false, "Get #{uri.to_s.inspect}: #{error.message}", nil]
      end

      def get_response(route)
        namespace = storage_namespace(route, operation: :get)
        object = default_on_read(route.resource, @store.get(resource: route.resource, namespace: namespace, name: route.name))
        if route.subresource == "status"
          object = status_view(object)
        elsif route.subresource == "scale"
          object = scale_view(object, route.resource)
        end
        json_response(object)
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                   details: resource_details(route))
      end

      SYSTEM_NAMESPACES = %w[default kube-system kube-public kube-node-lease].freeze

      # ObjectMeta and core invariants beyond the OpenAPI schema; the Status
      # matches apierrors.NewInvalid.
      def validate_object!(resource, object, old: nil)
        kind = resource.kind
        causes = ObjectValidation.validate(kind, object, old: old, namespaced: resource.namespaced?)
        return object if causes.empty?

        name = metadata_value(object, "name")
        details = {
          "name" => name, "group" => resource.group.to_s, "kind" => kind,
          "causes" => causes.map { |cause| {"reason" => cause.reason, "message" => cause.message, "field" => cause.field} }
        }
        raise Status::Invalid.new(ObjectValidation.status_message(kind, name, causes), details: details)
      end

      # NamespaceLifecycle admission: a namespaced object cannot be created in
      # a namespace that does not exist, and the system namespaces always do.
      def ensure_namespace_exists!(resource, namespace)
        return unless @namespace_lifecycle
        return if resource.cluster_scoped? || namespace == :cluster || namespace == :all || namespace.to_s.empty?
        return if resource.kind == "Namespace"

        namespaces = namespaces_resource
        return if namespaces.nil?

        found = @store.get(resource: namespaces, namespace: :cluster, name: namespace.to_s)
        # plugin/pkg/admission/namespace/lifecycle: while a namespace is being
        # terminated no new content may be created inside it, or the namespace
        # controller races new objects forever and never finishes.
        return unless metadata_value(found, "deletionTimestamp")

        raise Status::Forbidden.new(
          "unable to create new content in namespace #{namespace} because it is being terminated",
          details: {"name" => namespace.to_s, "kind" => resource.kind.to_s.downcase,
                    "causes" => [{"reason" => "NamespaceTerminating", "message" => "namespace #{namespace} is being terminated",
                                  "field" => "metadata.namespace"}]}
        )
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("namespaces #{namespace.to_s.inspect} not found",
                                   details: {"name" => namespace.to_s, "kind" => "namespaces"})
      end

      def namespaces_resource
        return @namespaces_resource if defined?(@namespaces_resource)

        @namespaces_resource = @registry.find_gvr(group: "", version: "v1", resource: "namespaces")
      end

      SCALE_API_VERSION = "autoscaling/v1"

      # autoscaling/v1 Scale projection of a workload object, the form the
      # scale client (kubectl scale, HPA) reads and writes.  A custom
      # resource's comes from its CRD's specReplicasPath, statusReplicasPath
      # and labelSelectorPath (scaleFromCustomResource); +for_update+ marks
      # a spec replicas the object does not have with the sentinel instead
      # of failing.
      def scale_view(object, resource = nil, for_update: false)
        paths = custom_scale_paths(resource)
        metadata = object.fetch("metadata", {})
        identity = metadata.slice("name", "namespace", "uid", "resourceVersion", "creationTimestamp")
        return builtin_scale_view(object, identity) unless paths

        spec_path = paths[:spec_replicas].to_s
        spec, found = nested_int64(object, spec_path)
        unless found
          raise Status::InternalError.new("the spec replicas field #{ManagedFields::Value.go_quote(spec_path)} does not exist") unless for_update

          spec = INVALID_SPEC_REPLICAS
        end
        status, = nested_int64(object, paths[:status_replicas].to_s)
        selector = paths[:label_selector].to_s.empty? ? nil : object.dig(*split_replicas_path(paths[:label_selector]))
        scale_status = {"replicas" => status || 0}
        scale_status["selector"] = selector if selector.is_a?(String) && !selector.empty?
        {"kind" => "Scale", "apiVersion" => SCALE_API_VERSION, "metadata" => identity,
         "spec" => {"replicas" => spec || 0}, "status" => scale_status}
      end

      INVALID_SPEC_REPLICAS = -2_147_483_648

      def builtin_scale_view(object, identity)
        selector = object.dig("spec", "selector")
        status = {"replicas" => Integer(object.dig("status", "replicas") || 0)}
        selector_text = selector_string(selector)
        status["selector"] = selector_text unless selector_text.nil? || selector_text.empty?
        {
          "kind" => "Scale", "apiVersion" => SCALE_API_VERSION, "metadata" => identity,
          "spec" => {"replicas" => Integer(object.dig("spec", "replicas") || 0)},
          "status" => status
        }
      end

      def custom_scale_paths(resource)
        return nil unless resource.respond_to?(:custom?) && resource.custom?

        schema = resource.schema
        schema.respond_to?(:scale_paths) ? schema.scale_paths : nil
      end

      # splitReplicasPath.
      def split_replicas_path(path) = path.to_s.delete_prefix(".").split(".")

      # unstructured.NestedInt64: [value, found]; a value of another type is
      # an error.
      def nested_int64(object, path)
        parts = split_replicas_path(path)
        value = parts.reduce(object) do |node, key|
          return [nil, false] unless node.is_a?(Hash) && node.key?(key)

          node[key]
        end
        return [value, true] if value.is_a?(Integer)

        type = value.is_a?(Float) ? "float64" : value.class.name.downcase
        raise Status::InternalError.new("#{path} accessor error: #{value.inspect} is of the type #{type}, expected int64")
      end

      # The managedFields entries a Scale is seen with (ScaleHandler
      # ToSubresource), and the parent's paths per version.
      def scale_mappings(resource)
        paths = custom_scale_paths(resource)
        @field_managers.scale_mappings(resource, replicas_path: paths && split_replicas_path(paths[:spec_replicas]))
      end

      def live_scale(route, existing)
        view = scale_view(existing, route.resource, for_update: true)
        entries = begin
          ManagedFields::ScaleHandler.to_subresource(existing.dig("metadata", "managedFields"), scale_mappings(route.resource))
        rescue ManagedFields::Entries::DecodeError
          nil
        end
        view["metadata"] = view["metadata"].merge("managedFields" => entries) if entries
        view
      end

      # metav1.FormatLabelSelector / labels.FormatLabels for the selector
      # forms workloads use (LabelSelector, or the map ReplicationController
      # keeps in spec.selector).
      def selector_string(selector)
        return nil unless selector.is_a?(Hash)

        if selector.key?("matchLabels") || selector.key?("matchExpressions")
          requirements = (selector["matchLabels"] || {}).sort.map { |key, value| "#{key}=#{value}" }
          Array(selector["matchExpressions"]).each do |expression|
            key = expression["key"]
            values = Array(expression["values"]).sort.join(",")
            requirements << case expression["operator"]
                            when "In" then "#{key} in (#{values})"
                            when "NotIn" then "#{key} notin (#{values})"
                            when "Exists" then key.to_s
                            when "DoesNotExist" then "!#{key}"
                            else "#{key} #{expression["operator"]} (#{values})"
                            end
          end
          requirements.join(",")
        else
          selector.sort.map { |key, value| "#{key}=#{value}" }.join(",")
        end
      end

      # The Scale a write produced: its replicas (ValidateScale, and the
      # sentinel check of a custom resource that never had replicas).
      def scale_body!(scale, route)
        raise Status::BadRequest.new("wrong object passed to Scale update: #{scale.inspect}") unless scale.is_a?(Hash)

        kind = scale["kind"].to_s
        raise Status::BadRequest.new("wrong object passed to Scale update: kind #{kind.inspect}") unless kind.empty? || kind == "Scale"
        replicas = scale.dig("spec", "replicas") || 0
        unless replicas.is_a?(Integer)
          raise Status::BadRequest.new("json: cannot unmarshal #{replicas.class.name.downcase} into Go struct field ScaleSpec.spec.replicas of type int32")
        end
        if replicas == INVALID_SPEC_REPLICAS && (paths = custom_scale_paths(route.resource))
          raise Status::BadRequest.new("the spec replicas field #{ManagedFields::Value.go_quote(paths[:spec_replicas].to_s)} cannot be empty")
        end
        if replicas.negative?
          cause = {"reason" => "FieldValueInvalid", "field" => "spec.replicas",
                   "message" => "Invalid value: #{replicas}: must be greater than or equal to 0"}
          raise Status::Invalid.new(
            "Scale.autoscaling #{route.name.to_s.inspect} is invalid: spec.replicas: #{cause["message"]}",
            details: {"name" => route.name.to_s, "group" => "autoscaling", "kind" => "Scale", "causes" => [cause]}
          )
        end
        replicas
      end

      def scale_update(existing, replicas, resource = nil)
        object = deep_copy(existing)
        path = (paths = custom_scale_paths(resource)) ? split_replicas_path(paths[:spec_replicas]) : %w[spec replicas]
        node = path[0...-1].reduce(object) { |parent, key| parent[key].is_a?(Hash) ? parent[key] : (parent[key] = {}) }
        node[path.last] = replicas
        object
      end

      # A PUT or non-apply PATCH of /scale: the Scale field manager records
      # the write against the Scale the parent projects, and its entries go
      # back onto the parent (ScaleHandler ToParent).
      def scale_update_response(request, route, existing, namespace, scale)
        live = live_scale(route, existing)
        entries = @field_managers.scale_field_manager.update(live: live, new_object: scale, manager: update_manager(request))
        scale_write_response(route, existing, namespace, scale, entries, dry_run: dry_run?(request))
      end

      # Server-side apply to /scale.
      def scale_apply_response(request, route, existing, namespace, document)
        raise Status::BadRequest.new("error decoding YAML: apply patch must be an object") unless document.is_a?(Hash)

        live = live_scale(route, existing)
        merged, entries = begin
          @field_managers.scale_field_manager.apply(live: live, config: stringify_keys(document),
                                                    manager: query(request, "fieldManager").to_s,
                                                    force: truthy?(query(request, "force")))
        rescue ManagedFields::FieldManager::Error, ManagedFields::TypedValue::Error => error
          raise Status::InternalError.new(error.message)
        end
        scale_write_response(route, existing, namespace, merged, entries, dry_run: dry_run?(request))
      end

      def scale_write_response(route, existing, namespace, scale, entries, dry_run: false)
        replicas = scale_body!(scale, route)
        expected = scale.dig("metadata", "resourceVersion")
        ensure_expected_version!(existing, expected) unless expected.to_s.empty?
        object = scale_update(existing, replicas, route.resource)
        object = apply_schema(route.resource, object, operation: :update, old: existing)
        parent = begin
          ManagedFields::ScaleHandler.to_parent(existing.dig("metadata", "managedFields"), entries,
                                                route.resource.api_version, scale_mappings(route.resource))
        rescue ManagedFields::Entries::DecodeError
          existing.dig("metadata", "managedFields")
        end
        object = with_managed_fields(object, parent)
        object = apply_generation(object, existing, subresource: route.subresource, resource: route.resource)
        return json_response(scale_view(object, route.resource)) if dry_run

        updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                object: object, resource_version: metadata_value(existing, "resourceVersion"))
        json_response(scale_view(updated, route.resource))
      end

      def list_item(resource, object)
        if resource.respond_to?(:custom?) && resource.custom?
          object.merge("apiVersion" => resource.api_version, "kind" => resource.kind)
        else
          object.reject { |key, _| %w[apiVersion kind].include?(key) }
        end
      end

      def list_response(request, route)
        namespace = storage_namespace(route, operation: :list)
        validate_list_options!(request)
        selectors = selectors_from(request)
        result = @store.list(
          resource: route.resource,
          namespace: namespace,
          selectors: selectors,
          resource_version: query(request, "resourceVersion"),
          resource_version_match: query(request, "resourceVersionMatch"),
          limit: integer_query(request, "limit"),
          continue_token: query(request, "continue")
        )
        payload = {
          "apiVersion" => route.resource.api_version,
          "kind" => route.resource.list_kind,
          "metadata" => {"resourceVersion" => result.resource_version.to_s},
          # kube-apiserver serializes built-in list items without their
          # TypeMeta: the list envelope's apiVersion/kind identify the item
          # type.  Custom resources are unstructured and keep theirs
          # (apiextensions-apiserver serves UnstructuredList, whose items are
          # whole objects), and clients such as the dynamic informer rely on it.
          "items" => result.items.map { |object| list_item(route.resource, default_on_read(route.resource, deep_copy(object))) }
        }
        payload["metadata"]["continue"] = result.continue_token if result.continue_token
        payload["metadata"]["remainingItemCount"] = result.remaining_item_count unless result.remaining_item_count.nil?
        json_response(payload)
      end

      def validate_list_options!(request)
        match = query(request, "resourceVersionMatch")
        send_initial = query(request, "sendInitialEvents")
        causes = []
        unless match.nil? || match.to_s.empty?
          if query(request, "resourceVersion").to_s.empty?
            causes << {
              "reason" => "FieldValueForbidden",
              "message" => "Forbidden: resourceVersionMatch is forbidden unless resourceVersion is provided",
              "field" => "resourceVersionMatch"
            }
          end
          unless query(request, "continue").to_s.empty?
            causes << {
              "reason" => "FieldValueForbidden",
              "message" => "Forbidden: resourceVersionMatch is forbidden when continue is provided",
              "field" => "resourceVersionMatch"
            }
          end
          unless %w[Exact NotOlderThan].include?(match.to_s)
            causes << {
              "reason" => "FieldValueNotSupported",
              "message" => "Unsupported value: #{match.inspect}: supported values: \"Exact\", \"NotOlderThan\"",
              "field" => "resourceVersionMatch"
            }
          end
          if match.to_s == "Exact" && query(request, "resourceVersion").to_s == "0"
            causes << {
              "reason" => "FieldValueForbidden",
              "message" => "Forbidden: resourceVersionMatch \"exact\" is forbidden for resourceVersion \"0\"",
              "field" => "resourceVersionMatch"
            }
          end
        end
        unless send_initial.nil?
          causes << {
            "reason" => "FieldValueForbidden",
            "message" => "Forbidden: sendInitialEvents is forbidden for list",
            "field" => "sendInitialEvents"
          }
        end
        return if causes.empty?

        rendered = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }
        summary = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
        raise Status::Invalid.new(
          "ListOptions.meta.k8s.io \"\" is invalid: #{summary}",
          details: {"group" => "meta.k8s.io", "kind" => "ListOptions", "causes" => causes}
        )
      end

      def create_response(request, route)
        namespace = storage_namespace(route, operation: :create)
        validate_write_options!(request, "CreateOptions")
        object = normalize_object(request, route)
        metadata = object["metadata"]
        generate_name = metadata["generateName"].to_s
        if metadata["name"].to_s.empty? && generate_name.empty?
          cause = {
            "reason" => "FieldValueRequired",
            "message" => "Required value: name or generateName is required",
            "field" => "metadata.name"
          }
          raise Status::Invalid.new(
            "#{route.resource.kind} \"\" is invalid: metadata.name: #{cause.fetch("message")}",
            details: {"kind" => route.resource.kind, "causes" => [cause]}
          )
        end
        object["metadata"]["namespace"] = namespace unless namespace == :cluster || namespace == :all
        ensure_namespace_exists!(route.resource, namespace)
        unknown_mode = enforce_field_validation(route.resource, object, request,
                                                duplicates: request_duplicate_fields(request))
        attempts = 0
        last_generated_name = nil
        loop do
          attempts += 1
          candidate = deep_copy(object)
          candidate["metadata"]["name"] = generated_name(generate_name) if candidate["metadata"]["name"].to_s.empty?
          last_generated_name = metadata_value(candidate, "name")
          # SetDefaults_* runs at decode time upstream, i.e. before the schema
          # validator requires a ReplicationController selector.
          candidate = apply_pre_validation_defaults(route.resource, candidate)
          candidate = apply_schema(route.resource, candidate, operation: :create,
                                   unknown_fields: unknown_mode)
          before_mutation = candidate
          candidate = before_mutation = with_managed_fields(candidate, record_managed_update(request, route, nil, candidate))
          candidate = admit_mutating(request, route, "CREATE", candidate, nil, namespace)
          candidate = redefault_after_mutation(route.resource, candidate, before_mutation, unknown_fields: unknown_mode)
          merge_label_keys!(candidate) if pod_resource?(route.resource)
          candidate = inject_csr_requester(request, route.resource, candidate)
          validate_object!(route.resource, candidate)
          admit_validating(request, route, "CREATE", candidate, nil, namespace)
          candidate = prepare_created_metadata(candidate)
          candidate = prepare_registry_create(route.resource, candidate)
          # Job selectors are generated from the apiserver-assigned UID. The
          # first schema pass necessarily precedes metadata allocation, so run
          # the idempotent defaulting pass once more for Job roots after the
          # UID is available.
          candidate = apply_schema(route.resource, candidate, operation: :create) if route.resource.kind.to_s == "Job"
          candidate = deep_copy(candidate)
          # ?dryRun=All runs admission and validation and returns the object
          # that WOULD have been stored, without storing it (upstream's
          # dryRun support in the generic registry).  Not honouring it made
          # "[sig-cli] Kubectl client Kubectl server-side dry-run" write the
          # object for real.
          return json_response(dry_run_view(candidate, namespace), status: 201) if dry_run?(request)

          begin
            created = @store.create(resource: route.resource, namespace: namespace, object: candidate)
            after_commit(route.resource, created)
            return json_response(created, status: 201)
          rescue MemoryStore::AlreadyExists
            raise unless !generate_name.empty? && attempts < MAX_GENERATE_NAME_ATTEMPTS
          end
          # Keep the caller's empty name so the next attempt receives a fresh
          # suffix rather than retrying the same colliding name.
          object = deep_copy(object)
        end
      rescue MemoryStore::AlreadyExists
        name = last_generated_name || metadata_value(object, "name")
        raise Status::AlreadyExists.new("#{route.resource.resource} #{name.inspect} already exists",
                                        details: resource_details(route, name: name))
      end

      # storage.Interface#GuaranteedUpdate re-reads and re-applies an
      # UNCONDITIONAL update when the object moved between the read and the
      # write; only a caller-supplied resourceVersion turns that race into a
      # 409.  Without the retry a client PUT racing a controller -- the root
      # CA publisher refilling kube-root-ca.crt -- failed with "changed during
      # update" where kube-apiserver just succeeds.
      MAX_UNCONDITIONAL_UPDATE_ATTEMPTS = 8

      def update_response(request, route)
        attempts = 0
        begin
          attempts += 1
          update_response_once(request, route, retry_conflicts: attempts < MAX_UNCONDITIONAL_UPDATE_ATTEMPTS)
        rescue UnconditionalUpdateConflict
          retry
        end
      end

      class UnconditionalUpdateConflict < StandardError; end

      # managedFields take part: an update that changes nothing keeps them as
      # they were (ManagedFields::FieldManager), and one that only strips them
      # (managedFields: [{}]) is a real write, as it is upstream.
      NOOP_IGNORED_METADATA = %w[resourceVersion].freeze

      def noop_update?(object, existing)
        return false unless object.is_a?(Hash) && existing.is_a?(Hash)

        # Stored metav1.Time fields are second precision, so an update carrying
        # the same instants with sub-second digits (the node agent stamps
        # status that way) is still no change.  Comparing the raw strings made
        # every such status sync a real write.
        # The stored object was truncated on its way in (StoreAdapter
        # #convert_in), so only the submitted one needs it; truncate_times
        # never mutates its argument, so neither side is copied.
        strip = lambda do |value|
          metadata = value["metadata"]
          return value unless metadata.is_a?(Hash)

          value.merge("metadata" => metadata.except(*NOOP_IGNORED_METADATA))
        end
        strip.call(StoreAdapter.time_codec.truncate_times(object)) == strip.call(existing)
      rescue StandardError
        false
      end

      def update_response_once(request, route, retry_conflicts: false)
        namespace = storage_namespace(route, operation: :update)
        validate_write_options!(request, "UpdateOptions")
        if route.subresource == "scale"
          existing = @store.get(resource: route.resource, namespace: namespace, name: route.name)
          return scale_update_response(request, route, existing, namespace, request_body(request))
        end

        object = phase("update.normalize") { normalize_object(request, route) }
        # GuaranteedUpdate with cachedExistingObject: an update that names the
        # resourceVersion it read starts from this replica's copy, without a
        # linearizable read.  The write proposes that version and the state
        # machine refuses it if the object moved on, so a stale copy costs a
        # 409 the client would have got anyway -- never a lost update.  A copy
        # that does not match (or is missing) may just be behind: read again
        # through the barrier before judging.
        hinted = metadata_value(object, "resourceVersion").to_s
        cached = false
        unless hinted.empty?
          existing = cached_store_read { @store.get(resource: route.resource, namespace: namespace, name: route.name) }
          cached = existing.is_a?(Hash) && metadata_value(existing, "resourceVersion").to_s == hinted
        end
        existing = @store.get(resource: route.resource, namespace: namespace, name: route.name) unless cached
        ensure_name!(object, route.name)
        # registry.Store#Update: an object submitted without a resourceVersion
        # is an *unconditional* update wherever the strategy allows one, which
        # every built-in kind does.  Upstream's own conformance tests rely on
        # it -- "should update ConfigMap successfully" updates the object it
        # built locally, never having read the one the server stored -- so
        # rejecting it fails the spec outright.  A resourceVersion that *is*
        # present is still enforced as an optimistic-concurrency precondition.
        expected = metadata_value(object, "resourceVersion")
        unconditional = expected.to_s.empty?
        # Strategy.AllowUnconditionalUpdate() == false: these kinds refuse an
        # update that carries no resourceVersion, exactly as a CRD does
        # (pkg/registry/*/*/strategy.go).  Accepting one let a client
        # last-write-wins over a Lease, a PDB or a webhook configuration that
        # upstream would have rejected.
        if unconditional && strict_update?(route.resource)
          raise Status::Invalid.new("#{route.resource.resource} #{route.name.inspect} is invalid: metadata.resourceVersion: Invalid value: 0x0: must be specified for an update",
                                    details: resource_details(route))
        end
        # Strategy.AllowCreateOnUpdate: a PUT to an object that does not exist
        # CREATES it for the kinds whose strategy says so (Lease,
        # LeaseCandidate, Endpoints, Event, LimitRange, Service).  Answering
        # 404 for those made a client that PUTs its own object -- which is how
        # leases and endpoints are written -- fail against us and work
        # everywhere else.
        return create_response(request, route) if existing.nil? && allow_create_on_update?(route.resource)
        raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                   details: resource_details(route)) if unconditional && existing.nil?
        ensure_expected_version!(existing, expected) unless unconditional
        object = preserve_metadata(object, existing)
        unknown_mode = enforce_field_validation(route.resource, object, request,
                                                duplicates: request_duplicate_fields(request))
        if route.subresource == "status"
          object = status_update(existing, object, resource: route.resource)
        elsif approval_subresource?(route)
          object = approval_update(existing, object)
        elsif pod_resize_route?(route)
          object = resize_update(existing, object)
        else
          object["status"] = deep_copy(existing["status"]) if existing.key?("status")
        end
        object = phase("update.schema") do
          apply_schema(route.resource, object, operation: :update, old: existing, subresource: route.subresource,
                       unknown_fields: unknown_mode)
        end
        object = prepare_registry_update(route.resource, existing, object) if route.subresource.nil?
        before_mutation = object
        object = before_mutation = with_managed_fields(object, record_managed_update(request, route, existing, object))
        object = admit_mutating(request, route, "UPDATE", object, existing, namespace)
        object = redefault_after_mutation(route.resource, object, before_mutation, unknown_fields: unknown_mode)
        authorize_resource_claim_status!(request, route, existing, object)
        phase("update.validate") { validate_object!(route.resource, object, old: existing) } unless route.subresource == "status"
        admit_validating(request, route, "UPDATE", object, existing, namespace)
        object = apply_generation(object, existing, subresource: route.subresource, resource: route.resource)
        if dry_run?(request)
          preview = dry_run_view(object, namespace)
          return json_response(route.subresource == "status" ? status_view(preview) : preview)
        end
        # etcd3 GuaranteedUpdate skips the write when the encoded object is
        # unchanged: a PUT that changes nothing leaves the resourceVersion
        # alone.  Bumping it made every controller resync (EndpointSlices
        # every few seconds) a new revision, which every other writer of the
        # object then lost a 409 to.
        # Truncated once: the no-op check compares it, and the store takes it
        # as is instead of truncating it again in convert_in.
        object = StoreAdapter.time_codec.truncated_frozen(object) if object.is_a?(Hash) && StoreAdapter.time_codec.respond_to?(:truncated_frozen)
        if phase("update.noop_check") { noop_update?(object, existing) }
          return json_response(route.subresource == "status" ? status_view(existing) : existing)
        end
        write = lambda do
          @store.update(resource: route.resource, namespace: namespace, name: route.name,
                        object: object,
                        resource_version: unconditional ? metadata_value(existing, "resourceVersion") : expected)
        end
        updated = cached ? cached_store_read(&write) : write.call
        after_commit(route.resource, updated) if route.subresource.nil?
        finalize_object_removal(route.resource, namespace, updated)
        phase("update.respond") { json_response(route.subresource == "status" ? status_view(updated) : updated) }
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                   details: resource_details(route))
      rescue MemoryStore::Conflict
        raise UnconditionalUpdateConflict if retry_conflicts && unconditional

        raise Status::Conflict.new("#{route.resource.kind} #{route.name.inspect} changed during update",
                                   details: resource_details(route))
      end

      # kube-apiserver retries a patch whose document carries no
      # resourceVersion when the object changed between the read and the
      # write (MaxRetryWhenPatchConflicts = 5): the patch is re-applied to the
      # fresh object.  This matters for a replicated store, where the read
      # and the compare-and-swap are not one atomic section.
      MAX_PATCH_CONFLICT_RETRIES = 5

      def patch_response(request, route)
        namespace = storage_namespace(route, operation: :update)
        content_type = request.content_type
        patch_type = Patch.type_for(content_type)
        if patch_type.nil? || patch_type == :apply_cbor
          raise Status::UnsupportedMediaType.new("unsupported patch content type #{content_type.inspect}")
        end
        validate_write_options!(request, "PatchOptions", patch_type: patch_type)
        patch_document = patch_document(request, patch_type)
        attempts = 0
        begin
          attempts += 1
          apply_patch_once(request, route, namespace, patch_type, patch_document)
        rescue MemoryStore::Conflict => error
          retry if attempts < MAX_PATCH_CONFLICT_RETRIES && !patch_carries_resource_version?(patch_document, patch_type)

          raise Status::Conflict.new("#{route.resource.kind} #{route.name.inspect} changed during patch",
                                     details: resource_details(route)), cause: error
        end
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                   details: resource_details(route))
      rescue MemoryStore::AlreadyExists
        raise Status::AlreadyExists.new("#{route.resource.resource} #{route.name.inspect} already exists",
                                        details: resource_details(route))
      end

      # FieldManager.Apply for an apply patch: [merged object, managedFields].
      # A failure that is not an API status is an internal error, as the
      # handler reports it.
      def server_side_apply(request, route, existing, document)
        @field_managers.field_manager(route.resource, route.subresource)
                       .apply(live: existing, config: document, manager: query(request, "fieldManager").to_s,
                              force: truthy?(query(request, "force")))
      rescue ManagedFields::FieldManager::Error, ManagedFields::TypedValue::Error, ManagedFields::FieldPath::DecodeError => error
        raise Status::InternalError.new(error.message)
      end

      def patch_carries_resource_version?(patch_document, patch_type)
        return false unless patch_document.is_a?(Hash)

        if patch_type == :json
          Array(patch_document).any? { |operation| operation.is_a?(Hash) && operation["path"].to_s == "/metadata/resourceVersion" }
        else
          value = patch_document.dig("metadata", "resourceVersion")
          !(value.nil? || value.to_s.empty?)
        end
      end

      def apply_patch_once(request, route, namespace, patch_type, patch_document)
        existing = begin
          @store.get(resource: route.resource, namespace: namespace, name: route.name)
        rescue MemoryStore::NotFound
          # handlers/patch.go sets forceAllowCreate for an apply patch, so an
          # apply to a missing object creates it -- but only through the main
          # resource.  A subresource has no create path (the status store's
          # Update never creates), and kube-apiserver answers 404.  Creating
          # here resurrected every namespace the e2e suite had just deleted:
          # the controller manager's status apply for the stale cached
          # Namespace arrived after the finalizer removal had deleted it, and
          # the namespace came back Active with a new uid.  463 of them were
          # left after one conformance round.
          raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                     details: resource_details(route)) unless patch_type == :apply && route.subresource.nil?
          nil
        end
        if route.subresource == "scale"
          raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                     details: resource_details(route)) if existing.nil?
          return scale_apply_response(request, route, existing, namespace, patch_document) if patch_type == :apply

          scale_patch_type = patch_type == :strategic ? :merge : patch_type
          patched = Patch.apply(scale_view(existing, route.resource, for_update: true), patch_document,
                                type: scale_patch_type, resource: route.resource)
          return scale_update_response(request, route, existing, namespace, patched)
        end
        patch_document = normalize_apply_document(patch_document, route) if patch_type == :apply
        object, managed_fields = if patch_type == :apply
                                   server_side_apply(request, route, existing, patch_document)
                                 else
                                   # The Update entry is recorded from the patched
                                   # object's diff below, once it is defaulted.
                                   [Patch.apply(existing, patch_document, type: patch_type, resource: route.resource), nil]
                                 end
        raise Status::Invalid.new("patch must produce a resource object") unless object.is_a?(Hash)
        # The patched document is decoded into the typed object upstream, so
        # a JSON null a merge or strategic patch leaves inside a replaced
        # list (Helm renders `annotations: null` / `selector: null` in a
        # StatefulSet's volumeClaimTemplates) is absent there.  Kept as nil,
        # it made ValidateStatefulSetUpdate see a changed template and refuse
        # every `helm upgrade` of a chart with a StatefulSet.
        if patch_type != :apply
          if route.resource.respond_to?(:custom?) && route.resource.custom?
            drop_null_fields!(object["metadata"]) if object["metadata"].is_a?(Hash)
          else
            drop_null_fields!(object)
          end
        end
        ensure_name!(object, route.name)
        if existing.nil? && namespace != :cluster && namespace != :all
          object["metadata"] ||= {}
          object["metadata"]["namespace"] = namespace
        end
        patch_resource_version = metadata_value(object, "resourceVersion")
        if existing && patch_resource_version && patch_resource_version.to_s != metadata_value(existing, "resourceVersion").to_s
          raise Status::Conflict.new("resourceVersion #{patch_resource_version.inspect} does not match current #{metadata_value(existing, "resourceVersion").inspect}")
        end
        # A patch that names a metadata.uid is a precondition on the object's
        # identity (upstream: "Precondition failed: UID in precondition ...",
        # 409).  A node's status report for a Pod it was starting otherwise
        # landed on the NEXT Pod of the same name: a StatefulSet recreating
        # ss-0 every 300 ms had each new incarnation marked Failed by its
        # predecessor's report and deleted again, 776 times in four minutes.
        patch_uid = patch_document.is_a?(Hash) ? patch_document.dig("metadata", "uid") : nil
        if existing && patch_uid && !patch_uid.to_s.empty? && patch_uid.to_s != metadata_value(existing, "uid").to_s
          raise Status::Conflict.new(
            "Precondition failed: UID in precondition: #{patch_uid}, UID in object meta: #{metadata_value(existing, "uid")}"
          )
        end
        object = existing ? preserve_metadata(object, existing) : object
        object = with_managed_fields(object, managed_fields) if patch_type == :apply
        if existing.nil?
          object = prepare_created_metadata(object)
          # Server-side apply and a patch that creates take the same registry
          # PrepareForCreate hooks as POST; skipping them here made an applied
          # object differ from a posted one.
          object = prepare_registry_create(route.resource, object)
          merge_label_keys!(object) if pod_resource?(route.resource)
        end
        object = status_update(existing, object, resource: route.resource) if route.subresource == "status" && existing
        if existing && approval_subresource?(route)
          object = approval_update(existing, object)
        elsif existing && pod_resize_route?(route)
          object = resize_update(existing, object)
        elsif route.subresource != "status" && existing&.key?("status")
          object["status"] = deep_copy(existing["status"])
        end
        # fieldValidation applies to PATCH too (handlers/patch.go:162): a strict
        # patch that introduces an unknown field must be refused, exactly as a
        # strict PUT is.  Skipping it here let a patch smuggle in fields that
        # the same body would have been rejected for on update.
        # An apply is validated against the applied configuration, not the
        # merged result: the merged object also carries server-owned fields
        # (status on a resource whose schema does not declare it) that the
        # client never sent and is not answerable for.
        unknown_mode = enforce_field_validation(route.resource, object, request,
                                                duplicates: request_duplicate_fields(request),
                                                apply: patch_type == :apply,
                                                document: patch_type == :apply ? patch_document : nil)
        object = apply_schema(route.resource, object,
                              operation: existing ? :update : :create, old: existing,
                              unknown_fields: unknown_mode, subresource: route.subresource)
        object = prepare_registry_update(route.resource, existing, object) if existing && route.subresource.nil?
        before_mutation = object
        object = before_mutation = with_managed_fields(object, record_managed_update(request, route, existing, object)) unless patch_type == :apply
        object = admit_mutating(request, route, existing ? "UPDATE" : "CREATE", object, existing, namespace)
        object = redefault_after_mutation(route.resource, object, before_mutation, unknown_fields: unknown_mode)
        object = inject_csr_requester(request, route.resource, object) if existing.nil?
        authorize_resource_claim_status!(request, route, existing, object) if existing
        validate_object!(route.resource, object, old: existing) unless route.subresource == "status"
        admit_validating(request, route, existing ? "UPDATE" : "CREATE", object, existing, namespace)
        ensure_namespace_exists!(route.resource, namespace) if existing.nil?
        object = apply_generation(object, existing, subresource: route.subresource, resource: route.resource)
        if dry_run?(request)
          preview = dry_run_view(object, namespace)
          return json_response(route.subresource == "status" ? status_view(preview) : preview,
                               status: existing ? 200 : 201)
        end
        if existing
          updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                  object: object, resource_version: metadata_value(existing, "resourceVersion"))
          after_commit(route.resource, updated) if route.subresource.nil?
          finalize_object_removal(route.resource, namespace, updated)
          json_response(route.subresource == "status" ? status_view(updated) : updated)
        else
          created = @store.create(resource: route.resource, namespace: namespace, object: object)
          after_commit(route.resource, created)
          json_response(created, status: 201)
        end
      end

      # DeleteOptions as the client sent them.  A body wins; a DELETE without
      # one still carries its options in the query string, which is what
      # upstream's ParameterCodec decodes when the body is empty
      # (endpoints/handlers/delete.go: "if len(body) > 0 ... else ...
      # DecodeParameters(req.URL.Query(), ...)").  Reading the body alone meant
      # ?gracePeriodSeconds=0 was ignored, so the DELETE that is supposed to
      # remove an already-terminating object just restarted its grace period.
      DELETE_OPTION_PARAMETERS = %w[gracePeriodSeconds propagationPolicy orphanDependents dryRun].freeze

      def delete_options_for(request)
        body = request_body(request)
        options = body.is_a?(Hash) ? stringify_keys(body) : {}
        DELETE_OPTION_PARAMETERS.each do |name|
          next if options.key?(name)

          value = query(request, name)
          next if value.nil? || value.to_s.empty?

          options[name] = case name
                          when "gracePeriodSeconds" then Integer(value)
                          when "orphanDependents" then %w[true 1].include?(value.to_s.downcase)
                          when "dryRun" then value.to_s.split(",")
                          else value.to_s
                          end
        end
        options
      rescue StandardError
        {}
      end

      # nil when the kind has no graceful deletion at all; otherwise the number
      # of seconds the object gets, 0 meaning "remove now".
      GRACEFUL_DELETION_KINDS = %w[Pod].freeze

      def graceful_deletion_seconds(resource, existing, options)
        return nil unless GRACEFUL_DELETION_KINDS.include?(resource.kind.to_s)

        requested = hash_value(options, "gracePeriodSeconds")
        period = if requested.nil?
                   value = Controller::Support.value(Controller::Support.spec(existing), "terminationGracePeriodSeconds", nil)
                   value.nil? ? 0 : Integer(value)
                 else
                   Integer(requested)
                 end
        # An unscheduled or already terminal Pod goes immediately.
        period = 0 if Controller::Support.value(Controller::Support.spec(existing), "nodeName", "").to_s.empty?
        phase = Controller::Support.value(Controller::Support.status(existing), "phase", "").to_s
        period = 0 if %w[Succeeded Failed].include?(phase)
        period = 1 if period.negative?
        period
      rescue ArgumentError, TypeError
        nil
      end

      def hash_value(hash, key)
        return nil unless hash.is_a?(Hash)

        hash[key] || hash[key.to_sym]
      end

      # Marking an object for deletion is a read-modify-write, so it races with
      # whatever else writes the object.  Upstream's registry retries the whole
      # cycle on a conflict; surfacing it would fail an ordinary DELETE.
      MARK_DELETION_ATTEMPTS = 5

      def mark_owner_deleting(route, namespace, existing, finalizer: nil)
        return existing if metadata_value(existing, "deletionTimestamp")

        object = deep_copy(existing)
        object["metadata"]["deletionTimestamp"] = @clock.call.utc.iso8601(6)
        add_finalizer(object, finalizer)
        updated = mark_for_deletion_with_retry(route, namespace, object, existing)
        after_commit(route.resource, updated)
        updated
      end

      # The client's resourceVersion precondition was checked before the
      # mark; the mark itself moved the version.  A client that pinned one
      # keeps its optimistic concurrency by pinning the version the mark
      # wrote, so a write landing between the mark and the removal still
      # conflicts.  A plain DELETE pins nothing, as upstream.
      def repin_after_mark(expected, marked)
        return nil if expected.to_s.empty?

        metadata_value(marked, "resourceVersion")
      end

      def add_finalizer(object, finalizer)
        return if finalizer.nil?

        finalizers = Array(object["metadata"]["finalizers"])
        object["metadata"]["finalizers"] = finalizers + [finalizer] unless finalizers.include?(finalizer)
      end

      def mark_for_deletion_with_retry(route, namespace, object, existing)
        attempts = 0
        current = existing
        candidate = object
        begin
          attempts += 1
          @store.update(resource: route.resource, namespace: namespace, name: route.name,
                        object: candidate, resource_version: metadata_value(current, "resourceVersion"))
        rescue MemoryStore::Conflict
          raise if attempts >= MARK_DELETION_ATTEMPTS

          current = @store.get(resource: route.resource, namespace: namespace, name: route.name)
          return current if metadata_value(current, "deletionTimestamp")

          candidate = deep_copy(current)
          candidate["metadata"]["deletionTimestamp"] ||= metadata_value(object, "deletionTimestamp")
          add_finalizer(candidate, FOREGROUND_FINALIZER) if Array(metadata_value(object, "finalizers")).include?(FOREGROUND_FINALIZER)
          if metadata_value(object, "deletionGracePeriodSeconds")
            candidate["metadata"]["deletionGracePeriodSeconds"] ||= metadata_value(object, "deletionGracePeriodSeconds")
            bump_pod_generation_on_delete(route.resource, candidate)
          end
          if namespace_resource?(route.resource)
            candidate["status"] = (candidate["status"] || {}).merge("phase" => "Terminating")
          end
          retry
        end
      end

      # registry/core/pod/strategy.go (PodObservedGenerationTracking): setting
      # a Pod's deletionTimestamp is a change to its desired state, so the
      # generation moves -- "[sig-node] Pods Extended Pod Generation
      # custom-set generation on new pods and graceful delete" reads 2 after
      # a graceful DELETE.
      def bump_pod_generation_on_delete(resource, object)
        return unless resource.group.to_s.empty? && resource.resource == "pods"

        object["metadata"]["generation"] = object["metadata"]["generation"].to_i + 1
      end

      def delete_response(request, route)
        namespace = storage_namespace(route, operation: :delete)
        existing = @store.get(resource: route.resource, namespace: namespace, name: route.name)
        delete_options = delete_options_for(request)
        preconditions = hash_value(delete_options, "preconditions")
        expected = query(request, "resourceVersion")
        expected = hash_value(preconditions, "resourceVersion") if expected.to_s.empty?
        ensure_expected_version!(existing, expected) unless expected.to_s.empty?
        expected_uid = hash_value(preconditions, "uid")
        unless expected_uid.to_s.empty? || expected_uid.to_s == metadata_value(existing, "uid").to_s
          raise Status::Conflict.new(
            "Precondition failed: UID in precondition: #{expected_uid}, " \
            "UID in object meta: #{metadata_value(existing, "uid")}"
          )
        end
        admit_mutating(request, route, "DELETE", nil, existing, namespace)
        admit_validating(request, route, "DELETE", nil, existing, namespace)
        if @crd_manager && crd_resource?(route.resource)
          marked = mark_crd_terminating(route, existing, namespace)
          schedule_crd_finalizer(metadata_value(existing, "name"))
          return json_response(marked)
        end
        # Graceful deletion (registry/core/pod/strategy.go#CheckGracefulDelete):
        # a scheduled, non-terminal Pod is not removed on DELETE.  Its
        # deletionTimestamp and deletionGracePeriodSeconds are set, the kubelet
        # stops the containers, and only then is the object removed -- which is
        # why the DELETED watch event carries a deletionTimestamp, as
        # "[sig-node] Pods should be submitted and removed" requires
        # (pods.go:333).  Deleting the object outright skipped all of that.
        if dry_run?(request) || !Array(delete_options["dryRun"]).empty?
          # A dry-run DELETE reports what would go without removing anything.
          return json_response(Status.success(details: resource_details(route).merge(
            "uid" => metadata_value(existing, "uid").to_s
          )))
        end
        grace = graceful_deletion_seconds(route.resource, existing, delete_options)
        if grace&.positive? && !metadata_value(existing, "deletionTimestamp")
          object = deep_copy(existing)
          object["metadata"]["deletionTimestamp"] = (@clock.call.utc + grace).iso8601(6)
          object["metadata"]["deletionGracePeriodSeconds"] = grace
          bump_pod_generation_on_delete(route.resource, object)
          updated = mark_for_deletion_with_retry(route, namespace, object, existing)
          after_commit(route.resource, updated)
          return json_response(updated)
        end

        finalizers = blocking_finalizers(route.resource, existing)
        if finalizers.any?
          return json_response(existing) if metadata_value(existing, "deletionTimestamp")

          object = deep_copy(existing)
          object["metadata"]["deletionTimestamp"] ||= @clock.call.utc.iso8601(6)
          if namespace_resource?(route.resource)
            object["status"] = (object["status"] || {}).merge("phase" => "Terminating")
          end
          updated = mark_for_deletion_with_retry(route, namespace, object, existing)
          after_commit(route.resource, updated)
          return json_response(updated)
        end
        delete_opts = delete_options
        # kubectl's default is --cascade=background: dependents go too, unless
        # propagationPolicy is Orphan (then their owner reference is stripped).
        if garbage_collection_unsupported?(route.resource)
          nil
        elsif orphan_deletion?(delete_opts, route.resource)
          # Upstream marks the owner as being deleted (deletionTimestamp plus
          # the orphan finalizer) BEFORE its dependents are released, so a
          # controller that sees a released Pod matching its selector does a
          # fresh read, finds its owner going away, and refuses to adopt it
          # back.  Releasing the dependents of a still-live owner raced that
          # guard: the ReplicationController re-adopted its own orphaned Pods,
          # was deleted, and the garbage collector then removed every Pod it
          # had just re-adopted -- "[sig-api-machinery] Garbage collector
          # should orphan pods created by rc if delete options say so" kept 0
          # of 100.  The resourceVersion precondition was already checked
          # above, so the final delete no longer pins the version this mark
          # moved.
          existing = mark_owner_deleting(route, namespace, existing)
          expected = repin_after_mark(expected, existing)
          orphan_dependents(route.resource, namespace, existing)
        else
          # Same reason as the orphan branch: the owner is marked as being
          # deleted before its dependents go, so its own controller stops
          # replacing them.  Deleting the Pods of a still-live
          # ReplicationController let it create new ones in the window before
          # it was removed, and those outlived it -- "[sig-api-machinery]
          # Garbage collector should keep the rc around until all its pods are
          # deleted if the deleteOptions says so" found Pods left after the rc.
          #
          # Foreground (registry/generic/registry/store.go
          # deletionFinalizersForGarbageCollection): the owner keeps the
          # foregroundDeletion finalizer and stays readable until the garbage
          # collector has seen every dependent gone, and only then is it
          # removed.  Removing it right after the synchronous cascade let a
          # creation batch its controller had already started land Pods after
          # the cascade had listed them; "[sig-api-machinery] Garbage
          # collector should keep the rc around until all its pods are deleted
          # if the deleteOptions says so" found them outliving the rc.
          foreground = foreground_deletion?(delete_opts) && CASCADE_OWNER_KINDS.include?(route.resource.kind.to_s)
          if CASCADE_OWNER_KINDS.include?(route.resource.kind.to_s)
            existing = mark_owner_deleting(route, namespace, existing, finalizer: foreground ? FOREGROUND_FINALIZER : nil)
            expected = repin_after_mark(expected, existing)
          end
          cascade_delete_dependents(existing, owner_kind: route.resource.kind)
          return json_response(existing) if foreground && Array(metadata_value(existing, "finalizers")).include?(FOREGROUND_FINALIZER)
        end
        # Upstream pins the stored resourceVersion ONLY when the client sent
        # Preconditions (registry/generic/registry/store.go#Delete).  Pinning
        # the version this handler happened to read turns an ordinary DELETE of
        # an object something else is updating -- a CronJob whose status the
        # controller is writing, a Pod whose status the kubelet is writing --
        # into "expected resourceVersion N, current is M", which is not an
        # error the client can act on and which no upstream cluster returns.
        begin
          @store.delete(resource: route.resource, namespace: namespace, name: route.name,
                        resource_version: expected.to_s.empty? ? nil : expected)
        rescue MemoryStore::NotFound
          # Once marked as being deleted (above, before its dependents were
          # released or removed), the object has a deletionTimestamp and no
          # finalizers, so the next write to it -- its own controller's status
          # update, typically -- completes the removal.  This request asked
          # for exactly that; reporting 404 for it made the client believe the
          # delete failed ("failed to delete the rc: ... not found").
          raise unless metadata_value(existing, "deletionTimestamp")
        end
        after_commit(route.resource, existing, deleted: true)
        release_registry_allocations(route.resource, existing)
        json_response(Status.success(details: resource_details(route).merge("uid" => metadata_value(existing, "uid").to_s)))
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                   details: resource_details(route))
      end

      def delete_collection_response(request, route)
        namespace = storage_namespace(route, operation: :list)
        selectors = selectors_from(request)
        result = @store.list(resource: route.resource, namespace: namespace, selectors: selectors)
        deleted = []
        result.items.each do |object|
          name = metadata_value(object, "name")
          begin
            admit_mutating(request, route, "DELETE", nil, object, namespace, name: name)
            admit_validating(request, route, "DELETE", nil, object, namespace, name: name)
            deleted << delete_one(route.resource, namespace, name, object, pin_version: false)
          rescue MemoryStore::NotFound
            # A concurrent delete has already achieved the requested state.
          end
        end
        json_response(Status.success(
                        message: "deleted #{deleted.length} #{route.resource.resource}",
                        details: {"group" => route.resource.group, "kind" => route.resource.kind,
                                  "names" => deleted.map { |object| metadata_value(object, "name") }}
                      ))
      end

      def watch_response(request, route)
        namespace = storage_namespace(route, operation: :watch)
        validate_watch_options!(request)
        stream = @store.watch(
          resource: route.resource,
          namespace: namespace,
          selectors: selectors_from(request),
          resource_version: query(request, "resourceVersion"),
          resource_version_match: query(request, "resourceVersionMatch"),
          allow_bookmarks: truthy?(query(request, "allowWatchBookmarks")),
          send_initial_events: truthy?(query(request, "sendInitialEvents")),
          timeout_seconds: integer_query(request, "timeoutSeconds")
        )
        Response.new(status: 200, headers: {"content-type" => "application/json",
                                             "cache-control" => "no-cache, private"},
                     body: stream, unbounded: true)
      end

      def validate_watch_options!(request)
        send_initial_value = query(request, "sendInitialEvents")
        resource_version_match = query(request, "resourceVersionMatch")
        resource_version_match_present = !resource_version_match.nil? && !resource_version_match.to_s.empty?
        send_initial_present = !send_initial_value.nil?
        causes = []
        if resource_version_match_present && !send_initial_present
          causes << {
            "reason" => "FieldValueForbidden",
            "message" => "Forbidden: resourceVersionMatch is forbidden for watch unless sendInitialEvents is provided",
            "field" => "resourceVersionMatch"
          }
        end
        if send_initial_present && resource_version_match != "NotOlderThan"
          causes << {
            "reason" => "FieldValueForbidden",
            "message" => "Forbidden: sendInitialEvents requires setting resourceVersionMatch to NotOlderThan",
            "field" => "resourceVersionMatch"
          }
        end
        if resource_version_match_present && resource_version_match != "NotOlderThan"
          causes << {
            "reason" => "FieldValueNotSupported",
            "message" => "Unsupported value: #{resource_version_match.inspect}: supported values: \"NotOlderThan\"",
            "field" => "resourceVersionMatch"
          }
        end
        if resource_version_match_present && !query(request, "continue").to_s.empty?
          causes << {
            "reason" => "FieldValueForbidden",
            "message" => "Forbidden: resourceVersionMatch is forbidden when continue is provided",
            "field" => "resourceVersionMatch"
          }
        end
        return if causes.empty?

        rendered = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }
        summary = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
        raise Status::Invalid.new(
          "ListOptions.meta.k8s.io \"\" is invalid: #{summary}",
          details: {"group" => "meta.k8s.io", "kind" => "ListOptions", "causes" => causes}
        )
      end

      def api_group_response(route)
        group_resources = enabled_resources.select { |resource| resource.group == route.group.to_s }
        if group_resources.empty? && @aggregator&.claims?(route.group.to_s)
          aggregated = @aggregator.groups.find { |group| group["name"] == route.group.to_s }
          return json_response({"apiVersion" => "v1", "kind" => "APIGroup"}.merge(aggregated))
        end
        return discovery_not_found_response if group_resources.empty?
        versions = ordered_group_versions(route.group.to_s, group_resources.map(&:version)).map do |version|
          {"groupVersion" => "#{route.group}/#{version}", "version" => version}
        end
        json_response({
          "apiVersion" => "v1",
          "kind" => "APIGroup",
          "name" => route.group.to_s,
          "versions" => versions,
          "preferredVersion" => versions.first
        })
      end

      def resource_list_response(route)
        resources = enabled_resources.select { |resource| resource.group == route.group.to_s && resource.version == route.version.to_s }
        if resources.empty?
          group_served = enabled_resources.any? { |resource| resource.group == route.group.to_s }
          return discovery_not_found_response unless group_served

          return error_response(
            Status::NotFound.new(
              "the server could not find the requested resource",
              details: {}
            )
          )
        end
        json_response({
          "apiVersion" => "v1",
          "groupVersion" => route.api_version,
          "kind" => "APIResourceList",
          "resources" => resources.sort_by(&:resource).flat_map { |resource| resource_discovery_entries(resource) }
            .sort_by { |entry| entry.fetch("name") }
        })
      end

      def resource_discovery_entries(resource)
        primary = resource_discovery(resource)
        subresources = resource.subresources.map do |subresource|
          entry = {
            "name" => "#{resource.resource}/#{subresource.resource}",
            "singularName" => "",
            "namespaced" => resource.namespaced?,
            "kind" => subresource.kind || resource.kind,
            "verbs" => subresource.verbs
          }
          # APIResourceList records the response identity for cross-group
          # subresources.  Omitting these fields makes clients lose the
          # autoscaling/v1 Scale aliases even though the parent route exists.
          advertised_group = subresource.advertised_group(resource.group)
          advertised_version = subresource.advertised_version(resource.group, resource.version)
          entry["group"] = advertised_group if advertised_group
          entry["version"] = advertised_version if advertised_version
          entry
        end
        [primary, *subresources]
      end

      def resource_discovery(resource)
        {
          "name" => resource.resource,
          "singularName" => resource.singular_name,
          "namespaced" => resource.namespaced?,
          "kind" => resource.kind,
          "verbs" => resource.verbs,
          "shortNames" => resource.short_names,
          "categories" => resource.categories
        }.tap do |payload|
          payload["storageVersionHash"] = resource.storage_version_hash if resource.storage_version_hash
        end
      end

      # Pod strategy PrepareForCreate mutatePodAffinity /
      # mutateTopologySpreadConstraints (MatchLabelKeysInPodAffinity,
      # MatchLabelKeysInPodTopologySpreadSelectorMerge): each matchLabelKeys
      # key the Pod carries becomes `key In (value)` in the term's selector,
      # each mismatchLabelKeys key `key NotIn (value)`.  A nil selector
      # matches nothing and is left alone.
      def merge_label_keys!(pod)
        labels = pod.dig("metadata", "labels")
        labels = {} unless labels.is_a?(Hash)
        spec = pod["spec"]
        return pod unless spec.is_a?(Hash)

        merge = lambda do |holder, keys, operator|
          selector = holder["labelSelector"]
          Array(keys).each do |key|
            next unless labels.key?(key.to_s)

            (selector["matchExpressions"] ||= []) << {"key" => key.to_s, "operator" => operator, "values" => [labels[key.to_s].to_s]}
          end
        end
        affinity = spec["affinity"]
        if affinity.is_a?(Hash)
          %w[podAffinity podAntiAffinity].each do |section|
            terms = affinity[section]
            next unless terms.is_a?(Hash)

            required = Array(terms["requiredDuringSchedulingIgnoredDuringExecution"])
            preferred = Array(terms["preferredDuringSchedulingIgnoredDuringExecution"]).map { |weighted| weighted.is_a?(Hash) ? weighted["podAffinityTerm"] : nil }
            (required + preferred).each do |term|
              next unless term.is_a?(Hash) && term["labelSelector"].is_a?(Hash)
              next if Array(term["matchLabelKeys"]).empty? && Array(term["mismatchLabelKeys"]).empty?

              merge.call(term, term["matchLabelKeys"], "In")
              merge.call(term, term["mismatchLabelKeys"], "NotIn")
            end
          end
        end
        Array(spec["topologySpreadConstraints"]).each do |constraint|
          next unless constraint.is_a?(Hash) && constraint["labelSelector"].is_a?(Hash) && !Array(constraint["matchLabelKeys"]).empty?

          merge.call(constraint, constraint["matchLabelKeys"], "In")
        end
        pod
      end

      # The top-level paths /statusz lists besides the API and discovery trees.
      STATUSZ_PATHS = %w[/flagz /healthz /livez /metrics /readyz /version].freeze

      def zpage_response(page, request)
        accept = request.respond_to?(:header) ? request.header("accept") : nil
        status, headers, body = if page == :statusz
                                  git = @version_info.fetch("gitVersion", "").to_s.delete_prefix("v")
                                  Observability::ZPages.statusz(
                                    component: "kube-apiserver", start_time: (@process_start ||= Observability::ZPages.process_start_time),
                                    binary_version: git, emulation_version: git.split(".").first(2).join("."), paths: STATUSZ_PATHS,
                                    accept: accept
                                  )
                                else
                                  Observability::ZPages.flagz(component: "kube-apiserver", flags: @component_flags || {}, accept: accept)
                                end
        Response.new(status: status, headers: headers.merge("cache-control" => "no-cache, private"), body: body)
      end

      def version_payload
        {"major" => @version_info.fetch("major"), "minor" => @version_info.fetch("minor"),
         "gitVersion" => @version_info.fetch("gitVersion"), "gitCommit" => @version_info.fetch("gitCommit"),
         "gitTreeState" => @version_info.fetch("gitTreeState"), "buildDate" => @version_info.fetch("buildDate"),
         "goVersion" => @version_info.fetch("goVersion"), "compiler" => @version_info.fetch("compiler"),
         "platform" => @version_info.fetch("platform")}
      end

      def api_versions_payload
        versions = enabled_resources.select { |resource| resource.group.empty? }.map(&:version).uniq.sort
        {"kind" => "APIVersions", "apiVersion" => "v1", "versions" => versions,
         "serverAddressByClientCIDRs" => []}
      end

      # apidiscovery.k8s.io/v2: kubectl 1.31+ asks /api and /apis for the
      # whole resource surface in a single round trip instead of one request
      # per group version.  The request is recognised by the Accept header's
      # `as=APIGroupDiscoveryList` conversion, and a client that does not ask
      # for it still gets the classic APIGroupList.
      AGGREGATED_DISCOVERY_GROUP = "apidiscovery.k8s.io"
      AGGREGATED_DISCOVERY_VERSION = "v2"
      AGGREGATED_DISCOVERY_KIND = "APIGroupDiscoveryList"

      def aggregated_discovery?(request)
        Negotiation.parse_accept(request.header("accept")).any? do |clause|
          params = clause.params || {}
          params["as"] == AGGREGATED_DISCOVERY_KIND && params["g"] == AGGREGATED_DISCOVERY_GROUP &&
            params["v"] == AGGREGATED_DISCOVERY_VERSION
        end
      rescue StandardError
        false
      end

      def aggregated_discovery_response(core_only:)
        selected = enabled_resources.select { |resource| core_only ? resource.group.empty? : !resource.group.empty? }
        items = selected.group_by(&:group).sort_by { |group, _| group }.map do |group, resources|
          versions = ordered_group_versions(group, resources.map(&:version)).map do |version|
            entries = resources.select { |resource| resource.version == version }.sort_by(&:resource)
            {"version" => version,
             "resources" => entries.map { |resource| aggregated_discovery_resource(resource) },
             "freshness" => "Current"}
          end
          {"metadata" => {"name" => group, "creationTimestamp" => nil}, "versions" => versions}
        end
        # The response must announce the aggregated representation in its own
        # Content-Type.  client-go decides how to parse a discovery document
        # from that header alone: served as plain application/json the body
        # is read as a legacy APIGroupList, yielding a client that believes
        # the server has no resources at all.
        # Aggregated APIService groups (wardle.example.com/...) live behind a
        # backend, not in enabled_resources, so they must be appended here or
        # the v2 discovery the 1.36 dynamic client reads omits them entirely.
        items += @aggregator.discovery_items if !core_only && @aggregator.respond_to?(:discovery_items)
        body = {"kind" => AGGREGATED_DISCOVERY_KIND,
                "apiVersion" => "#{AGGREGATED_DISCOVERY_GROUP}/#{AGGREGATED_DISCOVERY_VERSION}",
                "metadata" => {}, "items" => items}
        Response.new(status: 200,
                     headers: {"content-type" => "application/json;g=#{AGGREGATED_DISCOVERY_GROUP};v=#{AGGREGATED_DISCOVERY_VERSION};as=#{AGGREGATED_DISCOVERY_KIND}",
                               "cache-control" => "no-cache, private"},
                     body: body)
      end

      def aggregated_discovery_resource(resource)
        entry = {
          "resource" => resource.resource,
          "responseKind" => {"group" => resource.group, "version" => resource.version, "kind" => resource.kind},
          "scope" => resource.namespaced? ? "Namespaced" : "Cluster",
          "singularResource" => resource.singular_name.to_s,
          "verbs" => resource.verbs
        }
        short_names = resource.respond_to?(:short_names) ? Array(resource.short_names) : []
        entry["shortNames"] = short_names unless short_names.empty?
        categories = resource.respond_to?(:categories) ? Array(resource.categories) : []
        entry["categories"] = categories unless categories.empty?
        subresources = resource.subresources.map do |subresource|
          {"subresource" => subresource.resource,
           "responseKind" => {"group" => subresource.advertised_group(resource.group).to_s,
                              "version" => subresource.advertised_version(resource.group, resource.version).to_s,
                              "kind" => subresource.kind || resource.kind},
           "verbs" => subresource.verbs}
        end
        entry["subresources"] = subresources unless subresources.empty?
        entry
      end

      def api_groups_payload
        groups = enabled_resources.reject { |resource| resource.group.empty? }.group_by(&:group).sort.map do |group, resources|
          versions = ordered_group_versions(group, resources.map(&:version)).map do |version|
            {"groupVersion" => "#{group}/#{version}", "version" => version}
          end
          {"name" => group, "versions" => versions, "preferredVersion" => versions.first}
        end
        if @aggregator
          @aggregator.groups.each do |aggregated|
            existing = groups.find { |group| group["name"] == aggregated["name"] }
            if existing
              aggregated["versions"].each { |version| existing["versions"] << version unless existing["versions"].include?(version) }
            else
              groups << aggregated
            end
          end
          groups.sort_by! { |group| group["name"] }
        end
        {"kind" => "APIGroupList", "apiVersion" => "v1", "groups" => groups}
      end

      def ordered_group_versions(group, versions)
        available = versions.map(&:to_s).uniq
        pinned = PINNED_VERSION_PRIORITY.fetch(group.to_s, [])
        ordered = pinned.select { |version| available.include?(version) }
        ordered + (available - ordered).sort { |left, right| compare_kube_aware_versions(right, left) }
      end

      # apimachinery version.CompareKubeAwareVersionStrings: GA before beta
      # before alpha, higher major first, then higher minor; unparseable
      # versions sort after parseable ones, among themselves reverse-lexically.
      KUBE_VERSION_PATTERN = /\Av(\d+)(?:(alpha|beta)(\d+))?\z/
      KUBE_VERSION_TYPES = {"alpha" => 0, "beta" => 1, nil => 2}.freeze

      def compare_kube_aware_versions(left, right)
        return 0 if left == right

        left_match = KUBE_VERSION_PATTERN.match(left)
        right_match = KUBE_VERSION_PATTERN.match(right)
        return right <=> left if left_match.nil? && right_match.nil?
        return -1 if left_match.nil?
        return 1 if right_match.nil?

        left_type = KUBE_VERSION_TYPES.fetch(left_match[2])
        right_type = KUBE_VERSION_TYPES.fetch(right_match[2])
        return left_type <=> right_type if left_type != right_type
        return left_match[1].to_i <=> right_match[1].to_i if left_match[1].to_i != right_match[1].to_i

        left_match[3].to_i <=> right_match[3].to_i
      end

      def enabled_resources
        @registry.resources.select { |resource| resource_enabled?(resource) }
      end

      # Group/versions served by the pinned kube-apiserver under its default
      # flags (schema/kubernetes/v1.36.2-defaults/bootstrap/discovery-default.json).
      DEFAULT_SERVED_GROUP_VERSIONS = begin
        path = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/bootstrap/discovery-default.json", __dir__)
        if File.file?(path)
          JSON.parse(File.read(path)).keys.filter_map do |key|
            next "v1" if key == "/api/v1"
            next unless key.start_with?("/apis/") && key.count("/") == 3

            key.delete_prefix("/apis/")
          end.to_set
        else
          nil
        end
      end

      def version_served?(resource)
        return true if resource.respond_to?(:custom?) && resource.custom?
        return true if DEFAULT_SERVED_GROUP_VERSIONS.nil?

        group_version = resource.group.empty? ? resource.version : "#{resource.group}/#{resource.version}"
        value = @runtime_config[group_version]
        return value == true || value == "true" unless value.nil?
        return true if %w[true 1].include?(@runtime_config["api/all"].to_s)

        DEFAULT_SERVED_GROUP_VERSIONS.include?(group_version)
      end

      # Feature-gate defaults from the pinned corpus
      # (schema/kubernetes/v1.36.2-defaults/features.json); the hand-written
      # table above is the fallback when the corpus is absent.
      CORPUS_FEATURE_GATES = begin
        path = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/features.json", __dir__)
        File.file?(path) ? JSON.parse(File.read(path)).fetch("gates").transform_values { |gate| gate["default"] == true } : nil
      end

      def feature_gate_enabled?(gate)
        return @feature_gates.fetch(gate) == true if @feature_gates.key?(gate)
        return CORPUS_FEATURE_GATES.fetch(gate, false) == true if CORPUS_FEATURE_GATES

        DEFAULT_FEATURE_GATES.fetch(gate, false) == true
      end

      # A resource is served when its group/version is enabled by the runtime
      # configuration and the feature gate guarding the resource (if any) is
      # on, exactly as kube-apiserver's resource config composes them.
      def resource_enabled?(resource)
        return false unless version_served?(resource)

        gate = DEFAULT_DISABLED_GATES_BY_GVR[[resource.group, resource.version, resource.resource]]
        return true unless gate

        feature_gate_enabled?(gate)
      end

      # One served request, counted the way kube-apiserver counts it.  The
      # metrics endpoint itself is not counted, so scraping cannot inflate
      # the very numbers it reports.
      SLOW_REQUEST_SECONDS = 3.0

      # A request that took seconds is otherwise invisible: the client sees a
      # slow answer and the server logs nothing.  Watches are excluded, they
      # are long by design.
      def log_slow_request(request, route, response, started)
        return unless @logger && request && started
        return if route && (route.kind == :metrics || route.operation == :watch)

        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        if (phases = Thread.current[REQUEST_PHASES_KEY])
          @logger.info("request.trace", method: request.respond_to?(:method) ? request.method : nil, path: request.path.to_s[0, 200],
                                        status: response.respond_to?(:status) ? response.status : nil, seconds: elapsed.round(4),
                                        phases: phases.sort_by { |_name, seconds| -seconds }.to_h.transform_values { |seconds| seconds.round(4) })
        end
        return if elapsed < SLOW_REQUEST_SECONDS

        @logger.warn("request.slow", method: request.respond_to?(:method) ? request.method : nil, path: request.path.to_s[0, 200],
                                     status: response.respond_to?(:status) ? response.status : nil, seconds: elapsed.round(3))
      rescue StandardError
        nil
      end

      def record_request_metric(request, route, response, started, webhook_seconds: 0.0, slow_log: true)
        # A watch or a followed log lasts as long as the client wants: its
        # duration is not a slow request.
        log_slow_request(request, route, response, started) if slow_log
        return unless @metrics && request && response
        return if route && route.kind == :metrics

        status = response.respond_to?(:status) ? response.status : nil
        return unless status

        body = response.respond_to?(:body) ? response.body : nil
        size = body.is_a?(String) ? body.bytesize : (body.is_a?(Array) && body.all?(String) ? body.sum(&:bytesize) : nil)
        size ||= response.encoded_body.bytesize if response.respond_to?(:encoded_body) && response.encoded_body.is_a?(String)
        dry_run = request.respond_to?(:query_values) ? Array(request.query_values("dryRun")).sort.join(",") : ""
        labels = request_metric_labels(request, route)
        if size.nil? && %w[GET LIST].include?(labels[:verb]) && response.respond_to?(:on_body_encoded)
          metrics = @metrics
          endpoint = Observability::Metrics.request_labels(**labels)
          response.on_body_encoded { |bytes| metrics.response_size(endpoint, bytes) }
        end
        @metrics.record_request(**labels, code: status,
                                                                         duration: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                                                                         dry_run: dry_run, response_size: size, webhook_seconds: webhook_seconds)
        record_request_extras(request, route, labels)
      rescue StandardError
        nil
      end

      # The rest of MonitorRequest and the body read: the series
      # fieldValidationRequestLatencies creates (and never observes),
      # apiserver_selfrequest_total for the loopback user, and
      # apiserver_request_body_size_bytes for a body a handler read.
      def record_request_extras(request, route, labels)
        @metrics.touch("field_validation_request_duration_seconds", {"field_validation" => metric_field_validation(request)})
        endpoint = Observability::Metrics.request_labels(**labels)
        identity = request.respond_to?(:identity) ? request.identity : nil
        user = identity.is_a?(Hash) ? (identity["username"] || identity[:username]) : nil
        if user.to_s == "system:apiserver"
          @metrics.increment("apiserver_selfrequest_total", endpoint.slice("verb", "group", "resource", "subresource"))
        end
        verb = REQUEST_BODY_VERBS[request.method.to_s.upcase]
        verb = "delete_collection" if verb == "delete" && route&.name.nil?
        body = request.respond_to?(:body) ? request.body : nil
        return unless verb && route&.resource_route? && body.is_a?(String)
        return if verb.start_with?("delete") && body.empty?

        @metrics.observe("apiserver_request_body_size_bytes", body.bytesize,
                         {"group" => route.resource.group.to_s, "resource" => route.resource.resource.to_s, "verb" => verb})
      end

      REQUEST_BODY_VERBS = {"POST" => "create", "PUT" => "update", "PATCH" => "patch", "DELETE" => "delete"}.freeze

      # cleanFieldValidation.
      def metric_field_validation(request)
        values = request.respond_to?(:query_values) ? Array(request.query_values("fieldValidation")) : Array(query(request, "fieldValidation"))
        return "" if values.empty?
        return "invalid" unless values.length == 1 && ["", *FIELD_VALIDATION_DIRECTIVES].include?(values.first.to_s)

        values.first.to_s
      end

      # RecordRequestTermination: a request the server itself cut short
      # (priority and fairness rejected it, 429).
      def record_request_termination(request, route, code)
        return unless @metrics && request

        labels = Observability::Metrics.request_labels(**request_metric_labels(request, route))
        @metrics.increment("apiserver_request_terminations_total", labels.merge("code" => code.to_s))
      rescue StandardError
        nil
      end

      # UpdateStoreStats: the stored objects of every served group/resource
      # (0 for none), asked by Metrics at scrape time, at most once a minute.
      def storage_object_counts
        raw = @store.respond_to?(:store) ? @store.store : @store
        return [] unless raw.respond_to?(:object_counts)

        counts = raw.object_counts
        @registry.resources.each_with_object({}) do |resource, result|
          key = [resource.group.to_s, resource.resource.to_s]
          next if result.key?(key)

          gvr = resource.respond_to?(:storage_gvr) ? resource.storage_gvr : resource.gvr
          result[key] = counts.fetch("registry/#{gvr}", 0)
        end.map { |(group, name), count| [group, name, count] }
      end

      # The endpoint labels MonitorRequest reports: CleanScope, and the verb
      # as CanonicalVerb + CleanVerb make it (LIST for a collection GET,
      # WATCH, APPLY for an apply patch, CONNECT for the streaming
      # subresources; anything else "other").
      def request_metric_labels(request, route)
        resource = route&.resource_route? ? route.resource : nil
        subresource = route&.subresource
        name = resource ? (subresource ? "#{resource.resource}/#{subresource}" : resource.resource) : (route&.kind || "unknown").to_s
        method = request.method.to_s.upcase
        scope = if resource && (route.name || method == "POST")
                  "resource"
                elsif resource && route.namespace
                  "namespace"
                elsif resource
                  "cluster"
                else
                  ""
                end
        verb = method
        verb = scope == "resource" || scope.empty? ? "GET" : "LIST" if %w[GET HEAD].include?(method)
        verb = "WATCH" if method == "GET" && watch_request?(request)
        verb = "APPLY" if method == "PATCH" && request.header("content-type").to_s.split(";").first.to_s.strip == APPLY_PATCH_TYPE
        verb = "CONNECT" if resource && CONNECT_SUBRESOURCES.include?(subresource.to_s)
        verb = "other" unless %w[APPLY CONNECT CREATE DELETE DELETECOLLECTION GET LIST PATCH POST PROXY PUT UPDATE WATCH
                                 WATCHLIST].include?(verb)
        {verb: verb, resource: name, group: resource ? resource.group : "", version: resource ? resource.version : "", scope: scope}
      end

      # A watch or a streaming subresource whose stream (or upgraded
      # connection) outlives this call: the same response, metered until it
      # ends; nil for everything else.
      def long_running_response(request, route, response, started, webhook_seconds)
        return nil unless @metrics && request && route&.resource_route? && response.is_a?(Response)

        watch = request.method == "GET" && watch_request?(request)
        return nil unless watch || LONG_RUNNING_SUBRESOURCES.include?(route.subresource.to_s)

        streamed = response.stream? && response.body.respond_to?(:each) && !response.body.is_a?(String)
        return nil unless streamed || response.upgrade?

        labels = Observability::Metrics.request_labels(**request_metric_labels(request, route))
        finish = -> { record_request_metric(request, route, response, started, webhook_seconds: webhook_seconds, slow_log: false) }
        if response.upgrade?
          upgrade = response.upgrade
          metrics = @metrics
          metered = lambda do |*arguments|
            metrics.longrunning(labels, 1)
            begin
              upgrade.call(*arguments)
            ensure
              metrics.longrunning(labels, -1)
              finish.call
            end
          end
          return Response.new(status: response.status, headers: response.headers, body: response.body, stream: response.stream?,
                              upgrade: metered, unbounded: response.unbounded?, encoded_body: response.encoded_body)
        end

        resource = route.resource
        events = watch ? {"group" => resource.group.to_s, "version" => resource.version.to_s, "resource" => resource.resource.to_s} : nil
        watch_list = if watch && truthy?(query(request, "sendInitialEvents")) && feature_gate_enabled?("WatchList")
                       {labels: events.merge("scope" => labels["scope"]), started: started}
                     end
        body = LongRunningBody.new(response.body, metrics: @metrics, labels: labels, watch: events, finish: finish, watch_list: watch_list)
        Response.new(status: response.status, headers: response.headers, body: body, stream: true, unbounded: response.unbounded?,
                     encoded_body: response.encoded_body)
      rescue StandardError
        nil
      end

      # /metrics in the Prometheus text format every Kubernetes component
      # serves.  Requests are counted as they are answered, so the endpoint
      # reflects this process rather than a static document.
      def metrics_response
        body = @metrics ? @metrics.render : ""
        Response.new(status: 200,
                     headers: {"content-type" => Observability::Metrics::CONTENT_TYPE, "cache-control" => "no-cache, private"},
                     body: body)
      end

      # /metrics/slis: the health check SLIs (component-base slis.Registry).
      def slis_response
        Response.new(status: 200,
                     headers: {"content-type" => Observability::Metrics::CONTENT_TYPE, "cache-control" => "no-cache, private"},
                     body: health_slis.render)
      end

      HEALTH_SLIS_MUTEX = Mutex.new

      def health_slis
        @health_slis || HEALTH_SLIS_MUTEX.synchronize { @health_slis ||= Observability::HealthcheckSLIs.new }
      end

      # The checks the root health handlers run: the handler itself (ping),
      # and on /readyz the datastore (etcd-readiness).
      def observe_health_checks(path, ready)
        type = Observability::HealthcheckSLIs.type_for(path)
        return unless type

        health_slis.observe("ping", type, true)
        health_slis.observe("etcd-readiness", type, ready) if type == "readyz"
      rescue StandardError
        nil
      end

      def health_response(path)
        observe_health_checks(path, path != "/readyz" || ready?)
        return Response.new(status: 500, headers: {"content-type" => "text/plain; charset=utf-8",
                                                   "cache-control" => "no-cache, private",
                                                   "x-content-type-options" => "nosniff"}, body: "not ready") if path == "/readyz" && !ready?

        Response.new(status: 200, headers: {"content-type" => "text/plain; charset=utf-8",
                                             "cache-control" => "no-cache, private",
                                             "x-content-type-options" => "nosniff"}, body: "ok")
      end

      # kube-apiserver routes an unserved discovery group/version through the
      # generic HTTP not-found handler rather than the Kubernetes Status
      # serializer. Clients observe this exact plain-text body and the
      # nosniff/content headers, including for APIs disabled by feature gates.
      def discovery_not_found_response
        Response.new(
          status: 404,
          headers: {
            "cache-control" => "no-cache, private",
            "content-type" => "text/plain; charset=utf-8",
            "x-content-type-options" => "nosniff"
          },
          body: "404 page not found\n"
        )
      end

      def openapi_response(request, route)
        document = @openapi.document_for(route.path)
        raise Status::NotFound.new("OpenAPI document was not found") if document.nil?

        protobuf = route.path == "/openapi/v2" && OpenAPIV2Protobuf.accepts?(request.header("accept"))
        content_type = protobuf ? OpenAPIV2Protobuf::RESPONSE_CONTENT_TYPE : "application/json"
        bytes, etag = openapi_encoded(route.path, document, protobuf)
        headers = {"content-type" => content_type, "cache-control" => "no-cache, private", "etag" => %("#{etag}")}
        return Response.new(status: 304, headers: headers, body: "") if etag_matches?(request.header("if-none-match"), etag)
        return Response.new(status: 200, headers: headers, body: bytes) if protobuf

        Response.new(status: 200, headers: headers, body: document, encoded_body: bytes)
      end

      # kube-openapi serves every spec with an ETag (hex SHA-512 of the bytes)
      # and answers a matching If-None-Match with 304.  The CRD publishing
      # specs poll /openapi/v2 over fresh connections until ten reads in a
      # row agree; without the ETag each read re-sent -- and the client
      # re-parsed -- the whole 3 MB swagger document.  The encoding of one
      # document object is kept: the repository hands out the same object
      # until a definition is published or withdrawn.
      def openapi_encoded(path, document, protobuf)
        key = [path.to_s, protobuf]
        cached = @openapi_encoded_mutex.synchronize { @openapi_encoded[key] }
        return cached.last if cached && cached.first.equal?(document)

        bytes = protobuf ? OpenAPIV2Protobuf.encode(document) : JSON.generate(document)
        encoded = [bytes, Digest::SHA512.hexdigest(bytes).upcase]
        @openapi_encoded_mutex.synchronize { @openapi_encoded[key] = [document, encoded] }
        encoded
      end

      def etag_matches?(header, etag)
        return false if header.nil? || header.to_s.strip.empty?

        header.to_s.split(",").any? do |candidate|
          value = candidate.strip.delete_prefix("W/")
          value == "*" || value.delete_prefix('"').delete_suffix('"') == etag
        end
      end

      def json_response(body, status: 200)
        Response.new(status: status, headers: {"content-type" => "application/json",
                                               "cache-control" => "no-cache, private"}, body: body)
      end

      def error_response(error)
        status = error.respond_to?(:to_status) ? error.to_status : Status.failure(message: error.message, code: 500, reason: "InternalError")
        headers = {"content-type" => "application/json", "cache-control" => "no-cache, private"}
        headers["www-authenticate"] = "Bearer" if status.fetch("code") == 401
        # ErrorNegotiated: Retry-After only for a positive retryAfterSeconds.
        headers["retry-after"] = status.dig("details", "retryAfterSeconds").to_s if status.dig("details", "retryAfterSeconds").to_i.positive?
        Response.new(status: status.fetch("code"), headers: headers, body: status)
      end

      def authenticate_request(request)
        unless request.respond_to?(:identity) && request.identity.nil? && @identity_resolver
          return impersonate(request)
        end

        identity = invoke_identity_resolver(request)
        impersonate(request.with(identity: identity))
      rescue Status::Error
        raise
      rescue StandardError => error
        raise Status::Unauthorized.new("request authentication failed"), cause: error
      end

      # Impersonation without the security pipeline (a server given only an
      # identity resolver and an authorizer): the legacy `impersonate` filter
      # of k8s.io/apiserver/pkg/endpoints/filters/impersonation.  With the
      # pipeline, impersonation already happened there and the Impersonate-*
      # headers are gone.
      def impersonate(request)
        return request unless request.respond_to?(:headers) && Security::Impersonation.requested?(request)

        filter = (@legacy_impersonation ||= Security::Impersonation::Filter.new(ImpersonationAuthorizer.new(@impersonation_authorizer),
                                                                                  constrained: false))
        wanted = filter.wanted_user(request)
        return request unless wanted

        requester = request.identity
        raise Status::Unauthorized.new("impersonation requires an authenticated request") if requester.nil?

        requester = requester.is_a?(String) ? Security::UserInfo.new(name: requester) : Security::UserInfo.from_h(requester)
        attributes = Security::Authorization::Attributes.new(user: requester, verb: "", path: request.path, resource_request: false)
        result = filter.impersonate(wanted, attributes)
        Security::Impersonation.strip_headers(request).with(identity: result.user.to_h)
      rescue Security::Impersonation::BadRequest => error
        raise Status::BadRequest.new(error.message)
      rescue Security::Impersonation::Forbidden => error
        raise Status::Forbidden.new(error.message, details: error.details)
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

      def subresource_object(route)
        namespace = storage_namespace(route, operation: :get)
        @store.get(resource: route.resource, namespace: namespace, name: route.name)
      rescue MemoryStore::NotFound
        raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                   details: resource_details(route))
      end

      def normalize_object(request, route)
        body = request_body(request)
        raise Status::Invalid.new("request body must be a JSON object") unless body.is_a?(Hash)
        # A JSON or protobuf body was just decoded into a fresh object with
        # String keys (request_body keeps nothing): copying it again was a
        # tenth of a Pod PUT's normalization.  A Hash handed in-process, or
        # YAML (whose keys need not be Strings), is still copied.
        fresh = request.body.is_a?(String) && !request.content_type.to_s.include?("yaml")
        object = fresh ? body : stringify_keys(body)
        validate_route_identity!(object, route)
        object["apiVersion"] ||= route_identity(route).fetch(:api_version)
        object["kind"] ||= route_identity(route).fetch(:kind)
        object["metadata"] = stringify_keys(object["metadata"] || {})
        # kube-apiserver decodes a JSON null for a map, slice or pointer field of
        # a typed object as "absent" and never serves it back; a stored
        # "annotations": null reached every Pod a Job created from such a
        # template and crashed node admission.  Custom resources keep their
        # own nullable/pruning rules, but ObjectMeta is typed for every kind.
        custom = route.respond_to?(:resource) && route.resource.respond_to?(:custom?) && route.resource.custom?
        if custom
          drop_null_fields!(object["metadata"])
        else
          drop_null_fields!(object)
        end
        object
      end

      def drop_null_fields!(value)
        case value
        when Hash
          value.delete_if { |_key, entry| entry.nil? }
          value.each_value { |entry| drop_null_fields!(entry) }
        when Array
          value.each { |entry| drop_null_fields!(entry) }
        end
        value
      end

      # sigs.k8s.io/json reports duplicate JSON object keys as strict violations.
      # Ruby's JSON parser keeps only the last of a duplicate pair, so the raw
      # body is scanned separately for repeated keys within one object.
      def request_duplicate_fields(request)
        body = request.body
        return [] unless body.is_a?(String) && !body.empty?

        media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
        return [] if media_type == Negotiation::PROTOBUF_TYPE

        text = body.dup.force_encoding(Encoding::UTF_8)
        return [] unless text.valid_encoding?

        begin
          duplicate_json_paths(text)
        rescue StandardError
          []
        end
      end

      # gopkg.in/yaml.v2, reached through sigs.k8s.io/yaml YAMLToJSONStrict,
      # refuses a repeated mapping key and names the line it found it on.  The
      # apiserver runs the body through it a second time purely to catch that
      # (runtime/serializer/json/json.go Serializer.unmarshal: "pass the
      # original data through the YAMLToJSONStrict converter ... to catch
      # duplicate fields in YAML that would have been dropped") and passes the
      # whole multi-line error through as ONE strict-decoding violation.  Ruby
      # and Go both keep the last of a repeated key, so without this a YAML
      # body could repeat any field and a Strict request would accept it.
      YAML_STRICT_PREFIX = "yaml: unmarshal errors:\n"

      YAML_MEDIA_TYPES = ["application/yaml", "application/x-yaml", "text/yaml",
                          "application/apply-patch+yaml"].freeze

      def request_duplicate_yaml_errors(request)
        body = request.body
        return [] unless body.is_a?(String) && !body.empty?

        media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
        return [] unless YAML_MEDIA_TYPES.include?(media_type)

        text = body.dup.force_encoding(Encoding::UTF_8)
        return [] unless text.valid_encoding?

        duplicates = begin
          duplicate_yaml_keys(text)
        rescue StandardError
          # A body YAML cannot parse at all is a decoding failure the normal
          # path reports; it is not a duplicate-key finding.
          []
        end
        return [] if duplicates.empty?

        [YAML_STRICT_PREFIX + duplicates.map do |line, key|
          "  line #{line}: key #{key.inspect} already set in map"
        end.join("\n")]
      end

      # [[line, key], ...] in document order, 1-based lines, matching the
      # yaml.v2 decoder's own report.
      def duplicate_yaml_keys(text)
        found = []
        visit = lambda do |node|
          if node.is_a?(Psych::Nodes::Mapping)
            seen = {}
            node.children.each_slice(2) do |key, value|
              name = key.respond_to?(:value) && key.is_a?(Psych::Nodes::Scalar) ? key.value.to_s : nil
              if name.nil?
                visit.call(key)
              elsif seen.key?(name)
                found << [key.start_line + 1, name]
              else
                seen[name] = true
              end
              visit.call(value) unless value.nil?
            end
          else
            Array(node.respond_to?(:children) ? node.children : nil).each { |child| visit.call(child) }
          end
        end
        Psych.parse_stream(text).children.each { |document| visit.call(document) }
        found
      end

      # For Warn the apiserver splits the same block back into one warning per
      # line (endpoints/handlers/rest.go parseYAMLWarnings).
      def split_yaml_strict_error(message)
        text = message.to_s
        return [text] unless text.start_with?(YAML_STRICT_PREFIX)

        text.delete_prefix(YAML_STRICT_PREFIX).split("\n").map(&:strip).reject(&:empty?)
      end

      def duplicate_json_paths(text)
        scanner = StringScanner.new(text)
        duplicates = []
        stack = []
        seen = []
        pending_key = nil
        until scanner.eos?
          if scanner.scan(/\s+/)
            next
          elsif scanner.scan(/\{/)
            stack.push(pending_key)
            seen.push({})
            pending_key = nil
          elsif scanner.scan(/\}/)
            stack.pop
            seen.pop
          elsif scanner.scan(/\[/)
            stack.push(pending_key)
            seen.push(nil)
            pending_key = nil
          elsif scanner.scan(/\]/)
            stack.pop
            seen.pop
          elsif (literal = scanner.scan(/"(?:\\.|[^"\\])*"/))
            if seen.last.is_a?(Hash) && scanner.check(/\s*:/)
              key = JSON.parse(literal).to_s
              path = (stack.compact + [key]).join(".")
              duplicates << path if seen.last.key?(key)
              seen.last[key] = true
              pending_key = key
            end
          else
            scanner.getch
          end
        end
        duplicates.uniq
      end

      def request_body(request)
        body = request.body
        return {} if body.nil?
        return {} if body.is_a?(String) && body.empty?
        return body unless body.is_a?(String)
        media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
        unless media_type == Negotiation::PROTOBUF_TYPE
          # JSON and YAML bodies must be valid UTF-8 (RFC 8259); anything else
          # is a 400, never an exception from the encoder later on.
          text = body.dup.force_encoding(Encoding::UTF_8)
          raise Status::BadRequest.new("request body is not valid UTF-8") unless text.valid_encoding?
          raise Status::BadRequest.new("request body contains a NUL byte") if text.include?("\0")

          body = text
        end
        # A request that names no Content-Type is JSON, the way kube-apiserver
        # treats it.  Asking a nil for #include? turned every such request --
        # a Binding posted by a client that omits the header among them --
        # into a 500.
        content_type = request.content_type.to_s
        if media_type == Negotiation::PROTOBUF_TYPE
          decode_protobuf_body(body)
        elsif content_type.include?("yaml")
          YAML.safe_load(body, permitted_classes: [], aliases: false) || {}
        else
          JSON.parse(body)
        end
      end

      # Kubernetes protobuf bodies arrive as the runtime.Unknown envelope that
      # typed client-go clients send; decoding yields the same JSON-shaped
      # object the rest of the server works with.
      def decode_protobuf_body(body)
        protobuf_codec.decode(body.b)
      rescue Schema::Codec::KubernetesProtobuf::Error, Schema::Codec::ParseError => error
        raise Status::BadRequest.new("request body is not valid Kubernetes protobuf: #{error.message}")
      end

      def protobuf_codec
        @protobuf_codec ||= Schema::Codec::KubernetesProtobuf.new
      end

      # Encodes the decoded response body according to the Accept header, the
      # way k8s.io/apiserver negotiates serializers: JSON (the transport's
      # default), YAML, or Kubernetes protobuf, and for watch streams the
      # length-prefixed protobuf WatchEvent framing.  Bodies that are not
      # decoded API objects (text health endpoints, upgraded connections,
      # explicitly typed responses) pass through unchanged.
      def finalize_response(request, response, route: nil)
        return response if request.nil? || response.nil? || response.upgrade?

        response = with_warning_headers(request, response)
        return response if route && route.kind == :openapi
        content_type = response.header("content-type").to_s
        return response unless content_type.empty? || content_type.start_with?("application/json")

        accept = request.header("accept")
        body = response.body
        if response.stream? && !body.is_a?(String) && body.respond_to?(:each)
          # A watch converts each event's object as a GET would: Table (JSON
          # only, headers on the first event alone) or PartialObjectMetadata.
          watch_convertible = route && route.resource_route? && request.method == "GET"
          selection = Negotiation.negotiate_output(accept, supported: Negotiation::STREAM_TYPES, stream: true, table: watch_convertible)
          if watch_convertible && (selection.table? || selection.partial_metadata?)
            body = transform_watch_events(body, selection, request, route)
            response = Response.new(status: response.status, headers: response.headers, body: body, stream: true,
                                    unbounded: response.unbounded?)
          end
          return response unless selection.protobuf?

          codec = protobuf_codec
          framed = Enumerator.new do |yielder|
            body.each { |event| yielder << encode_watch_frame(codec, event) }
          end
          return Response.new(status: response.status, headers: response.headers.merge("content-type" => selection.content_type),
                              body: framed, stream: true, unbounded: response.unbounded?)
        end
        return response unless body.is_a?(Hash)

        # Table/PartialObjectMetadata conversion applies to a successful read
        # of a resource; a Status or a subresource body is served as-is.
        convertible = response.status < 300 && route && route.resource_route? &&
                      %w[GET HEAD].include?(request.method) && body["kind"].to_s != "Status"
        selection = Negotiation.negotiate_output(accept, supported: Negotiation::STANDARD_TYPES, table: convertible)
        if convertible && selection.table?
          table = table_body(body, selection, request, route)
          if table
            body = table
            response = Response.new(status: response.status, headers: response.headers, body: table, stream: false)
          end
        elsif convertible && selection.partial_metadata?
          body = partial_metadata_body(body, selection)
          response = Response.new(status: response.status, headers: response.headers, body: body, stream: false)
        end
        if selection.protobuf?
          api_version = body["apiVersion"].to_s
          kind = body["kind"].to_s
          unless !api_version.empty? && !kind.empty? && protobuf_codec.supports?(api_version: api_version, kind: kind)
            # An Accept header lists media types in order of preference, so a
            # body that cannot be protobuf-encoded is served as the next type
            # the client accepts -- /version and the discovery documents are
            # not protobuf-encodable, and client-go asks for
            # "application/vnd.kubernetes.protobuf, application/json" by
            # default.  406 is correct only when nothing acceptable is left.
            selection = negotiate_without_protobuf(accept, convertible, kind)
          end
        end
        if selection.protobuf?
          Response.new(status: response.status, headers: response.headers.merge("content-type" => Negotiation::PROTOBUF_TYPE),
                       body: protobuf_codec.encode(body), stream: false)
        elsif selection.yaml?
          Response.new(status: response.status, headers: response.headers.merge("content-type" => Negotiation::YAML_TYPE),
                       body: Negotiation.dump_yaml(body), stream: false)
        else
          response
        end
      rescue Status::NotAcceptable, Status::Error => error
        error_response(error)
      end

      # Re-negotiates with protobuf removed from what the server can produce.
      # Raises NotAcceptable when the client accepts nothing else.
      def negotiate_without_protobuf(accept, convertible, kind)
        supported = Negotiation::STANDARD_TYPES.reject { |type| type == Negotiation::PROTOBUF_TYPE }
        Negotiation.negotiate_output(accept, supported: supported, table: convertible)
      rescue Status::NotAcceptable
        raise Status::NotAcceptable.new("#{kind.to_s.empty? ? "the response" : kind} cannot be encoded as #{Negotiation::PROTOBUF_TYPE}")
      end

      # TableOptions.includeObject (ValidateTableOptions): Metadata when
      # empty, and anything but Metadata, Object or None is a bad request.
      def table_include_object(request)
        value = query(request, "includeObject").to_s
        return "Metadata" if value.empty?
        return value if %w[Object Metadata None].include?(value)

        raise Status::BadRequest.new("Unable to convert to Table as requested: includeObject: Invalid value: #{value.inspect}: " \
                                     "must be 'Metadata', 'Object', 'None', or empty")
      end

      def meta_api_version(selection)
        "#{Negotiation::META_GROUP}/#{selection.convert.fetch(:version)}"
      end

      # The TableConvertor registered for the route's resource: a custom
      # resource's served-version printer columns, otherwise chosen by kind.
      def table_convertor(route)
        resource = route&.resource
        resource = @registry.find_gvr(group: route.group.to_s, version: route.version.to_s, resource: resource.to_s) if resource && !resource.is_a?(Resource)
        return nil unless resource.respond_to?(:custom?) && resource.custom?
        return nil if route.subresource && !route.subresource.to_s.empty? && route.subresource.to_s != "status"

        [:crd, TablePrinter.crd_columns(resource.printer_columns)]
      end

      def table_body(body, selection, request, route, no_headers: false)
        TablePrinter.table_for(body, include_object: table_include_object(request), now: @clock.call.utc, no_headers: no_headers,
                                     convertor: table_convertor(route), api_version: meta_api_version(selection))
      rescue TablePrinter::PrintError => error
        raise Status::Error.new(message: error.message, code: 500, reason: "InternalError")
      end

      # asPartialObjectMetadata / asPartialObjectMetadataList: the metadata
      # alone, and a 406 when the object and the requested kind disagree.
      def partial_metadata_body(body, selection)
        api_version = meta_api_version(selection)
        wanted = selection.convert.fetch(:kind)
        list = body["kind"].to_s.end_with?("List") && body["items"].is_a?(Array)
        if wanted == "PartialObjectMetadata" && list
          raise Status::NotAcceptable.new("you requested PartialObjectMetadata, but the requested object is a list (#{body["kind"]})")
        end
        if wanted == "PartialObjectMetadataList" && !list
          raise Status::NotAcceptable.new("you requested PartialObjectMetadataList, but the requested object is not a list (#{body["kind"]})")
        end

        partial = ->(item) { {"kind" => "PartialObjectMetadata", "apiVersion" => api_version, "metadata" => item["metadata"] || {}} }
        return partial.call(body) unless list

        metadata = body["metadata"].is_a?(Hash) ? body["metadata"] : {}
        {"kind" => "PartialObjectMetadataList", "apiVersion" => api_version,
         "metadata" => metadata.slice("resourceVersion", "continue", "remainingItemCount"),
         "items" => body["items"].map { |item| partial.call(item) }}
      end

      # watchEmbeddedEncoder: every event object is transformed (a Status in
      # an ERROR event is left alone), and a Table carries its column
      # definitions on the first event only.
      def transform_watch_events(events, selection, request, route)
        table = selection.table?
        include_object = table_include_object(request) if table
        headers_sent = false
        Enumerator.new do |yielder|
          events.each do |event|
            hash = (event.is_a?(Hash) ? event : event.to_h).transform_keys(&:to_s)
            object = hash["object"]
            if object.is_a?(Hash) && object["kind"].to_s != "Status"
              hash["object"] = if table
                                 converted = TablePrinter.table_for(object, include_object: include_object, now: @clock.call.utc,
                                                                            no_headers: headers_sent, convertor: table_convertor(route),
                                                                            api_version: meta_api_version(selection))
                                 headers_sent = true
                                 converted
                               else
                                 {"kind" => "PartialObjectMetadata", "apiVersion" => meta_api_version(selection),
                                  "metadata" => object["metadata"] || {}}
                               end
            end
            yielder << hash
          rescue TablePrinter::PrintError
            yielder << hash
          end
        end
      end

      def encode_watch_frame(codec, event)
        hash = event.is_a?(Hash) ? event : event.to_h
        hash = hash.transform_keys(&:to_s)
        codec.encode_watch_frame(hash.fetch("type"), hash.fetch("object"))
      end

      def patch_document(request, patch_type)
        body = request_body(request)
        if patch_type == :json && !body.is_a?(Array)
          raise Status::Invalid.new("JSON Patch body must be an array")
        end
        body
      end

      def normalize_apply_document(document, route)
        raise Status::Invalid.new("server-side apply body must be a JSON/YAML object") unless document.is_a?(Hash)
        result = stringify_keys(document)
        validate_route_identity!(result, route)
        result["apiVersion"] ||= route_identity(route).fetch(:api_version)
        result["kind"] ||= route_identity(route).fetch(:kind)
        result["metadata"] = stringify_keys(result["metadata"] || {})
        result["metadata"]["name"] ||= route.name
        result
      end

      # A PATCH route identifies a concrete GVR, so an apply document cannot
      # silently target another GVK. Kubernetes returns an Invalid (422)
      # Status with one cause per mismatching identity field.
      def validate_route_identity!(object, route)
        causes = []
        identity = route_identity(route)
        expected_api_version = identity.fetch(:api_version)
        expected_kind = identity.fetch(:kind)
        if object.key?("apiVersion") && object["apiVersion"].to_s != expected_api_version
          causes << {
            "reason" => "FieldValueInvalid",
            "message" => "apiVersion #{object["apiVersion"].inspect} does not match #{expected_api_version.inspect}",
            "field" => "apiVersion"
          }
        end
        if object.key?("kind") && object["kind"].to_s != expected_kind
          causes << {
            "reason" => "FieldValueInvalid",
            "message" => "kind #{object["kind"].inspect} does not match #{expected_kind.inspect}",
            "field" => "kind"
          }
        end
        return if causes.empty?

        raise Status::Invalid.new(
          "resource body does not match the requested #{expected_api_version}, Kind=#{expected_kind}",
          details: resource_details(route).merge("apiVersion" => expected_api_version,
                                                 "causes" => causes)
        )
      end

      def route_identity(route)
        subresource = route.subresource && route.resource.subresource(route.subresource)
        advertised_group = subresource&.advertised_group(route.resource.group)
        advertised_version = subresource&.advertised_version(route.resource.group, route.resource.version)
        {
          api_version: if advertised_group && advertised_version
                         advertised_group.to_s.empty? ? advertised_version.to_s : "#{advertised_group}/#{advertised_version}"
                       else
                         route.resource.api_version
                       end,
          kind: subresource&.kind || route.resource.kind
        }
      end

      def selectors_from(request)
        Selectors.new(label_selector: query(request, "labelSelector"), field_selector: query(request, "fieldSelector"))
      end

      def query(request, key)
        request.query_value(key)
      end

      def integer_query(request, key)
        value = query(request, key)
        return nil if value.nil? || value.to_s.empty?
        integer = Integer(value)
        if integer.negative?
          raise Status::BadRequest.new(
            "query parameter #{key} must be a non-negative integer",
            details: {"causes" => [{"reason" => "FieldValueInvalid",
                                     "message" => "must be a non-negative integer",
                                     "field" => key}]}
          )
        end

        integer
      rescue ArgumentError, TypeError
        raise Status::BadRequest.new(
          "query parameter #{key} must be an integer",
          details: {"causes" => [{"reason" => "FieldValueInvalid",
                                   "message" => "must be an integer",
                                   "field" => key}]}
        )
      end

      def truthy?(value)
        %w[1 true yes].include?(value.to_s.downcase)
      end

      def watch_request?(request)
        request.method == "GET" && truthy?(query(request, "watch"))
      end

      def api_verb_for(request, route)
        method = request.method
        return "watch" if method == "GET" && watch_request?(request)
        return "list" if %w[GET HEAD].include?(method) && route.collection
        return "get" if %w[GET HEAD].include?(method)
        return "create" if method == "POST"
        return "update" if method == "PUT"
        return "patch" if method == "PATCH"
        return "deletecollection" if method == "DELETE" && route.collection
        return "delete" if method == "DELETE"

        method.downcase
      end

      def storage_namespace(route, operation:)
        return :cluster if route.resource.cluster_scoped?
        return route.namespace unless route.namespace.nil?
        return :all if operation == :list || operation == :watch

        raise Status::Invalid.new("namespace is required for #{operation} on namespaced resources")
      end

      def require_collection!(route)
        raise Status::Invalid.new("operation requires a resource collection") unless route.collection
      end

      def require_member!(route)
        raise Status::Invalid.new("operation requires a named resource") if route.collection || route.name.nil?
      end

      def ensure_name!(object, expected_name)
        actual = metadata_value(object, "name")
        return if actual.to_s.empty? || actual.to_s == expected_name.to_s

        raise Status::Invalid.new("metadata.name #{actual.inspect} does not match URL name #{expected_name.inspect}")
      end

      def ensure_expected_version!(existing, expected)
        actual = metadata_value(existing, "resourceVersion").to_s
        return if expected.to_s == actual

        raise Status::Conflict.new("resourceVersion #{expected.inspect} does not match current #{actual.inspect}")
      end

      def preserve_metadata(object, existing)
        # Only metadata changes here: copy it and the top level, and share
        # the rest -- the request's object was already copied into string
        # keys by normalize_object and the caller drops it.
        result = object.transform_keys(&:to_s)
        result["metadata"] = result["metadata"].is_a?(Hash) ? result["metadata"].transform_keys(&:to_s) : {}
        existing_metadata = existing["metadata"] || {}
        # ValidateObjectMetaUpdate treats these as immutable; upstream's
        # registry preserves them from the stored object rather than taking
        # whatever the client sent.  deletionGracePeriodSeconds belongs to the
        # same set -- a client must not be able to shorten or clear the grace
        # period the API server granted.
        %w[uid creationTimestamp deletionTimestamp deletionGracePeriodSeconds].each do |key|
          if existing_metadata.key?(key)
            result["metadata"][key] = deep_copy(existing_metadata[key])
          else
            result["metadata"].delete(key)
          end
        end
        # generation never goes backwards.
        if existing_metadata.key?("generation") && result["metadata"]["generation"].to_i < existing_metadata["generation"].to_i
          result["metadata"]["generation"] = existing_metadata["generation"]
        end
        result["metadata"]["namespace"] = existing_metadata["namespace"] if existing_metadata.key?("namespace")
        result
      end

# E2 status writes keep metadata unless the kind's status strategy resets it
      # Kinds whose status strategy calls rest.ResetObjectMetaForStatus
      # (pkg/registry/**/strategy.go): only these discard metadata changes
      # sent on the status subresource.  Every other kind (Namespace,
      # Deployment, ...) applies labels/annotations/finalizers/ownerReferences
      # from a status write, and the conformance suite relies on it.
      STATUS_META_RESET_KINDS = %w[
        Pod ServiceCIDR VolumeAttachment ResourceClaim DeviceTaintRule StorageVersionMigration
        ResourcePoolStatusRequest PodGroup ValidatingAdmissionPolicy PodCertificateRequest StorageVersion
      ].freeze
      STATUS_META_UPDATABLE_FIELDS = %w[labels annotations finalizers ownerReferences].freeze

      # The /approval subresource of a CertificateSigningRequest writes exactly
      # one thing: the approval conditions.  registry/certificates/
      # certificates/strategy.go approvalStrategy#PrepareForUpdate --
      # "Updating the approval should only update the conditions" -- resets the
      # spec to the stored one and keeps the stored status apart from
      # conditions, while the request's metadata (its annotations) applies
      # normally.  Treating it like any non-status subresource discarded the
      # conditions entirely, so a patch to /approval came back with none and
      # "[sig-auth] Certificates API should support CSR API operations"
      # reported "patched object should have the applied condition".
      APPROVAL_STATUS_FIELDS = %w[conditions].freeze

      def approval_subresource?(route)
        route.subresource.to_s == "approval" &&
          route.resource.respond_to?(:kind) && route.resource.kind.to_s == "CertificateSigningRequest"
      end

      def approval_update(existing, candidate)
        object = deep_copy(candidate)
        object["spec"] = deep_copy(existing["spec"]) if existing.key?("spec")
        status = deep_copy(existing["status"] || {})
        submitted = candidate["status"].is_a?(Hash) ? candidate["status"] : {}
        APPROVAL_STATUS_FIELDS.each do |field|
          next unless submitted.key?(field)

          status[field] = deep_copy(submitted[field])
        end
        status["conditions"] = populate_condition_timestamps(status["conditions"], existing.dig("status", "conditions"))
        status.delete("conditions") if status["conditions"].nil?
        object["status"] = status
        object
      end

      # strategy.go populateConditionTimestamps: a condition the client sent
      # without timestamps gets them, and one whose status has not changed
      # keeps the transition time it already had.
      def populate_condition_timestamps(conditions, previous)
        return nil unless conditions.is_a?(Array)

        now = @clock.call.utc.iso8601
        existing = Array(previous)
        conditions.map do |value|
          condition = value.is_a?(Hash) ? deep_copy(value) : value
          next condition unless condition.is_a?(Hash)

          condition["lastUpdateTime"] = now if condition["lastUpdateTime"].to_s.empty?
          if condition["lastTransitionTime"].to_s.empty?
            matching = existing.find { |old| old.is_a?(Hash) && old["type"].to_s == condition["type"].to_s }
            condition["lastTransitionTime"] = if matching && matching["status"].to_s == condition["status"].to_s &&
                                                 !matching["lastTransitionTime"].to_s.empty?
                                                matching["lastTransitionTime"]
                                              else
                                                now
                                              end
          end
          condition
        end
      end

      def status_update(existing, candidate, resource: nil)
        result = deep_copy(existing)
        result["status"] = deep_copy(candidate["status"] || {})
        result["metadata"] ||= {}
        metadata = candidate.is_a?(Hash) && candidate["metadata"].is_a?(Hash) ? candidate["metadata"] : {}
        kind = resource.respond_to?(:kind) ? resource.kind.to_s : nil
        unless kind && STATUS_META_RESET_KINDS.include?(kind)
          STATUS_META_UPDATABLE_FIELDS.each do |field|
            next unless metadata.key?(field)

            if metadata[field].nil?
              result["metadata"].delete(field)
            else
              result["metadata"][field] = deep_copy(metadata[field])
            end
          end
        end
        fields = metadata["managedFields"]
        result["metadata"]["managedFields"] = deep_copy(fields) if fields
        # "the Pod QoS is immutable and populated at creation time by the
        # kube-apiserver ... backfill it" (registry/core/pod/strategy.go:225).
        # A kubelet that omits qosClass from its status write must not erase it.
        if kind == "Pod"
          status = result["status"] ||= {}
          previous_qos = existing.dig("status", "qosClass")
          status["qosClass"] = previous_qos if status["qosClass"].to_s.empty? && !previous_qos.to_s.empty?
        end
        result
      end

      # kube-apiserver serves the whole object from the status subresource
      # (GET and after PUT/PATCH); only the writable fields differ.
      def status_view(object)
        object
      end

      # Kubernetes `?fieldValidation=` handling.  The directive defaults to Warn
      # (apiserver rest.go fieldValidation); Ignore drops unknown and duplicate
      # fields silently, Warn drops them and reports one warning per violation,
      # Strict fails the request with a BadRequest naming every violation.
      # Unknown fields are dropped from the stored object in every mode.
      FIELD_VALIDATION_DIRECTIVES = %w[Ignore Warn Strict].freeze
      FIELD_MANAGER_MAX_LENGTH = 128
      GO_BOOLS = %w[1 t T TRUE true True 0 f F FALSE false False].freeze

      # metav1 validation ValidateCreateOptions / ValidateUpdateOptions /
      # ValidatePatchOptions: fieldManager (required for an apply, at most
      # 128 bytes, printable), force only on an apply, dryRun "All",
      # fieldValidation Ignore/Warn/Strict -- an Invalid <Kind>.meta.k8s.io.
      def validate_write_options!(request, kind, patch_type: nil)
        force = query(request, "force")
        if !force.nil? && !GO_BOOLS.include?(force.to_s)
          raise Status::BadRequest.new("strconv.ParseBool: parsing #{ManagedFields::Value.go_quote(force.to_s)}: invalid syntax")
        end
        causes = []
        manager = query(request, "fieldManager").to_s
        if %i[apply apply_cbor].include?(patch_type)
          if manager.empty?
            causes << {"reason" => "FieldValueRequired", "message" => "Required value: is required for apply patch", "field" => "fieldManager"}
          end
        elsif patch_type && !force.nil?
          causes << {"reason" => "FieldValueForbidden", "message" => "Forbidden: may not be specified for non-apply patch", "field" => "force"}
        end
        if manager.bytesize > FIELD_MANAGER_MAX_LENGTH
          causes << {"reason" => "FieldValueTooLong", "message" => "Too long: may not be more than #{FIELD_MANAGER_MAX_LENGTH} bytes",
                     "field" => "fieldManager"}
        end
        byte = 0
        manager.each_char do |char|
          unless go_printable?(char)
            causes << {"reason" => "FieldValueInvalid", "field" => "fieldManager",
                       "message" => "Invalid value: #{ManagedFields::Value.go_quote(manager)}: invalid character U+#{format("%04X", char.ord)} (at position #{byte})"}
          end
          byte += char.bytesize
        end
        dry_run = request.respond_to?(:query_values) ? Array(request.query_values("dryRun")) : Array(query(request, "dryRun"))
        unless dry_run.all? { |value| value.to_s == "All" }
          causes << {"reason" => "FieldValueNotSupported", "field" => "dryRun",
                     "message" => "Unsupported value: #{JSON.generate(dry_run.map(&:to_s))}: supported values: \"All\""}
        end
        directive = query(request, "fieldValidation")
        unless directive.nil? || directive.to_s.empty? || FIELD_VALIDATION_DIRECTIVES.include?(directive.to_s)
          causes << {"reason" => "FieldValueNotSupported", "field" => "fieldValidation",
                     "message" => "Unsupported value: #{ManagedFields::Value.go_quote(directive.to_s)}: supported values: \"\", \"Ignore\", \"Strict\", \"Warn\""}
        end
        return if causes.empty?

        rendered = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }
        summary = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
        raise Status::Invalid.new("#{kind}.meta.k8s.io \"\" is invalid: #{summary}",
                                  details: {"group" => "meta.k8s.io", "kind" => kind, "causes" => causes})
      end

      # unicode.IsPrint: letters, marks, numbers, punctuation, symbols and
      # the ASCII space.
      def go_printable?(char)
        char == " " || char.match?(/[\p{L}\p{M}\p{N}\p{P}\p{S}]/)
      end

      def field_validation_directive(request)
        directive = query(request, "fieldValidation").to_s
        return "Warn" if directive.empty?
        unless FIELD_VALIDATION_DIRECTIVES.include?(directive)
          raise Status::BadRequest.new(
            "fieldValidation: Invalid value: #{directive.inspect}: must be one of #{FIELD_VALIDATION_DIRECTIVES.join(", ")}"
          )
        end

        directive
      end

      # `unknown field "spec.foo"` / `duplicate field "metadata.name"`, matching
      # sigs.k8s.io/json strictError.Error().
      def strict_field_violations(resource, object, duplicates: [], yaml_errors: [])
        # sigs.k8s.io/json reports strict errors in the order the decoder met
        # them, and the body a client sends declares its unknown field before
        # it repeats a known one -- which is the order conformance matches on
        # ("unknown field \"spec.unknownField\", duplicate field
        # \"spec.replicas\"").
        violations = []
        schema = resource.respond_to?(:schema) ? resource.schema : nil
        # A custom resource is validated against its CRD's structural schema,
        # which knows exactly which fields it would prune.  Without this a
        # Strict request could smuggle any field at all into a CR.
        if schema.respond_to?(:unknown_fields)
          paths = begin
            Array(schema.unknown_fields(object))
          rescue StandardError
            []
          end
          paths.each { |path| violations << "unknown field #{render_object_path(path).inspect}" }
        end

        validator = if schema.respond_to?(:validator)
                      schema.validator
                    elsif schema.respond_to?(:errors)
                      schema
                    end
        if validator.respond_to?(:errors)
          issues = begin
            validator.errors(object, unknown_fields: :reject)
          rescue StandardError
            []
          end
          Array(issues).each do |issue|
            next unless issue.respond_to?(:code) && issue.code == :unknown_field

            violations << "unknown field #{issue.path.join(".").inspect}"
          end
        end
        # The YAML decoder runs before the typed decoder, so its errors come
        # first: "strict decoding error: yaml: unmarshal errors:\n  line 5:
        # key \"other\" already set in map, unknown field \"unknown\"".
        Array(yaml_errors) + violations + duplicates.map { |path| "duplicate field #{path.inspect}" }
      end

      # "spec.ports[0].unknown" -- the strict decoder's rendering.  The apply
      # type converter prints the same path with a leading dot.
      def render_object_path(path)
        Array(path).each_with_object(+"") do |segment, rendered|
          if segment.is_a?(Integer)
            rendered << "[#{segment}]"
          else
            rendered << "." unless rendered.empty?
            rendered << segment.to_s
          end
        end
      end

      def enforce_field_validation(resource, object, request, duplicates: [], apply: false, document: nil,
                                   yaml_errors: nil)
        directive = field_validation_directive(request)
        yaml_errors = request_duplicate_yaml_errors(request) if yaml_errors.nil?
        violations = strict_field_violations(resource, document.nil? ? object : document,
                                             duplicates: duplicates, yaml_errors: yaml_errors)
        return :prune if violations.empty?

        case directive
        when "Strict"
          raise Status::BadRequest.new(apply_validation_message(resource, violations)) if apply

          kind = resource.respond_to?(:kind) ? resource.kind.to_s : "object"
          version = resource.respond_to?(:version) ? resource.version.to_s : ""
          raise Status::BadRequest.new(
            "#{kind} in version #{version.inspect} cannot be handled as a #{kind}: " \
            "strict decoding error: #{violations.join(", ")}"
          )
        when "Warn"
          violations.each do |violation|
            split_yaml_strict_error(violation).each { |warning| request_warnings(request) << warning }
          end
        end
        :prune
      end

      # Server-side apply reports an undeclared field through the typed
      # converter rather than the strict decoder, and clients match on its
      # wording (test/e2e/apimachinery/field_validation.go expects
      # ".unknownField: field not declared in schema").
      def apply_validation_message(resource, violations)
        kind = resource.respond_to?(:kind) ? resource.kind.to_s : "object"
        api_version = resource.respond_to?(:api_version) ? resource.api_version.to_s : "v1"
        details = violations.map do |violation|
          path = violation[/\Aunknown field "(.*)"\z/, 1]
          path ? ".#{path}: field not declared in schema" : violation
        end
        "failed to create typed patch object (#{api_version}, Kind=#{kind}): #{details.join("; ")}"
      end

      # Not every schema contract accepts a field-validation directive; the ones
      # that do drop undeclared fields, the ones that do not keep their own default.
      def apply_defaulting(target, object, unknown_fields, old = nil)
        if old && target.method(:default).parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :old }
          return target.default(object, unknown_fields: unknown_fields, old: old)
        end

        target.default(object, unknown_fields: unknown_fields)
      rescue ArgumentError
        target.default(object)
      end

      # A mutating webhook adds fields the client never sent -- a whole
      # container, in the conformance spec "should mutate pod and apply
      # defaults after mutation" -- and upstream defaults the patched object
      # again before anything else looks at it
      # (admission/plugin/webhook/mutating/patch.go).  Without that the added
      # container has no terminationMessagePolicy, no imagePullPolicy and no
      # resources.
      def redefault_after_mutation(resource, object, before, unknown_fields: :preserve)
        return object unless object.is_a?(Hash) && object != before

        apply_defaults_only(resource, object, unknown_fields: unknown_fields)
      end

      def apply_defaults_only(resource, object, unknown_fields: :preserve, old: nil)
        schema = resource.respond_to?(:schema) ? resource.schema : nil
        defaulting = schema.respond_to?(:defaulting) ? schema.defaulting : nil
        if defaulting.respond_to?(:apply_hash)
          defaulting.apply_hash(object, unknown_fields: unknown_fields, kubernetes_admission_defaults: true, old: old)
        elsif resource.respond_to?(:default)
          apply_defaulting(resource, object, unknown_fields, old)
        elsif schema.respond_to?(:default)
          apply_defaulting(schema, object, unknown_fields, old)
        else
          object
        end
      end

      def pod_resize_route?(route)
        route.subresource.to_s == "resize" && pod_resource?(route.resource)
      end

      # pkg/registry/core/pod podResizeStrategy PrepareForUpdate
      # (dropNonResizeUpdates): only container/initContainer resources and
      # resizePolicy, and the pod-level resources, come from the request;
      # everything else -- the rest of the spec, the status, labels and
      # annotations -- stays as stored.  Added, removed, renamed or reordered
      # containers are passed through for validation to refuse.
      def resize_update(existing, candidate)
        new_spec = candidate["spec"].is_a?(Hash) ? candidate["spec"] : {}
        old_spec = existing["spec"].is_a?(Hash) ? existing["spec"] : {}
        merged = lambda do |field|
          new_list = Array(new_spec[field])
          old_list = Array(old_spec[field])
          return nil if new_list.length != old_list.length
          return old_list if new_list.empty?

          new_list.each_with_index.map do |container, index|
            return nil unless container.is_a?(Hash) && old_list[index].is_a?(Hash) && container["name"] == old_list[index]["name"]

            deep_copy(old_list[index]).merge("resources" => deep_copy(container["resources"]),
                                            "resizePolicy" => deep_copy(container["resizePolicy"])).compact
          end
        end
        containers = merged.call("containers")
        init_containers = merged.call("initContainers")
        return candidate if containers.nil? || init_containers.nil?

        result = deep_copy(existing)
        result["spec"] = deep_copy(old_spec)
        if feature_gate_enabled?("InPlacePodLevelResourcesVerticalScaling")
          new_spec.key?("resources") ? result["spec"]["resources"] = deep_copy(new_spec["resources"]) : result["spec"].delete("resources")
        end
        result["spec"]["containers"] = containers
        result["spec"]["initContainers"] = init_containers if old_spec.key?("initContainers")
        # ResetObjectMetaForStatus keeps the stored metadata; the request's
        # resourceVersion still guards the write.
        rv = metadata_value(candidate, "resourceVersion")
        result["metadata"]["resourceVersion"] = rv unless rv.nil?
        managed = candidate.dig("metadata", "managedFields")
        result["metadata"]["managedFields"] = managed if managed
        result
      end

      def apply_schema(resource, object, operation: nil, old: nil, unknown_fields: :preserve, subresource: nil)
        # Only a stored object in this very version is a defaulted baseline:
        # a view converted from another storage version was defaulted
        # against that version's schema.
        baseline = if operation.to_s.casecmp?("update") && old.is_a?(Hash) && old.frozen?
                     wanted = resource.group.to_s.empty? ? resource.version.to_s : "#{resource.group}/#{resource.version}"
                     old if old["apiVersion"].to_s == wanted
                   end
        result = apply_defaults_only(resource, object, unknown_fields: unknown_fields, old: baseline)
        schema = resource.schema
        validator = if schema.respond_to?(:validator)
                      schema.validator
                    elsif resource.respond_to?(:validate)
                      resource
                    elsif schema.respond_to?(:validate)
                      schema
                    end
        if validator
          validation = if validator.respond_to?(:validate)
                         validator.validate(result, unknown_fields: :preserve,
                                            operation: operation, old: old, subresource: subresource)
                       else
                         true
                       end
          if validation == false
            raise Status::Invalid.new("resource validation failed")
          elsif validation.is_a?(Array) && !validation.empty?
            causes = validation.map do |cause|
              if cause.is_a?(Hash) then cause.transform_keys(&:to_s)
              elsif cause.respond_to?(:to_cause) then cause.to_cause(result)
              else {"message" => cause.to_s}
              end
            end
            rendered = causes.map { |cause| [cause["field"], cause["message"]].compact.join(": ") }
            name = metadata_value(result, "name")
            body = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
            qualified = resource.group.to_s.empty? ? resource.kind : "#{resource.kind}.#{resource.group}"
            raise Status::Invalid.new("#{qualified} #{name.to_s.inspect} is invalid: #{body}",
                                      details: {"name" => name, "group" => resource.group.to_s, "kind" => resource.kind,
                                                "causes" => causes})
          end
        end
        result
      end

      # +pin_version+: a DELETE of a collection deletes each listed item by
      # name (store.go DeleteCollection calls Delete per item with the
      # client's options, which carry no resourceVersion); pinning the
      # version the listing happened to read turned a Deployment whose status
      # the controller was writing into "expected resourceVersion N, current
      # is M" ("[sig-apps] Deployment should run the lifecycle of a
      # Deployment" deletes via collection).
      def delete_one(resource, namespace, name, object, pin_version: true)
        expected = pin_version ? metadata_value(object, "resourceVersion") : nil
        finalizers = Array(metadata_value(object, "finalizers"))
        if finalizers.any?
          updated = deep_copy(object)
          updated["metadata"]["deletionTimestamp"] ||= @clock.call.utc.iso8601(6)
          @store.update(resource: resource, namespace: namespace, name: name, object: updated,
                        resource_version: expected)
        else
          @store.delete(resource: resource, namespace: namespace, name: name, resource_version: expected)
          release_registry_allocations(resource, object)
        end
      end

      def resource_details(route, name: route.name)
        details = {"kind" => route.resource.resource, "name" => name.to_s}
        details["group"] = route.resource.group unless route.resource.group.to_s.empty?
        details
      end

      # Registry strategy PrepareForCreate hooks for the dynamic API objects:
      # apiextensions clears status and records the storage version, defaults
      # the conversion strategy; kube-aggregator clears status and marks
      # local APIServices available immediately.
      # PrepareForUpdate hooks of the registry strategies that own
      # allocations (Service ClusterIPs and NodePorts follow type changes).
      def prepare_registry_update(resource, existing, object)
        object = drop_stateful_set_disabled_fields(resource, object, existing)
        if csr_resource?(resource) && existing.is_a?(Hash) && object.is_a?(Hash)
          # csrStrategy.PrepareForUpdate: a request is immutable except
          # through its /status and /approval subresources.
          result = deep_copy(object)
          existing.key?("spec") ? result["spec"] = deep_copy(existing["spec"]) : result.delete("spec")
          existing.key?("status") ? result["status"] = deep_copy(existing["status"]) : result.delete("status")
          return result
        end
        return object unless @service_allocator && @service_allocator.service?(resource)

        @service_allocator.prepare_update(existing, object)
      end

      # DRAResourceClaimGranularStatusAuthorization (Beta, on;
      # pkg/registry/resource AuthorizedForBinding / AuthorizedForDeviceStatus):
      # a ResourceClaim status update that changes status.allocation or
      # status.reservedFor also needs <verb> on resourceclaims/binding (the
      # scheduler's "bind claim"), and one that changes a driver's
      # status.devices needs associated-node:<verb> (a service account on the
      # allocated node) or arbitrary-node:<verb> on resourceclaims/driver
      # named after the driver.
      def authorize_resource_claim_status!(request, route, existing, object)
        return unless route.subresource.to_s == "status" && existing.is_a?(Hash) && object.is_a?(Hash)
        return unless route.resource.group.to_s == "resource.k8s.io" && route.resource.resource.to_s == "resourceclaims"
        return unless @security.respond_to?(:authorizer) && (authorizer = @security.authorizer)

        base = request.respond_to?(:attributes) ? request.attributes : nil
        return unless base.is_a?(Security::Authorization::Attributes)

        old_status = existing["status"].is_a?(Hash) ? existing["status"] : {}
        new_status = object["status"].is_a?(Hash) ? object["status"] : {}
        causes = []
        if old_status["allocation"] != new_status["allocation"] || old_status["reservedFor"] != new_status["reservedFor"]
          binding = base.with(subresource: "binding", namespace: "", name: "")
          decision = authorizer.authorize(binding)
          unless decision.allowed?
            causes << {"field" => "status.allocation", "reason" => "FieldValueForbidden",
                       "message" => %(Forbidden: changing status.allocation or status.reservedFor requires resource="resourceclaims/binding", ) +
                                    %(verb="#{base.verb}" permission: #{decision.reason || "forbidden"})}
          end
        end
        if new_status["allocation"]
          drivers = claim_device_status_drivers(old_status, new_status)
          unless drivers.empty?
            verbs = if claim_node_service_account?(base.user, new_status["allocation"])
                      ["associated-node:#{base.verb}", "arbitrary-node:#{base.verb}"]
                    else
                      ["arbitrary-node:#{base.verb}"]
                    end
            drivers.each do |driver|
              reasons = verbs.map do |verb|
                decision = authorizer.authorize(base.with(verb: verb, subresource: "driver", name: driver))
                break nil if decision.allowed?

                decision.reason || "forbidden"
              end
              next if reasons.nil?

              causes << {"field" => "status.devices", "reason" => "FieldValueForbidden",
                         "message" => %(Forbidden: changing status.devices requires resource="resourceclaims/driver", verb="[#{verbs.join(" ")}]" ) +
                                      "permission: #{reasons.first}"}
            end
          end
        end
        return if causes.empty?

        name = metadata_value(object, "name")
        raise Status::Invalid.new(%(ResourceClaim.resource.k8s.io "#{name}" is invalid: #{causes.map { |cause| "#{cause["field"]}: #{cause["message"]}" }.join(", ")}),
                                  details: {"name" => name, "group" => "resource.k8s.io", "kind" => "ResourceClaim", "causes" => causes})
      end

      # getModifiedDrivers: drivers with an added, changed or removed device status.
      def claim_device_status_drivers(old_status, new_status)
        key = ->(device) { [device["driver"], device["pool"], device["device"], device["shareID"]] }
        old_devices = Array(old_status["devices"]).to_h { |device| [key.call(device), device] }
        drivers = []
        Array(new_status["devices"]).each do |device|
          previous = old_devices.delete(key.call(device))
          drivers << device["driver"].to_s if previous != device
        end
        drivers.concat(old_devices.values.map { |device| device["driver"].to_s })
        drivers.uniq.sort
      end

      # saAssociatedWithAllocatedNode: a service account whose token names the
      # one node the allocation is pinned to.
      def claim_node_service_account?(user, allocation)
        terms = Array(allocation.dig("nodeSelector", "nodeSelectorTerms"))
        return false unless terms.length == 1 && Array(terms[0]["matchExpressions"]).empty? && Array(terms[0]["matchFields"]).length == 1

        field = terms[0]["matchFields"][0]
        return false unless field["key"] == "metadata.name" && field["operator"] == "In" && Array(field["values"]).length == 1
        return false unless user.respond_to?(:name) && user.name.to_s.start_with?("system:serviceaccount:")

        nodes = Array(user.extra["authentication.kubernetes.io/node-name"])
        nodes.length == 1 && nodes.first == field["values"][0]
      end

      def csr_resource?(resource)
        resource.respond_to?(:group) && resource.group.to_s == "certificates.k8s.io" &&
          resource.resource.to_s == "certificatesigningrequests"
      end

      # csrStrategy.PrepareForCreate: whatever the client wrote, the request
      # names the user who created it (username, uid, groups, extra).  It
      # runs after mutating admission and before validation, as upstream.
      def inject_csr_requester(request, resource, object)
        return object unless csr_resource?(resource) && object.is_a?(Hash)

        result = deep_copy(object)
        spec = result["spec"].is_a?(Hash) ? result["spec"] : (result["spec"] = {})
        %w[username uid groups extra].each { |key| spec.delete(key) }
        identity = request.respond_to?(:identity) ? request.identity : nil
        identity = identity.to_h if identity.respond_to?(:to_h) && !identity.is_a?(Hash)
        if identity.is_a?(Hash)
          username = (identity["username"] || identity[:username] || identity["name"] || identity[:name]).to_s
          uid = (identity["uid"] || identity[:uid]).to_s
          groups = Array(identity["groups"] || identity[:groups]).map(&:to_s)
          extra = identity["extra"] || identity[:extra] || {}
          spec["username"] = username unless username.empty?
          spec["uid"] = uid unless uid.empty?
          spec["groups"] = groups unless groups.empty?
          spec["extra"] = extra.to_h { |key, values| [key.to_s, Array(values).map(&:to_s)] } unless extra.empty?
        end
        result
      end

      # AfterDelete: allocations return to their pools.
      def release_registry_allocations(resource, object)
        return unless @service_allocator && @service_allocator.service?(resource)

        @service_allocator.release(object)
      rescue StandardError => error
        @logger&.warn("service.release_failed", name: metadata_value(object, "name"), error: error.message) if respond_to?(:logger, true)
      end

      # Strategy.PrepareForCreate resets .status -- but only for the kinds whose
      # strategy actually does it.  NOT every kind: a Node is REGISTERED with
      # its status by the kubelet (nodeStrategy.PrepareForCreate touches only
      # disabled fields), and a Pod's binding-time status likewise.  Clearing
      # it everywhere left every Node without conditions, so no Node ever
      # became Ready and the cluster never came up.
      #
      # This is the exact set: `grep -A 12 "func .*) PrepareForCreate"
      # pkg/registry/*/*/strategy.go | grep "\.Status = .*{}"`.
      STATUS_CLEARED_ON_CREATE = [
        ["admissionregistration.k8s.io", "validatingadmissionpolicies"],
        ["internal.apiserver.k8s.io", "storageversions"],
        ["apps", "daemonsets"], ["apps", "deployments"], ["apps", "replicasets"],
        ["apps", "statefulsets"],
        ["autoscaling", "horizontalpodautoscalers"],
        ["batch", "cronjobs"], ["batch", "jobs"],
        ["certificates.k8s.io", "certificatesigningrequests"], ["certificates.k8s.io", "podcertificaterequests"],
        ["", "persistentvolumeclaims"], ["", "persistentvolumes"],
        ["", "replicationcontrollers"], ["", "resourcequotas"], ["", "services"],
        ["flowcontrol.apiserver.k8s.io", "flowschemas"],
        ["flowcontrol.apiserver.k8s.io", "prioritylevelconfigurations"],
        ["networking.k8s.io", "ingresses"], ["networking.k8s.io", "servicecidrs"],
        ["policy", "poddisruptionbudgets"],
        ["resource.k8s.io", "devicetaintrules"], ["resource.k8s.io", "resourceclaims"],
        ["scheduling.k8s.io", "podgroups"],
        ["storagemigration.k8s.io", "storageversionmigrations"],
        ["storage.k8s.io", "volumeattachments"]
      ].freeze

      def clear_status_on_create(resource, object)
        return object unless object.is_a?(Hash) && object.key?("status")
        return object if resource.respond_to?(:custom?) && resource.custom?
        return object unless STATUS_CLEARED_ON_CREATE.include?([resource.group.to_s, resource.resource.to_s])

        result = deep_copy(object)
        result["status"] = {}
        result
      end

      def prepare_registry_create(resource, object)
        object = clear_status_on_create(resource, object)
        object = drop_stateful_set_disabled_fields(resource, object, nil)
        if crd_resource?(resource)
          result = deep_copy(object)
          result["spec"] ||= {}
          result["spec"]["conversion"] ||= {"strategy" => "None"}
          storage = Array(result.dig("spec", "versions")).find { |version| version["storage"] == true }
          result["status"] = {"conditions" => nil, "acceptedNames" => {"plural" => "", "kind" => ""},
                              "storedVersions" => storage ? [storage["name"]] : []}
          result
        elsif @service_allocator && @service_allocator.service?(resource)
          @service_allocator.prepare_create(object)
        elsif replication_controller_resource?(resource)
          # pkg/apis/core/v1/defaults.go SetDefaults_ReplicationController:
          # spec.replicas defaults to 1 and a missing selector is the
          # template's labels.
          result = deep_copy(object)
          result["spec"] = {} unless result["spec"].is_a?(Hash)
          result["spec"]["replicas"] = 1 if result["spec"]["replicas"].nil?
          labels = result.dig("spec", "template", "metadata", "labels")
          result["spec"]["selector"] = deep_copy(labels) if (result["spec"]["selector"].nil? || result["spec"]["selector"] == {}) && labels.is_a?(Hash) && !labels.empty?
          result
        elsif persistent_volume_resource?(resource)
          # pkg/registry/core/persistentvolume/strategy.go PrepareForCreate:
          # a new PersistentVolume starts in phase Pending.
          result = deep_copy(object)
          result["status"] = {"phase" => "Pending", "lastPhaseTransitionTime" => @clock.call.utc.iso8601}
          result
        elsif persistent_volume_claim_resource?(resource)
          # The claim strategy clears status; the PV controller then stamps
          # Pending on its first sync, which clients observe within
          # milliseconds upstream.  Stamping it here gives the same view
          # without a race against the controller's reconcile latency.
          result = deep_copy(object)
          result["status"] = {"phase" => "Pending"}
          result
        elsif pod_resource?(resource)
          # pkg/registry/core/pod/strategy.go PrepareForCreate: a created Pod
          # always carries a status of Pending plus its QoS class.  Storing it
          # without one leaves `kubectl get pods` and every client that reads
          # status.phase with nothing to show.
          result = deep_copy(object)
          # v1 SetDefaults_Pod: a container limit without a request defaults
          # the request to the limit.
          %w[containers initContainers].each do |field|
            Array(result.dig("spec", field)).each do |container|
              next unless container.is_a?(Hash) && container["resources"].is_a?(Hash)

              limits = container["resources"]["limits"]
              next unless limits.is_a?(Hash) && !limits.empty?

              requests = (container["resources"]["requests"] ||= {})
              limits.each { |name, value| requests[name] = value unless requests.key?(name) }
            end
          end
          result["status"] = {"phase" => "Pending", "qosClass" => pod_qos_class(result)}
          # applySchedulingGatedCondition: a Pod created with scheduling
          # gates says why it is not being scheduled.
          unless Array(result.dig("spec", "schedulingGates")).empty?
            result["status"]["conditions"] = [{"type" => "PodScheduled", "status" => "False", "lastProbeTime" => nil,
                                               "lastTransitionTime" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                               "reason" => "SchedulingGated",
                                               "message" => "Scheduling is blocked due to non-empty scheduling gates"}]
          end
          result
        elsif namespace_resource?(resource)
          # pkg/registry/core/namespace/strategy.go PrepareForCreate: a created
          # Namespace is Active and always carries the built-in "kubernetes"
          # finalizer.  Without it DELETE removes the Namespace immediately and
          # every object inside it is orphaned instead of being collected.
          result = deep_copy(object)
          result["status"] = {"phase" => "Active"}
          # Upstream APPENDS the kubernetes finalizer rather than replacing the
          # list, so a Namespace created with a finalizer of its own keeps it
          # (pkg/registry/core/namespace/strategy.go:78-84).
          existing_finalizers = Array((result["spec"] || {})["finalizers"]).map(&:to_s)
          existing_finalizers << "kubernetes" unless existing_finalizers.include?("kubernetes")
          result["spec"] = (result["spec"] || {}).merge("finalizers" => existing_finalizers)
          # namespaceStrategy.Canonicalize repeats SetDefaults_Namespace here
          # because a generateName Namespace has no name to label until the
          # registry has assigned one.
          name = result.dig("metadata", "name").to_s
          unless name.empty?
            metadata = result["metadata"].is_a?(Hash) ? result["metadata"] : {}
            labels = metadata["labels"].is_a?(Hash) ? metadata["labels"] : {}
            result["metadata"] = metadata.merge(
              "labels" => labels.merge("kubernetes.io/metadata.name" => name)
            )
          end
          result
        elsif apiservice_resource?(resource)
          result = deep_copy(object)
          result["status"] = {}
          if result.dig("spec", "service").nil?
            result["status"]["conditions"] = [{"type" => "Available", "status" => "True", "lastTransitionTime" => @clock.call.utc.iso8601,
                                               "reason" => "Local", "message" => "Local APIServices are always available"}]
          end
          result
        else
          object
        end
      end

      def namespace_resource?(resource)
        resource.respond_to?(:kind) && resource.kind == "Namespace" &&
          resource.respond_to?(:group) && resource.group.to_s.empty?
      end

      # Namespaces carry their finalizers in spec, not metadata (the legacy
      # shape predates metadata.finalizers), so both lists gate removal.
      # Kinds that can own dependents; a leaf delete (Pod, ConfigMap) skips the
      # dependent scan entirely.
      CASCADE_OWNER_KINDS = %w[Deployment ReplicaSet ReplicationController StatefulSet DaemonSet Job CronJob].freeze
      # Finalizers only the owning controller ever removes.  Once the owner is
      # deleted nothing can clear them, so a cascaded dependent would hang in
      # Terminating forever (the Job spec's "there are N pods left").
      OWNER_MANAGED_FINALIZERS = {"Job" => %w[batch.kubernetes.io/job-tracking]}.freeze

      def cascade_delete_dependents(owner, visited: {}, owner_kind: nil)
        uid = metadata_value(owner, "uid").to_s
        return if uid.empty? || visited[uid]
        kind = (owner_kind || owner["kind"]).to_s
        return unless visited.any? || CASCADE_OWNER_KINDS.include?(kind)

        visited[uid] = true
        namespace = metadata_value(owner, "namespace")
        ORPHAN_DEPENDENT_RESOURCES.each do |group, version, plural|
          descriptor = @registry.find_gvr(group: group, version: version, resource: plural)
          next if descriptor.nil?

          listing = @store.list(resource: descriptor, namespace: descriptor.namespaced? ? namespace : nil, selectors: nil)
          items = listing.respond_to?(:items) ? Array(listing.items) : Array(listing.is_a?(Hash) ? listing["items"] : listing)
          items.each do |item|
            references = Array(item.dig("metadata", "ownerReferences"))
            next unless references.any? { |reference| reference["uid"].to_s == uid }

            # garbagecollector.go attemptToDeleteItem: a dependent that still
            # has an owner which is not going away is not deleted; only the
            # reference to this owner is removed.  Deleting it anyway took the
            # Pods "[sig-api-machinery] Garbage collector should not delete
            # dependents that have both valid owner and owner that's waiting
            # for dependents to be deleted" gives a second owner (2 of 50 left).
            if other_live_owner?(item, uid, namespace)
              release_dependent(descriptor, item, uid)
              next
            end

            cascade_delete_dependents(item, visited: visited)
            item = release_owner_finalizers(descriptor, item, kind)
            begin
              delete_one(descriptor, item.dig("metadata", "namespace"), item.dig("metadata", "name"), item)
            rescue StandardError
              nil
            end
          end
        rescue StandardError
          next
        end
      end

      def other_live_owner?(item, uid, namespace)
        Array(item.dig("metadata", "ownerReferences")).any? do |reference|
          next false if reference["uid"].to_s == uid

          group, version = reference["apiVersion"].to_s.include?("/") ? reference["apiVersion"].to_s.split("/", 2) : ["", reference["apiVersion"].to_s]
          resource = @registry.find_gvk(group: group, version: version, kind: reference["kind"].to_s)
          next false if resource.nil?

          owner = begin
            @store.get(resource: resource, namespace: resource.namespaced? ? namespace : nil, name: reference["name"].to_s)
          rescue MemoryStore::NotFound
            nil
          end
          owner && metadata_value(owner, "uid").to_s == reference["uid"].to_s && metadata_value(owner, "deletionTimestamp").nil?
        rescue StandardError
          false
        end
      end

      def release_dependent(descriptor, item, uid)
        ORPHAN_CONFLICT_ATTEMPTS.times do
          updated = deep_copy(item)
          updated["metadata"]["ownerReferences"] = Array(updated["metadata"]["ownerReferences"]).reject { |reference| reference["uid"].to_s == uid }
          @store.update(resource: descriptor, namespace: item.dig("metadata", "namespace"), name: item.dig("metadata", "name"),
                        object: updated, resource_version: metadata_value(item, "resourceVersion"))
          return
        rescue MemoryStore::Conflict
          item = @store.get(resource: descriptor, namespace: item.dig("metadata", "namespace"), name: item.dig("metadata", "name"))
          return unless Array(item.dig("metadata", "ownerReferences")).any? { |reference| reference["uid"].to_s == uid }
        end
      rescue StandardError
        nil
      end

      def release_owner_finalizers(descriptor, item, owner_kind)
        managed = OWNER_MANAGED_FINALIZERS[owner_kind.to_s]
        return item if managed.nil?

        finalizers = Array(item.dig("metadata", "finalizers"))
        remaining = finalizers - managed
        return item if remaining.length == finalizers.length

        updated = deep_copy(item)
        if remaining.empty?
          updated["metadata"].delete("finalizers")
        else
          updated["metadata"]["finalizers"] = remaining
        end
        @store.update(resource: descriptor, namespace: item.dig("metadata", "namespace"),
                      name: item.dig("metadata", "name"), object: updated,
                      resource_version: metadata_value(item, "resourceVersion"))
      rescue StandardError
        item
      end

      # Strategy.DefaultGarbageCollectionPolicy: when the client sends no
      # propagation policy the RESOURCE decides, and for backwards
      # compatibility core/v1 ReplicationController and batch/v1 Job default to
      # ORPHANING their dependents rather than deleting them
      # (pkg/registry/core/replicationcontroller/strategy.go,
      # pkg/registry/batch/job/strategy.go).  Events support no cascade at all.
      # Defaulting everything to cascade deleted Pods that upstream keeps.
      DEFAULT_ORPHAN_DEPENDENTS = [["", "v1", "replicationcontrollers"],
                                   ["batch", "v1", "jobs"],
                                   ["batch", "v1", "cronjobs"]].freeze
      GARBAGE_COLLECTION_UNSUPPORTED = [["", "v1", "events"],
                                        ["events.k8s.io", "v1", "events"]].freeze

      # pkg/registry/*/*/strategy.go AllowCreateOnUpdate() == true.
      ALLOW_CREATE_ON_UPDATE = [["coordination.k8s.io", "v1", "leases"],
                                ["coordination.k8s.io", "v1beta1", "leases"],
                                ["coordination.k8s.io", "v1alpha2", "leasecandidates"],
                                ["coordination.k8s.io", "v1beta1", "leasecandidates"],
                                ["", "v1", "endpoints"],
                                ["", "v1", "events"],
                                ["events.k8s.io", "v1", "events"],
                                ["", "v1", "limitranges"],
                                ["", "v1", "services"]].freeze

      # Strategy.AllowUnconditionalUpdate() == false.
      STRICT_UPDATE_RESOURCES = [
        ["admissionregistration.k8s.io", "mutatingwebhookconfigurations"],
        ["admissionregistration.k8s.io", "validatingwebhookconfigurations"],
        ["admissionregistration.k8s.io", "validatingadmissionpolicies"],
        ["admissionregistration.k8s.io", "validatingadmissionpolicybindings"],
        ["admissionregistration.k8s.io", "mutatingadmissionpolicies"],
        ["admissionregistration.k8s.io", "mutatingadmissionpolicybindings"],
        ["internal.apiserver.k8s.io", "storageversions"],
        ["certificates.k8s.io", "clustertrustbundles"],
        ["certificates.k8s.io", "podcertificaterequests"],
        ["coordination.k8s.io", "leases"],
        ["coordination.k8s.io", "leasecandidates"],
        ["node.k8s.io", "runtimeclasses"],
        ["policy", "poddisruptionbudgets"],
        ["storage.k8s.io", "csidrivers"],
        ["storage.k8s.io", "csinodes"],
        ["storage.k8s.io", "csistoragecapacities"],
        ["storage.k8s.io", "volumeattachments"],
        ["storagemigration.k8s.io", "storageversionmigrations"]
      ].freeze

      def strict_update?(resource)
        return false if resource.nil?
        return true if resource.respond_to?(:custom?) && resource.custom?

        STRICT_UPDATE_RESOURCES.include?([resource.group.to_s, resource.resource.to_s])
      end

      def allow_create_on_update?(resource)
        return false if resource.nil?
        return false if resource.respond_to?(:custom?) && resource.custom?

        ALLOW_CREATE_ON_UPDATE.include?(resource_triple(resource))
      end

      # dryRun accepts only the value "All" (metav1.DryRunAll).
      def dry_run?(request)
        values = request.respond_to?(:query_values) ? Array(request.query_values("dryRun")) : []
        values = [query(request, "dryRun")].compact if values.empty?
        values.map(&:to_s).reject(&:empty?).any? { |value| value == "All" }
      rescue StandardError
        false
      end

      # What the object would look like once stored, without storing it: the
      # server still fills in what it owns.
      def dry_run_view(object, namespace)
        result = deep_copy(object)
        result["metadata"] ||= {}
        result["metadata"]["namespace"] ||= namespace unless namespace == :cluster || namespace == :all
        result["metadata"]["uid"] ||= @uid_generator ? @uid_generator.call : SecureRandom.uuid
        result["metadata"]["creationTimestamp"] ||= @clock.call.utc.iso8601
        result["metadata"]["resourceVersion"] ||= "0"
        result
      end

      def resource_triple(resource)
        [resource.group.to_s, resource.version.to_s, resource.resource.to_s]
      end

      FOREGROUND_FINALIZER = "foregroundDeletion"

      def foreground_deletion?(delete_options)
        delete_options["propagationPolicy"].to_s == "Foreground"
      end

      def orphan_deletion?(delete_options, resource = nil)
        policy = delete_options["propagationPolicy"].to_s
        return true if policy == "Orphan" || delete_options["orphanDependents"] == true
        return false unless policy.empty? && delete_options["orphanDependents"].nil?
        return false if resource.nil?

        DEFAULT_ORPHAN_DEPENDENTS.include?(resource_triple(resource))
      end

      def garbage_collection_unsupported?(resource)
        return false if resource.nil?

        GARBAGE_COLLECTION_UNSUPPORTED.include?(resource_triple(resource))
      end

      # Garbage collector "orphan" finalizer, applied synchronously: every
      # dependent that names this object as an owner loses that reference
      # and lives on (the GC spec deletes a Deployment with
      # propagationPolicy=Orphan and expects its ReplicaSet to stay, unowned).
      ORPHAN_DEPENDENT_RESOURCES = [["", "v1", "pods"], ["apps", "v1", "replicasets"], ["batch", "v1", "jobs"],
                                    ["apps", "v1", "controllerrevisions"], ["", "v1", "persistentvolumeclaims"],
                                    ["discovery.k8s.io", "v1", "endpointslices"], ["", "v1", "endpoints"],
                                    ["", "v1", "secrets"], ["", "v1", "configmaps"]].freeze

      def orphan_dependents(resource, namespace, owner)
        uid = metadata_value(owner, "uid").to_s
        return if uid.empty?

        ORPHAN_DEPENDENT_RESOURCES.each do |group, version, plural|
          descriptor = @registry.find_gvr(group: group, version: version, resource: plural)
          next if descriptor.nil?
          next if resource.namespaced? && !descriptor.namespaced?

          listing = @store.list(resource: descriptor, namespace: resource.namespaced? ? namespace : nil, selectors: nil)
          items = listing.respond_to?(:items) ? Array(listing.items) : Array(listing.is_a?(Hash) ? listing["items"] : listing)
          items.each { |item| orphan_one_dependent(descriptor, item, uid) }
        rescue StandardError
          next
        end
      end

      # A dependent that could not be released keeps an owner reference to an
      # object that is about to stop existing, and the garbage collector then
      # deletes it -- the very thing an orphaning delete asks not to happen.
      # One rescue covered the whole collection, so a single conflicting Pod
      # abandoned every Pod after it: "[sig-api-machinery] Garbage collector
      # should orphan pods created by rc if delete options say so" kept 35 of
      # 100.  Each dependent now stands on its own and a conflict is re-read
      # and retried, as the garbage collector's orphaning does upstream.
      ORPHAN_CONFLICT_ATTEMPTS = 5

      def orphan_one_dependent(descriptor, item, uid)
        namespace = item.dig("metadata", "namespace")
        name = item.dig("metadata", "name")
        attempts = 0
        current = item
        begin
          references = Array(current.dig("metadata", "ownerReferences"))
          return unless references.any? { |reference| reference["uid"].to_s == uid }

          updated = deep_copy(current)
          updated["metadata"]["ownerReferences"] = references.reject { |reference| reference["uid"].to_s == uid }
          updated["metadata"].delete("ownerReferences") if updated["metadata"]["ownerReferences"].empty?
          @store.update(resource: descriptor, namespace: namespace, name: name,
                        object: updated, resource_version: metadata_value(current, "resourceVersion"))
        rescue MemoryStore::Conflict
          attempts += 1
          raise if attempts >= ORPHAN_CONFLICT_ATTEMPTS

          current = @store.get(resource: descriptor, namespace: namespace, name: name)
          retry
        end
      rescue MemoryStore::NotFound
        # Already gone; nothing left to release.
        nil
      rescue StandardError => error
        @logger&.warn("orphan.dependent_failed", object: [namespace, name].compact.join("/"),
                                                 error: error.class.name, message: error.message)
      end

      def blocking_finalizers(resource, object)
        list = Array(metadata_value(object, "finalizers"))
        list += Array(object.dig("spec", "finalizers")) if namespace_resource?(resource) && object.is_a?(Hash)
        list
      end

      # Once the last finalizer is gone from an object already marked for
      # deletion, the object itself is removed.  That rule belongs to EVERY
      # kind, not just Namespace: registry/generic/registry/store.go
      # updateForGracefulDeletionAndFinalizers deletes immediately when "the
      # object has a deletionTimestamp and no finalizers", and the generic
      # store is what every resource is served from.
      #
      # Restricting it to namespaces left every other finalizer-protected
      # object in the API for ever after its controller had done its work: a
      # PersistentVolumeClaim whose pvc-protection finalizer had been removed
      # stayed Terminating, and every spec that waits for one to disappear
      # timed out.
      def finalize_object_removal(resource, namespace, updated)
        return updated unless metadata_value(updated, "deletionTimestamp")
        return updated unless blocking_finalizers(resource, updated).empty?

        begin
          @store.delete(resource: resource, namespace: namespace, name: metadata_value(updated, "name"),
                        resource_version: metadata_value(updated, "resourceVersion"))
          after_commit(resource, updated, deleted: true)
        rescue MemoryStore::NotFound, MemoryStore::Conflict
          nil
        end
        updated
      end

      # apiextensions applies a structural schema's defaults when an object is
      # read from storage as well as on write: a default added to the CRD
      # after the object was stored is visible on the next GET/LIST.
      def default_on_read(resource, object)
        return object unless object.is_a?(Hash) && resource.respond_to?(:custom?) && resource.custom?
        return object unless resource.respond_to?(:schema) && resource.schema.respond_to?(:default)

        resource.schema.default(object)
      rescue StandardError
        object
      end

      # v1 defaults that validation itself relies on (SetDefaults_* runs at
      # decode time upstream, before ValidateReplicationController requires a
      # selector).
      def apply_pre_validation_defaults(resource, object)
        return object unless replication_controller_resource?(resource) && object.is_a?(Hash)

        result = deep_copy(object)
        result["spec"] = {} unless result["spec"].is_a?(Hash)
        result["spec"]["replicas"] = 1 if result["spec"]["replicas"].nil?
        labels = result.dig("spec", "template", "metadata", "labels")
        if (result["spec"]["selector"].nil? || result["spec"]["selector"] == {}) && labels.is_a?(Hash) && !labels.empty?
          result["spec"]["selector"] = deep_copy(labels)
        end
        result
      end

      # statefulset strategy dropStatefulSetDisabledFields: with
      # MaxUnavailableStatefulSet off (Beta, off by default) a new
      # rollingUpdate.maxUnavailable is dropped unless the old object used it.
      def drop_stateful_set_disabled_fields(resource, object, existing)
        return object unless resource.respond_to?(:kind) && resource.kind == "StatefulSet" && resource.group.to_s == "apps"
        return object if feature_gate_enabled?("MaxUnavailableStatefulSet")
        return object unless object.is_a?(Hash) && !object.dig("spec", "updateStrategy", "rollingUpdate", "maxUnavailable").nil?
        return object if existing.is_a?(Hash) && !existing.dig("spec", "updateStrategy", "rollingUpdate", "maxUnavailable").nil?

        result = deep_copy(object)
        result["spec"]["updateStrategy"]["rollingUpdate"].delete("maxUnavailable")
        result
      end

      def replication_controller_resource?(resource)
        resource.respond_to?(:kind) && resource.kind == "ReplicationController" && resource.respond_to?(:group) && resource.group.to_s.empty?
      end

      def persistent_volume_resource?(resource)
        resource.respond_to?(:kind) && resource.kind == "PersistentVolume" && resource.respond_to?(:group) && resource.group.to_s.empty?
      end

      def persistent_volume_claim_resource?(resource)
        resource.respond_to?(:kind) && resource.kind == "PersistentVolumeClaim" && resource.respond_to?(:group) && resource.group.to_s.empty?
      end

      def pod_resource?(resource)
        resource.respond_to?(:kind) && resource.kind == "Pod" &&
          resource.respond_to?(:group) && resource.group.to_s.empty?
      end

      # qos.ComputePodQOS, pod-level resources included (ResourceHelpers).
      def pod_qos_class(pod)
        ResourceHelpers.qos_class(pod, pod_level_resources: feature_gate_enabled?("PodLevelResources"))
      end

      POD_SCHEDULE_WAIT_SECONDS = Float(ENV.fetch("RUBERNETES_LOG_SCHEDULE_WAIT", "120"))

      # A follow request is a long-lived stream, and clients open it as soon as
      # the pod exists.  The kubelet waits for the container in that case, so
      # the API server waits for the assignment that precedes it instead of
      # answering "not assigned to a node" for a pod that is about to be bound.
      def await_scheduled_pod(route, request)
        pod = subresource_object(route)
        return pod unless route.subresource.to_s == "log"

        # Not gated on `follow`: a client that asks for a pod's logs the moment
        # it is created is asking about a pod that is about to be bound, and
        # answering "not assigned to a node" is a race, not an answer.
        follow = %w[1 true yes].include?(request.query_value("follow").to_s.downcase)
        deadline = @clock.call.to_f + (follow ? POD_SCHEDULE_WAIT_SECONDS : 30.0)
        while pod.dig("spec", "nodeName").to_s.empty? && @clock.call.to_f < deadline
          sleep(0.5)
          pod = subresource_object(route)
        end
        pod
      end

      # rest.BeforeCreate -> FillObjectMetaSystemFields: uid and
      # creationTimestamp are the server's, whatever the client sent.  Keeping
      # a client-supplied uid let a controller's stale apply of a cached Node
      # re-create the Node the e2e suite had just deleted -- as the same
      # object, same uid, same creationTimestamp -- and every later spec then
      # waited seven minutes for the ghost node to become Ready.
      def prepare_created_metadata(object)
        result = deep_copy(object)
        result["metadata"] ||= {}
        result["metadata"]["uid"] = @uid_generator.call.to_s
        result["metadata"]["creationTimestamp"] = @clock.call.utc.iso8601(6)
        result["metadata"]["generation"] = 1 if result["spec"].is_a?(Hash)
        result
      end

      # metadata.generation is server-owned: every strategy that tracks it sets
      # it to 1 in PrepareForCreate, whatever the client sent
      # (pkg/registry/core/pod/strategy.go and ~30 peers).  Ours kept a
      # client-supplied value, so a Pod created with generation 100 kept it --
      # "[sig-node] Pods Extended (pod generation) custom-set generation on new
      # pods" checks for exactly 1.
      GENERATION_TRACKED_KINDS = %w[ValidatingWebhookConfiguration MutatingWebhookConfiguration].freeze

      def tracks_generation?(object, resource)
        return true if object.is_a?(Hash) && object["spec"].is_a?(Hash)

        resource.respond_to?(:kind) && GENERATION_TRACKED_KINDS.include?(resource.kind.to_s)
      end

      def apply_generation(object, existing, subresource: nil, resource: nil)
        return object if subresource == "status" || !object.is_a?(Hash)
        return object unless tracks_generation?(object, resource)

        # Only metadata.generation changes: copy the top level and metadata.
        candidate = object.transform_keys(&:to_s)
        candidate["metadata"] = candidate["metadata"].is_a?(Hash) ? candidate["metadata"].transform_keys(&:to_s) : {}
        if existing.nil?
          candidate["metadata"]["generation"] = 1
        elsif existing["spec"] != candidate["spec"]
          candidate["metadata"]["generation"] = metadata_value(existing, "generation").to_i + 1
        else
          candidate["metadata"]["generation"] = metadata_value(existing, "generation").to_i if metadata_value(existing, "generation")
        end
        candidate
      end

      def generated_name(prefix)
        suffix = if @name_generator.respond_to?(:call)
                   parameters = @name_generator.parameters
                   parameters.empty? ? @name_generator.call : @name_generator.call(prefix)
                 else
                   SecureRandom.alphanumeric(DEFAULT_GENERATE_NAME_SUFFIX_LENGTH).downcase
                 end
        suffix = suffix.to_s
        raise Status::Invalid.new("metadata.generateName must produce a non-empty suffix") if suffix.empty?

        "#{prefix}#{suffix}"
      rescue ArgumentError => error
        raise Status::Invalid.new("metadata.generateName could not be generated: #{error.message}")
      end

      # fieldmanager.UpdateNoErrors for a write that is not an apply: the
      # managed fields the object is stored with (nil for none), from the
      # live object and the one written -- decoded and defaulted, before
      # mutating admission, where upstream's handlers run it.
      def record_managed_update(request, route, existing, object)
        @field_managers.field_manager(route.resource, route.subresource)
                       .update(live: existing, new_object: object, manager: update_manager(request))
      end

      # The object with +managed_fields+ as its metadata.managedFields (none
      # when empty).  Stored objects are frozen, so nothing is changed in place.
      def with_managed_fields(object, managed_fields)
        return object unless object.is_a?(Hash)

        metadata = object["metadata"].is_a?(Hash) ? object["metadata"] : {}
        metadata = if managed_fields.nil? || managed_fields.empty?
                     metadata.except("managedFields")
                   else
                     metadata.merge("managedFields" => managed_fields)
                   end
        object.merge("metadata" => metadata)
      end

      # managerOrUserAgent: the fieldManager option, else the user agent up
      # to its first "/", printable characters only and at most 128 bytes
      # ("" leaves the field manager to name it "unknown").
      def update_manager(request)
        explicit = query(request, "fieldManager")
        return explicit.to_s unless explicit.to_s.empty?

        prefix = request.header("user-agent").to_s.split("/", 2).first.to_s
        out = +""
        prefix.each_char do |char|
          next unless go_printable?(char)
          break if out.bytesize + char.bytesize > FIELD_MANAGER_MAX_LENGTH

          out << char
        end
        out
      end

      def stringify_keys(value)
        case value
        when Hash then value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = stringify_keys(item) }
        when Array then value.map { |item| stringify_keys(item) }
        else value
        end
      end

      def symbolize_keys(value)
        value.each_with_object({}) { |(key, item), copy| copy[key.to_sym] = item }
      end

      def metadata_value(object, key)
        metadata = object.is_a?(Hash) ? (object["metadata"] || object[:metadata] || {}) : {}
        metadata[key] || metadata[key.to_sym]
      end

      def deep_copy(value)
        case value
        when Hash then value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = deep_copy(item) }
        when Array then value.map { |item| deep_copy(item) }
        else value
        end
      end
    end

    APIServer = Server
    Handler = Server
  end
end
