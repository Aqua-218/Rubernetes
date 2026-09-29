# frozen_string_literal: true

require_relative "controller/errors"
require_relative "controller/support"
require_relative "controller/types"
require_relative "controller/registry"
require_relative "controller/ownership"
require_relative "controller/store_adapter"
require_relative "controller/effect_journal"
require_relative "controller/lease"
require_relative "controller/runtime"
require_relative "controller/dsl"
require_relative "controller/builtins"
require_relative "controller/secondary_support"
require_relative "controller/serviceaccount_token_controller"
require_relative "controller/endpointslice_controller"
require_relative "controller/endpointslice_mirroring_controller"
require_relative "controller/replicationcontroller_controller"
require_relative "controller/pod_garbage_collector_controller"
require_relative "controller/resourcequota_controller"
require_relative "controller/namespace_controller"
require_relative "controller/serviceaccount_controller"
require_relative "controller/horizontal_pod_autoscaler_controller"
require_relative "controller/security_lifecycle"
require_relative "controller/infrastructure_storage"
require_relative "controller/protection_publication"
require_relative "controller/advanced_misc"

module Rubernetes
  module Controller
    BASE_BUILTIN_IMPLEMENTATIONS = {
      "deployment-controller" => DeploymentController,
      "replicaset-controller" => ReplicaSetController,
      "statefulset-controller" => StatefulSetController,
      "daemonset-controller" => DaemonSetController,
      "job-controller" => JobController,
      "cronjob-controller" => CronJobController,
      "node-lifecycle-controller" => NodeController,
      "endpoints-controller" => EndpointController,
      "garbage-collector-controller" => GarbageCollectorController,
      "serviceaccount-token-controller" => ServiceAccountTokenController,
      "endpointslice-controller" => EndpointSliceController,
      "endpointslice-mirroring-controller" => EndpointSliceMirroringController,
      "replicationcontroller-controller" => ReplicationControllerController,
      "pod-garbage-collector-controller" => PodGarbageCollectorController,
      "resourcequota-controller" => ResourceQuotaController,
      "namespace-controller" => NamespaceController,
      "serviceaccount-controller" => ServiceAccountController,
      "horizontal-pod-autoscaler-controller" => HorizontalPodAutoscalerController
    }.freeze

    BUILTIN_FACTORY_MODULES = [
      SecurityLifecycleRegistration,
      InfrastructureStorageControllerFactory,
      ProtectionPublicationControllerFactory,
      AdvancedMiscControllerFactory
    ].freeze

    # Factory modules keep their implementation maps private to each batch;
    # flatten them once at the integration seam so the corpus and registry
    # share one 52-name inventory.  A duplicate name is a wiring error, not a
    # reason to silently prefer one implementation.
    BUILTIN_FACTORY_IMPLEMENTATIONS = BUILTIN_FACTORY_MODULES.each_with_object({}) do |factory, implementations|
      factory::IMPLEMENTATIONS.each do |name, implementation|
        raise ValidationError, "duplicate built-in implementation #{name.inspect}" if implementations.key?(name)

        implementations[name] = implementation
      end
    end.freeze

    BUILTIN_IMPLEMENTATIONS = BASE_BUILTIN_IMPLEMENTATIONS.merge(BUILTIN_FACTORY_IMPLEMENTATIONS).freeze

    # Completeness is derived from the concrete implementation contract and
    # the pinned corpus metadata.  A controller may not be promoted by a
    # placeholder reason or by suppressing a startup validation error.
    BUILTIN_INCOMPLETE_REASONS = {}.freeze

    UNIMPLEMENTED_BUILTIN_CONTROLLERS = (BuiltinControllerCorpus.names - BUILTIN_IMPLEMENTATIONS.keys).freeze

    class << self
      def default_registry
        @default_registry ||= build_default_registry
      end

      alias controller_registry default_registry

      def build_default_registry(schema_registry: nil)
        registry = ControllerRegistry.new(schema_registry: schema_registry,
                                          corpus: BuiltinControllerCorpus,
                                          require_corpus: true)
        factory_definitions = BUILTIN_FACTORY_MODULES.flat_map do |factory|
          factory.definitions(registry: registry)
        end.to_h { |definition| [definition.name, definition] }
        BuiltinControllerCorpus.entries.each do |entry|
          implementation = BUILTIN_IMPLEMENTATIONS[entry.name]
          unless implementation
            raise MissingControllerError, "built-in controller #{entry.name.inspect} has no concrete implementation"
          end

          definition = factory_definitions[entry.name]
          if definition
            registry.register(definition, incomplete_reasons: BUILTIN_INCOMPLETE_REASONS.fetch(entry.name, []))
            next
          end

          descriptor = entry.descriptor
          owns, watches = builtin_wiring(entry.name, descriptor)
          instance_mutex = Mutex.new
          controller_instance = nil
          definition = nil
          implementation_block = lambda do |resource, context = nil|
            context = {} unless context.is_a?(Hash)
            controller = context[:controller] || context["controller"]
            options = context[:options] || context["options"] || {}
            options = options.dup if options.is_a?(Hash)
            options = {} unless options.is_a?(Hash)
            options[:store] ||= context[:store] || context["store"]
            unless controller
              controller = instance_mutex.synchronize do
                controller_instance ||= implementation.new(store: options[:store] || options["store"], definition: definition)
              end
            end
            controller.plan(resource, **options)
          end
          definition = ControllerDefinition.new(
            name: entry.name,
            kind: descriptor,
            owns: owns,
            watches: watches,
            reconcile_block: implementation_block,
            feature_gates: entry.feature_gates,
            startup_conditions: entry.startup_conditions,
            sync_targets: entry.sync_targets,
            status_fields: entry.status_fields,
            events: entry.events,
            implementation: implementation
          )
          registry.register(definition, incomplete_reasons: BUILTIN_INCOMPLETE_REASONS.fetch(entry.name, []))
        end
        registry
      end

      def unimplemented_builtin_controllers
        UNIMPLEMENTED_BUILTIN_CONTROLLERS
      end

      def validate_startup!(registry: default_registry)
        registry.startup_validate!
      end

      def registered_complete_count(registry: default_registry)
        registry.registered_complete_count
      end

      def incomplete_builtin_controllers(registry: default_registry)
        registry.incomplete_controllers
      end

      private

      def builtin_wiring(name, owner)
        pod = ResourceDescriptor.parse("Pod")
        replica_set = ResourceDescriptor.parse("ReplicaSet")
        job = ResourceDescriptor.parse("Job")
        node = ResourceDescriptor.parse("Node")
        service = ResourceDescriptor.parse("Service")
        endpoints = ResourceDescriptor.parse("Endpoints")
        endpoint_slice = ResourceDescriptor.parse("EndpointSlice")
        secret = ResourceDescriptor.parse("Secret")
        service_account = ResourceDescriptor.parse("ServiceAccount")
        namespace = ResourceDescriptor.parse("Namespace")
        resource_quota = ResourceDescriptor.parse("ResourceQuota")
        config_map = ResourceDescriptor.parse("ConfigMap")
        hpa = ResourceDescriptor.parse("HorizontalPodAutoscaler")
        stateful_revision = ResourceDescriptor.parse("ControllerRevision")
        stateful_claim = ResourceDescriptor.parse("PersistentVolumeClaim")
        owns = case name
               when "deployment-controller" then [OwnershipEdge.new(owner: owner, dependent: replica_set)]
               when "replicaset-controller", "daemonset-controller", "job-controller" then [OwnershipEdge.new(owner: owner, dependent: pod)]
               when "cronjob-controller" then [OwnershipEdge.new(owner: owner, dependent: job)]
               when "statefulset-controller" then [OwnershipEdge.new(owner: owner, dependent: pod), OwnershipEdge.new(owner: owner, dependent: stateful_revision)]
               when "serviceaccount-token-controller" then [OwnershipEdge.new(owner: owner, dependent: secret)]
               when "replicationcontroller-controller" then [OwnershipEdge.new(owner: owner, dependent: pod)]
               else []
               end
        watches = case name
                  when "deployment-controller" then [watch_for(owner, :all), watch_for(replica_set, :owner_reference, owner: owner), watch_for(pod, :owner_reference, owner: owner)]
                  when "replicaset-controller" then [watch_for(owner, :all), watch_for(pod, :owner_reference, owner: owner)]
                  when "statefulset-controller" then [watch_for(owner, :all), watch_for(pod, :owner_reference, owner: owner),
                                                       watch_for(stateful_revision, :owner_reference, owner: owner),
                                                       watch_for(stateful_claim, :label)]
                  when "daemonset-controller" then [watch_for(owner, :all), watch_for(pod, :owner_reference, owner: owner), watch_for(node, :all)]
                  when "job-controller" then [watch_for(owner, :all), watch_for(pod, :owner_reference, owner: owner)]
                  when "cronjob-controller" then [watch_for(owner, :all), watch_for(job, :owner_reference, owner: owner)]
                  when "endpoints-controller"
                    [watch_for(service, :all, route: :self), watch_for(pod, :label, selector_source: service)]
                  # An EndpointSlice names its Service (or, for a mirror, its
                  # Endpoints) in kubernetes.io/service-name, and each of the two
                  # controllers cares only about the slices it manages
                  # (endpointslice.kubernetes.io/managed-by), exactly as upstream's
                  # onEndpointSliceAdd filters.  Routing a slice event as a plain
                  # :all watch reconciled a key named after the SLICE (which is
                  # no Service) and, for the mirroring controller, a :label watch
                  # against selector-less Endpoints matched every Endpoints in the
                  # namespace: "Service endpoints latency" (150 Services in one
                  # namespace) produced 18,000 mirroring enqueues in thirty
                  # seconds, a 400-key queue and 16-27 s of queue wait, which
                  # failed the 12 s budget of the EndpointSlice mirroring spec
                  # running alongside.
                  when "endpointslice-controller"
                    [watch_for(service, :all, route: :self), watch_for(pod, :label, selector_source: service),
                     watch_for(endpoint_slice, :all, route: :self, queue_key: SLICE_OWNER_KEY,
                                               predicate: slice_managed_by("endpointslice-controller.k8s.io"))]
                  when "endpointslice-mirroring-controller"
                    [watch_for(endpoints, :all, route: :self),
                     watch_for(endpoint_slice, :all, route: :self, queue_key: SLICE_OWNER_KEY,
                                               predicate: slice_managed_by("endpointslicemirroring-controller.k8s.io"))]
                  when "replicationcontroller-controller" then [watch_for(owner, :all), watch_for(pod, :owner_reference, owner: owner), watch_for(pod, :label)]
                  when "serviceaccount-token-controller" then [watch_for(service_account, :all), watch_for(secret, :owner_reference, owner: owner)]
                  when "pod-garbage-collector-controller" then [watch_for(pod, :all), watch_for(node, :all)]
                  when "resourcequota-controller"
                    # Replenishment (pkg/controller/resourcequota): every kind a
                    # quota can count is watched so that a deletion recomputes
                    # status.used at once.  Without the ReplicaSet watch the
                    # count only dropped at the periodic resync, and the
                    # conformance spec that deletes a ReplicaSet and waits five
                    # minutes for count/replicasets.apps to reach zero passed
                    # or failed on where the resync timer happened to be.
                    [watch_for(resource_quota, :all), watch_for(pod, :all, route: :namespace),
                     watch_for(service, :all, route: :namespace), watch_for(config_map, :all, route: :namespace),
                     watch_for(secret, :all, route: :namespace), watch_for(stateful_claim, :all, route: :namespace),
                     watch_for(replica_set, :all, route: :namespace),
                     watch_for(ResourceDescriptor.parse("ReplicationController"), :all, route: :namespace),
                     watch_for(ResourceDescriptor.parse("Deployment"), :all, route: :namespace),
                     watch_for(ResourceDescriptor.parse("StatefulSet"), :all, route: :namespace),
                     watch_for(ResourceDescriptor.parse("DaemonSet"), :all, route: :namespace),
                     watch_for(job, :all, route: :namespace),
                     watch_for(ResourceDescriptor.parse("CronJob"), :all, route: :namespace),
                     watch_for(ResourceDescriptor.parse("ResourceClaim"), :all, route: :namespace)]
                  when "namespace-controller" then [watch_for(namespace, :all), watch_for(pod, :all), watch_for(service, :all),
                                                    watch_for(endpoints, :all), watch_for(endpoint_slice, :all),
                                                    watch_for(config_map, :all), watch_for(secret, :all),
                                                    watch_for(service_account, :all), watch_for(resource_quota, :all)]
                  when "serviceaccount-controller" then [watch_for(namespace, :all, route: :self), watch_for(service_account, :all)]
                  when "horizontal-pod-autoscaler-controller" then [watch_for(hpa, :all)]
                  # A Pod event concerns only the node it is bound to (upstream
                  # nodelifecycle/tainteviction handle it per Pod); fanning it
                  # out reconciled every node for every Pod event.
                  when "node-lifecycle-controller"
                    # The node Leases are watched as upstream's leaseInformer
                    # does: the heartbeat is read from the cache, where every
                    # reconcile used to LIST kube-node-lease from the API.
                    [watch_for(node, :all), watch_for(pod, :all, route: :self, queue_key: InfrastructureStorageControllerFactory::POD_NODE_KEY),
                     watch_for(Builtins::NodeController::LEASE, :all, route: :self, queue_key: NODE_LEASE_KEY)]
                  when "taint-eviction-controller"
                    [watch_for(node, :all), watch_for(pod, :all, route: :self, queue_key: InfrastructureStorageControllerFactory::POD_NODE_KEY)]
                  when "garbage-collector-controller"
                    # An owner deletion produces no Pod event; the collector must
                    # hear about the owner kinds it reaps dependents of.
                    [watch_for(pod, :all)] + %w[ReplicationController ReplicaSet Deployment Job CronJob StatefulSet DaemonSet].map do |kind|
                      watch_for(ResourceDescriptor.parse(kind), :all)
                    end
                  else []
                  end
        [owns, watches]
      end

      SLICE_SERVICE_LABEL = "kubernetes.io/service-name"
      SLICE_MANAGED_BY_LABEL = "endpointslice.kubernetes.io/managed-by"

      # namespace/<service-name label>; nil (no key) for a slice without one.
      # A node Lease (kube-node-lease/<node>) renews its node's heartbeat.
      NODE_LEASE_KEY = lambda do |lease|
        next nil unless Support.namespace(lease).to_s == Builtins::NodeController::NODE_LEASE_NAMESPACE

        name = Support.name(lease).to_s
        name.empty? ? nil : name
      end

      SLICE_OWNER_KEY = lambda do |object|
        owner = Support.labels(object)[SLICE_SERVICE_LABEL].to_s
        owner.empty? ? nil : [Support.namespace(object), owner].compact.join("/")
      end

      def slice_managed_by(manager)
        ->(object) { Support.labels(object)[SLICE_MANAGED_BY_LABEL].to_s == manager }
      end

      def watch_for(resource, via, owner: nil, route: :fan_out, selector_source: nil, queue_key: nil, predicate: nil)
        queue_key ||= if via.to_sym == :owner_reference && owner
                      lambda do |object|
                        reference = Support.owner_references(object).find do |ref|
                          Support.ref_value(ref, "kind", "").to_s == owner.kind &&
                            (Support.ref_value(ref, "controller", true) == true ||
                             Support.ref_value(ref, "controller", true).to_s.casecmp("true").zero?)
                        end
                        if reference
                          [Support.namespace(object), Support.ref_value(reference, "name", "")].compact.join("/")
                        else
                          [Support.namespace(object), Support.name(object)].compact.join("/")
                        end
                      end
                    else
                      ->(object) { [Support.namespace(object), Support.name(object)].compact.join("/") }
                    end
        WatchSpec.new(resource: resource, via: via, scope: resource.scope,
                      index_name: "builtin/#{resource.identifier}/#{via}",
                      predicate: predicate || ->(_object) { true }, queue_key: queue_key, route: route,
                      selector_source: selector_source)
      end
    end

    # Compatibility convenience for callers that use `Rubernetes::Controller::DSL`.
    module_function

    def controller(name, registry: default_registry, kind: nil, implementation: nil, &block)
      DSL.controller(name, registry: registry, kind: kind, implementation: implementation, &block)
    end
  end
end
