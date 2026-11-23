# frozen_string_literal: true

require_relative "support/autoload"

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

module Rubernetes
  module Controller
    files = {
      "advanced_misc" => %i[AdvancedMiscControllerFactory AdvancedMiscRegistration AdvancedMiscSupport
                            LegacyServiceAccountTokenCleanerController ResourceClaimController SELinuxWarningController ServiceCIDRController
                            StorageVersionMigratorController ValidatingAdmissionPolicyStatusController],
      "apply_failures" => %i[ApplyFailures],
      "builtin_implementations" => %i[BASE_BUILTIN_IMPLEMENTATIONS BUILTIN_FACTORY_IMPLEMENTATIONS BUILTIN_FACTORY_MODULES
                                      BUILTIN_IMPLEMENTATIONS BUILTIN_INCOMPLETE_REASONS UNIMPLEMENTED_BUILTIN_CONTROLLERS],
      "builtins" => %i[Builtins CronJobController DaemonSetController DeploymentController EndpointController EndpointsController
                       GarbageCollectorController JobController NodeController ReplicaSetController StatefulSetController],
      "endpoint_slice_hints" => %i[EndpointSliceHints],
      "endpointslice_controller" => %i[EndpointSliceController],
      "endpointslice_mirroring_controller" => %i[EndpointSliceMirroringController],
      "horizontal_pod_autoscaler_controller" => %i[HorizontalPodAutoscalerController MetricsClient RESTMapper ReplicaCalculator ScaleClient
                                                   ScaleSnapshot],
      "horizontal_pod_autoscaler_status" => %i[HorizontalPodAutoscalerStatus],
      "hpa_scale_discovery" => %i[HPAScaleDiscovery],
      "hpa_sync" => %i[HPASync],
      "infrastructure_storage" => %i[InfrastructureCapability InfrastructureStorageFactory PinnedInfrastructureControllerFactory],
      "infrastructure_storage/attach_detach_volumes" => %i[AttachDetachVolumes],
      "infrastructure_storage/cloud_provider_controllers" => %i[CloudNodeLifecycleController NodeRouteController ServiceLBController
                                                                ServiceLbController ServiceLoadBalancerController],
      "infrastructure_storage/cluster_role_aggregation_controller" => %i[ClusterRoleAggregationController],
      "infrastructure_storage/factory" => %i[InfrastructureStorageControllerFactory],
      "infrastructure_storage/persistent_volume_attach_detach_controller" => %i[PersistentVolumeAttachDetachController],
      "infrastructure_storage/persistent_volume_binder_controller" => %i[PersistentVolumeBinderController],
      "infrastructure_storage/persistent_volume_expander_controller" => %i[PersistentVolumeExpanderController],
      "infrastructure_storage/routed_load_balancer" => %i[RoutedLoadBalancer],
      "infrastructure_storage/support" => %i[InfrastructureStorageSupport],
      "infrastructure_storage/taint_eviction_controller" => %i[DeviceTaintEvictionController TaintEvictionController],
      "namespace_controller" => %i[NamespaceController],
      "persistent_volume_claim_protection_controller" => %i[PersistentVolumeClaimProtectionController],
      "pod_deletion_ranking" => %i[PodDeletionRanking],
      "pod_garbage_collector_controller" => %i[PodGarbageCollectorController],
      "protection_publication" => %i[EphemeralVolumeController KubeAPIServerServingClusterTrustBundlePublisherController
                                     PersistentVolumeProtectionController PinnedProtectionPublicationControllerFactory PodGroupProtectionController
                                     ProtectionPublicationControllerFactory ProtectionPublicationRegistration ProtectionPublicationSupport
                                     RootCACertificatePublisherController StorageVersionGarbageCollectorController TTLAfterFinishedController
                                     VolumeAttributesClassProtectionController],
      "replica_failure_status" => %i[ReplicaFailureStatus],
      "replicationcontroller_controller" => %i[ReplicationControllerController],
      "resource_claim_workloads" => %i[ResourceClaimWorkloads],
      "resource_pool_status_request_controller" => %i[ResourcePoolStatusRequestController],
      "resourcequota_controller" => %i[ResourceQuotaController],
      "secondary_support" => %i[SecondarySupport],
      "security_lifecycle" => %i[BootstrapSignerController CertificateSigningRequestApprovingController
                                 CertificateSigningRequestCleanerController CertificateSigningRequestSigningController DisruptionController NodeIPAMController
                                 PinnedSecurityLifecycleControllerFactory PodCertificateRequestCleanerController SecurityLifecycleControllerFactory
                                 SecurityLifecycleRegistration SecurityLifecycleSupport TTLController TTLControllerAlias TokenCleanerController TtlController],
      "serviceaccount_controller" => %i[ServiceAccountController],
      "serviceaccount_token_controller" => %i[ServiceAccountTokenController]
    }
    Autoload.register(self, File.join(__dir__, "controller"), files)

    BUILTIN_PLAN_OPTIONS = lambda do |options, store|
      options = {} unless options.is_a?(Hash)
      options.merge(store: options[:store] || store)
    end
    private_constant :BUILTIN_PLAN_OPTIONS

    class << self
      def default_registry
        @default_registry ||= build_default_registry
      end

      alias controller_registry default_registry

      def build_default_registry(schema_registry: nil, feature_gates: {})
        registry = ControllerRegistry.new(schema_registry: schema_registry,
                                          corpus: BuiltinControllerCorpus,
                                          require_corpus: true)
        factory_definitions = BUILTIN_FACTORY_MODULES.flat_map do |factory|
          if factory == AdvancedMiscControllerFactory
            factory.definitions(registry: registry, feature_gates: feature_gates)
          else
            factory.definitions(registry: registry)
          end
        end.to_h { |definition| [definition.name, definition] }
        BuiltinControllerCorpus.entries.each do |entry|
          implementation = BUILTIN_IMPLEMENTATIONS[entry.name]
          raise MissingControllerError, "built-in controller #{entry.name.inspect} has no concrete implementation" unless implementation

          definition = factory_definitions[entry.name]
          if definition
            registry.register(definition, incomplete_reasons: BUILTIN_INCOMPLETE_REASONS.fetch(entry.name, []))
            next
          end

          descriptor = entry.descriptor
          owns, watches = builtin_wiring(entry.name, descriptor)
          add_job_scheduling_wiring(descriptor, owns, watches) if entry.name == "job-controller" && feature_gates[Builtins::JobScheduling::GATE] == true
          definition = entry.build_controller(implementation, kind: descriptor, owns: owns, watches: watches,
                                                              options_for: BUILTIN_PLAN_OPTIONS) do |declaration, _store, options|
            implementation.new(store: options[:store] || options["store"], definition: declaration)
          end
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
        dependents = case name
                     when "deployment-controller" then %w[ReplicaSet]
                     when "replicaset-controller", "replicationcontroller-controller", "daemonset-controller", "job-controller" then %w[Pod]
                     when "cronjob-controller" then %w[Job]
                     when "statefulset-controller" then %w[Pod ControllerRevision]
                     when "serviceaccount-token-controller" then %w[Secret]
                     else []
                     end
        owns = dependents.map { |kind| OwnershipEdge.new(owner: owner, dependent: ResourceDescriptor.parse(kind)) }
        watches = case name
                  when "deployment-controller" then [watch_for(owner, :all), watch_for("ReplicaSet", :owner_reference, owner: owner),
                                                     watch_for("Pod", :owner_reference, owner: owner)]
                  when "replicaset-controller", "job-controller" then [watch_for(owner, :all), watch_for("Pod", :owner_reference, owner: owner)]
                  when "statefulset-controller" then statefulset_watches(owner)
                  when "daemonset-controller" then [watch_for(owner, :all), watch_for("Pod", :owner_reference, owner: owner),
                                                    watch_for("Node", :all)]
                  when "cronjob-controller" then [watch_for(owner, :all), watch_for("Job", :owner_reference, owner: owner)]
                  when "endpoints-controller"
                    [watch_for("Service", :all, route: :self), watch_for("Pod", :label, selector_source: ResourceDescriptor.parse("Service"))]
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
                    [watch_for("Service", :all, route: :self), watch_for("Pod", :label, selector_source: ResourceDescriptor.parse("Service")),
                     # Node informer data is read during the Service's periodic sync.
                     watch_for("Node", :all, predicate: ->(_node) { false }),
                     watch_for("EndpointSlice", :all, route: :self, queue_key: SLICE_OWNER_KEY,
                                                      predicate: slice_managed_by("endpointslice-controller.k8s.io"))]
                  when "endpointslice-mirroring-controller"
                    [watch_for("Endpoints", :all, route: :self),
                     watch_for("EndpointSlice", :all, route: :self, queue_key: SLICE_OWNER_KEY,
                                                      predicate: slice_managed_by("endpointslicemirroring-controller.k8s.io"))]
                  when "replicationcontroller-controller" then [watch_for(owner, :all), watch_for("Pod", :owner_reference, owner: owner),
                                                                watch_for("Pod", :label)]
                  when "serviceaccount-token-controller" then [watch_for("ServiceAccount", :all),
                                                               watch_for("Secret", :owner_reference, owner: owner)]
                  when "pod-garbage-collector-controller" then [watch_for("Pod", :all), watch_for("Node", :all)]
                  when "resourcequota-controller"
                    # Replenishment (pkg/controller/resourcequota): every kind a
                    # quota can count is watched so that a deletion recomputes
                    # status.used at once.  Without the ReplicaSet watch the
                    # count only dropped at the periodic resync, and the
                    # conformance spec that deletes a ReplicaSet and waits five
                    # minutes for count/replicasets.apps to reach zero passed
                    # or failed on where the resync timer happened to be.
                    replenishment = %w[Pod Service ConfigMap Secret PersistentVolumeClaim ReplicaSet ReplicationController
                                       Deployment StatefulSet DaemonSet Job CronJob ResourceClaim]
                    [watch_for(owner, :all)] + replenishment.map { |kind| watch_for(kind, :all, route: :namespace) }
                  when "namespace-controller"
                    %w[Namespace Pod Service Endpoints EndpointSlice ConfigMap Secret ServiceAccount ResourceQuota].map { |kind| watch_for(kind, :all) }
                  when "serviceaccount-controller" then service_account_watches
                  when "horizontal-pod-autoscaler-controller" then [watch_for("HorizontalPodAutoscaler", :all)]
                  # A Pod event concerns only the node it is bound to (upstream
                  # nodelifecycle/tainteviction handle it per Pod); fanning it
                  # out reconciled every node for every Pod event.
                  when "node-lifecycle-controller"
                    # The node Leases are watched as upstream's leaseInformer
                    # does: the heartbeat is read from the cache, where every
                    # reconcile used to LIST kube-node-lease from the API.
                    [watch_for("Node", :all), watch_for("Pod", :all, route: :self, queue_key: InfrastructureStorageControllerFactory::POD_NODE_KEY),
                     watch_for(Builtins::NodeController::LEASE, :all, route: :self, queue_key: NODE_LEASE_KEY)]
                  when "taint-eviction-controller"
                    [watch_for("Node", :all), watch_for("Pod", :all, route: :self, queue_key: InfrastructureStorageControllerFactory::POD_NODE_KEY)]
                  when "garbage-collector-controller"
                    # An owner deletion produces no Pod event; the collector must
                    # hear about the owner kinds it reaps dependents of.
                    [watch_for("Pod", :all)] + %w[ReplicationController ReplicaSet Deployment Job CronJob StatefulSet DaemonSet].map do |kind|
                      watch_for(kind, :all)
                    end
                  else []
                  end
        [owns, watches]
      end

      def statefulset_watches(owner)
        [watch_for(owner, :all), watch_for("Pod", :owner_reference, owner: owner),
         watch_for("Pod", :label, predicate: ->(object) { Support.controller_owner_reference(object).nil? }),
         watch_for("ControllerRevision", :owner_reference, owner: owner), watch_for("PersistentVolumeClaim", :label)]
      end

      def add_job_scheduling_wiring(owner, owns, watches)
        [Builtins::JobScheduling::WORKLOAD, Builtins::JobScheduling::POD_GROUP].each do |dependent|
          owns << OwnershipEdge.new(owner: owner, dependent: dependent)
          watches << watch_for(dependent, :owner_reference, owner: owner)
        end
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

      def service_account_watches
        [watch_for("Namespace", :all, route: :self),
         watch_for("ServiceAccount", :all, route: :self, queue_key: ->(account) { Support.namespace(account) },
                                           predicate: ->(account) { Support.name(account) == ServiceAccountController::DEFAULT_NAME })]
      end

      def watch_for(resource, via, owner: nil, route: :fan_out, selector_source: nil, queue_key: nil, predicate: nil)
        resource = ResourceDescriptor.parse(resource)
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

    def controller(name, registry: default_registry, kind: nil, implementation: nil, &)
      DSL.controller(name, registry: registry, kind: kind, implementation: implementation, &)
    end
  end
end
