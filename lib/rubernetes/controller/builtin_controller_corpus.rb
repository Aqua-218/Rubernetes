# frozen_string_literal: true

require_relative "types"

module Rubernetes
  module Controller
    # Versioned inventory of the controllers shipped by Kubernetes v1.36.2.
    # The inventory is deliberately data, not a list inferred from loaded Ruby
    # classes: a missing entry must fail closed before the manager starts.
    module BuiltinControllerCorpus
      VERSION = "v1.36.2"

      Entry = Struct.new(:name, :kind, :startup_conditions, :feature_gates,
                         :sync_targets, :status_fields, :events, :aliases,
                         :cloud_provider, keyword_init: true) do
        def initialize(name:, kind:, startup_conditions:, feature_gates:, sync_targets:,
                       status_fields:, events:, aliases: [], cloud_provider: false)
          super(name: name.to_s.freeze, kind: kind.to_s.freeze,
                startup_conditions: Array(startup_conditions).map(&:to_s).freeze,
                feature_gates: Array(feature_gates).map(&:to_s).freeze,
                sync_targets: Array(sync_targets).map(&:to_s).freeze,
                status_fields: Array(status_fields).map(&:to_s).freeze,
                events: Array(events).map(&:to_s).freeze,
                aliases: Array(aliases).map(&:to_s).freeze,
                cloud_provider: !!cloud_provider)
          freeze
        end

        def descriptor
          BuiltinControllerCorpus.descriptors_for(kind).first
        end

        def metadata
          {kind: kind, feature_gates: feature_gates, startup_conditions: startup_conditions,
           sync_targets: sync_targets, status_fields: status_fields, events: events}.freeze
        end

        # Each registration owns one lazily constructed planner. A caller may
        # supply its own controller, and a failed constructor can be retried.
        def build_controller(implementation, kind:, watches:, owns: [], options_for: nil)
          lock = Mutex.new
          instance = definition = nil
          reconcile = lambda do |resource, context = nil|
            context = {} unless context.is_a?(Hash)
            controller = context[:controller] || context["controller"]
            store = context[:store] || context["store"]
            options = context[:options] || context["options"] || {}
            options = if options_for
                        options_for.call(options, store)
                      elsif !options.is_a?(Hash)
                        {}
                      elsif options.key?(:store) || options.key?("store")
                        options
                      else
                        options.merge(store: store)
                      end
            controller ||= lock.synchronize { instance ||= yield(definition, store, options) }
            controller.plan(resource, **options)
          end
          definition = ControllerDefinition.new(name: name, kind: kind, owns: owns, watches: watches,
                                                reconcile_block: reconcile, implementation: implementation,
                                                **metadata.except(:kind))
        end

        def to_h
          {"name" => name, "kind" => kind, "apiVersion" => descriptor.api_version,
           "resource" => descriptor.resource, "scope" => descriptor.scope.to_s,
           "startupConditions" => startup_conditions,
           "featureGates" => feature_gates, "syncTargets" => sync_targets,
           "statusFields" => status_fields, "events" => events,
           "aliases" => aliases, "cloudProvider" => cloud_provider}.freeze
        end
      end

      # The publisher also supports the older served ClusterTrustBundle version.
      RESOURCE_DESCRIPTORS = {
        "PodGroup" => [ResourceDescriptor.parse("PodGroup")].freeze,
        "ResourcePoolStatusRequest" => [ResourceDescriptor.parse("ResourcePoolStatusRequest")].freeze,
        "ClusterTrustBundle" => [ResourceDescriptor.parse("ClusterTrustBundle"),
                                 ResourceDescriptor.parse("ClusterTrustBundle", version: "v1alpha1")].freeze
      }.freeze

      # Names match cmd/kube-controller-manager v1.36.2 controller_names.go
      # and cloud-provider/names/controller_names.go.  The metadata captures
      # the startup gate and externally observable sync/status/event contract
      # for every entry, including controllers whose implementation is not a
      # workload reconciler in this Ruby package.
      RAW_ENTRIES = [
        ["serviceaccount-token-controller", "ServiceAccount", ["API server available"], [], %w[ServiceAccount Secret], ["secrets"],
         ["TokenCreated"]],
        ["endpoints-controller", "Endpoints", ["API server available"], [], %w[Service Pod Endpoints], ["subsets"],
         ["EndpointsUpdated"]],
        ["endpointslice-controller", "EndpointSlice", ["API server available"], [], %w[Service Pod Node EndpointSlice],
         %w[endpoints conditions], ["EndpointSliceUpdated"]],
        ["endpointslice-mirroring-controller", "EndpointSlice", ["API server available"], [], %w[Endpoints EndpointSlice],
         ["endpoints"], ["EndpointSliceMirrored"]],
        ["replicationcontroller-controller", "ReplicationController", ["API server available"], [], %w[ReplicationController Pod],
         %w[replicas fullyLabeledReplicas], %w[SuccessfulCreate SuccessfulDelete]],
        ["pod-garbage-collector-controller", "Pod", ["API server available"], [], %w[Pod Node], %w[terminatedAll reason],
         ["TerminatedAll"]],
        ["resourcequota-controller", "ResourceQuota", ["API server available"], [],
         %w[ResourceQuota Pod Service ConfigMap Secret], %w[hard used], ["ResourceQuotaSyncFailed"]],
        ["namespace-controller", "Namespace", ["API server available"], [], ["Namespace", "all namespaced resources"], ["phase"],
         ["NamespaceDeletionContentFailure"]],
        ["serviceaccount-controller", "ServiceAccount", ["API server available"], [], %w[Namespace ServiceAccount], ["secrets"],
         ["ServiceAccountCreated"]],
        ["garbage-collector-controller", "GarbageCollector", ["API server available", "Discovery complete"], [],
         ["all resources", "ownerReferences"], ["deletion"], ["OwnerReferenceCycle"]],
        ["daemonset-controller", "DaemonSet", ["API server available"], [], %w[DaemonSet Pod Node],
         %w[desiredNumberScheduled numberReady updatedNumberScheduled], %w[SuccessfulCreate SuccessfulDelete]],
        ["job-controller", "Job", ["API server available"], [], %w[Job Pod], %w[active succeeded failed conditions],
         %w[SuccessfulCreate SuccessfulDelete Completed]],
        ["deployment-controller", "Deployment", ["API server available"], [], %w[Deployment ReplicaSet Pod],
         %w[observedGeneration replicas updatedReplicas availableReplicas unavailableReplicas], %w[ScalingReplicaSet DeploymentComplete DeploymentProgressing]],
        ["replicaset-controller", "ReplicaSet", ["API server available"], [], %w[ReplicaSet Pod],
         %w[replicas fullyLabeledReplicas readyReplicas availableReplicas], %w[SuccessfulCreate SuccessfulDelete]],
        ["horizontal-pod-autoscaler-controller", "HorizontalPodAutoscaler", ["API server available"], ["HPAContainerMetrics"],
         ["HorizontalPodAutoscaler", "scale target",
          "metrics"], %w[observedGeneration currentReplicas desiredReplicas conditions], %w[SuccessfulRescale FailedRescale]],
        ["disruption-controller", "PodDisruptionBudget", ["API server available"], [], %w[PodDisruptionBudget Pod],
         %w[currentHealthy desiredHealthy disruptionsAllowed], ["NoPods"]],
        ["statefulset-controller", "StatefulSet", ["API server available"], [],
         %w[StatefulSet Pod ControllerRevision PersistentVolumeClaim],
         %w[observedGeneration currentReplicas updatedReplicas readyReplicas currentRevision updateRevision],
         %w[SuccessfulCreate SuccessfulDelete SuccessfulRescale]],
        ["cronjob-controller", "CronJob", ["API server available"], [], %w[CronJob Job],
         %w[active lastScheduleTime lastSuccessfulTime], %w[SawCompletedJob TooManyMissedTimes]],
        ["certificatesigningrequest-signing-controller", "CertificateSigningRequest", ["API server available"], [],
         ["CertificateSigningRequest"], %w[certificate conditions], %w[CertificateIssued CertificateFailed]],
        ["certificatesigningrequest-approving-controller", "CertificateSigningRequest", ["API server available"], [],
         ["CertificateSigningRequest"], ["conditions"], ["CertificateApproved"]],
        ["certificatesigningrequest-cleaner-controller", "CertificateSigningRequest", ["API server available"], [],
         ["CertificateSigningRequest"], ["deletion"], ["CertificateDeleted"]],
        ["podcertificaterequest-cleaner-controller", "PodCertificateRequest", ["API server available"], ["PodCertificateRequest"],
         ["PodCertificateRequest"], ["deletion"], ["PodCertificateRequestDeleted"]],
        # v1.36.2's ttlafterfinished controller watches Jobs only.  The
        # generic name is retained for the upstream controller entry, but its
        # sync contract must not claim kinds the implementation cannot serve.
        ["ttl-controller", "Job", ["API server available"], [], ["Job"], ["deletion"], ["TTLExpired"]],
        ["bootstrap-signer-controller", "ConfigMap", ["API server available"], [], %w[ConfigMap Secret], ["data"],
         ["BootstrapSignerError"]],
        ["token-cleaner-controller", "Secret", ["API server available"], [], %w[Secret ServiceAccount], ["deletion"], ["TokenCleaned"]],
        ["node-ipam-controller", "Node", ["API server available"], [], %w[Node CIDR], %w[podCIDR conditions],
         ["CIDRAssignmentFailed"]],
        ["node-lifecycle-controller", "Node", ["API server available"], [], %w[Node Pod], %w[conditions taints],
         %w[NodeNotReady NodeReady]],
        ["taint-eviction-controller", "Node", ["API server available"], ["SeparateTaintEvictionController"], %w[Node Pod], ["taints"],
         ["TaintManagerEviction"]],
        ["device-taint-eviction-controller", "Node", ["API server available"], ["DynamicResourceAllocation"], %w[Node Pod], ["taints"],
         ["DeviceTaintEviction"]],
        ["service-lb-controller", "Service", ["cloud provider configured"], [], %w[Service Node LoadBalancer], ["loadBalancer"],
         %w[EnsuringLoadBalancer EnsuredLoadBalancer DeletingLoadBalancer], [], true],
        ["node-route-controller", "Node", ["cloud provider configured"], [], %w[Node Route], ["routes"],
         %w[RouteCreated RouteDeleted], [], true],
        ["cloud-node-lifecycle-controller", "Node", ["cloud provider configured"], [], ["Node"], ["conditions"], ["CloudNodeNotReady"], [],
         true],
        ["persistentvolume-binder-controller", "PersistentVolumeClaim", ["API server available"], [],
         %w[PersistentVolume PersistentVolumeClaim], %w[phase capacity], %w[ProvisioningSucceeded ProvisioningFailed]],
        ["persistent-volume-attach-detach-controller", "Node", ["API server available"], [],
         %w[PersistentVolume PersistentVolumeClaim Pod Node VolumeAttachment CSIDriver], ["attached"], %w[SuccessfulAttachVolume FailedAttachVolume]],
        ["persistent-volume-expander-controller", "PersistentVolumeClaim", ["API server available"], [],
         %w[PersistentVolumeClaim PersistentVolume], %w[capacity conditions], %w[ExternalExpanding VolumeResizeSuccessful VolumeResizeFailed]],
        ["clusterrole-aggregation-controller", "ClusterRole", ["API server available"], [], ["ClusterRole"], ["rules"],
         ["ClusterRoleAggregated"]],
        ["persistentvolumeclaim-protection-controller", "PersistentVolumeClaim", ["API server available"], [],
         %w[PersistentVolumeClaim Pod], %w[finalizers conditions], ["PVCProtectionFinalizer"]],
        ["persistent-volume-protection-controller", "PersistentVolume", ["API server available"], [], ["PersistentVolume"], ["finalizers"],
         ["PVProtectionFinalizer"]],
        ["podgroup-protection-controller", "PodGroup", ["API server available"], ["GenericWorkload"], %w[PodGroup Pod], ["finalizers"],
         ["PodGroupProtectionFinalizer"]],
        ["volume-attributes-class-protection-controller", "VolumeAttributesClass", ["API server available"], [],
         %w[VolumeAttributesClass PersistentVolume], ["finalizers"], ["VolumeAttributesClassProtectionFinalizer"]],
        ["ttl-after-finished-controller", "Job", ["API server available"], [], ["Job"], ["deletion"], ["TTLExpired"]],
        ["root-ca-certificate-publisher-controller", "ConfigMap", ["API server available"], [], %w[Namespace ConfigMap], ["data"],
         ["RootCACertificatePublisher"]],
        ["kube-apiserver-serving-clustertrustbundle-publisher-controller", "ClusterTrustBundle",
         ["API server available",
          "ClusterTrustBundle API served"], ["ClusterTrustBundle"], %w[ClusterTrustBundle ConfigMap], ["data"], ["ClusterTrustBundlePublished"]],
        ["ephemeral-volume-controller", "Pod", ["API server available"], ["GenericEphemeralVolume"], %w[Pod PersistentVolumeClaim],
         ["volume"], %w[EphemeralVolumeCreated EphemeralVolumeFailed]],
        ["storageversion-garbage-collector-controller", "StorageVersion", ["API server available"], %w[APIServerIdentity StorageVersionAPI],
         ["StorageVersion"], ["deletion"],
         ["StorageVersionGarbageCollected"]],
        ["resourceclaim-controller", "ResourceClaim", ["API server available"], ["DynamicResourceAllocation"],
         %w[ResourceClaim ResourceSlice Pod], %w[allocation reservedFor], %w[ResourceClaimAllocated ResourceClaimFailed]],
        ["resourcepoolstatusrequest-controller", "ResourcePoolStatusRequest", ["API server available"], ["DRAResourcePoolStatus"],
         %w[ResourcePoolStatusRequest ResourceSlice ResourceClaim], ["status"], ["ResourcePoolStatusUpdated"]],
        ["legacy-serviceaccount-token-cleaner-controller", "Secret", ["API server available"], [], %w[Secret ServiceAccount],
         ["deletion"], ["LegacyTokenCleaned"]],
        ["validatingadmissionpolicy-status-controller", "ValidatingAdmissionPolicy", ["API server available"],
         ["ValidatingAdmissionPolicy"], %w[ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding], %w[observedGeneration typeChecking],
         ["ValidatingAdmissionPolicyStatusUpdated"]],
        ["service-cidr-controller", "ServiceCIDR", ["API server available"], ["MultiCIDRServiceAllocator"], %w[ServiceCIDR Node],
         ["status"], ["ServiceCIDRUpdated"]],
        ["storage-version-migrator-controller", "StorageVersionMigration", ["API server available"], ["StorageVersionMigrator"],
         ["StorageVersionMigration"], ["conditions"], %w[MigrationSucceeded MigrationFailed]],
        ["selinux-warning-controller", "Pod", ["API server available"], ["SELinuxChangePolicy"], %w[Pod Node], ["conditions"],
         ["SELinuxWarning"]]
      ].freeze

      ENTRIES = RAW_ENTRIES.map do |row|
        name, kind, startup, gates, targets, fields, events, aliases, cloud = row
        Entry.new(name: name, kind: kind, startup_conditions: startup,
                  feature_gates: gates, sync_targets: targets,
                  status_fields: fields, events: events, aliases: aliases || [],
                  cloud_provider: cloud || false)
      end.freeze

      NAMES = ENTRIES.map(&:name).freeze

      BY_NAME = ENTRIES.each_with_object({}) do |entry, index|
        [entry.name, *entry.aliases].each { |name| index[name] ||= entry }
      end.freeze
      private_constant :BY_NAME

      module_function

      def entries
        ENTRIES
      end

      def names
        NAMES
      end

      alias expected_names names

      def fetch(name)
        BY_NAME[name.to_s]
      end

      # Return the exact upstream descriptors for a controller kind.  The
      # fallback retains the existing kind-based mapping for the rest of the
      # corpus; special entries above must never be inferred as core/v1.
      def descriptors_for(kind)
        RESOURCE_DESCRIPTORS.fetch(kind.to_s) { [ResourceDescriptor.parse(kind)].freeze }
      end

      def complete?
        NAMES.length == NAMES.uniq.length && ENTRIES.all? do |entry|
          !entry.name.empty? && !entry.kind.empty? && entry.startup_conditions.any? &&
            entry.sync_targets.any? && entry.status_fields.any? && entry.events.any?
        end
      end

      def assert_complete!
        raise ValidationError, "built-in controller corpus #{VERSION} is incomplete" unless complete?

        self
      end

      assert_complete!
    end
  end
end
