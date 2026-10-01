# frozen_string_literal: true

require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "ownership"

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

        def to_h
          {"name" => name, "kind" => kind, "apiVersion" => descriptor.api_version,
           "resource" => descriptor.resource, "scope" => descriptor.scope.to_s,
           "startupConditions" => startup_conditions,
           "featureGates" => feature_gates, "syncTargets" => sync_targets,
           "statusFields" => status_fields, "events" => events,
           "aliases" => aliases, "cloudProvider" => cloud_provider}.freeze
        end
      end

      # Controller metadata names the primary kind, while a few built-in
      # controllers use an API type that is not inferable from that kind
      # alone.  Keep those mappings pinned to the v1.36.2 schema corpus so a
      # descriptor cannot silently fall back to core/v1 (or to a made-up
      # version) during registry validation.  ClusterTrustBundle deliberately
      # lists both served versions because the upstream publisher prefers
      # v1beta1 and falls back to v1alpha1 after discovery.
      RESOURCE_DESCRIPTORS = {
        "PodGroup" => [
          ResourceDescriptor.parse(
            {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup"},
            resource: "podgroups", scope: :namespaced
          )
        ].freeze,
        "ClusterTrustBundle" => [
          ResourceDescriptor.parse(
            {"apiVersion" => "certificates.k8s.io/v1beta1", "kind" => "ClusterTrustBundle"},
            resource: "clustertrustbundles", scope: :cluster
          ),
          ResourceDescriptor.parse(
            {"apiVersion" => "certificates.k8s.io/v1alpha1", "kind" => "ClusterTrustBundle"},
            resource: "clustertrustbundles", scope: :cluster
          )
        ].freeze,
        "ResourcePoolStatusRequest" => [
          ResourceDescriptor.parse(
            {"apiVersion" => "resource.k8s.io/v1alpha3", "kind" => "ResourcePoolStatusRequest"},
            resource: "resourcepoolstatusrequests", scope: :cluster
          )
        ].freeze
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
        ["endpointslice-controller", "EndpointSlice", ["API server available"], [], %w[Service Pod EndpointSlice],
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
         ["HorizontalPodAutoscaler", "scale target", "metrics"], %w[observedGeneration currentReplicas desiredReplicas conditions], %w[SuccessfulRescale FailedRescale]],
        ["disruption-controller", "PodDisruptionBudget", ["API server available"], [], %w[PodDisruptionBudget Pod],
         %w[currentHealthy desiredHealthy disruptionsAllowed], ["NoPods"]],
        ["statefulset-controller", "StatefulSet", ["API server available"], [],
         %w[StatefulSet Pod ControllerRevision PersistentVolumeClaim], %w[observedGeneration currentReplicas updatedReplicas readyReplicas currentRevision updateRevision], %w[SuccessfulCreate SuccessfulDelete SuccessfulRescale]],
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
        ["persistent-volume-attach-detach-controller", "PersistentVolume", ["API server available"], [],
         %w[PersistentVolume Node VolumeAttachment], ["attached"], %w[SuccessfulAttachVolume FailedAttachVolume]],
        ["persistent-volume-expander-controller", "PersistentVolumeClaim", ["API server available"], [],
         %w[PersistentVolumeClaim PersistentVolume], %w[capacity conditions], %w[VolumeResizeSuccessful VolumeResizeFailed]],
        ["clusterrole-aggregation-controller", "ClusterRole", ["API server available"], [], ["ClusterRole"], ["rules"],
         ["ClusterRoleAggregated"]],
        ["persistentvolumeclaim-protection-controller", "PersistentVolumeClaim", ["API server available"], [],
         %w[PersistentVolumeClaim Pod], ["finalizers"], ["PVCProtectionFinalizer"]],
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
         ["API server available", "ClusterTrustBundle API served"], ["ClusterTrustBundle"], %w[ClusterTrustBundle ConfigMap], ["data"], ["ClusterTrustBundlePublished"]],
        ["ephemeral-volume-controller", "Pod", ["API server available"], ["GenericEphemeralVolume"], %w[Pod PersistentVolumeClaim],
         ["volume"], %w[EphemeralVolumeCreated EphemeralVolumeFailed]],
        ["storageversion-garbage-collector-controller", "StorageVersion", ["API server available"], [], ["StorageVersion"], ["deletion"],
         ["StorageVersionGarbageCollected"]],
        ["resourceclaim-controller", "ResourceClaim", ["API server available"], ["DynamicResourceAllocation"],
         %w[ResourceClaim ResourceSlice Pod], %w[allocation reservedFor], %w[ResourceClaimAllocated ResourceClaimFailed]],
        ["resourcepoolstatusrequest-controller", "ResourcePoolStatusRequest", ["API server available"], ["DynamicResourceAllocation"],
         %w[ResourcePoolStatusRequest ResourceSlice ResourceClaim], ["status"], ["ResourcePoolStatusUpdated"]],
        ["legacy-serviceaccount-token-cleaner-controller", "Secret", ["API server available"], [], %w[Secret ServiceAccount],
         ["deletion"], ["LegacyTokenCleaned"]],
        ["validatingadmissionpolicy-status-controller", "ValidatingAdmissionPolicy", ["API server available"],
         ["ValidatingAdmissionPolicy"], %w[ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding], %w[observedGeneration typeChecking], ["ValidatingAdmissionPolicyStatusUpdated"]],
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

      module_function

      def entries
        ENTRIES
      end

      def names
        NAMES
      end

      alias expected_names names

      def fetch(name)
        ENTRIES.find { |entry| entry.name == name.to_s || entry.aliases.include?(name.to_s) }
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

    class ControllerRegistry
      include Enumerable

      attr_reader :schema_registry, :ownership_index, :corpus

      def initialize(schema_registry: nil, corpus: BuiltinControllerCorpus, require_corpus: true)
        @schema_registry = schema_registry
        @corpus = corpus
        @require_corpus = !!require_corpus
        @definitions = {}
        @ownership_index = OwnerReferenceIndex.new
        @mutex = Mutex.new
        @sealed = false
      end

      def register(definition, incomplete_reasons: [])
        raise ArgumentError, "controller definition is required" unless definition.is_a?(ControllerDefinition)

        reasons = Array(incomplete_reasons).map(&:to_s).reject(&:empty?).uniq
        definition = definition.with_incomplete_reasons(reasons) if reasons.any?
        @mutex.synchronize do
          raise RegistrySealedError, "controller registry is sealed" if @sealed
          raise DuplicateControllerError, "controller #{definition.name.inspect} is already registered" if @definitions.key?(definition.name)

          validate_definition!(definition)
          @definitions[definition.name] = definition
          definition.owns.each do |edge|
            @ownership_index.register(edge.owner, edge.dependent,
                                      controller: edge.controller,
                                      block_owner_deletion: edge.block_owner_deletion)
          end
        end
        definition
      end

      alias add register

      def register_many(definitions)
        Array(definitions).each { |definition| register(definition) }
        self
      end

      def fetch(name)
        find(name) || raise(UnknownControllerError, "controller #{name.inspect} is not registered")
      end

      def [](name)
        find(name)
      end

      def find(name)
        normalized = name.to_s
        @mutex.synchronize do
          @definitions[normalized] || @definitions.values.find { |definition| definition.name == normalized }
        end
      end

      def definitions
        @mutex.synchronize { @definitions.values.sort_by(&:name).freeze }
      end

      alias all definitions

      def each(&block)
        return enum_for(__method__) unless block

        definitions.each(&block)
      end

      def names
        @mutex.synchronize { @definitions.keys.sort.freeze }
      end

      # Names in the pinned corpus that are not represented by a concrete
      # registered implementation.  Keeping this explicit lets startup and
      # callers report the exact fail-closed boundary instead of treating a
      # generic status observer as a completed controller.
      def missing_names
        @corpus.names.reject { |name| find(name) }.freeze
      end

      def unimplemented_names
        definitions.filter_map { |definition| definition.name unless definition.implemented? }.freeze
      end

      def incomplete_names
        definitions.filter_map { |definition| definition.name if definition.incomplete? }.freeze
      end

      def incomplete_controllers
        definitions.filter_map do |definition|
          next if definition.complete?

          [definition.name, definition.completeness_reasons]
        end.to_h.freeze
      end

      def registered_complete_count
        definitions.count(&:complete?)
      end

      def size
        @mutex.synchronize { @definitions.size }
      end

      alias length size

      def sealed?
        @sealed
      end

      def seal!
        startup_validate!
        @mutex.synchronize { @sealed = true }
        self
      end

      def startup_validate!
        missing = missing_names
        unimplemented = @require_corpus ? unimplemented_names : []
        incomplete = @require_corpus ? incomplete_controllers : {}
        unless (missing.empty? && unimplemented.empty? && incomplete.empty?) || !@require_corpus
          details = []
          details << "missing: #{missing.join(", ")}" unless missing.empty?
          details << "without concrete implementation: #{unimplemented.join(", ")}" unless unimplemented.empty?
          unless incomplete.empty?
            detail = incomplete.map { |name, reasons| "#{name} [#{reasons.join(", ")}]" }.join("; ")
            details << "incomplete: #{detail}"
          end
          raise MissingControllerError, "built-in controller corpus #{@corpus::VERSION} is not ready (#{details.join("; ")})"
        end
        definitions.each { |definition| validate_definition!(definition) }
        validate_ownership_cycles!
        self
      end

      def requires_corpus?
        @require_corpus
      end

      def entry(name)
        @corpus.fetch(name)
      end

      def resource_registered?(descriptor)
        return true if ResourceDescriptor::KNOWN.any? do |_kind, values|
          values[0] == descriptor.group && values[1] == descriptor.version &&
          values[2] == descriptor.resource && values[3] == descriptor.scope
        end

        if @corpus.respond_to?(:descriptors_for)
          return true if @corpus.descriptors_for(descriptor.kind).any? do |expected|
            expected.gvk == descriptor.gvk && expected.gvr == descriptor.gvr && expected.scope == descriptor.scope
          end
        elsif @corpus.entries.any? do |entry|
          expected = ResourceDescriptor.parse(entry.kind)
          expected.group == descriptor.group && expected.version == descriptor.version && expected.kind == descriptor.kind
        end
          return true
        end
        return false unless schema_registry

        if schema_registry.respond_to?(:find_gvk)
          !!schema_registry.find_gvk(group: descriptor.group, version: descriptor.version, kind: descriptor.kind)
        elsif schema_registry.respond_to?(:fetch_gvk)
          schema_registry.fetch_gvk(descriptor.identifier)
          true
        else
          false
        end
      rescue StandardError
        false
      end

      def validate_descriptor!(descriptor)
        raise UnknownGVKError, "unknown or unregistered GVK #{descriptor.identifier}" unless resource_registered?(descriptor)

        descriptor
      end

      private

      def validate_definition!(definition)
        corpus_entry = @require_corpus ? @corpus.fetch(definition.name) : nil
        definition.validate!(corpus_entry: corpus_entry)
        if @require_corpus && corpus_entry && corpus_entry.descriptor != definition.kind
          raise ValidationError,
                "controller #{definition.name.inspect} is registered for #{definition.kind.identifier}, expected #{corpus_entry.descriptor.identifier}"
        end
        validate_descriptor!(definition.kind)
        definition.owns.each do |edge|
          validate_descriptor!(edge.owner)
          validate_descriptor!(edge.dependent)
          validate_scope_edge!(edge.owner, edge.dependent)
        end
        definition.watches.each do |watch|
          validate_descriptor!(watch.resource)
          expected_scope = watch.scope || watch.resource.scope
          unless expected_scope == watch.resource.scope
            raise ScopeMismatchError, "watch scope #{expected_scope.inspect} conflicts with #{watch.resource.identifier}"
          end
          unless %i[owner_reference label selector all].include?(watch.via)
            raise InvalidWatchError, "unsupported watch relationship #{watch.via.inspect}"
          end
        end
        raise MissingReconcileError, "controller #{definition.name} has no reconcile block" unless definition.reconcile_block
      end

      def validate_scope_edge!(owner, dependent)
        return true if owner.cluster_scoped? && dependent.cluster_scoped?
        if owner.namespaced? && dependent.cluster_scoped?
          raise ScopeMismatchError, "namespaced owner #{owner.identifier} cannot own cluster-scoped #{dependent.identifier}"
        end

        true
      end

      def validate_ownership_cycles!
        graph = Hash.new { |hash, key| hash[key] = [] }
        definitions.each do |definition|
          definition.owns.each { |edge| graph[edge.owner.identifier] << edge.dependent.identifier }
        end
        visiting = {}
        visited = {}
        walk = lambda do |node|
          return false if visited[node]
          raise OwnershipCycleError, "ownership declaration contains a cycle at #{node}" if visiting[node]

          visiting[node] = true
          graph[node].each { |child| walk.call(child) }
          visiting.delete(node)
          visited[node] = true
          false
        end
        graph.keys.each { |node| walk.call(node) }
        true
      end
    end
  end
end
