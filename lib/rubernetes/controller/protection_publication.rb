# frozen_string_literal: true

require "digest"
require "time"

require_relative "errors"
require_relative "registry"
require_relative "runtime"
require_relative "support"
require_relative "types"

module Rubernetes
  module Controller
    # Shared descriptors and small, side-effect-free helpers for the concrete
    # protection and publication controllers in this file.  The individual
    # controllers keep their Kubernetes-specific decision rules in their own
    # #plan methods so a generic status observer cannot be mistaken for one.
    module ProtectionPublicationSupport
      POD = ResourceDescriptor.parse("Pod")
      PVC = ResourceDescriptor.parse("PersistentVolumeClaim")
      PV = ResourceDescriptor.parse("PersistentVolume")
      VAC = ResourceDescriptor.parse("VolumeAttributesClass")
      JOB = ResourceDescriptor.parse("Job")
      NAMESPACE = ResourceDescriptor.parse("Namespace")
      CONFIG_MAP = ResourceDescriptor.parse("ConfigMap")
      POD_GROUP = ResourceDescriptor.parse({"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup"},
                                           resource: "podgroups", scope: :namespaced)
      CLUSTER_TRUST_BUNDLE = ResourceDescriptor.parse(
        {"apiVersion" => "certificates.k8s.io/v1beta1", "kind" => "ClusterTrustBundle"},
        resource: "clustertrustbundles", scope: :cluster
      )
      STORAGE_VERSION = ResourceDescriptor.parse("StorageVersion")
      LEASE = ResourceDescriptor.parse("Lease")

      PVC_PROTECTION_FINALIZER = "kubernetes.io/pvc-protection"
      PV_PROTECTION_FINALIZER = "kubernetes.io/pv-protection"
      VAC_PROTECTION_FINALIZER = "kubernetes.io/vac-protection"
      POD_GROUP_PROTECTION_FINALIZER = "scheduling.k8s.io/podgroup-protection"
      ROOT_CA_CONFIG_MAP_NAME = "kube-root-ca.crt"
      ROOT_CA_DESCRIPTION_ANNOTATION = "kubernetes.io/description"
      ROOT_CA_DESCRIPTION = "Contains a CA bundle that can be used to verify the kube-apiserver when using internal endpoints such as the internal service IP or kubernetes.default.svc. No other usage is guaranteed across distributions of Kubernetes clusters."
      CLUSTER_TRUST_BUNDLE_SIGNER = "kubernetes.io/kube-apiserver-serving"
      IDENTITY_LEASE_LABEL = "apiserver.kubernetes.io/identity"
      KUBE_APISERVER_IDENTITY = "kube-apiserver"
      KUBE_SYSTEM_NAMESPACE = "kube-system"

      module_function

      def adapter_for(store, fallback = nil)
        candidate = store || fallback
        return nil unless candidate

        candidate.is_a?(StoreAdapter) ? candidate : StoreAdapter.new(candidate)
      end

      def list_kind(adapter, kind, namespace: :all)
        return [] unless adapter
        # The production adapter answers #list from the per-kind informer
        # cache; #all walks -- and deep-copies -- every object in the cluster,
        # which is why a single root-CA publish took seconds once a
        # conformance run had filled the store.
        return Array(adapter.list(kind, namespace: namespace)) if adapter.respond_to?(:list)

        adapter.all.select do |object|
          next false unless Support.kind(object) == kind.to_s
          next true if namespace == :all || namespace.nil? || ResourceDescriptor.parse(kind).cluster_scoped?

          Support.namespace(object).to_s == namespace.to_s
        end
      end

      def finalizers(object)
        values = Support.value(Support.metadata(object), "finalizers", [])
        Array(values).map(&:to_s)
      end

      def deletion_timestamp?(object)
        !Support.value(Support.metadata(object), "deletionTimestamp", nil).nil?
      end

      def deletion_candidate?(object, finalizer)
        deletion_timestamp?(object) && finalizers(object).include?(finalizer)
      end

      def need_finalizer?(object, finalizer)
        !deletion_timestamp?(object) && !finalizers(object).include?(finalizer)
      end

      def candidate_with_finalizers(object, values)
        candidate = Support.deep_copy(object)
        candidate["metadata"] ||= {}
        candidate["metadata"]["finalizers"] = Array(values).map(&:to_s)
        candidate
      end

      def result_for(resource, operations: [], status: nil, events: [], controller: nil)
        ReconcileResult.new(
          operations: Array(operations).compact,
          status: status || Support.status(resource),
          events: events,
          controller: controller,
          key: [Support.namespace(resource), Support.name(resource)].compact.join("/")
        )
      end

      def empty_result(resource, controller:, status: nil)
        result_for(resource, status: status, controller: controller)
      end

      def resource_kind?(resource, expected)
        Support.kind(resource) == expected.to_s
      end

      def active_namespace?(namespace)
        return false if deletion_timestamp?(namespace)

        phase = Support.value(Support.status(namespace), "phase", nil)
        phase.nil? || phase.to_s.empty? || phase.to_s == "Active"
      end

      def namespace_name(value)
        value.is_a?(Hash) ? Support.name(value) : value.to_s
      end

      def pod_is_shut_down?(pod)
        deletion_timestamp?(pod) &&
          Support.integer(Support.value(Support.metadata(pod), "deletionGracePeriodSeconds", nil), -1).zero?
      end

      def ephemeral_claim_name(pod, volume)
        "#{Support.name(pod)}-#{Support.value(volume, "name", "")}".to_s
      end

      def owner_reference_for?(owner, dependent)
        Support.owner_reference_matches?(owner, dependent, controller: true)
      end

      def operation_event(type, reason, message)
        {"type" => type, "reason" => reason, "message" => message}
      end

      def storage_version_entries(status)
        values = Support.value(status, "storageVersions", [])
        Array(values).select { |entry| entry.is_a?(Hash) }
      end

      def identity_lease?(lease)
        labels = Support.labels(lease)
        namespace = Support.namespace(lease)
        (namespace.nil? || namespace.to_s == KUBE_SYSTEM_NAMESPACE) &&
          labels[IDENTITY_LEASE_LABEL].to_s == KUBE_APISERVER_IDENTITY
      end

      def actual_descriptor_for(object, fallback)
        api_version = Support.api_version(object)
        return fallback if api_version.nil? || api_version.to_s.empty?

        ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => Support.kind(object)},
                                 resource: fallback.resource, scope: fallback.scope)
      rescue UnknownGVKError
        fallback
      end
    end

    # Removes PVCProtectionFinalizer only after a complete snapshot shows no
    # scheduled Pod references the claim.  The Kubernetes controller also
    # repairs finalizers missing from old PVCs, which is retained here.
    class PersistentVolumeClaimProtectionController < BaseController
      include ProtectionPublicationSupport

      def plan(pvc, store: nil, pods: nil, **_options)
        return empty_result(pvc, controller: name) unless resource_kind?(pvc, PVC.kind)

        current_finalizers = finalizers(pvc)
        if need_finalizer?(pvc, PVC_PROTECTION_FINALIZER)
          candidate = candidate_with_finalizers(pvc, current_finalizers + [PVC_PROTECTION_FINALIZER])
          operation = operation_update(pvc, candidate, descriptor: PVC, reason: "add PVC protection finalizer")
          event = operation_event("Normal", "PVCProtectionFinalizer", "PVC #{Support.name(pvc)} protection finalizer added")
          return result_for(pvc, operations: [operation], status: {"finalizers" => candidate.dig("metadata", "finalizers")},
                            events: [event], controller: name)
        end

        return empty_result(pvc, controller: name, status: {"finalizers" => current_finalizers}) unless deletion_candidate?(pvc, PVC_PROTECTION_FINALIZER)

        adapter = adapter_for(store, self.store)
        observed = !pods.nil? || !adapter.nil?
        observed_pods = if pods.nil?
                          list_kind(adapter, "Pod", namespace: Support.namespace(pvc))
                        else
                          Array(pods).select { |pod| Support.namespace(pod).to_s == Support.namespace(pvc).to_s }
                        end
        # A missing list is an unknown dependency, not evidence that a PVC is
        # unused.  Keeping the finalizer is the safe result during recovery.
        return empty_result(pvc, controller: name, status: {"finalizers" => current_finalizers}) unless observed
        return empty_result(pvc, controller: name, status: {"finalizers" => current_finalizers}) if observed_pods.any? { |pod| pod_uses_pvc_for_deletion?(pod, pvc) }

        candidate = candidate_with_finalizers(pvc, current_finalizers.reject { |value| value == PVC_PROTECTION_FINALIZER })
        operation = operation_update(pvc, candidate, descriptor: PVC, reason: "remove PVC protection finalizer")
        event = operation_event("Normal", "PVCProtectionFinalizer", "PVC #{Support.name(pvc)} protection finalizer removed")
        result_for(pvc, operations: [operation], status: {"finalizers" => candidate.dig("metadata", "finalizers")},
                   events: [event], controller: name)
      end

      private

      def pod_uses_pvc_for_deletion?(pod, pvc)
        node_name = Support.value(Support.spec(pod), "nodeName", nil)
        return false if node_name.nil? || node_name.to_s.empty?

        Array(Support.value(Support.spec(pod), "volumes", [])).any? do |volume|
          claim = Support.value(Support.value(volume, "persistentVolumeClaim", {}), "claimName", nil)
          direct_reference = claim.to_s == Support.name(pvc)
          ephemeral = Support.value(volume, "ephemeral", nil)
          ephemeral_reference = ephemeral.is_a?(Hash) &&
                                !pod_is_shut_down?(pod) &&
                                ephemeral_claim_name(pod, volume) == Support.name(pvc) &&
                                owner_reference_for?(pod, pvc)
          direct_reference || ephemeral_reference
        end
      end
    end

    # Adds PVProtectionFinalizer to legacy PVs and removes it only after the
    # PV controller has observed a non-Bound phase.
    class PersistentVolumeProtectionController < BaseController
      include ProtectionPublicationSupport

      def plan(pv, **_options)
        return empty_result(pv, controller: name) unless resource_kind?(pv, PV.kind)

        current_finalizers = finalizers(pv)
        if need_finalizer?(pv, PV_PROTECTION_FINALIZER)
          candidate = candidate_with_finalizers(pv, current_finalizers + [PV_PROTECTION_FINALIZER])
          operation = operation_update(pv, candidate, descriptor: PV, reason: "add PV protection finalizer")
          event = operation_event("Normal", "PVProtectionFinalizer", "PV #{Support.name(pv)} protection finalizer added")
          return result_for(pv, operations: [operation], status: {"finalizers" => candidate.dig("metadata", "finalizers")},
                            events: [event], controller: name)
        end

        return empty_result(pv, controller: name, status: {"finalizers" => current_finalizers}) unless deletion_candidate?(pv, PV_PROTECTION_FINALIZER)
        phase = Support.value(Support.status(pv), "phase", "").to_s
        return empty_result(pv, controller: name, status: {"finalizers" => current_finalizers}) if phase == "Bound"

        candidate = candidate_with_finalizers(pv, current_finalizers.reject { |value| value == PV_PROTECTION_FINALIZER })
        operation = operation_update(pv, candidate, descriptor: PV, reason: "remove PV protection finalizer")
        event = operation_event("Normal", "PVProtectionFinalizer", "PV #{Support.name(pv)} protection finalizer removed")
        result_for(pv, operations: [operation], status: {"finalizers" => candidate.dig("metadata", "finalizers")},
                   events: [event], controller: name)
      end
    end

    # PodGroup protection is admission-stamped in Kubernetes.  This controller
    # therefore removes, but does not add, its finalizer while active Pods still
    # reference spec.schedulingGroup.podGroupName.
    class PodGroupProtectionController < BaseController
      include ProtectionPublicationSupport

      def plan(pod_group, store: nil, pods: nil, **_options)
        return empty_result(pod_group, controller: name) unless resource_kind?(pod_group, POD_GROUP.kind)

        current_finalizers = finalizers(pod_group)
        return empty_result(pod_group, controller: name, status: {"finalizers" => current_finalizers}) unless deletion_candidate?(pod_group, POD_GROUP_PROTECTION_FINALIZER)

        adapter = adapter_for(store, self.store)
        observed = !pods.nil? || !adapter.nil?
        observed_pods = if pods.nil?
                          list_kind(adapter, "Pod", namespace: Support.namespace(pod_group))
                        else
                          Array(pods).select { |pod| Support.namespace(pod).to_s == Support.namespace(pod_group).to_s }
                        end
        return empty_result(pod_group, controller: name, status: {"finalizers" => current_finalizers}) unless observed
        return empty_result(pod_group, controller: name, status: {"finalizers" => current_finalizers}) if observed_pods.any? { |pod| active_pod_group_reference?(pod, pod_group) }

        candidate = candidate_with_finalizers(pod_group, current_finalizers.reject { |value| value == POD_GROUP_PROTECTION_FINALIZER })
        operation = operation_update(pod_group, candidate, descriptor: POD_GROUP, reason: "remove PodGroup protection finalizer")
        event = operation_event("Normal", "PodGroupProtectionFinalizer", "PodGroup #{Support.name(pod_group)} protection finalizer removed")
        result_for(pod_group, operations: [operation], status: {"finalizers" => candidate.dig("metadata", "finalizers")},
                   events: [event], controller: name)
      end

      private

      def active_pod_group_reference?(pod, pod_group)
        phase = Support.value(Support.status(pod), "phase", "").to_s
        return false if %w[Succeeded Failed].include?(phase)

        group = Support.value(Support.value(Support.spec(pod), "schedulingGroup", {}), "podGroupName", nil)
        group.to_s == Support.name(pod_group)
      end
    end

    # VAC protection observes both PV and PVC references.  The upstream
    # controller intentionally trusts informer snapshots; this planner uses a
    # supplied/store-backed complete snapshot and fails closed when absent.
    class VolumeAttributesClassProtectionController < BaseController
      include ProtectionPublicationSupport

      def plan(vac, store: nil, pvs: nil, pvcs: nil, **_options)
        return empty_result(vac, controller: name) unless resource_kind?(vac, VAC.kind)

        current_finalizers = finalizers(vac)
        if need_finalizer?(vac, VAC_PROTECTION_FINALIZER)
          candidate = candidate_with_finalizers(vac, current_finalizers + [VAC_PROTECTION_FINALIZER])
          operation = operation_update(vac, candidate, descriptor: VAC, reason: "add VAC protection finalizer")
          event = operation_event("Normal", "VolumeAttributesClassProtectionFinalizer",
                                  "VolumeAttributesClass #{Support.name(vac)} protection finalizer added")
          return result_for(vac, operations: [operation], status: {"finalizers" => candidate.dig("metadata", "finalizers")},
                            events: [event], controller: name)
        end

        return empty_result(vac, controller: name, status: {"finalizers" => current_finalizers}) unless deletion_candidate?(vac, VAC_PROTECTION_FINALIZER)

        adapter = adapter_for(store, self.store)
        pvs_observed = !pvs.nil? || !adapter.nil?
        pvcs_observed = !pvcs.nil? || !adapter.nil?
        observed_pvs = pvs.nil? ? list_kind(adapter, "PersistentVolume") : Array(pvs)
        observed_pvcs = pvcs.nil? ? list_kind(adapter, "PersistentVolumeClaim", namespace: :all) : Array(pvcs)
        return empty_result(vac, controller: name, status: {"finalizers" => current_finalizers}) unless pvs_observed && pvcs_observed

        vac_name = Support.name(vac)
        used = observed_pvs.any? { |pv| pv_volume_attributes_class(pv) == vac_name } ||
               observed_pvcs.any? { |pvc| pvc_volume_attributes_classes(pvc).include?(vac_name) }
        return empty_result(vac, controller: name, status: {"finalizers" => current_finalizers}) if used

        candidate = candidate_with_finalizers(vac, current_finalizers.reject { |value| value == VAC_PROTECTION_FINALIZER })
        operation = operation_update(vac, candidate, descriptor: VAC, reason: "remove VAC protection finalizer")
        event = operation_event("Normal", "VolumeAttributesClassProtectionFinalizer",
                                "VolumeAttributesClass #{Support.name(vac)} protection finalizer removed")
        result_for(vac, operations: [operation], status: {"finalizers" => candidate.dig("metadata", "finalizers")},
                   events: [event], controller: name)
      end

      private

      def pv_volume_attributes_class(pv)
        Support.value(Support.spec(pv), "volumeAttributesClassName", nil).to_s
      end

      def pvc_volume_attributes_classes(pvc)
        spec = Support.spec(pvc)
        status = Support.status(pvc)
        modify_status = Support.value(status, "modifyVolumeStatus", {})
        [Support.value(spec, "volumeAttributesClassName", nil),
         Support.value(status, "currentVolumeAttributesClassName", nil),
         Support.value(modify_status, "targetVolumeAttributesClassName", nil)].compact.map(&:to_s).reject(&:empty?).uniq
      end
    end

    # Deletes finished Jobs after ttlSecondsAfterFinished, rechecking an
    # optional fresh snapshot before emitting a UID-bearing delete operation.
    class TTLAfterFinishedController < BaseController
      include ProtectionPublicationSupport

      def initialize(clock: nil, **options)
        @clock = clock || -> { Time.now.utc }
        super(**options)
      end

      def plan(job, fresh: nil, now: nil, **_options)
        candidate = fresh || job
        return empty_result(candidate, controller: name) unless resource_kind?(candidate, JOB.kind)
        return empty_result(candidate, controller: name) if deletion_timestamp?(candidate)

        raw_ttl = Support.value(Support.spec(candidate), "ttlSecondsAfterFinished", nil)
        return empty_result(candidate, controller: name) if raw_ttl.nil?

        ttl = Integer(raw_ttl)
        raise ArgumentError, "Job TTL must be non-negative" if ttl.negative?

        finished_at = job_finish_time(candidate)
        return empty_result(candidate, controller: name) unless finished_at

        current_time = Support.parse_time(now || @clock.call)
        raise ArgumentError, "clock must return Time or RFC3339 value" unless current_time
        expires_at = finished_at + ttl
        return empty_result(candidate, controller: name) if current_time < expires_at

        operation = operation_delete(candidate, descriptor: JOB, reason: "TTLExpired")
        event = operation_event("Normal", "TTLExpired", "Job #{Support.name(candidate)} TTL expired")
        result_for(candidate, operations: [operation], events: [event], controller: name)
      rescue ArgumentError => error
        raise ArgumentError, "invalid Job TTL: #{error.message}" if error.message.include?("Job TTL") || error.message.include?("invalid")

        raise
      end

      private

      def job_finish_time(job)
        condition = Array(Support.value(Support.status(job), "conditions", [])).find do |value|
          %w[Complete Failed].include?(Support.value(value, "type", "").to_s) &&
            (Support.value(value, "status", "").to_s == "True" || Support.value(value, "status", false) == true)
        end
        return Support.parse_time(Support.value(condition, "lastTransitionTime", nil)) if condition

        # The upstream controller derives expiry from the terminal condition's
        # LastTransitionTime.  A completionTime without that condition is not
        # sufficient evidence that the Job is finished.
        nil
      end
    end

    # Publishes kube-root-ca.crt into every active namespace.  The source
    # controller replaces ConfigMap data with the current CA and preserves
    # unrelated annotations while repairing the documented description.
    class RootCACertificatePublisherController < BaseController
      include ProtectionPublicationSupport

      def initialize(root_ca: "", ca_bundle: nil, **options)
        @root_ca = ca_bundle.nil? ? root_ca.to_s : ca_bundle.to_s
        super(**options)
      end

      def plan(resource = nil, store: nil, namespaces: nil, config_maps: nil, root_ca: nil, **_options)
        adapter = adapter_for(store, self.store)
        ca_value = root_ca.nil? ? @root_ca : root_ca.to_s
        namespace_values = namespace_targets(resource, adapter, namespaces)
        # Only the target namespaces' ConfigMaps are ever inspected, so listing
        # the whole cluster's ConfigMaps on every reconcile is pure overhead.
        config_map_scope = namespace_values.length == 1 ? namespace_name(namespace_values.first).to_s : :all
        config_map_scope = :all if config_map_scope.respond_to?(:empty?) && config_map_scope.empty?
        existing_config_maps = if config_maps.nil?
                                 list_kind(adapter, "ConfigMap", namespace: config_map_scope)
                               else
                                 Array(config_maps)
                               end
        operations = []
        events = []
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        namespace_values.each do |namespace_value|
          namespace = namespace_name(namespace_value)
          next if namespace.empty?
          if namespace_value.is_a?(Hash) && !active_namespace?(namespace_value)
            record_sync(started, nil)
            next
          end

          current = existing_config_maps.find do |candidate|
            resource_kind?(candidate, CONFIG_MAP.kind) &&
              Support.name(candidate) == ROOT_CA_CONFIG_MAP_NAME &&
              Support.namespace(candidate).to_s == namespace
          end
          if current.nil? && resource_kind?(resource, CONFIG_MAP.kind) &&
             Support.name(resource) == ROOT_CA_CONFIG_MAP_NAME && Support.namespace(resource).to_s == namespace
            current = resource
          end

          desired_data = {"ca.crt" => ca_value}
          if current.nil?
            candidate = {
              "apiVersion" => "v1", "kind" => "ConfigMap",
              "metadata" => {"name" => ROOT_CA_CONFIG_MAP_NAME, "namespace" => namespace,
                             "annotations" => {ROOT_CA_DESCRIPTION_ANNOTATION => ROOT_CA_DESCRIPTION}},
              "data" => desired_data
            }
            operation = operation_create(candidate, descriptor: CONFIG_MAP, reason: "publish root CA certificate")
            # A create refused because the namespace is gone or terminating
            # is not retried and counts as done.
            operations << operation.observed do |_succeeded, error|
              ignored = error && ((error.respond_to?(:status) && error.status.to_i == 404) || StoreAdapter.namespace_terminating?(error))
              record_sync(started, ignored ? nil : error)
            end
            events << operation_event("Normal", "RootCACertificatePublisher", "published #{ROOT_CA_CONFIG_MAP_NAME} in namespace #{namespace}")
            next
          end

          current_data = Support.value(current, "data", {})
          current_annotations = Support.annotations(current)
          if current_data == desired_data && current_annotations[ROOT_CA_DESCRIPTION_ANNOTATION].to_s.length.positive?
            record_sync(started, nil)
            next
          end

          candidate = Support.deep_copy(current)
          candidate["data"] = desired_data
          candidate["metadata"] ||= {}
          candidate["metadata"]["annotations"] ||= {}
          candidate["metadata"]["annotations"][ROOT_CA_DESCRIPTION_ANNOTATION] = ROOT_CA_DESCRIPTION
          operation = operation_update(current, candidate, descriptor: CONFIG_MAP, reason: "publish root CA certificate")
          operations << operation.observed { |_succeeded, error| record_sync(started, error) } if operation
          record_sync(started, nil) unless operation
          events << operation_event("Normal", "RootCACertificatePublisher", "updated #{ROOT_CA_CONFIG_MAP_NAME} in namespace #{namespace}") if operation
        end
        status = operations.empty? ? Support.status(resource || {}) : {"data" => {"ca.crt" => ca_value}}
        result_for(resource || {"metadata" => {}}, operations: operations, status: status, events: events, controller: name)
      end

      # rootcacertpublisher recordMetrics: one per namespace sync, by the
      # API's status code (200 when nothing failed, 500 for an error without
      # one).
      def record_sync(started, error)
        code = if error.nil? then "200"
               elsif error.respond_to?(:status) && error.status.to_i.positive? then error.status.to_i.to_s
               else "500"
               end
        labels = {"code" => code}
        ControllerMetrics.observe("root_ca_cert_publisher_sync_duration_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
        ControllerMetrics.increment("root_ca_cert_publisher_sync_total", labels)
      end

      # The published ConfigMap is deleted by users and by namespace teardown.
      # Upstream's publisher enqueues the NAMESPACE on a ConfigMap delete, so
      # the copy comes back; a key that names nothing would otherwise reconcile
      # nothing at all -- which is what "[sig-auth] ServiceAccounts should
      # guarantee kube-root-ca.crt exist in any namespace" deletes and waits for.
      def plan_orphans(key, store: nil)
        namespace, _, name = key.to_s.partition("/")
        return nil if namespace.empty?
        return nil unless name.empty? || name == ROOT_CA_CONFIG_MAP_NAME

        # Plan for the NAMESPACE, as upstream's publisher does when it
        # enqueues one on a ConfigMap delete.  Planning for a synthesised
        # ConfigMap made #plan take that stub for the live object ("the event
        # carried it, so it exists") and issue an UPDATE, which the API
        # answered 404 -- 13 times in 30 s, until the spec that had deleted
        # kube-root-ca.crt gave up waiting for it to come back.
        plan({"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace}}, store: store)
      end

      private

      # pkg/controller/certificates/rootcacertpublisher/publisher.go syncs
      # exactly one namespace per work item.  Planning every namespace on every
      # key instead made each reconcile O(namespaces) and, worse, let a single
      # namespace that refuses writes -- one being terminated, one behind a
      # fail-closed webhook -- abort the batch for all of them, so a freshly
      # created namespace waited tens of seconds for its ConfigMap.
      def namespace_targets(resource, adapter, explicit)
        return Array(explicit) unless explicit.nil?

        name = target_namespace_name(resource)
        unless name.empty?
          return [name] unless adapter

          namespace = list_kind(adapter, "Namespace", namespace: :all).find do |candidate|
            namespace_name(candidate) == name
          end
          # A namespace the cache does not hold is gone or on its way out;
          # publishing into it is a guaranteed rejection.
          return namespace ? [namespace] : []
        end

        if adapter
          return list_kind(adapter, "Namespace", namespace: :all)
        end
        return [resource] if resource_kind?(resource, NAMESPACE.kind)

        []
      end

      # A Namespace key names itself; any namespaced object names the namespace
      # whose published copy has to be reconciled.
      def target_namespace_name(resource)
        return "" if resource.nil?
        return namespace_name(resource).to_s if resource_kind?(resource, NAMESPACE.kind)

        Support.namespace(resource).to_s
      end
    end

    # Publishes the CA content for the kube-apiserver-serving signer under the
    # deterministic name used by Kubernetes and removes older bundles for the
    # same signer.  Alpha and beta snapshots are accepted for updates/deletes.
    class KubeAPIServerServingClusterTrustBundlePublisherController < BaseController
      include ProtectionPublicationSupport

      API_VERSION = "certificates.k8s.io/v1beta1"

      def initialize(signer_name: CLUSTER_TRUST_BUNDLE_SIGNER, ca_bundle: "", **options)
        @signer_name = signer_name.to_s
        raise ArgumentError, "signerName cannot be empty" if @signer_name.empty?

        @ca_bundle = ca_bundle.to_s
        super(**options)
      end

      def plan(resource = nil, store: nil, trust_bundles: nil, ca_bundle: nil, signer_name: nil, **_options)
        selected_signer = (signer_name.nil? ? @signer_name : signer_name.to_s)
        raise ArgumentError, "signerName cannot be empty" if selected_signer.empty?

        adapter = adapter_for(store, self.store)
        bundle_content = ca_bundle.nil? ? @ca_bundle : ca_bundle.to_s
        observed_bundles = if trust_bundles.nil?
                             list_kind(adapter, "ClusterTrustBundle", namespace: :all)
                           else
                             Array(trust_bundles)
                           end
        if observed_bundles.empty? && resource_kind?(resource, CLUSTER_TRUST_BUNDLE.kind)
          observed_bundles = [resource]
        end
        signer_bundles = observed_bundles.select { |bundle| ctb_signer_name(bundle) == selected_signer }
        desired_name = self.class.construct_bundle_name(selected_signer, bundle_content)
        current = signer_bundles.find { |bundle| Support.name(bundle) == desired_name }
        operations = []
        events = []
        if current.nil?
          desired = {
            "apiVersion" => API_VERSION, "kind" => "ClusterTrustBundle",
            "metadata" => {"name" => desired_name},
            "spec" => {"signerName" => selected_signer, "trustBundle" => bundle_content}
          }
          operations << operation_create(desired, descriptor: CLUSTER_TRUST_BUNDLE, reason: "publish cluster trust bundle")
          events << operation_event("Normal", "ClusterTrustBundlePublished", "published ClusterTrustBundle #{desired_name}")
        elsif ctb_trust_bundle(current) != bundle_content
          candidate = Support.deep_copy(current)
          candidate["spec"] ||= {}
          candidate["spec"]["signerName"] = selected_signer
          candidate["spec"]["trustBundle"] = bundle_content
          operation = operation_update(current, candidate, descriptor: actual_descriptor_for(current, CLUSTER_TRUST_BUNDLE),
                                       reason: "publish cluster trust bundle")
          operations << operation if operation
          events << operation_event("Normal", "ClusterTrustBundlePublished", "updated ClusterTrustBundle #{desired_name}") if operation
        end

        signer_bundles.each do |bundle|
          next if Support.name(bundle) == desired_name

          operations << operation_delete(bundle, descriptor: actual_descriptor_for(bundle, CLUSTER_TRUST_BUNDLE),
                                         reason: "remove stale cluster trust bundle")
          events << operation_event("Normal", "ClusterTrustBundlePublished", "removed stale ClusterTrustBundle #{Support.name(bundle)}")
        end
        result_for(resource || {"metadata" => {}}, operations: record_sync(operations), status: {"data" => {"trustBundle" => bundle_content}},
                   events: events, controller: name)
      end

      # clustertrustbundlepublisher recordMetrics: one per sync -- when its
      # last write went through, or at the first that failed (a stale
      # bundle already gone does not count), by the API status code.
      def record_sync(operations)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        record = lambda do |error|
          code = if error.nil? then "200"
                 elsif error.respond_to?(:status) && error.status.to_i.positive? then error.status.to_i.to_s
                 else "500"
                 end
          ControllerMetrics.observe("clustertrustbundle_publisher_sync_duration_seconds",
                                    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, {"code" => code})
          ControllerMetrics.increment("clustertrustbundle_publisher_sync_total", {"code" => code})
        end
        if operations.empty?
          record.call(nil)
          return operations
        end

        remaining = operations.length
        done = false
        lock = Mutex.new
        operations.map do |operation|
          operation.observed do |succeeded, error|
            error = nil if !succeeded && operation.delete? && error.respond_to?(:status) && error.status.to_i == 404
            fire = lock.synchronize do
              next false if done

              remaining -= 1
              done = error || remaining.zero? ? true : false
            end
            record.call(error) if fire
          end
        end
      end

      def self.construct_bundle_name(signer_name, bundle_content)
        normalized_signer = signer_name.to_s.gsub("/", ":")
        digest = Digest::SHA256.hexdigest(bundle_content.to_s)[0, 24]
        "#{normalized_signer}:#{digest}"
      end

      private

      def ctb_signer_name(bundle)
        Support.value(Support.spec(bundle), "signerName", "").to_s
      end

      def ctb_trust_bundle(bundle)
        Support.value(Support.spec(bundle), "trustBundle", "").to_s
      end
    end

    # Creates one PVC per generic ephemeral inline volume and binds it to the
    # Pod by controller ownerReference.  Existing same-name PVCs are accepted
    # only when the UID-backed ownership edge is exact.
    class EphemeralVolumeController < BaseController
      include ProtectionPublicationSupport

      def plan(pod, store: nil, pvcs: nil, **_options)
        return empty_result(pod, controller: name) unless resource_kind?(pod, POD.kind)
        return empty_result(pod, controller: name) if deletion_timestamp?(pod)

        volumes = Array(Support.value(Support.spec(pod), "volumes", []))
        ephemeral_volumes = volumes.select { |volume| Support.value(volume, "ephemeral", nil).is_a?(Hash) }
        return empty_result(pod, controller: name) if ephemeral_volumes.empty?

        adapter = adapter_for(store, self.store)
        observed = !pvcs.nil? || !adapter.nil?
        return empty_result(pod, controller: name) unless observed

        observed_pvcs = if pvcs.nil?
                          list_kind(adapter, "PersistentVolumeClaim", namespace: Support.namespace(pod))
                        else
                          Array(pvcs).select { |pvc| Support.namespace(pvc).to_s == Support.namespace(pod).to_s }
                        end
        operations = []
        events = []
        ephemeral_volumes.each do |volume|
          pvc_name = ephemeral_claim_name(pod, volume)
          current = observed_pvcs.find { |pvc| Support.name(pvc) == pvc_name }
          if current
            unless owner_reference_for?(pod, current)
              raise StoreError, "PVC #{Support.namespace(current)}/#{Support.name(current)} was not created for pod #{Support.namespace(pod)}/#{Support.name(pod)} (pod is not owner)"
            end
            next
          end

          source = Support.value(volume, "ephemeral", {})
          template = Support.value(source, "volumeClaimTemplate", {})
          template = {} unless template.is_a?(Hash)
          template_metadata = Support.value(template, "metadata", {})
          template_metadata = {} unless template_metadata.is_a?(Hash)
          metadata = {"name" => pvc_name, "namespace" => Support.namespace(pod),
                      "ownerReferences" => [Support.owner_reference(pod)]}
          %w[annotations labels].each do |field|
            value = Support.value(template_metadata, field, nil)
            metadata[field] = Support.deep_copy(value) if value.is_a?(Hash)
          end
          candidate = {
            "apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => metadata,
            "spec" => Support.deep_copy(Support.value(template, "spec", {}))
          }
          # ephemeral volume metrics: every create attempted, and the failed ones.
          operations << operation_create(candidate, owner: pod, descriptor: PVC, reason: "create ephemeral volume PVC").observed do |succeeded, _|
            ControllerMetrics.increment("ephemeral_volume_controller_create_total")
            ControllerMetrics.increment("ephemeral_volume_controller_create_failures_total") unless succeeded
          end
          events << operation_event("Normal", "EphemeralVolumeCreated", "created PVC #{Support.namespace(pod)}/#{pvc_name} for Pod #{Support.name(pod)}")
        end
        result_for(pod, operations: operations, status: {"volume" => operations.map { |operation| Support.name(operation.object) }},
                   events: events, controller: name)
      end
    end

    # Removes stale API-server entries from StorageVersion.status.  A
    # StorageVersion with no remaining identity is deleted, matching the
    # v1.36.2 storageversiongc controller.
    class StorageVersionGarbageCollectorController < BaseController
      include ProtectionPublicationSupport

      ALL_ENCODING_VERSIONS_EQUAL = "AllEncodingVersionsEqual"

      def initialize(clock: nil, **options)
        @clock = clock || -> { Time.now.utc }
        super(**options)
      end

      def plan(storage_version, store: nil, leases: nil, deleted_lease: nil, storage_versions: nil, now: nil, **_options)
        targets = if storage_versions.nil?
                    [storage_version].compact
                  else
                    Array(storage_versions)
                  end
        targets = targets.select { |candidate| resource_kind?(candidate, STORAGE_VERSION.kind) }
        return empty_result(storage_version || {"metadata" => {}}, controller: name) if targets.empty?

        adapter = adapter_for(store, self.store)
        observed_leases = if leases.nil?
                            list_kind(adapter, "Lease", namespace: KUBE_SYSTEM_NAMESPACE)
                          else
                            Array(leases)
                          end
        leases_observed = !leases.nil? || !adapter.nil?
        operations = []
        events = []
        result_status = Support.status(storage_version || targets.first)
        targets.each do |candidate|
          status = Support.status(candidate)
          entries = storage_version_entries(status)
          next if entries.empty?

          remaining = if deleted_lease
                        entries.reject { |entry| Support.value(entry, "apiServerID", "").to_s == deleted_lease.to_s }
                      else
                        next unless leases_observed
                        valid_ids = observed_leases.select { |lease| identity_lease?(lease) }.map { |lease| Support.name(lease) }
                        entries.select { |entry| valid_ids.include?(Support.value(entry, "apiServerID", "").to_s) }
                      end
          next if remaining == entries

          if remaining.empty?
            operations << operation_delete(candidate, descriptor: STORAGE_VERSION, reason: "StorageVersionGarbageCollected")
            events << operation_event("Normal", "StorageVersionGarbageCollected", "deleted stale StorageVersion #{Support.name(candidate)}")
            next
          end

          desired_status = status_after_pruning(candidate, remaining, now: now)
          operation = operation_status(candidate, desired_status, descriptor: STORAGE_VERSION,
                                       reason: "StorageVersionGarbageCollected")
          operations << operation if operation
          result_status = desired_status if operation && candidate.equal?(storage_version || targets.first)
          events << operation_event("Normal", "StorageVersionGarbageCollected", "removed stale API-server entries from StorageVersion #{Support.name(candidate)}") if operation
        end
        result_for(storage_version || targets.first, operations: operations, status: result_status,
                   events: events, controller: name)
      end

      private

      def status_after_pruning(storage_version, remaining, now: nil)
        status = Support.deep_copy(Support.status(storage_version))
        previous_common = Support.value(status, "commonEncodingVersion", nil)
        status["storageVersions"] = Support.deep_copy(remaining)
        encodings = remaining.map { |entry| Support.value(entry, "encodingVersion", nil).to_s }
        if encodings.any? && encodings.uniq.length == 1
          status["commonEncodingVersion"] = encodings.first
        else
          status.delete("commonEncodingVersion")
        end
        status["conditions"] = encoding_condition(status, storage_version, encodings,
                                                    previous_common: previous_common, now: now)
        status
      end

      def encoding_condition(status, storage_version, encodings, previous_common: nil, now: nil)
        values = Array(Support.value(status, "conditions", [])).map { |condition| Support.deep_copy(condition) }
        equal = encodings.any? && encodings.uniq.length == 1
        condition = values.find { |entry| Support.value(entry, "type", "").to_s == ALL_ENCODING_VERSIONS_EQUAL }
        previous_status = condition && Support.value(condition, "status", "").to_s
        if condition.nil?
          condition = {"type" => ALL_ENCODING_VERSIONS_EQUAL}
          values << condition
        end
        condition["status"] = equal ? "True" : "False"
        condition["reason"] = equal ? "CommonEncodingVersionSet" : "CommonEncodingVersionUnset"
        condition["message"] = equal ? "Common encoding version set" : "Common encoding version unset"
        condition["observedGeneration"] = Support.value(Support.metadata(storage_version), "generation", nil) if Support.value(Support.metadata(storage_version), "generation", nil)
        common = Support.value(status, "commonEncodingVersion", nil)
        common_changed = previous_common != common
        if previous_status != condition["status"] || common_changed || Support.value(condition, "lastTransitionTime", nil).nil?
          timestamp = Support.parse_time(now || @clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless timestamp
          condition["lastTransitionTime"] = timestamp.iso8601
        end
        values
      end
    end

    # Metadata and wiring for the nine concrete entries owned by this file.
    # Registration is explicit so merely requiring this file never mutates a
    # caller's registry.
    module ProtectionPublicationControllerFactory
      VERSION = "v1.36.2"
      NAMES = %w[
        persistentvolumeclaim-protection-controller
        persistent-volume-protection-controller
        podgroup-protection-controller
        volume-attributes-class-protection-controller
        ttl-after-finished-controller
        root-ca-certificate-publisher-controller
        kube-apiserver-serving-clustertrustbundle-publisher-controller
        ephemeral-volume-controller
        storageversion-garbage-collector-controller
      ].freeze
      CONTROLLER_NAMES = NAMES

      IMPLEMENTATIONS = {
        "persistentvolumeclaim-protection-controller" => PersistentVolumeClaimProtectionController,
        "persistent-volume-protection-controller" => PersistentVolumeProtectionController,
        "podgroup-protection-controller" => PodGroupProtectionController,
        "volume-attributes-class-protection-controller" => VolumeAttributesClassProtectionController,
        "ttl-after-finished-controller" => TTLAfterFinishedController,
        "root-ca-certificate-publisher-controller" => RootCACertificatePublisherController,
        "kube-apiserver-serving-clustertrustbundle-publisher-controller" => KubeAPIServerServingClusterTrustBundlePublisherController,
        "ephemeral-volume-controller" => EphemeralVolumeController,
        "storageversion-garbage-collector-controller" => StorageVersionGarbageCollectorController
      }.freeze

      METADATA = NAMES.each_with_object({}) do |controller_name, result|
        entry = BuiltinControllerCorpus.fetch(controller_name)
        result[controller_name] = entry.to_h
      end.freeze

      WATCHES = {
        "persistentvolumeclaim-protection-controller" => [["PersistentVolumeClaim", :all], ["Pod", :all]],
        "persistent-volume-protection-controller" => [["PersistentVolume", :all]],
        "podgroup-protection-controller" => [["PodGroup", :all], ["Pod", :all]],
        "volume-attributes-class-protection-controller" => [["VolumeAttributesClass", :all], ["PersistentVolume", :all], ["PersistentVolumeClaim", :all]],
        "ttl-after-finished-controller" => [["Job", :all]],
        "root-ca-certificate-publisher-controller" => [["Namespace", :all], ["ConfigMap", :all]],
        "kube-apiserver-serving-clustertrustbundle-publisher-controller" => [["ClusterTrustBundle", :all], ["ConfigMap", :all]],
        "ephemeral-volume-controller" => [["Pod", :all], ["PersistentVolumeClaim", :all]],
        "storageversion-garbage-collector-controller" => [["StorageVersion", :all], ["Lease", :all]]
      }.freeze

      OWNERS = {
        "ephemeral-volume-controller" => [["Pod", "PersistentVolumeClaim"]]
      }.freeze

      module_function

      def entries
        NAMES.map do |name|
          BuiltinControllerCorpus.fetch(name) || raise(ValidationError, "missing pinned corpus entry #{name.inspect}")
        end
      end

      def names
        NAMES
      end

      def metadata(name = nil)
        return entries.map(&:to_h).freeze if name.nil?

        METADATA.fetch(name.to_s) do
          raise ValidationError, "missing pinned corpus entry #{name.inspect}"
        end
      end

      def definitions(registry: nil, root_ca: "", signer_name: ProtectionPublicationSupport::CLUSTER_TRUST_BUNDLE_SIGNER, ca_bundle: "")
        entries.map do |entry|
          implementation = IMPLEMENTATIONS.fetch(entry.name)
          definition = nil
          mutex = Mutex.new
          instance = nil
          reconcile = lambda do |resource, context = nil|
            context = {} unless context.is_a?(Hash)
            controller = context[:controller] || context["controller"]
            controller ||= mutex.synchronize do
              options = {store: context[:store] || context["store"], definition: definition}
              if entry.name == "root-ca-certificate-publisher-controller"
                options[:root_ca] = root_ca
              elsif entry.name == "kube-apiserver-serving-clustertrustbundle-publisher-controller"
                options[:signer_name] = signer_name
                options[:ca_bundle] = ca_bundle
              end
              instance ||= implementation.new(**options)
            end
            options = context[:options] || context["options"] || {}
            options = options.dup if options.is_a?(Hash)
            options[:store] ||= context[:store] || context["store"] if options.is_a?(Hash)
            controller.plan(resource, **(options.is_a?(Hash) ? options : {}))
          end
          definition = ControllerDefinition.new(
            name: entry.name,
            kind: descriptor_for(entry.kind, registry: registry),
            owns: ownership_edges(entry.name, registry: registry),
            watches: watch_specs(entry.name, registry: registry),
            reconcile_block: reconcile,
            feature_gates: entry.feature_gates,
            startup_conditions: entry.startup_conditions,
            sync_targets: entry.sync_targets,
            status_fields: entry.status_fields,
            events: entry.events,
            implementation: implementation
          )
          definition
        end.freeze
      end

      alias build_definitions definitions

      def register!(registry, **options)
        definitions(registry: registry, **options).each { |definition| registry.register(definition) }
        registry
      end

      alias register register!

      def descriptor_for(kind, registry: nil)
        descriptor = case kind.to_s
                     when "PodGroup"
                       ProtectionPublicationSupport::POD_GROUP
                     when "ClusterTrustBundle"
                       ProtectionPublicationSupport::CLUSTER_TRUST_BUNDLE
                     else
                       ResourceDescriptor.parse(kind)
                     end
        return descriptor unless registry

        registry.validate_descriptor!(descriptor)
        descriptor
      rescue UnknownGVKError
        ResourceDescriptor.parse(descriptor.kind)
      end

      def ownership_edges(name, registry: nil)
        return [] unless name.to_s == "ephemeral-volume-controller"

        owner = descriptor_for("Pod", registry: registry)
        dependent = descriptor_for("PersistentVolumeClaim", registry: registry)
        [OwnershipEdge.new(owner: owner, dependent: dependent)]
      end

      # Controllers whose foreign watch exists to *create* their own object
      # (a Namespace produces its kube-root-ca.crt ConfigMap, a
      # ClusterTrustBundle its published ConfigMap, a Pod its ephemeral
      # PersistentVolumeClaim).  Fanning such an event out to existing own-kind
      # objects reaches nothing on the very first event, so the observed
      # object is reconciled itself (WatchSpec route: :self).
      SELF_ROUTED_WATCHES = {
        "root-ca-certificate-publisher-controller" => %w[Namespace],
        "kube-apiserver-serving-clustertrustbundle-publisher-controller" => %w[ClusterTrustBundle],
        "ephemeral-volume-controller" => %w[Pod]
      }.freeze

      def watch_specs(name, registry: nil)
        WATCHES.fetch(name).map.with_index do |(kind, relationship), index|
          descriptor = descriptor_for(kind, registry: registry)
          route = SELF_ROUTED_WATCHES.fetch(name, []).include?(kind) ? :self : :fan_out
          WatchSpec.new(resource: descriptor, via: relationship,
                        index_name: "protection-publication/#{name}/#{index}",
                        predicate: ->(_object) { true },
                        queue_key: ->(object) { [Support.namespace(object), Support.name(object)].compact.join("/") },
                        scope: descriptor.scope, route: route)
        end
      end
    end

    ProtectionPublicationRegistration = ProtectionPublicationControllerFactory
    PinnedProtectionPublicationControllerFactory = ProtectionPublicationControllerFactory
  end
end
