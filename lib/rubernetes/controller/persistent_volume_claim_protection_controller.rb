# frozen_string_literal: true

module Rubernetes
  module Controller
    # Removes PVCProtectionFinalizer only after a complete snapshot shows no
    # scheduled Pod references the claim.  The Kubernetes controller also
    # repairs finalizers missing from old PVCs, which is retained here.
    class PersistentVolumeClaimProtectionController < BaseController
      include ProtectionPublicationSupport
      include ProtectionFinalizers

      def plan(pvc, store: nil, pods: nil, feature_gates: {}, now: nil, **_options)
        return empty_result(pvc, controller: name) unless resource_kind?(pvc, PVC.kind)

        adapter = adapter_for(store, self.store)
        status = nil
        status_write = nil
        if feature_gates["PersistentVolumeClaimUnusedSinceTime"] == true && !deletion_timestamp?(pvc)
          used = observed_pvc_usage(pvc, pods, adapter) { |pod| pod_uses_pvc_for_unused_since?(pod, pvc) }
          status = unused_status(pvc, used, now || Time.now.utc) unless used.nil?
          status_write = operation_status(pvc, status, descriptor: PVC, reason: "track PVC usage") if status
        end

        reconcile_finalizer(pvc, PVC, PVC_PROTECTION_FINALIZER, label: "PVC", status: status, status_write: status_write) do
          observed_pvc_usage(pvc, pods, adapter) { |pod| pod_uses_pvc_for_deletion?(pod, pvc) } == false
        end
      end

      private

      def observed_pvc_usage(pvc, pods, adapter, &)
        namespace = Support.namespace(pvc).to_s
        return Array(pods).any? { |pod| Support.namespace(pod).to_s == namespace && yield(pod) } unless pods.nil?
        return nil unless adapter

        return true if adapter.list(POD, namespace: namespace).any?(&)

        # A negative cache lookup may have missed a newly admitted Pod.
        adapter.list(POD, namespace: namespace, fresh: true).any?(&)
      end

      def unused_status(pvc, used, now)
        status = Support.status(pvc)
        conditions = Array(Support.value(status, "conditions", []))
        index = conditions.index { |condition| Support.value(condition, "type", nil) == "Unused" }
        previous = index && Support.value(conditions[index], "status", nil)
        return nil if index && (used ? previous != "True" : previous == "True")

        condition = {"type" => "Unused", "lastTransitionTime" => now.utc.iso8601}
        if used
          condition.merge!("status" => "False", "reason" => "PodUsingPVC", "message" => "A pod is currently referencing this PVC")
        else
          condition.merge!("status" => "True", "reason" => "NoPodsUsingPVC", "message" => "No pods are currently referencing this PVC")
        end
        updated = conditions.dup
        updated[index || updated.length] = condition
        status.merge("conditions" => updated)
      end

      def pod_uses_pvc_for_unused_since?(pod, pvc)
        status = Support.status(pod)
        return false if %w[Failed Succeeded].include?(Support.value(status, "phase", nil))
        if deletion_timestamp?(pod) && %w[initContainerStatuses containerStatuses ephemeralContainerStatuses].all? do |field|
             Array(Support.value(status, field, [])).all? do |container|
               state = Support.value(container, "state", {})
               Support.value(state, "terminated", nil) || Support.value(state, "waiting", nil)
             end
           end
          return false
        end

        pod_references_claim?(pod, pvc, ephemeral_allowed: true)
      end

      def pod_uses_pvc_for_deletion?(pod, pvc)
        node_name = Support.value(Support.spec(pod), "nodeName", nil)
        return false if node_name.to_s.empty?

        pod_references_claim?(pod, pvc, ephemeral_allowed: !pod_is_shut_down?(pod))
      end

      def pod_references_claim?(pod, pvc, ephemeral_allowed:)
        Array(Support.value(Support.spec(pod), "volumes", [])).any? do |volume|
          claim = Support.value(Support.value(volume, "persistentVolumeClaim", {}), "claimName", nil)
          direct_reference = claim.to_s == Support.name(pvc)
          ephemeral = Support.value(volume, "ephemeral", nil)
          ephemeral_reference = ephemeral_allowed && ephemeral.is_a?(Hash) &&
                                ephemeral_claim_name(pod, volume) == Support.name(pvc) &&
                                owner_reference_for?(pod, pvc)
          direct_reference || ephemeral_reference
        end
      end
    end
  end
end
