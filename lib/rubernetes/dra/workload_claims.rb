# frozen_string_literal: true

module Rubernetes
  module DRA
    # k8s.io/dynamic-resource-allocation/resourceclaim's workload ownership
    # and reservation checks shared by the controllers and kubelet.
    module WorkloadClaims
      GATE = "DRAWorkloadResourceClaims"
      SCHEDULING_GROUP = "scheduling.k8s.io"
      GROUP_VERSION = "#{SCHEDULING_GROUP}/v1alpha2".freeze
      CLAIM_REFERENCE_FIELDS = %w[name resourceClaimName resourceClaimTemplateName].freeze

      module_function

      def pod_group_name(pod)
        pod.dig("spec", "schedulingGroup", "podGroupName")
      end

      def matching_group_claim(group, pod_claim)
        return nil unless group

        Array(group.dig("spec", "resourceClaims")).find do |group_claim|
          group_claim.is_a?(Hash) && CLAIM_REFERENCE_FIELDS.all? { |field| group_claim[field] == pod_claim[field] }
        end
      end

      def reference_for(pod, pod_claim, group = nil, workload_claims: false)
        if workload_claims && group && member?(pod, group) && matching_group_claim(group, pod_claim)
          reference(group, "podgroups").merge("apiGroup" => SCHEDULING_GROUP)
        else
          reference(pod, "pods")
        end
      end

      def group_reference?(reference)
        reference["apiGroup"] == SCHEDULING_GROUP && reference["resource"] == "podgroups"
      end

      def group_owner_for_pod?(pod, reference)
        name = pod_group_name(pod)
        !name.nil? && reference["controller"] == true && reference["kind"] == "PodGroup" &&
          reference["name"] == name && reference["apiVersion"].to_s.start_with?("#{SCHEDULING_GROUP}/")
      end

      def reserved_for_pod?(pod, claim, workload_claims: false)
        uid = pod.dig("metadata", "uid")
        group_name = pod_group_name(pod) if workload_claims
        Array(claim.dig("status", "reservedFor")).any? do |consumer|
          (uid && consumer["uid"] == uid) || (group_name && group_reference?(consumer) && consumer["name"] == group_name)
        end
      end

      def member?(pod, group)
        pod.dig("metadata", "namespace") == group.dig("metadata", "namespace") &&
          pod_group_name(pod) == group.dig("metadata", "name")
      end

      def reference(object, resource)
        {"resource" => resource, "name" => object.dig("metadata", "name"), "uid" => object.dig("metadata", "uid")}
      end
      private_class_method :reference
    end
  end
end
