# frozen_string_literal: true

require_relative "../dra/workload_claims"
require_relative "types"

module Rubernetes
  module Controller
    # PodGroup side of pkg/controller/resourceclaim's template and reservation lifecycle.
    module ResourceClaimWorkloads
      WORKLOAD_CLAIMS = DRA::WorkloadClaims
      CLAIM_POD_GROUP = ResourceDescriptor.parse("PodGroup")
      CLAIM = ResourceDescriptor.parse("ResourceClaim")
      CLAIM_TEMPLATE = ResourceDescriptor.parse("ResourceClaimTemplate")

      private

      def plan_pod_group(group, store:, claims: nil, templates: nil, **)
        options = {controller: name, descriptor: CLAIM_POD_GROUP}
        return result(group, operations: [], **options) if metadata_value(group, "deletionTimestamp", nil)

        namespace = Support.namespace(group)
        adapter = adapter_for(store)
        group_claims = Array(Support.spec(group)["resourceClaims"])
        return result(group, operations: [], **options) if group_claims.empty?

        claims ||= list_for(adapter, CLAIM, namespace: namespace)
        templates ||= list_for(adapter, CLAIM_TEMPLATE, namespace: namespace)
        operations = []
        updates = []
        group_claims.each do |group_claim|
          resolved = handle_claim(group, group_claim, claims, templates)
          next unless resolved

          operations << template_claim_creation(resolved[:create]) if resolved[:create]
          updates << {"name" => group_claim["name"], "resourceClaimName" => resolved.fetch(:name)}
        rescue ClaimFailure => error
          event = {"type" => "Warning", "reason" => "FailedResourceClaimCreation",
                   "message" => "PodGroupResourceClaim #{group_claim["name"]}: #{error.message}"}
          return result(group, operations: operations, events: [event], **options)
        end

        unless updates.empty?
          statuses = merge_claim_statuses(group, updates)
          operations << operation_status(group, {"resourceClaimStatuses" => statuses}, descriptor: CLAIM_POD_GROUP,
                                                                                       reason: "record ResourceClaims created for the PodGroup", force: true)
        end
        result(group, operations: operations, **options)
      end

      def merge_claim_statuses(object, updates)
        observed = Array(Support.status(object)["resourceClaimStatuses"])
        changed_names = updates.map { |status| status["name"] }
        observed.reject { |status| changed_names.include?(status["name"]) } + updates
      end

      def pod_group_for(pod, adapter)
        group_name = WORKLOAD_CLAIMS.pod_group_name(pod)
        return if group_name.nil?

        group = find_for(adapter, CLAIM_POD_GROUP, group_name, namespace: Support.namespace(pod))
        raise StoreError, "PodGroup #{group_name.inspect} not found" unless group

        group
      end

      def keep_group_reservation?(claim, reference, groups, deleted_uids, adapter)
        uid = reference["uid"]
        return false if uid && deleted_uids.include?(uid.to_s)

        namespace = Support.namespace(claim)
        name = reference["name"]
        if groups
          group = Array(groups).find { |candidate| Support.namespace(candidate) == namespace && Support.name(candidate) == name }
          return !group.nil? && Support.uid(group) == uid
        end
        return true unless adapter

        group = find_for(adapter, CLAIM_POD_GROUP, name, namespace: namespace)
        group = adapter.find_live(CLAIM_POD_GROUP, name: name, namespace: namespace) if group.nil? && Builtins::AdapterCapability.live_reads?(adapter)
        !group.nil? && Support.uid(group) == uid
      end

      def related_pod_group(object, adapter)
        return unless adapter

        find_for(adapter, CLAIM_POD_GROUP, Support.name(object), namespace: Support.namespace(object))
      end
    end
  end
end
