# frozen_string_literal: true

module Rubernetes
  module Scheduler
    class DynamicResources
      # The group can pick different devices on a later scheduling attempt
      # once none of its members is assigned or assumed on a node.
      def unreserve_idle_group_claim(pod, context)
        return unless @workload_claims && @api && pod.scheduling_group && context

        group = context.pod_group(pod.namespace, pod.scheduling_group)
        return unless group
        return if context.pods.any? do |other|
          !other.node_name.empty? && other.namespace == pod.namespace && other.scheduling_group == pod.scheduling_group
        end

        group_uid = group.dig("metadata", "uid")
        return if group_uid.to_s.empty?

        claims = claims_by_key(context)
        statuses = Array(group.dig("status", "resourceClaimStatuses")).to_h do |entry|
          [entry["name"], entry["resourceClaimName"]]
        end
        Array(group.dig("spec", "resourceClaims")).each do |entry|
          name = entry["resourceClaimName"] || statuses[entry["name"]]
          claim = claims["#{pod.namespace}/#{name}"]
          next unless claim && allocated?(claim)

          if entry["resourceClaimTemplateName"]
            owner = Array(claim.dig("metadata", "ownerReferences")).find { |ref| ref["controller"] == true }
            next unless owner && owner["uid"] == group_uid
          end
          next unless Array(claim.dig("status", "reservedFor")).any? do |reference|
            WorkloadClaims.group_reference?(reference) && reference["uid"] == group_uid
          end

          patch = {"metadata" => {"uid" => claim_uid(claim)}, "status" => {"reservedFor" => [{"$patch" => "delete", "uid" => group_uid}]}}
          return @api.patch_claim_status(pod.namespace, name, patch)
        end
        nil
      end

      private

      def claim_bindings(pod, context)
        return {} unless @workload_claims

        group = pod.scheduling_group && context&.pod_group(pod.namespace, pod.scheduling_group)
        raise ClaimError, "pod group #{pod.namespace}/#{pod.scheduling_group} not found" if pod.scheduling_group && group.nil?

        Array(pod.spec["resourceClaims"]).each_with_object({}) do |entry, result|
          name, = claim_name(pod, entry)
          next if name.nil?

          result["#{pod.namespace}/#{name}"] = WorkloadClaims.reference_for(pod.to_h, entry, group, workload_claims: true)
        end
      end

      def share_pending_claim?(binding, pending)
        binding && WorkloadClaims.group_reference?(binding) && Array(pending.dig("status", "reservedFor")).include?(binding)
      end

      def verify_shared_claim!(pod, claim)
        current = @api&.get_claim(claim.dig("metadata", "namespace"), claim.dig("metadata", "name"))
        return if current && claim_uid(current) == claim_uid(claim) && allocated?(current) && reserved_for_pod?(pod, current)

        raise PluginError.new("claim #{ref(claim)} did not bind for the pod group", plugin: NAME, phase: :pre_bind)
      end

      # foreachPodResourceClaim.
      def pod_claims(pod, context)
        spec = pod.spec
        return [] if Array(spec["resourceClaims"]).empty?

        claims = claims_by_key(context)
        Array(spec["resourceClaims"]).filter_map do |entry|
          name, must_check_owner = claim_name(pod, entry)
          next nil if name.nil?

          claim = claims["#{pod.namespace}/#{name}"]
          raise ClaimError, "resourceclaim.resource.k8s.io \"#{name}\" not found" unless claim
          raise ClaimError, "resourceclaim \"#{name}\" is being deleted" if claim.dig("metadata", "deletionTimestamp")

          if must_check_owner
            owner = Array(claim.dig("metadata", "ownerReferences")).find { |reference| reference["controller"] == true }
            unless owner && (owner["uid"].to_s == pod.uid || (@workload_claims && WorkloadClaims.group_owner_for_pod?(pod.to_h, owner)))
              raise ClaimError,
                    "ResourceClaim #{pod.namespace}/#{name} was not created for Pod #{pod.namespace}/#{pod.name} (Pod is not owner)"
            end
          end
          claim
        end
      end

      # resourceclaim.Name.
      def claim_name(pod, entry)
        if entry["resourceClaimName"]
          [entry["resourceClaimName"], false]
        elsif entry["resourceClaimTemplateName"]
          status = Array(pod.status["resourceClaimStatuses"]).find { |candidate| candidate["name"] == entry["name"] }
          raise ClaimError, "pod \"#{pod.namespace}/#{pod.name}\": ResourceClaim not created yet" unless status

          # A nil name: the claim was not needed and is not created.
          [status["resourceClaimName"], true]
        else
          raise ClaimError,
                "pod \"#{pod.namespace}/#{pod.name}\", spec.resourceClaim #{entry["name"].to_s.dump}: none of the supported fields are set"
        end
      end
    end
  end
end
