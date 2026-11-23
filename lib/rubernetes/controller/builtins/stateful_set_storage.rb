# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class StatefulSetController < WorkloadController
        private

        def volume_claim_templates_for(resource)
          Array(Support.value(Support.spec(resource), "volumeClaimTemplates", [])).filter_map do |claim|
            next unless claim.is_a?(Hash)

            name = Support.name(claim)
            raise ArgumentError, "StatefulSet volumeClaimTemplates entries require metadata.name" if name.empty?

            Support.deep_copy(claim)
          end
        end

        def stateful_pod_for(owner, name:, template_value:, revision_hash:, ordinal:, claim_templates:, existing: nil)
          labels = {REVISION_LABEL => revision_hash.to_s, POD_NAME_LABEL => name.to_s,
                    POD_INDEX_LABEL => ordinal.to_s}
          candidate = if existing
                        Support.deep_copy(existing)
                      else
                        pod_for(owner, name: name, template_value: template_value, labels: labels)
                      end
          candidate["metadata"] ||= {}
          candidate["metadata"]["name"] = name
          candidate["metadata"]["namespace"] ||= Support.namespace(owner) if Support.namespace(owner)
          candidate["metadata"]["labels"] = Support.labels(candidate).merge(labels)
          candidate["spec"] ||= {}
          candidate["spec"]["hostname"] ||= name unless existing
          candidate["spec"]["subdomain"] ||= Support.value(Support.spec(owner), "serviceName", nil) unless existing
          update_storage_volumes(candidate, owner, claim_templates, ordinal)
          candidate
        end

        def update_storage_volumes(pod, owner, claim_templates, ordinal)
          return pod if claim_templates.empty?

          desired = claim_templates.map do |claim|
            {"name" => Support.name(claim), "persistentVolumeClaim" => {
              "claimName" => "#{Support.name(claim)}-#{Support.name(owner)}-#{ordinal}"
            }}
          end
          names = desired.map { |volume| volume["name"] }
          existing = Array(Support.value(Support.spec(pod), "volumes", [])).filter_map do |volume|
            next unless volume.is_a?(Hash)
            next if names.include?(Support.value(volume, "name", "").to_s)

            Support.deep_copy(volume)
          end
          pod["spec"]["volumes"] = desired + existing
          pod
        end

        def reconcile_claims(owner, templates, claims, desired, start, existing_by_ordinal, create_through:)
          return [] if templates.empty? || claims.nil?

          existing = Array(claims).each_with_object({}) do |claim, result|
            result[Support.name(claim)] = claim if Support.kind(claim) == "PersistentVolumeClaim"
          end
          operations = []
          (start...(start + desired)).each do |ordinal|
            templates.each do |template_value|
              name = "#{Support.name(template_value)}-#{Support.name(owner)}-#{ordinal}"
              current = existing[name]
              if current.nil?
                next if ordinal > create_through

                claim = claim_for(owner, template_value, name, ordinal, scaled_down: false)
                # Create the claim before the Pod and attach the retention
                # references when the controller can see the Pod's identity.
                claim.fetch("metadata").delete("ownerReferences")
                operations << operation_create(claim, descriptor: PERSISTENT_VOLUME_CLAIM, reason: "statefulset volume claim")
                next
              end
              pod = existing_by_ordinal[ordinal]
              next unless pod

              desired_claim = claim_for(owner, template_value, name, ordinal, scaled_down: false)
              candidate = claim_metadata_update(current, desired_claim, owner: owner, pod: pod)
              update = operation_update(current, candidate, descriptor: PERSISTENT_VOLUME_CLAIM,
                                                            reason: "statefulset volume claim retention policy")
              operations << update if update
            end
          end

          policy = pvc_retention_policy(owner)
          if policy.fetch(:when_scaled) == "Delete"
            existing.each_value do |claim|
              ordinal = ordinal_for_claim(claim, owner)
              next unless ordinal && (ordinal < start || ordinal >= start + desired)
              next unless existing_by_ordinal[ordinal]

              desired_claim = claim_for(owner, claim, Support.name(claim), ordinal, scaled_down: true,
                                                                                    pod: existing_by_ordinal[ordinal])
              candidate = claim_metadata_update(claim, desired_claim, owner: owner,
                                                                      pod: existing_by_ordinal[ordinal])
              update = operation_update(claim, candidate, descriptor: PERSISTENT_VOLUME_CLAIM,
                                                          reason: "statefulset scaled volume claim retention policy")
              operations << update if update
            end
          end
          operations
        end

        def claim_for(owner, template_value, name, _ordinal, scaled_down:, pod: nil)
          candidate = Support.deep_copy(template_value)
          candidate["apiVersion"] ||= "v1"
          candidate["kind"] = "PersistentVolumeClaim"
          candidate["metadata"] ||= {}
          candidate["metadata"]["name"] = name
          candidate["metadata"]["namespace"] ||= Support.namespace(owner) if Support.namespace(owner)
          selector = Support.value(Support.spec(owner), "selector", {})
          selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && selector.key?("matchLabels")
          labels = Support.value(candidate["metadata"], "labels", {})
          labels = {} unless labels.is_a?(Hash)
          candidate["metadata"]["labels"] = labels.merge(selector.is_a?(Hash) ? selector : {})
          candidate["metadata"]["ownerReferences"] = desired_claim_owner_references(
            owner, candidate, scaled_down: scaled_down, pod: pod
          )
          candidate
        end

        def claim_metadata_update(current, desired, owner:, pod:)
          managed_uids = [owner, pod].to_h do |object|
            [claim_owner_key(Support.owner_reference(object)), Support.uid(object).to_s]
          end
          existing_refs = Support.owner_references(current)
          managed_refs, retained_refs = existing_refs.partition { |reference| managed_uids.key?(claim_owner_key(reference)) }
          # The referenced StatefulSet or Pod may have been recreated with
          # the same name. Leave that previous incarnation's claim alone.
          stale_owner = managed_refs.any? do |reference|
            Support.ref_value(reference, "uid").to_s != managed_uids[claim_owner_key(reference)]
          end
          return current if stale_owner

          controller = Support.controller_owner_reference(current)
          retained_refs.concat(Support.owner_references(desired)) if controller.nil? || managed_refs.include?(controller)
          return current if retained_refs == existing_refs

          candidate = Support.deep_copy(current)
          candidate["metadata"] = Support.metadata(candidate).merge("ownerReferences" => retained_refs)
          candidate
        end

        def claim_owner_key(reference)
          %w[apiVersion kind name].map { |field| Support.ref_value(reference, field).to_s }
        end

        def desired_claim_owner_references(owner, _claim, scaled_down:, pod: nil)
          policy = pvc_retention_policy(owner)
          retain = []
          return retain if policy.fetch(:when_deleted) == "Retain" && policy.fetch(:when_scaled) == "Retain"

          return [Support.owner_reference(pod)] if scaled_down && policy.fetch(:when_scaled) == "Delete" && pod
          return [Support.owner_reference(owner)] if policy.fetch(:when_deleted) == "Delete"

          retain
        end

        def pvc_retention_policy(resource)
          raw = Support.value(Support.spec(resource), "persistentVolumeClaimRetentionPolicy", {})
          raw = {} unless raw.is_a?(Hash)
          when_deleted = Support.value(raw, "whenDeleted", "Retain").to_s
          when_scaled = Support.value(raw, "whenScaled", "Retain").to_s
          unless %w[Retain Delete].include?(when_deleted) && %w[Retain Delete].include?(when_scaled)
            raise ArgumentError, "StatefulSet PVC retention policy must use Retain or Delete"
          end

          {when_deleted: when_deleted, when_scaled: when_scaled}
        end

        def ordinal_for_claim(claim, owner)
          prefix = "-#{Support.name(owner)}-"
          match = Support.name(claim).match(/#{Regexp.escape(prefix)}(\d+)\z/)
          match && Integer(match[1])
        rescue ArgumentError
          nil
        end
      end
    end
  end
end
