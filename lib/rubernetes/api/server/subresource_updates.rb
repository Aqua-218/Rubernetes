# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # What a write through a subresource may change: status, the CSR approval
      # conditions, a Pod resize, and the extra authorization of a ResourceClaim
      # status.
      module SubresourceUpdates
        private

        # E2 status writes keep metadata unless the kind's status strategy resets it
        # Kinds whose status strategy calls rest.ResetObjectMetaForStatus
        # (pkg/registry/**/strategy.go): only these discard metadata changes
        # sent on the status subresource.  Every other kind (Namespace,
        # Deployment, ...) applies labels/annotations/finalizers/ownerReferences
        # from a status write, and the conformance suite relies on it.
        STATUS_META_RESET_KINDS = %w[
          Pod ServiceCIDR VolumeAttachment ResourceClaim DeviceTaintRule StorageVersionMigration
          ResourcePoolStatusRequest PodGroup ValidatingAdmissionPolicy PodCertificateRequest StorageVersion
        ].freeze

        STATUS_META_UPDATABLE_FIELDS = %w[labels annotations finalizers ownerReferences].freeze

        # The /approval subresource of a CertificateSigningRequest writes exactly
        # one thing: the approval conditions.  registry/certificates/
        # certificates/strategy.go approvalStrategy#PrepareForUpdate --
        # "Updating the approval should only update the conditions" -- resets the
        # spec to the stored one and keeps the stored status apart from
        # conditions, while the request's metadata (its annotations) applies
        # normally.  Treating it like any non-status subresource discarded the
        # conditions entirely, so a patch to /approval came back with none and
        # "[sig-auth] Certificates API should support CSR API operations"
        # reported "patched object should have the applied condition".
        APPROVAL_STATUS_FIELDS = %w[conditions].freeze

        def approval_subresource?(route)
          route.subresource.to_s == "approval" && route.resource.kind.to_s == "CertificateSigningRequest"
        end

        def approval_update(existing, candidate)
          object = deep_copy(candidate)
          object["spec"] = deep_copy(existing["spec"]) if existing.key?("spec")
          status = deep_copy(existing["status"] || {})
          submitted = candidate["status"].is_a?(Hash) ? candidate["status"] : {}
          APPROVAL_STATUS_FIELDS.each do |field|
            next unless submitted.key?(field)

            status[field] = deep_copy(submitted[field])
          end
          status["conditions"] = populate_condition_timestamps(status["conditions"], existing.dig("status", "conditions"))
          status.delete("conditions") if status["conditions"].nil?
          object["status"] = status
          object
        end

        # strategy.go populateConditionTimestamps: a condition the client sent
        # without timestamps gets them, and one whose status has not changed
        # keeps the transition time it already had.
        def populate_condition_timestamps(conditions, previous)
          return nil unless conditions.is_a?(Array)

          now = @clock.call.utc.iso8601
          existing = Array(previous)
          conditions.map do |value|
            condition = value.is_a?(Hash) ? deep_copy(value) : value
            next condition unless condition.is_a?(Hash)

            condition["lastUpdateTime"] = now if condition["lastUpdateTime"].to_s.empty?
            if condition["lastTransitionTime"].to_s.empty?
              matching = existing.find { |old| old.is_a?(Hash) && old["type"].to_s == condition["type"].to_s }
              condition["lastTransitionTime"] = if matching && matching["status"].to_s == condition["status"].to_s &&
                                                   !matching["lastTransitionTime"].to_s.empty?
                                                  matching["lastTransitionTime"]
                                                else
                                                  now
                                                end
            end
            condition
          end
        end

        def status_update(existing, candidate, resource: nil)
          result = deep_copy(existing)
          result["status"] = deep_copy(candidate["status"] || {})
          best_effort { record_csr_honored_duration(existing, result) } if resource && csr_resource?(resource)
          result["metadata"] ||= {}
          metadata = candidate.is_a?(Hash) && candidate["metadata"].is_a?(Hash) ? candidate["metadata"] : {}
          kind = resource ? resource.kind.to_s : nil
          unless kind && STATUS_META_RESET_KINDS.include?(kind)
            STATUS_META_UPDATABLE_FIELDS.each do |field|
              next unless metadata.key?(field)

              if metadata[field].nil?
                result["metadata"].delete(field)
              else
                result["metadata"][field] = deep_copy(metadata[field])
              end
            end
          end
          fields = metadata["managedFields"]
          result["metadata"]["managedFields"] = deep_copy(fields) if fields
          # "the Pod QoS is immutable and populated at creation time by the
          # kube-apiserver ... backfill it" (registry/core/pod/strategy.go:225).
          # A kubelet that omits qosClass from its status write must not erase it.
          if kind == "Pod"
            status = result["status"] ||= {}
            previous_qos = existing.dig("status", "qosClass")
            status["qosClass"] = previous_qos if status["qosClass"].to_s.empty? && !previous_qos.to_s.empty?
          end
          result
        end

        def pod_resize_route?(route)
          route.subresource.to_s == "resize" && pod_resource?(route.resource)
        end

        # What the route's subresource lets a write change: status alone, the
        # approval conditions, a Pod's resources -- and through the resource
        # itself, everything but the stored status.
        def apply_subresource_strategy(route, existing, object)
          if route.subresource == "status" then status_update(existing, object, resource: route.resource)
          elsif approval_subresource?(route) then approval_update(existing, object)
          elsif pod_resize_route?(route) then resize_update(existing, object)
          else
            object["status"] = deep_copy(existing["status"]) if existing.key?("status")
            object
          end
        end

        # pkg/registry/core/pod podResizeStrategy PrepareForUpdate
        # (dropNonResizeUpdates): only container/initContainer resources and
        # resizePolicy, and the pod-level resources, come from the request;
        # everything else -- the rest of the spec, the status, labels and
        # annotations -- stays as stored.  Added, removed, renamed or reordered
        # containers are passed through for validation to refuse.
        def resize_update(existing, candidate)
          new_spec = candidate["spec"].is_a?(Hash) ? candidate["spec"] : {}
          old_spec = existing["spec"].is_a?(Hash) ? existing["spec"] : {}
          merged = lambda do |field|
            new_list = Array(new_spec[field])
            old_list = Array(old_spec[field])
            return nil if new_list.length != old_list.length
            return old_list if new_list.empty?

            new_list.each_with_index.map do |container, index|
              return nil unless container.is_a?(Hash) && old_list[index].is_a?(Hash) && container["name"] == old_list[index]["name"]

              deep_copy(old_list[index]).merge("resources" => deep_copy(container["resources"]),
                                               "resizePolicy" => deep_copy(container["resizePolicy"])).compact
            end
          end
          containers = merged.call("containers")
          init_containers = merged.call("initContainers")
          return candidate if containers.nil? || init_containers.nil?

          result = deep_copy(existing)
          result["spec"] = deep_copy(old_spec)
          if feature_gate_enabled?("InPlacePodLevelResourcesVerticalScaling")
            new_spec.key?("resources") ? result["spec"]["resources"] = deep_copy(new_spec["resources"]) : result["spec"].delete("resources")
          end
          result["spec"]["containers"] = containers
          result["spec"]["initContainers"] = init_containers if old_spec.key?("initContainers")
          # ResetObjectMetaForStatus keeps the stored metadata; the request's
          # resourceVersion still guards the write.
          rv = metadata_value(candidate, "resourceVersion")
          result["metadata"]["resourceVersion"] = rv unless rv.nil?
          managed = candidate.dig("metadata", "managedFields")
          result["metadata"]["managedFields"] = managed if managed
          result
        end

        # DRAResourceClaimGranularStatusAuthorization (Beta, on;
        # pkg/registry/resource AuthorizedForBinding / AuthorizedForDeviceStatus):
        # a ResourceClaim status update that changes status.allocation or
        # status.reservedFor also needs <verb> on resourceclaims/binding (the
        # scheduler's "bind claim"), and one that changes a driver's
        # status.devices needs associated-node:<verb> (a service account on the
        # allocated node) or arbitrary-node:<verb> on resourceclaims/driver
        # named after the driver.
        def authorize_resource_claim_status!(request, route, existing, object)
          return unless route.subresource.to_s == "status" && existing.is_a?(Hash) && object.is_a?(Hash)
          return unless route.resource.group.to_s == "resource.k8s.io" && route.resource.resource.to_s == "resourceclaims"

          authorizer = @security&.authorizer
          return unless authorizer

          base = request.attributes
          return unless base.is_a?(Security::Authorization::Attributes)

          old_status = existing["status"].is_a?(Hash) ? existing["status"] : {}
          new_status = object["status"].is_a?(Hash) ? object["status"] : {}
          causes = claim_binding_causes(authorizer, base, old_status, new_status) +
                   claim_device_status_causes(authorizer, base, old_status, new_status)
          return if causes.empty?

          name = metadata_value(object, "name")
          rendered = causes.map { |cause| "#{cause["field"]}: #{cause["message"]}" }.join(", ")
          raise Status::Invalid.new(%(ResourceClaim.resource.k8s.io "#{name}" is invalid: #{rendered}),
                                    details: {"name" => name, "group" => "resource.k8s.io", "kind" => "ResourceClaim", "causes" => causes})
        end

        # AuthorizedForBinding.
        def claim_binding_causes(authorizer, base, old_status, new_status)
          return [] if old_status["allocation"] == new_status["allocation"] && old_status["reservedFor"] == new_status["reservedFor"]

          decision = authorizer.authorize(base.with(subresource: "binding", namespace: "", name: ""))
          return [] if decision.allowed?

          message = %(Forbidden: changing status.allocation or status.reservedFor requires resource="resourceclaims/binding", ) +
                    %(verb="#{base.verb}" permission: #{decision.reason || "forbidden"})
          [{"field" => "status.allocation", "reason" => "FieldValueForbidden", "message" => message}]
        end

        # AuthorizedForDeviceStatus: one cause per driver whose device
        # statuses changed and that none of the verbs is granted for.
        def claim_device_status_causes(authorizer, base, old_status, new_status)
          return [] unless new_status["allocation"]

          drivers = claim_device_status_drivers(old_status, new_status)
          return [] if drivers.empty?

          verbs = if claim_node_service_account?(base.user, new_status["allocation"])
                    ["associated-node:#{base.verb}", "arbitrary-node:#{base.verb}"]
                  else
                    ["arbitrary-node:#{base.verb}"]
                  end
          drivers.filter_map do |driver|
            reasons = verbs.map do |verb|
              decision = authorizer.authorize(base.with(verb: verb, subresource: "driver", name: driver))
              break nil if decision.allowed?

              decision.reason || "forbidden"
            end
            next if reasons.nil?

            message = %(Forbidden: changing status.devices requires resource="resourceclaims/driver", verb="[#{verbs.join(" ")}]" ) +
                      "permission: #{reasons.first}"
            {"field" => "status.devices", "reason" => "FieldValueForbidden", "message" => message}
          end
        end

        # getModifiedDrivers: drivers with an added, changed or removed device status.
        def claim_device_status_drivers(old_status, new_status)
          key = ->(device) { [device["driver"], device["pool"], device["device"], device["shareID"]] }
          old_devices = Array(old_status["devices"]).to_h { |device| [key.call(device), device] }
          drivers = []
          Array(new_status["devices"]).each do |device|
            previous = old_devices.delete(key.call(device))
            drivers << device["driver"].to_s if previous != device
          end
          drivers.concat(old_devices.values.map { |device| device["driver"].to_s })
          drivers.uniq.sort
        end

        # saAssociatedWithAllocatedNode: a service account whose token names the
        # one node the allocation is pinned to.
        def claim_node_service_account?(user, allocation)
          terms = Array(allocation.dig("nodeSelector", "nodeSelectorTerms"))
          return false unless terms.length == 1 && Array(terms[0]["matchExpressions"]).empty? && Array(terms[0]["matchFields"]).length == 1

          field = terms[0]["matchFields"][0]
          return false unless field["key"] == "metadata.name" && field["operator"] == "In" && Array(field["values"]).length == 1
          return false unless user&.name.to_s.start_with?("system:serviceaccount:")

          nodes = Array(user.extra["authentication.kubernetes.io/node-name"])
          nodes.length == 1 && nodes.first == field["values"][0]
        end

        # ... and one whose issued certificate honoured it (the registry's
        # status strategy compares the certificate's validity with the request).
        def record_csr_honored_duration(existing, updated)
          return unless existing.is_a?(Hash) && updated.is_a?(Hash)

          before = existing.dig("status", "certificate").to_s
          after = updated.dig("status", "certificate").to_s
          return if after.empty? || after == before

          requested = updated.dig("spec", "expirationSeconds")
          return if requested.nil?

          certificate = OpenSSL::X509::Certificate.new(after.unpack1("m0"))
          issued = certificate.not_after - certificate.not_before
          # kube-controller-manager clamps and skews by up to 5 minutes.
          return unless (issued - requested.to_i).abs <= 600

          @metrics&.increment("apiserver_certificates_registry_csr_honored_duration_total",
                              {"signerName" => updated.dig("spec", "signerName").to_s})
        end
      end
    end
  end
end
