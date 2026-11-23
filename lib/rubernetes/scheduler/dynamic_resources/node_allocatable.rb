# frozen_string_literal: true

module Rubernetes
  module Scheduler
    class DynamicResources
      # The compute footprint of DRA allocations comes from the devices in the
      # scheduler's slice cache and the allocation quantities on each claim.
      module NodeAllocatable
        STATUS_FIELD = "nodeAllocatableResourceClaimStatuses"
        Quantity = Schema::Quantity

        module_function

        def claim_statuses(pod, claims, allocations, slices)
          by_id = devices_by_id(slices)
          containers_by_claim = container_claim_names(pod)
          claims.zip(allocations).filter_map do |claim, allocation|
            name = claim.dig("metadata", "name")
            resources = mapped_resources(allocation, by_id, name)
            next if resources.empty?

            {"resourceClaimName" => name, "containers" => containers_by_claim.fetch(name, []),
             "resources" => resources.transform_values(&:canonical)}
          end.uniq { |status| status.fetch("resourceClaimName") }.sort_by { |status| status.fetch("resourceClaimName") }
        end

        def devices_by_id(slices)
          slices.sort_by { |slice| -slice.dig("spec", "pool", "generation").to_i }.each_with_object({}) do |slice, index|
            spec = slice.fetch("spec", {})
            Array(spec["devices"]).each do |device|
              id = [spec["driver"], spec.dig("pool", "name"), device["name"]]
              index[id] ||= device
            end
          end
        end

        def container_claim_names(pod)
          generated = Array(pod.status["resourceClaimStatuses"]).to_h { |entry| [entry["name"], entry["resourceClaimName"]] }
          names = Array(pod.spec["resourceClaims"]).to_h do |entry|
            [entry["name"], entry["resourceClaimName"] || generated[entry["name"]]]
          end
          (pod.init_containers + pod.containers).each_with_object({}) do |container, result|
            Array(container.dig("resources", "claims")).filter_map { |ref| names[ref["name"]] }.uniq.each do |name|
              (result[name] ||= []) << container.fetch("name")
            end
          end
        end

        def mapped_resources(allocation, devices, claim_name)
          Array(allocation&.dig("devices", "results")).each_with_object({}) do |result, resources|
            id = result.values_at("driver", "pool", "device")
            mappings = devices.dig(id, "nodeAllocatableResourceMappings") || {}
            mappings.each do |resource, mapping|
              multiplier = Quantity.from_json(mapping.fetch("allocationMultiplier", "1"))
              capacity_key = mapping["capacityKey"]
              quantity = multiplier
              if capacity_key && !capacity_key.empty?
                raise ClaimError, "claim #{claim_name}, device #{id.last}: consumed capacity is missing for #{capacity_key}" unless result["consumedCapacity"]

                capacity = result["consumedCapacity"][capacity_key]
                next if capacity.nil?

                amount = Quantity.from_json(capacity)
                quantity = Quantity.new(amount.value * multiplier.value, amount.format)
              end
              resources[resource] = Allocator.add(resources[resource], quantity)
            end
          end
        end

        def rejection(pod, node, statuses)
          used_claims = node.pods.reject { |other| other.uid == pod.uid || other.namespace != pod.namespace }.flat_map do |other|
            Array(other.status[STATUS_FIELD]).map { |status| status["resourceClaimName"] }
          end.to_set
          statuses.each do |status|
            name = status.fetch("resourceClaimName")
            return reject("node allocatable resource claim #{name} is already used by another pod") if used_claims.include?(name)
            return reject("claim #{name}: node-allocatable resource claim not referenced by any container within the pod") if status.fetch("containers").empty?
          end

          candidate = with_status(pod, statuses)
          demand = candidate.requests(use_dra_node_allocatable: true)
          budget = ResourceHelpers.resource_list(pod.spec.dig("resources", "requests"))
          unless budget.empty?
            container_demand = Support.requests_for(candidate, use_dra_node_allocatable: true, skip_pod_level: true)
            budget.each_key do |resource|
              next unless ResourceHelpers.supported_pod_level_resource?(resource)
              if container_demand.fetch(resource, 0) > demand.fetch(resource, 0)
                return reject("pod level request for #{resource} is insufficient to cover the aggregated container and node-allocatable DRA requests")
              end
            end
          end

          capacity = node.allocatable
          available = node.available
          missing = demand.keys.select do |resource|
            (%w[cpu memory ephemeral-storage].include?(resource) || resource.start_with?("hugepages-")) &&
              demand.fetch(resource).positive? && demand.fetch(resource) > available.fetch(resource, 0)
          end
          return if missing.empty?

          code = missing.any? { |name| demand.fetch(name) > capacity.fetch(name, 0) } ? "UnschedulableAndUnresolvable" : "Unschedulable"
          reject(missing.map { |name| "Insufficient #{name}" }.join(", "), code: code)
        end

        def reject(message, code: "UnschedulableAndUnresolvable")
          Filters::Helpers.reject(message, code: code)
        end

        def with_status(pod, statuses)
          pod.with("status" => pod.status.merge(STATUS_FIELD => statuses))
        end
      end
    end
  end
end
