# frozen_string_literal: true

module Rubernetes
  module Scheduler
    class VolumeBinding
      private

      # checkVolumeProvisions: [provision satisfied, sufficient storage, provisions].
      def check_volume_provisions(claims, node, data)
        provisions = []
        capacities = []
        claims.each do |claim|
          class_name = claim_class(claim)
          if class_name.empty?
            raise BindingError,
                  %(no class for claim "#{value(claim, "metadata", "namespace")}/#{value(claim, "metadata", "name")}")
          end

          storage_class = index(data)[:classes][class_name]
          raise BindingError, %(failed to find storage class "#{class_name}") if storage_class.nil?

          provisioner = Support.value(storage_class, "provisioner", "").to_s
          return [false, true, []] if provisioner.empty? || provisioner == NOT_SUPPORTED_PROVISIONER
          return [false, true, []] unless topology_matches?(Support.value(storage_class, "allowedTopologies", nil), node.labels)

          fits, capacity = enough_capacity(provisioner, claim, class_name, node, data)
          return [true, false, []] unless fits

          provisions << claim
          capacities << capacity if @capacity_scoring
        end
        [true, true, provisions, capacities]
      end

      # hasEnoughCapacity.
      def enough_capacity(provisioner, claim, class_name, node, data)
        request = value(claim, "spec", "resources", "requests", "storage")
        return [true, nil] if request.nil?

        driver = index(data)[:csi_drivers][provisioner]
        return [true, nil] if driver.nil? || value(driver, "spec", "storageCapacity") != true

        size = storage(request)
        capacity = index(data)[:capacities].find do |capacity|
          limit = Support.value(capacity, "maximumVolumeSize", nil) || Support.value(capacity, "capacity", nil)
          topology = Support.value(capacity, "nodeTopology", nil)
          Support.value(capacity, "storageClassName", "").to_s == class_name && !limit.nil? && storage(limit) >= size &&
            !topology.nil? && label_selector_matches?(topology, node.labels)
        end
        [!capacity.nil?, capacity]
      end

      def storage_capacity_score(volumes)
        return 0 if volumes.nil?

        resources = Hash.new { |hash, key| hash[key] = [0, 0] }
        if volumes.bindings.empty?
          volumes.provisions.zip(volumes.provision_capacities || []).each do |claim, capacity|
            next if capacity.nil?

            entry = resources[claim_class(claim)]
            entry[0] += storage(value(claim, "spec", "resources", "requests", "storage")).ceil
            entry[1] = storage(Support.value(capacity, "capacity", nil)).ceil
          end
        else
          volumes.bindings.each do |volume, claim|
            entry = resources[claim_class(claim)]
            entry[0] += storage(value(claim, "spec", "resources", "requests", "storage")).ceil
            entry[1] += storage(value(volume, "spec", "capacity", "storage")).ceil
          end
        end
        return 0 if resources.empty?

        # The pinned default shape assigns 100 at zero utilization and 0 at capacity.
        total = resources.values.sum { |request, capacity| capacity.zero? || request > capacity ? 0 : 100 - (request * 100 / capacity) }
        Rational(total, resources.length).round
      end
    end
  end
end
