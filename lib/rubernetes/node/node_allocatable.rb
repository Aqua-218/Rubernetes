# frozen_string_literal: true

require_relative "../resource_helpers"

module Rubernetes
  module Node
    # Node Allocatable (pkg/kubelet/cm GetNodeAllocatableReservation and the
    # nodestatus MachineInfo setter): allocatable is capacity less
    # system-reserved, kube-reserved and the hard eviction thresholds for
    # memory.available and nodefs.available, never below zero, and memory
    # less every hugepage pool.
    module NodeAllocatable
      Quantity = ResourceHelpers::Quantity

      module_function

      # GetNodeAllocatableReservation: {resource => Quantity}, zeros omitted.
      # +hard_thresholds+ are EvictionManager::Threshold values.
      def reservation(capacity:, system_reserved: {}, kube_reserved: {}, hard_thresholds: [])
        capacity = quantities(capacity)
        system = quantities(system_reserved)
        kube = quantities(kube_reserved)
        eviction = hard_eviction_reservation(hard_thresholds, capacity)
        capacity.each_key.with_object({}) do |name, result|
          value = [system[name], kube[name], eviction[name]].compact.reduce(Quantity.new(Rational(0), :decimal_si)) do |sum, item|
            add(sum, item)
          end
          result[name] = value unless value.value.zero?
        end
      end

      # hardEvictionReservation.
      def hard_eviction_reservation(thresholds, capacity)
        Array(thresholds).each_with_object({}) do |threshold, result|
          next unless threshold.hard?

          resource = case threshold.signal
                     when "memory.available" then "memory"
                     when "nodefs.available" then "ephemeral-storage"
                     end
          next unless resource

          result[resource] = if threshold.quantity
                               threshold.quantity
                             else
                               total = capacity[resource]&.value || 0
                               Quantity.new(Rational((total.to_f * threshold.percentage).to_i), :binary_si)
                             end
        end
      end

      # The MachineInfo setter: capacity - reservation, clamped at zero;
      # memory also less the hugepage pools.  Values render canonically in
      # the capacity quantity's format.
      def allocatable(capacity, reservation)
        capacity = quantities(capacity)
        reservation = quantities(reservation)
        result = capacity.to_h do |name, quantity|
          value = quantity.value - (reservation[name]&.value || 0)
          [name, Quantity.new([value, Rational(0)].max, quantity.format)]
        end
        capacity.each do |name, quantity|
          next unless name.start_with?("hugepages-") && result.key?("memory")

          memory = result["memory"]
          result["memory"] = Quantity.new([memory.value - quantity.value, Rational(0)].max, memory.format)
        end
        result.transform_values(&:to_s)
      end

      def quantities(map)
        (map || {}).each_with_object({}) do |(name, value), result|
          next if value.nil?

          result[name.to_s] = value.is_a?(Quantity) ? value : Quantity.from_json(value)
        end
      end

      # Quantity.Add: a zero receiver takes the addend's format.
      def add(sum, addend)
        format = sum.value.zero? ? addend.format : sum.format
        Quantity.new(sum.value + addend.value, format)
      end
    end
  end
end
