# frozen_string_literal: true

require_relative "../dra_feature_fields"

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      def dra_node_allocatable_mapping_errors(device, path)
        mappings = fetch(device, DRAFeatureFields::MAPPINGS)
        return [] unless mappings.is_a?(Hash)

        capacities = fetch(device, "capacity") || {}
        mappings.flat_map do |name, mapping|
          next [] unless mapping.is_a?(Hash)

          key_path = path + [DRAFeatureFields::MAPPINGS, "[#{name}]"]
          errors = []
          errors << issue(key_path, :invalid, "must be a node allocatable resource name") unless native_resource?(name)
          multiplier = fetch(mapping, "allocationMultiplier")
          errors << issue(key_path + ["allocationMultiplier"], :invalid, "must be positive") if !multiplier.nil? && (Quantity.from_json(multiplier).value <= 0)
          capacity_key = fetch(mapping, "capacityKey")
          if capacity_key == ""
            errors << issue(key_path + ["capacityKey"], :invalid, "capacityKey must not be an empty string")
          elsif capacity_key && !capacities.key?(capacity_key)
            errors << issue(key_path + ["capacityKey"], :not_found, "#{capacity_key.inspect} not found")
          end
          errors << issue(key_path, :invalid, "at least one of allocationMultiplier or capacityKey must be set") if multiplier.nil? && capacity_key.nil?
          errors
        rescue Quantity::ParseError
          errors
        end
      end

      def dra_node_allocatable_status_errors(root)
        direct_claims = Array(root.dig("spec", "resourceClaims"))
        generated_claims = Array(root.dig("status", "resourceClaimStatuses"))
        names = (direct_claims + generated_claims).grep(Hash).filter_map { |entry| fetch(entry, "resourceClaimName") }.to_set
        statuses = Array(root.dig("status", DRAFeatureFields::CLAIM_STATUSES))
        statuses.each_with_index.flat_map do |status, index|
          next [] unless status.is_a?(Hash)

          path = ["status", DRAFeatureFields::CLAIM_STATUSES, index.to_s]
          errors = []
          name = fetch(status, "resourceClaimName")
          errors << issue(path + ["resourceClaimName"], :required, "must not be empty") if name.to_s.empty?
          errors << issue(path + ["resourceClaimName"], :invalid, "no mapping found in pod reference") unless names.include?(name)
          errors << issue(path + ["containers"], :required, "must not be empty") if Array(fetch(status, "containers")).empty?
          errors.concat(dra_node_allocatable_resource_errors(fetch(status, "resources"), path + ["resources"]))
          errors
        end
      end

      def dra_node_allocatable_resource_errors(resources, path)
        return [issue(path, :required, "must not be empty")] unless resources.is_a?(Hash) && !resources.empty?

        resources.flat_map do |name, quantity|
          errors = []
          key = path + ["[#{name}]"]
          errors << issue(key, :invalid, "must be a node allocatable resource name") unless native_resource?(name)
          errors << issue(key, :invalid, "must be non-negative") if Quantity.from_json(quantity).value.negative?
          errors
        rescue Quantity::ParseError
          errors
        end
      end
    end
  end
end
