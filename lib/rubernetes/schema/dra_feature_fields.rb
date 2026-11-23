# frozen_string_literal: true

module Rubernetes
  module Schema
    # REST strategy field pruning for alpha DRA features. Updates preserve
    # previously stored gated fields while the corresponding feature is off.
    module DRAFeatureFields
      NODE_ALLOCATABLE = "DRANodeAllocatableResources"
      LIST_TYPE_ATTRIBUTES = "DRAListTypeAttributes"
      CLAIM_STATUSES = "nodeAllocatableResourceClaimStatuses"
      MAPPINGS = "nodeAllocatableResourceMappings"
      LIST_ATTRIBUTES = %w[bools ints strings versions].freeze

      module_function

      def prepare(resource, object, old, gate_enabled)
        return object if resource.custom?

        if resource.group == "resource.k8s.io" && resource.kind == "ResourceSlice"
          prepare_slice(object, old, gate_enabled)
        elsif resource.group.to_s.empty? && resource.kind == "Pod"
          prepare_pod(object, old, gate_enabled)
        else
          object
        end
      end

      def prepare_slice(object, old, gate_enabled)
        devices = Array(old&.dig("spec", "devices")).grep(Hash).map { |device| device["basic"] || device }
        mappings_in_use = devices.any? { |device| !device.fetch(MAPPINGS, {}).to_h.empty? }
        lists_in_use = devices.any? do |device|
          device.fetch("attributes", {}).to_h.values.grep(Hash).any? { |attribute| LIST_ATTRIBUTES.any? { |key| attribute.key?(key) } }
        end
        drop_mappings = !mappings_in_use && !gate_enabled.call(NODE_ALLOCATABLE)
        drop_lists = !lists_in_use && !gate_enabled.call(LIST_TYPE_ATTRIBUTES)
        spec = object["spec"]
        return object unless (drop_mappings || drop_lists) && spec.is_a?(Hash) && spec["devices"].is_a?(Array)

        prepared = spec["devices"].map do |device|
          next device unless device.is_a?(Hash)

          if device["basic"].is_a?(Hash)
            device.merge("basic" => prepare_device(device["basic"], drop_mappings, drop_lists))
          else
            prepare_device(device, drop_mappings, drop_lists)
          end
        end
        object.merge("spec" => spec.merge("devices" => prepared))
      end

      def prepare_device(device, drop_mappings, drop_lists)
        device = device.except(MAPPINGS) if drop_mappings
        return device unless drop_lists && device["attributes"].is_a?(Hash)

        attributes = device["attributes"].transform_values { |attribute| attribute.is_a?(Hash) ? attribute.except(*LIST_ATTRIBUTES) : attribute }
        device.merge("attributes" => attributes)
      end

      def prepare_pod(object, old, gate_enabled)
        status = object["status"]
        return object unless status.is_a?(Hash) && status.key?(CLAIM_STATUSES)
        return object if gate_enabled.call(NODE_ALLOCATABLE) || !Array(old&.dig("status", CLAIM_STATUSES)).empty?

        object.merge("status" => status.except(CLAIM_STATUSES))
      end
    end
  end
end
