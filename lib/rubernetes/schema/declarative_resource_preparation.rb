# frozen_string_literal: true

module Rubernetes
  module Schema
    # Projects the DRA strategy input used for the comparison. Its caller
    # continues to validate and persist the original request object.
    class DeclarativeResourcePreparation
      KV = KubernetesValidator
      BINDING = %w[bindingConditions bindingFailureConditions].freeze
      LIST_ATTRIBUTES = %w[bools ints strings versions].freeze
      DEVICE_PLACEMENT = %w[nodeName nodeSelector allNodes].freeze
      SHARE = %w[shareID consumedCapacity].freeze

      def initialize(gate_enabled)
        @gate_enabled = gate_enabled
      end

      def prepare(kind, object, old, subresource)
        case kind
        when "DeviceClass" then device_class(object, old)
        when "ResourceClaim"
          subresource == "status" ? claim_status(object, old) : claim(object, old)
        when "ResourceSlice" then resource_slice(object, old)
        end
      end

      private

      def disabled?(gate, in_use)
        !in_use && !@gate_enabled.call(gate)
      end

      def edit(object, field)
        value = KV.fetch(object, field)
        return object unless value.is_a?(Hash)

        object.merge(field => yield(value))
      end

      def edit_items(object, field)
        items = KV.fetch(object, field)
        return object unless items.is_a?(Array)

        object.merge(field => items.map { |item| item.is_a?(Hash) ? yield(item) : item })
      end

      def items(object, *path)
        value = KV.value_at_path(object, path)
        value.is_a?(Array) ? value : []
      end

      def populated?(object, field)
        value = KV.fetch(object, field)
        (value.is_a?(Array) || value.is_a?(Hash)) && !value.empty?
      end

      def set_any?(object, fields)
        fields.any? { |field| !KV.fetch(object, field).nil? }
      end

      def device_class(object, old)
        return object unless disabled?("DRAExtendedResource", !KV.value_at_path(old, %w[spec extendedResourceName]).nil?)

        edit(object, "spec") { |spec| spec.except("extendedResourceName") }
      end

      def slice_devices(object)
        items(object, "spec", "devices").map { |device| KV.fetch(device, "basic") || device }
      end

      def resource_slice(object, old)
        devices = slice_devices(old)
        previous_spec = KV.fetch(old, "spec")
        placement_in_use = populated?(previous_spec, "sharedCounters") || set_any?(previous_spec, %w[perDeviceNodeSelection]) ||
                           devices.any? { |device| populated?(device, "consumesCounters") || set_any?(device, DEVICE_PLACEMENT) }
        partitions = disabled?("DRAPartitionableDevices", placement_in_use)
        taints = disabled?("DRADeviceTaints", devices.any? { |device| populated?(device, "taints") })
        binding_in_use = devices.any? { |device| BINDING.any? { |field| populated?(device, field) } || set_any?(device, %w[bindsToNode]) }
        bindings = !binding_in_use && %w[DRADeviceBindingConditions DRAResourceClaimDeviceStatus].any? { |gate| !@gate_enabled.call(gate) }
        attributes_in_use = devices.any? do |device|
          attributes = KV.fetch(device, "attributes")
          attributes.is_a?(Hash) && attributes.values.any? { |attribute| set_any?(attribute, LIST_ATTRIBUTES) }
        end
        lists = disabled?("DRAListTypeAttributes", attributes_in_use)
        return object unless partitions || taints || bindings || lists

        edit(object, "spec") do |spec|
          spec = spec.except("sharedCounters", "perDeviceNodeSelection") if partitions
          edit_items(spec, "devices") do |device|
            if device["basic"].is_a?(Hash)
              edit(device, "basic") { |basic| slice_device(basic, partitions, taints, bindings, lists) }
            else
              slice_device(device, partitions, taints, bindings, lists)
            end
          end
        end
      end

      def slice_device(device, partitions, taints, bindings, lists)
        device = device.except("consumesCounters", *DEVICE_PLACEMENT) if partitions
        device = device.except("taints") if taints
        device = device.except(*BINDING, "bindsToNode") if bindings
        return device unless lists

        edit(device, "attributes") do |attributes|
          attributes.transform_values { |value| value.is_a?(Hash) ? value.except(*LIST_ATTRIBUTES) : value }
        end
      end

      def exact(request)
        KV.fetch(request, "exactly") || request
      end

      def subrequests(request)
        items(request, "firstAvailable")
      end

      def capacity_in_use?(object, requests)
        items(object, "spec", "devices", "constraints").any? { |entry| set_any?(entry, %w[distinctAttribute]) } ||
          requests.any? { |request| [exact(request), *subrequests(request)].any? { |entry| set_any?(entry, %w[capacity]) } }
      end

      def claim(object, old)
        object = object.merge("status" => KV.fetch(old, "status"))
        requests = items(old, "spec", "devices", "requests")
        priorities = disabled?("DRAPrioritizedList", requests.any? { |request| !subrequests(request).empty? })
        taints_in_use = requests.any? do |request|
          [exact(request), *subrequests(request)].any? { |entry| populated?(entry, "tolerations") }
        end
        taints = disabled?("DRADeviceTaints", taints_in_use)
        admin = disabled?("DRAAdminAccess", requests.any? { |request| set_any?(exact(request), %w[adminAccess]) })
        capacity = disabled?("DRAConsumableCapacity", capacity_in_use?(old, requests))
        return object unless priorities || taints || admin || capacity

        edit(object, "spec") do |spec|
          edit(spec, "devices") do |devices|
            devices = edit_items(devices, "constraints") { |item| item.except("distinctAttribute") } if capacity
            edit_items(devices, "requests") { |item| claim_request(item, priorities, taints, admin, capacity) }
          end
        end
      end

      def claim_request(request, priorities, taints, admin, capacity)
        request = request.except("firstAvailable") if priorities
        exact_fields = []
        exact_fields << "tolerations" if taints
        exact_fields << "adminAccess" if admin
        exact_fields << "capacity" if capacity
        request = request.except(*exact_fields)
        request = edit(request, "exactly") { |body| body.except(*exact_fields) }
        sub_fields = exact_fields - ["adminAccess"]
        edit_items(request, "firstAvailable") { |body| body.except(*sub_fields) }
      end

      def allocation_results(object)
        items(object, "status", "allocation", "devices", "results")
      end

      def claim_status(object, old)
        old_devices = items(old, "status", "devices")
        previous_results = allocation_results(old)
        requests = items(old, "spec", "devices", "requests")
        devices = disabled?("DRAResourceClaimDeviceStatus", !old_devices.empty?)
        admin_in_use = requests.any? { |request| set_any?(exact(request), %w[adminAccess]) } ||
                       previous_results.any? { |result| set_any?(result, %w[adminAccess]) }
        admin = disabled?("DRAAdminAccess", admin_in_use)
        capacity_in_use = capacity_in_use?(old, requests) || previous_results.any? { |result| set_any?(result, SHARE) } ||
                          old_devices.any? { |device| set_any?(device, %w[shareID]) }
        capacity = disabled?("DRAConsumableCapacity", capacity_in_use)
        bindings = disabled?("DRADeviceBindingConditions", previous_results.any? { |result| set_any?(result, BINDING) })
        fields = []
        fields << "adminAccess" if admin
        fields.concat(SHARE) if capacity
        fields.concat(BINDING) if bindings
        object = edit(object, "status") do |status|
          status = status.except("devices") if devices
          status = edit_items(status, "devices") { |device| device.except("shareID") } if capacity
          edit(status, "allocation") do |allocation|
            edit(allocation, "devices") { |value| edit_items(value, "results") { |result| result.except(*fields) } }
          end
        end
        return object if devices || !populated?(KV.fetch(object, "status"), "devices")

        remaining = allocation_results(object).map { |entry| KV.claim_device_id(entry) }
        removed = previous_results.map { |entry| KV.claim_device_id(entry) } - remaining
        edit(object, "status") do |status|
          status.merge("devices" => items(status, "devices").reject { |device| removed.include?(KV.claim_device_id(device)) })
        end
      end
    end
  end
end
