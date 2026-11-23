# frozen_string_literal: true

require_relative "../../volume/csi_migration"

module Rubernetes
  module Controller
    # Expands a PVC only after its bound PV reports enough capacity. Filesystem
    # claims retain FileSystemResizePending until node expansion is observed.
    class PersistentVolumeExpanderController < BaseController
      include InfrastructureStorageSupport

      PV = ResourceDescriptor.parse("PersistentVolume")
      PVC = ResourceDescriptor.parse("PersistentVolumeClaim")
      STORAGE_CLASS = ResourceDescriptor.parse("StorageClass")
      STORAGE_RESIZER = "volume.kubernetes.io/storage-resizer"

      def plan(claim, store: nil, persistent_volume: nil, volume: nil, storage_class: nil,
               allow_volume_expansion: nil, node_expanded: false, provider: nil,
               cloud_provider: nil, cloud: nil, **_options)
        adapter = adapter_for(store)
        pv = persistent_volume || volume || bound_volume(claim, adapter)
        return no_expansion_result(claim) unless pv

        requested = claim_requested_capacity(claim)
        return no_expansion_result(claim) unless requested > claim_status_capacity(claim)

        volume_spec = Support.spec(pv)
        migrated_driver = ::Rubernetes::Volume::CSIMigration::DRIVERS.find { |source, _| volume_spec[source].is_a?(Hash) }&.last
        return external_expansion_result(claim, migrated_driver: migrated_driver) if volume_spec["csi"].is_a?(Hash) || migrated_driver

        class_object = storage_class.nil? ? claim_storage_class(claim, adapter) : storage_class
        return failed_expansion_result(claim, "VolumeExpansionNotAllowed") unless expansion_allowed?(class_object, allow_volume_expansion)

        pv_capacity_value = volume_capacity_value(pv)
        if quantity_base(pv_capacity_value) < requested
          expanded = call_provider(provider_from(provider || cloud_provider || cloud), %i[expand_volume expand],
                                   positional: [pv, claim], keywords: {volume: pv, claim: claim, requested_capacity: requested})
          pv_capacity_value = provider_capacity(expanded) || pv_capacity_value
        end
        return resizing_result(claim, requested) if quantity_base(pv_capacity_value) < requested

        expanded_result(claim, pv, pv_capacity_value, node_expanded)
      end

      private

      def external_expansion_result(claim, migrated_driver:)
        annotations = Support.value(Support.metadata(claim), "annotations", {}) || {}
        resizer = annotations[STORAGE_RESIZER]
        return no_expansion_result(claim) if resizer && (!migrated_driver || resizer == migrated_driver)

        operations = []
        if migrated_driver
          candidate = Support.deep_copy(claim)
          (candidate.fetch("metadata")["annotations"] ||= {})[STORAGE_RESIZER] = migrated_driver
          operations << operation_update(claim, candidate, descriptor: PVC, subresource: "status",
                                                           reason: "assign migrated volume to external resizer")
        end
        ReconcileResult.new(operations: operations, status: Support.status(claim), controller: name, key: name_key(claim),
                            events: [{"type" => "Normal", "reason" => "ExternalExpanding",
                                      "message" => "waiting for an external controller to expand this PVC"}])
      end

      def bound_volume(claim, adapter)
        volume_name = Support.value(Support.spec(claim), "volumeName", nil).to_s
        list_storage_objects(adapter, PV, namespace: :all).find { |candidate| Support.name(candidate) == volume_name }
      end

      def claim_storage_class(claim, adapter)
        return nil unless adapter

        class_name = Support.value(Support.spec(claim), "storageClassName", nil).to_s
        return nil if class_name.empty?

        list_storage_objects(adapter, STORAGE_CLASS, namespace: :all).find { |candidate| Support.name(candidate) == class_name }
      end

      # An explicit answer wins; otherwise the StorageClass decides.
      def expansion_allowed?(class_object, allow_volume_expansion)
        return !!allow_volume_expansion unless allow_volume_expansion.nil?

        class_spec = Support.spec(class_object || {})
        Support.value(class_spec, "allowVolumeExpansion",
                      Support.value(class_object || {}, "allowVolumeExpansion", false)) == true
      end

      # The volume is large enough: record its capacity on the volume (when a
      # provider grew it) and on the claim, with FileSystemResizePending until
      # the node has expanded a filesystem volume.
      def expanded_result(claim, volume, capacity, node_expanded)
        operations = []
        if provider_capacity_candidate?(volume, capacity)
          candidate_pv = Support.deep_copy(volume)
          candidate_pv["spec"] ||= {}
          candidate_pv["spec"]["capacity"] ||= {}
          candidate_pv["spec"]["capacity"]["storage"] = capacity
          pv_operation = operation_update(volume, candidate_pv, descriptor: PV, reason: "persistent volume expansion")
          operations << pv_operation if pv_operation
        end
        candidate_status = Support.deep_copy(Support.status(claim))
        candidate_status["capacity"] = Support.deep_copy(Support.value(Support.spec(volume), "capacity", {}))
        candidate_status["capacity"] ||= {}
        candidate_status["capacity"]["storage"] = capacity
        conditions = remove_conditions(candidate_status["conditions"], "Resizing", "ResizeStarted", "ResizeFailed")
        filesystem = Support.value(Support.spec(volume), "volumeMode", "Filesystem").to_s != "Block"
        conditions = if filesystem && !node_expanded
                       upsert_condition(conditions, "FileSystemResizePending", "True", "ControllerResizeInProgress")
                     else
                       remove_conditions(conditions, "FileSystemResizePending")
                     end
        candidate_status["conditions"] = conditions
        status_operation = operation_status(claim, candidate_status, descriptor: PVC, reason: "persistent volume expansion")
        operations << status_operation if status_operation
        ReconcileResult.new(operations: operations, status: candidate_status,
                            events: [{"type" => "Normal", "reason" => "VolumeResizeSuccessful",
                                      "message" => "persistent volume claim #{name_key(claim)} expanded"}],
                            controller: name, key: name_key(claim))
      end

      def no_expansion_result(claim)
        ReconcileResult.new(operations: [], status: Support.status(claim), controller: name,
                            key: name_key(claim))
      end

      def failed_expansion_result(claim, reason)
        status = Support.deep_copy(Support.status(claim))
        status["conditions"] = upsert_condition(status["conditions"], "Resizing", "False", reason)
        operation = operation_status(claim, status, descriptor: PVC, reason: "persistent volume expansion failed")
        ReconcileResult.new(operations: [operation].compact, status: status,
                            events: [{"type" => "Warning", "reason" => "VolumeResizeFailed",
                                      "message" => "persistent volume claim #{name_key(claim)} cannot be expanded: #{reason}"}],
                            controller: name, key: name_key(claim))
      end

      def resizing_result(claim, requested)
        status = Support.deep_copy(Support.status(claim))
        status["conditions"] = upsert_condition(status["conditions"], "Resizing", "True", "ExternalExpanding",
                                                message: "waiting for volume capacity #{requested}")
        operation = operation_status(claim, status, descriptor: PVC, reason: "persistent volume expansion pending")
        ReconcileResult.new(operations: [operation].compact, status: status,
                            events: [{"type" => "Normal", "reason" => "VolumeResizeSuccessful",
                                      "message" => "persistent volume claim #{name_key(claim)} expansion is pending"}],
                            controller: name, key: name_key(claim))
      end

      def claim_requested_capacity(claim)
        resources = Support.value(Support.spec(claim), "resources", {})
        quantity_base(Support.value(Support.value(resources, "requests", {}), "storage", 0))
      end

      def claim_status_capacity(claim)
        quantity_base(Support.value(Support.value(Support.status(claim), "capacity", {}), "storage", 0))
      end

      def volume_capacity_value(volume)
        spec_capacity = Support.value(Support.value(Support.spec(volume), "capacity", {}), "storage", nil)
        status_capacity = Support.value(Support.value(Support.status(volume), "capacity", {}), "storage", nil)
        spec_capacity || status_capacity || 0
      end

      def provider_capacity(value)
        return nil if value.nil? || value == false
        return Support.value(value, "capacity", nil) if value.is_a?(Hash)
        return value if value.is_a?(Numeric) || value.is_a?(String)

        nil
      end

      def provider_capacity_candidate?(pv, capacity)
        quantity_base(capacity) > quantity_base(volume_capacity_value(pv))
      end
    end
  end
end
