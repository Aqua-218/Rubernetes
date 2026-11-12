# frozen_string_literal: true

module Rubernetes
  module Controller
    class PersistentVolumeBinderController < BaseController
      private

      # bind: the volume first (claimRef, bound-by-controller, phase
      # Bound), then the claim (volumeName, bound-by-controller,
      # bind-completed, phase Bound with the volume's modes and capacity).
      def bind(volume, claim, context)
        updated_volume = Support.deep_copy(volume)
        reference = claim_ref(volume)
        unless reference && Support.value(reference, "name", "") == Support.name(claim) &&
               Support.value(reference, "namespace", "") == Support.namespace(claim) &&
               Support.value(reference, "uid", "").to_s == Support.uid(claim).to_s
          (updated_volume["spec"] ||= {})["claimRef"] = claim_reference(claim)
        end
        if !bound_to_claim?(volume, claim) && !annotation?(updated_volume, ANN_BOUND_BY_CONTROLLER)
          set_annotation(updated_volume, ANN_BOUND_BY_CONTROLLER, "yes")
        end
        context[:operations] << operation_update(volume, updated_volume, descriptor: PV, reason: "bind PersistentVolume to claim")
        update_volume_phase(updated_volume, "Bound", "", context)

        updated_claim = Support.deep_copy(claim)
        if Support.value(Support.spec(claim), "volumeName", "").to_s != Support.name(volume)
          (updated_claim["spec"] ||= {})["volumeName"] = Support.name(volume)
          set_annotation(updated_claim, ANN_BOUND_BY_CONTROLLER, "yes") unless annotation?(updated_claim, ANN_BOUND_BY_CONTROLLER)
        end
        set_annotation(updated_claim, ANN_BIND_COMPLETED, "yes") unless annotation?(updated_claim, ANN_BIND_COMPLETED)
        context[:operations] << operation_update(claim, updated_claim, descriptor: PVC, reason: "bind claim to PersistentVolume")
        update_claim_status(updated_claim, "Bound", updated_volume, context)
      end

      def claim_reference(claim)
        {"kind" => "PersistentVolumeClaim", "namespace" => Support.namespace(claim), "name" => Support.name(claim),
         "uid" => Support.uid(claim), "apiVersion" => "v1",
         "resourceVersion" => Support.value(Support.metadata(claim), "resourceVersion", nil)}.compact
      end

      # updateClaimStatus.
      def update_claim_status(claim, phase, volume, context)
        status = Support.deep_copy(Support.status(claim))
        current_phase = Support.value(status, "phase", "").to_s
        status["phase"] = phase
        if volume.nil?
          status.delete("accessModes")
          status.delete("capacity")
          status.delete("currentVolumeAttributesClassName")
        else
          modes = Support.value(Support.spec(volume), "accessModes", nil)
          modes.nil? ? status.delete("accessModes") : status["accessModes"] = modes
          if current_phase != phase
            capacity = volume_capacity(volume)
            pre_resize = Support.value(Support.value(Support.metadata(volume), "annotations", {}) || {}, ANN_PRE_RESIZE_CAPACITY, nil)
            if pre_resize
              status["capacity"] = Support.deep_copy(Support.value(status, "capacity", {}) || {}).merge("storage" => pre_resize)
            elsif storage(Support.value(Support.value(status, "capacity", {}) || {}, "storage", nil)) != storage(capacity) ||
                  Support.value(Support.value(status, "capacity", {}) || {}, "storage", nil).nil?
              status["capacity"] = Support.deep_copy(Support.value(Support.spec(volume), "capacity", {}))
            end
          end
          if current_phase == "Pending" && phase == "Bound"
            vac_name = Support.value(Support.spec(volume), "volumeAttributesClassName", nil)
            vac_name.nil? ? status.delete("currentVolumeAttributesClassName") : status["currentVolumeAttributesClassName"] = vac_name
          end
        end
        return claim if status == Support.status(claim)

        context[:operations] << operation_status(claim, status, descriptor: PVC, reason: "claim phase #{phase}", force: true)
        claim.merge("status" => status)
      end

      def update_claim_status_with_event(claim, phase, volume, context, type, reason, message)
        return claim if Support.value(Support.status(claim), "phase", "").to_s == phase

        updated = update_claim_status(claim, phase, volume, context)
        event(context, type, reason, message)
        updated
      end

      # findBestMatchForClaim: the access-mode groups that contain the
      # request, smallest group first; in each, FindMatchingVolume.
      def find_best_match(claim, volumes, delay)
        requested = access_modes(claim)
        groups = Array(volumes).group_by { |volume| mode_key(access_modes(volume)) }
        groups.keys.select { |key| access_modes_contain?(key.split(","), requested) }
          .sort_by { |key| [key.split(",").length, key] }.each do |key|
          best = find_matching_volume(claim, groups[key], delay)
          return best if best
        end
        nil
      end

      # FindMatchingVolume (node = nil: the controller binds without topology).
      def find_matching_volume(claim, volumes, delay)
        requested = storage(claim_request(claim))
        selector = Support.value(Support.spec(claim), "selector", nil)
        smallest = nil
        volumes.sort_by { |volume| Support.name(volume) }.each do |volume|
          next if claim_ref(volume) && !bound_to_claim?(volume, claim)

          size = storage(volume_capacity(volume))
          next if size < requested
          next if volume_mode(claim) != volume_mode(volume)
          next if vac(claim) != vac(volume)
          next unless Support.value(Support.metadata(volume), "deletionTimestamp", nil).nil?
          return volume if bound_to_claim?(volume, claim)
          next if delay
          next unless Support.value(Support.status(volume), "phase", "").to_s == "Available"
          next if selector && !Support.selector_matches?(selector, volume)
          next if volume_class(volume) != claim_class(claim)

          smallest = volume if smallest.nil? || storage(volume_capacity(smallest)) > size
        end
        smallest
      end
    end
  end
end
