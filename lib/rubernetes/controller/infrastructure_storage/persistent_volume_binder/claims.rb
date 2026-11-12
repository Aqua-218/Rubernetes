# frozen_string_literal: true

module Rubernetes
  module Controller
    class PersistentVolumeBinderController < BaseController
      private

      def sync_claim(claim, context)
        claim = anneal_claim_migration(claim, context)
        return if claim.nil?

        if annotation?(claim, ANN_BIND_COMPLETED)
          sync_bound_claim(claim, context)
        else
          sync_unbound_claim(claim, context)
        end
      end

      def sync_unbound_claim(claim, context)
        volume_name = Support.value(Support.spec(claim), "volumeName", "").to_s
        if volume_name.empty?
          delay = delay_binding?(claim, context)
          if delay.is_a?(String)
            context[:requeue] = RECHECK_SECONDS
            return
          end

          volume = find_best_match(claim, context[:volumes], delay)
          if volume.nil?
            return if assign_default_class(claim, context)

            if delay && !annotation?(claim, ANN_SELECTED_NODE)
              emit_delay_binding_event(claim, context)
            elsif !claim_class(claim).empty?
              provision_claim(claim, context)
              return
            else
              event(context, "Normal", "FailedBinding", "no persistent volumes available for this claim and no storage class is set")
            end
            update_claim_status(claim, "Pending", nil, context)
          else
            bind(volume, claim, context)
          end
          return
        end

        volume = find_volume(context, volume_name)
        if volume.nil?
          update_claim_status(claim, "Pending", nil, context)
        elsif claim_ref(volume).nil?
          if (reason = volume_satisfy_error(volume, claim))
            event(context, "Warning", "VolumeMismatch", "Cannot bind to requested volume #{volume_name.dump}: #{reason}")
            update_claim_status(claim, "Pending", nil, context)
          else
            bind(volume, claim, context)
          end
        elsif bound_to_claim?(volume, claim)
          bind(volume, claim, context)
        else
          event(context, "Warning", "FailedBinding", "volume #{volume_name.dump} already bound to a different claim.")
          # A claim the controller bound itself to a now-foreign volume is
          # an error upstream (retried); a user's pre-binding stays Pending.
          if annotation?(claim, ANN_BOUND_BY_CONTROLLER)
            context[:requeue] = RECHECK_SECONDS
          else
            update_claim_status(claim, "Pending", nil, context)
          end
        end
      end

      def sync_bound_claim(claim, context)
        volume_name = Support.value(Support.spec(claim), "volumeName", "").to_s
        if volume_name.empty?
          return update_claim_status_with_event(claim, "Lost", nil, context, "Warning", "ClaimLost",
                                                "Bound claim has lost reference to PersistentVolume. Data on the volume is lost!")
        end

        volume = find_volume(context, volume_name)
        if volume.nil?
          update_claim_status_with_event(claim, "Lost", nil, context, "Warning", "ClaimLost",
                                         "Bound claim has lost its PersistentVolume. Data on the volume is lost!")
        elsif claim_ref(volume).nil? || Support.value(claim_ref(volume), "uid", "").to_s == Support.uid(claim).to_s
          bind(volume, claim, context)
        else
          update_claim_status_with_event(claim, "Lost", nil, context, "Warning", "ClaimMisbound",
                                         "Two claims are bound to the same volume, this one is bound incorrectly")
        end
      end

      # checkVolumeSatisfyClaim.
      def volume_satisfy_error(volume, claim)
        return "the volume is marked for deletion #{Support.name(volume).dump}" unless Support.value(Support.metadata(volume),
                                                                                                     "deletionTimestamp", nil).nil?
        return "requested PV is too small" if storage(volume_capacity(volume)) < storage(claim_request(claim))
        return "storageClassName does not match" if volume_class(volume) != claim_class(claim)
        return "volumeAttributesClassName does not match" if vac(claim) != vac(volume)
        return "incompatible volumeMode" if volume_mode(claim) != volume_mode(volume)
        return "incompatible accessMode" unless access_modes_contain?(access_modes(volume), access_modes(claim))

        nil
      end

      # IsDelayBindingMode: true/false, or an error message.
      def delay_binding?(claim, context)
        class_name = claim_class(claim)
        return false if class_name.empty?

        storage_class = find_class(context, class_name)
        return false if storage_class.nil?

        mode = Support.value(storage_class, "volumeBindingMode", nil)
        return "VolumeBindingMode not set for StorageClass #{class_name.dump}" if mode.nil?

        mode.to_s == "WaitForFirstConsumer"
      end

      def emit_delay_binding_event(claim, context)
        names = pods_using(claim, context).reject do |pod|
          pod_terminated?(pod)
        end.select { |pod| Support.value(Support.spec(pod), "nodeName", "").to_s.empty? }
          .map { |pod| Support.name(pod) }
        if names.empty?
          event(context, "Normal", "WaitForFirstConsumer", "waiting for first consumer to be created before binding")
        elsif names.length == 1
          event(context, "Normal", "WaitForPodScheduled", "waiting for pod #{names.first} to be scheduled")
        else
          event(context, "Normal", "WaitForPodScheduled", "waiting for pods #{names.join(",")} to be scheduled")
        end
      end

      # assignDefaultStorageClass: a claim with no class at all gets the
      # default one (retroactive default StorageClass assignment).
      def assign_default_class(claim, context)
        return false if claim_has_class?(claim)

        default = default_class(context[:classes])
        return false if default.nil?

        updated = Support.deep_copy(claim)
        (updated["spec"] ||= {})["storageClassName"] = Support.name(default)
        # RecordRetroactiveStorageClassMetric: every assignment, and the ones
        # whose claim update failed.
        assign = operation_update(claim, updated, descriptor: PVC, reason: "assign the default StorageClass")&.observed do |succeeded, _|
          ControllerMetrics.increment("retroactive_storageclass_total")
          ControllerMetrics.increment("retroactive_storageclass_errors_total") unless succeeded
        end
        context[:operations] << assign if assign
        true
      end

      # updateClaimMigrationAnnotations (claim side).
      def anneal_claim_migration(claim, context)
        annotations = Support.value(Support.metadata(claim), "annotations", nil)
        return claim unless annotations.is_a?(Hash)

        provisioner = annotations[ANN_STORAGE_PROVISIONER] || annotations[ANN_BETA_STORAGE_PROVISIONER]
        return claim if provisioner.nil?

        updated_annotations = migration_annotations(annotations, provisioner)
        return claim if updated_annotations.nil?

        updated = Support.deep_copy(claim)
        updated["metadata"]["annotations"] = updated_annotations
        context[:operations] << operation_update(claim, updated, descriptor: PVC, reason: "anneal migration annotations")
        nil
      end

      def migration_annotations(annotations, provisioner)
        driver = MIGRATED_PLUGINS[provisioner]
        current = annotations[ANN_MIGRATED_TO]
        if driver
          return nil if current == driver

          annotations.merge(ANN_MIGRATED_TO => driver)
        else
          return nil if current.to_s.empty?

          annotations.reject { |key, _| key == ANN_MIGRATED_TO }
        end
      end
    end
  end
end
