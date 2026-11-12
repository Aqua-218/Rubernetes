# frozen_string_literal: true

module Rubernetes
  module Controller
    class PersistentVolumeBinderController < BaseController
      private

      def sync_volume(volume, context)
        volume = anneal_volume(volume, context)
        return if volume.nil?

        reference = claim_ref(volume)
        if reference.nil? || Support.value(reference, "uid", "").to_s.empty?
          update_volume_phase(volume, "Available", "", context)
          return
        end

        namespace = Support.value(reference, "namespace", "")
        claim_name = Support.value(reference, "name", "")
        claim = find_claim(context, namespace, claim_name)
        phase = Support.value(Support.status(volume), "phase", "").to_s
        # A claim missing from the cache, or with another UID, is read from
        # the API server before the volume is released (cache lag).
        if (claim.nil? && !%w[Released Failed].include?(phase)) ||
           (claim && Support.uid(claim).to_s != Support.value(reference, "uid", "").to_s)
          claim = live_claim(context, namespace, claim_name) || (claim.nil? ? nil : claim)
        end
        claim = nil if claim && Support.uid(claim).to_s != Support.value(reference, "uid", "").to_s
        if claim.nil?
          release_and_reclaim(volume, context)
        elsif Support.value(Support.spec(claim), "volumeName", "").to_s.empty?
          if volume_mode(claim) != volume_mode(volume)
            event(context, "Warning", "VolumeMismatch",
                  "Cannot bind PersistentVolume to requested PersistentVolumeClaim #{Support.name(claim).dump} due to incompatible volumeMode.")
            event(context, "Warning", "VolumeMismatch",
                  "Cannot bind PersistentVolume #{Support.name(volume).dump} to requested PersistentVolumeClaim due to incompatible volumeMode.",
                  involved: claim)
          end
          # The claim's own sync binds it (claimQueue.Add).
        elsif Support.value(Support.spec(claim), "volumeName", "").to_s == Support.name(volume)
          update_volume_phase(volume, "Bound", "", context)
        elsif annotation?(volume, ANN_DYNAMICALLY_PROVISIONED) && reclaim_policy(volume) == "Delete"
          release_and_reclaim(volume, context)
        else
          unbind_volume(volume, context)
        end
      end

      def release_and_reclaim(volume, context)
        phase = Support.value(Support.status(volume), "phase", "").to_s
        volume = update_volume_phase(volume, "Released", "", context) unless %w[Released Failed].include?(phase)
        reclaim_volume(volume, context)
      end

      # updateVolumeMigrationAnnotationsAndFinalizers.
      def anneal_volume(volume, context)
        annotations = Support.value(Support.metadata(volume), "annotations", nil)
        updated_annotations = nil
        if annotations.is_a?(Hash) && annotations.key?(ANN_DYNAMICALLY_PROVISIONED)
          updated_annotations = migration_annotations(annotations, annotations[ANN_DYNAMICALLY_PROVISIONED])
        end
        finalizers = deletion_finalizers(volume)
        return volume if updated_annotations.nil? && finalizers.nil?

        updated = Support.deep_copy(volume)
        updated["metadata"]["annotations"] = updated_annotations if updated_annotations
        updated["metadata"]["finalizers"] = finalizers if finalizers
        context[:operations] << operation_update(volume, updated, descriptor: PV, reason: "anneal migration annotations or finalizers")
        nil
      end

      # modifyDeletionFinalizers: nil when unchanged.
      def deletion_finalizers(volume)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        return nil unless annotations.key?(ANN_DYNAMICALLY_PROVISIONED)

        current = Array(Support.value(Support.metadata(volume), "finalizers", []))
        provisioner = annotations[ANN_DYNAMICALLY_PROVISIONED].to_s
        if MIGRATED_PLUGINS.key?(provisioner)
          return current.include?(IN_TREE_FINALIZER) ? current - [IN_TREE_FINALIZER] : nil
        end
        return nil unless provisioner.start_with?("kubernetes.io/")

        result = current.dup
        policy = reclaim_policy(volume)
        if policy == "Delete" && !result.include?(IN_TREE_FINALIZER)
          result << IN_TREE_FINALIZER
        elsif %w[Retain Recycle].include?(policy) && result.include?(IN_TREE_FINALIZER)
          result -= [IN_TREE_FINALIZER]
        end
        result -= [EXTERNAL_FINALIZER]
        result == current ? nil : result
      end

      def update_volume_phase(volume, phase, message, context)
        return volume if Support.value(Support.status(volume), "phase", "").to_s == phase

        status = Support.deep_copy(Support.status(volume)).merge("phase" => phase)
        message.to_s.empty? ? status.delete("message") : status["message"] = message
        context[:operations] << operation_status(volume, status, descriptor: PV, reason: "volume phase #{phase}", force: true)
        volume.merge("status" => status)
      end

      def update_volume_phase_with_event(volume, phase, context, type, reason, message)
        return volume if Support.value(Support.status(volume), "phase", "").to_s == phase

        updated = update_volume_phase(volume, phase, message, context)
        event(context, type, reason, message)
        updated
      end

      # unbindVolume: a controller-bound volume forgets its claim, a
      # user-bound one keeps the reference without the UID.
      def unbind_volume(volume, context)
        updated = Support.deep_copy(volume)
        if annotation?(volume, ANN_BOUND_BY_CONTROLLER)
          updated["spec"].delete("claimRef")
          annotations = updated["metadata"]["annotations"].reject { |key, _| key == ANN_BOUND_BY_CONTROLLER }
          annotations.empty? ? updated["metadata"].delete("annotations") : updated["metadata"]["annotations"] = annotations
        else
          updated["spec"]["claimRef"] = updated["spec"]["claimRef"].merge("uid" => "")
        end
        context[:operations] << operation_update(volume, updated, descriptor: PV, reason: "unbind PersistentVolume")
        update_volume_phase(updated, "Available", "", context)
      end

      # reclaimVolume.
      def reclaim_volume(volume, context)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        return unless annotations[ANN_MIGRATED_TO].to_s.empty?

        case reclaim_policy(volume)
        when "Retain" then nil
        when "Recycle" then recycle_volume(volume, context)
        when "Delete" then delete_volume(volume, context)
        else
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeUnknownReclaimPolicy",
                                         "Volume has unrecognized PersistentVolumeReclaimPolicy")
        end
      end

      # deleteVolumeOperation: hostPath is the only in-tree deleter; an
      # externally provisioned (or CSI, or migrated) volume is left to its
      # provisioner.
      #
      # A failed deletion is volume_operation_errors_total{operation_name=
      # "delete"}, by getProvisionerNameFromVolume ("N/A" when no deleter
      # matched).
      def delete_volume(volume, context)
        plugin, error = deletable_plugin(volume)
        if error
          record_volume_operation_error("N/A", "delete")
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedDelete", error)
          return
        end
        return if plugin.nil?
        return unless volume_released?(volume, context)

        begin
          @host_path_deleter.call(Support.value(Support.value(Support.spec(volume), "hostPath", {}), "path", ""))
        rescue StandardError => failure
          record_volume_operation_error("kubernetes.io/host-path", "delete")
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedDelete", failure.message)
          return
        end
        finalizers = Array(Support.value(Support.metadata(volume), "finalizers", []))
        if finalizers.include?(IN_TREE_FINALIZER)
          updated = Support.deep_copy(volume)
          updated["metadata"]["finalizers"] = finalizers - [IN_TREE_FINALIZER]
          context[:operations] << operation_update(volume, updated, descriptor: PV, reason: "remove the in-tree deletion finalizer")
        end
        remove = operation_delete(volume, descriptor: PV, reason: "delete released PersistentVolume")&.observed do |succeeded, error|
          not_found = InfrastructureCapability.not_found?(error)
          record_volume_operation_error("kubernetes.io/host-path", "delete") unless succeeded || not_found
        end
        context[:operations] << remove if remove
      end

      def record_volume_operation_error(plugin, operation)
        ControllerMetrics.increment("volume_operation_errors_total",
                                    {"plugin_name" => plugin.to_s.empty? ? "N/A" : plugin, "operation_name" => operation})
      end

      # findDeletablePlugin: [:host_path | nil, error message | nil].
      def deletable_plugin(volume)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        provisioner = annotations[ANN_DYNAMICALLY_PROVISIONED].to_s
        unless provisioner.empty?
          return [:host_path, nil] if provisioner == "kubernetes.io/host-path"
          return [nil, nil] unless provisioner.start_with?("kubernetes.io/")

          return [nil, "no deletable volume plugin matched"]
        end
        return [nil, nil] unless annotations[ANN_MIGRATED_TO].to_s.empty?
        return [nil, nil] unless Support.value(Support.spec(volume), "csi", nil).nil?
        return [:host_path, nil] unless Support.value(Support.spec(volume), "hostPath", nil).nil?

        [nil, "error getting deleter volume plugin for volume #{Support.name(volume).dump}: no deletable volume plugin matched"]
      end

      # isVolumeReleased.
      def volume_released?(volume, context)
        reference = claim_ref(volume)
        return false if reference.nil? || Support.value(reference, "uid", "").to_s.empty?

        claim = find_claim(context, Support.value(reference, "namespace", ""), Support.value(reference, "name", ""))
        return true unless claim && Support.uid(claim).to_s == Support.value(reference, "uid", "").to_s

        volume_name = Support.value(Support.spec(claim), "volumeName", "").to_s
        !volume_name.empty? && volume_name != Support.name(volume)
      end

      # recycleVolumeOperation with the hostPath/NFS recycler Pod
      # (RecycleVolumeByWatchingPodUntilCompletion), one step per sync.
      def recycle_volume(volume, context)
        return unless volume_released?(volume, context)

        reference = claim_ref(volume)
        users = pods_by_claim(context, Support.value(reference, "namespace", ""), Support.value(reference, "name", ""))
          .reject { |pod| pod_terminated?(pod) }.map { |pod| "#{Support.namespace(pod)}/#{Support.name(pod)}" }.sort
        cached = find_claim(context, Support.value(reference, "namespace", ""), Support.value(reference, "name", ""))
        if !users.empty? && cached.nil?
          event(context, "Normal", "VolumeFailedRecycle", "Volume is used by pods: #{users.join(",")}")
          return
        end

        source = recycler_source(volume)
        if source.nil?
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedRecycle",
                                         "No recycler plugin found for the volume!")
          return
        end

        pod_name = "recycler-for-#{Support.name(volume)}"
        pod = context[:adapter] && context[:adapter].find(POD, name: pod_name, namespace: "default")
        if pod.nil?
          context[:operations] << operation_create(recycler_pod(pod_name, volume, source), descriptor: POD,
                                                                                           reason: "start the volume recycler")
          context[:requeue] = RECHECK_SECONDS
          return
        end

        case Support.value(Support.status(pod), "phase", "").to_s
        when "Succeeded"
          context[:operations] << operation_delete(pod, descriptor: POD, reason: "remove the finished recycler")
          event(context, "Normal", "VolumeRecycled", "Volume recycled")
          unbind_volume(volume, context)
        when "Failed"
          context[:operations] << operation_delete(pod, descriptor: POD, reason: "remove the failed recycler")
          message = Support.value(Support.status(pod), "message", "").to_s
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedRecycle",
                                         "Recycle failed: pod failed, pod.Status.Message #{message}")
        else
          context[:requeue] = RECHECK_SECONDS
        end
      end

      def recycler_source(volume)
        spec = Support.spec(volume)
        return {"hostPath" => Support.deep_copy(spec["hostPath"]), minimum: 60} if spec["hostPath"]
        return {"nfs" => Support.deep_copy(spec["nfs"]), minimum: 300} if spec["nfs"]

        nil
      end

      # NewPersistentVolumeRecyclerPodTemplate with the plugin's timeout:
      # max(minimum, 30 s per GiB).
      def recycler_pod(name, volume, source)
        size_gib = (storage(volume_capacity(volume)) / (1024**3)).ceil
        timeout = [source[:minimum], 30 * size_gib].max
        {"apiVersion" => "v1", "kind" => "Pod",
         "metadata" => {"name" => name, "namespace" => "default"},
         "spec" => {"activeDeadlineSeconds" => timeout, "restartPolicy" => "Never",
                    "volumes" => [{"name" => "vol"}.merge(source.except(:minimum))],
                    "containers" => [{"name" => "pv-recycler", "image" => RECYCLER_IMAGE, "command" => ["/bin/sh"],
                                      "args" => ["-c", RECYCLER_SCRIPT], "volumeMounts" => [{"name" => "vol", "mountPath" => "/scrub"}]}]}}
      end
    end
  end
end
