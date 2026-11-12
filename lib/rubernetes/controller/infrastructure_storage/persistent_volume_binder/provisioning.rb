# frozen_string_literal: true

module Rubernetes
  module Controller
    class PersistentVolumeBinderController < BaseController
      private

      # provisionClaim: without --enable-hostpath-provisioner no in-tree
      # plugin can provision, so a kubernetes.io/ provisioner that was not
      # migrated to CSI fails; with it, kubernetes.io/host-path provisions
      # here.  Any other provisioner is external.
      def provision_claim(claim, context)
        storage_class = find_class(context, claim_class(claim))
        if storage_class.nil?
          event(context, "Warning", "ProvisioningFailed", "storageclass.storage.k8s.io #{claim_class(claim).dump} not found")
          return
        end

        provisioner = Support.value(storage_class, "provisioner", "").to_s
        provisioner = MIGRATED_PLUGINS.fetch(provisioner, provisioner)
        return provision_host_path(claim, storage_class, context) if provisioner == HOST_PATH_PLUGIN && context[:hostpath_provisioner]

        if provisioner.start_with?("kubernetes.io/")
          event(context, "Warning", "ProvisioningFailed", "no provisionable volume plugin matched")
          return
        end

        set_claim_provisioner(claim, provisioner, context)
        event(context, "Normal", "ExternalProvisioning",
              "Waiting for a volume to be created either by the external provisioner '#{provisioner}' or manually by the system " \
              "administrator. If volume creation is delayed, please verify that the provisioner is running and correctly registered.")
      end

      # provisionClaimOperation with the in-tree hostPath plugin, and
      # hostPathProvisioner.Provision: a directory under /tmp/hostpath_pv on
      # this host becomes the claim's volume, named pvc-<claim uid>.
      def provision_host_path(claim, storage_class, context)
        unless Support.value(Support.spec(claim), "dataSource", nil).nil?
          return provisioning_failed(context, "plugin #{HOST_PATH_PLUGIN.dump} is not a CSI plugin. Only CSI plugin can provision a claim " \
                                              "with a datasource")
        end

        set_claim_provisioner(claim, HOST_PATH_PLUGIN, context)
        name = "pvc-#{Support.uid(claim)}"
        return if Array(context[:volumes]).any? { |volume| Support.name(volume) == name }

        class_name = Support.name(storage_class)
        mount_options = Array(Support.value(storage_class, "mountOptions", []))
        unless mount_options.empty?
          return provisioning_failed(context, "Mount options are not supported by the provisioner but StorageClass #{class_name.dump} " \
                                              "has mount options [#{mount_options.join(" ")}]")
        end

        node = (Support.value(Support.metadata(claim), "annotations", {}) || {})[ANN_SELECTED_NODE]
        if node && context[:adapter] && context[:adapter].find(NODE, name: node).nil?
          return provisioning_failed(context, "Failed to get target node: node #{node.dump} not found")
        end

        path = File.join(HOST_PATH_BASE, SecureRandom.uuid)
        begin
          block = Support.value(Support.spec(claim), "volumeMode", nil) == "Block"
          raise ArgumentError, "#{HOST_PATH_PLUGIN} does not support block volume provisioning" if block

          @host_path_provisioner.call(path)
        rescue ArgumentError, SystemCallError => failure
          reschedule_provisioning(claim, context)
          return provisioning_failed(context, "Failed to provision volume with StorageClass #{class_name.dump}: #{failure.message}")
        end

        # A volume the API refused (or that another pass created first) must
        # not leave its directory behind.
        create = operation_create(provisioned_host_path_volume(name, path, claim, storage_class), descriptor: PV,
                                                                                                  reason: "provision a hostPath volume")
        context[:operations] << create&.observed { |succeeded, _error| @host_path_deleter.call(path) unless succeeded }
        event(context, "Normal", "ProvisioningSucceeded", "Successfully provisioned volume #{name} using #{HOST_PATH_PLUGIN}")
      end

      def provisioned_host_path_volume(name, path, claim, storage_class)
        policy = Support.value(storage_class, "reclaimPolicy", nil) || "Delete"
        modes = Array(Support.value(Support.spec(claim), "accessModes", []))
        capacity = Support.value(Support.value(Support.value(Support.spec(claim), "resources", {}), "requests", {}), "storage", nil)
        {"apiVersion" => "v1", "kind" => "PersistentVolume",
         "metadata" => {"name" => name, "finalizers" => (policy == "Delete" ? [IN_TREE_FINALIZER] : nil),
                        "annotations" => {ANN_CREATED_BY => "hostpath-dynamic-provisioner", ANN_BOUND_BY_CONTROLLER => "yes",
                                          ANN_DYNAMICALLY_PROVISIONED => HOST_PATH_PLUGIN}}.compact,
         "spec" => {"persistentVolumeReclaimPolicy" => policy, "accessModes" => modes.empty? ? ["ReadWriteOnce"] : modes,
                    "capacity" => {"storage" => capacity}, "hostPath" => {"path" => path},
                    "storageClassName" => claim_class(claim),
                    "claimRef" => claim_reference(claim)}}
      end

      def provisioning_failed(context, message)
        event(context, "Warning", "ProvisioningFailed", message)
        nil
      end

      # rescheduleProvisioning: the scheduler picks a node again.
      def reschedule_provisioning(claim, context)
        return unless annotation?(claim, ANN_SELECTED_NODE)

        updated = Support.deep_copy(claim)
        updated["metadata"]["annotations"] = updated["metadata"]["annotations"].except(ANN_SELECTED_NODE)
        context[:operations] << operation_update(claim, updated, descriptor: PVC, reason: "reschedule provisioning")
      end

      # setClaimProvisioner.
      def set_claim_provisioner(claim, provisioner, context)
        annotations = Support.value(Support.metadata(claim), "annotations", {}) || {}
        return if annotations[ANN_STORAGE_PROVISIONER] == provisioner && annotations[ANN_BETA_STORAGE_PROVISIONER] == provisioner

        updated = Support.deep_copy(claim)
        updated["metadata"]["annotations"] =
          annotations.merge(ANN_STORAGE_PROVISIONER => provisioner, ANN_BETA_STORAGE_PROVISIONER => provisioner)
        annotate = operation_update(claim, updated, descriptor: PVC,
                                                    reason: "set the claim's external provisioner")&.observed do |succeeded, _|
          # provisionClaimOperationExternal failed: RecordMetric's error.
          unless succeeded
            ControllerMetrics.increment("volume_operation_errors_total",
                                        {"plugin_name" => provisioner, "operation_name" => "provision"})
          end
        end
        context[:operations] << annotate if annotate
      end
    end
  end
end
