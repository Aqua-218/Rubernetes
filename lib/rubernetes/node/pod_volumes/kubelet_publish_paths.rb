# frozen_string_literal: true

module Rubernetes
  module Node
    class PodVolumes
      module KubeletPublishPaths
        private

        CSI_PLUGIN_DIRECTORY = "kubernetes.io~csi"
        NFS_PLUGIN_DIRECTORY = "kubernetes.io~nfs"
        PATH_COMPONENT = /\A[a-zA-Z0-9][a-zA-Z0-9.-]*\z/

        def kubelet_publish_target(id, uid, name, spec, publish_targets)
          return unless @kubelet_pod_root && @volume.is_a?(Volume::Manager)

          if spec["backend"] == "nfs" && !spec.key?("persistentVolume") && real_mounts?
            return File.join(plugin_directory(uid, NFS_PLUGIN_DIRECTORY), publish_path_component(name))
          end

          csi_publish_target(id, uid, name, spec, publish_targets)
        end

        def csi_publish_target(id, uid, name, spec, publish_targets)
          return if spec["migratedInline"] || !@volume.kubelet_csi_filesystem?(id)

          # The kubelet passes Spec.Name(), the PV's metadata.name for a
          # claim and the Pod volume name for inline CSI. It never places the
          # driver's volumeHandle on the target path.
          spec_name = publish_path_component(spec.fetch("persistentVolume", name))
          target = File.join(plugin_directory(uid, CSI_PLUGIN_DIRECTORY), spec_name, "mount")
          # The manager owns a separate lifecycle for each Pod volume alias.
          # Keep the established second publish path if a Pod refers to one
          # PV twice, including when a later container starts using the alias.
          target unless publish_targets.key?(target)
        end

        def prepare_publish_target!(target)
          return reclaim_abandoned_mount(target) unless kubelet_pod_target?(target)

          @volume.path_security.validate_target!(target)
          # A target newer than this Pod's record can still be in active use
          # or fenced for an interrupted RPC. Never detach it without that
          # publication's recorded mount identity.
          return unless @volume.mount_adapter.find_mount(target)

          raise Error, "volume publish target already has a mount: #{target}"
        end

        def unpublish_volume(id, pod, uid, target, token)
          @volume.node_unpublish(id, pod, target, token: "#{token}-unpublish-#{id}")
          remove_empty_csi_target(uid, target)
        end

        def remove_empty_csi_target(uid, target)
          return unless kubelet_pod_target?(target) && PATH_COMPONENT.match?(uid)

          plugin = plugin_directory(uid, CSI_PLUGIN_DIRECTORY)
          parent = File.dirname(target)
          return unless File.basename(target) == "mount" && File.dirname(parent) == plugin

          remove_empty_publish_directories(target, parent, plugin)
        end

        def remove_empty_nfs_target(uid, target)
          return unless kubelet_pod_target?(target) && PATH_COMPONENT.match?(uid)

          plugin = plugin_directory(uid, NFS_PLUGIN_DIRECTORY)
          return unless File.dirname(target) == plugin

          # Keep the Pod's volume directory until both the publication and
          # the NFS stage have been released. Another mount can still own it.
          remove_empty_publish_directories(target, plugin, File.dirname(plugin))
        end

        def remove_empty_publish_directories(*directories)
          directories.each do |directory|
            @volume.path_security.validate_target!(directory)
            Dir.rmdir(directory)
          rescue Errno::ENOENT
            next
          rescue Errno::ENOTEMPTY, Errno::EEXIST, Errno::EBUSY
            break
          end
        end

        def kubelet_pod_target?(target)
          target && @kubelet_pod_root && target.start_with?("#{@kubelet_pod_root}/") && !target.start_with?("#{@root}/")
        end

        def plugin_directory(uid, plugin)
          File.join(@kubelet_pod_root, publish_path_component(uid), "volumes", plugin)
        end

        def publish_path_component(name)
          raise Error, "volume publication requires a valid Pod UID and volume name" unless PATH_COMPONENT.match?(name)

          name
        end
      end
    end
  end
end
