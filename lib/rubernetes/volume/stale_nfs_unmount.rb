# frozen_string_literal: true

module Rubernetes
  module Volume
    class NativeMountAdapter
      # A deleted NFS subdirectory can refuse even O_PATH. Linux still
      # allows umount2 to find that mount with its mountpoint-only lookup.
      def unmount_stale_nfs_subpath(target, identity:, path_security:, volume_id:)
        path = normalize_target(target)
        unless identity["target"] == path && Types.present?(identity["mountId"]) && Types.present?(identity["deviceId"])
          raise MountIdentityError, "stale NFS subPath cleanup requires its recorded mount identity"
        end

        resource_id = resource_id_for("unmount", path, volume_id)
        parent = path_security.open(File.dirname(path), flags: O_PATH)
        descriptor = descriptor_number(parent)
        parent_id = File.read("/proc/self/fdinfo/#{descriptor}")[/^mnt_id:\s*(\d+)/, 1]

        target_lock(path).synchronize do
          mounts = read_mounts.select { |entry| entry["target"] == path }
          return true if mounts.empty?

          observed = mounts.first
          unless mounts.one? && parent_id && parent_id == observed["parentId"] && %w[nfs nfs4].include?(observed["filesystem"])
            raise MountIdentityError, "stale NFS subPath has no unique mount on its leased parent"
          end

          verify_identity!(observed, identity, leased: true)
          dispatch = "/proc/#{Process.pid}/fd/#{descriptor}/#{File.basename(path)}"
          result = unmount_syscall(dispatch, MNT_DETACH | UMOUNT_NOFOLLOW, resource_id)
          unless [true, 0].include?(result) && read_mounts.none? { |entry| entry["target"] == path }
            raise_cleanup_ambiguity!("stale NFS subPath cleanup could not be verified", resource_id, "mount cleanup is unverified")
          end

          true
        end
      ensure
        parent&.close
      end
    end
  end
end
