# frozen_string_literal: true

module Rubernetes
  module Volume
    module StaleUnmount
      def self.stale_path?(error)
        while error
          return true if error.is_a?(Errno::ESTALE) ||
                         (error.is_a?(Rubernetes::Platform::Linux::Error) && error.errno == Errno::ESTALE::Errno)

          error = error.cause
        end
        false
      end
    end

    class PathSecurity
      # NFS can revoke a file handle while its local mount still exists. O_PATH
      # pins the mount without asking the server to stat the revoked object.
      class StaleTargetLease < TargetLease
        private

        def verify_mounted_target!(mount_identity)
          unless identity.fetch("mountId").to_s == mount_identity.fetch("mountId").to_s
            raise PathSecurityError, "stale volume target does not cover the recorded mount"
          end

          super
        end

        def reject_visible_symlink_components!(path)
          # The openat2 leaf lookup already rejected symlinks. Subsequent
          # fdinfo checks still require the same kernel mount ID and inode.
          super(path == original_path ? File.dirname(path) : path)
        end

        def stat_identity(target)
          fields = File.read("/proc/self/fdinfo/#{descriptor_number(target.fd)}").lines.to_h do |line|
            key, value = line.split(":", 2)
            [key, value.strip]
          end
          {"device" => nil, "inode" => Integer(fields.fetch("ino"), 10), "mountId" => Integer(fields.fetch("mnt_id"), 10)}
        rescue ArgumentError, KeyError, SystemCallError => error
          raise PathSecurityError, "stale volume target descriptor identity could not be read: #{error.message}"
        end

        def descriptor_identity(path)
          io = IO.for_fd(IO.sysopen(path, path_open_flags))
          stat_identity(Handle.new(fd: io))
        ensure
          io&.close
        end
      end

      class Resolver
        def acquire_stale_mount_target!(path, identity)
          parent = self.open(File.dirname(path), flags: default_open_flags)
          leaf = open_relative(parent, File.basename(path), flags: default_open_flags, resolve: target_resolve_flags(nil))
          dispatch = "/proc/#{Process.pid}/fd/#{descriptor_number(leaf.fd)}"
          target = StaleTargetLease.new(original_path: File.expand_path(path), dispatch_path: dispatch,
                                        handle: leaf, parent_handle: parent)
          target.verify_original!(mounted: true, mount_identity: identity)
          target
        rescue StandardError
          leaf&.close
          parent&.close
          raise
        end
      end

      def validate_unmount_target!(path)
        validate_target!(path)
      rescue PathSecurityError => error
        raise unless StaleUnmount.stale_path?(error)

        validate_target!(File.dirname(path))
        path.to_s
      end

      def acquire_stale_mount_target!(path, identity)
        resolver.acquire_stale_mount_target!(path, identity)
      end
    end
  end
end
