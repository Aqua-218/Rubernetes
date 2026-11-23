# frozen_string_literal: true

module Rubernetes
  module Volume
    # The native manager's own data directory can be on another filesystem.
    # Pin only the exact configured directory, using the mount table to
    # attest the pinned descriptor. Lookups beneath it remain mount-local.
    module ConfiguredRoots
      def pin_configured_root!(path)
        return unless @adapter.is_a?(Platform::Linux::Openat2)
        return unless within_configured_path?(File.expand_path(path), @root)

        relative_root = relative(path)
        return if relative_root == "." || @configured_roots&.key?(relative_root)

        flags = default_open_flags | Platform::Linux::Openat2::O_DIRECTORY
        @adapter.open(relative_root, flags: flags).close
      rescue Platform::Linux::Error => error
        unless error.errno == Errno::EXDEV::Errno
          raise PathSecurityError, "could not open configured volume root #{path.inspect}: #{error.message}", cause: error
        end

        pin_mounted_root!(relative_root, flags, yield)
      end

      def close
        @configured_roots&.each_value(&:close)
        @configured_roots = nil
        @adapter.close if defined?(Platform::Linux::Openat2) && @adapter.is_a?(Platform::Linux::Openat2)
        true
      end

      private

      def pin_mounted_root!(relative_root, flags, mounts)
        path = File.join(@root, relative_root)
        @adapter.with_open(".", flags: flags) do |resolver_root|
          # This is the one lookup which may cross mounts on the configured
          # path itself. Its flags still reject symlinks and magic links.
          opened = @adapter.open_relative(parent: resolver_root, path: relative_root, flags: flags,
                                          resolve: target_resolve_flags(nil), resource_id: "volume-root:#{path}")
          directory = IO.for_fd(opened.fd)
          mount_id = mount_id_of(directory.fileno)
          mount = mounts.find { |entry| entry.fetch("mountId") == mount_id }
          stat = directory.stat
          device = "#{stat.dev_major}:#{stat.dev_minor}"
          unless mount && mount.fetch("deviceId") == device && within_configured_path?(path, mount.fetch("target"))
            raise PathSecurityError, "mount identity changed while opening configured volume root #{path.inspect}"
          end

          (@configured_roots ||= {})[relative_root] = directory
          directory = nil
        ensure
          directory&.close
        end
      rescue Platform::Linux::Error, SystemCallError, IOError => error
        raise PathSecurityError, "could not pin configured volume root #{path.inspect}: #{error.message}", cause: error
      end

      def configured_root_for(relative_path)
        @configured_roots&.keys&.select { |root| within_configured_path?(relative_path, root) }&.max_by(&:length)
      end

      def within_configured_path?(path, root)
        path == root || path.start_with?(root.end_with?("/") ? root : "#{root}/")
      end

      def open_pinned_root(root, relative_path, flags:, mode:, resolve:, resource_id:)
        path = relative_path == root ? "." : relative_path.delete_prefix("#{root}/")
        raw = @adapter.open_relative(parent: @configured_roots.fetch(root), path: path,
                                     flags: flags || default_open_flags, mode: mode || 0,
                                     resolve: secure_resolve_flags(resolve), resource_id: resource_id)
        stat = IO.for_fd(raw.fd, autoclose: false).stat
        PathSecurity::Handle.new(fd: raw.fd, path: relative_path, root: @root, identity: "#{stat.dev}:#{stat.ino}:#{stat.mode}")
      rescue StandardError
        raw&.close
        raise
      end
    end
  end
end
