# frozen_string_literal: true

module Rubernetes
  module Volume
    # HostPath clients such as Cilium select paths below procfs or sysfs.
    # Cross only an expected kernel mount at its canonical location. All
    # other components are still resolved beneath a retained descriptor
    # with NO_XDEV, NO_SYMLINKS and NO_MAGICLINKS.
    module KernelHostPaths
      FILESYSTEMS = {
        "proc" => "proc", "sys" => "sysfs",
        "sys/fs/bpf" => "bpf", "sys/fs/cgroup" => "cgroup2", "dev" => "devtmpfs"
      }.freeze
      DIRECTORY_FLAG = 0x10000

      def kernel_host_path?(path, block_device: false)
        return false unless root == "/" && descriptor_capable?

        prefix = relative(path).split("/", 2).first
        %w[proc sys].include?(prefix) || (block_device && prefix == "dev")
      end

      def open_kernel_host_path(path, flags: nil, resource_id: nil)
        relative_path = relative(path)
        mounts = kernel_mounts_for(relative_path)
        raise PathSecurityError, "could not identify a trusted kernel mount for #{path.inspect}" if mounts.empty?

        boundary = nil
        base = nil
        mounts.each do |mount, mount_id|
          mount_flags = mount == relative_path ? flags : default_open_flags | DIRECTORY_FLAG
          next_base = open_kernel_mount(base, boundary, mount, mount_id, mount_flags, resource_id)
          base&.close
          base = next_base
          boundary = mount
        end
        handle = if relative_path == boundary
                   base
                 else
                   remainder = relative_path.delete_prefix("#{boundary}/")
                   open_relative(base, remainder, flags: flags || default_open_flags, resolve: secure_resolve_flags(nil),
                                                  resource_id: resource_id)
                 end
        handle.path = relative_path
        handle
      ensure
        base&.close unless base.equal?(handle)
      end

      private

      def kernel_mounts_for(path)
        matches = File.foreach("/proc/self/mountinfo").filter_map do |line|
          fields, filesystem = line.split(" - ", 2)
          id, _, _, filesystem_root, mountpoint = fields.split(" ", 6)
          mount = mountpoint&.delete_prefix("/")
          next unless FILESYSTEMS.key?(mount) && filesystem&.split&.first == FILESYSTEMS[mount] && filesystem_root == "/"
          next unless path == mount || path.start_with?("#{mount}/")

          [mount, id]
        end
        matches.to_h.sort_by { |mount, _id| mount.count("/") }
      rescue SystemCallError => error
        raise PathSecurityError, "could not read the kernel mount table: #{error.message}", cause: error
      end

      def open_kernel_mount(base, boundary, mount, mount_id, flags, resource_id)
        handle = if base
                   open_nested_kernel_mount(base, mount.delete_prefix("#{boundary}/"), flags, resource_id)
                 else
                   open_mount_point("/#{mount}", flags: flags, resource_id: resource_id)
                 end
        verified = mount_id_of(descriptor_number(handle.fd)) == mount_id
        return handle if verified

        raise PathSecurityError, "kernel mount identity changed at /#{mount}"
      ensure
        handle&.close unless verified
      end

      def open_nested_kernel_mount(base, path, flags, resource_id)
        directory, leaf = File.split(path)
        parent = if directory == "."
                   base
                 else
                   open_relative(base, directory, flags: default_open_flags | DIRECTORY_FLAG, resolve: secure_resolve_flags(nil))
                 end
        open_relative(parent, leaf, flags: flags || default_open_flags,
                                    resolve: target_resolve_flags(nil), resource_id: resource_id)
      ensure
        parent&.close unless parent.equal?(base)
      end
    end
  end
end
