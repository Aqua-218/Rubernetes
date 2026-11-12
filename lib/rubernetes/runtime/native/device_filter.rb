# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # The cgroup device allowlist of each container: builds the eBPF
      # attacher, derives a container's device rules from its mounts, and
      # attaches/detaches the program around the container cgroup's life.
      module DeviceFilter
        DEVICE_DIRECTORY_SKIPS = %w[pts shm fd mqueue .lxc .lxd-mounts .udev].freeze

        private

        # The cgroup device controller (runc's eBPF allowlist) for every
        # container cgroup.  A host profile that cannot load the program does
        # not start: a container without it may mknod and read host block
        # devices.  The pure profile has no cgroups to attach to.
        def build_device_filter
          return @adapters[:device_filter] if @adapters.key?(:device_filter)
          return nil if config.pure_profile?

          filter = Platform::Linux::DeviceCgroup::Attacher.new
          filter.validate!
          filter
        rescue Platform::Linux::DeviceCgroup::Error => error
          raise CapabilityError, "cgroup device filter is unavailable for the #{config.profile} profile " \
                                 "(BPF_PROG_TYPE_CGROUP_DEVICE needs a kernel with CONFIG_BPF_SYSCALL and CONFIG_CGROUP_BPF): #{error.message}"
        end

        # Attaches the container's device allowlist to its cgroup before any
        # process can join it: containerd's rules (deny all -- allow all when
        # privileged -- plus the container's own devices) and runc's default
        # devices.
        def attach_device_filter(sandbox, container, cgroup, input, plan)
          return unless @device_filter

          privileged = plan.context.privileged?
          devices = container_device_rules(input)
          rules = Platform::Linux::DeviceCgroup.rules_for(privileged: privileged, devices: devices)
          program_id = @device_filter.attach(cgroup.path, rules)
          record(:device_filter_attached, sandbox_id: sandbox.id, container_id: container.id, cgroup: cgroup.path,
                                          program_id: program_id, privileged: privileged, devices: devices)
          program_id
        rescue Platform::Linux::DeviceCgroup::Error => error
          raise ResourceError, "container #{container.id}: #{error.message}"
        end

        # Detaches before the cgroup goes (the kernel would release the program
        # with the cgroup anyway); a failure here is recorded, not raised, so
        # the removal still reaches the cgroup.
        def detach_device_filter(sandbox, container_id, cgroup)
          return unless @device_filter

          detached = @device_filter.detach(cgroup.path)
          record(:device_filter_detached, sandbox_id: sandbox.id, container_id: container_id, cgroup: cgroup.path, program_ids: detached)
          detached
        rescue Platform::Linux::DeviceCgroup::Error => error
          record(:device_filter_detach_error, sandbox_id: sandbox.id, container_id: container_id, cgroup: cgroup.path, error: error.message)
          nil
        end

        # The container's own device nodes as cgroup rules: every mount flagged
        # "device" (device plugin allocations, CDI deviceNodes) with the
        # permissions its source gave, resolved like containerd's
        # oci.DeviceFromPath -- a directory contributes every node beneath it
        # (HostDevices), CDI may name type/major/minor itself.
        def container_device_rules(input)
          Array(input["mounts"]).flat_map do |mount|
            next [] unless mount["device"] == true

            permissions = mount["permissions"].nil? ? "" : String(mount["permissions"])
            if mount["device_type"] && mount["major"]
              next [{"type" => String(mount["device_type"]), "major" => Integer(mount["major"]), "minor" => Integer(mount["minor"] || 0),
                     "access" => permissions, "allow" => true}]
            end

            device_nodes(mount.fetch("source")).map do |stat|
              {"type" => stat.chardev? ? "c" : "b", "major" => stat.rdev_major, "minor" => stat.rdev_minor,
               "access" => permissions, "allow" => true}
            end
          end
        end

        def device_nodes(path)
          stat = File.stat(path)
          return [stat] if stat.chardev? || stat.blockdev?
          raise ConfigurationError, "device mount source #{path} is not a device node" unless stat.directory?

          Dir.children(path).sort.flat_map do |name|
            child = File.join(path, name)
            if File.directory?(child) && !File.symlink?(child)
              DEVICE_DIRECTORY_SKIPS.include?(name) ? [] : device_nodes(child)
            else
              next [] if name == "console"

              begin
                child_stat = File.stat(child)
              rescue Errno::ENOENT, Errno::ELOOP
                next []
              end
              child_stat.chardev? || child_stat.blockdev? ? [child_stat] : []
            end
          end
        rescue Errno::ENOENT
          raise ConfigurationError, "device mount source #{path} does not exist"
        end
      end
    end
  end
end
