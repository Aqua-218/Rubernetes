# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Construction of the container root: the kernel filesystems, the device
        # nodes, the masked and read-only paths, and the pivot into it.
        class SecurityAdapter
          # §5.8.7 in the container's private mount namespace:
          # 1. MS_PRIVATE|MS_REC propagation;
          # 2. the verified OverlayFS (already mounted by the holder) is the
          #    new root; 3. /proc, /sys, /dev, devpts, shm, mqueue, cgroup2;
          # 4. maskedPaths/readonlyPaths and read-only rootfs;
          # 5. pivot_root, then a regular umount of the old root tree with a
          #    mount-ID proof that nothing from it remains; 6. cwd and the
          #    executable are re-validated inside the new root by the caller.
          def build_rootfs(rootfs, context:, cwd: nil, mounts: [])
            path = File.expand_path(String(rootfs))
            raise EffectError, "workload rootfs must be absolute" unless path.start_with?("/")
            raise EffectError, "workload rootfs contains NUL" if path.include?("\0")

            # The whole view becomes a slave of the host peer groups (runc's
            # default): host-side mounts keep propagating in, which is what a
            # HostToContainer volume relies on, and nothing made here reaches
            # the host.  The container root itself is then made recursively
            # private (§5.8.7 step 1) so the workload's own mounts never leave.
            @mount.make_slave(target: "/", recursive: true, resource_id: "workload:mount-propagation")
            stat = File.stat(path)
            raise EffectError, "workload rootfs is not a directory" unless stat.directory?

            before = @pivot.read_mountinfo
            overlay = before.select { |entry| entry.mountpoint == path }.max_by(&:index)
            if overlay.nil?
              # A verified rootfs handed over as a plain directory (an
              # already-unpacked image tree) becomes its own mount point in
              # this private mount namespace, which is what pivot_root(2)
              # requires; the bind is recursive so nothing beneath it is
              # hidden from the identity proof below.
              @mount.mount(source: path, target: path, filesystem: nil, flags: MS_BIND | MS_REC,
                           resource_id: "workload:rootfs-bind")
              before = @pivot.read_mountinfo
              overlay = before.select { |entry| entry.mountpoint == path }.max_by(&:index)
              raise EffectError, "workload rootfs bind mount is not visible: #{path}" unless overlay
            elsif overlay.filesystem != "overlay"
              raise EffectError, "workload rootfs mount is not OverlayFS"
            end
            @mount.make_private(target: path, recursive: true, resource_id: "workload:rootfs-propagation")

            privileged = context.privileged?
            mount_proc(path)
            mount_sys(path, privileged: privileged)
            mount_dev(path, privileged: privileged)
            apply_bind_mounts(path, mounts, context)
            apply_masked_paths(path, context) unless privileged
            apply_readonly_paths(path, context) unless privileged
            pivot_into(path, overlay: overlay, before: before, read_only: context.read_only_root_filesystem == true)
            target_cwd = cwd.nil? || String(cwd).empty? ? "/" : String(cwd)
            raise EffectError, "workload cwd must be absolute" unless target_cwd.start_with?("/")
            raise EffectError, "workload cwd contains NUL" if target_cwd.include?("\0")

            Dir.chdir(target_cwd)
            @rootfs_report
          rescue SystemCallError => error
            raise EffectError, "workload rootfs construction failed: #{error.message}"
          end

          private

          def mount_proc(root)
            target = ensure_directory(File.join(root, "proc"))
            @mount.mount(source: "proc", target: target, filesystem: "proc",
                         flags: MS_NOSUID | MS_NODEV | MS_NOEXEC, resource_id: "workload:proc")
          end

          def mount_sys(root, privileged:)
            target = ensure_directory(File.join(root, "sys"))
            flags = MS_NOSUID | MS_NODEV | MS_NOEXEC
            flags |= MS_RDONLY unless privileged
            @mount.mount(source: "sysfs", target: target, filesystem: "sysfs", flags: flags, resource_id: "workload:sys")
            cgroup_target = File.join(target, "fs", "cgroup")
            return unless File.directory?(cgroup_target)

            # The cgroup namespace was unshared after cgroup placement, so
            # this mount is rooted at the container's own cgroup.
            @mount.mount(source: "cgroup2", target: cgroup_target, filesystem: "cgroup2",
                         flags: MS_NOSUID | MS_NODEV | MS_NOEXEC | (privileged ? 0 : MS_RDONLY),
                         resource_id: "workload:cgroup2")
          end

          # /dev is a nodev tmpfs: a node the workload mknods there (the
          # device cgroup lets every container mknod) cannot be opened.  The
          # device nodes it does get are bind mounts, and a bind carries its
          # source mount's flags, so /dev/null and friends still open.
          def mount_dev(root, privileged: false)
            target = ensure_directory(File.join(root, "dev"))
            @mount.mount(source: "tmpfs", target: target, filesystem: "tmpfs",
                         flags: MS_NOSUID | MS_NODEV | MS_STRICTATIME, data: "mode=755,size=65536k", resource_id: "workload:dev")
            ROOTFS_DEVICES.each do |name|
              source = File.join("/dev", name)
              raise EffectError, "required host device is unavailable: #{source}" unless File.stat(source).chardev?

              device = File.join(target, name)
              File.open(device, File::WRONLY | File::CREAT | File::EXCL, 0o666).close
              @mount.mount(source: source, target: device, filesystem: nil, flags: MS_BIND, resource_id: "workload:dev:#{name}")
            end
            mount_host_devices(target, "/dev") if privileged
            DEVICE_SYMLINKS.each { |name, link_target| File.symlink(link_target, File.join(target, name)) }
            pts = ensure_directory(File.join(target, "pts"))
            @mount.mount(source: "devpts", target: pts, filesystem: "devpts", flags: MS_NOSUID | MS_NOEXEC,
                         data: "newinstance,ptmxmode=0666,mode=0620,gid=5", resource_id: "workload:devpts")
            shm = ensure_directory(File.join(target, "shm"))
            @mount.mount(source: "shm", target: shm, filesystem: "tmpfs", flags: MS_NOSUID | MS_NODEV | MS_NOEXEC,
                         data: "mode=1777,size=65536k", resource_id: "workload:shm")
            mqueue = ensure_directory(File.join(target, "mqueue"))
            @mount.mount(source: "mqueue", target: mqueue, filesystem: "mqueue", flags: MS_NOSUID | MS_NODEV | MS_NOEXEC,
                         resource_id: "workload:mqueue")
          end

          # Directories containerd's HostDevices walk leaves out.
          HOST_DEVICE_SKIPPED_DIRECTORIES = %w[pts shm fd mqueue .lxc .lxd-mounts .udev].freeze

          # A privileged container gets every host device node (containerd
          # WithPrivileged -> WithAllDevices, the device cgroup allows all).
          # Nodes already provided (the standard set) and the names that are
          # symlinks in a container /dev stay as they are; sockets, fifos and
          # dangling symlinks are not devices.  Bind mounts rather than
          # mknod because the tmpfs is nodev.
          def mount_host_devices(target, source)
            Dir.children(source).sort.each do |name|
              host = File.join(source, name)
              if File.directory?(host) && !File.symlink?(host)
                next if HOST_DEVICE_SKIPPED_DIRECTORIES.include?(name)

                mount_host_devices(ensure_directory(File.join(target, name)), host)
                next
              end
              next if name == "console" || DEVICE_SYMLINKS.key?(name)

              stat = begin
                File.stat(host)
              rescue Errno::ENOENT, Errno::ELOOP, Errno::EACCES
                next
              end
              next unless stat.chardev? || stat.blockdev?

              device = File.join(target, name)
              next if File.exist?(device) || File.symlink?(device)

              File.open(device, File::WRONLY | File::CREAT | File::EXCL, stat.mode & 0o777).close
              @mount.mount(source: host, target: device, filesystem: nil, flags: MS_BIND,
                           resource_id: "workload:dev:#{host.delete_prefix("/dev/")}")
            end
          end

          def apply_masked_paths(root, context)
            return if context.proc_mount.to_s == "Unmasked"

            DEFAULT_MASKED_PATHS.each do |relative|
              target = File.join(root, relative)
              next unless File.exist?(target)

              if File.directory?(target)
                @mount.mount(source: "tmpfs", target: target, filesystem: "tmpfs", flags: MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                             data: "mode=755", resource_id: "workload:mask:#{relative}")
              else
                @mount.mount(source: "/dev/null", target: target, filesystem: nil, flags: MS_BIND, resource_id: "workload:mask:#{relative}")
              end
            end
          end

          def apply_readonly_paths(root, context)
            return if context.proc_mount.to_s == "Unmasked"

            DEFAULT_READONLY_PATHS.each do |relative|
              target = File.join(root, relative)
              next unless File.exist?(target)

              @mount.mount(source: target, target: target, filesystem: nil, flags: MS_BIND | MS_REC, resource_id: "workload:ro:#{relative}")
              # A bind remount must repeat the locked flags of the underlying
              # mount (nosuid/nodev/noexec on proc) or the kernel rejects it.
              @mount.mount(source: nil, target: target, filesystem: nil,
                           flags: MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                           resource_id: "workload:ro-remount:#{relative}")
            end
          end

          def pivot_into(root, overlay:, before:, read_only:)
            Dir.chdir(root)
            put_old = File.join(root, PIVOT_OLD)
            Dir.mkdir(put_old, 0o700)
            # Everything not beneath the new root belongs to the old root
            # tree and must be gone after the pivot.
            old_ids = before.reject { |entry| entry.mountpoint == root || entry.mountpoint.start_with?("#{root}/") }.map(&:id)
            @pivot.pivot_root(new_root: ".", put_old: PIVOT_OLD, resource_id: "workload:pivot_root")
            Dir.chdir("/")
            @pivot.detach_tree("/#{PIVOT_OLD}", old_mount_ids: old_ids, resource_id: "workload:old-root")
            Dir.rmdir("/#{PIVOT_OLD}")
            if read_only
              @mount.mount(source: nil, target: "/", filesystem: nil, flags: MS_BIND | MS_REMOUNT | MS_RDONLY,
                           resource_id: "workload:rootfs-readonly")
            end
            after_raw = File.binread("/proc/self/mountinfo")
            after = PivotRoot.parse_mountinfo(after_raw)
            root_entry = after.select { |entry| entry.mountpoint == "/" }.max_by(&:index)
            unless root_entry && root_entry.filesystem == overlay.filesystem
              raise EffectError,
                    "pivot_root did not install the workload root"
            end
            raise EffectError, "root mount identity changed across pivot_root" unless root_entry.id == overlay.id

            # detach_tree proved the old root unreachable (nothing left under
            # the put-old directory, no descriptor on a detached mount).
            # Intersecting ids with the pre-pivot list is not a proof: ids are
            # recycled while the rootfs is built, and a new-root mount holding
            # a recycled id failed ~10 container starts a round.
            remaining = after.select { |entry| entry.mountpoint == "/#{PIVOT_OLD}" || entry.mountpoint.start_with?("/#{PIVOT_OLD}/") }
            raise EffectError, "old root mounts remain reachable: #{remaining.map(&:mountpoint).join(", ")}" unless remaining.empty?

            leaked = after.reject { |entry| entry.mountpoint.start_with?("/") }
            raise EffectError, "mount table contains entries outside the new root" unless leaked.empty?

            @rootfs_report = Rootfs.new(
              root_mount_id: root_entry.id, mount_count: after.length, old_root_mount_ids: old_ids.sort,
              old_root_unreachable: true, mountinfo_sha256: Digest::SHA256.hexdigest(after_raw),
              rootfs_read_only: read_only
            )
          end

          def ensure_directory(path)
            Dir.mkdir(path, 0o755) unless File.directory?(path)
            raise EffectError, "rootfs mountpoint is a symlink: #{path}" if File.symlink?(path)

            path
          end
        end
      end
    end
  end
end
