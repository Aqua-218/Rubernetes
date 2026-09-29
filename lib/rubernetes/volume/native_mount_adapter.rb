# frozen_string_literal: true

require "fileutils"
require "monitor"

require_relative "errors"
require_relative "types"
require_relative "../platform/linux/mount"
require_relative "../platform/linux/statfs"

module Rubernetes
  module Volume
    # Production mount adapter for Linux volume effects.
    #
    # The adapter owns only mount(2)/umount2, open_tree/move_mount effects and
    # mountinfo readback.  Lifecycle policy, path authorization, and durable
    # ownership remain in Volume::Manager and its backends.  A syscall
    # returning success is never exposed to callers until the requested mount
    # is visible in mountinfo.
    #
    # Identity vocabulary (spec 5.11.3 "mount source, target, mount ID,
    # filesystem UUID, device ID"):
    #   source         the mount source the caller asked for.  For a bind mount
    #                  this is the bound directory/file, which is what the
    #                  ledger and operators reason about.
    #   kernelSource   the superblock source reported by mountinfo.  For a bind
    #                  mount this is the underlying block device (or "tmpfs"),
    #                  and it is what unmount-time verification compares.
    #   sourceIdentity the kernel source; it participates in the ledger
    #                  fingerprint because raw mountinfo observations carry it.
    #   bind           true when the mount is a bind of an existing subtree.
    #                  A bind is identified by (mountId, deviceId, root, target)
    #                  and never by a filesystem UUID.
    class NativeMountAdapter
      LinuxMount = Rubernetes::Platform::Linux::Mount
      LinuxStatfs = Rubernetes::Platform::Linux::Statfs

      MS_RDONLY = LinuxMount::MS_RDONLY
      MS_NOSUID = LinuxMount::MS_NOSUID
      MS_NODEV = LinuxMount::MS_NODEV
      MS_NOEXEC = LinuxMount::MS_NOEXEC
      MS_REMOUNT = LinuxMount::MS_REMOUNT
      MS_BIND = LinuxMount::MS_BIND
      MS_PRIVATE = LinuxMount::MS_PRIVATE
      MS_REC = LinuxMount::MS_REC
      MNT_DETACH = LinuxMount::MNT_DETACH
      UMOUNT_NOFOLLOW = LinuxMount.const_defined?(:UMOUNT_NOFOLLOW) ? LinuxMount::UMOUNT_NOFOLLOW : 8

      # include/uapi/asm-generic/fcntl.h: O_PATH, O_CLOEXEC, O_NOFOLLOW.
      O_PATH = 0x200000
      O_CLOEXEC = 0x80000
      O_NOFOLLOW = 0x20000

      STABLE_FIELDS = %w[mountId deviceId root target filesystem source options].freeze
      UUID_FILESYSTEMS = %w[ext4 xfs].freeze
      FLAG_OPTIONS = {
        "ro" => MS_RDONLY,
        "rw" => 0,
        "nosuid" => MS_NOSUID,
        "nodev" => MS_NODEV,
        "noexec" => MS_NOEXEC,
        "remount" => MS_REMOUNT,
        "bind" => MS_BIND,
        "rbind" => MS_BIND | MS_REC,
        "rec" => MS_REC,
        "private" => MS_PRIVATE,
        "rprivate" => MS_PRIVATE | MS_REC
      }.freeze

      def self.parse_mountinfo(contents)
        String(contents).each_line.with_index(1).map do |line, line_number|
          parse_mountinfo_line(line, line_number)
        end.compact.freeze
      rescue TypeError
        raise MountIdentityError, "mountinfo contents must be a string"
      end

      def self.parse_mountinfo_line(line, line_number = nil)
        value = String(line).strip
        return nil if value.empty?

        before_separator, after_separator = value.split(" - ", 2)
        unless before_separator && after_separator
          raise MountIdentityError, "mountinfo line #{line_number || "?"} has no filesystem separator"
        end

        fields = before_separator.split(" ")
        if fields.length < 6
          raise MountIdentityError, "mountinfo line #{line_number || "?"} has fewer than six pre-filesystem fields"
        end

        filesystem_fields = after_separator.split(" ", 3)
        if filesystem_fields.length < 2
          raise MountIdentityError, "mountinfo line #{line_number || "?"} has incomplete filesystem fields"
        end

        mount_id, parent_id, device_id, root, mountpoint, options = fields.first(6)
        unless mount_id.match?(/\A\d+\z/) && parent_id.match?(/\A\d+\z/)
          raise MountIdentityError, "mountinfo line #{line_number || "?"} has invalid mount or parent id"
        end
        unless device_id.match?(/\A\d+:\d+\z/)
          raise MountIdentityError, "mountinfo line #{line_number || "?"} has invalid device major:minor"
        end

        fs_type, source, super_options = filesystem_fields
        decoded_source = decode_mountinfo_field(source)
        record = {
          "mountId" => mount_id,
          "parentId" => parent_id,
          "deviceId" => device_id,
          "deviceMajorMinor" => device_id,
          "root" => decode_mountinfo_field(root),
          "mountpoint" => decode_mountinfo_field(mountpoint),
          "target" => decode_mountinfo_field(mountpoint),
          "options" => decode_mountinfo_field(options),
          "optionalFields" => fields.drop(6).map { |field| decode_mountinfo_field(field) }.freeze,
          "filesystem" => decode_mountinfo_field(fs_type),
          "fsType" => decode_mountinfo_field(fs_type),
          "source" => decoded_source,
          "kernelSource" => decoded_source,
          "sourceIdentity" => decoded_source,
          "superOptions" => decode_mountinfo_field(super_options.to_s),
          "line" => value.freeze,
          # Linux mountinfo does not carry a filesystem UUID.  The adapter
          # deliberately leaves it absent instead of deriving a synthetic id.
          "filesystemUuid" => nil,
          "filesystemUuidAvailable" => false
        }
        record["stableIdentity"] = STABLE_FIELDS.to_h { |field| [field, record.fetch(field)] }.freeze
        record.freeze
      end

      def self.decode_mountinfo_field(value)
        String(value).gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }.freeze
      end

      def initialize(mount: nil, mountinfo_path: "/proc/self/mountinfo", mountinfo_reader: nil,
                     mountinfo: nil, filesystem_uuid_resolver: nil, verify_mount_binding: nil, use_open_tree: nil)
        @mount = mount || LinuxMount.new
        @mountinfo_reader = mountinfo_reader || (mountinfo.respond_to?(:call) ? mountinfo : nil)
        @mountinfo_path =
          if mountinfo && !mountinfo.respond_to?(:call)
            File.expand_path(String(mountinfo))
          else
            File.expand_path(String(mountinfo_path))
          end
        @filesystem_uuid_resolver = filesystem_uuid_resolver
        @verify_mount_binding = verify_mount_binding.nil? ? @mount.is_a?(LinuxMount) : verify_mount_binding == true
        # Bind mounts go through open_tree/mount_setattr/move_mount whenever
        # the injected mount object implements it: attributes become final
        # before the tree is reachable, and both ends are descriptors.
        @use_open_tree = use_open_tree.nil? ? @mount.respond_to?(:bind_tree) : use_open_tree == true
        @mutex = Monitor.new
        # Mount, bind and unmount are serialised per target: the check that a
        # target is free and the mount that takes it must not interleave with
        # another operation on the same path.  One lock for the whole node
        # made thirty Pods starting together queue every volume mount behind
        # each other's mountinfo readbacks (~1.5 s of waiting per mount).
        @target_locks = Array.new(TARGET_LOCK_STRIPES) { Monitor.new }
      end

      attr_reader :mountinfo_path

      # Built-in Backend callers must acquire a descriptor lease for every
      # mount target.  Keeping this contract on the native adapter lets the
      # backend fail closed when it is accidentally assembled with a
      # pathname-only resolver.
      def target_handle_required?
        true
      end

      # Native mountinfo is authoritative for descriptor-to-mount binding.
      # Remote/in-memory adapters may expose lifecycle-shaped identities, but
      # only this adapter can prove that both the visible target and the held
      # parent/leaf descriptor resolve to the same kernel mount.
      def descriptor_mount_binding?
        @verify_mount_binding
      end

      def open_tree_bind?
        @use_open_tree
      end

      # Return every mount visible in this process's mount namespace.  Block
      # filesystem mounts are decorated with their superblock UUID when a
      # resolver is configured so that ledger reconciliation can match the
      # identity it registered at mount time.
      def list_mounts
        read_mounts.map { |entry| decorate_observation(entry) }.freeze
      end

      # Return the mount currently covering target, or nil when the target is
      # not present in the mountinfo snapshot.
      def find_mount(target)
        normalized_target = normalize_target(target)
        mount_entry_at(normalized_target)&.then { |entry| decorate_observation(entry) }
      end

      alias mount_at find_mount

      # Mount a filesystem or create a directory bind mount.  The return value
      # is the post-effect mountinfo identity, never the raw syscall result.
      def mount(source:, target:, filesystem: nil, readonly: false, options: {}, volume_id: nil, stage: false,
                source_handle: nil, target_handle: nil, flags: nil, data: nil, resource_id: nil, **_kwargs)
        normalized_target = normalize_target(target)
        kernel_source = source_for_mount(source, source_handle)
        requested_source = requested_source_identity(source, source_handle)
        kernel_target = target_for_mount(normalized_target, target_handle)
        requested_filesystem = filesystem && String(filesystem)
        requested_filesystem = nil if requested_filesystem&.empty?
        option_flags, option_data, option_names = normalize_options(options, data)
        requested_flags = flags.nil? ? 0 : Integer(flags)
        bind = bind_mount?(requested_filesystem, option_flags, requested_flags)
        effective_flags = requested_flags | option_flags
        effective_flags |= MS_BIND if bind
        effective_readonly = readonly == true || (effective_flags & MS_RDONLY) != 0 || option_names.include?("ro")
        resource_id ||= resource_id_for("mount", normalized_target, volume_id)
        kernel_filesystem = bind ? nil : requested_filesystem
        mount_api = bind && open_tree_bind? ? "open_tree" : "mount"

        target_lock(normalized_target).synchronize do
          existing = possibly_mount_root?(normalized_target) ? mount_entry_at(normalized_target) : nil
          if existing
            raise MountIdentityError, "mount target #{normalized_target.inspect} is already mounted with id #{existing.fetch("mountId")}"
          end

          # A descriptor lease has already created and opened the target
          # through its verified parent.  Touching the pathname again here
          # would reintroduce the replacement race the lease is meant to
          # close.
          ensure_mount_target!(normalized_target) unless target_handle
          mounted = false
          begin
            verify_target_handle!(target_handle)
            if mount_api == "open_tree"
              bind_with_open_tree(kernel_source: kernel_source, source_handle: source_handle,
                                  target: normalized_target, target_handle: target_handle,
                                  flags: effective_flags, readonly: effective_readonly, resource_id: resource_id)
              mounted = true
            else
              syscall_result = @mount.mount(source: kernel_source, target: kernel_target, filesystem: kernel_filesystem,
                                            flags: effective_flags | (effective_readonly && !bind ? MS_RDONLY : 0),
                                            data: option_data, resource_id: resource_id)
              mounted = true
              ensure_syscall_success!(syscall_result, "mount(2)", resource_id)
            end

            # The descriptor pins the inode used by the mount syscall, but the
            # user-visible path may still have been renamed or replaced while
            # the syscall was in flight.  Treat that mismatch as a failed
            # operation and clean up through the held descriptor.
            verify_target_handle!(target_handle, mounted: true)

            if mount_api == "mount" && bind && effective_readonly
              # mount(2) ignores MS_RDONLY on the initial bind; a remount is
              # the only way to make it read-only through this API.
              remount_flags = MS_BIND | MS_REMOUNT | MS_RDONLY
              remount_flags |= effective_flags & (MS_NOSUID | MS_NODEV | MS_NOEXEC)
              remount_result = @mount.mount(source: nil, target: kernel_target, filesystem: nil, flags: remount_flags,
                                            data: nil, resource_id: "#{resource_id}:readonly")
              ensure_syscall_success!(remount_result, "mount(2) read-only remount", "#{resource_id}:readonly")
            end

            observed = readback_mount!(normalized_target, requested_filesystem: requested_filesystem,
                                       bind: bind, readonly: effective_readonly, resource_id: resource_id)
            verify_target_handle!(target_handle, mounted: true,
                                  mount_identity: descriptor_mount_binding? ? observed : nil)
            decorate_mount(observed, requested_source: requested_source, dispatch_source: kernel_source,
                           requested_filesystem: requested_filesystem, requested_options: options,
                           volume_id: volume_id, stage: stage, readonly: effective_readonly, bind: bind,
                           mount_api: mount_api)
          rescue StandardError => error
            if mounted
              begin
                cleanup_mounted_target(normalized_target, resource_id, target_handle: target_handle)
              rescue CleanupError => cleanup_error
                details = {
                  "primaryError" => {"class" => error.class.name, "message" => error.message.to_s},
                  "cleanupErrors" => Array(cleanup_error.cleanup_errors).map do |child|
                    {"class" => child.class.name, "message" => child.message.to_s}
                  end
                }
                raise CleanupError.new(
                  "#{error.message}; mount cleanup failed: #{cleanup_error.message}",
                  resource_id: resource_id, details: details,
                  cleanup_errors: Array(cleanup_error.cleanup_errors)
                ), cause: error
              end
            end
            raise error
          end
        end
      end

      # Create a directory bind mount.  Linux ignores MS_RDONLY on the first
      # bind call, so mount performs the required bind-remount when needed.
      def bind(source:, target:, readonly: false, volume_id: nil, options: {}, source_handle: nil, target_handle: nil, **kwargs)
        merged_options = options.respond_to?(:to_h) ? options.to_h.merge("bind" => true) : {"bind" => true}
        mount(source: source, target: target, filesystem: nil, readonly: readonly, options: merged_options,
              volume_id: volume_id, source_handle: source_handle, target_handle: target_handle, **kwargs)
      end

      # Unmount target with umount2(2) and verify that target disappeared from
      # the same mount namespace before reporting success.
      def unmount(target:, mount_id: nil, identity: nil, flags: 0, volume_id: nil, resource_id: nil,
                  target_handle: nil, **_kwargs)
        normalized_target = normalize_target(target)
        resource_id ||= resource_id_for("unmount", normalized_target, volume_id)
        expected = identity.respond_to?(:to_h) ? identity.to_h.transform_keys(&:to_s) : identity

        target_lock(normalized_target).synchronize do
          observed = mount_entry_at(normalized_target)
          raise MountIdentityError, "mount target #{normalized_target.inspect} is not present in mountinfo" unless observed

          verify_identity!(observed, expected) if expected
          if mount_id && observed.fetch("mountId").to_s != mount_id.to_s
            raise MountIdentityError, "mount id changed at #{normalized_target}: expected #{mount_id}, observed #{observed.fetch("mountId")}"
          end

          # Native callers hold the target inode for the complete syscall. A
          # pathname-only umount would let a rename/replacement redirect the
          # cleanup to another mount between the readback and umount2(2).
          verify_target_handle!(target_handle, mounted: true, mount_identity: observed) if target_handle
          kernel_target, kernel_flags = unmount_dispatch(normalized_target, target_handle, observed, Integer(flags))
          syscall_result = unmount_syscall(kernel_target, kernel_flags, resource_id)
          unless syscall_result == true || syscall_result == 0
            begin
              remaining = read_mounts
              detail = if remaining.any? { |entry| entry.fetch("mountId").to_s == observed.fetch("mountId").to_s && entry.fetch("target") == normalized_target }
                         "adapter returned #{syscall_result.inspect}; the original mount remains present"
                       else
                         "adapter returned #{syscall_result.inspect}; post-unmount readback cannot prove the outcome"
                       end
            rescue StandardError => error
              detail = "adapter returned #{syscall_result.inspect}; post-unmount readback failed: #{error.message}"
            end
            raise_cleanup_ambiguity!("umount2(2) did not report success for #{resource_id}", resource_id, detail)
          end

          begin
            remaining = [mount_entry_at(normalized_target)].compact
          rescue StandardError => error
            raise build_cleanup_error("umount2(2) post-readback is ambiguous for #{resource_id}", resource_id,
                                      "post-unmount mountinfo read failed: #{error.message}"), cause: error
          end
          # The kernel allocates mount ids from the lowest free number, so the
          # id this mount just gave up is the next one handed out anywhere on
          # the host -- another Pod's tmpfs, another node agent's bind mount.
          # Judging "still mounted" by id alone mistook that newcomer for the
          # old mount, reported an ambiguous unmount, and left the Pod in
          # CleanupPending with its ledger entries; those entries then blocked
          # every later mount that drew the same id.  The old mount is present
          # only if its id still covers its own target.
          same_mount = remaining.find do |entry|
            entry.fetch("mountId").to_s == observed.fetch("mountId").to_s &&
              entry.fetch("target") == normalized_target
          end
          if same_mount
            raise_cleanup_ambiguity!("umount2 reported success but mount #{observed.fetch("mountId")} remains mounted",
                                     resource_id, "mount identity remains present")
          end
          replacement = remaining.find { |entry| entry.fetch("target") == normalized_target }
          if replacement
            raise_cleanup_ambiguity!("umount2 changed the mount at #{normalized_target.inspect} unexpectedly", resource_id,
                                     "a different mount now covers the target")
          end
          true
        rescue CleanupError
          raise
        rescue MountIdentityError
          raise
        rescue StandardError => error
          raise build_cleanup_error("umount2(2) outcome is unknown for #{resource_id}", resource_id, error.message),
                cause: error
        end
      end

      # Mount a tmpfs for Secret/projected/emptyDir memory volumes.  The
      # existing mount is returned idempotently when it is already tmpfs.
      def ensure_tmpfs(path, size_limit: nil, volume_id: nil, target_handle: nil, **kwargs)
        normalized_target = normalize_target(path)
        existing = find_mount(normalized_target)
        if existing && existing.fetch("filesystem").casecmp?("tmpfs")
          verify_target_handle!(target_handle, mounted: true, mount_identity: existing) if target_handle
          return existing
        end

        options = {}
        unless size_limit.nil?
          options["size"] = Rubernetes::Volume::Types.parse_capacity(size_limit)
        end
        mount(source: "tmpfs", target: normalized_target, filesystem: "tmpfs", options: options,
              volume_id: volume_id, target_handle: target_handle, **kwargs)
      end

      # kubelet's SetVolumeOwnership (pkg/volume/volume_linux.go): every file
      # in the volume is given the Pod's fsGroup and the group bits that go
      # with it, so a container running as a non-root user in that group can
      # read (and, for a writable volume, write) what was projected as root.
      # Directories additionally get the setgid bit so files created later
      # inherit the group.
      #
      # `readonly` selects upstream's roMask/rwMask, and
      # fsGroupChangePolicy: OnRootMismatch skips the walk when the volume
      # root already carries the right group and setgid bit.
      RW_MASK = 0o660
      RO_MASK = 0o440
      EXEC_MASK = 0o110
      SETGID = 0o2000

      def apply_fs_group(path:, fs_group:, pod: nil, readonly: false, change_policy: nil, **_kwargs)
        group = Integer(fs_group)
        root = normalize_target(path)
        mask = readonly ? RO_MASK : RW_MASK
        return true if change_policy.to_s == "OnRootMismatch" && fs_group_root_matches?(root, group, mask)

        walk_volume(root) { |entry, stat| apply_fs_group_entry(entry, stat, group, mask) }
        true
      rescue SystemCallError => error
        raise SecurityError, "cannot apply fsGroup #{fs_group} to #{path.inspect}: #{error.message}", cause: error
      end

      def tmpfs?(path = nil)
        mounts = list_mounts
        return mounts.any? { |entry| entry.fetch("filesystem").casecmp?("tmpfs") } if path.nil?

        normalized_target = normalize_target(path)
        mounts.any? do |entry|
          entry.fetch("target") == normalized_target && entry.fetch("filesystem").casecmp?("tmpfs")
        end
      end

      # Kernel-backed capacity/usage for a mounted volume via statfs(2).  The
      # values are what NodeGetVolumeStats reports for built-in backends.
      def stats(path:, volume_id:, capacity_bytes: nil, **_kwargs)
        normalized = normalize_target(path)
        result = LinuxStatfs.statfs(normalized, resource_id: resource_id_for("statfs", normalized, volume_id))
        Stats.new(volume_id: volume_id, used_bytes: result.used_bytes, capacity_bytes: result.capacity_bytes,
                  available_bytes: result.available_bytes, inodes_used: result.files - result.files_free,
                  inodes: result.files)
      rescue Rubernetes::Platform::Linux::Error => error
        raise MountIdentityError, "statfs readback failed for #{normalized.inspect}: #{error.message}", cause: error
      end

      # statfs identity (type magic, fsid) for an observation runner or for
      # a caller that wants to bind a path to the filesystem it lives on.
      def filesystem_identity(path)
        normalized = normalize_target(path)
        LinuxStatfs.statfs(normalized, resource_id: "statfs:#{normalized}").to_h
      rescue Rubernetes::Platform::Linux::Error => error
        raise MountIdentityError, "statfs readback failed for #{normalized.inspect}: #{error.message}", cause: error
      end

      private

      def read_mounts
        self.class.parse_mountinfo(read_mountinfo_contents)
      end

      # The first entry mounted at +target+ -- what read_mounts.find would
      # return -- without parsing the whole table.  Every mount, bind and
      # unmount reads its target back, and a node with a few hundred volume
      # mounts spent most of MountVolume.SetUp decoding every mountinfo line
      # into a record to look at one of them.
      def mount_entry_at(target)
        line_number = 0
        needle = " #{mountinfo_encode(target)} "
        read_mountinfo_contents.each_line do |line|
          line_number += 1
          next unless line.include?(needle)

          fields = line.split(" ", 6)
          next if fields.length < 6

          mountpoint = fields[4]
          mountpoint = self.class.decode_mountinfo_field(mountpoint) if mountpoint.include?("\\")
          return self.class.parse_mountinfo_line(line, line_number) if mountpoint == target
        end
        nil
      end

      # False only when +path+ provably is not the root of a mount: it and its
      # parent directory sit on the same mount (fdinfo "mnt_id"), or it does
      # not exist.  The pre-mount "already mounted?" check used to read and
      # scan the node's whole mount table for every volume mount; anything
      # this cannot decide still gets that full lookup.
      def possibly_mount_root?(path)
        return false unless File.exist?(path)
        return true if path == "/"

        own = descriptor_mount_id(path)
        parent = descriptor_mount_id(File.dirname(path))
        own.nil? || parent.nil? || own != parent
      rescue SystemCallError, IOError
        true
      end

      def descriptor_mount_id(path)
        File.open(path, File::RDONLY | File::NONBLOCK | File::NOFOLLOW) do |io|
          File.read("/proc/self/fdinfo/#{io.fileno}")[/^mnt_id:\s*(\d+)/, 1]
        end
      rescue SystemCallError, IOError
        nil
      end

      # mountinfo escapes space, tab, newline and backslash as \\ooo.
      TARGET_LOCK_STRIPES = 64

      def target_lock(target)
        @target_locks[target.hash % TARGET_LOCK_STRIPES]
      end

      def mountinfo_encode(path)
        path.to_s.gsub(/[ \t\n\\]/) { |char| format("\\%03o", char.ord) }
      end

      def read_mountinfo_contents
        contents = if @mountinfo_reader
                     @mountinfo_reader.call
                   else
                     File.binread(@mountinfo_path)
                   end
        raise MountIdentityError, "mountinfo contents must be a string" unless contents.is_a?(String)

        contents
      rescue MountIdentityError
        raise
      rescue SystemCallError, IOError => error
        raise MountIdentityError, "failed to read #{@mountinfo_path}: #{error.message}", cause: error
      end

      def fs_group_root_matches?(root, group, mask)
        stat = File.lstat(root)
        stat.gid == group && (stat.mode & (SETGID | EXEC_MASK | mask)) == (SETGID | EXEC_MASK | mask)
      rescue SystemCallError
        false
      end

      # Depth-first walk that never follows a symlink out of the volume: each
      # entry is examined with lstat and a symlink is left alone entirely,
      # which is what upstream does.
      def walk_volume(root, &block)
        stat = File.lstat(root)
        yield(root, stat)
        return unless stat.directory?

        Dir.children(root).each do |child|
          child_path = File.join(root, child)
          child_stat = begin
            File.lstat(child_path)
          rescue Errno::ENOENT
            next
          end
          if child_stat.directory?
            walk_volume(child_path, &block)
          else
            yield(child_path, child_stat)
          end
        end
      end

      def apply_fs_group_entry(entry, stat, group, mask)
        return if stat.symlink?

        File.lchown(nil, group, entry)
        bits = mask
        bits |= (SETGID | EXEC_MASK) if stat.directory?
        File.chmod(stat.mode & 0o7777 | bits, entry)
      rescue Errno::ENOENT
        nil
      end

      def normalize_target(target)
        value = String(target)
        raise PathSecurityError, "mount target must not contain NUL" if value.include?("\0")
        raise PathSecurityError, "mount target must be absolute" unless value.start_with?("/")
        File.expand_path(value)
      rescue TypeError
        raise PathSecurityError, "mount target must be a string"
      end

      def source_for_mount(source, source_handle)
        if source_handle
          descriptor = descriptor_number(source_handle)
          return "/proc/self/fd/#{descriptor}" if descriptor
          if source_handle.respond_to?(:root) && source_handle.respond_to?(:path) && source_handle.path
            return File.expand_path(File.join(source_handle.root.to_s, source_handle.path.to_s))
          end
        end

        return nil if source.nil?

        value = String(source)
        raise PathSecurityError, "mount source must not contain NUL" if value.include?("\0")
        value
      rescue TypeError
        raise PathSecurityError, "mount source must be a string"
      end

      # The stable, human-meaningful source: an absolute path for binds and
      # block devices, or the pseudo source ("tmpfs") for nodev filesystems.
      # A /proc/self/fd dispatch string is never recorded as identity because
      # it is meaningless after the descriptor closes.
      def requested_source_identity(source, source_handle)
        if source_handle && source_handle.respond_to?(:root) && source_handle.respond_to?(:path) && source_handle.path &&
           source_handle.root
          return File.expand_path(File.join(source_handle.root.to_s, source_handle.path.to_s))
        end
        return nil if source.nil?

        value = String(source)
        value.start_with?("/") ? File.expand_path(value) : value
      end

      # A non-lazy umount2(2) needs the mount to be unpinned: the lease's leaf
      # descriptor is released and the target is dispatched through the pinned
      # parent descriptor with UMOUNT_NOFOLLOW, after proving that the leaf
      # name still resolves to the mount just read back.
      # A busy mount is detached instead of being left behind.
      #
      # Teardown runs after the containers are gone, so nothing SHOULD hold the
      # mount -- but a nested submount (a subPath bind under the volume) or a
      # process still on its way out keeps umount2(2) returning EBUSY, and a
      # teardown that cannot finish is a Pod that can never be deleted: the
      # node leaves it in CleanupPending, never issues the final delete, and it
      # stays Terminating in the API for ever.  MNT_DETACH is the kernel's
      # answer to exactly that -- the mount leaves the namespace at once and
      # the kernel frees it when the last reference goes -- and it is what
      # kubelet reaches for when a mount point will not come away
      # (mount-utils CleanupMountWithForce).  This whole method only ever runs
      # to REMOVE a mount, so there is no case where retrying is wrong.
      def unmount_syscall(kernel_target, kernel_flags, resource_id)
        @mount.unmount(target: kernel_target, flags: kernel_flags, resource_id: resource_id)
      rescue StandardError => error
        raise unless busy_unmount?(error)
        raise if (Integer(kernel_flags) & MNT_DETACH) != 0

        @mount.unmount(target: kernel_target, flags: Integer(kernel_flags) | MNT_DETACH, resource_id: resource_id)
      end

      BUSY_UNMOUNT_PATTERN = /device or resource busy|\bEBUSY\b/i

      def busy_unmount?(error)
        return true if error.is_a?(SystemCallError) && error.errno == Errno::EBUSY::Errno
        return true if error.respond_to?(:errno) && error.errno == Errno::EBUSY::Errno

        BUSY_UNMOUNT_PATTERN.match?(error.message.to_s)
      end

      def unmount_dispatch(normalized_target, target_handle, observed, flags)
        return [target_for_mount(normalized_target, target_handle), flags] unless target_handle.respond_to?(:release_leaf_for_unmount!)

        dispatch_path = String(target_handle.release_leaf_for_unmount!)
        stat = File.lstat(dispatch_path)
        raise PathSecurityError, "unmount target #{normalized_target.inspect} became a symlink" if stat.symlink?

        leaf_device = "#{stat.dev_major}:#{stat.dev_minor}"
        unless leaf_device == observed.fetch("deviceId").to_s
          raise MountIdentityError, "unmount target #{normalized_target.inspect} no longer resolves to mount #{observed.fetch("mountId")} (device #{leaf_device} != #{observed.fetch("deviceId")})"
        end
        [dispatch_path, flags | UMOUNT_NOFOLLOW]
      rescue SystemCallError => error
        raise MountIdentityError, "unmount target #{normalized_target.inspect} could not be re-resolved: #{error.message}", cause: error
      end

      def target_for_mount(target, target_handle)
        return target unless target_handle

        if target_handle.respond_to?(:dispatch_path)
          dispatch_path = String(target_handle.dispatch_path)
          raise PathSecurityError, "mount target descriptor dispatch path must be absolute" unless dispatch_path.start_with?("/")

          return dispatch_path
        end

        descriptor = descriptor_number(target_handle)
        return "/proc/self/fd/#{descriptor}" if descriptor

        raise PathSecurityError, "mount target descriptor did not expose a file descriptor"
      rescue TypeError
        raise PathSecurityError, "mount target descriptor dispatch path must be a string"
      end

      # Extract an integer descriptor from the handle shapes used in the
      # volume package: PathSecurity::TargetLease (#handle), PathSecurity::Handle
      # and Openat2::Handle (#fd as Integer or IO), IO, or Integer.
      def descriptor_number(handle)
        return nil if handle.nil?
        return handle if handle.is_a?(Integer)
        return handle.fileno if handle.respond_to?(:fileno)
        return descriptor_number(handle.handle) if handle.respond_to?(:handle) && !handle.respond_to?(:fd)

        if handle.respond_to?(:fd)
          descriptor = handle.fd
          return nil if descriptor.nil?
          return descriptor if descriptor.is_a?(Integer)
          return descriptor.fileno if descriptor.respond_to?(:fileno)
        end
        nil
      end

      # Descriptor-anchored bind through the new mount API.  Source and target
      # are opened as O_PATH descriptors when the caller did not hand one over;
      # the tree is cloned from the source descriptor, attributes applied on
      # the detached copy, then attached onto the target descriptor.
      def bind_with_open_tree(kernel_source:, source_handle:, target:, target_handle:, flags:, readonly:, resource_id:)
        source_fd = descriptor_number(source_handle)
        target_fd = descriptor_number(target_handle)
        opened = []
        begin
          if source_fd.nil?
            raise PathSecurityError, "bind mount requires a source path or descriptor" if kernel_source.nil?

            source_fd = IO.sysopen(kernel_source, O_PATH | O_CLOEXEC)
            opened << source_fd
          end
          if target_fd.nil?
            target_fd = IO.sysopen(target, O_PATH | O_CLOEXEC | O_NOFOLLOW)
            opened << target_fd
          end
          @mount.bind_tree(source_fd: source_fd, target_fd: target_fd, readonly: readonly,
                           nosuid: (flags & MS_NOSUID) != 0, nodev: (flags & MS_NODEV) != 0,
                           noexec: (flags & MS_NOEXEC) != 0, recursive: (flags & MS_REC) != 0,
                           resource_id: resource_id)
        rescue SystemCallError => error
          raise MountIdentityError, "bind source/target descriptor could not be opened for #{resource_id}: #{error.message}",
                cause: error
        ensure
          opened.each do |descriptor|
            IO.for_fd(descriptor).close
          rescue IOError, SystemCallError
            # The descriptor was only used to anchor the syscalls; a failed
            # close after the mount is visible cannot change the outcome and
            # the readback below remains authoritative.
            nil
          end
        end
        true
      end

      def verify_target_handle!(target_handle, mounted: false, mount_identity: nil)
        return true unless target_handle
        return true unless target_handle.respond_to?(:verify_original!)

        verifier = target_handle.method(:verify_original!)
        accepts_mount_identity = verifier.parameters.any? do |kind, name|
          kind == :keyrest || (%i[key keyreq].include?(kind) && name.to_sym == :mount_identity)
        end
        if accepts_mount_identity
          target_handle.verify_original!(mounted: mounted, mount_identity: mount_identity)
        else
          target_handle.verify_original!(mounted: mounted)
        end
      end

      def ensure_mount_target!(target)
        return true if File.exist?(target) || File.symlink?(target)

        FileUtils.mkdir_p(target)
        true
      rescue SystemCallError => error
        raise MountIdentityError, "failed to create mount target #{target.inspect}: #{error.message}", cause: error
      end

      def bind_mount?(filesystem, option_flags, requested_flags)
        filesystem.to_s.casecmp?("bind") || ((option_flags | requested_flags) & MS_BIND) != 0
      end

      def normalize_options(options, data)
        names = []
        flags = 0
        data_parts = data.nil? ? [] : option_parts(data)
        entries = case options
                  when nil then []
                  when Hash then options.to_a
                  else Array(options).map { |value| [value, true] }
                  end
        entries.each do |raw_name, raw_value|
          name = String(raw_name)
          raise ValidationError, "mount option must not contain NUL" if name.include?("\0")
          value = raw_value
          normalized_name = name.downcase
          next if value == false || value.nil?

          if FLAG_OPTIONS.key?(normalized_name)
            flags |= FLAG_OPTIONS.fetch(normalized_name)
            names << normalized_name unless normalized_name == "rw"
          elsif value == true
            data_parts << name
            names << name
          else
            text = String(value)
            raise ValidationError, "mount option value must not contain NUL" if text.include?("\0")

            data_parts << "#{name}=#{text}"
            names << "#{name}=#{text}"
          end
        end
        [flags, data_parts.empty? ? nil : data_parts.join(","), names.freeze]
      rescue TypeError
        raise ValidationError, "mount options must be a map, array, or string"
      end

      def option_parts(value)
        case value
        when String then value.split(",").reject(&:empty?)
        when Array then value.map { |item| String(item) }
        else [String(value)]
        end
      end

      def readback_mount!(target, requested_filesystem:, bind:, readonly:, resource_id:)
        observed = mount_entry_at(target)
        unless observed
          raise MountIdentityError, "mount(2) reported success but #{target.inspect} is absent from mountinfo (resource=#{resource_id})"
        end

        validate_stable_identity!(observed, resource_id)
        if requested_filesystem && !bind && !observed.fetch("filesystem").casecmp?(requested_filesystem)
          raise MountIdentityError, "mount(2) mounted #{observed.fetch("filesystem")} at #{target.inspect}; expected #{requested_filesystem}"
        end
        if readonly && !observed.fetch("options").split(",").include?("ro")
          raise MountIdentityError, "mount(2) mounted #{target.inspect} writable although read-only was requested"
        end
        observed
      end

      def validate_stable_identity!(entry, resource_id)
        missing = STABLE_FIELDS.select { |field| entry[field].nil? || entry[field].to_s.empty? }
        return true if missing.empty?

        raise MountIdentityError, "mount readback for #{resource_id} lacks stable fields: #{missing.join(", ")}"
      end

      def decorate_mount(entry, requested_source:, dispatch_source:, requested_filesystem:, requested_options:,
                         volume_id:, stage:, readonly:, bind:, mount_api:)
        result = entry.dup
        kernel_source = entry.fetch("source")
        result["kernelSource"] = kernel_source
        result["sourceIdentity"] = kernel_source
        result["bind"] = bind == true
        # A bind mount's UUID is the underlying filesystem's, not the volume's.
        # It is withheld so a directory bind on the root disk can never be
        # mistaken for ownership of that disk.
        result["filesystemUuid"] = bind ? nil : resolve_filesystem_uuid(result)
        result["filesystemUuidAvailable"] = !result["filesystemUuid"].nil?
        result["source"] = bind && requested_source ? requested_source : kernel_source
        result["requestedSource"] = requested_source || dispatch_source
        result["dispatchSource"] = dispatch_source
        result["requestedFilesystem"] = requested_filesystem
        result["requestedOptions"] = requested_options
        result["mountApi"] = mount_api
        result["volumeId"] = volume_id unless volume_id.nil?
        result["stage"] = stage == true
        result["readonly"] = readonly == true
        result["stableIdentity"] = STABLE_FIELDS.to_h { |field| [field, result.fetch(field)] }.merge(
          "kernelSource" => kernel_source
        ).freeze
        result.freeze
      end

      # Observations never claim bind-ness (mountinfo cannot express it); the
      # ledger decides that from its own registration record.
      def decorate_observation(entry)
        return entry unless @filesystem_uuid_resolver
        return entry unless UUID_FILESYSTEMS.include?(entry.fetch("filesystem").downcase) &&
                            entry.fetch("source").start_with?("/dev/")

        uuid = resolve_filesystem_uuid(entry)
        return entry if uuid.nil?

        entry.merge("filesystemUuid" => uuid, "filesystemUuidAvailable" => true).freeze
      end

      def resolve_filesystem_uuid(entry)
        return nil unless @filesystem_uuid_resolver

        value = @filesystem_uuid_resolver.call(entry)
        return nil if value.nil?

        uuid = String(value)
        raise MountIdentityError, "filesystem UUID resolver returned an empty value" if uuid.empty?
        uuid.freeze
      rescue TypeError => error
        raise MountIdentityError, "filesystem UUID resolver returned a non-string value", cause: error
      end

      # Compare the durable identity against the live mountinfo entry.  The
      # requested bind source is intent, not something mountinfo can show, so
      # the kernel source recorded at mount time is what "source" means here.
      def verify_identity!(observed, expected)
        STABLE_FIELDS.each do |field|
          value = if field == "source"
                    expected_kernel_source(expected)
                  else
                    expected[field] || expected[field.gsub(/([A-Z])/, '_\\1').downcase]
                  end
          next if value.nil? || value.to_s == observed.fetch(field).to_s

          raise MountIdentityError, "mount identity changed at #{observed.fetch("target")}: #{field} mismatch"
        end
      end

      def expected_kernel_source(expected)
        kernel = expected["kernelSource"] || expected["kernel_source"]
        return kernel unless kernel.nil?

        bind = expected["bind"] == true
        return expected["sourceIdentity"] || expected["source_identity"] if bind

        expected["source"]
      end

      def ensure_syscall_success!(result, operation, resource_id)
        return true if result == true || result == 0

        raise MountIdentityError, "#{operation} did not report success for #{resource_id}"
      end

      def raise_cleanup_ambiguity!(message, resource_id, detail)
        raise build_cleanup_error(message, resource_id, detail)
      end

      def build_cleanup_error(message, resource_id, detail)
        child = MountIdentityError.new(detail, resource_id: resource_id,
                                       details: {"cleanupErrors" => [{"class" => MountIdentityError.name,
                                                                       "message" => detail}]})
        CleanupError.new(message, resource_id: resource_id,
                         details: {"cleanupErrors" => [{"class" => child.class.name,
                                                         "message" => child.message}]},
                         cleanup_errors: [child])
      end

      def cleanup_mounted_target(target, resource_id, target_handle: nil)
        cleanup_target = target_for_mount(target, target_handle)
        result = @mount.unmount(target: cleanup_target, flags: 0, resource_id: "#{resource_id}:cleanup")
        ensure_syscall_success!(result, "umount2(2) cleanup", "#{resource_id}:cleanup")
        remaining = mount_entry_at(normalize_target(target))
        if remaining
          raise MountIdentityError, "cleanup umount2 reported success but #{target.inspect} remains mounted"
        end
        true
      rescue StandardError => error
        raise CleanupError.new(
          "mount cleanup failed for #{resource_id}: #{error.message}",
          resource_id: resource_id,
          details: {"cleanupErrors" => [{"class" => error.class.name, "message" => error.message.to_s}]},
          cleanup_errors: [error]
        ), cause: error
      end

      def resource_id_for(operation, target, volume_id)
        prefix = volume_id.nil? ? "volume" : "volume:#{volume_id}"
        "#{prefix}:#{operation}:#{target}"
      end
    end

    NativeMount = NativeMountAdapter unless const_defined?(:NativeMount, false)
  end
end
