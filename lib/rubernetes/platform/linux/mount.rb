# frozen_string_literal: true

require "fiddle"
require "rbconfig"
require_relative "error"
require_relative "syscall"

module Rubernetes
  module Platform
    module Linux
      class Mount
        # Values come from include/uapi/linux/mount.h and sys/mount.h.
        MS_RDONLY = 1
        MS_NOSUID = 2
        MS_NODEV = 4
        MS_NOEXEC = 8
        MS_REMOUNT = 32
        MS_BIND = 4_096
        MS_PRIVATE = 1 << 18
        MS_SLAVE = 1 << 19
        MS_SHARED = 1 << 20
        MS_REC = 16_384
        MNT_DETACH = 2

        # New mount API (include/uapi/linux/mount.h, Linux >= 5.2 for
        # open_tree/move_mount, >= 5.12 for mount_setattr).
        OPEN_TREE_CLONE = 1
        # OPEN_TREE_CLOEXEC is defined as O_CLOEXEC (include/uapi/asm-generic/fcntl.h).
        OPEN_TREE_CLOEXEC = 0x80000
        MOVE_MOUNT_F_SYMLINKS = 0x00000001
        MOVE_MOUNT_F_AUTOMOUNTS = 0x00000002
        MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
        MOVE_MOUNT_T_SYMLINKS = 0x00000010
        MOVE_MOUNT_T_AUTOMOUNTS = 0x00000020
        MOVE_MOUNT_T_EMPTY_PATH = 0x00000040
        MOVE_MOUNT_SET_GROUP = 0x00000100
        MOVE_MOUNT_BENEATH = 0x00000200
        MOUNT_ATTR_RDONLY = 0x00000001
        MOUNT_ATTR_NOSUID = 0x00000002
        MOUNT_ATTR_NODEV = 0x00000004
        MOUNT_ATTR_NOEXEC = 0x00000008
        MOUNT_ATTR_NOSYMFOLLOW = 0x00200000
        # struct mount_attr { __u64 attr_set; __u64 attr_clr; __u64 propagation; __u64 userns_fd; }
        # MOUNT_ATTR_SIZE_VER0 (include/uapi/linux/mount.h).
        MOUNT_ATTR_SIZE_VER0 = 32
        # include/uapi/linux/fcntl.h
        AT_FDCWD = -100
        AT_EMPTY_PATH = 0x1000
        AT_RECURSIVE = 0x8000
        # arch/x86/entry/syscalls/syscall_64.tbl and arch/arm64 (asm-generic/unistd.h)
        # share these numbers for the new mount API.
        SYS_OPEN_TREE = {"x86_64" => 428, "amd64" => 428, "aarch64" => 428, "arm64" => 428}.freeze
        SYS_MOVE_MOUNT = {"x86_64" => 429, "amd64" => 429, "aarch64" => 429, "arm64" => 429}.freeze
        SYS_MOUNT_SETATTR = {"x86_64" => 442, "amd64" => 442, "aarch64" => 442, "arm64" => 442}.freeze

        LIBC = Fiddle::Handle::DEFAULT
        MOUNT = Fiddle::Function.new(
          LIBC["mount"],
          [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_ULONG, Fiddle::TYPE_VOIDP],
          Fiddle::TYPE_INT
        )
        UMOUNT2 = Fiddle::Function.new(
          LIBC["umount2"],
          [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
          Fiddle::TYPE_INT
        )

        def mount(source:, target:, filesystem:, flags: 0, data: nil, resource_id: "mount:#{target}")
          strings = [source, target, filesystem, data].map { |value| value.nil? ? nil : "#{value}\0" }
          pointers = strings.map { |value| value.nil? ? 0 : Fiddle::Pointer[value] }
          result = MOUNT.call(*pointers.take(3), Integer(flags), pointers.fetch(3))
          # R-1.2: libc mount exposes its failure only through errno.
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "mount", resource_id: resource_id) if result == -1

          true
        end

        def unmount(target:, flags: 0, resource_id: "mount:#{target}")
          target_string = "#{target}\0"
          result = UMOUNT2.call(Fiddle::Pointer[target_string], Integer(flags))
          # R-1.2: capture before exception formatting or cleanup.
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "umount2", resource_id: resource_id) if result == -1

          true
        end

        # open_tree(2): obtain a detached copy of the mount tree rooted at the
        # descriptor.  The result is a file descriptor that no pathname can
        # reach, so nothing racing on the filesystem can redirect it before
        # move_mount(2) attaches it.
        def open_tree(dirfd:, path: "", flags: OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH, resource_id: "open_tree:#{dirfd}")
          number = SYS_OPEN_TREE.fetch(RbConfig::CONFIG.fetch("host_cpu"))
          result = Syscall.call(number, Integer(dirfd), Fiddle::Pointer["#{path}\0"], Integer(flags))
          raise Linux::Error.new(errno: result.errno, operation: "open_tree", resource_id: resource_id) if result.value == -1

          Integer(result.value)
        end

        # move_mount(2): attach a detached tree (or move an attached one) onto
        # the target descriptor.  Both ends are descriptors so the attach is
        # bound to the inodes the caller already verified.
        def move_mount(from_dirfd:, to_dirfd:, from_path: "", to_path: "",
                       flags: MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH, resource_id: "move_mount:#{to_dirfd}")
          number = SYS_MOVE_MOUNT.fetch(RbConfig::CONFIG.fetch("host_cpu"))
          result = Syscall.call(number, Integer(from_dirfd), Fiddle::Pointer["#{from_path}\0"],
                                Integer(to_dirfd), Fiddle::Pointer["#{to_path}\0"], Integer(flags))
          raise Linux::Error.new(errno: result.errno, operation: "move_mount", resource_id: resource_id) if result.value == -1

          true
        end

        # mount_setattr(2) on a detached tree.  Setting read-only/nosuid/nodev
        # before move_mount(2) means the target is never observable in a
        # writable state, unlike the mount(2) bind + MS_REMOUNT sequence.
        def mount_setattr(dirfd:, attr_set:, attr_clr: 0, path: "", flags: AT_EMPTY_PATH, propagation: 0,
                          resource_id: "mount_setattr:#{dirfd}")
          number = SYS_MOUNT_SETATTR.fetch(RbConfig::CONFIG.fetch("host_cpu"))
          attributes = [Integer(attr_set), Integer(attr_clr), Integer(propagation), 0].pack("Q<4")
          raise ArgumentError, "struct mount_attr must be #{MOUNT_ATTR_SIZE_VER0} bytes" unless attributes.bytesize == MOUNT_ATTR_SIZE_VER0

          result = Syscall.call(number, Integer(dirfd), Fiddle::Pointer["#{path}\0"], Integer(flags),
                                Fiddle::Pointer[attributes], MOUNT_ATTR_SIZE_VER0)
          raise Linux::Error.new(errno: result.errno, operation: "mount_setattr", resource_id: resource_id) if result.value == -1

          true
        end

        # Descriptor-anchored bind: clone the source tree, apply the final
        # attributes to the detached copy, then attach it to the target
        # descriptor.  Order matters (R-1.6): attributes are applied while the
        # tree is unreachable, so a reader never observes the bind before its
        # read-only/nosuid/nodev state is final.  The detached descriptor is
        # closed on every path; an unattached clone disappears with its fd.
        def bind_tree(source_fd:, target_fd:, readonly: false, nosuid: false, nodev: false, noexec: false,
                      recursive: false, resource_id: "bind_tree:#{target_fd}")
          open_flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH
          open_flags |= AT_RECURSIVE if recursive
          tree_fd = open_tree(dirfd: source_fd, flags: open_flags, resource_id: "#{resource_id}:open_tree")
          begin
            attributes = 0
            attributes |= MOUNT_ATTR_RDONLY if readonly
            attributes |= MOUNT_ATTR_NOSUID if nosuid
            attributes |= MOUNT_ATTR_NODEV if nodev
            attributes |= MOUNT_ATTR_NOEXEC if noexec
            unless attributes.zero?
              setattr_flags = AT_EMPTY_PATH
              setattr_flags |= AT_RECURSIVE if recursive
              mount_setattr(dirfd: tree_fd, attr_set: attributes, flags: setattr_flags,
                            resource_id: "#{resource_id}:mount_setattr")
            end
            move_mount(from_dirfd: tree_fd, to_dirfd: target_fd, resource_id: "#{resource_id}:move_mount")
          ensure
            close_descriptor(tree_fd)
          end
          true
        end

        def remount_proc(target: "/proc", resource_id: "mount:proc:#{target}")
          mount(
            source: "proc",
            target: target,
            filesystem: "proc",
            flags: MS_NOSUID | MS_NODEV | MS_NOEXEC,
            resource_id: resource_id
          )
        end

        def make_private(target: "/", recursive: true, resource_id: "mount-propagation:#{target}")
          set_propagation(target: target, propagation: MS_PRIVATE, recursive: recursive, resource_id: resource_id)
        end

        # Slave propagation: mounts made by the peer group (the host) keep
        # arriving here, nothing made here leaves.  This is runc's default for
        # a container root and what a HostToContainer volume mount needs.
        def make_slave(target: "/", recursive: true, resource_id: "mount-propagation:#{target}")
          set_propagation(target: target, propagation: MS_SLAVE, recursive: recursive, resource_id: resource_id)
        end

        def make_shared(target:, recursive: true, resource_id: "mount-propagation:#{target}")
          set_propagation(target: target, propagation: MS_SHARED, recursive: recursive, resource_id: resource_id)
        end

        # True when this process still shares PID 1's mount namespace.
        def initial_mount_namespace?
          File.readlink("/proc/self/ns/mnt") == File.readlink("/proc/1/ns/mnt")
        rescue SystemCallError
          false
        end

        # Make +target+ the root of a shared mount (a bind of itself when it
        # is not a mount point yet), so mounts made beneath it later propagate
        # into every mount namespace holding a slave copy -- what containerd
        # relies on from a systemd host whose "/" is shared, established here
        # for one directory because "/" may well be private.  Idempotent:
        # returns true when it changed anything.
        def ensure_shared_self_bind(target:, resource_id: "shared-root:#{target}")
          path = File.expand_path(String(target))
          entry = mountinfo_entry(path)
          changed = false
          if entry.nil?
            mount(source: path, target: path, filesystem: nil, flags: MS_BIND, resource_id: "#{resource_id}:bind")
            entry = mountinfo_entry(path)
            raise Linux::Error.new(errno: Errno::ENOENT::Errno, operation: "mount", resource_id: resource_id) if entry.nil?

            changed = true
          end
          unless entry.any? { |field| field.start_with?("shared:") }
            make_shared(target: path, recursive: false, resource_id: "#{resource_id}:shared")
            changed = true
          end
          changed
        end

        # The optional fields ("shared:N", "master:N", ...) of the newest
        # mountinfo entry whose mount point is +path+, or nil.
        def mountinfo_entry(path, mountinfo: "/proc/self/mountinfo")
          found = nil
          File.foreach(mountinfo) do |line|
            fields = line.split
            mount_point = fields[4].to_s.gsub(/\\(\d{3})/) { Regexp.last_match(1).to_i(8).chr }
            next unless mount_point == path

            found = fields.drop(6).take_while { |field| field != "-" }
          end
          found
        end

        def set_propagation(target:, propagation:, recursive: true, resource_id: "mount-propagation:#{target}")
          unless [MS_PRIVATE, MS_SLAVE, MS_SHARED].include?(Integer(propagation))
            raise ArgumentError, "mount propagation must be MS_PRIVATE, MS_SLAVE, or MS_SHARED"
          end
          # A recursive private/slave on "/" is what a holder or workload does
          # in ITS OWN namespace.  Done in the initial namespace it rewrites
          # the host's peer groups: the shared Pod root the agents rely on
          # (and, on a systemd host, everything containerd and docker rely
          # on) silently turns private.  A process that has not unshared its
          # mount namespace never has a legitimate reason to do this.
          if recursive && Integer(propagation) != MS_SHARED && File.expand_path(String(target)) == "/" && initial_mount_namespace?
            raise Linux::Error.new(errno: Errno::EPERM::Errno,
                                   operation: "mount(#{propagation == MS_PRIVATE ? "MS_PRIVATE" : "MS_SLAVE"}|MS_REC, \"/\") in the initial mount namespace",
                                   resource_id: resource_id)
          end

          flags = Integer(propagation)
          flags |= MS_REC if recursive
          mount(
            source: nil,
            target: target,
            filesystem: nil,
            flags: flags,
            resource_id: resource_id
          )
        end

        private

        def close_descriptor(fd)
          IO.for_fd(Integer(fd)).close
        rescue IOError, SystemCallError => error
          # A close(2) failure on a detached tree descriptor is a leak of a
          # kernel object, not something a caller can compensate; surface it.
          raise Linux::Error.new(errno: error.respond_to?(:errno) && error.errno ? error.errno : Errno::EBADF::Errno,
                                 operation: "close", resource_id: "open_tree:#{fd}")
        end
      end
    end
  end
end
