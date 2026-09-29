# frozen_string_literal: true

# pivot_root(2), execveat(2), and mount-table readback used by the workload
# bootstrap.  These helpers only execute what the caller already decided;
# the ordering policy (private propagation -> rootfs construction ->
# pivot_root -> regular umount -> unreachability proof) lives in the
# SecurityAdapter, which cites spec/node/runtime.md §5.8.7.

require "fiddle"
require "rbconfig"
require_relative "error"
require_relative "mount"
require_relative "syscall"

module Rubernetes
  module Platform
    module Linux
      class PivotRoot
        class Unsupported < StandardError; end
        class Busy < StandardError; end

        # Values from include/uapi/linux/mount.h that Mount does not export.
        MS_NOATIME = 1 << 10
        MS_RELATIME = 1 << 21
        MS_STRICTATIME = 1 << 24
        MS_SLAVE = 1 << 19
        MS_SHARED = 1 << 20
        MS_UNBINDABLE = 1 << 17
        # Value from include/uapi/linux/fcntl.h.
        AT_EMPTY_PATH = 0x1000
        AT_FDCWD = -100

        # Syscall numbers from arch/x86/entry/syscalls/syscall_64.tbl and
        # include/uapi/asm-generic/unistd.h (arm64).
        SYSCALLS = {
          "x86_64" => {pivot_root: 155, execveat: 322},
          "aarch64" => {pivot_root: 41, execveat: 281}
        }.freeze

        Entry = Data.define(:id, :parent_id, :major_minor, :root, :mountpoint, :options, :filesystem, :source, :super_options, :index) do
          def to_h
            {
              "mount_id" => id, "parent_id" => parent_id, "major_minor" => major_minor, "root" => root,
              "mountpoint" => mountpoint, "options" => options, "filesystem" => filesystem,
              "source" => source, "super_options" => super_options
            }
          end
        end

        def self.architecture
          key = RbConfig::CONFIG.fetch("host_cpu").downcase
          return "x86_64" if %w[x86_64 amd64].include?(key)
          return "aarch64" if %w[aarch64 arm64].include?(key)

          raise Unsupported, "unsupported Linux architecture #{key.inspect}"
        end

        def initialize(architecture: self.class.architecture, mount: Mount.new)
          @numbers = SYSCALLS.fetch(String(architecture)) do
            raise Unsupported, "pivot_root/execveat numbers are unknown for #{architecture.inspect}"
          end
          @mount = mount
        end

        attr_reader :mount

        def pivot_root(new_root:, put_old:, resource_id: "pivot_root:#{new_root}")
          [new_root, put_old].each do |value|
            raise ArgumentError, "pivot_root paths must not contain NUL" if String(value).include?("\0")
          end
          result = Syscall.call(@numbers.fetch(:pivot_root), Fiddle::Pointer["#{new_root}\0"], Fiddle::Pointer["#{put_old}\0"])
          raise Linux::Error.new(errno: result.errno, operation: "pivot_root", resource_id: resource_id) if result.value == -1

          true
        end

        # execveat(2) with AT_EMPTY_PATH executes the already-verified
        # descriptor; the pathname cannot be swapped between verification and
        # exec.  This only returns on failure.
        def execveat(fd:, argv:, envp:, resource_id: "execveat")
          result = Syscall.call(@numbers.fetch(:execveat), Integer(fd), Fiddle::Pointer["\0"], argv, envp, AT_EMPTY_PATH)
          Linux::Error.new(errno: result.errno, operation: "execveat", resource_id: resource_id)
        end

        # execveat(2) by pathname for "#!" scripts: run through a descriptor the
        # interpreter would see /dev/fd/N as $0 (and ENOENT if the descriptor
        # were close-on-exec), while runc gives it the real path.  The pathname
        # is resolved inside the already pivoted rootfs.  Only returns on failure.
        def execveat_path(path:, argv:, envp:, resource_id: "execveat")
          result = Syscall.call(@numbers.fetch(:execveat), AT_FDCWD, Fiddle::Pointer["#{path}\0"], argv, envp, 0)
          Linux::Error.new(errno: result.errno, operation: "execveat", resource_id: resource_id)
        end

        # Parse /proc/<pid>/mountinfo (proc(5)).  Field 4 (mountpoint) is
        # octal-escaped for space, tab, newline, and backslash.
        def self.parse_mountinfo(contents)
          String(contents).each_line(chomp: true).each_with_index.filter_map do |line, index|
            next if line.strip.empty?

            before, after = line.split(" - ", 2)
            fields = before.to_s.split(" ")
            tail = after.to_s.split(" ", 3)
            next if fields.length < 6 || tail.length < 2

            Entry.new(
              id: Integer(fields.fetch(0)), parent_id: Integer(fields.fetch(1)), major_minor: fields.fetch(2),
              root: unescape(fields.fetch(3)), mountpoint: unescape(fields.fetch(4)), options: fields.fetch(5),
              filesystem: tail.fetch(0), source: unescape(tail.fetch(1)), super_options: tail.fetch(2, ""), index: index
            )
          end
        end

        def self.unescape(value)
          String(value).gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
        end

        ALREADY_UNMOUNTED_ERRNOS = [Errno::ENOENT::Errno, Errno::EINVAL::Errno, Errno::ENXIO::Errno].freeze

        ALREADY_UNMOUNTED_PATTERN = /no such file or directory|not mounted|invalid argument/i

        def already_unmounted?(error)
          errno = error.respond_to?(:errno) ? error.errno : nil
          return true if errno && ALREADY_UNMOUNTED_ERRNOS.include?(errno)

          ALREADY_UNMOUNTED_PATTERN.match?(error.message.to_s)
        end

        def read_mountinfo(path = "/proc/self/mountinfo")
          self.class.parse_mountinfo(File.binread(path))
        end

        # Detach the old root in one umount2(MNT_DETACH), as runc does, and
        # then prove it unreachable.  After pivot_root and chdir("/") a
        # detached tree can be reached only through an open descriptor, so
        # the proof is: none of the old root's mounts is still in this
        # namespace's mountinfo, and no descriptor this process holds lives
        # on one of them (fdinfo "mnt_id").  The per-mount umount of
        # #unmount_tree walked the node's whole mount table -- 950 umount2(2)
        # calls, six seconds of every container start on a busy node.
        def detach_tree(prefix, old_mount_ids:, mountinfo_path: "/proc/self/mountinfo", fdinfo_path: "/proc/self/fdinfo",
                        resource_id: "detach-tree:#{prefix}")
          normalized = String(prefix)
          @mount.unmount(target: normalized, flags: Mount::MNT_DETACH, resource_id: resource_id)
          current = read_mountinfo(mountinfo_path)
          remaining = current.select { |entry| entry.mountpoint == normalized || entry.mountpoint.start_with?("#{normalized}/") }
          raise Busy, "old root mounts remain after detach: #{remaining.map(&:mountpoint).join(", ")}" unless remaining.empty?

          # Mount ids are recycled: the node keeps unmounting while this
          # container is built, and a mount of the new root can be given the
          # id an old-root mount had when the id list was read.  An id that is
          # live in this namespace now is therefore not evidence of the old
          # root; only a descriptor on an id that is gone from the table is.
          live = current.to_h { |entry| [entry.id.to_s, true] }
          forbidden = old_mount_ids.map(&:to_s).reject { |id| live.key?(id) }.to_h { |id| [id, true] }
          holding = descriptors_on(forbidden, fdinfo_path)
          raise Busy, "descriptors still reach the detached old root: #{holding.join(", ")}" unless holding.empty?

          old_mount_ids
        end

        def descriptors_on(forbidden_ids, fdinfo_path)
          Dir.children(fdinfo_path).filter_map do |fd|
            info = begin
              File.read(File.join(fdinfo_path, fd))
            rescue Errno::ENOENT, Errno::EBADF
              next # the descriptor used to list the directory, already closed
            end
            mount_id = info[/^mnt_id:\s*(\d+)/, 1]
            fd if mount_id && forbidden_ids.key?(mount_id)
          end
        end

        # Regular (non-detaching) umount of every mount at or beneath
        # `prefix`.  Mounts are released in reverse post-order of the mount
        # tree: within a parent, the most recently attached child comes first,
        # because a later mount on the same mountpoint shadows an earlier one
        # and the shadowed pathname is unreachable until the cover is gone.
        # MNT_DETACH is deliberately not used: a lazily detached old root stays
        # reachable through open descriptors and would defeat the
        # unreachability proof required by §5.8.7.
        def unmount_tree(prefix, mountinfo_path: "/proc/self/mountinfo", resource_id: "umount-tree:#{prefix}")
          normalized = String(prefix)
          entries = read_mountinfo(mountinfo_path).select do |entry|
            entry.mountpoint == normalized || entry.mountpoint.start_with?("#{normalized}/")
          end
          by_id = entries.to_h { |entry| [entry.id, entry] }
          children = Hash.new { |hash, key| hash[key] = [] }
          entries.each { |entry| children[entry.parent_id] << entry if by_id.key?(entry.parent_id) }
          roots = entries.reject { |entry| by_id.key?(entry.parent_id) }
          released = []
          visit = lambda do |entry|
            children[entry.id].sort_by(&:index).reverse_each { |child| visit.call(child) }
            begin
              @mount.unmount(target: entry.mountpoint, flags: 0,
                             resource_id: "#{resource_id}:#{entry.id}:#{entry.filesystem}:#{entry.mountpoint}")
            rescue StandardError => error
              # A mount that is already gone by the time we get to it is one
              # fewer mount to release, not a failure.  The list was read from
              # /proc/self/mountinfo a moment ago and the rest of the node does
              # not stand still: another Pod starting or stopping unmounts its
              # own volumes in the same namespace, so an entry can disappear
              # between the read and the syscall.  The unreachability proof
              # below is what actually decides the outcome -- it re-reads
              # mountinfo and refuses to continue if anything REMAINS -- so
              # tolerating ENOENT here weakens nothing and stops a container
              # start from failing because of another container's teardown.
              raise unless already_unmounted?(error)
            end
            released << entry.id
          end
          roots.sort_by(&:index).reverse_each { |entry| visit.call(entry) }
          remaining = read_mountinfo(mountinfo_path).select do |entry|
            entry.mountpoint == normalized || entry.mountpoint.start_with?("#{normalized}/")
          end
          raise Busy, "mounts remained under #{normalized}: #{remaining.map(&:mountpoint).join(", ")}" unless remaining.empty?

          released
        end
      end
    end
  end
end
