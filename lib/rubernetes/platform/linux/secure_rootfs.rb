# frozen_string_literal: true

# Descriptor-relative rootfs mutations.  This boundary deliberately has no
# pathname fallback: a kernel without openat2(2), or a process without the
# required *at operations, must reject extraction rather than downgrade to a
# TOCTOU-prone implementation.

require "fiddle"
require_relative "error"
require_relative "xattr"
require_relative "openat2"

module Rubernetes
  module Platform
    module Linux
      class SecureRootfs
        class Error < StandardError
          attr_reader :cause, :errno

          def initialize(message, cause: nil)
            @cause = cause
            @errno = cause.errno if cause.respond_to?(:errno)
            super(message)
          end
        end

        class Unsupported < Error; end
        class UnsafePath < Error; end

        AT_REMOVEDIR = 0x200
        AT_EMPTY_PATH = 0x1000
        O_NOFOLLOW = 0x20000
        O_CLOEXEC = Openat2::O_CLOEXEC
        O_DIRECTORY = Openat2::O_DIRECTORY
        O_PATH = Openat2::O_PATH
        O_RDONLY = Openat2::O_RDONLY
        O_WRONLY = Openat2::O_WRONLY
        O_CREAT = Openat2::O_CREAT
        O_EXCL = Openat2::O_EXCL
        RESOLVE = Openat2::RESOLVE_BENEATH |
                  Openat2::RESOLVE_NO_SYMLINKS |
                  Openat2::RESOLVE_NO_MAGICLINKS |
                  Openat2::RESOLVE_NO_XDEV

        LIBC = Fiddle::Handle::DEFAULT
        OPENAT = Fiddle::Function.new(
          LIBC["openat"],
          [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_INT],
          Fiddle::TYPE_INT
        )
        MKDIRAT = Fiddle::Function.new(
          LIBC["mkdirat"],
          [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
          Fiddle::TYPE_INT
        )
        UNLINKAT = Fiddle::Function.new(
          LIBC["unlinkat"],
          [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
          Fiddle::TYPE_INT
        )
        LINKAT = Fiddle::Function.new(
          LIBC["linkat"],
          [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
          Fiddle::TYPE_INT
        )
        SYMLINKAT = Fiddle::Function.new(
          LIBC["symlinkat"],
          [Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP],
          Fiddle::TYPE_INT
        )
        RENAMEAT = Fiddle::Function.new(
          LIBC["renameat"],
          [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP],
          Fiddle::TYPE_INT
        )
        FCHMOD = Fiddle::Function.new(
          LIBC["fchmod"],
          [Fiddle::TYPE_INT, Fiddle::TYPE_INT],
          Fiddle::TYPE_INT
        )
        FCHOWN = Fiddle::Function.new(
          Fiddle::Handle::DEFAULT["fchown"], [Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_INT
        )
        FCHOWNAT = Fiddle::Function.new(
          Fiddle::Handle::DEFAULT["fchownat"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_INT,
                                                Fiddle::TYPE_INT], Fiddle::TYPE_INT
        )
        AT_SYMLINK_NOFOLLOW = 0x100

        Directory = Data.define(:fd, :relative, :owned) do
          def close
            return false unless owned

            IO.for_fd(fd).close
            true
          rescue IOError, SystemCallError
            false
          end
        end

        attr_reader :root

        def initialize(root:, openat2: nil, race_hook: nil)
          raise Unsupported, "secure rootfs mutations require Linux" unless RUBY_PLATFORM.include?("linux")

          @root = File.expand_path(String(root)).freeze
          @race_hook = race_hook
          @root_io = File.open(@root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
          @resolver = openat2 || Openat2.new(root: @root, root_fd: @root_io.fileno, strict: true)
          probe_openat2!
          @closed = false
        rescue SystemCallError => error
          @root_io&.close
          raise Unsupported.new("cannot open secure rootfs #{@root}: #{error.message}", cause: error), cause: error
        rescue Linux::Error => error
          @root_io&.close
          raise Unsupported.new("secure rootfs openat2 is unavailable: #{error.message}", cause: error), cause: error
        end

        def close
          return false if @closed

          @closed = true
          @resolver.close if @resolver.respond_to?(:close)
          @root_io&.close
          true
        rescue IOError, SystemCallError
          false
        end

        # sync: false leaves the data to writeback: an image layer is unpacked
        # into a private staging tree that is only published by rename once
        # complete, and nothing refers to it after a crash, so an fsync per
        # file bought nothing and was most of an unpack's wall time.
        # xattrs: {"security.capability" => bytes, "user.x" => bytes} applied with
        # fsetxattr on the open descriptor (file capabilities are how a non-root
        # image binary such as ingress-nginx binds port 80).
        def write_file(relative, mode: 0o600, sync: true, xattrs: nil, owner: nil)
          ensure_open!
          parent_relative, name = split_parent(relative)
          with_parent(parent_relative, operation: :write_file) do |parent|
            remove_at(parent.fd, name, relative)
            fd = call_openat(parent.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600,
                             operation: "openat", resource_id: "rootfs:file:#{relative}")
            io = IO.for_fd(fd)
            begin
              yield io
              io.flush
              # Order matters: a chown clears security.capability (as it clears
              # setuid), so ownership first, then xattrs, then the mode.
              call_fchown(fd, owner, "rootfs:file:#{relative}")
              (xattrs || {}).each { |key, value| Xattr.fset(fd, key, value, resource_id: "rootfs:file:#{relative}") }
              io.fsync if sync
              call_fchmod(fd, Integer(mode), "rootfs:file:#{relative}")
            ensure
              io.close unless io.closed?
            end
          end
        rescue Error
          raise
        rescue Linux::Error, SystemCallError => error
          raise Error.new("cannot create rootfs file #{relative.inspect}: #{error.message}", cause: error), cause: error
        end

        def create_directory(relative, mode: 0o700, owner: nil)
          ensure_open!
          parent_relative, name = split_parent(relative)
          with_parent(parent_relative, operation: :create_directory) do |parent|
            begin
              call_mkdirat(parent.fd, name, 0o700, "rootfs:directory:#{relative}")
            rescue Linux::Error => error
              raise unless error.errno == Errno::EEXIST::Errno

              existing_fd = nil
              begin
                existing_fd = call_openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0,
                                          operation: "openat", resource_id: "rootfs:directory:#{relative}")
                call_fchown(existing_fd, owner, "rootfs:directory:#{relative}")
                call_fchmod(existing_fd, Integer(mode), "rootfs:directory:#{relative}")
                next
              rescue Linux::Error => existing_error
                raise unless [Errno::ENOTDIR::Errno, Errno::ELOOP::Errno].include?(existing_error.errno)
              ensure
                IO.for_fd(existing_fd).close if existing_fd
              end
              remove_at(parent.fd, name, relative)
              call_mkdirat(parent.fd, name, 0o700, "rootfs:directory:#{relative}")
            end
            directory_fd = call_openat(parent.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0,
                                       operation: "openat", resource_id: "rootfs:directory:#{relative}")
            begin
              call_fchown(directory_fd, owner, "rootfs:directory:#{relative}")
              call_fchmod(directory_fd, Integer(mode), "rootfs:directory:#{relative}")
            ensure
              IO.for_fd(directory_fd).close
            end
          end
        rescue Error
          raise
        rescue Linux::Error, SystemCallError => error
          raise Error.new("cannot create rootfs directory #{relative.inspect}: #{error.message}", cause: error), cause: error
        end

        def create_symlink(relative, target, validation_path: nil, owner: nil)
          ensure_open!
          parent_relative, name = split_parent(relative)
          normalized_target = validation_path || target
          validate_symlink_target!(normalized_target)
          with_parent(parent_relative, operation: :create_symlink) do |parent|
            remove_at(parent.fd, name, relative)
            call_symlinkat(target.to_s.b, parent.fd, name, "rootfs:symlink:#{relative}")
            call_fchownat_nofollow(parent.fd, name, owner, "rootfs:symlink:#{relative}")
          end
        rescue Error
          raise
        rescue Linux::Error, SystemCallError => error
          raise Error.new("cannot create rootfs symlink #{relative.inspect}: #{error.message}", cause: error), cause: error
        end

        def create_hardlink(relative, target)
          ensure_open!
          destination_parent_relative, destination_name = split_parent(relative)
          destination_parent = nil
          begin
            target_handle = openat2_target(target)
            target_stat = stat_handle(target_handle)
            raise UnsafePath, "hardlink target must be a regular file" unless target_stat.file? && !target_stat.symlink?

            destination_parent = parent_directory(destination_parent_relative, operation: :create_hardlink)
            remove_at(destination_parent.fd, destination_name, relative)
            # Link the already-open target descriptor. Re-resolving
            # target_parent/target_name here would reintroduce a replacement
            # race between the regular-file check and link creation.
            call_linkat(target_handle.fd, "", destination_parent.fd, destination_name,
                        "rootfs:hardlink:#{relative}", flags: AT_EMPTY_PATH)
          ensure
            target_handle&.close
            destination_parent&.close
          end
        rescue Errno::ENOENT => error
          raise UnsafePath.new("hardlink target does not exist", cause: error), cause: error
        rescue Error
          raise
        rescue Linux::Error, SystemCallError => error
          raise Error.new("cannot create rootfs hardlink #{relative.inspect}: #{error.message}", cause: error), cause: error
        end

        def remove(relative, expected_identity: nil)
          ensure_open!
          raise UnsafePath, "refusing to remove the secure root itself" if relative.to_s.empty?

          parent_relative, name = split_parent(relative)
          with_parent(parent_relative, operation: :remove) do |parent|
            if expected_identity && identity_at(parent.fd, name, relative) != expected_identity
              raise UnsafePath, "rootfs entry identity changed before removal"
            end

            remove_at(parent.fd, name, relative)
          end
        rescue Linux::Error => error
          return false if error.errno == Errno::ENOENT::Errno

          raise Error.new("cannot remove rootfs entry #{relative.inspect}: #{error.message}", cause: error), cause: error
        rescue Errno::ENOENT
          false
        end

        def clear_directory(relative)
          ensure_open!
          directory = open_directory(relative)
          @race_hook&.call(operation: :clear_directory, relative: relative.to_s, fd: directory.fd)
          stream = Dir.for_fd(directory.fd)
          begin
            stream.each_child do |child|
              remove_at(directory.fd, child, join_relative(relative, child))
            end
          ensure
            stream.close
            directory.close
          end
          true
        rescue Linux::Error => error
          return false if error.errno == Errno::ENOENT::Errno

          raise Error.new("cannot clear rootfs directory #{relative.inspect}: #{error.message}", cause: error), cause: error
        rescue SystemCallError => error
          return false if error.is_a?(Errno::ENOENT)

          raise Error.new("cannot clear rootfs directory #{relative.inspect}: #{error.message}", cause: error), cause: error
        end

        def link(old_relative, new_relative)
          create_hardlink(new_relative, old_relative)
        end

        def symlink(target, new_relative, validation_path: nil)
          create_symlink(new_relative, target, validation_path: validation_path)
        end

        def rename(old_relative, new_relative)
          ensure_open!
          old_parent_relative, old_name = split_parent(old_relative)
          new_parent_relative, new_name = split_parent(new_relative)
          old_parent = open_directory(old_parent_relative)
          new_parent = nil
          begin
            new_parent = parent_directory(new_parent_relative, operation: :rename)
            call_renameat(old_parent.fd, old_name, new_parent.fd, new_name, "rootfs:rename:#{old_relative}")
          ensure
            new_parent&.close
            old_parent&.close
          end
          true
        rescue Error
          raise
        rescue Linux::Error, SystemCallError => error
          raise Error.new("cannot rename rootfs entry: #{error.message}", cause: error), cause: error
        end

        def identity(relative)
          handle = openat2_target(relative)
          stat_identity(handle)
        rescue Linux::Error => error
          return nil if error.errno == Errno::ENOENT::Errno

          raise Error.new("cannot stat rootfs entry #{relative.inspect}: #{error.message}", cause: error), cause: error
        ensure
          handle&.close
        end

        private

        def probe_openat2!
          handle = @resolver.open(".", flags: O_PATH | O_DIRECTORY | O_CLOEXEC, resolve: RESOLVE,
                                       resource_id: "rootfs:openat2-probe")
          handle.close
        rescue Openat2::Unsupported, Openat2::UnsafePath, Linux::Error => error
          raise Unsupported.new("openat2 rootfs resolution is unavailable: #{error.message}", cause: error), cause: error
        end

        def ensure_open!
          raise Unsupported, "secure rootfs descriptor is closed" if @closed
        end

        def open_directory(relative)
          value = validate_relative(relative)
          return Directory.new(fd: @root_io.fileno, relative: "", owned: false) if value.empty?

          handle = @resolver.open(value, flags: O_RDONLY | O_DIRECTORY | O_CLOEXEC, resolve: RESOLVE,
                                         resource_id: "rootfs:directory:#{value}")
          Directory.new(fd: handle.fd, relative: value.freeze, owned: true)
        rescue Openat2::UnsafePath => error
          raise UnsafePath.new(error.message, cause: error), cause: error
        end

        def ensure_directory(relative)
          value = validate_relative(relative)
          return open_directory(value) if value.empty?

          current = open_directory("")
          prefix = []
          value.split("/").each do |component|
            prefix << component
            candidate = prefix.join("/")
            next_directory = begin
              open_directory(candidate)
            rescue Linux::Error => error
              raise unless error.errno == Errno::ENOENT::Errno

              call_mkdirat(current.fd, component, 0o700, "rootfs:mkdir:#{candidate}")
              open_directory(candidate)
            end
            current.close
            current = next_directory
          end
          current
        rescue Error
          current&.close
          raise
        rescue Linux::Error, SystemCallError => error
          current&.close
          raise Error.new("cannot prepare rootfs parent #{relative.inspect}: #{error.message}", cause: error), cause: error
        end

        def parent_directory(relative, operation:)
          directory = ensure_directory(relative)
          @race_hook&.call(operation: operation, relative: relative.to_s, fd: directory.fd)
          directory
        end

        def with_parent(relative, operation:)
          directory = parent_directory(relative, operation: operation)
          begin
            yield directory
          ensure
            directory.close
          end
        end

        def openat2_target(relative)
          value = validate_relative(relative)
          raise UnsafePath, "rootfs target must not be the root" if value.empty?

          @resolver.open(value, flags: O_PATH | O_CLOEXEC, resolve: RESOLVE,
                                resource_id: "rootfs:target:#{value}")
        rescue Openat2::UnsafePath => error
          raise UnsafePath.new(error.message, cause: error), cause: error
        end

        # Containment of a symlink is decided lexically (validate_relative:
        # relative, no traversal, no NUL).  It deliberately does NOT resolve the
        # target: during layer extraction the target routinely does not exist
        # yet, and its own parent is often itself a not-yet-created symlink
        # ("etc/alternatives/pager" -> "/bin/more" while "bin" -> "usr/bin").
        # Resolution-time containment is what actually protects the rootfs, and
        # that is enforced by openat2 with RESOLVE_IN_ROOT whenever the link is
        # followed -- long after this call.
        def validate_symlink_target!(relative)
          validate_relative(relative)
          nil
        end

        def remove_at(parent_fd, name, relative)
          target = nil
          directory = nil
          stream = nil
          begin
            target = call_openat(parent_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC, 0,
                                 operation: "openat", resource_id: "rootfs:remove-target:#{relative}")
            target_stat = stat_handle(Directory.new(fd: target, relative: relative, owned: false))
            target_identity = [target_stat.dev, target_stat.ino, target_stat.mode].freeze
            unless target_stat.directory?
              @race_hook&.call(operation: :remove_before_unlink, relative: relative.to_s, fd: target)
              raise UnsafePath, "rootfs entry identity changed before unlink" if identity_at(parent_fd, name, relative) != target_identity

              call_unlinkat(parent_fd, name, 0, "rootfs:unlink:#{relative}")
              return true
            end

            directory = call_openat(parent_fd, name,
                                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0,
                                    operation: "openat", resource_id: "rootfs:remove:#{relative}")
            directory_identity = stat_identity(Directory.new(fd: directory, relative: relative, owned: false))
            raise UnsafePath, "rootfs directory identity changed while opening" unless directory_identity == target_identity

            # Re-resolve the complete path from the fixed root fd. This rejects
            # a mount replacement before descriptor-relative recursion begins.
            verified = @resolver.open(validate_relative(relative),
                                      flags: O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                                      resolve: RESOLVE,
                                      resource_id: "rootfs:remove-verify:#{relative}")
            begin
              raise UnsafePath, "rootfs directory identity changed before removal" unless stat_identity(verified) == directory_identity
            ensure
              verified.close
            end
            stream = Dir.for_fd(directory)
            stream.each_child do |child|
              remove_at(directory, child, join_relative(relative, child))
            end
            @race_hook&.call(operation: :remove_before_rmdir, relative: relative.to_s, fd: directory)
            if identity_at(parent_fd, name, relative) != directory_identity
              raise UnsafePath, "rootfs directory identity changed before rmdir"
            end

            call_unlinkat(parent_fd, name, AT_REMOVEDIR, "rootfs:rmdir:#{relative}")
          rescue Linux::Error => error
            raise unless error.errno == Errno::ENOENT::Errno
          ensure
            stream&.close
            if directory
              begin
                IO.for_fd(directory).close
              rescue IOError, SystemCallError
                nil
              end
            end
            if target
              begin
                IO.for_fd(target).close
              rescue IOError, SystemCallError
                nil
              end
            end
          end
          true
        rescue Linux::Error => error
          return false if error.errno == Errno::ENOENT::Errno

          raise
        end

        def identity_at(parent_fd, name, relative)
          fd = call_openat(parent_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC, 0,
                           operation: "openat", resource_id: "rootfs:identity:#{relative}")
          begin
            stat_identity(Directory.new(fd: fd, relative: relative, owned: false))
          ensure
            IO.for_fd(fd).close
          end
        rescue Linux::Error => error
          return nil if error.errno == Errno::ENOENT::Errno

          raise
        end

        def stat_handle(handle)
          IO.for_fd(handle.fd, autoclose: false).stat
        rescue SystemCallError, TypeError => error
          raise Error.new("cannot inspect secure rootfs descriptor: #{error.message}", cause: error), cause: error
        end

        def stat_identity(handle)
          stat = stat_handle(handle)
          [stat.dev, stat.ino, stat.mode].freeze
        end

        def split_parent(relative)
          value = validate_relative(relative)
          parts = value.split("/")
          [parts[0...-1].join("/"), parts.last]
        end

        def validate_relative(relative)
          value = String(relative)
          raise UnsafePath, "rootfs path contains NUL" if value.include?("\0")
          raise UnsafePath, "rootfs path must be relative" if value.start_with?("/")
          raise UnsafePath, "rootfs path must not be empty" if value.empty? && relative.to_s != ""

          return "" if value.empty?

          components = value.split("/")
          raise UnsafePath, "rootfs path contains an empty component" if components.any?(&:empty?)
          raise UnsafePath, "rootfs path contains traversal" if components.any? { |component| [".", ".."].include?(component) }

          value
        rescue TypeError => error
          raise UnsafePath.new("rootfs path is not a string: #{error.message}", cause: error), cause: error
        end

        def join_relative(parent, child)
          parent.to_s.empty? ? child.to_s : "#{parent}/#{child}"
        end

        def call_openat(parent_fd, name, flags, mode, operation:, resource_id:)
          pointer = c_string(name)
          call_native(OPENAT, [Integer(parent_fd), pointer, Integer(flags), Integer(mode)], operation, resource_id)
        end

        def call_mkdirat(parent_fd, name, mode, resource_id)
          pointer = c_string(name)
          call_native(MKDIRAT, [Integer(parent_fd), pointer, Integer(mode)], "mkdirat", resource_id)
        end

        def call_unlinkat(parent_fd, name, flags, resource_id)
          pointer = c_string(name)
          call_native(UNLINKAT, [Integer(parent_fd), pointer, Integer(flags)], "unlinkat", resource_id)
        end

        def call_linkat(old_fd, old_name, new_fd, new_name, resource_id, flags: 0)
          old_pointer = c_string(old_name)
          new_pointer = c_string(new_name)
          call_native(LINKAT, [Integer(old_fd), old_pointer, Integer(new_fd), new_pointer, Integer(flags)], "linkat", resource_id)
        end

        def call_symlinkat(target, new_fd, new_name, resource_id)
          target_pointer = c_string(target)
          new_pointer = c_string(new_name)
          call_native(SYMLINKAT, [target_pointer, Integer(new_fd), new_pointer], "symlinkat", resource_id)
        end

        def call_renameat(old_fd, old_name, new_fd, new_name, resource_id)
          old_pointer = c_string(old_name)
          new_pointer = c_string(new_name)
          call_native(RENAMEAT, [Integer(old_fd), old_pointer, Integer(new_fd), new_pointer], "renameat", resource_id)
        end

        def call_fchmod(fd, mode, resource_id)
          call_native(FCHMOD, [Integer(fd), Integer(mode)], "fchmod", resource_id)
        end

        # owner: [uid, gid] from the layer tar; applied only when this process can
        # (root), exactly like containerd's extraction.  Ownership is set before
        # the mode so a setuid/setgid bit is not cleared by the chown.
        def call_fchown(fd, owner, resource_id)
          return unless owner && Process.euid.zero?

          call_native(FCHOWN, [Integer(fd), Integer(owner[0]), Integer(owner[1])], "fchown", resource_id)
        end

        def call_fchownat_nofollow(parent_fd, name, owner, resource_id)
          return unless owner && Process.euid.zero?

          call_native(FCHOWNAT, [Integer(parent_fd), c_string(name), Integer(owner[0]), Integer(owner[1]), AT_SYMLINK_NOFOLLOW],
                      "fchownat", resource_id)
        end

        def call_native(function, arguments, operation, resource_id)
          result = function.call(*arguments)
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: operation, resource_id: resource_id) if result == -1

          result
        end

        def c_string(value)
          text = String(value)
          raise UnsafePath, "rootfs component contains NUL" if text.include?("\0")

          Fiddle::Pointer["#{text}\0"]
        end
      end
    end
  end
end
