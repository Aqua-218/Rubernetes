# frozen_string_literal: true

# Safe, descriptor-relative path resolution for rootfs and volume operations.
# The resolver never falls back to pathname checks when openat2 is unavailable:
# callers receive a fail-closed error instead of a TOCTOU-prone open.

require "fiddle"
require "rbconfig"
require_relative "error"
require_relative "syscall"

module Rubernetes
  module Platform
    module Linux
      class Openat2
        class Error < StandardError; end
        class UnsafePath < Error; end
        class Unsupported < Error; end

        # Values from include/uapi/linux/openat2.h and fcntl.h.
        RESOLVE_NO_XDEV = 0x01
        RESOLVE_NO_MAGICLINKS = 0x02
        RESOLVE_NO_SYMLINKS = 0x04
        RESOLVE_BENEATH = 0x08
        RESOLVE_IN_ROOT = 0x10
        RESOLVE_CACHED = 0x20
        O_RDONLY = 0
        O_WRONLY = 1
        O_RDWR = 2
        O_CREAT = 0x40
        O_EXCL = 0x80
        O_PATH = 0x200000
        O_CLOEXEC = 0x80000
        O_DIRECTORY = 0x10000
        O_NOFOLLOW = 0x20000
        DEFAULT_RESOLVE = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
        # A target lease is allowed to resolve the final path component across
        # an existing mount. The parent descriptor, beneath and no-symlink
        # constraints still keep the lookup anchored to the authorized tree.
        TARGET_RESOLVE = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS
        SYS_OPENAT2 = {"x86_64" => 437, "amd64" => 437, "aarch64" => 437, "arm64" => 437}.freeze
        OPEN_HOW_SIZE = 24

        OpenHow = Data.define(:flags, :mode, :resolve) do
          def to_binary
            [Integer(flags), Integer(mode), Integer(resolve)].pack("Q<3")
          end
        end
        Handle = Data.define(:fd, :path, :root, :flags) do
          def close
            IO.for_fd(fd).close
          end

          def to_i
            fd
          end
        end

        class SystemAdapter
          def initialize(syscall: Syscall)
            @syscall = syscall
          end

          def openat2(dirfd:, path:, how:, resource_id:)
            path_pointer = Fiddle::Pointer["#{path}\0"]
            how_pointer = Fiddle::Pointer[how.to_binary]
            number = SYS_OPENAT2.fetch(RbConfig::CONFIG.fetch("host_cpu"))
            result = @syscall.call(number, Integer(dirfd), path_pointer, how_pointer, OPEN_HOW_SIZE)
            raise Linux::Error.new(errno: result.errno, operation: "openat2", resource_id: resource_id) if result.value == -1

            Integer(result.value)
          end
        end

        def initialize(root:, adapter: SystemAdapter.new, root_fd: nil, strict: true)
          @root = File.expand_path(String(root))
          @adapter = adapter
          @root_fd = root_fd
          @strict = strict == true
          @opened_root = nil
          @mutex = Mutex.new
        end

        attr_reader :root

        def validate!(path)
          value = String(path)
          raise UnsafePath, "path must not contain NUL" if value.include?("\0")
          raise UnsafePath, "path must be relative to the configured root" if value.start_with?("/")
          raise UnsafePath, "path must not be empty" if value.empty?

          components = value.split("/")
          raise UnsafePath, "path contains a parent traversal component" if components.include?("..")
          raise UnsafePath, "path contains an empty component" if components.any?(&:empty?)
          raise UnsafePath, "path contains an invalid component" if components.any? do |component|
            component == "." && component != components.first
          end

          value
        end

        def open(path, flags: O_RDONLY, mode: 0, resolve: DEFAULT_RESOLVE, resource_id: nil)
          relative = validate!(path)
          root_fd = descriptor
          how = OpenHow.new(flags: Integer(flags) | O_CLOEXEC, mode: Integer(mode), resolve: Integer(resolve))
          validate_resolve!(how.resolve)

          fd = call_openat2(root_fd, relative, how, resource_id || "openat2:#{relative}")
          Handle.new(fd: fd, path: relative.freeze, root: @root.freeze, flags: how.flags)
        rescue ArgumentError, TypeError
          raise UnsafePath, "openat2 flags, mode, and resolve must be integers"
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "openat2", resource_id: resource_id || "openat2:#{relative}"), cause: error
        end

        # Resolve a leaf relative to an already-held directory descriptor.
        # This is intentionally a separate operation from #open: re-resolving
        # the user's absolute path after the parent descriptor is held would
        # reintroduce a rename/replace race between validation and dispatch.
        def open_relative(parent:, path:, flags: O_RDONLY, mode: 0, resolve: DEFAULT_RESOLVE, resource_id: nil)
          relative = validate!(path)
          parent_fd = descriptor_for(parent)
          how = OpenHow.new(flags: Integer(flags) | O_CLOEXEC, mode: Integer(mode), resolve: Integer(resolve))
          validate_resolve!(how.resolve, allow_mount_crossing: how.resolve.nobits?(RESOLVE_NO_XDEV))

          fd = call_openat2(parent_fd, relative, how, resource_id || "openat2-relative:#{relative}")
          Handle.new(fd: fd, path: relative.freeze, root: @root.freeze, flags: how.flags)
        rescue ArgumentError, TypeError
          raise UnsafePath, "openat2 flags, mode, and resolve must be integers"
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "openat2-relative",
                                         resource_id: resource_id || "openat2-relative:#{relative}"), cause: error
        end

        alias open_file open
        alias resolve open
        alias resolve_path open

        def with_open(path, **)
          handle = open(path, **)
          yield handle
        ensure
          handle&.close
        end

        def close
          @mutex.synchronize do
            @opened_root&.close
            @opened_root = nil
          end
          true
        end

        private

        # Either containment is acceptable, and nothing weaker is.
        #
        # RESOLVE_NO_SYMLINKS refuses a symlink outright.  RESOLVE_IN_ROOT
        # follows it but treats the directory descriptor as "/", so an absolute
        # target, a "..", and a symlink chain all get clamped to that directory
        # and cannot escape it -- openat2(2) calls it "chroot-like".  The
        # second is what a subPath into an atomic-writer volume needs, because
        # configMap, secret, downwardAPI and projected volumes publish every
        # entry as a symlink into "..data/": refusing symlinks there refuses
        # the whole volume.  Magic links and mount crossing stay forbidden
        # either way.
        IN_ROOT_RESOLVE = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV

        def validate_resolve!(resolve, allow_mount_crossing: false)
          value = Integer(resolve)
          required = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
          required = TARGET_RESOLVE if allow_mount_crossing
          return true if value.allbits?(required)

          in_root = allow_mount_crossing ? (RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS) : IN_ROOT_RESOLVE
          return true if value.allbits?(in_root)

          raise UnsafePath,
                "openat2 requires RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS, and RESOLVE_NO_XDEV " \
                "(or RESOLVE_IN_ROOT with RESOLVE_NO_MAGICLINKS and RESOLVE_NO_XDEV)"
        rescue ArgumentError, TypeError
          raise UnsafePath, "openat2 flags, mode, and resolve must be integers"
        end

        def descriptor_for(value)
          candidate = value.respond_to?(:fd) ? value.fd : value
          return candidate.fileno if candidate.respond_to?(:fileno)
          return Integer(candidate) if candidate.is_a?(Integer)

          raise UnsafePath, "openat2 parent did not expose a directory descriptor"
        rescue ArgumentError, TypeError
          raise UnsafePath, "openat2 parent did not expose a directory descriptor"
        end

        def descriptor
          return Integer(@root_fd) if @root_fd
          return @opened_root.fileno if @opened_root

          @mutex.synchronize do
            @opened_root ||= File.open(@root, File::RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            @opened_root.fileno
          end
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "open(root)", resource_id: "openat2-root:#{@root}"), cause: error if @strict

          raise Unsupported, "configured root #{@root} cannot be opened securely: #{error.message}"
        end

        def call_openat2(root_fd, relative, how, resource_id)
          if @adapter.respond_to?(:openat2)
            value = @adapter.openat2(dirfd: root_fd, path: relative, how: how, resource_id: resource_id)
            return Integer(value)
          end
          if @adapter.respond_to?(:call)
            value = @adapter.call(root_fd: root_fd, path: relative, how: how, resource_id: resource_id)
            return Integer(value)
          end

          raise Unsupported, "openat2 adapter does not expose an open operation"
        end
      end

      OpenAt2 = Openat2 unless const_defined?(:OpenAt2, false)
    end
  end
end
