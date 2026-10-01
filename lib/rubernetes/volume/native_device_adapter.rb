# frozen_string_literal: true

# Linux loop-device and device-mapper effects.  The adapter deliberately owns
# only kernel-facing device operations; volume policy and durable lifecycle
# state remain in Volume::Manager and LoopDMBackend.

require "digest"
require "fiddle"
require "monitor"

require_relative "../platform/linux/error"
require_relative "errors"
require_relative "types"

module Rubernetes
  module Volume
    # Direct ioctl implementation for loop-control and device-mapper.
    #
    # A successful ioctl is never returned as a device identity until the
    # corresponding kernel readback has proved the stable fields.  The
    # low-level IO object is injectable so unit tests can exercise packing,
    # bounds, and cleanup without requiring CAP_SYS_ADMIN or device-mapper.
    class NativeDeviceAdapter
      class Unsupported < UnsupportedError; end

      LOOP_CONTROL_PATH = "/dev/loop-control"
      MAPPER_CONTROL_PATH = "/dev/mapper/control"
      DEVICE_DIRECTORY = "/dev"
      MAPPER_DIRECTORY = "/dev/mapper"

      SECTOR_SIZE = 512
      LOOP_NAME_SIZE = 64
      LOOP_KEY_SIZE = 32
      LOOP_INFO64_FORMAT = "Q<Q<Q<Q<Q<L<L<L<L<a64a64a32Q<Q<"
      LOOP_INFO64_SIZE = [0, 0, 0, 0, 0, 0, 0, 0, 0, "", "", "", 0, 0].pack(LOOP_INFO64_FORMAT).bytesize
      LOOP_CONFIGURE_SIZE = 4 + 4 + LOOP_INFO64_SIZE + (8 * 8)

      # The loop ioctls are ABI-stable values from linux/loop.h.
      LOOP_SET_FD = 0x4C00
      LOOP_CLR_FD = 0x4C01
      LOOP_SET_STATUS64 = 0x4C04
      LOOP_GET_STATUS64 = 0x4C05
      LOOP_SET_BLOCK_SIZE = 0x4C09
      LOOP_CONFIGURE = 0x4C0A
      LOOP_CTL_GET_FREE = 0x4C82

      DM_NAME_LEN = 128
      DM_UUID_LEN = 129
      DM_MAX_TYPE_NAME = 16
      DM_IOCTL_FORMAT = "L<L<L<L<L<L<l<L<L<L<Q<a128a129a7"
      DM_IOCTL_SIZE = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "", "", ""].pack(DM_IOCTL_FORMAT).bytesize
      DM_IOCTL = 0xFD
      DM_VERSION = 0
      DM_DEV_CREATE = 3
      DM_DEV_REMOVE = 4
      DM_DEV_SUSPEND = 6
      DM_DEV_STATUS = 7
      DM_TABLE_LOAD = 9
      DM_SUSPEND_FLAG = 1 << 1
      DM_IOCTL_VERSION = [4, 48, 0].freeze

      # _IOWR(DM_IOCTL, command, sizeof(struct dm_ioctl)).
      DM_IOCTL_READ_WRITE = 3
      DM_IOCTLS = {
        version: (DM_IOCTL_READ_WRITE << 30) | (DM_IOCTL_SIZE << 16) | (DM_IOCTL << 8) | DM_VERSION,
        dev_create: (DM_IOCTL_READ_WRITE << 30) | (DM_IOCTL_SIZE << 16) | (DM_IOCTL << 8) | DM_DEV_CREATE,
        dev_remove: (DM_IOCTL_READ_WRITE << 30) | (DM_IOCTL_SIZE << 16) | (DM_IOCTL << 8) | DM_DEV_REMOVE,
        dev_suspend: (DM_IOCTL_READ_WRITE << 30) | (DM_IOCTL_SIZE << 16) | (DM_IOCTL << 8) | DM_DEV_SUSPEND,
        dev_status: (DM_IOCTL_READ_WRITE << 30) | (DM_IOCTL_SIZE << 16) | (DM_IOCTL << 8) | DM_DEV_STATUS,
        table_load: (DM_IOCTL_READ_WRITE << 30) | (DM_IOCTL_SIZE << 16) | (DM_IOCTL << 8) | DM_TABLE_LOAD
      }.freeze

      MAX_PATH_BYTES = 4_096
      MAX_NAME_BYTES = DM_NAME_LEN - 1
      MAX_UUID_BYTES = DM_UUID_LEN - 1
      MAX_SIZE_BYTES = (1 << 63) - 1
      MAX_TARGET_BYTES = 4_096
      LOOP_NUMBER_PATTERN = %r{\A/dev/loop(\d+)\z}
      MAPPER_PATH_PATTERN = %r{\A/dev/mapper/([^/]+)\z}
      SAFE_DM_NAME = /\A[A-Za-z0-9_.:+-]+\z/

      # Ruby's Fiddle call has a fixed third argument, which is sufficient for
      # the integer loop-control argument and pointers to ioctl structures.
      S_IFBLK = 0o060000
      DEVICE_NODE_TIMEOUT_SECONDS = 2.0
      DEVICE_NODE_POLL_SECONDS = 0.01
      MKNOD = if RUBY_PLATFORM.include?("linux")
                Fiddle::Function.new(
                  Fiddle::Handle::DEFAULT["mknod"],
                  [Fiddle::TYPE_VOIDP, Fiddle::TYPE_UINT, Fiddle::TYPE_ULONG],
                  Fiddle::TYPE_INT
                )
              end
      IOCTL = if RUBY_PLATFORM.include?("linux")
                Fiddle::Function.new(
                  Fiddle::Handle::DEFAULT["ioctl"],
                  [Fiddle::TYPE_INT, Fiddle::TYPE_ULONG, Fiddle::TYPE_ULONG],
                  Fiddle::TYPE_INT
                )
              end

      # The default system object is intentionally tiny.  It has no shell or
      # command execution path and is replaceable in unit tests.
      class SystemIO
        def open(path, flags, mode = nil)
          mode.nil? ? File.open(path, flags) : File.open(path, flags, mode)
        end

        def stat(path_or_io)
          path_or_io.respond_to?(:stat) ? path_or_io.stat : File.stat(path_or_io)
        end

        def truncate(io, size)
          io.truncate(Integer(size))
        end

        def entries(path)
          Dir.children(path)
        end

        def read_at(io, offset, length)
          io.pread(Integer(length), Integer(offset))
        end

        def ioctl(fd, command, argument)
          raise NativeDeviceAdapter::Unsupported, "Linux ioctl is unavailable" unless NativeDeviceAdapter::IOCTL

          pointer = argument.respond_to?(:to_i) ? argument.to_i : Integer(argument)
          value = NativeDeviceAdapter::IOCTL.call(Integer(fd), Integer(command), pointer)
          errno = Fiddle.last_error
          if value == -1
            raise Rubernetes::Platform::Linux::Error.new(
              errno: errno,
              operation: format("ioctl(0x%x)", Integer(command)),
              resource_id: "linux-device"
            )
          end
          value
        end
      end

      # Direct superblock UUID reader for the formats whose on-disk UUID
      # offsets are stable and documented by their kernel filesystem layouts.
      # It intentionally does not invoke blkid(8), libblkid, or any fallback
      # that could invent an identity when the superblock is unavailable.
      class FilesystemUuidResolver
        SUPPORTED_FILESYSTEMS = %w[ext4 xfs].freeze
        EXT4_SUPERBLOCK_OFFSET = 1_024
        EXT4_MAGIC_OFFSET = 56
        EXT4_UUID_OFFSET = 104
        EXT4_MAGIC = "\x53\xEF".b.freeze
        XFS_MAGIC_OFFSET = 0
        XFS_UUID_OFFSET = 32
        XFS_MAGIC = "XFSB".b.freeze
        UUID_BYTES = 16
        MAX_SOURCE_BYTES = 4_096

        def initialize(reader: nil, opener: nil)
          @reader = reader
          @opener = opener || method(:open_source)
        end

        # Compatible with NativeMountAdapter's injectable resolver contract.
        def call(entry)
          hash = entry.respond_to?(:to_h) ? entry.to_h.transform_keys(&:to_s) : {}
          filesystem = hash["filesystem"] || hash["fsType"]
          source = hash["source"] || hash["device"]
          return nil if source.nil?

          resolve(source, filesystem: filesystem)
        end

        def resolve(source, filesystem: nil)
          path = validate_source(source)
          requested = filesystem.to_s.downcase
          requested = nil if requested.empty?
          return parse_xfs(path) if requested == "xfs"
          return parse_ext4(path) if requested == "ext4"
          return nil unless requested.nil?

          # A caller that cannot provide a reliable filesystem type may still
          # be using a device readback.  Detect only the two exact magics.
          parse_ext4(path) || parse_xfs(path)
        rescue Errno::EACCES, Errno::EBADF, Errno::EINTR, Errno::EINVAL, Errno::EIO,
               Errno::ELOOP, Errno::ENOENT, Errno::ENOTDIR, Errno::ENXIO, IOError
          nil
        end

        private

        def validate_source(source)
          value = String(source)
          raise ArgumentError, "filesystem source is empty" if value.empty?
          raise ArgumentError, "filesystem source contains NUL" if value.include?("\0")
          raise ArgumentError, "filesystem source contains a control character" if value.match?(/[[:cntrl:]]/)
          raise ArgumentError, "filesystem source is too long" if value.bytesize > MAX_SOURCE_BYTES

          value
        rescue TypeError
          raise ArgumentError, "filesystem source must be a path"
        end

        def parse_ext4(path)
          data = read(path, EXT4_SUPERBLOCK_OFFSET, EXT4_UUID_OFFSET + UUID_BYTES)
          return nil unless data && data.byteslice(EXT4_MAGIC_OFFSET, EXT4_MAGIC.bytesize) == EXT4_MAGIC

          uuid_from_bytes(data.byteslice(EXT4_UUID_OFFSET, UUID_BYTES))
        end

        def parse_xfs(path)
          data = read(path, XFS_MAGIC_OFFSET, XFS_UUID_OFFSET + UUID_BYTES)
          return nil unless data && data.byteslice(XFS_MAGIC_OFFSET, XFS_MAGIC.bytesize) == XFS_MAGIC

          uuid_from_bytes(data.byteslice(XFS_UUID_OFFSET, UUID_BYTES))
        end

        def uuid_from_bytes(bytes)
          return nil unless bytes && bytes.bytesize == UUID_BYTES
          return nil if bytes.bytes.all?(&:zero?)

          hex = bytes.unpack1("H32").downcase
          "#{hex[0, 8]}-#{hex[8, 4]}-#{hex[12, 4]}-#{hex[16, 4]}-#{hex[20, 12]}".freeze
        end

        def read(path, offset, length)
          bytes = if @reader
                    @reader.call(path, Integer(offset), Integer(length))
                  else
                    @opener.call(path) do |io|
                      io.respond_to?(:pread) ? io.pread(Integer(length), Integer(offset)) : io.read(Integer(length))
                    end
                  end
          return nil unless bytes.is_a?(String) && bytes.bytesize == length

          bytes.b
        end

        def open_source(path, &)
          flags = File::RDONLY
          flags |= File::CLOEXEC if File.const_defined?(:CLOEXEC)
          File.open(path, flags, &)
        end
      end

      attr_reader :loop_control_path, :mapper_control_path, :device_directory, :mapper_directory

      def initialize(loop_control_path: LOOP_CONTROL_PATH, mapper_control_path: MAPPER_CONTROL_PATH,
                     device_directory: DEVICE_DIRECTORY, mapper_directory: MAPPER_DIRECTORY,
                     io: nil, max_size_bytes: MAX_SIZE_BYTES, require_device_node: false)
        raise Unsupported, "native device adapter requires Linux" unless RUBY_PLATFORM.include?("linux")

        @loop_control_path = absolute_path(loop_control_path, "loop-control path")
        @mapper_control_path = absolute_path(mapper_control_path, "device-mapper control path")
        @device_directory = absolute_path(device_directory, "device directory")
        @mapper_directory = absolute_path(mapper_directory, "mapper directory")
        @io = io || SystemIO.new
        @max_size_bytes = Integer(max_size_bytes)
        raise ArgumentError, "max_size_bytes must be positive" unless @max_size_bytes.positive?
        raise ArgumentError, "max_size_bytes exceeds the signed kernel limit" if @max_size_bytes > MAX_SIZE_BYTES

        @require_device_node = require_device_node == true
        @devices = {}
        @volume_devices = {}
        @mutex = Monitor.new
      rescue TypeError, ArgumentError => error
        raise ArgumentError, "invalid native device adapter configuration: #{error.message}", cause: error
      end

      def create_loop(path:, volume_id:, size_bytes: nil, **_kwargs)
        normalized_path = backing_path(path)
        size = bounded_size(size_bytes)
        volume = identifier(volume_id, "volume id")

        @mutex.synchronize do
          existing = @volume_devices[["loop", volume]]
          return deep_copy(existing) if existing && existing["backingPath"] == normalized_path && existing["sizeBytes"] == size
          raise MountIdentityError, "volume #{volume} already owns a different loop device" if existing

          backing = open_backing(normalized_path, size)
          begin
            backing_stat = @io.stat(backing)
            validate_regular_file!(backing_stat, normalized_path)
            existing_identity = find_existing_loop(backing_stat, normalized_path, size)
            if existing_identity
              @devices[existing_identity.fetch("id")] = existing_identity
              @volume_devices[["loop", volume]] = existing_identity
              return deep_copy(existing_identity)
            end

            loop_path = allocate_loop_path
            loop_io = nil
            configured = false
            begin
              loop_io = open_device(loop_path, read_write_flags, "loop device")
              configure_loop(loop_io, backing, backing_stat, normalized_path, size)
              configured = true
              status = read_loop_status(loop_io, loop_path)
              identity = loop_identity(loop_path, status, backing_stat, normalized_path, size)
              @devices[loop_path] = identity
              @volume_devices[["loop", volume]] = identity
              deep_copy(identity)
            rescue StandardError
              if configured && loop_io
                # The backing identity is known even when the readback above is
                # what failed, and the rollback must not replace the error that
                # caused it with one of its own.
                rollback_status = status || {"device" => Integer(backing_stat.dev),
                                             "inode" => Integer(backing_stat.ino)}
                begin
                  clear_loop(loop_io, loop_path, rollback_status)
                rescue StandardError
                  nil
                end
              end
              raise
            ensure
              close(loop_io)
            end
          ensure
            close(backing)
          end
        end
      rescue Errno::ENOENT => error
        raise Unsupported, "loop-device support is unavailable at #{@loop_control_path}: #{error.message}", cause: error
      end

      def create_dm(device:, volume_id:, size_bytes: nil, **_kwargs)
        source_path = device_path(device)
        volume = identifier(volume_id, "volume id")
        size = bounded_size(size_bytes)
        ensure_sector_aligned!(size)

        @mutex.synchronize do
          existing = @volume_devices[["dm", volume]]
          if existing
            unless existing["source"] == source_path && existing["sizeBytes"] == size
              raise MountIdentityError, "volume #{volume} already owns a different device-mapper device"
            end

            return deep_copy(existing)
          end

          source_stat = @io.stat(source_path)
          validate_block_device!(source_stat, source_path)
          source_device = device_number(source_stat)
          dm_name = dm_name_for(volume)
          dm_uuid = dm_uuid_for(volume)
          created = false
          begin
            with_mapper_control do |control|
              verify_dm_version!(control)
              dm_create(control, dm_name, dm_uuid)
              created = true
              # DM_DEV_CREATE registers both identities; every later lookup
              # must carry exactly one of them (drivers/md/dm-ioctl.c
              # lookup_device: "only supply one of name or uuid"), so the
              # verified name addresses the device from here on.
              dm_table_load(control, dm_name, "", source_device, size)
              dm_resume(control, dm_name, "")
              status = dm_status(control, dm_name, "")
              identity = dm_identity(dm_name, dm_uuid, status, size, source_path)
              @devices[identity.fetch("id")] = identity
              @volume_devices[["dm", volume]] = identity
              deep_copy(identity)
            end
          rescue StandardError => error
            if created
              begin
                with_mapper_control { |control| remove_dm(control, dm_name, dm_uuid) }
              rescue StandardError => cleanup_error
                raise MountIdentityError, "device-mapper cleanup failed after #{dm_name}: #{cleanup_error.message}",
                      cause: error
              end
            end
            raise error
          end
        end
      rescue Errno::ENOENT => error
        raise Unsupported, "device-mapper support is unavailable at #{@mapper_control_path}: #{error.message}", cause: error
      end

      # Destroying a device is idempotent.  A missing readback after a remove
      # is success; a still-visible device is an identity error and is never
      # silently treated as cleaned up.
      def destroy_device(id:, volume_id: nil, **_kwargs)
        identity = id.respond_to?(:to_h) ? id.to_h.transform_keys(&:to_s) : {}
        identifier = identity["id"] || identity["path"] || id.to_s
        raise ValidationError, "device id must not be empty" if identifier.empty?

        @mutex.synchronize do
          known = @devices[identifier] || identity
          kind = known["kind"] || infer_device_kind(identifier)
          case kind
          when "device-mapper"
            destroy_dm(known, identifier)
          when "loop"
            destroy_loop(known, identifier)
          else
            raise ValidationError, "unsupported native device identity #{identifier.inspect}"
          end
          @devices.delete(identifier)
          @volume_devices.delete_if { |_key, value| value["id"] == identifier }
          true
        end
      end

      def list_devices
        @mutex.synchronize { @devices.values.map { |value| deep_copy(value) }.freeze }
      end

      class << self
        attr_reader :loop_info64_size, :loop_configure_size, :dm_ioctl_size
      end

      @loop_info64_size = LOOP_INFO64_SIZE
      @loop_configure_size = LOOP_CONFIGURE_SIZE
      @dm_ioctl_size = DM_IOCTL_SIZE

      private

      def absolute_path(value, field)
        raw = String(value)
        raise ArgumentError, "#{field} must be absolute" unless raw.start_with?(File::SEPARATOR)

        path = File.expand_path(raw)
        raise ArgumentError, "#{field} contains NUL" if path.include?("\0")
        raise ArgumentError, "#{field} is too long" if path.bytesize > MAX_PATH_BYTES

        path.freeze
      rescue TypeError
        raise ArgumentError, "#{field} must be a path"
      end

      def identifier(value, field)
        Types.identifier(value, field)
      end

      def backing_path(value)
        path = absolute_path(value, "backing path")
        raise ValidationError, "backing path must not be a device node" if path == "/dev" || path.start_with?("/dev/")

        path
      end

      def device_path(value)
        hash = value.respond_to?(:to_h) ? value.to_h.transform_keys(&:to_s) : {}
        candidate = hash["path"] || hash["device"] || value.to_s
        path = absolute_path(candidate, "device path")
        unless path.match?(LOOP_NUMBER_PATTERN) || path.match?(MAPPER_PATH_PATTERN)
          raise ValidationError, "device path must identify a loop or device-mapper node"
        end

        path
      end

      def bounded_size(value)
        size = Integer(value || SECTOR_SIZE)
        raise CapacityError, "device size must be positive" unless size.positive?
        raise CapacityError, "device size exceeds the kernel bound" if size > @max_size_bytes

        size
      rescue TypeError, ArgumentError
        raise CapacityError, "device size must be an integer"
      end

      def ensure_sector_aligned!(size)
        return true if (size % SECTOR_SIZE).zero?

        raise CapacityError, "device size must be aligned to #{SECTOR_SIZE} bytes"
      end

      def validate_regular_file!(stat, path)
        raise ValidationError, "loop backing path #{path.inspect} is not a regular file" unless stat.respond_to?(:file?) && stat.file?
      end

      def validate_block_device!(stat, path)
        return if stat.respond_to?(:blockdev?) && stat.blockdev?

        raise ValidationError, "device-mapper source #{path.inspect} is not a block device"
      end

      def read_write_flags
        flags = File::RDWR
        flags |= File::CLOEXEC if File.const_defined?(:CLOEXEC)
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        flags
      end

      # LOOP_GET_STATUS64 needs no write access, and a detach readback must
      # take the weakest reference it can on the device it is watching.
      def read_only_flags
        flags = File::RDONLY
        flags |= File::CLOEXEC if File.const_defined?(:CLOEXEC)
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        flags
      end

      def open_backing(path, size)
        flags = read_write_flags
        begin
          io = @io.open(path, flags)
        rescue Errno::ENOENT
          io = @io.open(path, flags | File::CREAT | File::EXCL, 0o600)
        end
        stat = @io.stat(io)
        validate_regular_file!(stat, path)
        @io.truncate(io, size) if stat.size < size
        io
      rescue StandardError
        close(io)
        raise
      end

      def open_device(path, flags, label)
        @io.open(path, flags)
      rescue SystemCallError => error
        raise Unsupported, "cannot open #{label} #{path.inspect}: #{error.message}", cause: error
      end

      def allocate_loop_path
        with_loop_control do |control|
          number = issue_ioctl(control, LOOP_CTL_GET_FREE, 0)
          number = Integer(number)
          raise MountIdentityError, "loop-control returned an invalid loop number" if number.negative?

          path = File.join(@device_directory, "loop#{number}")
          raise MountIdentityError, "loop-control returned an unsafe device path" unless path.match?(%r{\A/dev/loop\d+\z})

          path
        end
      end

      def configure_loop(loop_io, backing, backing_stat, path, size)
        config = Fiddle::Pointer.malloc(LOOP_CONFIGURE_SIZE)
        config[0, LOOP_CONFIGURE_SIZE] = pack_loop_config(backing.fileno, backing_stat, path, size)
        begin
          issue_ioctl(loop_io, LOOP_CONFIGURE, config)
        rescue Rubernetes::Platform::Linux::Error => error
          # LOOP_CONFIGURE was added in Linux 5.8.  The fallback is retained
          # only for kernels that reject the command itself or its ABI size;
          # all state is still read back before returning an identity.
          raise unless [Errno::ENOTTY::Errno, Errno::EINVAL::Errno].include?(error.errno)

          issue_ioctl(loop_io, LOOP_SET_FD, backing.fileno)
          issue_ioctl(loop_io, LOOP_SET_BLOCK_SIZE, SECTOR_SIZE)
        end
      end

      def pack_loop_config(backing_fd, stat, path, size)
        [Integer(backing_fd), 0].pack("L<L<") + pack_loop_info(stat, path, size) + ("\0" * (8 * 8))
      end

      def pack_loop_info(_stat, path, size)
        filename = path.b.byteslice(0, LOOP_NAME_SIZE - 1).to_s
        filename = filename.ljust(LOOP_NAME_SIZE, "\0")
        [0, 0, 0, 0, Integer(size), 0, 0, 0, 0, filename, "\0" * LOOP_NAME_SIZE,
         "\0" * LOOP_KEY_SIZE, 0, 0].pack(LOOP_INFO64_FORMAT)
      end

      def read_loop_status(loop_io, path)
        buffer = zeroed_pointer(LOOP_INFO64_SIZE)
        issue_ioctl(loop_io, LOOP_GET_STATUS64, buffer)
        values = buffer[0, LOOP_INFO64_SIZE].unpack(LOOP_INFO64_FORMAT)
        {
          "device" => values.fetch(0), "inode" => values.fetch(1), "rdevice" => values.fetch(2),
          "offset" => values.fetch(3), "sizeLimit" => values.fetch(4), "number" => values.fetch(5),
          "flags" => values.fetch(8), "fileName" => c_string(values.fetch(9))
        }
      rescue Rubernetes::Platform::Linux::Error => error
        raise MountIdentityError, "loop readback failed for #{path.inspect}: #{error.message}", cause: error
      end

      def loop_identity(path, status, backing_stat, backing_path, size)
        expected_device = Integer(backing_stat.dev)
        expected_inode = Integer(backing_stat.ino)
        unless status["device"] == expected_device && status["inode"] == expected_inode
          raise MountIdentityError, "loop readback does not identify the requested backing file"
        end
        raise MountIdentityError, "loop readback returned an invalid number" unless Integer(status["number"]) >= 0

        node_stat = @io.stat(path)
        node_device = device_number(node_stat, allow_non_block: true)
        {
          "id" => path, "device" => path, "path" => path, "kind" => "loop", "loopNumber" => status["number"],
          "deviceId" => node_device, "backingPath" => backing_path, "backingDevice" => expected_device,
          "backingInode" => expected_inode, "offsetBytes" => status["offset"],
          "sizeBytes" => size, "sizeLimitBytes" => status["sizeLimit"], "flags" => status["flags"]
        }.freeze
      rescue SystemCallError => error
        raise MountIdentityError, "loop device readback failed for #{path.inspect}: #{error.message}", cause: error
      end

      def find_existing_loop(backing_stat, backing_path, size)
        entries = @io.entries(@device_directory)
        entries.grep(/\Aloop\d+\z/).sort_by { |entry| entry.delete_prefix("loop").to_i }.each do |entry|
          path = File.join(@device_directory, entry)
          loop_io = nil
          begin
            loop_io = @io.open(path, read_write_flags)
            status = read_loop_status(loop_io, path)
            next unless status["device"] == Integer(backing_stat.dev) && status["inode"] == Integer(backing_stat.ino)
            next if status["sizeLimit"].positive? && status["sizeLimit"] != size

            return loop_identity(path, status, backing_stat, backing_path, size)
          rescue SystemCallError, MountIdentityError
            next
          ensure
            close(loop_io)
          end
        end
        nil
      rescue Errno::ENOENT, Errno::EACCES, Errno::ENOTDIR
        nil
      end

      # LOOP_CLR_FD only *requests* detachment: while the kernel still holds a
      # reference (a partition scan, udev, a closing opener) the ioctl returns
      # success, the device is marked LO_FLAGS_AUTOCLEAR and it stays
      # configured until the last reference goes.  util-linux documents the
      # same deferred behaviour for `losetup -d`, so the readback is polled
      # instead of being read exactly once.
      #
      # The descriptor the ioctl was issued on is itself one of those
      # references, so polling through it observes a detach that its own
      # existence is deferring.  The clear therefore releases the caller's
      # descriptor first and polls through short-lived reopens.
      LOOP_CLEAR_TIMEOUT = 30.0
      LOOP_CLEAR_POLL_INTERVAL = 0.01

      def clear_loop(loop_io, path, status = nil)
        issue_ioctl(loop_io, LOOP_CLR_FD, 0)
        close(loop_io)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + LOOP_CLEAR_TIMEOUT
        loop do
          return true if loop_backing_released?(path, status)

          if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
            raise MountIdentityError,
                  "loop clear for #{path.inspect} reported success but device remains configured " \
                  "after #{LOOP_CLEAR_TIMEOUT}s"
          end

          sleep(LOOP_CLEAR_POLL_INTERVAL)
        end
      rescue Rubernetes::Platform::Linux::Error => error
        return true if not_present_error?(error)

        raise
      end

      # True once the device no longer carries the backing file the caller
      # attached.  A vanished device and a device the kernel has already
      # handed to a different backing file both satisfy that: what must never
      # count as released is the original mapping still being readable.
      def loop_backing_released?(path, status)
        io = nil
        begin
          io = @io.open(path, read_only_flags)
        rescue SystemCallError => error
          return true if not_present_error?(error)

          raise
        end

        begin
          current = read_loop_status(io, path)
        rescue MountIdentityError => error
          cause = error.cause
          return true if cause && not_present_error?(cause)
          return true if error.message.match?(/No such device|No such file|Bad file descriptor/)

          raise
        ensure
          close(io)
        end

        return false if status.nil?

        current["device"] != status["device"] || current["inode"] != status["inode"]
      end

      def destroy_loop(identity, identifier)
        path = identity["path"] || identity["device"] || identifier
        path = device_path(path)
        io = nil
        begin
          io = open_device(path, read_write_flags, "loop device")
          status = read_loop_status(io, path)
          verify_loop_identity!(identity, status, path)
          # clear_loop closes the descriptor: it cannot observe the detach
          # while holding a reference that defers it.
          clear_loop(io, path, status)
          io = nil
        rescue Unsupported => error
          cause = error.cause
          return true if cause && not_present_error?(cause)

          raise
        rescue SystemCallError => error
          return true if not_present_error?(error)

          raise
        rescue MountIdentityError => error
          cause = error.cause
          return true if cause && not_present_error?(cause)

          raise
        ensure
          close(io)
        end
        true
      end

      def verify_loop_identity!(identity, status, path)
        return true if identity.empty?
        raise MountIdentityError, "loop identity changed at #{path.inspect}" if identity["loopNumber"] && identity["loopNumber"].to_i != status["number"].to_i
        if identity["backingInode"] && identity["backingInode"].to_i != status["inode"].to_i
          raise MountIdentityError, "loop backing inode changed at #{path.inspect}"
        end
        if identity["backingDevice"] && identity["backingDevice"].to_i != status["device"].to_i
          raise MountIdentityError, "loop backing device changed at #{path.inspect}"
        end

        true
      end

      def with_mapper_control
        control = nil
        begin
          control = open_device(@mapper_control_path, read_write_flags, "device-mapper control")
          yield control
        ensure
          close(control)
        end
      end

      def with_loop_control
        control = nil
        begin
          control = open_device(@loop_control_path, read_write_flags, "loop-control")
          yield control
        ensure
          close(control)
        end
      end

      def verify_dm_version!(control)
        buffer = dm_buffer
        issue_ioctl(control, DM_IOCTLS.fetch(:version), buffer)
        version = parse_dm_ioctl(buffer).fetch(:version)
        raise Unsupported, "device-mapper ioctl version #{version.join(".")} is unsupported" unless version[0] == DM_IOCTL_VERSION[0] && version[1] >= 1

        true
      end

      def dm_create(control, name, uuid)
        issue_ioctl(control, DM_IOCTLS.fetch(:dev_create), dm_buffer(name: name, uuid: uuid))
      end

      def dm_table_load(control, name, uuid, source_device, size)
        sectors = size / SECTOR_SIZE
        target = [0, sectors, 0, 0, "linear\0".ljust(DM_MAX_TYPE_NAME, "\0")].pack("Q<Q<l<L<a16")
        params = "#{source_device} 0\0"
        payload = target + params
        payload = payload.ljust((payload.bytesize + 7) & ~7, "\0")
        header = dm_buffer(name: name, uuid: uuid, target_count: 1, data_start: DM_IOCTL_SIZE,
                           data_size: DM_IOCTL_SIZE + payload.bytesize)
        buffer = header[0, DM_IOCTL_SIZE] + payload
        raise CapacityError, "device-mapper table exceeds the bounded ioctl buffer" if payload.bytesize > MAX_TARGET_BYTES

        issue_ioctl(control, DM_IOCTLS.fetch(:table_load), pointer_for(buffer))
      end

      def dm_resume(control, name, uuid)
        issue_ioctl(control, DM_IOCTLS.fetch(:dev_suspend), dm_buffer(name: name, uuid: uuid))
      end

      def remove_dm(control, name, _uuid)
        # DM_DEV_REMOVE synchronously tears down the inactive/active table
        # and refuses an in-use device.  Issuing DM_DEV_SUSPEND here first is
        # incorrect for a device whose table load failed: the kernel returns
        # EINVAL and leaves the otherwise removable empty device behind.
        # Name lookup is required here.  Some kernels reject a remove ioctl
        # addressed by UUID for an empty (table-load-failed) device even after
        # a matching status readback; the name was already verified above.
        issue_ioctl(control, DM_IOCTLS.fetch(:dev_remove), dm_buffer(name: name, uuid: ""))
        begin
          dm_status(control, name, "")
        rescue Rubernetes::Platform::Linux::Error => error
          return true if dm_absent_error?(error)

          raise
        end
        raise MountIdentityError, "device-mapper remove for #{name.inspect} reported success but status remains"
      rescue Rubernetes::Platform::Linux::Error => error
        return true if not_present_error?(error)

        raise
      end

      def dm_status(control, name, uuid)
        buffer = dm_buffer(name: name, uuid: uuid)
        issue_ioctl(control, DM_IOCTLS.fetch(:dev_status), buffer)
        parse_dm_ioctl(buffer)
      end

      def parse_dm_ioctl(buffer)
        data = buffer.respond_to?(:[]) ? buffer[0, DM_IOCTL_SIZE] : buffer
        values = data.unpack(DM_IOCTL_FORMAT)
        {
          version: values.first(3), data_size: values.fetch(3), data_start: values.fetch(4),
          target_count: values.fetch(5), open_count: values.fetch(6), flags: values.fetch(7),
          event_nr: values.fetch(8), dev: values.fetch(10), name: c_string(values.fetch(11)),
          uuid: c_string(values.fetch(12))
        }
      end

      def dm_identity(name, uuid, status, size, source_path)
        unless status[:name] == name && status[:uuid] == uuid && status[:dev].to_i.positive?
          raise MountIdentityError, "device-mapper readback does not match the requested identity"
        end

        path = File.join(@mapper_directory, name)
        ensure_device_node!(path, status[:dev], "device-mapper")
        {
          "id" => path, "device" => path, "path" => path, "kind" => "device-mapper", "name" => name,
          "uuid" => uuid, "dev" => status[:dev], "deviceId" => decode_device_number(status[:dev]),
          "sizeBytes" => size, "source" => source_path, "flags" => status[:flags]
        }.freeze
      end

      # udev creates /dev/mapper/<name> asynchronously after DM_DEV_CREATE;
      # the mount that follows needs the node now.  Wait briefly for udev and
      # otherwise create the block node ourselves; either way the node's rdev
      # must equal the kernel readback before it is trusted.
      def ensure_device_node!(path, dev, label)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + DEVICE_NODE_TIMEOUT_SECONDS
        loop do
          node_stat = begin
            @io.stat(path)
          rescue Errno::ENOENT
            nil
          end
          if node_stat
            unless node_stat.respond_to?(:rdev) && Integer(node_stat.rdev) == Integer(dev)
              raise MountIdentityError, "#{label} node #{path.inspect} does not match kernel readback"
            end

            return true
          end
          break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep DEVICE_NODE_POLL_SECONDS
        end
        raise MountIdentityError, "#{label} node #{path.inspect} did not appear" if @require_device_node

        create_device_node!(path, dev)
        node_stat = @io.stat(path)
        unless node_stat.respond_to?(:rdev) && Integer(node_stat.rdev) == Integer(dev)
          raise MountIdentityError, "#{label} node #{path.inspect} does not match kernel readback"
        end

        true
      end

      def create_device_node!(path, dev)
        raise Unsupported, "mknod(2) binding is unavailable" unless MKNOD

        mode = S_IFBLK | 0o600
        result = MKNOD.call(Fiddle::Pointer["#{path}\0"], mode, Integer(dev))
        errno = Fiddle.last_error
        return true unless result == -1
        return true if errno == Errno::EEXIST::Errno

        raise Rubernetes::Platform::Linux::Error.new(errno: errno, operation: "mknod", resource_id: "linux-device:#{path}")
      end

      def destroy_dm(identity, identifier)
        name = identity["name"] || mapper_name(identifier)
        identity["uuid"] || ""
        with_mapper_control do |control|
          status = begin
            verify_dm_version!(control)
            # Lookups carry exactly one identity (name); the UUID is compared
            # against the readback below.
            dm_status(control, name, "")
          rescue Rubernetes::Platform::Linux::Error => error
            return true if dm_absent_error?(error)

            raise
          end
          unless status[:name] == name &&
                 (identity.empty? || identity["dev"].nil? || identity["dev"].to_i == status[:dev].to_i) &&
                 (identity["uuid"].nil? || identity["uuid"].to_s == status[:uuid].to_s)
            raise MountIdentityError, "device-mapper identity changed for #{name.inspect}"
          end

          remove_dm(control, name, status[:uuid])
        end
        true
      rescue Unsupported => error
        cause = error.cause
        return true if cause && not_present_error?(cause)

        raise
      end

      def dm_name_for(volume_id)
        "rubernetes-#{Digest::SHA256.hexdigest(volume_id.to_s)[0, 32]}"
      end

      def dm_uuid_for(volume_id)
        "RUBERNETES-#{Digest::SHA256.hexdigest(volume_id.to_s)}"
      end

      def mapper_name(path)
        match = path.to_s.match(MAPPER_PATH_PATTERN)
        raise ValidationError, "device-mapper identity must use /dev/mapper/<name>" unless match

        name = match[1]
        validate_dm_name(name)
      end

      def validate_dm_name(name)
        value = String(name)
        raise ValidationError, "device-mapper name is empty" if value.empty?
        raise ValidationError, "device-mapper name exceeds #{MAX_NAME_BYTES} bytes" if value.bytesize > MAX_NAME_BYTES
        raise ValidationError, "device-mapper name contains unsafe characters" unless value.match?(SAFE_DM_NAME)

        value
      end

      def dm_buffer(name: "", uuid: "", flags: 0, target_count: 0, data_start: 0, data_size: DM_IOCTL_SIZE)
        name = validate_dm_name(name) unless name.to_s.empty?
        uuid = String(uuid)
        raise ValidationError, "device-mapper UUID contains NUL" if uuid.include?("\0")
        raise ValidationError, "device-mapper UUID exceeds #{MAX_UUID_BYTES} bytes" if uuid.bytesize > MAX_UUID_BYTES
        raise CapacityError, "device-mapper ioctl data size is out of bounds" unless Integer(data_size).between?(DM_IOCTL_SIZE,
                                                                                                                 DM_IOCTL_SIZE + MAX_TARGET_BYTES)

        packed_name = name.to_s.b.ljust(DM_NAME_LEN, "\0")
        packed_uuid = uuid.b.ljust(DM_UUID_LEN, "\0")
        packed = [DM_IOCTL_VERSION[0], DM_IOCTL_VERSION[1], DM_IOCTL_VERSION[2], Integer(data_size),
                  Integer(data_start), Integer(target_count), 0, Integer(flags), 0, 0, 0, packed_name,
                  packed_uuid, "\0" * 7].pack(DM_IOCTL_FORMAT)
        pointer_for(packed)
      end

      def pointer_for(bytes)
        pointer = Fiddle::Pointer.malloc(bytes.bytesize)
        pointer[0, bytes.bytesize] = bytes
        pointer
      end

      def zeroed_pointer(size)
        pointer_for("\0" * Integer(size))
      end

      def issue_ioctl(io, command, argument)
        value = @io.ioctl(io.fileno, command, argument)
        return value unless value == -1

        raise MountIdentityError, "ioctl(0x#{Integer(command).to_s(16)}) returned failure without errno"
      end

      def c_string(value)
        String(value).split("\0", 2).first.to_s
      end

      def device_number(stat, allow_non_block: false)
        unless allow_non_block || (stat.respond_to?(:blockdev?) && stat.blockdev?)
          raise ValidationError, "device stat is not a block device"
        end

        major = stat.respond_to?(:rdev_major) ? stat.rdev_major : decode_device_number(stat.rdev).split(":").first
        minor = stat.respond_to?(:rdev_minor) ? stat.rdev_minor : decode_device_number(stat.rdev).split(":").last
        "#{Integer(major)}:#{Integer(minor)}"
      rescue NoMethodError, TypeError, ArgumentError
        raise MountIdentityError, "device readback lacks a stable major:minor identity"
      end

      def decode_device_number(value)
        dev = Integer(value)
        major = ((dev & 0x00000fff00) >> 8) | ((dev >> 32) & 0xfffff000)
        minor = (dev & 0x000000000ff) | ((dev >> 12) & 0xffffff00)
        "#{major}:#{minor}"
      end

      def infer_device_kind(identifier)
        return "loop" if identifier.match?(LOOP_NUMBER_PATTERN)
        return "device-mapper" if identifier.match?(MAPPER_PATH_PATTERN)

        nil
      end

      def close(io)
        return unless io && (!io.respond_to?(:closed?) || !io.closed?)

        io.close
      rescue IOError, SystemCallError
        nil
      end

      def not_present_error?(error)
        errno = error.respond_to?(:errno) ? error.errno : nil
        return false unless errno

        [Errno::ENXIO::Errno, Errno::ENODEV::Errno, Errno::ENOENT::Errno, Errno::EBADF::Errno].include?(errno)
      end

      def dm_absent_error?(error)
        return true if not_present_error?(error)

        error.respond_to?(:errno) && error.errno == Errno::EINVAL::Errno
      end

      def deep_copy(value)
        Types.deep_copy(value)
      rescue StandardError
        value.dup
      end
    end

    NativeFilesystemUuidResolver = NativeDeviceAdapter::FilesystemUuidResolver unless const_defined?(:NativeFilesystemUuidResolver, false)
    FilesystemUuidResolver = NativeDeviceAdapter::FilesystemUuidResolver unless const_defined?(:FilesystemUuidResolver, false)
    FilesystemUUIDResolver = NativeDeviceAdapter::FilesystemUuidResolver unless const_defined?(:FilesystemUUIDResolver, false)
    if defined?(NativeMountAdapter)
      NativeMountAdapter.const_set(:FilesystemUuidResolver, NativeDeviceAdapter::FilesystemUuidResolver) unless
        NativeMountAdapter.const_defined?(:FilesystemUuidResolver, false)
      NativeMountAdapter.const_set(:FilesystemUUIDResolver, NativeDeviceAdapter::FilesystemUuidResolver) unless
        NativeMountAdapter.const_defined?(:FilesystemUUIDResolver, false)
    end
  end
end
