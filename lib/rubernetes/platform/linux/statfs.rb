# frozen_string_literal: true

# statfs(2)/fstatfs(2) readback for volume identity and capacity evidence.
# The descriptor form is preferred: a held fd cannot be redirected by a
# concurrent rename the way a pathname can.

require "fiddle"
require "rbconfig"
require_relative "error"

module Rubernetes
  module Platform
    module Linux
      class Statfs
        # struct statfs for 64-bit ABIs (include/uapi/asm-generic/statfs.h with
        # __statfs_word == long): f_type, f_bsize, f_blocks, f_bfree, f_bavail,
        # f_files, f_ffree, f_fsid (two ints), f_namelen, f_frsize, f_flags,
        # f_spare[4].  120 bytes on x86_64 and aarch64.
        STRUCT_SIZE = 120
        STRUCT_FORMAT = "q<q<Q<Q<Q<Q<Q<l<l<q<q<q<q<4".freeze
        SUPPORTED_CPUS = %w[x86_64 amd64 aarch64 arm64].freeze

        # include/uapi/linux/magic.h
        MAGIC = {
          0xEF53 => "ext4",
          0x58465342 => "xfs",
          0x01021994 => "tmpfs",
          0x9fa0 => "proc",
          0x62656572 => "sysfs",
          0x794c7630 => "overlay",
          0x858458f6 => "ramfs",
          0x1cd1 => "devpts",
          0x6165676C => "pstore",
          0x63677270 => "cgroup2"
        }.freeze

        Result = Data.define(:type, :type_name, :block_size, :blocks, :blocks_free, :blocks_available,
                             :files, :files_free, :fsid, :name_length, :fragment_size, :flags) do
          def capacity_bytes
            blocks * fragment_size_or_block_size
          end

          def available_bytes
            blocks_available * fragment_size_or_block_size
          end

          def free_bytes
            blocks_free * fragment_size_or_block_size
          end

          def used_bytes
            capacity_bytes - free_bytes
          end

          def fragment_size_or_block_size
            fragment_size.positive? ? fragment_size : block_size
          end

          def to_h
            {
              "type" => format("0x%x", type), "typeName" => type_name, "blockSize" => block_size,
              "blocks" => blocks, "blocksFree" => blocks_free, "blocksAvailable" => blocks_available,
              "files" => files, "filesFree" => files_free, "fsid" => fsid, "nameLength" => name_length,
              "fragmentSize" => fragment_size, "flags" => flags, "capacityBytes" => capacity_bytes,
              "availableBytes" => available_bytes, "usedBytes" => used_bytes
            }
          end
        end

        LIBC = Fiddle::Handle::DEFAULT
        STATFS = Fiddle::Function.new(LIBC["statfs"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
        FSTATFS = Fiddle::Function.new(LIBC["fstatfs"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)

        def self.supported?
          SUPPORTED_CPUS.include?(RbConfig::CONFIG.fetch("host_cpu"))
        end

        def self.ensure_supported!
          return true if supported?

          raise ArgumentError, "struct statfs layout is defined only for #{SUPPORTED_CPUS.join(", ")}"
        end

        def self.statfs(path, resource_id: "statfs:#{path}")
          ensure_supported!
          value = String(path)
          raise ArgumentError, "statfs path must not contain NUL" if value.include?("\0")

          buffer = Fiddle::Pointer.malloc(STRUCT_SIZE)
          buffer[0, STRUCT_SIZE] = "\0" * STRUCT_SIZE
          result = STATFS.call(Fiddle::Pointer["#{value}\0"], buffer)
          # R-1.2: errno must be read before any allocation below.
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "statfs", resource_id: resource_id) if result == -1

          parse(buffer[0, STRUCT_SIZE])
        end

        def self.fstatfs(fd, resource_id: "fstatfs:#{fd}")
          ensure_supported!
          descriptor = fd.respond_to?(:fileno) ? fd.fileno : Integer(fd)
          buffer = Fiddle::Pointer.malloc(STRUCT_SIZE)
          buffer[0, STRUCT_SIZE] = "\0" * STRUCT_SIZE
          result = FSTATFS.call(descriptor, buffer)
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "fstatfs", resource_id: resource_id) if result == -1

          parse(buffer[0, STRUCT_SIZE])
        end

        def self.parse(bytes)
          raise ArgumentError, "struct statfs must be #{STRUCT_SIZE} bytes" unless bytes.bytesize == STRUCT_SIZE

          values = bytes.unpack(STRUCT_FORMAT)
          type = values.fetch(0)
          Result.new(
            type: type, type_name: MAGIC.fetch(type, nil), block_size: values.fetch(1), blocks: values.fetch(2),
            blocks_free: values.fetch(3), blocks_available: values.fetch(4), files: values.fetch(5),
            files_free: values.fetch(6), fsid: [values.fetch(7), values.fetch(8)].freeze,
            name_length: values.fetch(9), fragment_size: values.fetch(10), flags: values.fetch(11)
          )
        end
      end
    end
  end
end
