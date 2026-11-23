# frozen_string_literal: true

require "digest"
require "fiddle"
require "fileutils"
require "tmpdir"

module Rubernetes
  module Node
    # Materialize a device described by an installed CDI spec without touching
    # its container path on the host. The Pod workspace owns the node's lifetime.
    module CDIDeviceNode
      MKNOD = if RUBY_PLATFORM.include?("linux")
                Fiddle::Function.new(Fiddle::Handle::DEFAULT["mknod"],
                                     [Fiddle::TYPE_VOIDP, Fiddle::TYPE_UINT, Fiddle::TYPE_ULONG], Fiddle::TYPE_INT)
              end

      module_function

      def stage(pod_directory, type, major, minor, node)
        mode = Integer(node["fileMode"] || 0o666)
        uid = Integer(node["uid"] || 0)
        gid = Integer(node["gid"] || 0)
        unless major.between?(1, 4095) && minor.between?(0, 1_048_575) && mode.between?(0, 0o777) &&
               uid.between?(0, 4_294_967_294) && gid.between?(0, 4_294_967_294)
          raise ArgumentError, "invalid device number, mode, or ownership"
        end

        directory = File.join(pod_directory, "cdi-devices")
        FileUtils.mkdir_p(directory, mode: 0o700)
        stat = File.lstat(directory)
        raise ArgumentError, "device staging directory must be private" unless stat.directory? && stat.owned? && stat.mode & 0o077 == 0

        key = Digest::SHA256.hexdigest([type, major, minor, mode, uid, gid].join(":"))
        path = File.join(directory, key)
        create(path, type, major, minor, mode, uid, gid) unless File.exist?(path)
        stat = File.lstat(path)
        valid_type = type == "b" ? stat.blockdev? : stat.chardev?
        unless valid_type && stat.rdev_major == major && stat.rdev_minor == minor && stat.mode & 0o777 == mode && stat.uid == uid && stat.gid == gid
          raise ArgumentError, "staged device does not match its CDI definition"
        end

        path
      end

      def create(path, type, major, minor, mode, uid, gid)
        directory = File.dirname(path)
        Dir.mktmpdir("node-", directory) do |temporary|
          candidate = File.join(temporary, "device")
          create_device(candidate, type, major, minor, mode)
          File.chown(uid, gid, candidate)
          File.chmod(mode, candidate)
          File.link(candidate, path)
        end
      rescue Errno::EEXIST
        # Another start published the same node. The caller validates it.
        path
      end

      def create_device(path, type, major, minor, mode)
        raise ArgumentError, "CDI device creation requires Linux mknod" unless MKNOD

        node_type = type == "b" ? 0o060000 : 0o020000
        # Linux's new_encode_dev keeps the upper minor bits above the major.
        device = (major << 8) | (minor & 0xff) | ((minor & ~0xff) << 12)
        result = MKNOD.call(path, node_type | mode, device)
        errno = Fiddle.last_error
        raise SystemCallError.new("mknod #{type} #{major}:#{minor}", errno) if result == -1
      end
    end
  end
end
