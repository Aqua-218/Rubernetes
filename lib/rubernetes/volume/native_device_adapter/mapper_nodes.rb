# frozen_string_literal: true

module Rubernetes
  module Volume
    class NativeDeviceAdapter
      private

      def create_device_node!(path, dev)
        raise Unsupported, "mknod(2) binding is unavailable" unless MKNOD

        mode = S_IFBLK | 0o600
        result = MKNOD.call(Fiddle::Pointer["#{path}\0"], mode, Integer(dev))
        errno = Fiddle.last_error
        return true unless result == -1
        return false if errno == Errno::EEXIST::Errno

        raise Rubernetes::Platform::Linux::Error.new(errno: errno, operation: "mknod", resource_id: "linux-device:#{path}")
      end

      def unlink_created_mapper_node(path)
        created = @created_mapper_nodes[path]
        return unless created

        current = File.lstat(path)
        File.unlink(path) if current.blockdev? && current.dev == created.dev && current.ino == created.ino && current.rdev == created.rdev
        @created_mapper_nodes.delete(path)
      rescue Errno::ENOENT
        @created_mapper_nodes.delete(path)
      end
    end
  end
end
