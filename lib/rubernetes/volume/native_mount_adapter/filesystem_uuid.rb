# frozen_string_literal: true

module Rubernetes
  module Volume
    class NativeMountAdapter
      private

      def decorate_observation(entry)
        return entry unless @filesystem_uuid_resolver
        return entry unless UUID_FILESYSTEMS.include?(entry.fetch("filesystem").downcase) &&
                            entry.fetch("source").start_with?("/dev/", "/proc/self/fd/")

        uuid = resolve_filesystem_uuid(entry)
        return entry if uuid.nil?

        entry.merge("filesystemUuid" => uuid, "filesystemUuidAvailable" => true).freeze
      end

      def resolve_filesystem_uuid(entry)
        return nil unless @filesystem_uuid_resolver

        source = entry.fetch("source")
        if source.start_with?("/proc/self/fd/")
          # The kernel keeps the pathname passed to mount(2) as its source.
          # That fd belongs to the mounting process and may now refer to
          # something else. Resolve the observed superblock's device instead.
          device = observed_block_device(entry.fetch("deviceId"))
          return nil unless device

          entry = entry.merge("source" => device)
        end
        value = @filesystem_uuid_resolver.call(entry)
        return nil if value.nil?

        uuid = String(value)
        raise MountIdentityError, "filesystem UUID resolver returned an empty value" if uuid.empty?

        uuid.freeze
      rescue TypeError => error
        raise MountIdentityError, "filesystem UUID resolver returned a non-string value", cause: error
      end

      def observed_block_device(device_id)
        return nil unless device_id.match?(/\A\d+:\d+\z/)

        device = "/dev/block/#{device_id}"
        return device if matches_device_id?(device, device_id)

        # udev has not necessarily created the /dev/block symlink yet.
        # devtmpfs creates the node named by sysfs as soon as it is visible.
        name = File.foreach("/sys/dev/block/#{device_id}/uevent").find { |line| line.start_with?("DEVNAME=") }
        name = name&.delete_prefix("DEVNAME=")&.strip
        return nil unless name && name.match?(%r{\A[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*\z})

        device = File.join("/dev", name)
        device if matches_device_id?(device, device_id)
      rescue SystemCallError
        nil
      end

      def matches_device_id?(path, device_id)
        stat = File.stat(path)
        stat.blockdev? && "#{stat.rdev_major}:#{stat.rdev_minor}" == device_id
      rescue SystemCallError
        false
      end
    end
  end
end
