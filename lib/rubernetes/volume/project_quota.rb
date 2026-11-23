# frozen_string_literal: true

require "fiddle"
require "securerandom"
require_relative "../platform/linux/openat2"
require_relative "../platform/linux/syscall"
require_relative "native_mount_adapter"

module Rubernetes
  module Volume
    # Measure an emptyDir with a Linux project quota on a dedicated volume
    # filesystem. The manager never enables quotas or writes quota limits.
    class ProjectQuota
      FEATURE_GATE = "LocalStorageCapacityIsolationFSQuotaMonitoring"
      OPEN_DIRECTORY = File::RDONLY | File::NOFOLLOW | Platform::Linux::Openat2::O_DIRECTORY
      PROJECT_INHERIT = 0x200
      GET_FSXATTR = 0x801c581f
      SET_FSXATTR = 0x401c5820
      GET_PROJECT_QUOTA = 0x80000702
      GET_PROJECT_QUOTA_STATE = 0x580802
      PROJECT_ACCOUNTING = 1 << 4
      QUOTA_USAGE_AND_LIMITS = 0xf
      QUOTACTL_FD = 443 # Linux x86-64 and aarch64
      PROJECT_IDS = (1 << 30)...(1 << 31)

      def initialize(root:)
        @root = File.expand_path(root)
      end

      def supported?
        with_mount_root { |root| usable_mount?(root) } == true
      rescue SystemCallError, MountIdentityError
        false
      end

      def provision(path)
        with_volume_root(path) do |root, child|
          return unless usable_mount?(root)

          # mkdir is the ownership boundary. A recovered or concurrently
          # created source is never assigned a different project.
          Dir.mkdir(child, 0o700)
          project = File.open(child, OPEN_DIRECTORY) { |directory| assign(root, directory) }
          Dir.rmdir(child) unless project
          project
        end
      rescue SystemCallError, MountIdentityError
        nil
      end

      def usage(path, project, published_path:)
        return unless PROJECT_IDS.cover?(project)

        with_volume_root(path) do |root, child|
          File.open(child, OPEN_DIRECTORY) do |directory|
            next unless same_directory?(directory, published_path) && same_mount?(root, directory)
            next unless labeled?(directory, project)

            record = quota_record(root, project)
            record.values_at(2, 5) if record.is_a?(Array) && record[5].positive?
          end
        end
      rescue SystemCallError
        nil
      end

      private

      def with_volume_root(path)
        return unless File.dirname(path) == @root

        with_mount_root { |root| yield root, "/proc/self/fd/#{root.fileno}/#{File.basename(path)}" }
      end

      def with_mount_root
        return unless RUBY_PLATFORM.match?(/\A(?:x86_64|aarch64)-linux/) && @root != "/"

        File.open(@root, OPEN_DIRECTORY) do |root|
          stat = root.stat
          yield root if stat.directory? && stat.uid == Process.euid && stat.mode & 0o022 == 0
        end
      end

      def usable_mount?(root)
        dedicated_mount?(root) && accounting?(root) && unlimited_project_defaults?(root)
      end

      def mount_id(io)
        File.read("/proc/self/fdinfo/#{io.fileno}")[/^mnt_id:\s*(\d+)/, 1]
      end

      def same_mount?(root, directory)
        id = mount_id(root)
        id && id == mount_id(directory)
      end

      def dedicated_mount?(root)
        id = mount_id(root)
        return false unless id

        entries = File.readlines("/proc/self/mountinfo")
        entry = entries.find { |line| line.start_with?("#{id} ") }
        return false unless entry

        mount = NativeMountAdapter.parse_mountinfo_line(entry)
        return false unless mount["root"] == "/" && mount["target"] == @root && %w[ext4 xfs].include?(mount["filesystem"])

        # Reject a whole-filesystem bind or another view of the host root.
        # Per-volume bind mounts use a subtree and can coexist with the root.
        entries.none? do |line|
          mount_id, _, device, subtree, = line.split(" ", 5)
          mount_id != id && device == mount["deviceId"] && subtree == "/"
        end
      end

      def accounting?(root)
        state = "\1".b + ("\0".b * 159) # fs_quota_statv version 1
        quotactl(root, GET_PROJECT_QUOTA_STATE, 0, state).value.zero? && state.unpack1("@2S") & PROJECT_ACCOUNTING != 0
      end

      def unlimited_project_defaults?(root)
        quota = quota_record(root, 0)
        quota == :missing || (quota.is_a?(Array) && quota.values_at(0, 1, 3, 4).all?(&:zero?))
      end

      def assign(root, directory)
        return unless directory.stat.directory? && same_mount?(root, directory)

        root.flock(File::LOCK_EX)
        attributes = read_attributes(directory)
        return unless attributes.unpack1("@12L").zero? && attributes.unpack1("L") & PROJECT_INHERIT == 0

        project = available_project(root)
        return unless project

        attributes[0, 4] = [attributes.unpack1("L") | PROJECT_INHERIT].pack("L")
        attributes[12, 4] = [project].pack("L")
        directory.ioctl(SET_FSXATTR, attributes)
        quota = quota_record(root, project)
        project if labeled?(directory, project) && quota.is_a?(Array) && quota[5] == 1 && quota.values_at(0, 1, 3, 4).all?(&:zero?)
      rescue SystemCallError
        nil
      end

      def available_project(root)
        8.times do
          project = PROJECT_IDS.begin + SecureRandom.random_number(PROJECT_IDS.size)
          quota = quota_record(root, project)
          return project if quota == :missing || (quota.is_a?(Array) && quota.first(6).all?(&:zero?))
        end
        nil
      end

      def quota_record(root, project)
        attributes = "\0".b * 72 # Linux struct if_dqblk
        result = quotactl(root, GET_PROJECT_QUOTA, project, attributes)
        return :missing if result.value == -1 && result.errno == Errno::ENOENT::Errno
        return unless result.value.zero?

        values = attributes.unpack("Q8L")
        values if values.last & QUOTA_USAGE_AND_LIMITS == QUOTA_USAGE_AND_LIMITS
      end

      def quotactl(root, command, project, buffer)
        Platform::Linux::Syscall.call(QUOTACTL_FD, root.fileno, command, project, Fiddle::Pointer[buffer])
      end

      def same_directory?(directory, path)
        source = directory.stat
        published = File.stat(path)
        source.directory? && source.dev == published.dev && source.ino == published.ino
      end

      def labeled?(directory, project)
        attributes = read_attributes(directory)
        attributes.unpack1("L") & PROJECT_INHERIT != 0 && attributes.unpack1("@12L") == project
      end

      def read_attributes(directory)
        attributes = "\0".b * 28 # Linux struct fsxattr
        directory.ioctl(GET_FSXATTR, attributes)
        attributes
      end
    end
  end
end
