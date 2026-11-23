# frozen_string_literal: true

require "open3"
require_relative "iscsi_sessions"

module Rubernetes
  module Volume
    # Resolves in-tree SAN volumes to Linux block devices. WWID lookups
    # must still identify an FC transport, and a multipath holder must have
    # a device-mapper multipath UUID.
    class LinuxStorageDevices
      COMMANDS = {
        "iscsiadm" => %w[/usr/sbin/iscsiadm /sbin/iscsiadm],
        "blkid" => %w[/usr/sbin/blkid /sbin/blkid],
        "mkfs.ext4" => %w[/usr/sbin/mkfs.ext4 /sbin/mkfs.ext4],
        "mkfs.xfs" => %w[/usr/sbin/mkfs.xfs /sbin/mkfs.xfs]
      }.freeze
      DISCOVERY_TIMEOUT = 20

      def initialize(data_dir:, fsync: true, dev: "/dev", sys: "/sys", runner: nil)
        @data_dir = data_dir
        @dev = dev
        @sys = sys
        @runner = runner || method(:run)
        @sessions = ISCSISessions.new(data_dir: data_dir, fsync: fsync, runner: @runner)
      end

      def with_device(backend, readonly:, credentials:)
        paths = if backend.is_a?(ISCSIBackend)
                  iscsi_paths(backend, credentials)
                else
                  fc_paths(backend)
                end
        path = paths.filter_map { |device| multipath_device(device) }.first || paths.first
        raise Error, "#{backend.type} LUN is not visible on this node" unless path

        File.open(path, File::RDONLY | File::NONBLOCK | File::NOFOLLOW) do |handle|
          raise MountIdentityError, "#{backend.type} source changed before opening" unless handle.stat.blockdev? && File.identical?(path, handle)

          lock = File.join(@data_dir, "storage-block-#{handle.stat.rdev}.lock")
          File.open(lock, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |file|
            file.flock(File::LOCK_EX)
            prepare_filesystem(handle, backend.filesystem, readonly: readonly) if backend.filesystem
            yield path, handle
          end
        end
      end

      def release(backend)
        @sessions.release(backend.id) if backend.is_a?(ISCSIBackend)
      end

      private

      def prepare_filesystem(handle, filesystem, readonly:)
        descriptor = handle.fileno
        pinned_path = "/proc/self/fd/#{descriptor}"
        flags = {descriptor => handle}
        output, status = @runner.call("blkid", %W[-p -o export -- #{pinned_path}], flags)
        if status == 0
          format = output.lines.find { |line| line.start_with?("TYPE=") }&.delete_prefix("TYPE=")&.strip
          raise ValidationError, "disk format #{format.inspect} does not match requested #{filesystem.inspect} filesystem" unless format == filesystem

          return
        end
        raise Error, "cannot determine SAN disk format (blkid exit #{status})" unless status == 2
        raise ValidationError, "cannot format an unformatted read-only disk" if readonly
        raise UnsupportedError, "formatting an unformatted #{filesystem} disk is unsupported" unless %w[ext4 xfs].include?(filesystem)

        options = filesystem == "ext4" ? ["-m", "0"] : []
        _output, status = @runner.call("mkfs.#{filesystem}", [*options, "--", pinned_path], flags)
        raise Error, "cannot format SAN disk as #{filesystem} (mkfs exit #{status})" unless status == 0
      end

      def fc_paths(backend)
        paths = find_fc_paths(backend)
        return paths unless paths.empty?

        Dir.glob(File.join(@sys, "class", "fc_host", "host*", "device", "scsi_host", "host*", "scan")).each do |scan|
          File.write(scan, "- - -")
        end
        wait_for_paths { find_fc_paths(backend) }
      end

      def find_fc_paths(backend)
        ids = File.join(@dev, "disk", "by-id")
        paths = backend.wwids.map { |wwid| File.join(ids, "scsi-#{wwid.tr(" ", "_")}") }
        unless backend.target_wwns.empty?
          dir = File.join(@dev, "disk", "by-path")
          suffixes = backend.target_wwns.map { |wwn| "fc-0x#{wwn.downcase}-lun-#{backend.lun}" }
          paths = children(dir).filter_map do |name|
            next unless suffixes.any? { |suffix| name.downcase == suffix || name.downcase.end_with?("-#{suffix}") }

            File.join(dir, name)
          end
        end

        paths.filter_map do |link|
          device = block_device(link)
          device if device && fc_device?(device)
        end.uniq
      end

      def fc_device?(device)
        physical = File.realpath(File.join(@sys, "class", "block", File.basename(device), "device"))
        host = physical.split("/").find { |component| component.match?(/\Ahost[0-9]+\z/) }
        host && File.directory?(File.join(@sys, "class", "fc_host", host))
      rescue Errno::ENOENT, Errno::ENOTDIR
        false
      end

      def iscsi_paths(backend, credentials)
        errors = []
        active = backend.portals.filter_map do |portal|
          @sessions.connect(backend, portal, credentials)
        rescue Error => error
          errors << error
          nil
        end
        raise errors.first if active.empty? && !errors.empty?

        wait_for_paths { find_iscsi_paths(backend, active) }
      end

      def find_iscsi_paths(backend, active)
        return [] if active.empty?

        # Select block devices from the kernel sessions that the daemon
        # recorded, by their SCSI LUN. A by-path link alone does not encode
        # the iSCSI interface and can refer to a different initiator.
        session_root = File.join(@sys, "class", "iscsi_session")
        active.flat_map do |session|
          Dir.glob(File.join(session_root, "session#{session}", "device", "target*", "*:*:*:#{backend.lun}", "block", "*"))
            .filter_map { |entry| block_device(File.join(@dev, File.basename(entry))) }
        end.uniq
      end

      def wait_for_paths
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + DISCOVERY_TIMEOUT
        loop do
          paths = yield
          return paths unless paths.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

          sleep(0.25)
        end
      end

      def multipath_device(device)
        holders = File.join(@sys, "class", "block", File.basename(device), "holders")
        children(holders).each do |holder|
          uuid_file = File.join(@sys, "class", "block", holder, "dm", "uuid")
          next unless File.file?(uuid_file) && File.read(uuid_file).start_with?("mpath-")

          path = block_device(File.join(@dev, holder))
          return path if path
        end
        nil
      end

      def block_device(path)
        canonical = File.realpath(path)
        canonical if File.dirname(canonical) == @dev && File.blockdev?(canonical)
      rescue Errno::ENOENT, Errno::ENOTDIR
        nil
      end

      def children(path)
        File.directory?(path) ? Dir.children(path).sort : []
      end

      def run(command, arguments, spawn_options = {})
        executable = COMMANDS.fetch(command).find { |candidate| File.executable?(candidate) }
        raise UnsupportedError, "#{command} is required for SAN volumes" unless executable

        output, status = Open3.capture2e({"LC_ALL" => "C"}, "/usr/bin/timeout", "--kill-after=5s", "45s",
                                         executable, *arguments, **spawn_options)
        [output, status.exitstatus || (128 + status.termsig)]
      rescue SystemCallError
        raise Error, "unable to run #{command} for SAN volume"
      end
    end
  end
end
