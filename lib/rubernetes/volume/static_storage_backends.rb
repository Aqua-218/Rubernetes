# frozen_string_literal: true

require "ipaddr"
require "socket"

module Rubernetes
  module Volume
    # These volumes point at existing storage. Creating or deleting a Pod's
    # volume record does not create or delete the remote export or disk.
    class StaticStorageBackend < Backend
      def initialize(**)
        super
        mode = Types.key(spec, "volumeMode", "Filesystem")
        raise UnsupportedError, "#{type} does not support volumeMode #{mode.inspect}" unless supported_volume_modes.include?(mode)

        @options = Array(Types.key(spec, "mountOptions")).flat_map { |option| String(option).split(",") }
          .map(&:strip).reject(&:empty?).uniq.freeze
        forbidden = %w[bind rbind rec remount move shared rshared private rprivate slave rslave unbindable runbindable]
        return unless @options.any? { |option| option.include?("\0") || forbidden.include?(option.partition("=").first.strip.downcase) }

        raise ValidationError, "#{type} mount options must describe a new filesystem mount"
      end

      def readonly?
        Types.key(spec, "readOnly") == true || @options.include?("ro")
      end

      def persistent?
        true
      end

      def provision
        {"source" => source_path, "backend" => type, "readonly" => readonly?}
      end

      def delete
        true
      end

      def snapshot(**)
        raise UnsupportedError, "#{type} requires a separate storage driver for snapshots"
      end

      def restore(**)
        raise UnsupportedError, "#{type} requires a separate storage driver to restore a snapshot"
      end

      def clone_from(**)
        raise UnsupportedError, "#{type} requires a separate storage driver for clones"
      end

      def expand(**)
        raise UnsupportedError, "#{type} does not support volume expansion"
      end

      def mount_options(_context)
        @options
      end

      def supported_volume_modes
        ["Filesystem"]
      end

      def self.host(value)
        host = value.to_s.delete_prefix("[").delete_suffix("]")
        return host if host.include?(":") && IPAddr.new(host).ipv6?
        return host if host.match?(/\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9.])?\z/)

        raise ValidationError, "invalid storage server address"
      rescue IPAddr::InvalidAddressError
        raise ValidationError, "invalid storage server address"
      end
    end

    class NFSBackend < StaticStorageBackend
      TYPE = "nfs"
      FALLBACK_ERRNOS = [Errno::EPROTONOSUPPORT::Errno, Errno::EOPNOTSUPP::Errno, Errno::ENODEV::Errno, Errno::ENOENT::Errno].freeze

      def initialize(**)
        super
        @host = self.class.host(Types.key(spec, "server"))
        @export = Types.key(spec, "path").to_s
        return if @export.start_with?("/") && !@export.match?(/[\x00-\x1f\x7f]/)

        raise ValidationError, "NFS export path must be absolute and contain no control characters"
      end

      def source_path
        server = @host.include?(":") ? "[#{@host}]" : @host
        "#{server}:#{@export}"
      end

      def filesystem
        TYPE
      end

      def stage(path:, node:, readonly: false, context: {})
        return super unless require_real_readback

        # Kernel text-based NFS mounts need the server's numeric address.
        # Supply it ourselves so the mount uses the held target descriptor.
        options = mount_options(context).reject { |option| option.start_with?("addr=") }
        addr = Addrinfo.getaddrinfo(@host, nil, nil, :STREAM, timeout: 10).first&.ip_address
        raise Error, "cannot resolve NFS server #{@host.inspect}" unless addr

        options << "addr=#{addr}"
        explicit_version = options.any? { |option| option.match?(/\A(?:vers|nfsvers)=/) }
        if explicit_version || options.any? { |option| option.start_with?("minorversion=") }
          options << "vers=4" unless explicit_version
          return mount_stage(path, source: source_path, readonly: readonly, options: options)
        end

        # A v3 export name may be absent from the v4 pseudo-filesystem.
        # Negotiate versions against the same export without rewriting its path.
        %w[4.2 4.1 4 3].each do |version|
          return mount_stage(path, source: source_path, readonly: readonly, options: options + ["vers=#{version}"])
        rescue Rubernetes::Platform::Linux::Error => error
          raise unless version != "3" && FALLBACK_ERRNOS.include?(error.errno)
        end
      rescue SocketError
        raise Error, "cannot resolve NFS server #{@host.inspect}"
      end
    end

    class SCSIBackend < StaticStorageBackend
      def initialize(storage_devices:, **)
        super(**)
        @storage_devices = storage_devices
        @filesystem = Types.key(spec, "fsType").to_s
        @filesystem = "ext4" if @filesystem.empty?
        return if @filesystem.match?(/\A[a-zA-Z0-9][a-zA-Z0-9_-]*\z/)

        raise ValidationError, "invalid #{type} filesystem type"
      end

      def filesystem
        @filesystem if target_directory?
      end

      def supported_volume_modes
        %w[Filesystem Block]
      end

      def source_path
        unique_name
      end

      def stage(path:, node:, readonly: false, context: {})
        raise UnsupportedError, "#{type} requires a Linux storage device adapter" unless @storage_devices

        read_only = readonly || readonly?
        @storage_devices.with_device(self, readonly: read_only, credentials: Types.key(context, "iscsiCredentials", {})) do |device, handle|
          identity = stage_device(path, device, handle, readonly: read_only, options: mount_options(context))
          identity.merge("sharedSource" => Types.digest(unique_name))
        end
      end

      def mount_options(context)
        return [] unless target_directory?

        options = super
        label = Types.key(spec, "selinuxMountLabel").to_s
        label.empty? ? options : options + [SELinux.mount_option(label)]
      end

      def delete
        @storage_devices&.release(self)
        super
      end

      private

      def stage_device(path, device, device_handle, readonly:, options:)
        mount_stage(path, source: device, source_handle: device_handle, readonly: readonly, options: options)
      rescue Rubernetes::Platform::Linux::Error => error
        # Linux refuses separate read-only and writable mounts of the same
        # block superblock. A reader can use a read-only clone of the mounted
        # filesystem. Verify the source mount through its own descriptor.
        raise unless readonly && filesystem && device_handle && error.errno == Errno::EBUSY::Errno

        stat = device_handle.stat
        device_id = "#{stat.rdev_major}:#{stat.rdev_minor}"
        mounts = AdapterSupport.call(@mount_adapter, :list_mounts)
        existing = mounts&.find do |entry|
          entry["deviceId"] == device_id && entry["root"] == "/" && entry["filesystem"] == filesystem &&
            entry["filesystemUuidAvailable"] && entry["options"].split(",").include?("rw")
        end
        raise unless existing

        source = existing.fetch("target")
        source_handle = open_stage_handle(source)
        mount_id = File.read("/proc/self/fdinfo/#{source_handle.fd}")[/^mnt_id:\s*(\d+)/, 1]
        raise MountIdentityError, "#{type} filesystem changed before read-only bind" unless mount_id == existing["mountId"].to_s

        mount_stage(path, source: source, source_handle: source_handle, readonly: true, options: options, requested_filesystem: nil)
      ensure
        source_handle&.close
      end
    end

    class ISCSIBackend < SCSIBackend
      TYPE = "iscsi"
      TARGET_NAME = /\A(?:iqn\.|eui\.|naa\.)[a-zA-Z0-9_.:-]+\z/

      attr_reader :target, :portals, :lun, :interface, :initiator

      def initialize(**)
        super
        @target = Types.key(spec, "iqn").to_s
        raise ValidationError, "invalid iSCSI target name" unless TARGET_NAME.match?(@target)

        @lun = Integer(Types.key(spec, "lun", 0))
        raise ValidationError, "invalid iSCSI LUN" unless (0..255).cover?(@lun)

        @portals = [Types.key(spec, "targetPortal"), *Array(Types.key(spec, "portals"))].map { |value| normalize_portal(value) }.uniq.freeze
        @interface = Types.key(spec, "iscsiInterface").to_s
        @interface = "default" if @interface.empty?
        raise ValidationError, "invalid iSCSI interface name" unless @interface.match?(/\A[a-zA-Z0-9][a-zA-Z0-9_.:-]*\z/)

        @initiator = Types.key(spec, "initiatorName").to_s
        raise ValidationError, "invalid iSCSI initiator name" if !@initiator.empty? && !TARGET_NAME.match?(@initiator)
      rescue ArgumentError, TypeError
        raise ValidationError, "invalid iSCSI LUN"
      end

      def unique_name
        self.class.unique_name(spec)
      end

      def self.unique_name(spec)
        "kubernetes.io/iscsi/#{Types.key(spec, "targetPortal")}:#{Types.key(spec, "iqn")}:#{Types.key(spec, "lun", 0)}"
      end

      def discovery_chap?
        Types.key(spec, "chapAuthDiscovery") == true
      end

      def session_chap?
        Types.key(spec, "chapAuthSession") == true
      end

      def authentication_identity
        [discovery_chap?, session_chap?, Types.key(spec, "secretRef")]
      end

      private

      def normalize_portal(value)
        portal = value.to_s
        if portal.start_with?("[")
          match = /\A\[([^\]]+)\](?::(\d+))?\z/.match(portal)
          raise ValidationError, "invalid iSCSI portal" unless match

          host, port = match.captures
        elsif portal.count(":") > 1
          host = portal
        else
          host, port = portal.split(":", -1)
        end
        host = self.class.host(host)
        port ||= "3260"
        raise ValidationError, "invalid iSCSI portal port" unless port.match?(/\A[0-9]{1,5}\z/) && (1..65_535).cover?(port.to_i)

        host = "[#{host}]" if host.include?(":")
        "#{host}:#{port.to_i}"
      end
    end

    class FibreChannelBackend < SCSIBackend
      TYPE = "fc"

      attr_reader :target_wwns, :wwids, :lun

      def initialize(**)
        super
        @target_wwns = Array(Types.key(spec, "targetWWNs")).map(&:to_s).freeze
        @wwids = Array(Types.key(spec, "wwids")).map(&:to_s).freeze
        if !@target_wwns.empty? && @wwids.empty?
          @lun = Integer(Types.key(spec, "lun"))
          unless (0..255).cover?(@lun) && @target_wwns.all? { |wwn| wwn.match?(/\A[0-9a-fA-F]{16}\z/) }
            raise ValidationError, "invalid Fibre Channel WWN or LUN"
          end
        elsif @target_wwns.empty? && !@wwids.empty?
          raise ValidationError, "invalid Fibre Channel WWID" unless @wwids.all? { |wwid| wwid.match?(/\A[a-zA-Z0-9][a-zA-Z0-9_.: +-]*\z/) }
        else
          raise ValidationError, "Fibre Channel requires WWNs with a LUN or WWIDs"
        end
      rescue ArgumentError, TypeError
        raise ValidationError, "invalid Fibre Channel LUN"
      end

      def unique_name
        self.class.unique_name(spec)
      end

      def self.unique_name(spec)
        wwns = Array(Types.key(spec, "targetWWNs"))
        return "kubernetes.io/fc/[#{wwns.join(" ")}]:#{Types.key(spec, "lun")}" unless wwns.empty?

        "kubernetes.io/fc/[#{Array(Types.key(spec, "wwids")).join(" ")}]"
      end
    end
  end
end
