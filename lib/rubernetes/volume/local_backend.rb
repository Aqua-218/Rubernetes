# frozen_string_literal: true

module Rubernetes
  module Volume
    class LocalBackend < HostPathBackend
      TYPE = "local"

      def source_path
        @host_source_path || super
      end

      def stage(path:, node:, readonly: false, context: {})
        kind = host_path_type
        source = @host_handle ? @host_source_path : raw_host_path
        handle = @host_handle || open_host_handle(source, kind: kind, allow_missing: false)
        source = resolved_host_path(handle, source)
        identity = local_source_identity(handle, source, kind)
        raise PathSecurityError, "local volume source #{source.inspect} changed before staging" if @local_source_identity && @local_source_identity != identity

        mounted = mount_stage(path, source: source, readonly: readonly, options: mount_options(context), source_handle: handle)
        @local_source_identity = identity
        @host_source_path = source
        # The stage is an independent bind. Keeping a descriptor on the
        # original after mounting would prevent its owner from unmounting it.
        @host_handle = nil
        mounted
      ensure
        handle&.close unless handle.equal?(@host_handle)
      end

      def delete
        @local_source_identity = nil
        super
      end

      private

      # Local volumes require storage prepared by the operator. The same
      # descriptor inspection as HostPath is used with source creation disabled.
      def open_host_handle(path, kind:, **)
        super(path, kind: kind, allow_missing: false)
      rescue PathSecurityError => error
        raise unless missing_path_error?(error)

        raise LocalSourceNotFoundError, "local volume path #{path.inspect} does not exist"
      end

      def local_source_identity(handle, source, kind)
        stat = host_path_stat(handle, source)
        validate_host_stat!(stat, source, kind)
        [source, stat.dev, stat.ino, stat.rdev, local_mountinfo(handle)].freeze
      end

      def local_mountinfo(handle)
        return unless RUBY_PLATFORM.include?("linux") && handle.is_a?(PathSecurity::Handle)
        return unless @path_security.is_a?(PathSecurity) && @path_security.resolver.is_a?(PathSecurity::Resolver)

        descriptor = handle.fd
        descriptor = descriptor.fileno if descriptor.is_a?(IO)
        return unless descriptor.is_a?(Integer)

        id = @path_security.resolver.mount_id_of(descriptor)
        # Linux can immediately recycle a mount ID. The record also checks
        # flags on a replacement bind of the same underlying inode.
        record = File.foreach("/proc/self/mountinfo").find { |entry| entry.start_with?("#{id} ") } if id
        record || raise(PathSecurityError, "local volume source mount identity is unavailable")
      rescue SystemCallError, IOError => error
        raise PathSecurityError, "local volume source mount identity could not be read: #{error.message}"
      end

      def host_path_type
        Types.key(spec, "volumeMode") == "Block" ? "BlockDevice" : super
      end

      def validate_host_stat!(stat, path, kind)
        super
      rescue ValidationError => error
        raise unless kind == "BlockDevice"

        raise LocalBlockDeviceError, error.message
      end
    end
  end
end
