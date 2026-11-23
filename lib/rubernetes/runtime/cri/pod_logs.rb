# frozen_string_literal: true

require "digest/sha2"
require "fileutils"
require_relative "../../platform/linux/secure_rootfs"

module Rubernetes
  module Runtime
    module CRI
      # Pod log directories outlive individual sandboxes and lifecycle records.
      # Mark only directories we create, and tie the marker to that inode.
      class PodLogs
        Openat2 = Platform::Linux::Openat2
        SecureRootfs = Platform::Linux::SecureRootfs
        Xattr = Platform::Linux::Xattr
        OWNERSHIP = "user.rubernetes.cri-pod-logs"
        NAME = /\A[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\z/
        LOOKUP_ERRORS = [Errno::ENOENT::Errno, Errno::ENOTDIR::Errno, Errno::ELOOP::Errno, Errno::EXDEV::Errno].freeze

        def initialize(root, handler:, client:)
          @root = File.expand_path(root)
          endpoint = client.endpoint if client.is_a?(Client)
          @owner = Digest::SHA256.digest("#{handler}\0#{endpoint}")
        end

        def path_for(metadata) = File.join(@root, directory_name(metadata))

        def prepare(metadata, node_name: nil)
          name = directory_name(metadata)
          FileUtils.mkdir_p(@root)
          with_root do |root, resolver|
            created = create_directory(root, name)
            with_directory(resolver, name) do |directory, stat|
              source = static_pod?(metadata) ? "static" : "api"
              Xattr.fset(directory.fileno, OWNERSHIP, ownership(name, stat, source, node_name)) if created && trusted?(root.stat) && trusted?(stat)
              true
            end or raise Backend::Error, "CRI log directory is unavailable: #{name}"
          end
        rescue Platform::Linux::Error => error
          # A backing filesystem without xattrs can store the logs, but the
          # agent cannot later establish ownership of the directory.
          raise unless error.errno == Errno::EOPNOTSUPP::Errno
        end

        def api_pods(node_name: nil)
          with_root do |root, resolver|
            next [] unless trusted?(root.stat)

            Dir.each_child("/proc/self/fd/#{root.fileno}").filter_map do |name|
              metadata = parse_name(name)
              next unless metadata

              with_directory(resolver, name) do |directory, stat|
                metadata if trusted?(stat) && marker(directory) == ownership(name, stat, "api", node_name)
              end
            end
          end
        rescue Errno::ENOENT, Errno::ENOTDIR, Errno::ELOOP
          []
        end

        def remove(metadata, node_name: nil)
          name = safe_name(metadata)
          return false unless name

          with_root do |root, resolver|
            next false unless trusted?(root.stat)

            with_directory(resolver, name) do |directory, stat|
              next false unless owned?(directory, stat, name, node_name)

              yield if block_given?
              remove_directory(root, name, stat)
            end
          end
        rescue Errno::ENOENT, Errno::ENOTDIR, Errno::ELOOP
          false
        end

        private

        def directory_name(metadata)
          safe_name(metadata) || raise(Backend::Error, "CRI log directory requires a valid Pod namespace, name and UID")
        end

        def safe_name(metadata)
          values = metadata.values_at("namespace", "name", "uid")
          values.join("_") if values.all? { |value| NAME.match?(value.to_s.b) }
        end

        def parse_name(name)
          fields = name.split("_", -1)
          %w[namespace name uid].zip(fields).to_h if fields.length == 3 && fields.all? { |value| NAME.match?(value.b) }
        end

        def static_pod?(metadata)
          %w[file http].include?(metadata.dig("annotations", "kubernetes.io/config.source")) &&
            metadata.dig("annotations", "kubernetes.io/config.hash") == metadata["uid"]
        end

        def trusted?(stat) = stat.uid == Process.euid && stat.mode.nobits?(0o022)

        def ownership(name, stat, source, node_name)
          Digest::SHA256.digest([@owner, source, node_name, stat.dev, stat.ino, name].join("\0"))
        end

        def owned?(directory, stat, name, node_name)
          return false unless trusted?(stat)

          current = marker(directory)
          %w[api static].any? { |source| current == ownership(name, stat, source, node_name) }
        end

        def marker(directory)
          Xattr.fget(directory.fileno, OWNERSHIP)
        rescue Platform::Linux::Error => error
          raise unless error.errno == Errno::EOPNOTSUPP::Errno
        end

        def with_root
          File.open(@root, File::RDONLY | File::NOFOLLOW | Openat2::O_DIRECTORY) do |root|
            resolver = Openat2.new(root: @root, root_fd: root.fileno)
            yield root, resolver
          ensure
            resolver&.close
          end
        end

        def with_directory(resolver, name)
          handle = resolver.open(name, flags: File::RDONLY | Openat2::O_DIRECTORY)
          # The handle owns the descriptor. The wrapper only supplies fstat.
          directory = IO.for_fd(handle.fd, autoclose: false)
          yield directory, directory.stat
        rescue Platform::Linux::Error => error
          raise unless LOOKUP_ERRORS.include?(error.errno)

          nil
        ensure
          handle&.close
        end

        def create_directory(root, name)
          Dir.mkdir("/proc/self/fd/#{root.fileno}/#{name}", 0o755)
          true
        rescue Errno::EEXIST
          false
        end

        def remove_directory(root, name, stat)
          filesystem = SecureRootfs.new(root: @root, root_io: root)
          filesystem.remove(name, expected_identity: [stat.dev, stat.ino, stat.mode])
        ensure
          filesystem&.close
        end
      end
    end
  end
end
