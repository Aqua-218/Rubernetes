# frozen_string_literal: true

require "pathname"

module Rubernetes
  module Volume
    # Descriptor-relative path validation boundary.  No pathname fallback is
    # permitted for hostPath or subPath: callers must inject an openat2-like
    # resolver (or the supplied Linux adapter) and retain its fd identity.
    class PathSecurity
      Handle = Struct.new(:fd, :path, :root, :identity, keyword_init: true) do
        def to_h
          {"fd" => fd, "path" => path, "root" => root, "identity" => identity}
        end

        def close
          descriptor = fd
          self.fd = nil
          return true unless descriptor
          return descriptor.close if descriptor.respond_to?(:close)
          return IO.for_fd(descriptor).close if descriptor.is_a?(Integer)

          true
        rescue IOError, SystemCallError
          true
        end

        def stat
          return fd.stat if fd.respond_to?(:stat)
          return IO.for_fd(fd, autoclose: false).stat if fd.is_a?(Integer)

          File.stat(File.join(root, path))
        end
      end

      # A target lease anchors CSI pathname dispatch to an already-opened
      # inode. The plugin receives /proc/<agent-pid>/fd/<fd>, so renaming or
      # replacing the user-visible path cannot redirect the in-flight RPC.
      class TargetLease
        attr_reader :original_path, :dispatch_path, :handle, :parent_handle, :identity

        def initialize(original_path:, dispatch_path:, handle:, parent_handle:)
          @original_path = original_path.to_s.freeze
          @dispatch_path = dispatch_path.to_s.freeze
          @handle = handle
          @parent_handle = parent_handle
          @leaf_name = File.basename(@original_path).freeze
          @identity = stat_identity(handle).freeze
          @parent_identity = stat_identity(parent_handle).freeze
          @closed = false
          @leaf_released = false
        end

        # umount2(2) refuses (EBUSY) a mount that any descriptor still pins,
        # and the leaf handle of this lease is exactly such a descriptor.  For
        # the unmount the leaf is released and the target is addressed through
        # the still-pinned parent descriptor plus the leaf name, so a rename or
        # replacement of the parent cannot redirect the syscall.  The returned
        # path is only valid inside this process.
        def release_leaf_for_unmount!
          raise PathSecurityError, "volume target lease is closed" if @closed

          parent_fd = parent_descriptor

          unless @leaf_released
            handle&.close
            @leaf_released = true
          end
          "/proc/#{Process.pid}/fd/#{parent_fd}/#{@leaf_name}"
        end

        def leaf_released?
          @leaf_released
        end

        def parent_descriptor
          raw = parent_handle.respond_to?(:fd) ? parent_handle.fd : parent_handle
          descriptor_number(raw)
        end

        # Revalidate both the held parent/leaf descriptors and the visible
        # pathname. A mounted target changes the identity returned by
        # stat(original_path), so mounted verification additionally binds the
        # visible and descriptor-relative leaves to the mountinfo entry.
        def verify_original!(mounted: false, mount_identity: nil)
          verify_descriptor_identity!
          reject_visible_symlink_components!
          parent_path_identity = descriptor_identity(File.dirname(original_path))
          verify_identity_match!(parent_path_identity, @parent_identity, "volume target parent changed")

          if mounted
            # The first post-syscall check runs before mountinfo readback is
            # available. It can still reject a missing/symlink replacement;
            # the mountinfo-bound identity check runs immediately afterward.
            return true unless mount_identity

            verify_mounted_target!(mount_identity)
          elsif @leaf_released
            # After an unmount the leaf identity legitimately changes (the
            # underlying directory is visible again); the parent descriptor
            # and a non-symlink leaf are what remain provable.
            stat = File.lstat(File.join("/proc/#{Process.pid}/fd/#{parent_descriptor}", @leaf_name))
            raise PathSecurityError, "volume target was replaced by a symlink while its lease was active" if stat.symlink?
          else
            current_identity = descriptor_identity(original_path)
            verify_identity_match!(current_identity, identity, "volume target changed while its descriptor lease was active")
          end
          true
        rescue Errno::ENOENT
          raise PathSecurityError, "volume target disappeared while its descriptor lease was active"
        rescue SystemCallError => error
          raise PathSecurityError, "volume target identity could not be revalidated: #{error.message}"
        end

        def close
          return true if @closed

          @closed = true
          handle&.close
          parent_handle&.close
          true
        end

        private

        def verify_descriptor_identity!
          unless @leaf_released
            verify_identity_match!(stat_identity(handle), identity,
                                   "held volume target descriptor identity changed")
          end
          verify_identity_match!(stat_identity(parent_handle), @parent_identity,
                                 "held volume target parent descriptor identity changed")
        end

        def verify_mounted_target!(mount_identity)
          observed = mount_identity.respond_to?(:to_h) ? mount_identity.to_h.transform_keys(&:to_s) : mount_identity
          raise PathSecurityError, "mounted volume target identity is unavailable" unless observed.respond_to?(:fetch)

          observed_target = observed["target"] || observed["mountpoint"]
          observed_mount_id = observed["mountId"] || observed["mount_id"]
          unless observed_target && observed_mount_id && !observed_mount_id.to_s.empty?
            raise PathSecurityError, "mounted volume target lacks a mountinfo target or mount id"
          end
          unless File.expand_path(observed_target.to_s) == File.expand_path(original_path)
            raise PathSecurityError, "mountinfo target does not match the leased volume target"
          end

          visible_identity = descriptor_identity(original_path)
          # A mountinfo id equal to the lease's original mount means that no
          # new mount is covering the held leaf. In that case the visible
          # pathname must still resolve to the original ordinary directory;
          # comparing only the parent fd would miss a same-parent leaf swap.
          if visible_identity.fetch("mountId").to_s == identity.fetch("mountId").to_s
            verify_identity_match!(visible_identity, identity, "volume target directory was replaced after mount readback")
            return true
          end

          held_identity = descriptor_identity(held_leaf_path)
          unless visible_identity.fetch("mountId").to_s == observed_mount_id.to_s &&
                 held_identity.fetch("mountId").to_s == observed_mount_id.to_s
            raise PathSecurityError, "mountinfo cannot prove that the leased volume target remains mounted"
          end
          unless visible_identity.fetch("device") == held_identity.fetch("device") &&
                 visible_identity.fetch("inode") == held_identity.fetch("inode")
            raise PathSecurityError, "volume target directory was replaced after mount readback"
          end

          true
        end

        def verify_identity_match!(observed, expected, message)
          unless observed.fetch("device") == expected.fetch("device") &&
                 observed.fetch("inode") == expected.fetch("inode") &&
                 observed.fetch("mountId").to_s == expected.fetch("mountId").to_s
            raise PathSecurityError, message
          end

          true
        end

        def stat_identity(target)
          stat = target.respond_to?(:stat) ? target.stat : nil
          raise PathSecurityError, "volume target descriptor did not expose stat identity" unless stat

          {
            "device" => stat.dev,
            "inode" => stat.ino,
            "mode" => stat.mode,
            "mountId" => mount_id_for(descriptor_number(target.respond_to?(:fd) ? target.fd : target))
          }
        end

        def descriptor_identity(path)
          descriptor = IO.sysopen(path, path_open_flags)
          io = IO.for_fd(descriptor)
          stat = io.stat
          {"device" => stat.dev, "inode" => stat.ino, "mode" => stat.mode,
           "mountId" => mount_id_for(io.fileno)}
        ensure
          io&.close
        end

        def held_leaf_path
          parent_fd = descriptor_number(parent_handle.fd)
          "/proc/self/fd/#{parent_fd}/#{@leaf_name}"
        end

        def path_open_flags
          path_flag = if defined?(File::O_PATH)
                        File::O_PATH
                      else
                        0x200000
                      end
          path_flag | File::NOFOLLOW
        end

        def reject_visible_symlink_components!
          current = File::SEPARATOR
          original_path.split(File::SEPARATOR).reject(&:empty?).each do |component|
            current = File.join(current, component)
            stat = File.lstat(current)
            raise PathSecurityError, "volume target path component #{component.inspect} is a symlink" if stat.symlink?
          end
          true
        end

        def descriptor_number(value)
          return value.fileno if value.respond_to?(:fileno)
          return Integer(value) if value.is_a?(Integer)

          raise PathSecurityError, "volume target lease did not expose a descriptor"
        end

        def mount_id_for(descriptor)
          line = File.foreach("/proc/self/fdinfo/#{descriptor}").find { |entry| entry.start_with?("mnt_id:") }
          raise PathSecurityError, "volume target lease did not expose a mount identity" unless line

          Integer(line.split(":", 2).last, 10)
        rescue ArgumentError, SystemCallError, IOError => error
          raise PathSecurityError, "volume target mount identity could not be read: #{error.message}"
        end
      end

      class Resolver
        def initialize(root:, adapter: nil, require_openat2: true)
          @root = File.expand_path(String(root))
          raise PathSecurityError, "configured path-security root must not be a symlink" if File.symlink?(@root)

          @adapter = adapter
          @require_openat2 = require_openat2 == true
        end

        attr_reader :root

        def descriptor_capable?
          !@adapter.nil?
        end

        def validate!(path, allow_absolute: false)
          value = String(path)
          raise PathSecurityError, "path must not contain NUL" if value.include?("\0")
          raise PathSecurityError, "path must not be empty" if value.empty?
          raise PathSecurityError, "absolute paths require an explicit configured root" if value.start_with?("/") && !allow_absolute

          components = value.split("/")
          raise PathSecurityError, "path contains parent traversal" if components.include?("..")

          empty_components = value.start_with?("/") ? components.drop(1) : components
          raise PathSecurityError, "path contains an empty component" if empty_components.any?(&:empty?)
          raise PathSecurityError, "path contains a current-directory component" if components.include?(".")

          value
        rescue TypeError
          raise PathSecurityError, "path must be a string"
        end

        def relative(path)
          value = validate!(path, allow_absolute: true)
          return value unless value.start_with?("/")

          absolute = File.expand_path(value)
          root_prefix = @root.end_with?(File::SEPARATOR) ? @root : "#{@root}#{File::SEPARATOR}"
          raise PathSecurityError, "path #{value.inspect} escapes configured root" unless absolute == @root || absolute.start_with?(root_prefix)

          relative = Pathname.new(absolute).relative_path_from(Pathname.new(@root)).to_s
          return "." if relative == "."
          raise PathSecurityError, "path resolves outside configured root" if relative == ".." || relative.start_with?("../")

          validate!(relative)
        end

        # kubelet setupDataDirs makes its root directory a shared mount
        # (MakeRShared) so container runtimes see the binds it makes later;
        # our Pod root is the same kind of mount.  A lookup from the
        # configured root with RESOLVE_NO_XDEV would stop at that mount
        # boundary with EXDEV, so a registered boundary is opened as a mount
        # point (strict parent, crossing leaf) and the rest of the path is
        # resolved beneath that descriptor, again without crossing anything.
        def allow_mount_boundary!(path)
          boundary = relative(path)
          raise PathSecurityError, "the configured root cannot be a mount boundary" if boundary == "."

          @mount_boundaries ||= []
          @mount_boundaries << boundary unless @mount_boundaries.include?(boundary)
          boundary
        end

        def mount_boundaries
          Array(@mount_boundaries).dup
        end

        def open(path, flags: nil, mode: 0, resolve: nil, resource_id: nil)
          relative_path = relative(path)
          if @adapter && (boundary = mount_boundary_for(relative_path))
            return open_across_boundary(boundary, relative_path, flags: flags, mode: mode, resolve: resolve,
                                                                 resource_id: resource_id)
          end
          unless @adapter
            raise PathSecurityError, "openat2 adapter is required for descriptor-relative volume paths" if @require_openat2

            reject_symlink_components!(relative_path)

            return Handle.new(fd: nil, path: relative_path, root: @root,
                              identity: stable_identity(relative_path))
          end

          flags ||= if @adapter.class.const_defined?(:O_PATH)
                      @adapter.class::O_PATH
                    elsif defined?(Rubernetes::Platform::Linux::Openat2::O_PATH)
                      Rubernetes::Platform::Linux::Openat2::O_PATH
                    else
                      0
                    end
          resolve ||= if @adapter.class.const_defined?(:DEFAULT_RESOLVE)
                        @adapter.class::DEFAULT_RESOLVE
                      elsif defined?(Rubernetes::Platform::Linux::Openat2::DEFAULT_RESOLVE)
                        Rubernetes::Platform::Linux::Openat2::DEFAULT_RESOLVE
                      else
                        0x08 | 0x04 | 0x02 | 0x01
                      end

          raw = if @adapter.respond_to?(:open)
                  @adapter.open(relative_path, flags: flags, mode: mode, resolve: resolve, resource_id: resource_id)
                elsif @adapter.respond_to?(:resolve)
                  @adapter.resolve(relative_path, flags: flags, mode: mode, resolve: resolve, resource_id: resource_id)
                elsif @adapter.respond_to?(:openat2)
                  @adapter.openat2(path: relative_path, flags: flags, mode: mode, resolve: resolve, resource_id: resource_id)
                else
                  raise PathSecurityError, "openat2 adapter does not expose open, resolve, or openat2"
                end
          normalize_handle(raw, relative_path)
        rescue PathSecurityError
          raise
        rescue StandardError => error
          raise PathSecurityError, "openat2 rejected #{path.inspect}: #{error.message}", cause: error
        end

        alias resolve open
        alias resolve_fd open

        # CSI creates staging and publish targets itself, so the leaf may not
        # exist when Ruby validates the request. Existing path components
        # must nevertheless be symlink-free before the RPC is allowed.
        def validate_target!(path)
          relative_path = relative(path)
          reject_symlink_components!(relative_path)
          path.to_s
        end

        # A staged volume's path is itself a mount point, so its final
        # component always crosses one.  Resolving it from the root with
        # RESOLVE_NO_XDEV fails with EXDEV, which is why every subPath mount
        # broke.  The parent is still resolved under the strict flags; only
        # the leaf lookup is allowed to cross, held by the parent descriptor
        # -- the same allowance #acquire_target! already makes for a CSI
        # target that is already mounted.
        def default_open_flags
          if @adapter && @adapter.class.const_defined?(:O_PATH)
            @adapter.class::O_PATH
          elsif defined?(Rubernetes::Platform::Linux::Openat2::O_PATH)
            Rubernetes::Platform::Linux::Openat2::O_PATH
          else
            0
          end
        end

        def open_mount_point(path, flags: nil, resource_id: nil)
          relative_path = relative(path)
          return open(relative_path, flags: flags, resource_id: resource_id) unless descriptor_capable?

          components = relative_path.split("/")
          leaf = components.pop
          return open(relative_path, flags: flags, resource_id: resource_id) if leaf.nil?

          parent_relative = components.empty? ? "." : components.join("/")
          path_flag = if defined?(Rubernetes::Platform::Linux::Openat2::O_PATH)
                        Rubernetes::Platform::Linux::Openat2::O_PATH
                      else
                        0x200000
                      end
          directory_flag = if defined?(Rubernetes::Platform::Linux::Openat2::O_DIRECTORY)
                             Rubernetes::Platform::Linux::Openat2::O_DIRECTORY
                           else
                             0x10000
                           end
          parent = open(parent_relative, flags: path_flag | directory_flag,
                                         resource_id: "volume-stage-parent:#{path}")
          begin
            open_relative(parent, leaf, flags: flags || (path_flag | directory_flag),
                                        resolve: target_resolve_flags(nil),
                                        resource_id: resource_id || "volume-stage:#{path}")
          ensure
            parent.close if parent.respond_to?(:close)
          end
        end

        # True for an empty directory or empty regular file that is not a
        # mount point (same mount id as its parent).
        def replaceable_stale_target?(anchored_target, stat, parent_fd)
          return false unless (stat.directory? && Dir.empty?(anchored_target)) || (stat.file? && stat.size.zero?)

          leaf = IO.sysopen(anchored_target, File::RDONLY | File::NOFOLLOW | O_PATH_FLAG)
          begin
            mount_id_of(leaf) == mount_id_of(parent_fd)
          ensure
            IO.for_fd(leaf).close
          end
        rescue SystemCallError
          false
        end

        O_PATH_FLAG = 0x200000

        def mount_id_of(descriptor)
          File.foreach("/proc/self/fdinfo/#{Integer(descriptor)}").find { |entry| entry.start_with?("mnt_id:") }&.split(":")&.last&.strip
        end

        def acquire_target!(path, directory: true, create: true, mode: nil)
          raise PathSecurityError, "openat2 adapter is required for a CSI target lease" unless descriptor_capable?

          relative_path = relative(path)
          raise PathSecurityError, "the configured root itself cannot be used as a CSI target" if relative_path == "."

          components = relative_path.split("/")
          leaf = components.pop
          parent_relative = components.empty? ? "." : components.join("/")
          path_flag = if defined?(Rubernetes::Platform::Linux::Openat2::O_PATH)
                        Rubernetes::Platform::Linux::Openat2::O_PATH
                      else
                        0x200000
                      end
          directory_flag = if defined?(Rubernetes::Platform::Linux::Openat2::O_DIRECTORY)
                             Rubernetes::Platform::Linux::Openat2::O_DIRECTORY
                           else
                             0x10000
                           end
          parent = open(parent_relative, flags: path_flag | directory_flag,
                                         resource_id: "volume-target-parent:#{path}")
          parent_fd = descriptor_number(parent.fd)
          anchored_target = "/proc/self/fd/#{parent_fd}/#{leaf}"
          stat = begin
            File.lstat(anchored_target)
          rescue Errno::ENOENT
            nil
          end
          # A publish that failed before its bind (the subPath did not exist
          # yet) can leave an empty target of the wrong kind; the retry needs
          # the right kind.  Only an empty, unmounted leaf is replaced --
          # anything with content or a mount on it is a real conflict.
          if stat && create && !directory.nil? && stat.directory? != directory && replaceable_stale_target?(anchored_target, stat,
                                                                                                            parent_fd)
            stat.directory? ? Dir.rmdir(anchored_target) : File.unlink(anchored_target)
            stat = nil
          end
          if stat.nil?
            raise PathSecurityError, "CSI target #{path.inspect} does not exist" unless create
            raise PathSecurityError, "CSI target type is required when creating a missing path" if directory.nil?

            if directory
              Dir.mkdir(anchored_target, mode || 0o750)
            else
              descriptor = IO.sysopen(anchored_target, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW,
                                      mode || 0o600)
              IO.for_fd(descriptor).close
            end
            stat = File.lstat(anchored_target)
          end
          raise PathSecurityError, "CSI target #{path.inspect} is a symlink" if stat.symlink?
          raise PathSecurityError, "CSI target #{path.inspect} must be a directory" if directory == true && !stat.directory?
          raise PathSecurityError, "CSI block target #{path.inspect} must be a regular file" if directory == false && !stat.file?

          open_flags = File::RDONLY | File::NOFOLLOW
          open_flags |= directory_flag if directory == true
          # The parent descriptor is the authority for the leaf lookup. Do
          # not re-resolve relative_path from the configured root: a parent
          # rename/replacement between these two operations would otherwise
          # hand CSI a different inode than the one just checked.
          target = open_relative(parent, leaf, flags: open_flags,
                                               # The final component may already be a CSI
                                               # mount. RESOLVE_NO_XDEV would reject the
                                               # legitimate lookup with EXDEV; the parent
                                               # descriptor, BENEATH, and no-symlink flags
                                               # continue to bind the target safely.
                                               resolve: target_resolve_flags(nil),
                                               resource_id: "volume-target:#{path}")
          target_fd = descriptor_number(target.fd)
          dispatch = "/proc/#{Process.pid}/fd/#{target_fd}"
          TargetLease.new(original_path: File.expand_path(path.to_s), dispatch_path: dispatch,
                          handle: target, parent_handle: parent)
        rescue PathSecurityError
          target&.close
          parent&.close
          raise
        rescue StandardError => error
          target&.close
          parent&.close
          raise PathSecurityError, "descriptor-relative CSI target acquisition failed: #{error.message}", cause: error
        end

        def open_relative(parent_handle, path, flags: nil, mode: 0, resolve: nil, resource_id: nil)
          value = validate!(path)
          unless @adapter && (@adapter.respond_to?(:open_relative) || @adapter.respond_to?(:resolve_relative) || @adapter.respond_to?(:openat2_relative))
            raise PathSecurityError, "openat2 adapter must expose descriptor-relative subPath resolution"
          end

          method_name = if @adapter.respond_to?(:open_relative)
                          :open_relative
                        elsif @adapter.respond_to?(:resolve_relative)
                          :resolve_relative
                        else
                          :openat2_relative
                        end
          # The adapter needs integers; a caller that leaves the flags out --
          # #validate_sub_path! supplies only the resolve flags -- gets the
          # same O_PATH default #open uses, not a nil that the adapter rejects
          # as "flags, mode, and resolve must be integers".
          raw = @adapter.public_send(method_name, parent: parent_handle, path: value,
                                                  flags: flags || default_open_flags, mode: mode || 0,
                                                  resolve: resolve || secure_resolve_flags(nil), resource_id: resource_id)
          normalize_handle(raw, value)
        rescue PathSecurityError
          raise
        rescue StandardError => error
          raise PathSecurityError, "descriptor-relative subPath resolution failed: #{error.message}", cause: error
        end

        def with_open(path, **)
          handle = open(path, **)
          yield handle
        ensure
          handle&.close
        end

        private

        def mount_boundary_for(relative_path)
          Array(@mount_boundaries).find { |boundary| relative_path == boundary || relative_path.start_with?("#{boundary}/") }
        end

        def open_across_boundary(boundary, relative_path, flags:, mode:, resolve:, resource_id:)
          base = open_mount_point(boundary, resource_id: "mount-boundary:#{boundary}")
          return base if relative_path == boundary

          rest = relative_path.delete_prefix("#{boundary}/")
          method_name = %i[open_relative resolve_relative openat2_relative].find { |name| @adapter.respond_to?(name) }
          raise PathSecurityError, "openat2 adapter must expose descriptor-relative resolution" unless method_name

          begin
            raw = @adapter.public_send(method_name, parent: base, path: rest, flags: flags || default_open_flags,
                                                    mode: mode || 0, resolve: secure_resolve_flags(resolve),
                                                    resource_id: resource_id || "openat2-boundary:#{relative_path}")
            normalize_handle(raw, relative_path)
          ensure
            base.close
          end
        rescue PathSecurityError
          raise
        rescue StandardError => error
          raise PathSecurityError, "openat2 rejected #{relative_path.inspect}: #{error.message}", cause: error
        end

        def descriptor_number(value)
          return value.fileno if value.respond_to?(:fileno)
          return Integer(value) if value.is_a?(Integer)

          raise PathSecurityError, "openat2 target parent did not expose a descriptor"
        end

        def secure_resolve_flags(value)
          required = if defined?(Rubernetes::Platform::Linux::Openat2::DEFAULT_RESOLVE)
                       Rubernetes::Platform::Linux::Openat2::DEFAULT_RESOLVE
                     else
                       0x08 | 0x02 | 0x04 | 0x01
                     end
          value.nil? ? required : Integer(value) | required
        rescue ArgumentError, TypeError
          raise PathSecurityError, "openat2 resolve flags must be an integer"
        end

        def target_resolve_flags(value)
          required = if defined?(Rubernetes::Platform::Linux::Openat2::TARGET_RESOLVE)
                       Rubernetes::Platform::Linux::Openat2::TARGET_RESOLVE
                     else
                       0x08 | 0x02 | 0x04
                     end
          value.nil? ? required : Integer(value) | required
        rescue ArgumentError, TypeError
          raise PathSecurityError, "openat2 resolve flags must be an integer"
        end

        def normalize_handle(raw, relative_path)
          if raw.is_a?(Handle)
            raise PathSecurityError, "openat2 returned a handle without a descriptor" if @require_openat2 && raw.fd.nil?
            raise PathSecurityError, "openat2 returned an absolute path" if raw.path.to_s.start_with?("/")

            validate!(raw.path)
            return raw
          end

          raise PathSecurityError, "openat2 returned no descriptor" if @require_openat2 && raw.nil?

          if raw.respond_to?(:fd)
            descriptor = raw.fd
            raise PathSecurityError, "openat2 returned no descriptor" if @require_openat2 && descriptor.nil?

            return Handle.new(fd: descriptor, path: relative_path, root: @root, identity: identity_for(raw, relative_path))
          end

          Handle.new(fd: raw, path: relative_path, root: @root, identity: stable_identity(relative_path))
        end

        def reject_symlink_components!(relative_path)
          current = @root
          relative_path.split("/").each do |component|
            current = File.join(current, component)
            stat = begin
              File.lstat(current)
            rescue Errno::ENOENT
              nil
            rescue SystemCallError => error
              # Permission, I/O, and lookup failures are not proof of a safe
              # path.  Refuse the request instead of turning them into a
              # false negative from File.exist?.
              raise PathSecurityError, "path component validation failed: #{error.message}"
            end
            next unless stat
            raise PathSecurityError, "path component #{component.inspect} is a symlink" if stat.symlink?
          end
        end

        def identity_for(raw, relative_path)
          return raw.identity if raw.respond_to?(:identity)
          return raw.to_h["identity"] if raw.respond_to?(:to_h) && raw.to_h.key?("identity")

          stable_identity(relative_path)
        end

        def stable_identity(relative_path)
          stat = File.stat(File.join(@root, relative_path))
          "#{stat.dev}:#{stat.ino}:#{stat.mode}"
        rescue SystemCallError
          # The actual openat2 adapter remains authoritative.  This marker is
          # deliberately not used as an authorization fallback.
          "unobserved:#{relative_path}"
        end
      end

      def initialize(root:, resolver: nil, adapter: nil, require_openat2: true)
        @root = File.expand_path(String(root))
        raise PathSecurityError, "configured path-security root must not be a symlink" if File.symlink?(@root)

        @resolver = resolver || Resolver.new(root: @root, adapter: adapter, require_openat2: require_openat2)
      end

      attr_reader :root, :resolver

      def descriptor_capable?
        resolver.respond_to?(:descriptor_capable?) && resolver.descriptor_capable?
      end

      def validate!(path, **)
        resolver.validate!(path, **)
      end

      def open(path, **)
        resolver.open(path, **)
      end

      def open_mount_point(path, **)
        resolver.open_mount_point(path, **)
      end

      # See Resolver#allow_mount_boundary!.
      def allow_mount_boundary!(path)
        raise PathSecurityError, "path resolver does not support mount boundaries" unless resolver.respond_to?(:allow_mount_boundary!)

        resolver.allow_mount_boundary!(path)
      end

      alias resolve open
      alias resolve_fd open

      def validate_host_path!(path, **)
        open(path, **)
      end

      def validate_target!(path)
        if resolver.respond_to?(:validate_target!)
          resolver.validate_target!(path)
        else
          # An injected resolver without target validation is still required
          # to prove the path through a descriptor rather than lexical checks.
          handle = open(path, resource_id: "volume-target:#{path}")
          handle.close
          path.to_s
        end
      end

      def acquire_target!(path, **)
        raise PathSecurityError, "path resolver does not expose descriptor target leases" unless resolver.respond_to?(:acquire_target!)

        resolver.acquire_target!(path, **)
      end

      def validate_sub_path!(root_handle, sub_path, create: false, mode: nil, **options)
        raise PathSecurityError, "subPath requires a parent descriptor" unless root_handle
        raise PathSecurityError, "subPath must be relative" if String(sub_path).start_with?("/")

        # kubelet creates a subPath directory that does not exist yet inside a
        # writable volume (doSafeMakeDir); a Pod naming a fresh subPath would
        # otherwise never start.  Each component is created through the
        # descriptor of the one above it, so the walk cannot be redirected by
        # a symlink planted mid-way.  The mode is the volume directory's own
        # (kubelet_pods.go: hu.GetMode(volumePath), setgid included): an
        # emptyDir is 0777, so a non-root container can write to a subPath of
        # it -- Bitnami's /tmp and conf subPaths failed with EACCES at 0755.
        create_sub_path!(root_handle, sub_path, mode || volume_directory_mode(root_handle)) if create
        sub_path = evaluate_sub_path_symlinks(root_handle, sub_path)

        options = options.merge(resolve: secure_resolve_flags(options[:resolve]))
        handle = begin
          open_sub_path(root_handle, sub_path, options)
        rescue StandardError => error
          # An atomic-writer volume (configMap, secret, downwardAPI,
          # projected) publishes every entry as a symlink into "..data/", so a
          # subPath into one IS a symlink and a walk that refuses symlinks
          # outright fails it with ELOOP.  The property a subPath actually has
          # to hold is that it stays INSIDE the volume, which is what
          # RESOLVE_IN_ROOT enforces: the kernel resolves the symlink but
          # clamps it -- and "..", and any absolute target -- to the volume
          # directory.  That is the same containment kubelet gets by evaluating
          # the symlink and then requiring the result to be within the volume
          # (subpath_linux.go doBindSubPath).  Refusing it instead meant no
          # Pod could ever use a subPath into a configMap or a projected
          # volume at all.
          raise unless symlink_resolution_error?(error)

          open_sub_path(root_handle, sub_path, options.merge(resolve: in_root_resolve_flags))
        end
        parent_identity = root_handle.respond_to?(:identity) ? root_handle.identity : nil
        if parent_identity && handle.respond_to?(:root) && handle.root.to_s != root_handle.root.to_s
          handle.close
          raise PathSecurityError, "subPath descriptor escaped its parent root"
        end
        handle
      end

      def self.secure(root:, adapter: nil, resolver: nil)
        new(root: root, adapter: adapter, resolver: resolver, require_openat2: true)
      end

      private

      def open_sub_path(root_handle, sub_path, options)
        if resolver.respond_to?(:open_relative)
          resolver.open_relative(root_handle, sub_path, **options)
        elsif resolver.respond_to?(:resolve_subpath)
          resolver.resolve_subpath(root_handle: root_handle, path: sub_path, **options)
        else
          raise PathSecurityError, "resolver does not expose descriptor-relative subPath resolution"
        end
      end

      SYMLINK_RESOLUTION_PATTERN = /too many levels of symbolic links|\bELOOP\b/i

      def symlink_resolution_error?(error)
        errno = error.respond_to?(:errno) ? error.errno : nil
        return true if errno == Errno::ELOOP::Errno

        message = error.message.to_s
        return true if SYMLINK_RESOLUTION_PATTERN.match?(message)

        cause = error.respond_to?(:cause) ? error.cause : nil
        cause && cause != error ? symlink_resolution_error?(cause) : false
      end

      # Symlinks are followed but cannot leave the volume: the kernel treats
      # the volume descriptor as "/" for this resolution.  Magic links and
      # mount crossing stay forbidden.
      def in_root_resolve_flags
        constants = Rubernetes::Platform::Linux::Openat2
        if defined?(constants::RESOLVE_IN_ROOT)
          constants::RESOLVE_IN_ROOT | constants::RESOLVE_NO_MAGICLINKS | constants::RESOLVE_NO_XDEV
        else
          0x10 | 0x02 | 0x01
        end
      end

      # kubelet doBindSubPath evaluates the subPath with symlinks followed and
      # then requires it to remain inside the volume; the descriptor walk
      # afterwards refuses symlinks.  Atomic-writer volumes (configMap,
      # secret, downwardAPI, projected) expose every top-level entry as a
      # "..data/<name>" symlink, so a subPath into one is always a symlink.
      def evaluate_sub_path_symlinks(root_handle, sub_path)
        root = root_handle.respond_to?(:root) ? root_handle.root.to_s : ""
        return sub_path if root.empty? || !File.directory?(root)

        candidate = File.join(root, String(sub_path))
        return sub_path unless File.exist?(candidate) || File.symlink?(candidate)

        real_root = File.realpath(root)
        real = File.realpath(candidate)
        prefix = "#{real_root}/"
        raise PathSecurityError, "subPath #{sub_path.inspect} resolves outside its volume" unless real.start_with?(prefix)

        real.delete_prefix(prefix)
      rescue Errno::ENOENT, Errno::ELOOP, Errno::EACCES
        sub_path
      end

      def volume_directory_mode(root_handle)
        target = root_handle.respond_to?(:fd) ? root_handle.fd : root_handle
        stat = if target.respond_to?(:fileno) || target.is_a?(Integer)
                 File.stat("/proc/self/fd/#{descriptor_number(target)}")
               elsif root_handle.respond_to?(:path)
                 File.stat(root_handle.path.to_s)
               end
        stat ? stat.mode & 0o7777 : 0o755
      rescue SystemCallError, PathSecurityError
        0o755
      end

      def create_sub_path!(root_handle, sub_path, mode)
        components = String(sub_path).split("/").reject { |part| part.empty? || part == "." }
        raise PathSecurityError, "subPath must not contain a parent traversal component" if components.include?("..")

        parent = root_handle
        opened = []
        components.each do |component|
          anchored = "/proc/self/fd/#{descriptor_number(parent.respond_to?(:fd) ? parent.fd : parent)}/#{component}"
          begin
            Dir.mkdir(anchored, mode)
            # mkdir is subject to umask; doSafeMakeDir fchmods the exact mode
            # (with the setgid bit) afterwards.
            File.chmod(mode, anchored)
          rescue Errno::EEXIST
            # already there
          rescue SystemCallError => error
            raise PathSecurityError, "cannot create subPath component #{component.inspect}: #{error.message}", cause: error
          end
          break if component == components.last

          parent = resolver.open_relative(parent, component, resolve: secure_resolve_flags(nil))
          opened << parent
        end
        true
      ensure
        opened&.each { |handle| handle.close if handle.respond_to?(:close) }
      end

      def descriptor_number(value)
        return value.fileno if value.respond_to?(:fileno)
        return Integer(value) if value.is_a?(Integer)

        raise PathSecurityError, "subPath parent did not expose a descriptor"
      end

      def secure_resolve_flags(value)
        required = if defined?(Rubernetes::Platform::Linux::Openat2::DEFAULT_RESOLVE)
                     Rubernetes::Platform::Linux::Openat2::DEFAULT_RESOLVE
                   else
                     0x08 | 0x02 | 0x04
                   end
        value.nil? ? required : Integer(value) | required
      end

      def self.secure(root:, adapter: nil, resolver: nil)
        new(root: root, adapter: adapter, resolver: resolver, require_openat2: true)
      end
    end

    Openat2PathValidator = PathSecurity unless const_defined?(:Openat2PathValidator, false)
  end
end
