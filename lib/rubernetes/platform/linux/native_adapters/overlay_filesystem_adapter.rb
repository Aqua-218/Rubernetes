# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # OverlayFS preparation creates only a private workspace in the
        # configured root.  The actual mount is performed inside the holder
        # mount namespace by a short-lived clone3 helper, so the agent's mount
        # namespace is never modified.  Per-container /proc, /sys, and /dev
        # are built later by the workload bootstrap in the container's own
        # mount namespace (§5.8.7 step 3); the shared holder mount carries
        # only the verified image layers plus the empty mountpoint
        # directories a read-only image may lack.
        class OverlayFilesystemAdapter
          include CapabilityContract

          MS_RDONLY = Mount::MS_RDONLY
          MS_BIND = Mount::MS_BIND
          RUNTIME_LOWER_DIRECTORIES = %w[proc sys dev].freeze

          def initialize(root:, namespace_adapter:, mount: Mount.new)
            @root = File.expand_path(String(root))
            @namespace_adapter = namespace_adapter
            @mount = mount
            @workspaces = {}
            @mutex = Mutex.new
          end

          attr_reader :root

          def native_capabilities
            {
              filesystem: true,
              overlayfs: overlay_filesystem_available? && existing_parent_directory?
            }.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:filesystem), "mount(2) is unavailable")
            require_capability!(native_capabilities.fetch(:overlayfs), "the configured sandbox root parent is unavailable")
            true
          end

          # `owner` is the Pod's mapped root (uid, gid) when hostUsers=false:
          # the merged root directory takes the upper directory's owner and
          # mode, so an unmapped host-root 0700 root would be untraversable
          # from inside the user namespace.
          def prepare(workspace:, lowerdirs:, read_only: false, owner: nil)
            validate_native_capabilities!
            paths = Array(lowerdirs).map { |path| validate_lowerdir(path) }
            base = File.join(@root, String(workspace.id))
            validate_workspace_component!(workspace.id)
            FileUtils.mkdir_p(base, mode: 0o700)
            # The base directory is traversed only by the agent-side helper;
            # the merged root below it must stay world-searchable like an
            # image root (0755) so a non-root workload can resolve paths.
            File.chmod(0o711, base)
            runtime_lower = prepare_runtime_lower(base)
            # The runtime layer is the lowest layer: image content always
            # wins, and it only contributes the empty proc/sys/dev mountpoints.
            paths.push(runtime_lower)
            [workspace.root, workspace.upper].compact.each do |path|
              FileUtils.mkdir_p(path, mode: 0o755)
              File.chmod(0o755, path)
              File.chown(Integer(owner.fetch(0)), Integer(owner.fetch(1)), path) if owner
            end
            if workspace.work
              FileUtils.mkdir_p(workspace.work, mode: 0o700)
              File.chmod(0o700, workspace.work)
            end
            root_stat = File.lstat(workspace.root)
            @mutex.synchronize do
              @workspaces[workspace.identity] = {
                "workspace" => workspace,
                "lowerdirs" => paths.freeze,
                "read_only" => read_only == true,
                "runtime_lower" => runtime_lower,
                "namespace" => nil,
                "mounted" => false,
                "mount_identity" => nil,
                "root_identity" => {"device" => root_stat.dev, "inode" => root_stat.ino}.freeze
              }
            end
            workspace
          rescue SystemCallError => error
            raise EffectError, "workspace preparation failed: #{error.message}"
          end

          def activate(workspace = nil, namespace:, **options)
            workspace ||= options.fetch(:workspace)
            metadata = metadata_for(workspace)
            return true if metadata.fetch("mounted") || metadata.fetch("lowerdirs").empty?

            namespace_handle = namespace.adapter_handle
            mount_data = ["lowerdir=#{metadata.fetch("lowerdirs").join(":")}"]
            # A read-only root is still writable while the container is being
            # built: bind mounts (the service account token under /var/run,
            # /etc/hosts, volumes) need their mountpoints created in it, which
            # a lower-only overlay refused with EROFS so the container never
            # started.  runc does the same -- mounts first, then the root is
            # remounted read-only (SecurityAdapter#pivot_into), which is what
            # the workload sees.
            if workspace.upper && workspace.work
              mount_data << "upperdir=#{workspace.upper}"
              mount_data << "workdir=#{workspace.work}"
            end
            mount = @mount
            flags = workspace.upper && workspace.work ? 0 : MS_RDONLY
            data = mount_data.join(",")
            identity = workspace.identity
            root = workspace.root
            @namespace_adapter.with_mount_namespace(namespace_handle) do
              # Slave, not private: the overlay stays inside the holder either
              # way, but private would cut the Pod root off from the host's
              # later binds (NamespaceAdapter#make_mounts_slave).
              mount.make_slave(target: "/", recursive: true, resource_id: identity)
              mount.mount(source: "overlay", target: root, filesystem: "overlay", flags: flags, data: data, resource_id: identity)
              true
            end
            mount_identity = mount_readback(namespace_handle, workspace.root)
            @mutex.synchronize do
              metadata["namespace"] = namespace_handle
              metadata["mounted"] = true
              metadata["mount_identity"] = mount_identity.freeze
            end
            true
          end

          # Re-register an already-mounted workspace after process restart.
          # Mount-table readback is mandatory; no path-only adoption is
          # allowed because a reused directory could belong to another Pod.
          def adopt(workspace:, namespace:, metadata: {})
            namespace_handle = namespace.adapter_handle
            expected_mounted = metadata["mounted"]
            expected_mounted = metadata[:mounted] if expected_mounted.nil?
            if expected_mounted == false
              raise EffectError, "unexpected mount at #{workspace.root} during workspace adoption" if mount_present?(namespace_handle,
                                                                                                                     workspace.root)

              mount_identity = nil
            else
              mount_identity = mount_readback(namespace_handle, workspace.root)
              expected_identity = metadata["mount_identity"] || metadata[:mount_identity]
              if expected_identity && !same_mount_identity?(mount_identity, expected_identity)
                raise EffectError, "overlay mount identity changed during adoption for #{workspace.identity}"
              end
            end
            @mutex.synchronize do
              @workspaces[workspace.identity] = {
                "workspace" => workspace,
                "lowerdirs" => Array(metadata["lowerdirs"] || metadata[:lowerdirs]).freeze,
                "read_only" => metadata["read_only"] == true || metadata[:read_only] == true,
                "runtime_lower" => metadata["runtime_lower"] || metadata[:runtime_lower],
                "namespace" => namespace_handle,
                "mounted" => expected_mounted != false,
                "mount_identity" => mount_identity&.freeze,
                "root_identity" => metadata["root_identity"] || metadata[:root_identity]
              }
            end
            workspace
          end

          def resources
            @mutex.synchronize do
              @workspaces.values.map do |metadata|
                workspace = metadata.fetch("workspace")
                workspace.to_h.merge(
                  "metadata" => {
                    "managed_by" => "rubernetes-native",
                    "mounted" => metadata.fetch("mounted"),
                    "lowerdirs" => metadata.fetch("lowerdirs"),
                    "runtime_lower" => metadata.fetch("runtime_lower"),
                    "mount_identity" => metadata.fetch("mount_identity"),
                    "root_identity" => metadata.fetch("root_identity")
                  }
                )
              end.freeze
            end
          end

          private

          def prepare_runtime_lower(base)
            root = File.join(base, "runtime-lower")
            FileUtils.mkdir_p(root, mode: 0o755)
            File.chmod(0o755, root)
            RUNTIME_LOWER_DIRECTORIES.each do |name|
              directory = File.join(root, name)
              FileUtils.mkdir_p(directory, mode: 0o755)
              stat = File.lstat(directory)
              raise EffectError, "runtime rootfs mountpoint is not a directory: #{directory}" unless stat.directory?
            end
            root
          rescue SystemCallError => error
            raise EffectError, "runtime rootfs mountpoint preparation failed: #{error.message}"
          end

          def existing_parent_directory?
            path = File.dirname(@root)
            path = File.dirname(path) until File.directory?(path) || path == File.dirname(path)
            File.directory?(path)
          end

          def overlay_filesystem_available?
            File.foreach("/proc/filesystems").any? { |line| line.split.last == "overlay" }
          rescue SystemCallError
            false
          end

          def metadata_for(workspace)
            identity = workspace.identity
            @mutex.synchronize { @workspaces.fetch(identity) { raise EffectError, "unknown workspace #{identity}" } }
          end

          def validate_workspace_component!(value)
            component = String(value)
            raise ArgumentError, "workspace id is invalid" unless component.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/)
          end

          def validate_lowerdir(value)
            path = File.expand_path(String(value))
            raise ArgumentError, "overlay lowerdir must be absolute" unless path.start_with?("/")
            raise ArgumentError, "overlay lowerdir contains an unsafe separator" if path.include?(":") || path.include?("\0")
            raise EffectError, "overlay lowerdir is not a directory" unless File.directory?(path) && !File.symlink?(path)

            real = File.realpath(path)
            raise EffectError, "overlay lowerdir changed during validation" unless real == path

            real
          rescue Errno::ENOENT => error
            raise EffectError, "overlay lowerdir is unavailable: #{error.message}"
          end
        end
      end
    end
  end
end
