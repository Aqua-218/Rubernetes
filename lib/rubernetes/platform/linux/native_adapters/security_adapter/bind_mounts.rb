# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Bind mounts of host paths into the container root.
        class SecurityAdapter
          private

          # Volume, projection and per-container files (termination log,
          # /etc/hosts, /etc/resolv.conf) enter the rootfs as bind mounts of
          # host paths.  The destination is resolved the way securejoin does:
          # symlinks inside the image are followed relative to the new root
          # and can never point outside it.
          def apply_bind_mounts(root, mounts, context)
            Array(mounts).each_with_index do |mount, index|
              apply_bind_mount(root, mount.to_h.transform_keys(&:to_s), index, context)
            end
            true
          rescue SystemCallError => error
            raise EffectError, "bind mount construction failed: #{error.message}"
          end

          def apply_bind_mount(root, spec, index, context)
            source = String(spec.fetch("source") { spec.fetch("host_path") })
            destination = String(spec.fetch("destination") { spec.fetch("container_path") })
            raise EffectError, "bind mount #{index} source must be absolute" unless source.start_with?("/")
            raise EffectError, "bind mount #{index} destination must be absolute" unless destination.start_with?("/")
            raise EffectError, "bind mount #{index} path contains NUL" if source.include?("\0") || destination.include?("\0")

            source_stat = File.stat(source)
            target = bind_mount_target(root, destination, source_stat, index)
            flag = bind_mount_propagation(spec, index, context)
            @mount.mount(source: source, target: target, filesystem: nil, flags: MS_BIND | MS_REC,
                         resource_id: "workload:bind:#{destination}")
            if spec["readonly"] == true || spec["read_only"] == true
              @mount.mount(source: nil, target: target, filesystem: nil,
                           flags: MS_BIND | MS_REMOUNT | MS_RDONLY | (source_stat.directory? ? MS_REC : 0),
                           resource_id: "workload:bind-ro:#{destination}")
              # A remount is never recursive (MS_REC is ignored there): the
              # submounts of a read-only volume stay writable unless the
              # mount asks for recursiveReadOnly, which mount_setattr(2)
              # with AT_RECURSIVE applies to the whole tree.
              recursive_readonly(target, spec["recursive_readonly"], destination)
            end
            @mount.set_propagation(target: target, propagation: flag, recursive: true,
                                   resource_id: "workload:bind-propagation:#{destination}")
          end

          # The mountpoint inside the root, created when the image lacks it: a
          # directory for a directory source, an empty file for anything else.
          def bind_mount_target(root, destination, source_stat, index)
            target = secure_join(root, destination)
            if source_stat.directory?
              ensure_directory_tree(root, target)
            else
              ensure_directory_tree(root, File.dirname(target))
              File.open(target, File::WRONLY | File::CREAT, 0o644).close unless File.exist?(target)
              raise EffectError, "bind mount #{index} destination is a directory but the source is a file" if File.directory?(target)
            end
            target
          end

          def bind_mount_propagation(spec, index, context)
            propagation = spec["propagation"] || spec["mount_propagation"] || "None"
            flag = MOUNT_PROPAGATION.fetch(String(propagation)) do
              raise EffectError, "bind mount #{index} has unknown propagation #{propagation.inspect}"
            end
            if flag == MS_SHARED && !context.privileged?
              raise EffectError, "bind mount #{index}: Bidirectional mount propagation requires a privileged container"
            end

            flag
          end

          # v1.VolumeMount.recursiveReadOnly: Enabled must succeed, IfPossible
          # falls back to the plain read-only bind where the kernel cannot.
          def recursive_readonly(target, mode, destination)
            return if mode.nil? || mode.to_s == "Disabled"

            @mount.mount_setattr(dirfd: Mount::AT_FDCWD, path: target, flags: Mount::AT_RECURSIVE,
                                 attr_set: Mount::MOUNT_ATTR_RDONLY, resource_id: "workload:bind-rro:#{destination}")
          rescue Linux::Error => error
            if mode.to_s == "Enabled"
              raise EffectError,
                    "volume at #{destination} requested recursive read-only mode, but it is not supported: #{error.message}"
            end
          end

          # Resolve `destination` beneath `root`, following symlinks that the
          # image may contain (e.g. /tmp -> /var/tmp) relative to the root.
          # The result is lexically and physically inside the root; an escape
          # is refused rather than clamped.
          def secure_join(root, destination)
            components = destination.split("/").reject(&:empty?)
            resolved = []
            follows = 0
            until components.empty?
              component = components.shift
              case component
              when "." then next
              when ".."
                resolved.pop
                next
              end
              candidate = File.join(root, *resolved, component)
              if File.symlink?(candidate)
                follows += 1
                raise EffectError, "too many symlinks resolving #{destination}" if follows > MAX_SYMLINK_FOLLOWS

                link = File.readlink(candidate)
                link_components = link.split("/").reject(&:empty?)
                resolved = [] if link.start_with?("/")
                components = link_components + components
                next
              end
              resolved << component
            end
            path = File.join(root, *resolved)
            unless path == root || path.start_with?("#{root}/")
              raise EffectError,
                    "bind mount destination escapes the rootfs: #{destination}"
            end

            path
          end

          def ensure_directory_tree(root, path)
            relative = path.delete_prefix(root).split("/").reject(&:empty?)
            current = root
            relative.each do |component|
              current = File.join(current, component)
              next if File.directory?(current) && !File.symlink?(current)
              raise EffectError, "rootfs mountpoint component is a symlink: #{current}" if File.symlink?(current)

              Dir.mkdir(current, 0o755)
            end
            path
          end
        end
      end
    end
  end
end
