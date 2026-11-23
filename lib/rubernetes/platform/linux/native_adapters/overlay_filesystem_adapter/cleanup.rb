# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Release of a workspace: the overlay is unmounted in the holder's mount
        # namespace while the holder lives, and the directory is removed.
        class OverlayFilesystemAdapter
          def cleanup(workspace = nil, **options)
            workspace ||= options.fetch(:workspace)
            metadata = begin
              metadata_for(workspace)
            rescue EffectError
              return cleanup_orphan_workspace(workspace)
            end
            if metadata.fetch("mounted")
              namespace_handle = metadata.fetch("namespace")
              # Native rollback destroys the namespace before releasing the
              # workspace.  Once its holder is gone, the namespace-scoped
              # mounts have already been released and their mountinfo cannot
              # be read back; retain strict identity checks while the holder
              # is alive and only skip that impossible readback in this case.
              cleanup_mounted_workspace(workspace, metadata, namespace_handle) unless namespace_holder_gone?(namespace_handle)
            end
            FileUtils.rm_rf(File.join(@root, String(workspace.id)))
            @mutex.synchronize { @workspaces.delete(workspace.identity) }
            true
          rescue SystemCallError => error
            raise EffectError, "workspace cleanup failed: #{error.message}"
          end

          # A workspace a dead operation left before this process started (the
          # ledger, not this adapter, knows it).  Its overlay lived in the
          # Pod's mount namespace, which went with its holder; what is left is
          # the directory, removed only when it is exactly this adapter's
          # <root>/<id> and nothing is mounted on it in this namespace.
          def cleanup_orphan_workspace(workspace)
            id = String(workspace.id)
            validate_workspace_component!(id)
            directory = File.join(@root, id)
            # Only <root>/<id> is ever removed; the recorded root must be it,
            # inside it, or "/" (a sandbox that runs on the host root).
            recorded = File.expand_path(String(workspace.root))
            unless recorded == "/" || recorded == directory || recorded.start_with?("#{directory}/")
              raise EffectError, "unknown workspace #{workspace.identity}"
            end

            mounted = File.readlines("/proc/self/mountinfo", chomp: true).any? do |line|
              point = unescape_mountinfo(line.split.fetch(4, ""))
              point == directory || point.start_with?("#{directory}/")
            end
            raise EffectError, "orphan workspace #{workspace.identity} is still mounted" if mounted

            FileUtils.rm_rf(directory)
            true
          end

          private

          # The overlay is released with a regular umount: a lazily detached
          # mount would stay alive behind any descriptor and defeat the
          # "no child mounts" release precondition of §5.8.4.
          def cleanup_mounted_workspace(workspace, metadata, namespace_handle)
            current_identity = cleanup_mount_identity(namespace_handle, workspace.root)
            return true unless current_identity

            unless same_mount_identity?(current_identity, metadata.fetch("mount_identity"))
              raise EffectError, "overlay mount identity changed before cleanup for #{workspace.identity}"
            end

            mount = @mount
            root = workspace.root
            identity = workspace.identity
            begin
              @namespace_adapter.with_mount_namespace(namespace_handle) do
                mount.unmount(target: root, flags: 0, resource_id: identity)
                true
              end
            rescue EffectError, Linux::Error
              # The helper can lose the reply after unmounting the target.
              # Confirm the effect from mountinfo before accepting completion.
              return true unless cleanup_mount_identity(namespace_handle, root)

              raise
            end
            raise EffectError, "overlay mount remained after cleanup for #{workspace.identity}" if cleanup_mount_identity(namespace_handle, root)

            true
          end

          def cleanup_mount_identity(namespace_handle, root)
            mount_readback(namespace_handle, root, allow_absent: true)
          rescue EffectError
            # The holder can exit between the liveness check and readback.
            raise unless namespace_holder_vanished?(namespace_handle)

            nil
          end

          def namespace_holder_gone?(namespace_handle)
            @namespace_adapter.destroyed?(namespace_handle) == true
          end

          # True when the namespace holder is no longer a live process.  Asked
          # only after a readback failed, to tell "the holder exited under us"
          # (cleanup already achieved) from "the mount table is unreadable for
          # some other reason" (a real failure).
          def namespace_holder_vanished?(namespace_handle)
            return true if namespace_holder_gone?(namespace_handle)

            pid = namespace_handle.pid
            return true if pid.nil?

            # procfs can still expose the mountinfo inode after the task has
            # dropped its namespace (opening it then returns EINVAL). Inspect
            # the namespace link itself so an unreaped holder is recognized.
            File.readlink("/proc/#{Integer(pid)}/ns/mnt")
            false
          rescue Errno::ENOENT, Errno::ESRCH
            true
          rescue SystemCallError, ArgumentError, TypeError
            false
          end
        end
      end
    end
  end
end
