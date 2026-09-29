# frozen_string_literal: true

require "digest"
require "fileutils"
require "open3"

require_relative "errors"
require_relative "artifacts"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Block images for the guest: a read-only ext4 image per pinned
      # container image (built once from the host's verified, extracted
      # rootfs and cached by digest) and one writable workspace image per
      # microVM.  The guest mounts image disks read-only with nosuid/nodev
      # as OverlayFS lowerdirs.
      class ImageDisks
        PLACEHOLDER_MIB = 16
        MAX_IMAGE_DRIVES = 4

        def initialize(root:, workspace_mib: 2048)
          @root = File.expand_path(root)
          @workspace_mib = workspace_mib
          FileUtils.mkdir_p(File.join(@root, "images"))
          FileUtils.mkdir_p(File.join(@root, "workspaces"))
          FileUtils.mkdir_p(File.join(@root, "placeholders"))
        end

        attr_reader :root

        # Returns the cached image disk for +digest+, building it from
        # +rootfs_dir+ when absent; the disk's own SHA-256 is recorded next
        # to it so the artifact can be re-verified.
        def image_disk(digest, rootfs_dir)
          raise ArtifactError, "image digest must be sha256:<hex>" unless digest.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
          raise ArtifactError, "image rootfs #{rootfs_dir} is not a directory" unless File.directory?(rootfs_dir)

          path = File.join(@root, "images", "#{digest.delete_prefix("sha256:")}.ext4")
          @verified ||= {}
          if File.file?(path) && File.file?("#{path}.sha256")
            recorded = File.read("#{path}.sha256").strip
            stat = File.stat(path)
            key = [stat.ino, stat.size, stat.mtime.to_f]
            return path if @verified[path] == key
            if Artifacts.file_digest(path) == recorded
              @verified[path] = key
              return path
            end
          end

          temporary = "#{path}.tmp-#{Process.pid}"
          usage_kib = Integer(Open3.capture2("du", "-sk", rootfs_dir).first.split.first)
          size_mib = [(usage_kib / 1024.0 * 1.3).ceil + 32, 64].max
          run!("mkfs.ext4", "-q", "-F", "-d", rootfs_dir, "-L", "image", "-O", "^has_journal", temporary, "#{size_mib}M")
          File.chmod(0o640, temporary)
          File.write("#{temporary}.sha256", Artifacts.file_digest(temporary) + "\n")
          File.rename("#{temporary}.sha256", "#{path}.sha256")
          File.rename(temporary, path)
          path
        end

        # Per-VM read grant on a shared image disk (POSIX ACL); revoked on
        # cleanup so a released UID keeps no access.
        def grant_read(path, uid)
          run!("setfacl", "-m", "u:#{Integer(uid)}:r", path)
          true
        end

        def revoke_read(path, uid)
          run!("setfacl", "-x", "u:#{Integer(uid)}", path)
          true
        rescue Error
          false
        end

        # Workspaces are sparse copies of a per-size formatted template, so a
        # new one costs a sparse copy of the filesystem metadata instead of a
        # full mkfs.
        def workspace_disk(workspace_id, size_mib: @workspace_mib)
          path = File.join(@root, "workspaces", "#{workspace_id}.ext4")
          raise Error, "workspace #{workspace_id} already exists" if File.exist?(path)

          template = workspace_template(size_mib)
          run!("cp", "--sparse=always", template, path)
          File.chmod(0o600, path)
          path
        end

        def workspace_template(size_mib)
          path = File.join(@root, "placeholders", "workspace-template-#{size_mib}.ext4")
          return path if File.file?(path)

          temporary = "#{path}.tmp-#{Process.pid}"
          run!("truncate", "-s", "#{size_mib}M", temporary)
          # No journal: the workspace is discarded with its VM, and a
          # journal-less filesystem mounts faster inside the guest.
          run!("mkfs.ext4", "-q", "-F", "-L", "workspace", "-O", "^has_journal", temporary)
          File.chmod(0o600, temporary)
          File.rename(temporary, path)
          path
        end

        def remove_workspace(workspace_id)
          path = File.join(@root, "workspaces", "#{workspace_id}.ext4")
          return false unless File.exist?(path)

          File.delete(path)
          true
        end

        def workspaces
          Dir.glob(File.join(@root, "workspaces", "*.ext4")).sort.map { |path| File.basename(path, ".ext4") }
        end

        # Placeholder drives keep the drive slots of the base snapshot valid.
        def placeholder(index)
          path = File.join(@root, "placeholders", "slot#{index}.ext4")
          unless File.file?(path)
            run!("truncate", "-s", "#{PLACEHOLDER_MIB}M", path)
            run!("mkfs.ext4", "-q", "-F", "-L", "placeholder", path)
            File.chmod(0o600, path)
          end
          path
        end

        private

        def run!(*arguments)
          output, status = Open3.capture2e(*arguments)
          raise Error, "#{arguments.first} failed: #{output.strip}" unless status.success?

          output
        end
      end
    end
  end
end
