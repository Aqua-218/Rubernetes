# frozen_string_literal: true

require "digest"
require "fileutils"
require "open3"
require "tmpdir"

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
        LOCK_STRIPES = 64
        EXT4_MAGIC_OFFSET = 1080
        EXT4_MAGIC = "\x53\xEF".b.freeze

        def initialize(root:, workspace_mib: 2048)
          @root = File.expand_path(root)
          @workspace_mib = workspace_mib
          @verified = {}
          %w[images workspaces placeholders].each { |directory| FileUtils.mkdir_p(File.join(@root, directory)) }
          FileUtils.mkdir_p(File.join(@root, ".locks"), mode: 0o700)
        end

        attr_reader :root

        # Returns the cached image disk for +digest+, building it from
        # +rootfs_dir+ when absent; the disk's own SHA-256 is recorded next
        # to it so the artifact can be re-verified.
        def image_disk(digest, rootfs_dir)
          raise ArtifactError, "image digest must be sha256:<hex>" unless digest.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
          raise ArtifactError, "image rootfs #{rootfs_dir} is not a directory" unless File.directory?(rootfs_dir)

          path = File.join(@root, "images", "#{digest.delete_prefix("sha256:")}.ext4")
          with_disk_lock(path) do
            discard_staged_disk(path)
            next if verified_image?(path)

            with_staged_disk(path) { |temporary| build_image_disk(rootfs_dir, path, temporary) }
          end
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
          template = workspace_template(size_mib)
          with_disk_lock(path) do
            discard_staged_disk(path)
            raise Error, "workspace #{workspace_id} already exists" if File.exist?(path) || File.symlink?(path)

            with_staged_disk(path) do |temporary|
              run!("cp", "--reflink=auto", "--sparse=always", "--", template, temporary)
              File.chmod(0o600, temporary)
              File.link(temporary, path)
            end
          end
          path
        rescue Errno::EEXIST
          raise Error, "workspace #{workspace_id} already exists"
        end

        def workspace_template(size_mib)
          path = File.join(@root, "placeholders", "workspace-template-#{size_mib}.ext4")
          # No journal: the workspace is discarded with its VM, and a
          # journal-less filesystem mounts faster inside the guest.
          formatted_disk(path, size_mib, "workspace", "-O", "^has_journal")
        end

        def remove_workspace(workspace_id)
          path = File.join(@root, "workspaces", "#{workspace_id}.ext4")
          with_disk_lock(path) do
            discard_staged_disk(path)
            File.unlink(path)
          end
          true
        rescue Errno::ENOENT
          false
        end

        def workspaces
          Dir.glob(File.join(@root, "workspaces", "*.ext4")).map { |path| File.basename(path, ".ext4") }
        end

        # Placeholder drives keep the drive slots of the base snapshot valid.
        def placeholder(index)
          path = File.join(@root, "placeholders", "slot#{index}.ext4")
          formatted_disk(path, PLACEHOLDER_MIB, "placeholder")
        end

        private

        # Independent keys can build concurrently. A fixed number of shared
        # locks keeps deleted workspaces from leaving a lock file behind.
        def with_disk_lock(path)
          key = path.delete_prefix("#{@root}/")
          stripe = Digest::SHA256.digest(key).getbyte(0) % LOCK_STRIPES
          lock_path = File.join(@root, ".locks", stripe.to_s)
          File.open(lock_path, File::RDWR | File::CREAT | File::NOFOLLOW | File::NONBLOCK, 0o600) do |lock|
            raise Error, "could not lock MicroVM disk cache" unless lock.stat.file? && lock.flock(File::LOCK_EX)

            yield
          end
        end

        # Names inside the stage are unique per build. A subprocess from a
        # killed writer cannot open a subsequent build's temporary disk.
        def with_staged_disk(path)
          stage = "#{path}.staging"
          Dir.mkdir(stage, 0o700)
          begin
            Dir.mktmpdir("build-", stage) { |directory| yield File.join(directory, "disk.ext4") }
          ensure
            Dir.rmdir(stage)
          end
        end

        def discard_staged_disk(path)
          stage = "#{path}.staging"
          return unless File.exist?(stage) || File.symlink?(stage)

          raise Error, "unexpected MicroVM disk stage #{stage}" unless File.lstat(stage).directory?

          Dir.children(stage).each do |entry|
            build = File.join(stage, entry)
            raise Error, "unexpected MicroVM disk stage #{build}" unless entry.start_with?("build-") && File.lstat(build).directory?

            FileUtils.rm_f([File.join(build, "disk.ext4"), File.join(build, "disk.ext4.sha256")])
            Dir.rmdir(build)
          end
          Dir.rmdir(stage)
        end

        def build_image_disk(rootfs, path, temporary)
          usage_kib = Integer(run!("du", "-sk", "--", rootfs).split.first)
          size_mib = [(usage_kib / 1024.0 * 1.3).ceil + 32, 64].max
          run!("mkfs.ext4", "-q", "-F", "-d", rootfs, "-L", "image", "-O", "^has_journal", temporary, "#{size_mib}M")
          File.chmod(0o640, temporary)
          checksum = Artifacts.file_digest(temporary)
          File.write("#{temporary}.sha256", "#{checksum}\n")
          File.rename(temporary, path)
          publish_checksum(path, temporary)
          @verified[path] = image_identity(path, checksum)
        end

        def publish_checksum(path, temporary)
          File.rename("#{temporary}.sha256", "#{path}.sha256")
        rescue StandardError
          FileUtils.rm_f([path, "#{path}.sha256"])
          raise
        end

        def verified_image?(path)
          return false unless File.file?(path) && File.file?("#{path}.sha256")

          checksum = File.read("#{path}.sha256").strip
          identity = image_identity(path, checksum)
          return true if @verified[path] == identity
          return false unless Artifacts.file_digest(path) == checksum

          @verified[path] = identity
          true
        end

        def image_identity(path, checksum)
          stat = File.stat(path)
          [stat.dev, stat.ino, stat.size, stat.mtime, checksum]
        end

        def formatted_disk(path, size_mib, label, *mkfs_options)
          with_disk_lock(path) do
            discard_staged_disk(path)
            next if formatted?(path, size_mib)

            with_staged_disk(path) do |temporary|
              run!("truncate", "-s", "#{size_mib}M", temporary)
              run!("mkfs.ext4", "-q", "-F", "-L", label, *mkfs_options, temporary)
              File.chmod(0o600, temporary)
              File.rename(temporary, path)
            end
          end
          path
        end

        def formatted?(path, size_mib)
          File.file?(path) && File.size(path) == Integer(size_mib) * 1024 * 1024 &&
            File.binread(path, EXT4_MAGIC.bytesize, EXT4_MAGIC_OFFSET) == EXT4_MAGIC
        end

        def run!(*arguments)
          output, status = Open3.capture2e(*arguments)
          raise Error, "#{arguments.first} failed: #{output.strip}" unless status.success?

          output
        end
      end
    end
  end
end
