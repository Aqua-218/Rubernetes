# frozen_string_literal: true

require "digest"
require "fileutils"
require "monitor"
require_relative "types"

module Rubernetes
  module Volume
    # Safe default adapter used for unit tests and unprivileged deployments.
    # Production must inject an adapter that performs real mount/device calls;
    # this adapter never invokes a shell or silently performs a privileged op.
    class FilesystemAdapter
      def initialize(root: nil, fsync: false, tmpfs: true)
        @root = root && File.expand_path(root.to_s)
        @fsync = fsync
        @tmpfs = tmpfs == true
        @mounts = {}
        @devices = {}
        @mutex = Monitor.new
        FileUtils.mkdir_p(@root) if @root
      end

      attr_reader :root

      def mkdir(path, mode: 0o755)
        FileUtils.mkdir_p(path)
        File.chmod(mode, path) if mode
        true
      end

      def create_file(path, mode: 0o640)
        File.open(path, File::WRONLY | File::CREAT | File::EXCL, mode) { |file| file.write("") }
        true
      end

      def remove(path)
        FileUtils.rm_rf(path)
        true
      end

      def stat(path)
        File.stat(path)
      end

      def mount(source:, target:, filesystem: nil, readonly: false, options: {}, volume_id: nil, stage: false, **_kwargs)
        mkdir(target)
        source = source.to_s
        target = File.expand_path(target.to_s)
        identity = {
          "mountId" => "mount-#{Digest::SHA256.hexdigest("#{source}\0#{target}")[0, 20]}",
          "filesystemUuid" => "fs-#{Digest::SHA256.hexdigest(source)[0, 20]}",
          "deviceId" => "dev-#{Digest::SHA256.hexdigest(filesystem.to_s + source)[0, 20]}",
          "source" => source, "target" => target, "readonly" => readonly == true,
          "filesystem" => filesystem, "options" => Types.deep_copy(options), "volumeId" => volume_id,
          "stage" => stage == true
        }
        @mutex.synchronize { @mounts[identity["mountId"]] = identity }
        identity
      end

      def bind(source:, target:, readonly: false, volume_id: nil, **)
        mount(source: source, target: target, filesystem: "bind", readonly: readonly, volume_id: volume_id, stage: false, **)
      end

      def unmount(target:, mount_id: nil, **_kwargs)
        target = File.expand_path(target.to_s)
        @mutex.synchronize do
          matches = @mounts.values.select do |mount|
            mount["target"] == target && (!mount_id || mount["mountId"] == mount_id.to_s)
          end
          raise MountIdentityError, "mount #{mount_id} is not present at #{target}" if mount_id && matches.empty?

          @mounts.delete_if { |_id, mount| matches.include?(mount) }
        end
        true
      end

      def list_mounts
        @mutex.synchronize { @mounts.values.map { |entry| Types.deep_copy(entry) } }
      end

      def tmpfs?(path = nil)
        return @tmpfs unless path

        @mutex.synchronize do
          @mounts.values.any? do |mount|
            mount["target"] == File.expand_path(path.to_s) && mount["filesystem"] == "tmpfs"
          end
        end
      end

      def ensure_tmpfs(path, size_limit: nil, volume_id: nil)
        return false unless @tmpfs

        mount(source: "tmpfs", target: path, filesystem: "tmpfs", readonly: false,
              options: {"size" => size_limit}, volume_id: volume_id)
        true
      end

      def create_loop(path:, volume_id:, size_bytes: nil, **_kwargs)
        identity = "loop-#{Digest::SHA256.hexdigest("#{volume_id}\0#{path}")[0, 20]}"
        @mutex.synchronize do
          @devices[identity] = {"id" => identity, "kind" => "loop", "path" => path, "volumeId" => volume_id, "sizeBytes" => size_bytes}
        end
        @devices[identity]
      end

      def create_dm(device:, volume_id:, size_bytes: nil, **_kwargs)
        identity = "dm-#{Digest::SHA256.hexdigest("#{volume_id}\0#{device}")[0, 20]}"
        @mutex.synchronize do
          @devices[identity] =
            {"id" => identity, "kind" => "device-mapper", "device" => device, "volumeId" => volume_id, "sizeBytes" => size_bytes}
        end
        @devices[identity]
      end

      def destroy_device(id:, **_kwargs)
        @mutex.synchronize { @devices.delete(id.to_s) }
        true
      end

      def list_devices
        @mutex.synchronize { @devices.values.map { |entry| Types.deep_copy(entry) } }
      end

      def expand(source:, capacity_bytes:, **_kwargs)
        {"source" => source, "capacityBytes" => Integer(capacity_bytes)}
      end

      def stats(path:, volume_id:, capacity_bytes: nil, **_kwargs)
        used = directory_size(path)
        capacity = capacity_bytes ? Integer(capacity_bytes) : used
        Stats.new(volume_id: volume_id, used_bytes: used, capacity_bytes: capacity)
      end

      private

      def directory_size(path)
        info = File.lstat(path)
        return 0 if info.symlink?
        return info.size if info.file?
        return 0 unless info.directory?

        Dir.children(path).sum { |child| directory_size(File.join(path, child)) }
      rescue SystemCallError
        0
      end
    end
  end
end
