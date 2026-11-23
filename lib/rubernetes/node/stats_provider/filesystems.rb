# frozen_string_literal: true

require_relative "../../runtime/cri/filesystem_stats"

module Rubernetes
  module Node
    class StatsProvider
      module Filesystems
        # Image GC needs capacity and availability without walking Pods.
        def image_fs_stats
          return native_image_fs_stats unless @cri_filesystem_stats

          @cri_filesystem_stats.sample(include_container: false)["imageFs"]&.stats || {}
        end

        def native_image_fs_stats
          fs_stats(filesystem_path(image_root), @clock.call.utc.iso8601)
        end

        def dedicated_image_fs?
          return cri_node_filesystem_stats(@clock.call.utc.iso8601).last&.first == true if @cri_filesystem_stats

          node, image, container = filesystem_devices
          image != node || container != node
        end

        def split_container_fs?
          return cri_node_filesystem_stats(@clock.call.utc.iso8601).last&.last == true if @cri_filesystem_stats

          _, image, container = filesystem_devices
          image != container
        end

        private

        def image_root = @image_root || @pod_root || "/"

        def filesystem_paths
          [@pod_root || "/", image_root, @container_root || image_root].map { |path| filesystem_path(path) }
        end

        # A configured runtime directory may not exist until its first use.
        # Its nearest existing parent is already on the configured mount.
        def filesystem_path(path)
          path = File.expand_path(path)
          path = File.dirname(path) until File.exist?(path) || path == "/"
          path
        end

        def filesystem_devices
          filesystem_paths.map { |path| File.stat(path).dev }
        rescue SystemCallError
          [nil, nil, nil]
        end

        def node_filesystem_stats(stamp)
          return cri_node_filesystem_stats(stamp) if @cri_filesystem_stats

          paths = filesystem_paths
          observed = paths.uniq.to_h { |path| [path, fs_stats(path, stamp)] }
          node, image, container = observed.values_at(*paths)
          runtime = {"imageFs" => image, "containerFs" => container}.compact
          [{"fs" => node, "runtime" => runtime.empty? ? nil : runtime}.compact, nil]
        end

        def cri_node_filesystem_stats(stamp)
          node = filesystem_path(@pod_root || "/")
          observed = @cri_filesystem_stats.sample
          image, container = observed.values_at("imageFs", "containerFs").map { |entry| entry&.device }
          node_device = filesystem_device(node)
          layout = [image != node_device || container != node_device, image != container].freeze if image && container && node_device
          stats = {"fs" => fs_stats(node, stamp), "runtime" => observed.empty? ? nil : observed.transform_values(&:stats)}.compact
          [stats, layout]
        end

        def filesystem_device(path)
          File.stat(path).dev
        rescue SystemCallError
          nil
        end

        def fs_stats(path, stamp)
          require_relative "../../platform/linux/statfs"
          return nil unless Platform::Linux::Statfs.supported? && File.exist?(path)

          result = Platform::Linux::Statfs.statfs(path)
          {"time" => stamp, "availableBytes" => result.available_bytes, "capacityBytes" => result.capacity_bytes,
           "usedBytes" => result.used_bytes, "inodesFree" => result.files_free, "inodes" => result.files,
           "inodesUsed" => result.files - result.files_free}
        rescue Platform::Linux::Error, SystemCallError, Fiddle::DLError
          nil
        end
      end
    end
  end
end
