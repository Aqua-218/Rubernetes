# frozen_string_literal: true

require "time"
require_relative "client"

module Rubernetes
  module Runtime
    module CRI
      # ImageFsInfo reports usage. Capacity, available space, and device
      # identity come from the first reported filesystem's local mount.
      class FilesystemStats
        Entry = Data.define(:stats, :device)

        def initialize(client)
          @client = client
        end

        def sample(include_container: true)
          response = @client.image("ImageFsInfo", {}) || {}
          image = entry(Array(response["image_filesystems"]).first)
          return {"imageFs" => image}.compact unless include_container

          writable_layer = Array(response["container_filesystems"]).first
          container = writable_layer ? entry(writable_layer) : image
          container = image if image&.device && container&.device == image.device
          {"imageFs" => image, "containerFs" => container}.compact
        rescue Client::Error
          {}
        end

        private

        def entry(filesystem)
          return unless filesystem

          stamp = Integer(filesystem["timestamp"] || 0)
          stats = {"usedBytes" => integer_usage(filesystem, "used_bytes"), "inodesUsed" => integer_usage(filesystem, "inodes_used")}.compact
          stats["time"] = Time.at(Rational(stamp, 1_000_000_000)).utc.iso8601(9) if stamp.positive?
          device = add_mount_stats(stats, filesystem.dig("fs_id", "mountpoint"))
          Entry.new(stats: stats.freeze, device: device) unless stats.empty?
        end

        def integer_usage(filesystem, field)
          value = filesystem.dig(field, "value")
          Integer(value) unless value.nil?
        end

        def add_mount_stats(stats, mountpoint)
          return unless mountpoint.is_a?(String) && mountpoint.start_with?("/") && !mountpoint.include?("\0")

          require_relative "../../platform/linux/statfs"
          return unless Platform::Linux::Statfs.supported?

          device = File.stat(mountpoint).dev
          fs = Platform::Linux::Statfs.statfs(mountpoint)
          stats.merge!("capacityBytes" => fs.capacity_bytes, "availableBytes" => fs.available_bytes,
                       "inodes" => fs.files, "inodesFree" => fs.files_free)
          device
        rescue Platform::Linux::Error, SystemCallError, Fiddle::DLError
          nil
        end
      end
    end
  end
end
