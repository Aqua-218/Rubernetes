# frozen_string_literal: true

require "set"

module Rubernetes
  module Runtime
    module CRI
      # The runtime's images as Node::ImageGCManager sees its resolver's: the
      # kubelet's image GC runs against a CRI runtime through ListImages,
      # RemoveImage and ImageFsInfo.  One entry per image; pinned images
      # (the sandbox image) are never offered.  An image counts as in use
      # when any of its tags is (+in_use+ answers the node's references).
      class ImageGCSource
        Image = Struct.new(:id, :tags, :size_bytes, keyword_init: true)

        def initialize(client:, in_use: -> { Set.new })
          @client = client
          @in_use = in_use
        end

        attr_reader :client

        # [[key, image, last_handed_out]]: key "<reference>|<id>", the
        # reference a used tag when there is one.
        def cached_images
          used = @in_use.call
          Array(@client.image("ListImages", {})["images"]).filter_map do |image|
            next if image["pinned"] == true

            tags = Array(image["repo_tags"]) + Array(image["repo_digests"])
            next if tags.empty?

            reference = tags.find { |tag| used.include?(tag) } || tags.first
            ["#{reference}|#{image["id"]}", Image.new(id: image["id"], tags: tags, size_bytes: Integer(image["size"] || 0)), nil]
          end
        end

        def evict_cached_image(key, unused_since: nil)
          id = key.to_s.split("|", 2).last
          @client.image("RemoveImage", {"image" => {"image" => id}})
          true
        rescue Client::Error => error
          return true if error.code == Client::NOT_FOUND

          raise
        end

        # The image filesystem the way StatsProvider#image_fs_stats reports
        # it: capacity and availability of the runtime's image mount.
        def fs_stats
          filesystem = Array(@client.image("ImageFsInfo", {})["image_filesystems"]).first || {}
          mountpoint = filesystem.dig("fs_id", "mountpoint").to_s
          used = Integer(filesystem.dig("used_bytes", "value") || 0)
          return {"usedBytes" => used} if mountpoint.empty?

          require "rubernetes/platform/linux/statfs"
          stat = Rubernetes::Platform::Linux::Statfs.statfs(mountpoint)
          {"capacityBytes" => stat.capacity_bytes, "availableBytes" => stat.available_bytes, "usedBytes" => used}
        rescue StandardError
          {"usedBytes" => used}.compact
        end
      end
    end
  end
end
