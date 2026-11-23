# frozen_string_literal: true

require_relative "filesystem_stats"

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

        def initialize(client:, in_use: -> { Set.new }, runtime_class_in_image_api: false)
          @client = client
          @filesystem_stats = FilesystemStats.new(client)
          @in_use = in_use
          @runtime_class_in_image_api = runtime_class_in_image_api
        end

        attr_reader :client

        # [[key, image, last_handed_out]]: key "<reference>|<id>", the
        # reference a used tag when there is one.
        def cached_images
          images = Array(@client.image("ListImages", {})["images"])
          return images_with_runtime_handlers(images) if @runtime_class_in_image_api

          used = @in_use.call
          images.filter_map do |image|
            next if image["pinned"] == true

            tags = Array(image["repo_tags"]) + Array(image["repo_digests"])
            next if tags.empty?

            reference = tags.find { |tag| used.include?(tag) } || tags.first
            ["#{reference}|#{image["id"]}", Image.new(id: image["id"], tags: tags, size_bytes: Integer(image["size"] || 0)), nil]
          end
        end

        def evict_cached_image(key, unused_since: nil)
          first, second = key.to_s.split("|", 2)
          image = {"image" => @runtime_class_in_image_api ? first : (second || first)}
          image["runtime_handler"] = second if @runtime_class_in_image_api && second
          @client.image("RemoveImage", {"image" => image})
          true
        rescue Client::Error => error
          return true if error.code == Client::NOT_FOUND

          raise
        end

        def fs_stats
          @filesystem_stats.sample(include_container: false)["imageFs"]&.stats || {}
        end

        private

        def images_with_runtime_handlers(images)
          used = Array(@client.runtime("ListContainers", {})["containers"]).to_set do |container|
            image_tuple(container["image_id"], container.dig("image", "runtime_handler"))
          end
          images.filter_map do |image|
            id = image["id"].to_s
            next if image["pinned"] == true || id.empty?

            key = image_tuple(id, image.dig("spec", "runtime_handler"))
            tags = Array(image["repo_tags"]) + Array(image["repo_digests"])
            [key, Image.new(id: id, tags: tags, size_bytes: Integer(image["size"] || 0)), nil, used.include?(key)]
          end
        end

        def image_tuple(id, handler)
          handler.to_s.empty? ? id.to_s : "#{id}|#{handler}"
        end
      end
    end
  end
end
