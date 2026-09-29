# frozen_string_literal: true

module Rubernetes
  module Node
    # kubelet nodestatus.Images: the node's images for node.status.images
    # (what the scheduler's ImageLocality scores), largest first, at most
    # nodeStatusMaxImages (50), each with its digests then tags, at most
    # MaxNamesPerImageInNodeStatus (5) names.  Read from the node's own image
    # store and from every CRI runtime it uses; the list is refreshed at most
    # every +refresh+ seconds, as kubelet's image cache is.
    class StatusImages
      MAX_IMAGES = 50
      MAX_NAMES = 5

      def initialize(resolver: nil, cri_clients: [], refresh: 30, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @resolver = resolver
        @cri_clients = cri_clients
        @refresh = refresh
        @clock = clock
        @mutex = Mutex.new
        @cached = nil
        @at = nil
      end

      def images
        @mutex.synchronize do
          return @cached if @cached && @clock.call - @at < @refresh

          @cached = collect
          @at = @clock.call
          @cached
        end
      end

      private

      def collect
        entries = native_images + cri_images
        merged = entries.group_by { |names, _size| names.first }.map do |_first, group|
          [group.flat_map(&:first).uniq, group.map(&:last).max]
        end
        merged.sort_by { |names, size| [-size, names.first.to_s] }.first(MAX_IMAGES).map do |names, size|
          {"names" => names.first(MAX_NAMES), "sizeBytes" => size}
        end
      rescue StandardError
        []
      end

      def native_images
        return [] unless @resolver.respond_to?(:cached_images)

        Array(@resolver.cached_images).filter_map do |_key, image, _last|
          reference = image.respond_to?(:reference) ? image.reference : nil
          next if reference.nil?

          digest = image.respond_to?(:digest) ? image.digest : nil
          repository = "#{reference.registry}/#{reference.repository}"
          names = []
          names << "#{repository}@#{digest}" if digest
          names << "#{repository}:#{reference.tag}" if reference.respond_to?(:tag) && reference.tag
          manifest = image.respond_to?(:manifest) ? image.manifest : nil
          size = manifest.respond_to?(:layers) ? Array(manifest.layers).sum { |layer| layer.size.to_i } : 0
          size += manifest.config.size.to_i if manifest.respond_to?(:config) && manifest.config.respond_to?(:size)
          [names, size] unless names.empty?
        end
      rescue StandardError
        []
      end

      def cri_images
        @cri_clients.flat_map do |client|
          Array(client.image("ListImages", {})["images"]).filter_map do |image|
            names = Array(image["repo_digests"]) + Array(image["repo_tags"])
            [names, Integer(image["size"] || 0)] unless names.empty?
          end
        rescue StandardError
          []
        end
      end
    end
  end
end
