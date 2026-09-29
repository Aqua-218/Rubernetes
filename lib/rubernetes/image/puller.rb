# frozen_string_literal: true

require "json"
require "fileutils"
require "securerandom"
require "stringio"

require_relative "content_store"
require_relative "errors"
require_relative "layer_extractor"
require_relative "manifest"
require_relative "registry_client"
require_relative "reference"
require_relative "strict_json"
require_relative "../platform/linux/secure_rootfs"

module Rubernetes
  module Image
    # Pulls a pinned image and, when requested, applies all verified layers to a
    # private staging rootfs. The staging directory is renamed only after every
    # config, layer digest, and archive safety check succeeds.
    class Puller
      DEFAULT_MAX_CONFIG_BYTES = 8 * 1024 * 1024

      attr_reader :registry_client, :store, :layer_limits

      def initialize(registry_client: nil, client: nil, store: nil, store_root: nil, layer_limits: nil, **client_options)
        @registry_client = registry_client || client || RegistryClient.new(**client_options)
        @store = store || (store_root && ContentStore.new(store_root))
        @layer_limits = layer_limits
      end

      # The digest the reference resolves to with this puller's credentials,
      # fetching only the manifest: KubeletEnsureSecretPulledImages proves a
      # Pod may use an image already on the node this way, without
      # downloading or unpacking it again.
      def resolve_digest(reference, platform: nil)
        registry_client.manifest(Reference.parse(reference), platform: platform).digest
      end

      def pull(reference, platform: nil, os: nil, architecture: nil, arch: nil, variant: nil, rootfs: nil, unpack: !rootfs.nil?)
        image_reference = Reference.parse(reference)
        resolved_manifest = registry_client.manifest(image_reference, platform: platform, os: os, architecture: architecture, arch: arch, variant: variant)
        pinned_reference = image_reference.with_digest(resolved_manifest.digest)
        config_bytes, config_path = fetch_config(pinned_reference, resolved_manifest.config)
        config = parse_config(config_bytes)
        layers = fetch_layers(pinned_reference, resolved_manifest.layers, unpack)
        layers.freeze
        root_path = unpack ? unpack_layers(layers, rootfs) : nil
        @last_rootfs = root_path
        @last_config = config
        Image.new(
          reference: pinned_reference,
          manifest: resolved_manifest,
          config: config_bytes,
          config_path: config_path,
          layers: layers,
          rootfs: root_path,
          config_object: config
        )
      rescue RegistryError, ManifestError, DigestError, LayerError, StoreError, ReferenceError
        raise
      rescue StandardError => error
        raise Error.new("image pull failed: #{error.message}", cause: error), cause: error
      ensure
        cleanup_temporary_layers(layers) if defined?(layers) && layers
      end

      # Layers are downloaded side by side (each request opens its own
      # connection) and extracted in manifest order afterwards.  One at a
      # time, a cold node spent 8-9 s fetching agnhost's and
      # jessie-dnsutils' layers before a DNS spec's Pod could start.
      MAX_PARALLEL_LAYER_DOWNLOADS = 4

      def fetch_layers(reference, descriptors, unpack)
        descriptors = Array(descriptors)
        digests = descriptors.map(&:digest)
        # A content store is written by digest; two downloads of a digest
        # the manifest lists twice must not race on the same entry.
        sequential = descriptors.length < 2 || (store && digests.uniq.length != digests.length)
        return descriptors.map { |descriptor| fetch_layer(reference, descriptor, unpack) } if sequential

        results = Array.new(descriptors.length)
        queue = Queue.new
        descriptors.each_with_index { |descriptor, index| queue << [descriptor, index] }
        queue.close
        failures = Queue.new
        workers = Array.new([MAX_PARALLEL_LAYER_DOWNLOADS, descriptors.length].min) do
          Thread.new do
            while (item = queue.pop)
              break unless failures.empty?

              descriptor, index = item
              begin
                results[index] = fetch_layer(reference, descriptor, unpack)
              rescue StandardError => error
                failures << error
              end
            end
          end
        end
        workers.each(&:join)
        unless failures.empty?
          cleanup_temporary_layers(results.compact)
          raise failures.pop
        end
        results
      end

      def fetch_layer(pinned_reference, descriptor, unpack)
        if store || unpack
          temporary = download_to_temp(pinned_reference, descriptor)
          if store
            begin
              temporary.rewind
              blob_path = store.put(descriptor.digest, io: temporary, size: descriptor.size, media_type: descriptor.media_type)
              {descriptor: descriptor, bytes: nil, path: blob_path}.freeze
            ensure
              temporary.close!
            end
          else
            {descriptor: descriptor, bytes: nil, path: temporary.path, temporary: temporary}.freeze
          end
        else
          # Preserve the historical String-returning shape for callers that
          # explicitly request an in-memory image and do not unpack it.
          bytes = registry_client.fetch_blob(
            pinned_reference,
            descriptor.digest,
            expected_size: descriptor.size,
            media_type: descriptor.media_type
          )
          {descriptor: descriptor, bytes: bytes, path: nil}.freeze
        end
      end

      def rootfs
        @last_rootfs
      end

      private

      def fetch_config(reference, descriptor)
        if descriptor.size > DEFAULT_MAX_CONFIG_BYTES
          raise LimitError, "image config exceeds the configured byte limit"
        end

        temporary = download_to_temp(reference, descriptor)
        config_path = nil
        begin
          if store
            temporary.rewind
            config_path = store.put(descriptor.digest, io: temporary, size: descriptor.size, media_type: descriptor.media_type)
          end
          temporary.rewind
          bytes = temporary.read(DEFAULT_MAX_CONFIG_BYTES + 1).to_s.b
          raise LimitError, "image config exceeds the configured byte limit" if bytes.bytesize > DEFAULT_MAX_CONFIG_BYTES

          [bytes, config_path]
        ensure
          temporary.close!
        end
      end

      def download_to_temp(reference, descriptor)
        temporary = Tempfile.new(["rubernetes-image", ".blob"])
        temporary.binmode
        registry_client.fetch_blob(
          reference,
          descriptor.digest,
          expected_size: descriptor.size,
          media_type: descriptor.media_type,
          io: temporary
        )
        temporary.flush
        temporary.rewind
        temporary
      rescue StandardError
        temporary.close! if defined?(temporary) && temporary
        raise
      end

      def cleanup_temporary_layers(layers)
        layers.each do |layer|
          temporary = layer[:temporary]
          temporary.close! if temporary && !temporary.closed?
        rescue IOError
          # The original pull or extraction error is the actionable failure.
        end
      end

      def parse_config(bytes)
        raise LimitError, "image config exceeds the configured byte limit" if bytes.bytesize > DEFAULT_MAX_CONFIG_BYTES
        parsed = StrictJSON.parse(bytes, max_bytes: DEFAULT_MAX_CONFIG_BYTES)
        raise ManifestError, "image config must be a JSON object" unless parsed.is_a?(Hash)

        deep_freeze(parsed)
      rescue StrictJSON::Error, JSON::ParserError => error
        raise ManifestError.new("image config is not valid JSON: #{error.message}", cause: error), cause: error
      end

      def unpack_layers(layers, destination)
        destination = File.expand_path(destination.to_s)
        raise LayerError, "rootfs destination must be a non-empty path" if destination.empty?
        parent = File.dirname(destination)
        FileUtils.mkdir_p(parent, mode: 0o700)
        staging = File.join(parent, ".#{File.basename(destination)}.#{Process.pid}.#{SecureRandom.hex(12)}.staging")
        FileUtils.mkdir_p(staging, mode: 0o700)
        extractor = nil
        begin
          extractor = LayerExtractor.new(staging, limits: layer_limits)
          layers.each do |layer|
            descriptor = layer.fetch(:descriptor)
            source = layer[:path] || StringIO.new(layer.fetch(:bytes).b)
            extractor.extract(source, digest: descriptor.digest, expected_size: descriptor.size, media_type: descriptor.media_type)
          end
          if File.exist?(destination) || File.symlink?(destination)
            stat = File.lstat(destination)
            raise LayerError, "rootfs destination must be a regular directory" unless stat.directory? && !stat.symlink?
            raise LayerError, "rootfs destination is not empty" unless Dir.empty?(destination)
            Dir.rmdir(destination)
          end
          File.rename(staging, destination)
          destination
        rescue StandardError
          remove_tree(staging)
          raise
        ensure
          extractor&.close
        end
      end

      def remove_tree(path)
        return unless RUBY_PLATFORM.include?("linux")

        filesystem = ::Rubernetes::Platform::Linux::SecureRootfs.new(root: File.dirname(path))
        begin
          filesystem.remove(File.basename(path))
        ensure
          filesystem.close
        end
      rescue SystemCallError, ::Rubernetes::Platform::Linux::SecureRootfs::Error
        # The staging path is unique and never exposed as a runtime root. The
        # original extraction error remains the actionable failure. The secure
        # backend deliberately leaves an uncertain path in place rather than
        # falling back to pathname recursion.
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each { |key, item| deep_freeze(key); deep_freeze(item) }
        when Array
          value.each { |item| deep_freeze(item) }
        end
        value.freeze
      end
    end
  end
end
