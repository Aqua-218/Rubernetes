# frozen_string_literal: true

# OCI Puller streaming contract tests.
# Specification coverage: M2 review findings #16/#17 require bounded blob
# downloads, incremental verification, and ContentStore-backed layer delivery.
# These tests cover normal, compatibility, and resource-safety paths.

require "digest"
require "json"
require "tmpdir"

require_relative "../test_helper"
require "rubernetes/image"

class OCIPullerTest < Minitest::Test
  Image = Rubernetes::Image

  class StreamingRegistry
    attr_reader :blob_calls

    def initialize(config:, layer:, manifest:)
      @blobs = {
        digest_for(config) => config,
        digest_for(layer) => layer
      }
      @manifest = manifest
      @blob_calls = []
    end

    def manifest(_reference, **_options)
      @manifest
    end

    def fetch_blob(_reference, digest, expected_size:, media_type:, io: nil)
      bytes = @blobs.fetch(digest.to_s)
      raise "descriptor size mismatch in test fixture" unless expected_size == bytes.bytesize

      @blob_calls << {digest: digest.to_s, media_type: media_type, streamed: !io.nil?}
      if io
        bytes.scan(/.{1,3}/m) { |chunk| io.write(chunk) }
        bytes.bytesize
      else
        bytes
      end
    end

    private

    def digest_for(bytes)
      "sha256:#{Digest::SHA256.hexdigest(bytes)}"
    end
  end

  def test_store_backed_pull_streams_config_and_layers_without_retaining_layer_strings
    config = '{"architecture":"amd64","os":"linux"}'
    layer = "large-enough-to-cross-multiple-stream-chunks"
    manifest = build_manifest(config, layer)

    Dir.mktmpdir("rubernetes-oci-store-") do |directory|
      store = Image::ContentStore.new(directory)
      registry = StreamingRegistry.new(config: config, layer: layer, manifest: manifest)
      puller = Image::Puller.new(registry_client: registry, store: store)

      image = puller.pull("registry.example/team/app:stable", unpack: false)

      assert_equal config, image.config
      assert_equal 2, registry.blob_calls.length
      assert(registry.blob_calls.all? { |call| call.fetch(:streamed) })
      assert_nil image.layers.fetch(0).fetch(:bytes)
      assert_equal layer, store.fetch(manifest.layers.fetch(0).digest)
      assert_equal config, store.fetch(manifest.config.digest)
    end
  end

  def test_without_store_and_unpack_the_legacy_layer_bytes_shape_remains_available
    config = '{"architecture":"amd64","os":"linux"}'
    layer = "legacy-compatible-layer"
    manifest = build_manifest(config, layer)
    registry = StreamingRegistry.new(config: config, layer: layer, manifest: manifest)

    image = Image::Puller.new(registry_client: registry).pull("registry.example/team/app:stable", unpack: false)

    assert_equal layer, image.layers.fetch(0).fetch(:bytes)
    layer_call = registry.blob_calls.find { |call| call.fetch(:digest) == digest_for(layer) }
    refute layer_call.fetch(:streamed), "legacy no-store layer path should preserve its String API"
  end

  private

  def build_manifest(config, layer)
    Image::Manifest.parse(
      JSON.generate(
        "schemaVersion" => 2,
        "mediaType" => Image::MediaTypes::OCI_IMAGE_MANIFEST,
        "config" => {
          "mediaType" => Image::MediaTypes::OCI_IMAGE_CONFIG,
          "digest" => digest_for(config),
          "size" => config.bytesize
        },
        "layers" => [{
          "mediaType" => Image::MediaTypes::OCI_IMAGE_LAYER,
          "digest" => digest_for(layer),
          "size" => layer.bytesize
        }]
      )
    )
  end

  def digest_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end
end
