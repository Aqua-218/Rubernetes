# frozen_string_literal: true

require "digest"
require "json"
require "tmpdir"

require_relative "../test_helper"
require "rubernetes/image"

# A cold node fetched an image's layers one at a time: 8-9 s for agnhost and
# jessie-dnsutils before a DNS spec's Pod could start.  Layers now download
# side by side and are still delivered -- and extracted -- in manifest order.
class OCIPullerParallelLayersTest < Minitest::Test
  Image = Rubernetes::Image

  class SlowRegistry
    attr_reader :peak

    def initialize(blobs:, manifest:, delay:, failing: nil)
      @blobs = blobs
      @manifest = manifest
      @delay = delay
      @failing = failing
      @active = 0
      @peak = 0
      @mutex = Mutex.new
    end

    def manifest(_reference, **_options) = @manifest

    def fetch_blob(_reference, digest, expected_size:, media_type:, io: nil)
      bytes = @blobs.fetch(digest.to_s)
      @mutex.synchronize do
        @active += 1
        @peak = [@peak, @active].max
      end
      sleep @delay if media_type == Image::MediaTypes::OCI_IMAGE_LAYER
      raise Image::RegistryError, "blob #{digest} unavailable" if digest.to_s == @failing

      io ? io.write(bytes) : bytes
    ensure
      @mutex.synchronize { @active -= 1 }
    end
  end

  def digest_for(bytes) = "sha256:#{Digest::SHA256.hexdigest(bytes)}"

  def fixture(count)
    config = '{"architecture":"amd64","os":"linux"}'
    layers = Array.new(count) { |index| "layer-#{index}-" + ("x" * index) }
    manifest = Image::Manifest.parse(JSON.generate(
      "schemaVersion" => 2, "mediaType" => Image::MediaTypes::OCI_IMAGE_MANIFEST,
      "config" => {"mediaType" => Image::MediaTypes::OCI_IMAGE_CONFIG, "digest" => digest_for(config), "size" => config.bytesize},
      "layers" => layers.map { |layer| {"mediaType" => Image::MediaTypes::OCI_IMAGE_LAYER, "digest" => digest_for(layer), "size" => layer.bytesize} }
    ))
    blobs = ([config] + layers).to_h { |bytes| [digest_for(bytes), bytes] }
    [manifest, blobs, layers]
  end

  def test_layers_download_concurrently_and_keep_manifest_order
    manifest, blobs, layers = fixture(4)
    Dir.mktmpdir do |directory|
      registry = SlowRegistry.new(blobs: blobs, manifest: manifest, delay: 0.2)
      puller = Image::Puller.new(registry_client: registry, store: Image::ContentStore.new(directory))
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      image = puller.pull("registry.example/app:1", unpack: false)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      assert_operator registry.peak, :>, 1, "more than one layer was in flight"
      assert_operator elapsed, :<, 0.6
      assert_equal(layers.map { |layer| digest_for(layer) }, image.layers.map { |layer| layer.fetch(:descriptor).digest.to_s })
    end
  end

  def test_a_failed_layer_fails_the_pull
    manifest, blobs, layers = fixture(3)
    registry = SlowRegistry.new(blobs: blobs, manifest: manifest, delay: 0.05, failing: digest_for(layers[1]))
    Dir.mktmpdir do |directory|
      puller = Image::Puller.new(registry_client: registry, store: Image::ContentStore.new(directory))

      assert_raises(Image::RegistryError) { puller.pull("registry.example/app:1", unpack: false) }
    end
  end
end
