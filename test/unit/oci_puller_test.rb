# frozen_string_literal: true

# OCI Puller streaming contract tests.
# Specification coverage: M2 review findings #16/#17 require bounded blob
# downloads, incremental verification, and ContentStore-backed layer delivery.
# These tests cover normal, compatibility, and resource-safety paths.

require "base64"
require "digest"
require "json"
require "tmpdir"

require_relative "../test_helper"
require "rubernetes/image"
require "rubernetes/image/public_blob_source"

class OCIPullerTest < Minitest::Test
  Image = Rubernetes::Image

  # zstd -q -c of a 2,048-byte tar with one file, followed by an optional
  # separate frame containing 300,000 bytes of zero tar padding.
  ZSTD_TAR = Base64.strict_decode64(
    "KLUv/QRYLQMAcoQPF5C1GgMEZ0vg8FAoqzGcmMJkkwqZmUIGTL1dKQRDJtcCSykC8MjWtePEg7SQ8dUgZLSUUcn/5+g/pi3WWy" \
    "MNAFrBD0hMhlIKTQpgBqzpYCgcgAdylociiBczDYBu5do5AS799rA2"
  ).freeze
  ZSTD_PADDING = Base64.strict_decode64("KLUv/QRYVAAAEAAAAQD7/znAAgIAEAADnwQALSjeJg==").freeze

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

  class PublicRegistry
    attr_reader :requests

    def initialize(manifest, blobs, allow_head:)
      @manifest = manifest
      @blobs = blobs
      @allow_head = allow_head
      @requests = []
    end

    def request(method:, uri:, **)
      @requests << [method, uri.path]
      return {status: 200, headers: {"content-type" => Image::MediaTypes::OCI_IMAGE_MANIFEST}, body: @manifest} if uri.path.include?("/manifests/")

      digest = uri.path.split("/").last
      bytes = @blobs.fetch(digest)
      headers = {"docker-content-digest" => digest, "content-length" => bytes.bytesize.to_s, "content-type" => "application/octet-stream"}
      return {status: @allow_head ? 200 : 405, headers: headers, body: ""} if method == "HEAD"

      {status: 200, headers: headers, body: bytes}
    end

    def stream(method:, uri:, **)
      response = request(method: method, uri: uri, **)
      yield response.fetch(:body)
      response.merge(body: "")
    end
  end

  def test_public_blob_source_serves_only_after_normal_manifest_and_head_checks
    with_public_source do |puller, transport, rootfs, _blob|
      image = puller.pull("registry.example/team/app:stable", rootfs: rootfs)

      assert_equal "zstd OCI layer", File.binread(File.join(rootfs, "payload"))
      assert_equal image.manifest.digest, image.reference.digest
      assert_equal %w[GET HEAD HEAD], transport.requests.map(&:first)
      assert(transport.requests.drop(1).all? { |_method, path| path.start_with?("/v2/team/app/blobs/sha256:") })
    end
  end

  def test_public_blob_source_falls_back_to_the_verified_remote_get_on_head_failure
    with_public_source(allow_head: false) do |puller, transport, rootfs, _blob|
      puller.pull("registry.example/team/app:stable", rootfs: rootfs)

      assert_equal %w[GET HEAD GET HEAD GET], transport.requests.map(&:first)
      assert_equal "zstd OCI layer", File.binread(File.join(rootfs, "payload"))
    end
  end

  def test_public_blob_source_rejects_an_altered_layer_without_publishing_rootfs
    with_public_source do |puller, _transport, rootfs, blob|
      damaged = File.binread(blob)
      damaged.setbyte(0, damaged.getbyte(0) ^ 1)
      File.binwrite(blob, damaged)

      assert_raises(Image::DigestError) { puller.pull("registry.example/team/app:stable", rootfs: rootfs) }
      refute_path_exists rootfs
    end
  end

  def test_public_blob_source_rejects_a_symlink_and_skips_it_for_credentials
    with_public_source do |puller, _transport, rootfs, blob|
      File.rename(blob, "#{blob}.external")
      File.symlink("#{blob}.external", blob)

      assert_raises(Image::Error) { puller.pull("registry.example/team/app:stable", rootfs: rootfs) }
    end
    with_public_source(credentials: {username: "fixture", password: "only-for-test"}) do |puller, transport, rootfs, blob|
      File.unlink(blob)
      File.symlink("#{blob}.nonexistent", blob)
      puller.pull("registry.example/team/app:stable", rootfs: rootfs)

      assert_equal %w[GET GET GET], transport.requests.map(&:first)
    end
  end

  def with_public_source(allow_head: true, credentials: {})
    config = '{"architecture":"amd64","os":"linux"}'
    manifest = build_manifest(config, ZSTD_TAR, media_type: Image::MediaTypes::OCI_IMAGE_LAYER_ZSTD)
    blobs = {digest_for(config) => config, digest_for(ZSTD_TAR) => ZSTD_TAR}
    transport = PublicRegistry.new(manifest.raw, blobs, allow_head: allow_head)
    registry = Image::RegistryClient.new("registry.example/team/app:stable", transport: transport, **credentials)
    Dir.mktmpdir do |directory|
      source = File.join(directory, "source")
      blob_directory = File.join(source, "blobs", "sha256")
      FileUtils.mkdir_p(blob_directory)
      blobs.each { |digest, bytes| File.binwrite(File.join(blob_directory, digest.delete_prefix("sha256:")), bytes) }
      File.write(File.join(source, "sources.json"), JSON.generate(["registry.example/team/app@#{manifest.digest}"]))
      puller = Image::Puller.new(registry_client: registry, public_blob_source: Image::PublicBlobSource.new(source))
      yield puller, transport, File.join(directory, "rootfs"), File.join(blob_directory, digest_for(ZSTD_TAR).delete_prefix("sha256:"))
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

  def test_store_backed_pull_unpacks_an_oci_zstd_layer_with_multiple_frames
    layer = ZSTD_TAR + ZSTD_PADDING
    pull_zstd(layer) do |puller, registry, rootfs|
      image = puller.pull("registry.example/team/app:stable", rootfs: rootfs)

      assert_equal rootfs, image.rootfs
      assert_equal "zstd OCI layer", File.binread(File.join(rootfs, "payload"))
      assert_equal Image::MediaTypes::OCI_IMAGE_LAYER_ZSTD, registry.blob_calls.last.fetch(:media_type)
      assert_equal layer, puller.store.fetch(image.layers.fetch(0).fetch(:descriptor).digest)
    end
  end

  def test_zstd_uncompressed_byte_limit_counts_padding_across_frames
    pull_zstd(ZSTD_TAR + ZSTD_PADDING, limits: Image::LayerLimits.new(max_uncompressed_bytes: 200_000)) do |puller, _, rootfs|
      assert_raises(Image::LimitError) { puller.pull("registry.example/team/app:stable", rootfs: rootfs) }

      refute_path_exists rootfs
    end
  end

  def test_a_downloaded_layer_is_consumed_from_its_verified_bytes_and_released
    Dir.mktmpdir do |directory|
      rootfs = File.join(directory, "rootfs")
      extractor = Image::LayerExtractor.new(rootfs)
      [false, true].each do |keep_link|
        Tempfile.open("layer-download", directory) do |download|
          download.binmode
          download.write(ZSTD_TAR)
          download.flush
          original = download.path
          alias_path = File.join(directory, "retained")
          File.link(original, alias_path) if keep_link
          bytes = extractor.extract_download(download, digest: digest_for(ZSTD_TAR), expected_size: ZSTD_TAR.bytesize,
                                                       media_type: Image::MediaTypes::OCI_IMAGE_LAYER_ZSTD)

          assert_equal ZSTD_TAR.bytesize, bytes
          assert_equal "zstd OCI layer", File.binread(File.join(rootfs, "payload"))
          assert_predicate download, :closed?
          refute_path_exists original
          assert_equal ZSTD_TAR, File.binread(alias_path) if keep_link
        end
      end
    ensure
      extractor&.close
    end
  end

  def test_a_direct_download_tempfile_is_rechecked_after_corruption
    Dir.mktmpdir do |directory|
      rootfs = File.join(directory, "rootfs")
      extractor = Image::LayerExtractor.new(rootfs)
      Tempfile.open("layer-download", directory) do |download|
        download.binmode
        download.write(ZSTD_TAR)
        download.flush
        altered = ZSTD_TAR.dup
        altered.setbyte(0, altered.getbyte(0) ^ 1)
        download.rewind
        download.write(altered)
        download.flush

        assert_raises(Image::DigestMismatch) do
          extractor.extract_download(download, digest: digest_for(ZSTD_TAR), expected_size: ZSTD_TAR.bytesize,
                                               media_type: Image::MediaTypes::OCI_IMAGE_LAYER_ZSTD)
        end
      end
      assert_empty Dir.children(rootfs)
    ensure
      extractor&.close
    end
  end

  def test_builtin_verified_download_handoff_is_bound_and_skips_a_redundant_digest_scan
    with_public_source do |puller, _transport, rootfs, _blob|
      descriptor = puller.registry_client.manifest("registry.example/team/app:stable").layers.first
      verified = puller.registry_client.download_blob("registry.example/team/app:stable", descriptor.digest,
                                                      expected_size: descriptor.size, media_type: descriptor.media_type,
                                                      handoff: true)

      refute_respond_to verified, :path
      extractor = Image::LayerExtractor.new(rootfs)
      scans = 0
      extractor.singleton_class.prepend(Module.new do
        define_method(:copy_and_verify_source) do |*arguments|
          scans += 1
          super(*arguments)
        end
      end)

      extractor.extract_download(verified, digest: descriptor.digest, expected_size: descriptor.size,
                                           media_type: descriptor.media_type)

      assert_equal 0, scans
      assert_equal "zstd OCI layer", File.binread(File.join(rootfs, "payload"))
    ensure
      extractor&.close
    end
  end

  def test_builtin_verified_download_rejects_a_descriptor_mismatch
    with_public_source do |puller, _transport, rootfs, _blob|
      descriptor = puller.registry_client.manifest("registry.example/team/app:stable").layers.first
      verified = puller.registry_client.download_blob("registry.example/team/app:stable", descriptor.digest,
                                                      expected_size: descriptor.size, media_type: descriptor.media_type,
                                                      handoff: true)
      extractor = Image::LayerExtractor.new(rootfs)

      assert_raises(Image::DigestMismatch) do
        extractor.extract_download(
          verified,
          digest: digest_for("different descriptor"),
          expected_size: descriptor.size,
          media_type: descriptor.media_type
        )
      end
      assert_predicate verified, :closed?
      assert_empty Dir.children(rootfs)
    ensure
      extractor&.close
    end
  end

  def test_builtin_get_rejects_an_altered_blob_before_read_only_handoff
    with_public_source do |source_puller, transport, rootfs, _blob|
      descriptor = source_puller.registry_client.manifest("registry.example/team/app:stable").layers.first
      altered = ZSTD_TAR.dup
      altered.setbyte(0, altered.getbyte(0) ^ 1)
      transport.instance_variable_get(:@blobs)[descriptor.digest.to_s] = altered
      puller = Image::Puller.new(registry_client: source_puller.registry_client)

      assert_raises(Image::DigestMismatch) do
        puller.pull("registry.example/team/app:stable", rootfs: rootfs)
      end
      refute_path_exists rootfs
    end
  end

  def test_layer_batches_limit_both_files_and_bytes_and_leave_large_layers_on_their_own
    mib = 1024 * 1024
    sizes = [1, 1, 1, 1, 32, 32, 1, 65, 1]
    descriptor = Data.define(:size)
    descriptors = sizes.map { |size| descriptor.new(size * mib) }
    puller = Image::Puller.new(registry_client: Object.new)
    batches = []

    puller.send(:each_layer_batch, descriptors) { |batch| batches << batch.map { |item| item.size / mib } }

    assert_equal [[1, 1, 1, 1], [32, 32], [1], [65], [1]], batches
  end

  def test_a_failed_later_batch_removes_staged_files_and_all_downloads
    config = '{"architecture":"amd64","os":"linux"}'
    manifest = build_manifest(config, ZSTD_TAR, media_type: Image::MediaTypes::OCI_IMAGE_LAYER_ZSTD)
    document = JSON.parse(manifest.raw)
    document["layers"] *= 5
    manifest = Image::Manifest.parse(JSON.generate(document))
    registry = StreamingRegistry.new(config: config, layer: ZSTD_TAR, manifest: manifest)
    downloads = []
    fetch = registry.method(:fetch_blob)
    Dir.mktmpdir do |directory|
      rootfs = File.join(directory, "rootfs")
      registry.define_singleton_method(:fetch_blob) do |reference, digest, io:, **options|
        if options[:media_type] == Image::MediaTypes::OCI_IMAGE_LAYER_ZSTD
          downloads << io
          if downloads.length == 5
            raise "first batch was not extracted" if Dir.glob(File.join(directory, ".*.staging", "payload")).empty?

            raise Image::RegistryError, "registry unavailable"
          end
        end
        fetch.call(reference, digest, io: io, **options)
      end
      puller = Image::Puller.new(registry_client: registry)

      assert_raises(Image::RegistryError) { puller.pull("registry.example/app:1", rootfs: rootfs) }
      assert_equal 5, downloads.length
      assert downloads.all?(&:closed?)
      assert_empty Dir.children(directory)
    end
  end

  def test_zstd_compressed_byte_limit_rejects_the_descriptor_before_download
    pull_zstd(ZSTD_TAR, limits: Image::LayerLimits.new(max_compressed_bytes: ZSTD_TAR.bytesize - 1)) do |puller, registry, rootfs|
      assert_raises(Image::LimitError) { puller.pull("registry.example/team/app:stable", rootfs: rootfs) }

      refute_path_exists rootfs
      assert_equal([Image::MediaTypes::OCI_IMAGE_CONFIG], registry.blob_calls.map { |call| call.fetch(:media_type) })
    end
  end

  def test_zstd_pull_rejects_a_truncated_second_frame_after_the_tar_end_marker
    truncated = ZSTD_TAR + ZSTD_PADDING.byteslice(0...-1)
    pull_zstd(truncated) do |puller, _, rootfs|
      error = assert_raises(Image::LayerError) { puller.pull("registry.example/team/app:stable", rootfs: rootfs) }

      assert_match(/truncated zstd layer stream/, error.message)
      refute_path_exists rootfs
      assert_empty Dir.glob(File.join(File.dirname(rootfs), ".*.staging"))
    end
  end

  private

  def pull_zstd(layer, limits: nil)
    config = '{"architecture":"amd64","os":"linux"}'
    manifest = build_manifest(config, layer, media_type: Image::MediaTypes::OCI_IMAGE_LAYER_ZSTD)
    registry = StreamingRegistry.new(config: config, layer: layer, manifest: manifest)
    Dir.mktmpdir("rubernetes-oci-zstd-") do |directory|
      store = Image::ContentStore.new(File.join(directory, "blobs"))
      puller = Image::Puller.new(registry_client: registry, store: store, layer_limits: limits)
      yield puller, registry, File.join(directory, "rootfs")
    end
  end

  def build_manifest(config, layer, media_type: Image::MediaTypes::OCI_IMAGE_LAYER)
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
          "mediaType" => media_type,
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
