# frozen_string_literal: true

require "digest"
require "json"

require_relative "../test_helper"
require "rubernetes/image"

class OCIManifestTest < Minitest::Test
  def test_selects_exact_platform_from_index_without_cross_arch_fallback
    index = Rubernetes::Image::Index.parse(JSON.generate(
      "schemaVersion" => 2,
      "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_INDEX,
      "manifests" => [
        descriptor("amd64", "linux", "sha256:#{'a' * 64}"),
        descriptor("arm64", "linux", "sha256:#{'b' * 64}")
      ]
    ))

    selected = index.select(os: "linux", architecture: "arm64")
    assert_equal "sha256:#{'b' * 64}", selected.digest.to_s
    assert_raises(Rubernetes::Image::ManifestError) { index.select(os: "linux", architecture: "ppc64le") }
  end

  def test_rejects_manifest_digest_and_descriptor_size_mismatch
    raw = JSON.generate(
      "schemaVersion" => 2,
      "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST,
      "config" => {
        "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_CONFIG,
        "digest" => "sha256:#{'a' * 64}",
        "size" => 1
      },
      "layers" => []
    )

    assert_raises(Rubernetes::Image::DigestMismatch) do
      Rubernetes::Image::Manifest.parse(raw, expected_digest: "sha256:#{'b' * 64}")
    end
    assert_raises(Rubernetes::Image::ManifestError) do
      Rubernetes::Image::Manifest.parse(raw, expected_size: raw.bytesize + 1)
    end
  end

  def test_rejects_duplicate_keys_in_manifest_index_and_config_json
    manifest = <<~JSON.chomp
      {"schemaVersion":2,"schemaVersion":2,"mediaType":"#{Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST}","config":{"mediaType":"#{Rubernetes::Image::MediaTypes::OCI_IMAGE_CONFIG}","digest":"sha256:#{'a' * 64}","size":2},"layers":[]}
    JSON
    index = <<~JSON.chomp
      {"schemaVersion":2,"mediaType":"#{Rubernetes::Image::MediaTypes::OCI_IMAGE_INDEX}","manifests":[{"mediaType":"#{Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST}","digest":"sha256:#{'a' * 64}","digest":"sha256:#{'b' * 64}","size":1,"platform":{"os":"linux","architecture":"amd64"}}]}
    JSON

    assert_raises(Rubernetes::Image::ManifestError) { Rubernetes::Image::Manifest.parse(manifest) }
    assert_raises(Rubernetes::Image::ManifestError) { Rubernetes::Image::Index.parse(index) }
    assert_raises(Rubernetes::Image::ManifestError) do
      Rubernetes::Image::Puller.new(client: Object.new).send(
        :parse_config,
        '{"config":{},"config":{"Cmd":["/bin/false"]}}'
      )
    end
  end

  private

  def descriptor(architecture, os, digest)
    {
      "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST,
      "digest" => digest,
      "size" => 10,
      "platform" => {"architecture" => architecture, "os" => os}
    }
  end
end
