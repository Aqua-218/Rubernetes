# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/image"

class OCIReferenceTest < Minitest::Test
  def test_normalizes_docker_hub_short_reference_and_pins_digest
    reference = Rubernetes::Image::Reference.parse(
      "ubuntu:24.04@sha256:#{"a" * 64}"
    )

    assert_equal "docker.io", reference.registry
    assert_equal "library/ubuntu", reference.repository
    assert_equal "24.04", reference.tag
    assert_equal "sha256:#{"a" * 64}", reference.digest.to_s
    assert_equal "docker.io/library/ubuntu:24.04@sha256:#{"a" * 64}", reference.to_s
  end

  def test_keeps_registry_qualified_repository_namespaces
    reference = Rubernetes::Image::Reference.parse("registry.example:5000/team/app:stable")

    assert_equal "registry.example:5000", reference.registry
    assert_equal "team/app", reference.repository
    assert_equal "stable", reference.tag
  end

  def test_rejects_ambiguous_or_malformed_references
    [
      "",
      "https://registry.example/app:latest",
      "registry.example/team/../app:latest",
      "registry.example/team/app@sha256:#{"b" * 63}",
      "registry.example/team/app:bad tag"
    ].each do |value|
      assert_raises(Rubernetes::Image::ReferenceError) { Rubernetes::Image::Reference.parse(value) }
    end
  end
end
