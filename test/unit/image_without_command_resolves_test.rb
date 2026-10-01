# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "tmpdir"
require "fileutils"
require "rubernetes/image"

# An image whose config has neither Entrypoint nor Cmd (cilium's
# operator-generic, distroless bases) is a valid image: the Pod supplies the
# command.  Refusing it at pull time made every such Pod ErrImagePull; the
# missing-command error belongs to container creation, when the Pod gives
# none either.
class ImageWithoutCommandResolvesTest < Minitest::Test
  Image = Rubernetes::Image

  class FakePuller
    def initialize(config:, digest:)
      @config = config
      @digest = digest
    end

    def pull(reference, platform:, rootfs:, unpack:)
      FileUtils.mkdir_p(rootfs)
      Image::Image.new(reference: reference.with_digest(@digest), manifest: Struct.new(:digest).new(@digest),
                       config: JSON.generate(@config), rootfs: rootfs, config_object: @config)
    end
  end

  def test_image_without_entrypoint_or_cmd_resolves_with_an_empty_command
    digest = Image::Digest.parse("sha256:#{"b" * 64}")
    config = {"architecture" => "amd64", "os" => "linux", "config" => {"Env" => ["A=1"]}}
    resolver = Image::Resolver.new(puller: FakePuller.new(config: config, digest: digest),
                                   platform: {"os" => "linux", "architecture" => "amd64"})

    resolved = resolver.resolve("quay.io/cilium/operator-generic:v1.20.1")

    assert_empty resolved.command
    assert_empty resolved.entrypoint
    assert_empty resolved.cmd
    assert_equal({"A" => "1"}, resolved.env)
  ensure
    resolver&.release(resolved) if resolved
  end

  def test_container_without_any_command_is_refused_at_container_build
    require "rubernetes/node/container_spec"
    error = assert_raises(Rubernetes::Node::ContainerSpec::ConfigError) do
      Rubernetes::Node::ContainerSpec.new.send(:build_command, {"name" => "c", "image" => "img"}, {"entrypoint" => [], "cmd" => []}, {})
    end

    assert_includes error.message, "no command"
  end
end
