# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/image"

# kubelet nodestatus.Images / RuntimeHandlers: the node's images (native store
# and CRI runtimes) largest first, 50 at most, digests then tags, 5 names at
# most; the handlers with the features they really have.
class NodeStatusImagesTest < Minitest::Test
  Layer = Struct.new(:size)
  Manifest = Struct.new(:layers, :config)
  Image = Struct.new(:reference, :digest, :manifest)

  class Resolver
    def initialize(images) = @images = images
    def cached_images = @images.map { |image| ["#{image.reference}|linux|amd64", image, nil] }
  end

  class CRIClient
    def image(_method, _request = {}, **)
      {"images" => [{"repo_tags" => ["registry.k8s.io/pause:3.10"], "repo_digests" => ["registry.k8s.io/pause@sha256:aa"], "size" => 700}]}
    end
  end

  def native(reference, size)
    ref = Rubernetes::Image::Reference.parse(reference)
    Image.new(ref, "sha256:#{"%064x" % size}", Manifest.new([Layer.new(size - 10)], Layer.new(10)))
  end

  def test_images_are_largest_first_with_digests_then_tags
    now = 0.0
    status = Rubernetes::Node::StatusImages.new(resolver: Resolver.new([native("busybox:1.36", 500), native("nginx:1.25", 9000)]),
                                                cri_clients: [CRIClient.new], clock: -> { now })
    images = status.images

    assert_equal([9000, 700, 500], images.map { |image| image["sizeBytes"] })
    assert_equal ["docker.io/library/nginx@sha256:#{format("%064x", 9000)}", "docker.io/library/nginx:1.25"], images.first["names"]
    assert_equal ["registry.k8s.io/pause@sha256:aa", "registry.k8s.io/pause:3.10"], images[1]["names"]
    assert_same images, status.images, "refreshed at most every 30 s"
  end

  def test_at_most_fifty_images_and_five_names
    many = Array.new(60) { |index| native("repo/image#{index}:1", 100 + index) }
    images = Rubernetes::Node::StatusImages.new(resolver: Resolver.new(many)).images

    assert_equal 50, images.length
    assert_equal 159, images.first["sizeBytes"]
  end

  def test_runtime_handlers_report_real_features
    agent = Rubernetes::Node::Agent.allocate
    agent.instance_variable_set(:@runtime, Object.new)
    handlers = agent.send(:node_runtime_handlers)

    assert_equal(["", "rubernetes-native"], handlers.map { |handler| handler["name"] })
    assert_equal({"recursiveReadOnlyMounts" => true, "userNamespaces" => true}, handlers.first["features"])
  end
end
