# frozen_string_literal: true

require "set"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/runtime/cri"

# The kubelet's image GC over a CRI runtime: unused, unpinned images are
# removed oldest first until usage is under the low threshold; an image in
# use under any of its tags stays.
class CRIImageGCTest < Minitest::Test
  class Client
    attr_reader :removed

    def initialize(images)
      @images = images
      @removed = []
    end

    def image(method, request = {}, **)
      case method
      when "ListImages" then {"images" => @images.reject { |image| @removed.include?(image["id"]) }}
      when "RemoveImage" then (@removed << request.dig("image", "image")) && {}
      when "ImageFsInfo" then {"image_filesystems" => [{"fs_id" => {"mountpoint" => ""}, "used_bytes" => {"value" => 0}}]}
      end
    end
  end

  def test_unused_unpinned_images_are_collected
    images = [
      {"id" => "sha256:pause", "repo_tags" => ["registry.k8s.io/pause:3.10"], "size" => 700_000, "pinned" => true},
      {"id" => "sha256:old", "repo_tags" => ["docker.io/library/old:1"], "size" => 40},
      {"id" => "sha256:used", "repo_tags" => ["docker.io/library/alias:1", "docker.io/library/busybox:1.36"], "size" => 30},
      {"id" => "sha256:new", "repo_tags" => ["docker.io/library/new:1"], "size" => 10}
    ]
    client = Client.new(images)
    in_use = -> { Set["docker.io/library/busybox:1.36"] }
    source = Rubernetes::Runtime::CRI::ImageGCSource.new(client: client, in_use: in_use)
    assert_equal ["docker.io/library/old:1|sha256:old", "docker.io/library/busybox:1.36|sha256:used", "docker.io/library/new:1|sha256:new"],
                 source.cached_images.map(&:first), "pinned never offered; a used tag keys a shared image"

    fs = {"capacityBytes" => 100, "availableBytes" => 10}
    pods = [{"spec" => {"containers" => [{"image" => "busybox:1.36"}]}}]
    now = 0.0
    manager = Rubernetes::Node::ImageGCManager.new(resolver: source, fs_stats: -> { fs }, pods: -> { pods },
                                                    high_threshold_percent: 85, low_threshold_percent: 60, min_age: 0,
                                                    monotonic: -> { now })
    manager.send(:images_in_eviction_order, now)
    now = 10.0
    fs = {"capacityBytes" => 100, "availableBytes" => 10}
    source.define_singleton_method(:evict_cached_image) do |key, unused_since: nil|
      result = super(key, unused_since: unused_since)
      fs = fs.merge("availableBytes" => fs["availableBytes"] + 20)
      result
    end
    manager.garbage_collect
    assert_equal ["sha256:new", "sha256:old"], client.removed.sort, "freed until under 60% used; the busybox image stays in use"
  end
end
