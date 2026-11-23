# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/runtime/cri"
require "rubernetes/runtime/multiplexer"

# The kubelet's image GC over a CRI runtime: unused, unpinned images are
# removed oldest first until usage is under the low threshold; an image in
# use under any of its tags stays.
class CRIImageGCTest < Minitest::Test
  class Client
    attr_reader :removed
    attr_accessor :filesystems

    def initialize(images)
      @images = images
      @removed = []
    end

    def image(method, request = {}, **)
      case method
      when "ListImages" then {"images" => @images.reject { |image| @removed.include?(image["id"]) }}
      when "RemoveImage" then (@removed << request.dig("image", "image")) && {}
      when "ImageFsInfo" then @filesystems || {}
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

  def test_maximum_age_evicts_a_never_used_cri_image_on_the_first_detection_after_the_grace_period
    client = Client.new([{"id" => "sha256:never", "repo_tags" => ["registry.example/never:1"], "size" => 1}])
    source = Rubernetes::Runtime::CRI::ImageGCSource.new(client: client)
    now = 0.0
    manager = Rubernetes::Node::ImageGCManager.new(resolver: source, fs_stats: -> { {"capacityBytes" => 100, "availableBytes" => 90} },
                                                   pods: -> { [] }, min_age: 1, max_age: 60, monotonic: -> { now })

    assert_empty manager.garbage_collect
    now = 61.0

    assert_equal ["registry.example/never:1|sha256:never"], manager.garbage_collect
    assert_equal ["sha256:never"], client.removed
  end

  def test_runtime_class_scopes_used_images_and_eviction_by_handler
    rows = %w[standard isolated].map do |handler|
      {"id" => "sha256:shared", "repo_tags" => ["docker.io/library/app:1"], "size" => 10,
       "spec" => {"runtime_handler" => handler}}
    end
    client = Client.new(rows)
    client.define_singleton_method(:runtime) do |method, _request|
      raise "unexpected RPC #{method}" unless method == "ListContainers"

      {"containers" => [{"image_id" => "sha256:shared", "image" => {"runtime_handler" => "standard"}}]}
    end
    removed = []
    client.define_singleton_method(:image) do |method, request = {}|
      if method == "RemoveImage"
        removed << request.fetch("image")
        {}
      else
        super(method, request)
      end
    end
    source = Rubernetes::Runtime::CRI::ImageGCSource.new(client: client, runtime_class_in_image_api: true)
    now = 0.0
    pods = [{"spec" => {"containers" => [{"image" => "app:1"}]}}]
    stats = {"capacityBytes" => 100, "availableBytes" => 10}
    manager = Rubernetes::Node::ImageGCManager.new(resolver: source, fs_stats: -> { stats }, pods: -> { pods },
                                                   high_threshold_percent: 85, low_threshold_percent: 85, min_age: 0,
                                                   monotonic: -> { now })
    source.define_singleton_method(:evict_cached_image) do |key, unused_since: nil|
      result = super(key, unused_since: unused_since)
      stats["availableBytes"] += 10
      result
    end

    assert_equal ["sha256:shared|isolated"], manager.garbage_collect
    assert_equal [{"image" => "sha256:shared", "runtime_handler" => "isolated"}], removed
  end

  def test_split_cri_filesystems_preserve_usage_and_their_own_device_capacity
    skip "no separate tmpfs for filesystem statistics" unless File.directory?("/dev/shm") && File.stat("/dev/shm").dev != File.stat("/").dev

    client = Client.new([])
    client.filesystems = {"image_filesystems" => [filesystem("/dev/shm", bytes: 80, inodes: 2)],
                          "container_filesystems" => [filesystem("/", bytes: 3, inodes: 1)]}
    stats = Rubernetes::Node::StatsProvider.new(node_name: "node", lifecycle: Object.new, runtime: Object.new, pod_root: "/",
                                                image_root: "/", cri_image_client: client)
    summary, layout = stats.summary_with_filesystems
    image, container = summary.dig("node", "runtime").values_at("imageFs", "containerFs")

    assert_equal [true, true], layout
    assert_equal [80, 2], image.values_at("usedBytes", "inodesUsed")
    assert_equal [3, 1], container.values_at("usedBytes", "inodesUsed")
    assert_equal [Rubernetes::Platform::Linux::Statfs.statfs("/dev/shm").capacity_bytes, summary.dig("node", "fs", "capacityBytes")],
                 [image.fetch("capacityBytes"), container.fetch("capacityBytes")]

    client.filesystems = {"image_filesystems" => [filesystem("/proc/self/nonexistent-cri-store", bytes: 12, inodes: 1)]}
    summary, layout = stats.summary_with_filesystems

    assert_nil layout
    assert_equal 12, summary.dig("node", "runtime", "imageFs", "usedBytes")
    refute summary.dig("node", "runtime", "imageFs").key?("capacityBytes")
  end

  def test_eviction_reclaims_from_the_default_runtime_only_after_confirming_its_node_device
    images = [{"id" => "sha256:unused", "repo_tags" => ["docker.io/library/old:1"], "size" => 40}]
    selected = Client.new(images)
    alternate = Client.new(images)
    alternate.filesystems = {"image_filesystems" => [filesystem("/", bytes: 10, inodes: 1)]}
    cri = Rubernetes::Runtime::CRI
    backends = {alternate: cri::Backend.new(client: alternate), selected: cri::Backend.new(client: selected)}
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: backends, default: "selected")
    now = Time.utc(2026, 1, 1)
    stats = Rubernetes::Node::StatsProvider.new(node_name: "node", lifecycle: Object.new, runtime: runtime, pod_root: "/",
                                                cri_image_client: selected, clock: -> { now })
    agent = Rubernetes::Node::Agent.new(node_name: "node", api: Object.new, runtime: runtime, stats_provider: stats,
                                        eviction: {"hard" => {"nodefs.available" => "100Ti"}}, image_gc: {"minimum_age" => "0s"})

    assert_empty agent.eviction_manager.synchronize
    assert_empty selected.removed
    assert_empty alternate.removed

    now += 1
    selected.filesystems = {"image_filesystems" => [filesystem("/", bytes: 10, inodes: 1)]}

    assert_empty agent.eviction_manager.synchronize
    assert_equal ["sha256:unused"], selected.removed
    assert_empty alternate.removed
  end

  private

  def filesystem(path, bytes:, inodes:)
    {"fs_id" => {"mountpoint" => path}, "timestamp" => "123000000000", "used_bytes" => {"value" => bytes}, "inodes_used" => {"value" => inodes}}
  end
end
