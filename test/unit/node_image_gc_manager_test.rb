# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/image/resolver"
require "tmpdir"

# pkg/kubelet/images/image_gc_manager.go over the resolver's unpacked-image
# cache, which used to keep every image a Pod ever ran for the life of the
# agent.
class NodeImageGCManagerTest < Minitest::Test
  GC = Rubernetes::Node::ImageGCManager
  GI = 1024**3

  Image = Struct.new(:rootfs)

  class Resolver
    attr_reader :evicted, :entries

    def initialize(entries)
      @entries = entries
      @evicted = []
    end

    def cached_images = @entries.map { |key, (image, last)| [key, image, last] }

    def evict_cached_image(key, unused_since: nil)
      _image, last = @entries[key]
      return false if unused_since && last && last > unused_since

      @evicted << key
      @entries.delete(key)
      true
    end
  end

  def setup
    @now = 1000.0
    @fs = {"capacityBytes" => 100 * GI, "availableBytes" => 10 * GI}
    @pods = []
    @events = []
    recorder = Object.new
    events = @events
    recorder.define_singleton_method(:record) { |**event| events << event }
    @recorder = recorder
  end

  def key(name) = "registry.example/#{name}:1|linux|amd64"

  def manager(resolver, sizes, **)
    GC.new(resolver: resolver, fs_stats: -> { @fs }, pods: -> { @pods }, monotonic: -> { @now },
           size_of: ->(root) { sizes.fetch(root) }, recorder: @recorder, node_ref: {"kind" => "Node", "name" => "n"}, **)
  end

  def test_frees_least_recently_used_unused_images_down_to_the_low_threshold
    resolver = Resolver.new(key("old") => [Image.new("/old"), 10.0], key("newer") => [Image.new("/newer"), 500.0],
                            key("used") => [Image.new("/used"), 5.0], key("big") => [Image.new("/big"), 400.0])
    sizes = {"/old" => 5 * GI, "/newer" => 6 * GI, "/used" => 50 * GI, "/big" => 3 * GI}
    @pods = [{"spec" => {"containers" => [{"image" => "registry.example/used:1"}]}}]
    subject = manager(resolver, sizes)
    # First detection: every image is younger than minAge, nothing can go.
    assert_raises(GC::Error) { subject.garbage_collect }
    assert_empty resolver.evicted

    @now += 121
    # 90% used >= 85%: free capacity*(100-80)% - available = 20Gi - 10Gi = 10Gi,
    # oldest-used first: old (5Gi), big (3Gi), newer (6Gi) -> 14Gi >= 10Gi.
    assert_equal [key("old"), key("big"), key("newer")], subject.garbage_collect
    refute_includes resolver.evicted, key("used"), "an image a Pod on the node uses is never deleted"
  end

  def test_below_the_high_threshold_nothing_is_deleted
    @fs = {"capacityBytes" => 100 * GI, "availableBytes" => 16 * GI}
    resolver = Resolver.new(key("a") => [Image.new("/a"), 1.0])
    subject = manager(resolver, {"/a" => GI})
    subject.garbage_collect
    @now += 500

    assert_empty subject.garbage_collect
  end

  def test_insufficient_space_raises_and_records_free_disk_space_failed
    resolver = Resolver.new(key("a") => [Image.new("/a"), 1.0])
    subject = manager(resolver, {"/a" => GI})
    begin
      subject.garbage_collect
    rescue StandardError
      nil
    end
    @now += 121
    error = assert_raises(GC::Error) { subject.garbage_collect }
    message = "Insufficient free disk space on the node's image filesystem (90% of 100.0 GiB used). Failed to free sufficient " \
              "space by deleting unused images (freed #{GI} bytes). Investigate disk usage, as it could be used by active " \
              "images, logs, volumes, or other data."

    assert_equal message, error.message
    assert_equal "FreeDiskSpaceFailed", @events.last[:reason]
    assert_equal message, @events.last[:message]
  end

  def test_zero_capacity_is_an_error
    @fs = {"capacityBytes" => 0, "availableBytes" => 0}
    subject = manager(Resolver.new({}), {})
    assert_raises(GC::Error) { subject.garbage_collect }
    assert_equal "InvalidDiskCapacity", @events.last[:reason]
  end

  def test_an_image_handed_out_after_the_pass_began_is_kept
    resolver = Resolver.new(key("a") => [Image.new("/a"), 1.0])
    subject = manager(resolver, {"/a" => GI})
    begin
      subject.garbage_collect
    rescue StandardError
      nil
    end
    @now += 121
    resolver.entries[key("a")][1] = @now + 1 # a Pod resolved it mid-pass

    assert_empty subject.delete_unused_images
  end

  def test_maximum_age_frees_old_unused_images_whatever_the_usage
    @fs = {"capacityBytes" => 100 * GI, "availableBytes" => 90 * GI}
    resolver = Resolver.new(key("stale") => [Image.new("/stale"), 1.0], key("fresh") => [Image.new("/fresh"), nil])
    subject = manager(resolver, {"/stale" => GI, "/fresh" => GI}, max_age: 600)
    subject.garbage_collect
    @now += 601
    resolver.entries[key("fresh")][1] = @now - 10

    assert_equal [key("stale")], subject.garbage_collect
  end

  def test_delete_unused_images_honours_the_minimum_age
    resolver = Resolver.new(key("a") => [Image.new("/a"), 1.0], key("b") => [Image.new("/b"), 2.0])
    subject = manager(resolver, {"/a" => GI, "/b" => GI})

    assert_empty subject.delete_unused_images
    @now += 121

    assert_equal [key("a"), key("b")], subject.delete_unused_images
  end

  def test_threshold_validation
    assert_raises(ArgumentError) { manager(Resolver.new({}), {}, high_threshold_percent: 101) }
    error = assert_raises(ArgumentError) { manager(Resolver.new({}), {}, high_threshold_percent: 50, low_threshold_percent: 60) }
    assert_equal "LowThresholdPercent 60 can not be higher than HighThresholdPercent 50", error.message
  end

  # The real resolver: cached_images reports what it handed out and when;
  # evicting deletes the unpacked stage only when nothing took it since.
  def test_resolver_cache_hooks
    resolver = Rubernetes::Image::Resolver.new(puller: Object.new)
    resolved = Struct.new(:rootfs, :stage_token).new(Dir.mktmpdir, nil)
    resolver.send(:store_image, "k|linux|amd64", resolved)
    key, image, last = resolver.cached_images.first

    assert_equal "k|linux|amd64", key
    assert_same resolved, image
    refute_nil last
    refute resolver.evict_cached_image(key, unused_since: last - 1), "handed out after the pass began"
    assert resolver.evict_cached_image(key, unused_since: last + 1)
    assert_empty resolver.cached_images
  ensure
    FileUtils.rm_rf(resolved.rootfs) if resolved
  end
end
