# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/image/resolver"
require "rubernetes/runtime/native"
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

  def test_keeps_mounted_rootfs_and_images_used_as_volumes
    resolver = Resolver.new(key("old-tag") => [Image.new("/running"), 1.0], key("volume") => [Image.new("/volume"), 1.0],
                            key("unused") => [Image.new("/unused"), 1.0])
    @pods = [{"spec" => {"volumes" => [{"image" => {"reference" => "registry.example/volume:1"}}]}}]
    subject = manager(resolver, {"/running" => GI, "/volume" => GI, "/unused" => GI}, min_age: 0,
                                                                                      used_roots: -> { ["/running"] })

    assert_equal [key("unused")], subject.delete_unused_images
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

  def test_maximum_age_evicts_never_used_images_on_the_first_detection_after_the_grace_period
    @fs = {"capacityBytes" => 100 * GI, "availableBytes" => 90 * GI}
    resolver = Resolver.new({})
    subject = manager(resolver, {}, max_age: 60)

    subject.garbage_collect
    @now += 61
    resolver.entries[key("never-used")] = [Image.new("/never-used"), nil]

    assert_equal [key("never-used")], subject.garbage_collect
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

  def test_agent_gc_reclaims_recovered_stages_after_the_last_durable_owner_leaves
    Dir.mktmpdir("recovered-image-gc-") do |root|
      staging = File.join(root, "stages")
      resolver = Rubernetes::Image::Resolver.new(staging_root: staging, puller: Object.new)
      pod_root, runtime_root, locked_root = Array.new(3) { fixture_rootfs(staging) }
      lease = Rubernetes::Image::StagingLease.acquire(File.dirname(locked_root))
      [pod_root, runtime_root].each { |path| Rubernetes::Image::StagingLease.acquire(File.dirname(path)).close }
      runtime = image_ledger_runtime(root, runtime_root)
      lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
      pods = [pod_root]
      lifecycle.stub(:image_roots_in_use, -> { pods }) do
        stats = Struct.new(:image_fs_stats, :metrics_observer).new({"capacityBytes" => 100, "availableBytes" => 95})
        agent = Rubernetes::Node::Agent.new(node_name: "n", api: Object.new, runtime: runtime, lifecycle: lifecycle,
                                            stats_provider: stats, image_resolver: resolver)
        gc = agent.image_gc_manager

        assert_empty gc.garbage_collect
        [pod_root, runtime_root, locked_root].each { |path| assert_path_exists File.join(path, "payload") }

        pods.clear

        assert_empty gc.delete_unused_images
        refute_path_exists File.dirname(pod_root)
        assert_path_exists File.join(runtime_root, "payload")

        runtime.ledger.release(operation_id: "runtime-op", kind: "workspace", id: "rootfs", identity: "id", force: true)

        assert_empty gc.garbage_collect
        refute_path_exists File.dirname(runtime_root)
        assert_path_exists File.join(locked_root, "payload")
      end
    ensure
      lease&.close
    end
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

  private

  def fixture_rootfs(staging)
    File.join(Dir.mktmpdir("rubernetes-image-", staging), "rootfs").tap do |path|
      Dir.mkdir(path)
      File.binwrite(File.join(path, "payload"), "x" * (128 * 1024))
    end
  end

  def image_ledger_runtime(root, image_root)
    journal = Rubernetes::Runtime::RollbackJournal.new(File.join(root, "journal.jsonl"), fsync: false)
    runtime = Rubernetes::Runtime::Native.new(journal: journal)
    runtime.ledger.begin_operation(operation_id: "runtime-op", owner: "sandbox", config_digest: "digest")
    runtime.ledger.claim(operation_id: "runtime-op", kind: "workspace", id: "rootfs", identity: "id", metadata: {"lowerdirs" => [image_root]})
    runtime
  end
end
