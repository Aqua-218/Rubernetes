# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/image"
require "rubernetes/node"

# A Pod's distinct images were pulled one after the other: a DNS spec's Pod
# waited for agnhost and then for jessie-dnsutils.  They are pulled side by
# side now, and a failed pull still leaves ErrImagePull.
class NodeParallelImagePullTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle
  Image = Rubernetes::Image

  Resolved = Struct.new(:reference, :digest, :rootfs, :command, :env, :working_dir, :entrypoint, :cmd, :os, :architecture, :config,
                        keyword_init: true)

  class SlowResolver
    attr_reader :calls

    def initialize(failing: nil)
      @failing = failing
      @calls = Queue.new
    end

    def resolve(reference, **_options)
      @calls << reference
      sleep 0.3
      raise "manifest unknown" if reference == @failing

      Resolved.new(reference: reference, digest: "sha256:#{"c" * 64}", rootfs: "/tmp/#{reference.tr("/:", "__")}",
                   command: ["/bin/sh"], env: {}, working_dir: "/", entrypoint: [], cmd: ["/bin/sh"],
                   os: "linux", architecture: "amd64", config: {})
    end
  end

  class PausingPuller
    def initialize(blocked)
      @blocked = blocked
    end

    def pull(reference, platform:, rootfs:, unpack:)
      if reference.repository == "library/jessie-dnsutils"
        @blocked.pop
        raise Image::RegistryError, "manifest unknown"
      end

      digest = Image::Digest.parse("sha256:#{"c" * 64}")
      config = {"os" => platform.os, "architecture" => platform.architecture, "config" => {"Cmd" => ["/bin/sh"]}}
      FileUtils.mkdir_p(rootfs)
      Image::Image.new(reference: reference.with_digest(digest), manifest: Struct.new(:digest).new(digest),
                       config: JSON.generate(config), rootfs: rootfs, config_object: config)
    end
  end

  def pod
    {"metadata" => {"name" => "dns", "namespace" => "ns", "uid" => "u"},
     "spec" => {"containers" => [{"name" => "webserver", "image" => "agnhost:2.59"},
                                 {"name" => "querier", "image" => "agnhost:2.59"},
                                 {"name" => "jessie", "image" => "jessie-dnsutils:1.7"}]}}
  end

  def lifecycle(resolver)
    subject = Lifecycle.allocate
    subject.instance_variable_set(:@image_resolver, resolver)
    subject.define_singleton_method(:event) { |*_args, **_options| nil }
    subject.define_singleton_method(:image_keyring) { |_pod| nil }
    subject.define_singleton_method(:image_to_hash) do |resolved, reference = nil|
      {"image" => reference, "digest" => resolved.digest, "rootfs" => resolved.rootfs}
    end
    subject
  end

  def record = {images: [], image_by_container: {}, volume_images: {}, volume_image_handles: [], reason: nil}

  def test_distinct_images_are_pulled_side_by_side_once_each
    resolver = SlowResolver.new
    subject = lifecycle(resolver)
    state = record
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    subject.send(:pin_images, pod, state)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_operator elapsed, :<, 0.55, "two 0.3 s pulls ran concurrently"
    assert_equal 2, resolver.calls.size
    assert_equal %w[agnhost:2.59 jessie-dnsutils:1.7], state[:images].map(&:reference)
    assert_equal 3, state[:image_by_container].size
  end

  def test_a_failed_pull_is_err_image_pull
    subject = lifecycle(SlowResolver.new(failing: "jessie-dnsutils:1.7"))
    state = record
    error = assert_raises(Lifecycle::LifecycleError) { subject.send(:pin_images, pod, state) }

    assert_equal "ErrImagePull", state[:reason]
    assert_includes error.message, "jessie-dnsutils:1.7"
  end

  def test_image_gc_cannot_evict_the_first_rootfs_while_a_sibling_pull_is_pending
    Dir.mktmpdir("image-claims") do |directory|
      blocked = Queue.new
      claimed = Queue.new
      resolver = Image::Resolver.new(puller: PausingPuller.new(blocked), staging_root: directory)
      cached = resolver.resolve("agnhost:2.59")
      resolver.define_singleton_method(:claim_image) do |image|
        super(image).tap { |handle| claimed << handle }
      end
      subject = Lifecycle.new(runtime: Object.new, image_resolver: resolver)
      gc = Rubernetes::Node::ImageGCManager.new(resolver: resolver, fs_stats: -> {}, pods: -> { subject.pods_on_node },
                                                used_roots: -> { subject.image_roots_in_use }, min_age: 0)
      worker = Thread.new { subject.start(pod) }

      assert_equal cached.rootfs, claimed.pop(timeout: 2)&.rootfs
      assert_empty subject.image_roots_in_use, "the image batch has not been pinned yet"
      assert_empty gc.delete_unused_images
      assert_path_exists cached.rootfs

      blocked << true

      assert_equal "Pending", worker.value.phase
      assert_equal 1, gc.delete_unused_images.length, "failed startup releases its successful sibling's claim"
      refute_path_exists cached.rootfs
    ensure
      blocked << true if worker&.alive?
      worker&.join
    end
  end

  def test_only_the_failed_init_image_reports_the_scheduled_pull_backoff
    failed_image = "broken:1"
    subject = Lifecycle.new(runtime: Object.new, image_resolver: SlowResolver.new(failing: failed_image))
    object = pod
    object["spec"]["initContainers"] = [{"name" => "prepare", "image" => failed_image}]
    wait_reason = ->(status) { status.first.dig("state", "waiting", "reason") }

    first = subject.start(object)

    assert_equal "Pending", first.phase
    assert_equal "ErrImagePull", wait_reason.call(first.status.fetch("initContainerStatuses"))

    backing_off = subject.reconcile(object)

    assert_equal "ImagePullBackOff", wait_reason.call(backing_off.status.fetch("initContainerStatuses"))
    assert_equal "PodInitializing", wait_reason.call(backing_off.status.fetch("containerStatuses"))
  end
end
