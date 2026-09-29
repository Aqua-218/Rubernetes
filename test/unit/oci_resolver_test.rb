# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
require "tmpdir"

class OCIResolverTest < Minitest::Test
  Image = Rubernetes::Image

  class FakePuller
    attr_reader :platforms, :references

    def initialize(config:, digest:)
      @config = config
      @digest = digest
      @platforms = []
      @references = []
    end

    def pull(reference, platform:, rootfs:, unpack:)
      @references << reference
      @platforms << platform
      raise "resolver must request extraction" unless unpack

      FileUtils.mkdir_p(rootfs)
      Image::Image.new(
        reference: reference.with_digest(@digest),
        manifest: Struct.new(:digest).new(@digest),
        config: JSON.generate(@config),
        rootfs: rootfs,
        config_object: @config
      )
    end
  end

  def setup
    @digest = Image::Digest.parse("sha256:#{"a" * 64}")
    @config = {
      "architecture" => "arm64",
      "os" => "linux",
      "config" => {
        "Entrypoint" => ["/bin/app"],
        "Cmd" => ["--serve"],
        "Env" => ["IMAGE_FLAG=on"],
        "WorkingDir" => "/srv"
      }
    }
    @puller = FakePuller.new(config: @config, digest: @digest)
  end

  def test_resolves_tag_to_pinned_digest_and_target_platform_without_network
    resolver = Image::Resolver.new(
      puller: @puller,
      platform: {"os" => "linux", "architecture" => "arm64"}
    )

    resolved = resolver.resolve("registry.example/app:stable")

    assert_equal("registry.example/app@sha256:#{"a" * 64}", resolved.reference.to_s)
    assert_equal(@digest, resolved.digest)
    assert_equal("arm64", @puller.platforms.fetch(0).architecture)
    assert_equal(["/bin/app", "--serve"], resolved.command)
    assert_equal({"IMAGE_FLAG" => "on"}, resolved.env)
    assert_equal("/srv", resolved.working_dir)
    assert(File.directory?(resolved.rootfs))
  ensure
    resolver&.release(resolved) if resolved
  end

  def test_rejects_config_architecture_mismatch_before_returning_image
    resolver = Image::Resolver.new(puller: @puller, platform: {"os" => "linux", "architecture" => "amd64"})

    assert_raises(Image::ManifestError) { resolver.resolve("registry.example/app:stable") }
  end

  # pull_policy Always: an uncached stage is owned by its one caller, so its
  # release removes it (a cached, shared stage is kept -- see
  # ImageResolverCacheTest).
  def test_release_accepts_only_a_registry_token_and_never_deletes_staging_root
    Dir.mktmpdir("rubernetes-image-staging-") do |staging_root|
      resolver = Image::Resolver.new(
        puller: @puller,
        platform: {"os" => "linux", "architecture" => "arm64"},
        staging_root: staging_root
      )
      # The first pull is the node's copy of the image, kept for later Pods
      # (release leaves it); pull policy Always pulls again into a stage of
      # the Pod's own, which release deletes.
      stages = -> { Dir.children(staging_root).map { |entry| File.join(staging_root, entry) } }
      node_copy = resolver.resolve("registry.example/app:stable", pull_policy: "Always")
      kept = stages.call
      assert resolver.release(node_copy)
      assert_equal kept, stages.call
      resolved = resolver.resolve("registry.example/app:stable", pull_policy: "Always")
      stage = (stages.call - kept).fetch(0)

      forged_path = Struct.new(:stage_root).new(staging_root)
      assert resolver.release(forged_path)
      assert File.directory?(staging_root)
      assert File.directory?(stage)

      forged_token = Struct.new(:stage_token).new(Object.new.freeze)
      refute resolver.release(forged_token)
      assert File.directory?(stage)

      assert resolver.release(resolved)
      refute File.exist?(stage)
      assert File.directory?(staging_root)

      swapped = resolver.resolve("registry.example/app:stable", pull_policy: "Always")
      swapped_stage = (stages.call - kept).find { |path| File.directory?(path) }
      outside = File.join(staging_root, "outside")
      Dir.mkdir(outside)
      File.rename(swapped_stage, File.join(staging_root, "stage-held"))
      File.symlink(outside, swapped_stage)

      refute resolver.release(swapped)
      assert File.directory?(outside)
      assert File.directory?(File.join(staging_root, "stage-held"))
    end
  end
end

class NativeImageRuntimeIntegrationTest < Minitest::Test
  Native = Rubernetes::Runtime::Native
  DIGEST = "sha256:#{"b" * 64}"

  class FakeResolver
    attr_reader :references, :released

    def initialize(rootfs)
      @rootfs = rootfs
      @references = []
      @released = []
    end

    def resolve(reference)
      @references << reference
      {
        "reference" => reference.to_s,
        "digest" => DIGEST,
        "rootfs" => @rootfs,
        "entrypoint" => ["/bin/app"],
        "cmd" => ["--serve"],
        "env" => {"IMAGE_FLAG" => "on"},
        "working_dir" => "/srv"
      }
    end

    def release(image)
      @released << image
      true
    end
  end

  def test_native_resolves_tag_before_container_creation_and_honors_command_override
    Dir.mktmpdir("rubernetes-image-root-") do |rootfs|
      resolver = FakeResolver.new(rootfs)
      process = Native::FakeProcessAdapter.new
      runtime = Native.new(image_resolver: resolver, process_adapter: process)
      sandbox = runtime.run_sandbox("image" => "registry.example/app:stable")

      first = runtime.create_container(sandbox, {"name" => "first", "image" => "registry.example/app:stable"})
      second = runtime.create_container(
        sandbox,
        {"name" => "second",
         "image" => "registry.example/app:stable",
         "command" => ["/bin/custom"]}
      )
      runtime.start_container(first)
      runtime.start_container(second)

      assert_equal(["/bin/app", "--serve"], process.calls.fetch(-4).fetch(1))
      assert_equal({"IMAGE_FLAG" => "on"}, process.calls.fetch(-4).fetch(2))
      assert_equal(["/bin/custom"], process.calls.fetch(-2).fetch(1))
      assert_equal(1, resolver.references.length)
      assert_equal(DIGEST, runtime.container_status(first).fetch("spec").fetch("image_digest"))
      assert_equal(DIGEST, runtime.container_status(second).fetch("spec").fetch("image_digest"))
    end
  end

  def test_native_rejects_image_reference_without_injected_resolver_before_effects
    runtime = Native.new

    assert_raises(Native::FailClosed) do
      runtime.run_sandbox("image" => "registry.example/app:mutable")
    end
    assert_empty(runtime.sandboxes)
    assert_empty(runtime.trace)
  end
end

class LifecycleImagePinningTest < Minitest::Test
  class EffectRuntime
    attr_reader :calls

    def initialize
      @calls = []
    end

    def run_sandbox(_pod, **)
      @calls << :sandbox
      "sandbox"
    end
  end

  class FailingResolver
    def resolve(_reference)
      raise Rubernetes::Image::DigestMismatch, "manifest digest mismatch"
    end
  end

  class RuntimeResolver
    attr_reader :released

    def initialize(rootfs)
      @rootfs = rootfs
      @released = []
    end

    def resolve(reference)
      {
        "reference" => reference.to_s,
        "digest" => "sha256:#{"c" * 64}",
        "rootfs" => @rootfs,
        "entrypoint" => ["/bin/app"],
        "cmd" => ["--serve"],
        "env" => {"IMAGE_FLAG" => "on"}
      }
    end

    def release(image)
      @released << image
      true
    end
  end

  def test_digest_failure_happens_before_volume_or_runtime_effects
    runtime = EffectRuntime.new
    volume_calls = []
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      image_resolver: FailingResolver.new,
      volume: ->(_pod) { volume_calls << :prepare }
    )
    pod = {
      "metadata" => {"name" => "image-failure", "uid" => "image-failure"},
      "spec" => {"containers" => [{"name" => "app", "image" => "registry.example/app:mutable"}]}
    }

    result = lifecycle.start(pod)

    # kubelet retries an image failure (ErrImagePull/ImagePullBackOff keeps
    # the Pod Pending); only a terminal admission rejection reaches Failed.
    assert_equal("Pending", result.phase)
    assert_match(/manifest digest mismatch/, result.error)
    assert_empty(volume_calls)
    assert_empty(runtime.calls)
  end

  def test_ordinary_pod_is_pinned_before_native_workload_start
    Dir.mktmpdir("rubernetes-pod-root-") do |rootfs|
      resolver = RuntimeResolver.new(rootfs)
      process = Rubernetes::Runtime::Native::FakeProcessAdapter.new
      runtime = Rubernetes::Runtime::Native.new(image_resolver: resolver, process_adapter: process)
      lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, image_resolver: resolver)
      pod = {
        "metadata" => {"name" => "ordinary-image", "uid" => "ordinary-image"},
        "spec" => {"containers" => [{"name" => "app", "image" => "registry.example/app:stable"}]}
      }

      result = lifecycle.start(pod)

      assert_equal("Running", result.phase)
      assert_equal(["/bin/app", "--serve"], process.calls.fetch(0).fetch(1))
      assert_equal({"IMAGE_FLAG" => "on"}, process.calls.fetch(0).fetch(2))
      terminated = lifecycle.terminate(pod)
      assert_equal("Succeeded", terminated.phase)
      assert_equal(1, resolver.released.length)
    end
  end

  # An agent that dies leaves staging directories that nothing can release
  # any more; without a startup reclaim they accumulate until the node's disk
  # is full and every later image pull fails with ENOSPC.
  def test_reclaim_removes_only_stages_whose_owner_is_gone
    Dir.mktmpdir("rubernetes-reclaim-") do |root|
      abandoned = File.join(root, "rubernetes-image-20260908-999999-abcdef")
      FileUtils.mkdir_p(File.join(abandoned, "rootfs"))
      File.write(File.join(abandoned, "rootfs", "layer"), "x" * 128)
      owned = File.join(root, "rubernetes-image-20260908-#{Process.pid}-abcdef")
      FileUtils.mkdir_p(owned)
      unrelated = File.join(root, "someone-elses-directory")
      FileUtils.mkdir_p(unrelated)

      assert_equal(1, Rubernetes::Image::Resolver.reclaim_abandoned_stages(staging_root: root))
      refute(File.exist?(abandoned), "a stage whose creating process is gone must be reclaimed")
      assert(File.directory?(owned), "a stage owned by a live process must be left alone")
      assert(File.directory?(unrelated), "only this resolver's own staging names may be removed")
      assert_equal(0, Rubernetes::Image::Resolver.reclaim_abandoned_stages(staging_root: root))
    end
  end
end
