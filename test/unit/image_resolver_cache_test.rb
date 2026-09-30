# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/image"
require "tmpdir"
require "json"
require "fileutils"

# Every Pod re-pulled AND re-unpacked its image into a fresh rootfs: measured
# at 83s per Pod for agnhost:2.57 on a node that had unpacked the same image
# minutes earlier.  That is ~85s added to every Pod of every conformance spec,
# which is the dominant cause both of specs timing out and of a 446-spec run
# taking 40h instead of 3h.  Upstream does not re-pull for the default
# imagePullPolicy of a tagged image (IfNotPresent).
class ImageResolverCacheTest < Minitest::Test
  Resolver = Rubernetes::Image::Resolver

  class CountingPuller
    attr_reader :pulls

    def initialize(root)
      @root = root
      @pulls = 0
    end

    def pull(reference, platform:, rootfs:, unpack:)
      @pulls += 1
      FileUtils.mkdir_p(rootfs)
      File.write(File.join(rootfs, "marker"), "pull-#{@pulls}")
      Struct.new(:reference, :digest, :manifest, :rootfs, :config, keyword_init: true).new(
        reference: reference.to_s,
        digest: "sha256:#{"a" * 64}",
        manifest: nil,
        rootfs: rootfs,
        config: config_document(platform)
      )
    end

    def config_document(platform)
      JSON.generate("os" => platform.os, "architecture" => platform.architecture,
                    "config" => {"Cmd" => ["/bin/sh"], "Env" => [], "WorkingDir" => ""})
    end
  end

  def with_resolver
    Dir.mktmpdir("image-cache") do |dir|
      puller = CountingPuller.new(dir)
      yield Resolver.new(puller: puller, staging_root: dir), puller
    end
  end

  # Releasing a Pod's image must not delete the unpacked rootfs other Pods
  # are still running from.
  def test_releasing_a_shared_cached_image_keeps_its_rootfs
    with_resolver do |resolver, _puller|
      first = resolver.resolve("registry.example.com/app:1.0")
      second = resolver.resolve("registry.example.com/app:1.0")

      assert resolver.release(first)
      assert File.directory?(second.rootfs), "the shared rootfs must survive one Pod's teardown"
      assert File.file?(File.join(second.rootfs, "marker"))
    end
  end

  def test_the_same_image_is_pulled_once
    with_resolver do |resolver, puller|
      first = resolver.resolve("registry.example.com/app:1.0")
      second = resolver.resolve("registry.example.com/app:1.0")

      assert_equal 1, puller.pulls, "a second Pod must reuse the unpacked image"
      assert_equal first.rootfs, second.rootfs
    end
  end

  def test_a_different_image_is_pulled_separately
    with_resolver do |resolver, puller|
      resolver.resolve("registry.example.com/app:1.0")
      resolver.resolve("registry.example.com/other:2.0")

      assert_equal 2, puller.pulls
    end
  end

  def test_pull_policy_always_bypasses_the_cache
    with_resolver do |resolver, puller|
      resolver.resolve("registry.example.com/app:1.0")
      resolver.resolve("registry.example.com/app:1.0", pull_policy: "Always")

      assert_equal 2, puller.pulls, "Always must re-pull"
    end
  end

  def test_a_caller_supplied_rootfs_is_never_served_from_the_cache
    with_resolver do |resolver, puller|
      resolver.resolve("registry.example.com/app:1.0")
      Dir.mktmpdir("explicit") do |explicit|
        resolved = resolver.resolve("registry.example.com/app:1.0", rootfs: explicit)

        assert_equal File.expand_path(explicit), resolved.rootfs
      end

      assert_equal 2, puller.pulls
    end
  end

  def test_a_reclaimed_rootfs_is_re_pulled
    with_resolver do |resolver, puller|
      first = resolver.resolve("registry.example.com/app:1.0")
      FileUtils.remove_entry(File.dirname(first.rootfs))

      second = resolver.resolve("registry.example.com/app:1.0")

      assert_equal 2, puller.pulls, "a cached entry whose rootfs is gone must not be served"
      refute_equal first.rootfs, second.rootfs
    end
  end
end
