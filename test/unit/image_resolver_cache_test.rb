# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/image"
require "rubernetes/node/image_gc_manager"
require "rubygems/package"
require "socket"
require "stringio"
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
  Image = Rubernetes::Image
  Resolver = Image::Resolver

  class LoopbackRegistry
    attr_reader :requests, :digests
    attr_accessor :tag

    def initialize
      @tag = "first"
      @digests = {}
      @blobs = {}
      @manifests = {}
      @requests = []
      %w[first second].each { |version| add_version(version) }
    end

    def run
      server = TCPServer.new("127.0.0.1", 0)
      worker = Thread.new do
        loop do
          client = server.accept
          begin
            answer(client)
          ensure
            client.close
          end
        end
      rescue IOError, Errno::EBADF
        nil
      end
      yield "127.0.0.1:#{server.addr[1]}/app:stable"
    ensure
      server&.close
      worker&.join
    end

    private

    def answer(client)
      prefix = client.read(5)
      if prefix.start_with?("\x16\x03".b)
        client.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        return
      end

      path = (prefix + client.gets("\r\n\r\n")).split.fetch(1)
      @requests << path
      locator = path.split("/").last
      body = if path.include?("/manifests/")
               @manifests.fetch(locator == "stable" ? @digests.fetch(tag) : locator)
             else
               @blobs.fetch(locator)
             end
      client.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n", body)
    end

    def add_version(version)
      media = Image::MediaTypes
      config = JSON.generate("os" => "linux", "architecture" => "amd64", "config" => {"Cmd" => ["/bin/app"]})
      archive = StringIO.new("".b)
      Gem::Package::TarWriter.new(archive) do |tar|
        payload = version.ljust(1024 * 1024, "x")
        tar.add_file_simple("payload", 0o644, payload.bytesize) { |file| file.write(payload) }
      end
      manifest = JSON.generate(
        "schemaVersion" => 2, "mediaType" => media::OCI_IMAGE_MANIFEST,
        "config" => add_blob(config, media::OCI_IMAGE_CONFIG),
        "layers" => [add_blob(archive.string, media::OCI_IMAGE_LAYER)]
      )
      digest = image_digest(manifest)
      @digests[version] = digest
      @manifests[digest] = manifest
    end

    def add_blob(bytes, media_type)
      digest = image_digest(bytes)
      @blobs[digest] = bytes
      {"digest" => digest, "mediaType" => media_type, "size" => bytes.bytesize}
    end

    def image_digest(bytes) = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end

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

  def test_each_rootfs_claim_has_to_be_released_before_gc
    with_resolver do |resolver, _puller|
      first = resolver.resolve("registry.example.com/app:1.0", retain: true)
      second = resolver.resolve("registry.example.com/app:1.0", retain: true)
      key = resolver.cached_images.first.first

      assert_equal first.rootfs, second.rootfs
      assert resolver.release(first)
      assert resolver.release(first)
      refute resolver.evict_cached_image(key)
      assert_path_exists second.rootfs
      assert resolver.release(second)
      assert resolver.evict_cached_image(key)
      refute_path_exists second.rootfs
    end
  end

  def test_a_different_image_is_pulled_separately
    with_resolver do |resolver, puller|
      first = resolver.resolve("registry.example.com/app:1.0")
      second = resolver.resolve("registry.example.com/other:2.0")

      assert_equal 2, puller.pulls
      refute_equal first.rootfs, second.rootfs
    end
  end

  def test_platform_variants_have_independent_rootfs_entries
    with_resolver do |resolver, puller|
      image = "registry.example.com/app:stable"
      first = resolver.resolve(image, platform: {architecture: "arm", variant: "v6"})
      second = resolver.resolve(image, platform: {architecture: "arm", variant: "v7"})

      assert_equal 2, puller.pulls
      refute_equal first.rootfs, second.rootfs
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
      FileUtils.remove_entry(first.rootfs)

      second = resolver.resolve("registry.example.com/app:1.0")

      assert_equal 2, puller.pulls, "a cached entry whose rootfs is gone must not be served"
      refute_equal first.rootfs, second.rootfs
      assert_equal 1, resolver.reclaim_unused_stages([])
      refute_path_exists File.dirname(first.rootfs)
      assert_path_exists File.join(second.rootfs, "marker")
    end
  end

  def test_failed_stage_removal_retries_without_reusing_the_partial_rootfs
    with_resolver do |resolver, puller|
      reference = "registry.example.com/app:1.0"
      entry = resolver.resolve(reference)
      stage = File.dirname(entry.rootfs)
      key = resolver.cached_images.first.first
      filesystem = Rubernetes::Platform::Linux::SecureRootfs
      original = filesystem.method(:new)
      fail_on_payload = lambda do |**options|
        original.call(**options, race_hook: lambda do |operation:, relative:, **|
          raise Errno::EBUSY if operation == :remove_before_unlink && relative.end_with?("/rootfs/marker")
        end)
      end

      filesystem.stub(:new, fail_on_payload) { refute resolver.evict_cached_image(key) }

      assert_empty resolver.cached_images
      assert_path_exists File.join(stage, Image::StagingLease::LOCK_NAME)

      new_image = resolver.resolve(reference)

      assert_equal 1, resolver.reclaim_unused_stages([new_image.rootfs])
      assert_equal 2, puller.pulls
      refute_path_exists stage
    end
  end

  def test_retagged_registry_image_shares_one_verified_unpack_and_keeps_the_in_use_root
    registry = LoopbackRegistry.new
    registry.run do |reference|
      Dir.mktmpdir("image-cache") do |dir|
        resolver = Resolver.new(staging_root: dir, platform: {architecture: "amd64"})
        events = []
        first = resolver.resolve(reference, on_pull: ->(*event) { events << event })

        assert_same first, resolver.resolve(reference)
        assert_equal first.manifest.config.size + first.manifest.layers.first.size, events.last.fetch(2)

        registry.tag = "second"
        newer = Array.new(6) { Thread.new { resolver.resolve(reference, pull_policy: "Always") } }.map(&:value)

        assert_equal 1, newer.map(&:rootfs).uniq.size
        second = newer.first

        assert_equal registry.digests.fetch("first"), first.digest.to_s
        assert_equal registry.digests.fetch("second"), second.digest.to_s
        assert_equal "first", File.binread(File.join(first.rootfs, "payload"), 5)
        assert_equal "second", File.binread(File.join(second.rootfs, "payload"), 6)
        assert_same second, resolver.resolve(reference)
        assert_same second, resolver.resolve(second.reference)
        assert_equal 4, registry.requests.count { |path| path.include?("/blobs/") }, "two full pulls total"
        assert_equal 7, registry.requests.count("/v2/app/manifests/stable"), "each Always caller checks the tag"
        assert_equal 1, registry.requests.count("/v2/app/manifests/#{second.digest}")
        assert_equal 2, Dir.children(dir).length

        names = Rubernetes::Node::StatusImages.new(resolver: resolver).images.to_h { |entry| [entry["names"].first, entry["names"]] }

        assert_equal [first.reference.to_s], names.fetch(first.reference.to_s)
        assert_equal [second.reference.to_s, reference], names.fetch(second.reference.to_s)

        used_roots = [first.rootfs, second.rootfs]
        pods = [{"spec" => {"containers" => [{"image" => reference}]}}]
        gc = Rubernetes::Node::ImageGCManager.new(resolver: resolver, fs_stats: -> {}, pods: -> { pods },
                                                  used_roots: -> { used_roots }, min_age: 0)

        assert resolver.release(second)
        assert_empty gc.delete_unused_images

        used_roots.delete(second.rootfs)

        assert_equal 1, gc.delete_unused_images.length, "the active Pod still mounts the old digest"
        assert_path_exists first.rootfs
        refute_path_exists second.rootfs
        assert_raises(Image::NeverPullError) { resolver.resolve(reference, pull_policy: "Never") }

        used_roots.clear

        assert_equal 1, gc.delete_unused_images.length
        assert_empty Dir.children(dir)
      end
    end
  end
end
