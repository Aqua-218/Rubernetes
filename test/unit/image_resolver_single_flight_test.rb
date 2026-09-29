# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
require "json"

# Pods started together on a node all asked for the same image before any
# pull finished, and each ran its own download and unpack of it (8-9 s for
# the DNS spec's jessie-dnsutils queriers).  Concurrent resolves of one image
# now share a single pull.
class ImageResolverSingleFlightTest < Minitest::Test
  Image = Rubernetes::Image

  class SlowPuller
    attr_reader :pulls

    def initialize(digest:, config:, fail_first: false)
      @digest = digest
      @config = config
      @pulls = 0
      @mutex = Mutex.new
      @fail_first = fail_first
    end

    def pull(reference, platform:, rootfs:, unpack:)
      first = @mutex.synchronize { (@pulls += 1) == 1 }
      sleep 0.2
      raise Image::RegistryError, "registry unavailable" if first && @fail_first

      FileUtils.mkdir_p(rootfs)
      Image::Image.new(reference: reference.with_digest(@digest), manifest: Struct.new(:digest).new(@digest),
                       config: JSON.generate(@config), rootfs: rootfs, config_object: @config)
    end
  end

  def config = {"architecture" => "amd64", "os" => "linux", "config" => {"Cmd" => ["/pause"]}}
  def digest = Image::Digest.parse("sha256:#{"b" * 64}")

  def test_concurrent_resolves_of_one_image_share_one_pull
    puller = SlowPuller.new(digest: digest, config: config)
    resolver = Image::Resolver.new(puller: puller, platform: {"os" => "linux", "architecture" => "amd64"})
    results = Array.new(5) { Thread.new { resolver.resolve("registry.example/pause:3.10") } }.map(&:value)

    assert_equal 1, puller.pulls
    assert_equal 1, results.map(&:object_id).uniq.length
  ensure
    resolver&.release(results.first) if results&.first
  end

  def test_waiters_pull_themselves_when_the_shared_pull_fails
    puller = SlowPuller.new(digest: digest, config: config, fail_first: true)
    resolver = Image::Resolver.new(puller: puller, platform: {"os" => "linux", "architecture" => "amd64"})
    outcomes = Array.new(3) do
      Thread.new do
        resolver.resolve("registry.example/pause:3.10")
      rescue Image::RegistryError => error
        error
      end
    end.map(&:value)

    assert_equal 1, outcomes.count { |outcome| outcome.is_a?(Image::RegistryError) }, "only the leader sees its own failure"
    assert(outcomes.any? { |outcome| outcome.respond_to?(:rootfs) })
  ensure
    resolved = outcomes&.find { |outcome| outcome.respond_to?(:rootfs) }
    resolver&.release(resolved) if resolved
  end
end
