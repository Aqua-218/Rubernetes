# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A Pod's distinct images were pulled one after the other: a DNS spec's Pod
# waited for agnhost and then for jessie-dnsutils.  They are pulled side by
# side now, and a failed pull still leaves ErrImagePull.
class NodeParallelImagePullTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  Resolved = Struct.new(:reference, :digest, :rootfs, :command, :env, :working_dir, :entrypoint, :cmd, :os, :architecture, :config, keyword_init: true)

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
    subject.define_singleton_method(:image_to_hash) { |resolved, reference = nil| {"image" => reference, "digest" => resolved.digest, "rootfs" => resolved.rootfs} }
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
end
