# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/resource_reader"

# `kubectl apply -f configmap.yaml && kubectl rollout restart` must give the
# new Pods the new values.  The reader caches reads for a few seconds, and a
# Pod created a second after the change was started with the copy another Pod
# had read just before it.
class NodeResourceReaderFreshPodTest < Minitest::Test
  class Client
    attr_accessor :data
    attr_reader :reads

    def initialize
      @data = {"MESSAGE" => "old"}
      @reads = 0
    end

    def read_object(plural, name, namespace:, api_version:)
      @reads += 1
      {"apiVersion" => api_version, "kind" => plural, "metadata" => {"name" => name, "namespace" => namespace}, "data" => @data.dup}
    end
  end

  def setup
    @client = Client.new
    @now = Time.utc(2026, 11, 11, 15, 0, 0)
    @reader = Rubernetes::Node::ResourceReader.new(client: @client, wall_clock: -> { @now })
  end

  def site_message
    @reader.get("configmaps", "site", namespace: "shop").dig("data", "MESSAGE")
  end

  def test_a_pod_created_after_a_read_does_not_start_with_that_read
    assert_equal "old", site_message
    @client.data = {"MESSAGE" => "new"}

    assert_equal "old", site_message, "within the cache window the copy is served"

    @reader.forget_read_before(@now + 1, namespace: "shop")

    assert_equal "new", site_message
  end

  # creationTimestamp has no fraction: a Pod created in the same second as
  # the read may still be younger than it.
  def test_a_read_in_the_second_the_pod_was_created_in_is_not_trusted
    site_message
    @client.data = {"MESSAGE" => "new"}
    @reader.forget_read_before(@now, namespace: "shop")

    assert_equal "new", site_message
  end

  # Thirty Pods of one rollout share the read the first of them made.
  def test_a_read_made_after_the_pod_was_created_is_kept
    site_message
    @now += 5
    @reader.forget_read_before(@now - 5, namespace: "shop")
    site_message
    reads = @client.reads
    @reader.forget_read_before(@now - 5, namespace: "shop")
    site_message

    assert_equal reads, @client.reads
  end

  def test_other_namespaces_and_other_kinds_keep_their_copies
    @reader.get("configmaps", "site", namespace: "other")
    @reader.get("services", "web", namespace: "shop")
    reads = @client.reads
    @reader.forget_read_before(@now + 1, namespace: "shop")
    @reader.get("configmaps", "site", namespace: "other")
    @reader.get("services", "web", namespace: "shop")

    assert_equal reads, @client.reads
  end
end
