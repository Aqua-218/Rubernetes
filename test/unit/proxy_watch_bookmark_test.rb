# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

# The watch stream carries BOOKMARK events: no object, only the
# resourceVersion a restart should resume from.  The proxy fed them to its
# Service and EndpointSlice handlers, which rejected them as nameless
# objects -- 183 warnings per proxy in one conformance round, drowning the
# validation failures that matter.
class ProxyWatchBookmarkTest < Minitest::Test
  Proxy = Rubernetes::Proxy

  def event(type, object) = {"type" => type, "object" => object}

  # The subscription re-lists after a stream ends, so the list must agree
  # with the events or the resync would wipe what the events applied.
  class Source
    def initialize(events)
      @events = events
      @items = events.filter_map { |event| event["object"] if event["type"] == "ADDED" }
    end

    def watch(**_options) = @events.dup
    def list(**_options) = {"items" => @items, "metadata" => {"resourceVersion" => "1"}}
  end

  def bookmark(kind)
    event("BOOKMARK", {"apiVersion" => "v1", "kind" => kind, "metadata" => {"resourceVersion" => "4242"}})
  end

  def service
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "svc", "namespace" => "ns"},
     "spec" => {"clusterIP" => "10.96.0.10", "type" => "ClusterIP",
                "ports" => [{"name" => "http", "port" => 80, "protocol" => "TCP", "targetPort" => 80}]}}
  end

  def slice
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
     "metadata" => {"name" => "svc-abc", "namespace" => "ns", "labels" => {"kubernetes.io/service-name" => "svc"}},
     "addressType" => "IPv4", "ports" => [{"name" => "http", "port" => 8080, "protocol" => "TCP"}],
     "endpoints" => [{"addresses" => ["10.244.0.5"], "conditions" => {"ready" => true}}]}
  end

  def wait_until(timeout = 3.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    sleep 0.02 until yield || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
  end

  def test_bookmarks_are_ignored_while_real_objects_are_applied
    errors = []
    proxy = Proxy::Proxy.new(local_node: "worker-0", backend: Proxy::MemoryBackend.new)
    subscriptions = proxy.start_watch(
      service_source: Source.new([bookmark("Service"), event("ADDED", service())]),
      endpoint_slice_source: Source.new([bookmark("EndpointSlice"), event("ADDED", slice())]),
      error_handler: ->(error) { errors << error.message }
    )
    wait_until { proxy.services.length.positive? && proxy.endpoint_slices.length.positive? }
    subscriptions.each { |subscription| subscription.close if subscription.respond_to?(:close) }

    assert_empty errors, "a bookmark must not be reported as an invalid object"
    assert_equal 1, proxy.services.length
    assert_equal 1, proxy.endpoint_slices.length
  end

  def test_an_object_that_really_is_invalid_is_still_reported
    errors = []
    proxy = Proxy::Proxy.new(local_node: "worker-0", backend: Proxy::MemoryBackend.new)
    nameless = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"namespace" => "ns"}, "spec" => {}}
    subscriptions = proxy.start_watch(
      service_source: Source.new([event("ADDED", nameless), event("ADDED", service())]),
      error_handler: ->(error) { errors << error.message }
    )
    wait_until { errors.any? && proxy.services.length.positive? }
    subscriptions.each { |subscription| subscription.close if subscription.respond_to?(:close) }

    assert_includes errors.join(" "), "name is required"
    assert_equal 1, proxy.services.length, "one bad object must not stop the next"
  end
end
