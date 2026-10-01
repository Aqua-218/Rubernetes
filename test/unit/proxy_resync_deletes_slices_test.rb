# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

# A watch resync removes the EndpointSlices that vanished while the watch was
# down.  delete_watch_key passed a braceless Hash to a method with keyword
# parameters, which Ruby 3 took for keywords: "wrong number of arguments
# (given 0, expected 1)" on every resync, so stale slices were never removed
# and the error repeated for the life of the proxy.
class ProxyResyncDeletesSlicesTest < Minitest::Test
  def setup
    @proxy = Rubernetes::Proxy::Proxy.new(local_node: "node-a", node_addresses: ["192.0.2.10"], backend: :nftables,
                                          node_port_allocator: Rubernetes::Proxy::NodePortAllocator.new)
    @proxy.apply_service({"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "apps"},
                          "spec" => {"type" => "ClusterIP", "clusterIP" => "10.96.0.10", "clusterIPs" => ["10.96.0.10"],
                                     "ports" => [{"name" => "http", "port" => 80, "targetPort" => 8080, "protocol" => "TCP"}]}})
    @proxy.apply_endpoint_slice({"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
                                 "metadata" => {"name" => "web-1", "namespace" => "apps", "labels" => {"kubernetes.io/service-name" => "web"}},
                                 "addressType" => "IPv4", "ports" => [{"name" => "http", "port" => 8080, "protocol" => "TCP"}],
                                 "endpoints" => [{"addresses" => ["10.244.0.5"], "conditions" => {"ready" => true}}]})
  end

  def test_a_resync_removes_a_slice_that_is_gone_without_raising
    removed = @proxy.send(:delete_watch_key, ["apps/web", "web-1"], :endpoint_slice)

    refute_nil removed
    assert_nil @proxy.send(:instance_variable_get,
                           :@endpoint_store).delete_endpoint_slice({"metadata" => {"name" => "web-1", "namespace" => "apps",
                                                                                   "labels" => {"kubernetes.io/service-name" => "web"}}}),
               "the slice was already removed by the resync"
  end
end

# A snapshot or an event carrying an EndpointSlice the proxy cannot use (no
# service-name label) must not abort the resync or the watch: every other
# slice is still applied and vanished ones still removed.
class ProxyResyncToleratesUnusableSlicesTest < Minitest::Test
  class Source
    def initialize(items) = @items = items
    def list(**_options) = {"items" => @items, "metadata" => {"resourceVersion" => "77"}}
  end

  def slice(name, service: "web", ip: "10.244.0.5")
    labels = service ? {"kubernetes.io/service-name" => service} : {}
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
     "metadata" => {"name" => name, "namespace" => "apps", "labels" => labels},
     "addressType" => "IPv4", "ports" => [{"name" => "http", "port" => 8080, "protocol" => "TCP"}],
     "endpoints" => [{"addresses" => [ip], "conditions" => {"ready" => true}}]}
  end

  def setup
    @proxy = Rubernetes::Proxy::Proxy.new(local_node: "node-a", node_addresses: ["192.0.2.10"], backend: :nftables,
                                          node_port_allocator: Rubernetes::Proxy::NodePortAllocator.new)
    @proxy.apply_service({"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "apps"},
                          "spec" => {"type" => "ClusterIP", "clusterIP" => "10.96.0.10", "clusterIPs" => ["10.96.0.10"],
                                     "ports" => [{"name" => "http", "port" => 80, "targetPort" => 8080, "protocol" => "TCP"}]}})
  end

  def test_a_resync_with_an_unusable_slice_still_applies_the_others_and_prunes_vanished_keys
    @proxy.apply_endpoint_slice(slice("web-old", ip: "10.244.0.9"))
    source = Source.new([slice("web-1"), slice("custom", service: nil)])

    result = @proxy.send(:resync_watch_source, source, kind: :endpoint_slice, resource_version: "1",
                                                       known_keys: [["apps/web", "web-old"]])

    assert_equal [["apps/web", "web-1"]], result[:keys]
    assert_equal "77", result[:resource_version]
    store = @proxy.send(:instance_variable_get, :@endpoint_store)

    assert_nil store.delete_endpoint_slice({"metadata" => {"name" => "web-old", "namespace" => "apps", "labels" => {"kubernetes.io/service-name" => "web"}}}),
               "the vanished slice was pruned by the resync"
  end

  def test_the_watch_key_of_an_unusable_slice_is_nil_instead_of_an_exception
    assert_nil @proxy.send(:watch_object_key, slice("custom", service: nil), :endpoint_slice)
    assert_equal ["apps/web", "web-1"], @proxy.send(:watch_object_key, slice("web-1"), :endpoint_slice)
  end
end

# A resync lists the CURRENT state.  Listing at the watch's last
# resourceVersion returned a historical snapshot that omitted every Service
# created since, and the resync pruned them all: three proxies dropped from 54
# known Services to 1 in the same minute and existing ClusterIPs went dark.
class ProxyResyncListsCurrentStateTest < Minitest::Test
  class RecordingSource
    attr_reader :calls

    def initialize = @calls = []

    def list(**options)
      @calls << options
      {"items" => [], "metadata" => {"resourceVersion" => "900"}}
    end
  end

  def test_the_resync_list_carries_no_resource_version
    proxy = Rubernetes::Proxy::Proxy.new(local_node: "node-a", node_addresses: ["192.0.2.10"], backend: :nftables,
                                         node_port_allocator: Rubernetes::Proxy::NodePortAllocator.new)
    source = RecordingSource.new

    result = proxy.send(:resync_watch_source, source, kind: :service, resource_version: "14049", known_keys: [])

    assert_equal [{}], source.calls, "the list must not be pinned to the old watch version"
    assert_equal "900", result[:resource_version]
  end
end
