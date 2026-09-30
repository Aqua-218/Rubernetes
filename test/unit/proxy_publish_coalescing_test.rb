# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

# A burst of watch events is published to the datapath once, not once per
# event; without coalescing a Service changed during the burst reached the
# datapath tens of seconds late.
class ProxyPublishCoalescingTest < Minitest::Test
  Proxy = Rubernetes::Proxy

  def service(i)
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "svc-#{i}", "namespace" => "ns"},
     "spec" => {"clusterIP" => "10.96.0.#{i + 1}", "clusterIPs" => ["10.96.0.#{i + 1}"], "type" => "ClusterIP",
                "ports" => [{"name" => "http", "port" => 80, "protocol" => "TCP", "targetPort" => 8080}]}}
  end

  def slice(i)
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice", "addressType" => "IPv4",
     "metadata" => {"name" => "svc-#{i}-x", "namespace" => "ns", "labels" => {"kubernetes.io/service-name" => "svc-#{i}"}},
     "ports" => [{"name" => "http", "port" => 8080, "protocol" => "TCP"}],
     "endpoints" => [{"addresses" => ["10.240.0.#{i + 1}"], "conditions" => {"ready" => true}}]}
  end

  def test_a_burst_is_published_once_and_the_rules_are_complete
    proxy = Proxy::Proxy.new(local_node: "worker-0", backend: Proxy::MemoryBackend.new)
    proxy.publish_coalescing_seconds = 0.05
    proxy.publish_stats(reset: true)

    40.times do |i|
      proxy.apply_service(service(i))
      proxy.apply_endpoint_slice(slice(i))
    end
    proxy.flush_publish!
    sleep 0.2
    proxy.flush_publish!

    stats = proxy.publish_stats

    assert_operator stats[:count], :<, 10, "80 events must not mean 80 publishes (#{stats[:count]})"
    assert_equal 40, proxy.rules.length
    assert_equal 40, proxy.backend.rules.length
    assert_nil proxy.last_publish_error
  ensure
    proxy&.close
  end

  def test_without_an_interval_every_event_publishes_synchronously
    proxy = Proxy::Proxy.new(local_node: "worker-0", backend: Proxy::MemoryBackend.new)
    proxy.publish_stats(reset: true)

    proxy.apply_service(service(0))
    proxy.apply_endpoint_slice(slice(0))

    assert_equal 2, proxy.publish_stats[:count]
    assert_equal 1, proxy.backend.rules.length
  end

  def test_a_deletion_during_the_burst_reaches_the_datapath
    proxy = Proxy::Proxy.new(local_node: "worker-0", backend: Proxy::MemoryBackend.new)
    proxy.publish_coalescing_seconds = 0.02
    3.times do |i|
      proxy.apply_service(service(i))
      proxy.apply_endpoint_slice(slice(i))
    end
    proxy.delete_service(service(1))
    proxy.flush_publish!
    sleep 0.1
    proxy.flush_publish!

    assert_equal %w[ns/svc-0 ns/svc-2], proxy.backend.rules.map(&:service_key).sort
  ensure
    proxy&.close
  end
end
