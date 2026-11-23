# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class ProxyTopologyHintsTest < Minitest::Test
  Proxy = Rubernetes::Proxy

  def endpoint(ip, node:, zone:, ready: true)
    hints = {"forZones" => [{"name" => zone}]}
    hints["forNodes"] = [{"name" => node}] if node
    Proxy::Endpoint.new(address: ip, port: 80, hints: hints, ready: ready)
  end

  def test_node_then_zone_then_cluster_fallback_agrees_in_all_dataplanes
    first = endpoint("10.1.0.1", node: "a", zone: "west")
    second = endpoint("10.1.0.2", node: "b", zone: "west")
    third = endpoint("10.1.0.3", node: "c", zone: "east")
    unready = endpoint("10.1.0.4", node: nil, zone: "north", ready: false)
    backends = [first, second, third, unready]

    assert_equal first.to_h, Proxy::Endpoint.new(first.to_h).to_h
    assert_dataplanes [first], backends, node: "a", zone: "east"
    assert_dataplanes [first, second], backends, node: "absent", zone: "west"
    assert_dataplanes [first, second, third], backends, node: "absent", zone: "absent"
    missing_node_hint = endpoint("10.1.0.5", node: nil, zone: "west")

    assert_dataplanes [third], [first, third, missing_node_hint], node: "a", zone: "east"
  end

  private

  def assert_dataplanes(expected, backends, node:, zone:)
    service = Proxy::Service.new("metadata" => {"name" => "web"}, "spec" => {"clusterIP" => "10.96.0.1", "ports" => [{"port" => 80}]})
    rule = Proxy::RuleCompiler.new(local_node: node, node_zone: zone).compile(service, endpoints: backends).rules.first
    nft = Proxy::NftablesNetlinkAdapter.new(transport: Object.new)
    iptables = Proxy::Iptables::Renderer.new(node_name: node)
    model = Proxy::Proxy.new(local_node: node, node_zone: zone, backend: Proxy::MemoryBackend.new)
    packet = Proxy::Packet.new(source_ip: "10.1.0.9", destination_ip: "10.96.0.1", destination_port: 80)

    assert_equal expected, model.send(:eligible_endpoints, rule, service, packet)
    assert_equal expected, Proxy::LinuxEBPFAdapter.new.send(:backend_candidates, rule, family: 4)
    assert_equal expected, iptables.categorize(iptables.service_ports([rule]).first).first
    addresses = nft.send(:endpoint_routes, rule).first.endpoints.map { |entry| entry.fetch("address") }

    assert_equal expected.map(&:address), addresses
  ensure
    model&.close
  end
end
