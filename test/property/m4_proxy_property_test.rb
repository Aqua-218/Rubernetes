# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class M4ProxyPropertyTest < Minitest::Test
  def test_deterministic_hash_is_order_independent
    endpoints = %w[10.0.0.1 10.0.0.2 10.0.0.3].map do |address|
      Rubernetes::Proxy::Endpoint.new(address: address, port: 8080, protocol: "TCP")
    end
    hasher = Rubernetes::Proxy::DeterministicHash.new(seed: "property")
    key = Rubernetes::Proxy::ConnectionKey.new(protocol: "TCP", source_ip: "192.0.2.1", source_port: 321,
                                               destination_ip: "10.96.0.1", destination_port: 80)
    expected = hasher.select(key, endpoints).identity

    20.times do
      assert_equal expected, hasher.select(key, endpoints.shuffle).identity
    end
  end

  def test_conntrack_reselects_only_after_backend_is_removed
    clock = 0.0
    endpoints = %w[10.0.0.1 10.0.0.2].map do |address|
      Rubernetes::Proxy::Endpoint.new(address: address, port: 8080, protocol: "TCP")
    end
    table = Rubernetes::Proxy::ConntrackTable.new(clock: -> { clock })
    hasher = Rubernetes::Proxy::DeterministicHash.new
    key = Rubernetes::Proxy::ConnectionKey.new(protocol: "UDP", source_ip: "192.0.2.4", source_port: 55,
                                               destination_ip: "10.96.0.4", destination_port: 53)
    first = table.find_or_select(key, service_key: "default/dns", backends: endpoints,
                                      selector: ->(items) { hasher.select(key, items) }, now: clock)
    clock += 1
    second = table.find_or_select(key, service_key: "default/dns", backends: endpoints,
                                       selector: ->(items) { hasher.select(key, items) }, now: clock)

    assert_equal first.backend.identity, second.backend.identity
    table.remove_backend(first.backend)
    replacement = table.find_or_select(key, service_key: "default/dns", backends: endpoints.reject do |item|
      item.identity == first.backend.identity
    end,
                                            selector: ->(items) { hasher.select(key, items) }, now: clock)

    refute_equal first.backend.identity, replacement.backend.identity
  end

  def test_backend_rule_digests_match_for_same_semantics
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "api"},
      "spec" => {"clusterIP" => "10.96.0.20", "ports" => [{"port" => 443, "targetPort" => 8443}]}
    )
    endpoint = Rubernetes::Proxy::Endpoint.new(address: "10.0.0.9", port: 8443)
    compiled = Rubernetes::Proxy::RuleCompiler.new.compile(service, endpoints: [endpoint], revision: 1)
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true)
    nftables = Rubernetes::Proxy::NftablesBackend.new
    ebpf.apply(compiled)
    nftables.apply(compiled)

    assert_equal ebpf.digest, nftables.digest
    assert_equal ebpf.rules.map(&:to_h), nftables.rules.map(&:to_h)
    refute_predicate ebpf, :ready?
    refute_predicate nftables, :ready?
  end

  # An EndpointSlice port is named after the *Service* port, never after the
  # Service's targetPort: upstream keys endpoints by
  # ServicePortName{namespace/name, *port.Name, protocol} and takes the slice's
  # own number as the target (pkg/proxy/endpointslicecache.go).  So for a
  # Service port named "http" with targetPort "web", the slice that belongs to
  # it is the one named "http", and the endpoint resolved from the container
  # port "web" carries that name.
  def test_endpoint_slice_port_is_matched_by_service_port_name_not_target_port
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "named"},
      "spec" => {"clusterIP" => "10.96.0.50", "ports" => [{"name" => "http", "port" => 80, "targetPort" => "web"}]}
    )
    compiler = Rubernetes::Proxy::RuleCompiler.new
    matching = Rubernetes::Proxy::Endpoint.new(address: "10.0.0.51", port: 8080, port_name: "http")
    # Named after the targetPort rather than the Service port: this is not a
    # slice of this Service port and must not be routed to.
    non_matching = Rubernetes::Proxy::Endpoint.new(address: "10.0.0.50", port: 8080, port_name: "web")
    rule = compiler.compile(service, endpoints: [matching, non_matching]).rules.first

    assert_equal [matching.identity], rule.backends.map(&:identity)
  end

  def test_unnamed_service_port_matches_only_unnamed_endpoint_slice_ports
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "unnamed"},
      "spec" => {"clusterIP" => "10.96.0.51", "ports" => [{"port" => 80, "targetPort" => 8080}]}
    )
    compiler = Rubernetes::Proxy::RuleCompiler.new
    matching = Rubernetes::Proxy::Endpoint.new(address: "10.0.0.52", port: 8080)
    non_matching = Rubernetes::Proxy::Endpoint.new(address: "10.0.0.53", port: 8080, port_name: "http")
    rule = compiler.compile(service, endpoints: [matching, non_matching]).rules.first

    assert_equal [matching.identity], rule.backends.map(&:identity)
  end

  def test_conntrack_affinity_expires_and_reselects_after_timeout
    now = 0.0
    endpoints = %w[10.0.0.60 10.0.0.61].map do |address|
      Rubernetes::Proxy::Endpoint.new(address: address, port: 8080, protocol: "TCP")
    end
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "sticky"},
      "spec" => {"clusterIP" => "10.96.0.60", "sessionAffinity" => "ClientIP",
                 "sessionAffinityConfig" => {"clientIP" => {"timeoutSeconds" => 2}},
                 "ports" => [{"port" => 80, "targetPort" => 8080}]}
    )
    table = Rubernetes::Proxy::ConntrackTable.new(clock: -> { now })
    key = Rubernetes::Proxy::ConnectionKey.new(protocol: "TCP", source_ip: "192.0.2.60", source_port: 1,
                                               destination_ip: "10.96.0.60", destination_port: 80)
    selector = lambda(&:first)
    first = table.find_or_select(key, service_key: service.key, backends: endpoints, selector: selector,
                                      session_affinity: service.session_affinity, source_ip: "192.0.2.60",
                                      timeout_seconds: service.session_affinity_timeout_seconds, now: now)
    now = 3.0
    second = table.find_or_select(key, service_key: service.key, backends: endpoints, selector: lambda(&:last),
                                       session_affinity: service.session_affinity, source_ip: "192.0.2.60",
                                       timeout_seconds: service.session_affinity_timeout_seconds, now: now)

    refute_equal first.created_at, second.created_at
    assert_equal endpoints.last.identity, second.backend.identity
  end

  def test_nftables_node_port_messages_use_inet_for_dual_stack_packets
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "dual-node"},
      "spec" => {"type" => "NodePort", "clusterIP" => "10.96.0.61", "clusterIPs" => ["10.96.0.61", "fd00::61"],
                 "ipFamilies" => %w[IPv4 IPv6], "ports" => [{"port" => 80, "nodePort" => 30_061}]}
    )
    rule = Rubernetes::Proxy::RuleCompiler.new.compile(service, endpoints: []).rules.find { |entry| entry.kind == "NodePort" }
    backend = Rubernetes::Proxy::NftablesBackend.new
    backend.apply(Rubernetes::Proxy::RuleDiff.new(added: [rule], from_revision: 0, to_revision: 1))

    assert_equal "inet", backend.messages.first.fetch("family")
  end
end
