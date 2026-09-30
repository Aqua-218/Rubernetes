# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class ProxyEBPFModelTestAdapter
  attr_reader :calls

  def initialize
    @calls = []
    @attached = false
    @fail_next_attach = false
    @fail_next_update = false
  end

  def test_adapter?
    true
  end

  def fail_next_attach!
    @fail_next_attach = true
  end

  def fail_next_update!
    @fail_next_update = true
  end

  def attach(**arguments)
    @calls << [:attach, arguments]
    raise IOError, "simulated model eBPF attach failure" if @fail_next_attach

    @attached = true
    {verified: true}
  end

  def update(backend:, diff:, program:)
    @calls << [:update, backend.name, diff, program]
    raise IOError, "simulated model eBPF update failure" if @fail_next_update

    {verified: true}
  end

  def verify_attach(backend:, result:, expected:, **_arguments)
    backend.name == "ebpf" && result.is_a?(Hash) && result[:verified] == true && !expected[:program].nil?
  end

  def verify_update(backend:, result:, expected:, **_arguments)
    backend.name == "ebpf" && result.is_a?(Hash) && result[:verified] == true && !expected[:diff].nil?
  end

  def detach(**_arguments)
    @attached = false
    true
  end
end

class ProxyNftablesModelTestAdapter
  attr_reader :calls

  def initialize
    @calls = []
    @attached = false
    @fail_next_attach = false
    @fail_next_transaction = false
  end

  def test_adapter?
    true
  end

  def fail_next_attach!
    @fail_next_attach = true
  end

  def fail_next_transaction!
    @fail_next_transaction = true
  end

  def send_messages(messages, **arguments)
    @calls << [messages, arguments]
    if @fail_next_attach && !@attached
      @fail_next_attach = false
      raise IOError, "simulated model nftables attach failure"
    end
    if @fail_next_transaction
      @fail_next_transaction = false
      raise IOError, "simulated model nftables transaction failure"
    end

    @attached = true
    {verified: true}
  end

  def verify_transaction(backend:, result:, expected:, **_arguments)
    messages = expected.is_a?(Array) ? expected : expected[:messages]
    backend.name == "nftables" && result.is_a?(Hash) && result[:verified] == true && messages.is_a?(Array)
  end

  def readback(backend:, **_arguments)
    {verified: backend.name == "nftables" && @attached}
  end

  def detach(**_arguments)
    @attached = false
    true
  end
end

class M4ProxyTest < Minitest::Test
  def setup
    @proxy = Rubernetes::Proxy::Proxy.new(
      local_node: "node-a",
      node_addresses: ["192.0.2.10"],
      backend: :nftables,
      node_port_allocator: Rubernetes::Proxy::NodePortAllocator.new
    )
    @service = {
      "apiVersion" => "v1", "kind" => "Service",
      "metadata" => {"name" => "web", "namespace" => "apps"},
      "spec" => {
        "type" => "NodePort", "clusterIP" => "10.96.0.10", "clusterIPs" => ["10.96.0.10", "fd00::10"],
        "ipFamilies" => %w[IPv4 IPv6], "internalTrafficPolicy" => "Local",
        "externalTrafficPolicy" => "Local", "sessionAffinity" => "ClientIP",
        "sessionAffinityConfig" => {"clientIP" => {"timeoutSeconds" => 60}},
        "ports" => [
          {"name" => "http", "port" => 80, "targetPort" => 8080, "nodePort" => 30_080, "protocol" => "TCP"},
          {"name" => "dns", "port" => 53, "targetPort" => 5353, "nodePort" => 30_053, "protocol" => "UDP"},
          {"name" => "sctp", "port" => 9899, "targetPort" => 9899, "nodePort" => 30_989, "protocol" => "SCTP"}
        ]
      }
    }
    @slice = {
      "apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
      "metadata" => {"name" => "web-1", "namespace" => "apps", "labels" => {"kubernetes.io/service-name" => "web"}},
      "addressType" => "IPv4",
      "ports" => [
        {"name" => "http", "port" => 8080, "protocol" => "TCP"},
        {"name" => "dns", "port" => 5353, "protocol" => "UDP"},
        {"name" => "sctp", "port" => 9899, "protocol" => "SCTP"}
      ],
      "endpoints" => [
        {"addresses" => ["10.1.0.1"], "nodeName" => "node-a", "zone" => "zone-a",
         "conditions" => {"ready" => true, "serving" => true}, "hints" => {"forZones" => [{"name" => "zone-a"}]}},
        {"addresses" => ["10.1.0.2"], "nodeName" => "node-b", "zone" => "zone-b",
         "conditions" => {"ready" => true, "serving" => true}},
        {"addresses" => ["10.1.0.3"], "nodeName" => "node-a", "zone" => "zone-a",
         "conditions" => {"ready" => false, "serving" => true, "terminating" => true}}
      ]
    }
  end

  def test_service_and_endpoint_slice_models_preserve_semantics
    service = Rubernetes::Proxy::Service.new(@service)
    slice = Rubernetes::Proxy::EndpointSlice.new(@slice)

    assert_equal "apps/web", service.key
    assert_equal ["10.96.0.10", "fd00::10"], service.cluster_ips
    assert_equal false, service.headless?
    assert_equal %w[UDP TCP SCTP], service.ports.map(&:protocol)
    assert_equal 9, slice.endpoints.length
    assert_equal 6, slice.endpoints.count(&:healthy?)
    assert slice.endpoints.any?(&:terminating?)
  end

  def test_compiles_dual_stack_rules_and_applies_differential_changes
    @proxy.apply_service(@service)
    @proxy.apply_endpoint_slice(@slice)

    rules = @proxy.rules

    assert_equal 9, rules.length # two ClusterIPs plus one NodePort for each of 3 protocols
    assert_equal(6, rules.count { |rule| rule.kind == "ClusterIP" })
    assert_equal(3, rules.count { |rule| rule.kind == "NodePort" })
    assert(@proxy.backend.messages.any? { |message| message["operation"] == "replace" })

    modified = Marshal.load(Marshal.dump(@slice))
    modified["metadata"]["name"] = "web-2"
    modified["endpoints"][0]["conditions"]["ready"] = false
    @proxy.apply_endpoint_slice(modified)
    diff = @proxy.rule_diff

    assert_equal 0, diff.added.length
    assert_equal 0, diff.deleted.length
    assert_predicate diff.updated, :any?
  end

  def test_client_ip_affinity_and_conntrack_keep_same_backend
    @proxy.apply_service(@service)
    @proxy.apply_endpoint_slice(@slice)
    packet = {"sourceIP" => "198.51.100.8", "sourcePort" => 10_001,
              "destinationIP" => "10.96.0.10", "destinationPort" => 80, "protocol" => "TCP", "zone" => "zone-b"}
    first = @proxy.route(packet)
    second = @proxy.route(packet.merge("sourcePort" => 10_002))

    assert_predicate first, :success?
    assert_equal first.endpoint.identity, second.endpoint.identity
  end

  def test_local_policy_falls_back_to_terminating_only_when_no_healthy_local_endpoint
    @proxy.apply_service(@service)
    @proxy.apply_endpoint_slice(@slice)
    packet = {"sourceIP" => "203.0.113.7", "sourcePort" => 12_000,
              "destinationIP" => "192.0.2.10", "destinationPort" => 30_080,
              "protocol" => "TCP", "external" => true}
    route = @proxy.route(packet)

    assert_predicate route, :success?
    assert_equal "10.1.0.1", route.address
    assert route.source_preserved

    terminating_only = Marshal.load(Marshal.dump(@slice))
    terminating_only["metadata"]["name"] = "web-terminating"
    terminating_only["endpoints"].each_with_index do |endpoint, index|
      endpoint["conditions"] = {"ready" => false, "serving" => true, "terminating" => index.zero?}
    end
    @proxy.delete_endpoint_slice(@slice)
    @proxy.apply_endpoint_slice(terminating_only)
    route = @proxy.route(packet.merge("sourcePort" => 12_001))

    assert_predicate route, :success?
    assert_predicate route.endpoint, :terminating?
  end

  def test_node_port_allocator_is_atomic_and_uses_default_range
    store = Rubernetes::Proxy::NodePortStore.new
    allocator = Rubernetes::Proxy::NodePortAllocator.new(store: store, min: 30_000, max: 30_001)
    first = allocator.allocate(service_key: "apps/a", protocol: "TCP", port: 80)

    assert_equal 30_000, first.node_port
    assert_raises(Rubernetes::Proxy::AllocationError) do
      allocator.allocate(service_key: "apps/b", protocol: "TCP", port: 80, requested: 30_000)
    end
    assert_equal 1, allocator.allocations.length
    assert_equal 2, store.transactions
  end

  def test_auto_backend_records_probe_selection_and_switch_measurement
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true,
                                              syscall_adapter: ProxyEBPFModelTestAdapter.new,
                                              test_adapter: true)
    nftables = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: ProxyNftablesModelTestAdapter.new,
                                                      test_adapter: true)
    auto = Rubernetes::Proxy::AutoBackend.new(ebpf: ebpf, nftables: nftables,
                                              capability_probe: Rubernetes::Proxy::CapabilityProbe.new(bpf: ebpf))

    assert_equal "ebpf", auto.selected_backend
    measurement = auto.switch!(target: "nftables", reason: "test")

    assert_equal "ebpf", measurement.from_backend
    assert_equal "nftables", measurement.to_backend
    assert_equal 1, auto.measurements.length
  end

  def test_kernel_backends_fail_closed_without_a_production_capable_adapter
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true)

    refute_predicate ebpf, :available?
    error = assert_raises(Rubernetes::Proxy::BackendError) { ebpf.attach }
    assert_match(/production-capable kernel adapter|adapter/, error.message)
    assert_equal :failed, ebpf.attach_state
    refute_predicate ebpf, :ready?
    assert_same error, ebpf.last_error
    assert_equal "failed", ebpf.status.state

    nftables = Rubernetes::Proxy::NftablesBackend.new

    refute_predicate nftables, :available?
    refute_predicate nftables, :ready?
    # The native adapter is mechanically attachable before any packet proof,
    # so the state is "unattached"; it becomes available only after attach
    # and verified packet semantics.
    assert_equal "unattached", nftables.status.state
    refute_predicate nftables, :production_capable?
  end

  def test_no_op_adapters_cannot_attach_even_when_explicitly_marked_as_test
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true, syscall_adapter: Object.new, test_adapter: true)
    nftables = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: Object.new, test_adapter: true)

    [ebpf, nftables].each do |backend|
      refute_predicate backend, :available?
      assert_raises(Rubernetes::Proxy::BackendError) { backend.attach }
      refute_predicate backend, :ready?
      assert_equal :failed, backend.attach_state
    end
  end

  def test_production_adapter_requires_verification_or_readback
    adapter = Object.new
    adapter.define_singleton_method(:production_capable?) { true }
    adapter.define_singleton_method(:attach) { |**| {verified: true} }
    adapter.define_singleton_method(:update) { |**| {verified: true} }
    backend = Rubernetes::Proxy::EBPFBackend.new(capability: true, syscall_adapter: adapter)

    refute_predicate backend, :available?
    error = assert_raises(Rubernetes::Proxy::BackendError) { backend.attach }
    assert_match(/verification|readback/, error.message)
    refute_predicate backend, :ready?
    assert_equal :failed, backend.attach_state
  end

  def test_adapter_attach_errors_leave_backends_non_ready
    ebpf_adapter = ProxyEBPFModelTestAdapter.new
    ebpf_adapter.fail_next_attach!
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true, syscall_adapter: ebpf_adapter, test_adapter: true)
    assert_raises(Rubernetes::Proxy::BackendError) { ebpf.attach }
    refute_predicate ebpf, :ready?
    assert_equal :failed, ebpf.attach_state
    assert_match(/attach failure/, ebpf.last_error.message)

    nftables_adapter = ProxyNftablesModelTestAdapter.new
    nftables_adapter.fail_next_attach!
    nftables = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: nftables_adapter, test_adapter: true)
    assert_raises(Rubernetes::Proxy::BackendError) { nftables.attach }
    refute_predicate nftables, :ready?
    assert_equal :failed, nftables.attach_state
    assert_match(/attach failure/, nftables.last_error.message)
  end

  def test_auto_backend_selects_native_nftables_when_ebpf_is_unavailable
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true)
    nftables = Rubernetes::Proxy::NftablesBackend.new
    auto = Rubernetes::Proxy::AutoBackend.new(ebpf: ebpf, nftables: nftables, capability_probe: -> { true })

    assert_equal "nftables", auto.selected_backend
    refute_predicate auto, :available?
    refute_predicate auto, :ready?
    # Selected because the native adapter can attach; not yet available
    # because no verified packet semantics exist.
    assert_equal "unattached", auto.status.state
  end

  def test_auto_backend_falls_back_to_an_available_nftables_adapter
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true)
    nftables = Rubernetes::Proxy::NftablesBackend.new(
      netlink_adapter: ProxyNftablesModelTestAdapter.new,
      test_adapter: true
    )
    auto = Rubernetes::Proxy::AutoBackend.new(ebpf: ebpf, nftables: nftables, capability_probe: -> { true })

    assert_equal "nftables", auto.selected_backend
    assert_predicate auto, :available?
    refute_predicate auto, :ready?
    assert_equal "unattached", auto.status.state
  end

  def test_external_name_is_returned_as_cname_like_route
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "database", "namespace" => "apps"},
      "spec" => {"type" => "ExternalName", "externalName" => "db.example.test", "ports" => [{"port" => 5432}]}
    )
    proxy = Rubernetes::Proxy::Proxy.new(backend: :nftables)
    proxy.apply_service(service)
    route = proxy.route({"sourceIP" => "10.0.0.2", "sourcePort" => 1000,
                         "destinationIP" => "192.0.2.20", "destinationPort" => 5432}, service: service)

    assert_instance_of Rubernetes::Proxy::ExternalNameRoute, route
    assert_equal "db.example.test", route.hostname
  end

  def test_publish_not_ready_addresses_routes_unready_non_terminating_endpoints
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "published"},
      "spec" => {"clusterIP" => "10.96.0.30", "publishNotReadyAddresses" => true,
                 "ports" => [{"port" => 80, "targetPort" => 8080}]}
    )
    slice = {
      "metadata" => {"name" => "published-1", "labels" => {"kubernetes.io/service-name" => "published"}},
      "addressType" => "IPv4",
      "ports" => [{"port" => 8080, "protocol" => "TCP"}],
      "endpoints" => [{"addresses" => ["10.1.0.20"], "conditions" => {"ready" => false, "serving" => false}}]
    }
    @proxy.apply_service(service)
    @proxy.apply_endpoint_slice(slice)

    route = @proxy.route({"sourceIP" => "198.51.100.1", "sourcePort" => 1,
                          "destinationIP" => "10.96.0.30", "destinationPort" => 80})

    assert_predicate route, :success?
    assert_equal "10.1.0.20", route.address
  end

  def test_endpoint_slice_rejects_address_type_mismatch
    assert_raises(Rubernetes::Proxy::ValidationError) do
      Rubernetes::Proxy::EndpointSlice.new(
        "metadata" => {"name" => "bad", "labels" => {"kubernetes.io/service-name" => "web"}},
        "addressType" => "IPv4",
        "ports" => [{"port" => 8080, "protocol" => "TCP"}],
        "endpoints" => [{"addresses" => ["fd00::20"]}]
      )
    end
  end

  def test_topology_hints_fall_back_when_any_endpoint_has_no_hint
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "topology"},
      "spec" => {"clusterIP" => "10.96.0.31", "ports" => [{"port" => 80, "targetPort" => 8080}]}
    )
    slice = {
      "metadata" => {"name" => "topology-1", "labels" => {"kubernetes.io/service-name" => "topology"}},
      "addressType" => "IPv4",
      "ports" => [{"port" => 8080, "protocol" => "TCP"}],
      "endpoints" => [
        {"addresses" => ["10.1.0.31"], "zone" => "zone-a", "hints" => {"forZones" => [{"name" => "zone-a"}]}},
        {"addresses" => ["10.1.0.32"], "zone" => "zone-b"}
      ]
    }
    @proxy.apply_service(service)
    @proxy.apply_endpoint_slice(slice)
    destinations = Array.new(20) do |index|
      @proxy.route({"sourceIP" => "198.51.100.#{index + 1}", "sourcePort" => index + 1,
                    "destinationIP" => "10.96.0.31", "destinationPort" => 80, "zone" => "zone-a"}).address
    end

    assert_includes destinations, "10.1.0.32"
  end

  def test_udp_service_health_check_uses_tcp_health_port
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "udp-health"},
      "spec" => {"type" => "NodePort", "clusterIP" => "10.96.0.32", "externalTrafficPolicy" => "Local",
                 "healthCheckNodePort" => 30_090,
                 "ports" => [{"port" => 53, "targetPort" => 5353, "nodePort" => 30_053, "protocol" => "UDP"}]}
    )
    rules = Rubernetes::Proxy::RuleCompiler.new(local_node: "node-a").compile(service, endpoints: []).rules
    health = rules.find(&:health_check)

    assert_equal "TCP", health.protocol
    assert_equal 30_090, health.port
    assert_equal 30_090, health.node_port
  end

  def test_health_check_node_port_responder_returns_200_and_503_from_local_endpoints
    probe = nil
    health_port = nil
    (30_000..32_767).each do |candidate|
      next if candidate == 30_080

      begin
        probe = TCPServer.new("127.0.0.1", candidate)
        health_port = candidate
        break
      rescue Errno::EADDRINUSE
        next
      end
    end
    raise "could not reserve a NodePort-range test port" unless probe

    probe.close
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "health-responder"},
      "spec" => {"type" => "NodePort", "clusterIP" => "10.96.0.90", "externalTrafficPolicy" => "Local",
                 "healthCheckNodePort" => health_port,
                 "ports" => [{"port" => 80, "targetPort" => 8080, "nodePort" => 30_080, "protocol" => "TCP"}]}
    )
    slice = {
      "metadata" => {"name" => "health-responder-1", "labels" => {"kubernetes.io/service-name" => "health-responder"}},
      "addressType" => "IPv4", "ports" => [{"port" => 8080, "protocol" => "TCP"}],
      "endpoints" => [{"addresses" => ["10.1.0.90"], "nodeName" => "node-a",
                       "conditions" => {"ready" => true, "serving" => true}}]
    }
    proxy = Rubernetes::Proxy::Proxy.new(local_node: "node-a", backend: :nftables)
    proxy.apply_service(service)
    proxy.apply_endpoint_slice(slice)
    responder = proxy.start_health_check_responder(bind_address: "127.0.0.1")

    assert_includes responder.ports, health_port

    request = lambda do
      socket = TCPSocket.new("127.0.0.1", health_port)
      socket.write("GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
      socket.close_write
      Timeout.timeout(3) { socket.read }
    ensure
      socket&.close
    end

    assert_match(%r{\AHTTP/1\.1 200 OK\r\n}, request.call)

    unhealthy = Marshal.load(Marshal.dump(slice))
    unhealthy["endpoints"][0]["conditions"] = {"ready" => false, "serving" => false}
    proxy.apply_endpoint_slice(unhealthy)

    assert_match(%r{\AHTTP/1\.1 503 Service Unavailable\r\n}, request.call)
  ensure
    proxy&.stop_health_check_responder
  end

  def test_node_port_update_releases_removed_port_and_type_change_releases_all
    store = Rubernetes::Proxy::NodePortStore.new
    allocator = Rubernetes::Proxy::NodePortAllocator.new(store: store, min: 30_000, max: 30_010)
    first = Rubernetes::Proxy::Service.new("metadata" => {"name" => "ports"},
                                           "spec" => {"type" => "NodePort", "ports" => [{"port" => 80}]})
    second = Rubernetes::Proxy::Service.new("metadata" => {"name" => "ports"},
                                            "spec" => {"type" => "NodePort", "ports" => [{"port" => 81}]})
    allocator.allocate_for_service(first)
    allocator.allocate_for_service(second)

    assert_equal [81], allocator.allocations.map(&:port)
    allocator.release_service(second)

    assert_empty allocator.allocations
  end

  def test_health_check_node_port_is_reserved_atomically_and_released_on_update
    store = Rubernetes::Proxy::NodePortStore.new
    allocator = Rubernetes::Proxy::NodePortAllocator.new(store: store, min: 30_000, max: 30_002)
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "health-reserved"},
      "spec" => {"type" => "NodePort", "externalTrafficPolicy" => "Local",
                 "healthCheckNodePort" => 30_000,
                 "ports" => [{"port" => 80, "nodePort" => 30_001}]}
    )
    allocator.allocate_for_service(service)

    assert_equal [30_000, 30_001], allocator.allocations.map(&:node_port).sort
    assert_raises(Rubernetes::Proxy::AllocationError) do
      allocator.allocate(service_key: "default/other", protocol: "TCP", port: 81, requested: 30_000)
    end

    updated = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "health-reserved"},
      "spec" => {"type" => "NodePort", "ports" => [{"port" => 80, "nodePort" => 30_001}]}
    )
    allocator.allocate_for_service(updated)

    assert_equal [30_001], allocator.allocations.map(&:node_port)
  end

  def test_auto_failover_applies_snapshot_diff_to_attached_nftables_adapter
    adapter = ProxyNftablesModelTestAdapter.new
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true,
                                              syscall_adapter: ProxyEBPFModelTestAdapter.new,
                                              test_adapter: true)
    nftables = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
    auto = Rubernetes::Proxy::AutoBackend.new(ebpf: ebpf, nftables: nftables, capability_probe: -> { true })
    service = Rubernetes::Proxy::Service.new("metadata" => {"name" => "failover"},
                                             "spec" => {"clusterIP" => "10.96.0.33", "ports" => [{"port" => 80}]})
    compiled = Rubernetes::Proxy::RuleCompiler.new.compile(service,
                                                           endpoints: [Rubernetes::Proxy::Endpoint.new(address: "10.1.0.33", port: 80)],
                                                           revision: 1)
    auto.apply(compiled)
    auto.switch!(target: "nftables", reason: "test")

    assert_equal 1, nftables.messages.length
    assert_equal 1, adapter.calls.length
    assert_equal 1, adapter.calls.last.first.length
  end

  def test_nftables_adapter_failure_rolls_back_local_state_and_sends_inverse
    adapter = ProxyNftablesModelTestAdapter.new
    backend = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
    backend.attach
    adapter.fail_next_transaction!
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "rollback"},
      "spec" => {"clusterIP" => "10.96.0.35", "ports" => [{"port" => 80}]}
    )
    compiled = Rubernetes::Proxy::RuleCompiler.new.compile(
      service,
      endpoints: [Rubernetes::Proxy::Endpoint.new(address: "10.1.0.35", port: 80)],
      revision: 1
    )

    assert_raises(Rubernetes::Proxy::BackendError) { backend.apply(compiled) }
    assert_equal 0, backend.revision
    assert_empty backend.rules
    assert_empty backend.messages
    assert_equal([[], ["add"], ["delete"]], adapter.calls.map { |messages, _| messages.map { |message| message.fetch("operation") } })
  end

  def test_ebpf_adapter_failure_rolls_back_program_and_rules
    adapter = ProxyEBPFModelTestAdapter.new
    backend = Rubernetes::Proxy::EBPFBackend.new(capability: true, syscall_adapter: adapter, test_adapter: true)
    backend.attach
    adapter.fail_next_update!
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "bpf-rollback"},
      "spec" => {"clusterIP" => "10.96.0.37", "ports" => [{"port" => 80}]}
    )
    compiled = Rubernetes::Proxy::RuleCompiler.new.compile(
      service,
      endpoints: [Rubernetes::Proxy::Endpoint.new(address: "10.1.0.37", port: 80)],
      revision: 1
    )

    assert_raises(Rubernetes::Proxy::BackendError) { backend.apply(compiled) }
    assert_equal 0, backend.revision
    assert_empty backend.rules
    refute_nil backend.program
    update_calls = adapter.calls.filter_map do |call|
      next unless call.first == :update

      _operation, backend_name, diff, program = call
      [backend_name, diff.added.length, diff.deleted.length, program.length]
    end

    assert_equal [["ebpf", 1, 0, 7], ["ebpf", 0, 1, 6]], update_calls
  end

  def test_watch_reconnects_with_resource_version_resyncs_and_stops_thread
    calls = []
    queues = []
    service_object = {
      "metadata" => {"name" => "watched", "resourceVersion" => "7"},
      "spec" => {"clusterIP" => "10.96.0.36", "ports" => [{"port" => 80}]}
    }
    source = Object.new
    source.define_singleton_method(:watch) do |**options|
      calls << options
      queue = Queue.new
      queues << queue
      Enumerator.new do |yielder|
        loop do
          event = queue.pop
          break if event == :stop

          yielder << event
        end
      end
    end
    source.define_singleton_method(:snapshot) do
      {"services" => [service_object], "revision" => 7}
    end
    source.define_singleton_method(:stop) do
      queues.each { |queue| queue << :stop }
    end
    subscription = @proxy.watch(source, kind: :service, min_backoff: 0.001, max_backoff: 0.002)

    wait_for = lambda do |condition|
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1.0
      until condition.call
        raise "watch test timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        Thread.pass
      end
    end
    wait_for.call(-> { queues.length == 1 })
    stale_service = {
      "metadata" => {"name" => "stale", "resourceVersion" => "6"},
      "spec" => {"clusterIP" => "10.96.0.38", "ports" => [{"port" => 80}]}
    }
    queues.first << {"type" => "ADDED", "object" => stale_service}
    event_service = Marshal.load(Marshal.dump(service_object))
    event_service["spec"]["clusterIP"] = "10.96.0.37"
    queues.first << {"type" => "MODIFIED", "object" => event_service}
    queues.first << :stop
    wait_for.call(-> { calls.length >= 2 })

    assert_equal "7", calls.fetch(1).fetch(:resource_version)
    assert_equal "7", subscription.resource_version
    assert_equal "10.96.0.36", @proxy.service("watched").cluster_ip
    assert_nil @proxy.service("stale")
    subscription.close

    refute_predicate subscription.thread, :alive?
  end

  def test_rule_set_rejects_out_of_order_revision
    rule_set = Rubernetes::Proxy::RuleSet.new
    rule = Rubernetes::Proxy::RuleCompiler.new.compile(
      Rubernetes::Proxy::Service.new("metadata" => {"name" => "revision"},
                                     "spec" => {"clusterIP" => "10.96.0.34", "ports" => [{"port" => 80}]}),
      endpoints: [], revision: 2
    ).rules
    rule_set.apply(rule, revision: 2)
    assert_raises(Rubernetes::Proxy::StaleRevisionError) { rule_set.apply([], revision: 1) }
  end
end
