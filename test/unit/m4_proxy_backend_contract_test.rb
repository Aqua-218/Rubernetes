# frozen_string_literal: true

# M4 proxy backend contract tests.
# Specification: spec/delivery/milestones.md (M4 exit criterion 2) and
# spec/node/service-proxy.md (backend switch and conntrack requirements).
# Coverage: atomic backend handoff, external connection-loss evidence, and
# model-only parity classification.

require_relative "../test_helper"
require "rubernetes/proxy"
require "rubernetes/bootstrap/control_plane_services"

class ProxyProductionContractAdapter
  attr_reader :events

  def initialize(name, events, fail_detach: false)
    @name = name
    @events = events
    @fail_detach = fail_detach
    @attached = false
  end

  def production_capable?
    true
  end

  def attach(**_arguments)
    @events << [@name, :attach]
    @attached = true
    {verified: true}
  end

  def send_messages(_messages, **_arguments)
    @events << [@name, :update]
    {verified: true}
  end

  alias update send_messages

  def verify_attach(backend:, result:, **_arguments)
    backend.name == @name && result[:verified] == true && @attached
  end

  alias verify_transaction verify_attach
  alias verify_update verify_attach

  def detach(**_arguments)
    @events << [@name, :detach]
    raise IOError, "simulated old backend detach failure" if @fail_detach

    @attached = false
    true
  end
end

class M4ProxyBackendContractTest < Minitest::Test
  def test_model_parity_is_never_a_production_verdict
    left = Rubernetes::Proxy::MemoryBackend.new
    right = Rubernetes::Proxy::MemoryBackend.new

    result = Rubernetes::Proxy::BackendParity.compare(left, right)

    assert_equal true, result.fetch("passed")
    assert_equal "model_only", result.fetch("measurementSource")
    refute result.fetch("productionCapable")
    refute result.fetch("productionVerified")

    missing = Rubernetes::Proxy::BackendParity.production_compare(
      left, right, packet_corpus: {"passed" => true}, kernel_readback: {}
    )

    refute missing.fetch("productionCapable")
    refute missing.fetch("productionVerified")

    forged = Rubernetes::Proxy::BackendParity.production_compare(
      left, right,
      packet_corpus: {"passed" => true, "packetTraceSha256" => "a" * 64},
      kernel_readback: {"ebpf" => {"readback" => true, "rules" => [{}]},
                        "nftables" => {"readback" => true, "rules" => [{}]}}
    )

    refute forged.fetch("productionCapable")
    refute forged.fetch("productionVerified")

    raw_trace = [{"direction" => "forward", "source" => "10.0.0.2", "destination" => "10.96.0.40"}]
    trace_digest = Rubernetes::Proxy::BackendParity.canonical_trace_digest(raw_trace)
    cases = [{"id" => "tcp-cluster-ip", "passed" => true, "expected" => {"status" => "dnat"},
              "actual" => {"status" => "dnat"}, "packetTraceSha256" => trace_digest}]
    packet_corpus = {
      "measurementSource" => "isolated_privileged_kernel",
      "executed" => true,
      "runnerIdentity" => "proxy-parity-runner",
      "runnerDigest" => "b" * 64,
      "mode" => "privileged-container",
      "inputBinding" => {"leftDigest" => left.digest, "rightDigest" => right.digest},
      "rawPacketTrace" => raw_trace,
      "packetTraceSha256" => trace_digest,
      "caseInventory" => [{"id" => "tcp-cluster-ip"}],
      "cases" => cases
    }
    kernel_readback = {
      "measurementSource" => "isolated_privileged_kernel",
      "runnerIdentity" => "proxy-parity-runner",
      "runnerDigest" => "b" * 64,
      "mode" => "privileged-container",
      "inputBinding" => {"leftDigest" => left.digest, "rightDigest" => right.digest}
    }
    %w[ebpf nftables].each do |name|
      identity = {"object" => name, "id" => name == "ebpf" ? 11 : 22, "tag" => "verified"}
      rules = [{"key" => "default/web", "family" => "ipv4", "protocol" => "TCP"}]
      kernel_readback[name] = {
        "readback" => true, "rules" => rules,
        "identity" => identity,
        "identityDigest" => Rubernetes::Proxy::BackendParity.canonical_trace_digest(identity),
        "rulesDigest" => Rubernetes::Proxy::BackendParity.canonical_trace_digest(rules),
        "inputDigest" => name == "ebpf" ? left.digest : right.digest
      }
    end
    verified = Rubernetes::Proxy::BackendParity.production_compare(
      left, right, packet_corpus: packet_corpus, kernel_readback: kernel_readback
    )

    refute verified.fetch("productionCapable")
    refute verified.fetch("productionVerified")
    assert_includes verified.fetch("evidenceErrors").join(";"), "production-capable external adapter"

    # A model-only backend cannot be promoted by a complete-looking corpus.
  end

  def test_transport_backed_readback_cannot_claim_live_nftables_capability
    adapter = Rubernetes::Proxy::NftablesNetlinkAdapter.new(table_name: "model_transport", transport: Object.new)

    refute_predicate adapter, :production_capable?
    assert_match(/live NETLINK_NETFILTER/, adapter.production_capability_error)
  end

  def test_switch_requires_external_connection_evidence_for_production_backends
    events = []
    ebpf_adapter = ProxyProductionContractAdapter.new("ebpf", events)
    nft_adapter = ProxyProductionContractAdapter.new("nftables", events)
    auto = build_auto(ebpf_adapter, nft_adapter)
    auto.attach

    error = assert_raises(Rubernetes::Proxy::BackendError) do
      auto.switch!(target: "nftables", reason: "missing external probe")
    end
    assert_match(/external connection tracker or probe/, error.message)
    assert_equal "ebpf", auto.selected_backend
    assert_equal ["ebpf", :attach], events.last
  end

  def test_plain_connection_probe_is_rejected_even_if_it_returns_counts
    events = []
    ebpf_adapter = ProxyProductionContractAdapter.new("ebpf", events)
    nft_adapter = ProxyProductionContractAdapter.new("nftables", events)
    probe = Object.new
    probe.define_singleton_method(:measure_switch) { |**_arguments| {active_connections: 1, lost_connections: 0} }
    auto = build_auto(ebpf_adapter, nft_adapter, connection_probe: probe)
    auto.attach

    error = assert_raises(Rubernetes::Proxy::BackendError) do
      auto.switch!(target: "nftables", reason: "forged probe")
    end
    assert_match(/external connection tracker or probe/, error.message)
  end

  def test_proxy_service_wires_external_probe_and_tracker_into_auto_backend
    probe = external_probe_fixture
    tracker = external_probe_fixture
    service = Rubernetes::Bootstrap::ProxyService.new(
      config: {"node_name" => "node-a", "backend" => "auto"},
      logger: Object.new,
      runtime_adapters: {proxy_client: Object.new, connection_probe: probe, connection_tracker: tracker}
    )
    service.send(:build_runtime!)

    assert_same probe, service.proxy.backend.connection_probe
    assert_same tracker, service.proxy.backend.connection_tracker
    assert_same tracker, service.proxy.connection_tracker
  end

  def test_switch_attaches_target_measures_externally_then_detaches_old_backend
    events = []
    ebpf_adapter = ProxyProductionContractAdapter.new("ebpf", events)
    nft_adapter = ProxyProductionContractAdapter.new("nftables", events)
    probe = external_probe_fixture(active: 7, lost: 0)
    auto = build_auto(ebpf_adapter, nft_adapter, connection_probe: probe)
    auto.attach

    measurement = auto.switch!(target: "nftables", reason: "external probe")

    assert_equal "ebpf", measurement.from_backend
    assert_equal "nftables", measurement.to_backend
    assert_equal 7, measurement.active_connections
    assert_equal 0, measurement.lost_connections
    assert_equal "external_probe", measurement.measurement_source
    assert_equal [
      ["ebpf", :attach],
      ["nftables", :attach],
      ["ebpf", :detach]
    ], events
    assert_equal "nftables", auto.selected_backend
  end

  def test_explicitly_authorized_external_tracker_can_supply_the_measurement
    events = []
    ebpf_adapter = ProxyProductionContractAdapter.new("ebpf", events)
    nft_adapter = ProxyProductionContractAdapter.new("nftables", events)
    tracker = external_probe_fixture(active: 2, lost: 1)
    auto = build_auto(ebpf_adapter, nft_adapter, connection_tracker: tracker)
    auto.attach

    measurement = auto.switch!(target: "nftables", reason: "external tracker")

    assert_equal 2, measurement.active_connections
    assert_equal 1, measurement.lost_connections
    assert_equal "external_probe", measurement.measurement_source
  end

  def test_switch_rolls_back_target_and_restores_old_backend_when_detach_fails
    events = []
    ebpf_adapter = ProxyProductionContractAdapter.new("ebpf", events, fail_detach: true)
    nft_adapter = ProxyProductionContractAdapter.new("nftables", events)
    probe = external_probe_fixture(active: 1, lost: 0)
    auto = build_auto(ebpf_adapter, nft_adapter, connection_probe: probe)
    auto.attach

    assert_raises(Rubernetes::Proxy::BackendError) do
      auto.switch!(target: "nftables", reason: "detach fault")
    end
    assert_equal "ebpf", auto.selected_backend
    assert_equal [
      ["ebpf", :attach],
      ["nftables", :attach],
      ["ebpf", :detach],
      ["nftables", :detach],
      ["ebpf", :attach]
    ], events
  end

  private

  def external_probe_fixture(active: 1, lost: 0)
    probe = Object.new
    identity = "focused-external-runner"
    digest = "c" * 64
    probe.define_singleton_method(:external?) { true }
    probe.define_singleton_method(:runner_identity) { identity }
    probe.define_singleton_method(:runner_digest) { digest }
    snapshot = lambda do |phase|
      value = {"connectionIDs" => ["conn-1"], "phase" => phase, "state" => "established"}
      value["rawObservationDigest"] = Rubernetes::Proxy::BackendParity.canonical_trace_digest(value)
      value
    end
    probe.define_singleton_method(:before_switch) { |**_arguments| snapshot.call("before") }
    probe.define_singleton_method(:after_switch) { |**_arguments| snapshot.call("after") }
    probe.define_singleton_method(:measure_switch) do |**arguments|
      raw = {"before" => arguments.fetch(:before).fetch(:raw), "after" => arguments.fetch(:after).fetch(:raw),
             "activeConnections" => active, "lostConnections" => lost}
      {active_connections: active, lost_connections: lost, connectionIDs: ["conn-1"],
       runnerIdentity: identity, runnerDigest: digest, rawObservation: raw,
       rawObservationDigest: Rubernetes::Proxy::BackendParity.canonical_trace_digest(raw)}
    end
    probe
  end

  def build_auto(ebpf_adapter, nft_adapter, connection_probe: nil, connection_tracker: nil)
    ebpf = Rubernetes::Proxy::EBPFBackend.new(capability: true, syscall_adapter: ebpf_adapter)
    nftables = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: nft_adapter)
    Rubernetes::Proxy::AutoBackend.new(
      ebpf: ebpf,
      nftables: nftables,
      capability_probe: -> { true },
      connection_probe: connection_probe,
      connection_tracker: connection_tracker
    )
  end
end
