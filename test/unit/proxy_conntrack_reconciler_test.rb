# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"
require "rubernetes/proxy/metrics"

# pkg/proxy/conntrack.CleanStaleEntries: stale UDP flows for Service front
# ends are deleted after a sync, over ctnetlink, and counted per family.
class ProxyConntrackReconcilerTest < Minitest::Test
  Proxy = Rubernetes::Proxy

  # A netlink socket standing in for the kernel: answers a dump with the
  # flows it was given, ACKs deletes (ENOENT for a flow it no longer holds).
  class FakeSocket
    attr_reader :deletes

    def initialize(flows, gone: [])
      @flows = flows
      @gone = gone
      @codec = Proxy::ConntrackNetlink.new
      @queue = []
      @deletes = []
      # IO.select needs a real descriptor; a pipe holding one byte is always readable.
      @reader, writer = IO.pipe
      writer.write("x")
    end

    def bind(_address) = nil
    def close = nil

    # IO#wait_readable, as the production socket path now waits (fiber-scheduler safe).
    def wait_readable(timeout = nil)
      @reader.wait_readable(timeout) ? self : nil
    end

    def to_io = @reader

    def send(bytes, _flags)
      _length, type, _flags, sequence = bytes.unpack("L<S<S<L<")
      case type & 0xff
      when Proxy::ConntrackNetlink::IPCTNL_MSG_CT_GET
        @flows.each { |flow| @queue << @codec.encode_flow_message(flow, sequence: sequence) }
        @queue << @codec.done_message(sequence: sequence)
      when Proxy::ConntrackNetlink::IPCTNL_MSG_CT_DELETE
        family = bytes.byteslice(16, 1).unpack1("C") == 10 ? "IPv6" : "IPv4"
        flow = @codec.decode_flow(bytes.byteslice(16..), family)
        @deletes << flow
        gone = @gone.any? { |candidate| candidate.reply_src == flow.reply_src && candidate.reply_sport == flow.reply_sport }
        @queue << @codec.error_message(gone ? Errno::ENOENT::Errno : 0, sequence: sequence)
      end
      bytes.bytesize
    end

    def recv(_max) = @queue.shift(3).join
  end

  def flow(orig_dst:, orig_dport:, reply_src:, reply_sport:, protocol: 17, family: "IPv4", orig_src: "10.244.1.9", orig_sport: 40_000,
           id: 7)
    Proxy::ConntrackFlow.new(family: family, protocol: protocol, orig_src: orig_src, orig_sport: orig_sport,
                             orig_dst: orig_dst, orig_dport: orig_dport, reply_src: reply_src, reply_sport: reply_sport,
                             reply_dst: orig_src, reply_dport: orig_sport, id: id, zone: 0)
  end

  def endpoint(ip, port, serving: true)
    Proxy::Endpoint.new(address: ip, port: port, protocol: "UDP", ready: serving, serving: serving, terminating: false,
                        family: ip.include?(":") ? "IPv6" : "IPv4")
  end

  def rule(kind:, vip: nil, node_port: nil, port: 53, protocol: "UDP", backends: [])
    Proxy::Rule.new(service_key: "kube-system/dns", service_type: kind == "NodePort" ? "NodePort" : "ClusterIP", kind: kind,
                    virtual_ip: vip, port: port, protocol: protocol, node_port: node_port, backends: backends)
  end

  def rules
    serving = [endpoint("10.244.0.10", 53), endpoint("10.244.0.11", 53), endpoint("10.244.0.12", 53, serving: false)]
    [rule(kind: "ClusterIP", vip: "10.96.0.10", backends: serving),
     rule(kind: "ExternalIP", vip: "192.0.2.10", backends: serving),
     rule(kind: "NodePort", node_port: 30_053, backends: serving),
     rule(kind: "ClusterIP", vip: "10.96.0.20", port: 9, protocol: "TCP", backends: [endpoint("10.244.0.30", 9)]),
     rule(kind: "ClusterIP", vip: "10.96.0.30", port: 5353, backends: [])]
  end

  def flows
    [flow(orig_dst: "10.96.0.10", orig_dport: 53, reply_src: "10.244.0.10", reply_sport: 53, id: 1),   # serving: kept
     flow(orig_dst: "10.96.0.10", orig_dport: 53, reply_src: "10.244.0.99", reply_sport: 53, id: 2),   # gone endpoint: stale
     flow(orig_dst: "10.96.0.10", orig_dport: 53, reply_src: "10.244.0.12", reply_sport: 53, id: 3),   # not serving: stale
     flow(orig_dst: "192.0.2.10", orig_dport: 53, reply_src: "10.244.0.98", reply_sport: 53, id: 4),   # external IP: stale
     flow(orig_dst: "172.16.0.5", orig_dport: 30_053, reply_src: "10.244.0.97", reply_sport: 53, id: 5), # node port: stale
     flow(orig_dst: "172.16.0.5", orig_dport: 30_053, reply_src: "10.244.0.11", reply_sport: 53, id: 6), # node port serving: kept
     flow(orig_dst: "10.96.0.20", orig_dport: 9, reply_src: "10.244.0.1", reply_sport: 9, protocol: 6, id: 7), # TCP: ignored
     flow(orig_dst: "10.96.0.30", orig_dport: 5353, reply_src: "10.244.0.1", reply_sport: 5353, id: 8), # no serving endpoints: kept
     flow(orig_dst: "10.96.0.10", orig_dport: 5300, reply_src: "10.244.0.1", reply_sport: 53, id: 9)] # other port: kept
  end

  def test_stale_filter_matches_upstream_rules
    stale = Proxy::ConntrackReconciler.stale_flows("IPv4", rules, flows)

    assert_equal [2, 3, 4, 5], stale.map(&:id)
    assert_empty Proxy::ConntrackReconciler.stale_flows("IPv6", rules, flows), "IPv4 front ends do not filter the IPv6 table"
  end

  def test_wire_format_round_trip
    codec = Proxy::ConntrackNetlink.new
    original = flow(orig_dst: "fd00::10", orig_dport: 53, reply_src: "fd00:1::5", reply_sport: 5353, family: "IPv6", orig_src: "fd00:2::9",
                    id: 42)
    message = codec.encode_flow_message(original, sequence: 9)
    decoded = codec.decode_flow(message.byteslice(16..), "IPv6")

    assert_equal original.to_h, decoded.to_h
  end

  def test_reconcile_deletes_over_netlink_and_records_metrics
    socket = FakeSocket.new(flows, gone: [flows[3]])
    netlink = Proxy::ConntrackNetlink.new(socket_factory: -> { socket }, timeout: 2.0)
    metrics = Proxy::Metrics.new
    ticks = [10.0, 10.25, 20.0, 20.5]
    reconciler = Proxy::ConntrackReconciler.new(families: %w[IPv4 IPv6], netlink: netlink, metrics: metrics, clock: -> { ticks.shift })
    result = reconciler.reconcile(rules)

    assert_nil reconciler.last_error
    assert_equal({"IPv4" => 3, "IPv6" => 0}, result, "four stale flows, one already gone (ENOENT is not a deletion)")
    assert_equal 4, socket.deletes.length
    assert_equal %w[10.244.0.99 10.244.0.12 10.244.0.98 10.244.0.97], socket.deletes.map(&:reply_src)
    text = metrics.registry.render_own

    assert_match(/kubeproxy_conntrack_reconciler_deleted_entries_total\{ip_family="IPv4"\} 3/, text)
    refute_match(/kubeproxy_conntrack_reconciler_deleted_entries_total\{ip_family="IPv6"\}/, text)
    assert_match(/kubeproxy_conntrack_reconciler_sync_duration_seconds_count\{ip_family="IPv4"\} 1/, text)
    assert_match(/kubeproxy_conntrack_reconciler_sync_duration_seconds_sum\{ip_family="IPv4"\} 0.25/, text)
    assert_match(/kubeproxy_conntrack_reconciler_sync_duration_seconds_count\{ip_family="IPv6"\} 1/, text)
    refute_predicate reconciler, :disabled?
  end

  def test_permission_failure_disables_the_reconciler_once
    netlink = Proxy::ConntrackNetlink.new(socket_factory: -> { raise Errno::EPERM, "netlink" })
    warnings = []
    logger = Object.new
    logger.define_singleton_method(:warn) { |event, **fields| warnings << [event, fields] }
    reconciler = Proxy::ConntrackReconciler.new(families: ["IPv4"], netlink: netlink, logger: logger)

    assert_equal({"IPv4" => 0}, reconciler.reconcile(rules))
    assert_predicate reconciler, :disabled?
    assert_equal "proxy.conntrack_reconcile_failed", warnings.first.first
    assert_equal({}, reconciler.reconcile(rules), "switched off after EPERM")
    assert_equal 1, warnings.length
  end

  def test_engine_runs_the_reconciler_after_each_publish
    calls = []
    fake = Object.new
    fake.define_singleton_method(:disabled?) { false }
    fake.define_singleton_method(:reconcile) do |rules|
      calls << rules
      {}
    end
    engine = Proxy::Proxy.new(local_node: "node-a", backend: Proxy::MemoryBackend.new)
    engine.conntrack_reconciler = fake
    engine.apply_service({"apiVersion" => "v1", "kind" => "Service",
                          "metadata" => {"name" => "dns", "namespace" => "kube-system", "uid" => "u1", "resourceVersion" => "1"},
                          "spec" => {"clusterIP" => "10.96.0.10", "clusterIPs" => ["10.96.0.10"], "type" => "ClusterIP",
                                     "ports" => [{"name" => "dns", "port" => 53, "targetPort" => 53, "protocol" => "UDP"}]}})
    engine.sync

    refute_empty calls
    assert(calls.last.any? { |r| r.kind == "ClusterIP" && r.protocol == "UDP" && r.virtual_ip == "10.96.0.10" })
  end

  def test_live_dump_when_the_kernel_allows_it
    skip "requires root" unless Process.uid.zero?
    netlink = Proxy::ConntrackNetlink.new(timeout: 5.0)
    entries = netlink.list("IPv4")

    assert_kind_of Array, entries
    entries.first(3).each { |entry| assert entry.orig_dst && entry.reply_src, "flow tuples decode: #{entry.inspect}" }
  rescue Proxy::ConntrackNetlinkError => error
    skip "conntrack netlink unavailable: #{error.message}" if [Errno::EPERM::Errno, Errno::EPROTONOSUPPORT::Errno,
                                                               Errno::EAFNOSUPPORT::Errno, Errno::ENOENT::Errno].include?(error.errno)
    raise
  end
end
