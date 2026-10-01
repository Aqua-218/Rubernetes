# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

# pkg/proxy/iptables: the iptables proxier as a Proxy backend (restore
# program, partial sync, jump chains, nfacct counters, the six
# kubeproxy_*iptables* families).
class ProxyIptablesBackendTest < Minitest::Test
  Proxy = Rubernetes::Proxy
  Iptables = Proxy::Iptables

  # A runner that records every invocation and answers like iptables.
  class FakeRunner
    attr_reader :calls, :programs
    attr_accessor :fail_restore, :existing_chains

    def initialize
      @calls = []
      @programs = []
      @fail_restore = false
      @existing_chains = []
    end

    def call(argv, stdin)
      @calls << argv
      case argv
      in [/iptables-restore/, *]
        @programs << stdin
        return [1, "", "iptables-restore: line 3 failed"] if @fail_restore

        [0, "", ""]
      in [/iptables-save/, *]
        [0, "*nat\n" + @existing_chains.map { |chain| ":#{chain} - [0:0]\n" }.join + "COMMIT\n", ""]
      in [/iptables$/, *rest] if rest.include?("-C")
        [1, "", "iptables: Bad rule"]
      else
        [0, "", ""]
      end
    end
  end

  def service(type: "ClusterIP", extra: {}, ports: nil)
    spec = {"clusterIP" => "10.96.0.10", "clusterIPs" => ["10.96.0.10"], "ipFamilies" => ["IPv4"], "type" => type,
            "ports" => ports || [{"name" => "http", "port" => 80, "protocol" => "TCP", "targetPort" => 8080}]}.merge(extra)
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "svc", "namespace" => "ns", "uid" => "u1"}, "spec" => spec}
  end

  def slice(endpoints)
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
     "metadata" => {"name" => "svc-abc", "namespace" => "ns", "labels" => {"kubernetes.io/service-name" => "svc"}},
     "addressType" => "IPv4", "ports" => [{"name" => "http", "port" => 8080, "protocol" => "TCP"}],
     "endpoints" => endpoints.map do |ip, node, ready|
       {"addresses" => [ip], "nodeName" => node, "conditions" => {"ready" => ready.nil? || ready, "serving" => true, "terminating" => false}}
     end}
  end

  def build(runner: FakeRunner.new, metrics: nil)
    adapter = Iptables::Adapter.new(runner: runner, test_adapter: true)
    backend = Iptables::Backend.new(adapter: adapter, families: ["IPv4"], node_name: "worker-0", node_addresses: ["192.168.1.10"],
                                    test_adapter: true, cluster_cidr: "10.244.0.0/16")
    proxy = Proxy::Proxy.new(local_node: "worker-0", node_addresses: ["192.168.1.10"], backend: backend)
    proxy.metrics = metrics if metrics
    [proxy, backend, runner]
  end

  def test_chain_names_follow_upstream_hashing
    # portProtoHash("ns/svc:http", "tcp") from upstream's own test table.
    assert_equal "KUBE-SVC-XPGD46QRK7WJZT7O", Iptables.service_chain("ns1/svc1:p80", "tcp")
    assert_equal "KUBE-SEP-SXIVWICOYRO3J4NJ", Iptables.endpoint_chain("ns1/svc1:p80", "tcp", "10.180.0.1:80")
    assert_equal "0.3333333333", Iptables.probability(3)
  end

  def test_full_sync_renders_upstream_chain_layout
    metrics = Proxy::Metrics.new(mode: :iptables)
    proxy, backend, runner = build(metrics: metrics)
    proxy.apply_service(service(type: "NodePort", extra: {"externalTrafficPolicy" => "Local", "externalIPs" => ["192.168.99.22"]},
                                ports: [{"name" => "http", "port" => 80, "protocol" => "TCP", "targetPort" => 8080, "nodePort" => 30_080}]))
    proxy.apply_endpoint_slice(slice([["10.244.0.5", "worker-0"], ["10.244.1.6", "worker-1"]]))
    backend.attach

    assert_predicate backend, :attached?
    program = runner.programs.last

    assert_match(
      /\A\*filter\n:KUBE-SERVICES - \[0:0\]\n:KUBE-EXTERNAL-SERVICES - \[0:0\]\n:KUBE-FORWARD - \[0:0\]\n:KUBE-NODEPORTS - \[0:0\]\n:KUBE-PROXY-FIREWALL - \[0:0\]\n:KUBE-FIREWALL - \[0:0\]\n/, program
    )
    svc = Iptables.service_chain("ns/svc:http", "TCP")
    svl = Iptables.local_chain("ns/svc:http", "TCP")
    ext = Iptables.external_chain("ns/svc:http", "TCP")
    sep_local = Iptables.endpoint_chain("ns/svc:http", "TCP", "10.244.0.5:8080")
    sep_remote = Iptables.endpoint_chain("ns/svc:http", "TCP", "10.244.1.6:8080")

    [
      "-A KUBE-SERVICES -m comment --comment \"ns/svc:http cluster IP\" -m tcp -p tcp -d 10.96.0.10 --dport 80 -j #{svc}",
      "-A KUBE-SERVICES -m comment --comment \"ns/svc:http external IP\" -m tcp -p tcp -d 192.168.99.22 --dport 80 -j #{ext}",
      "-A KUBE-NODEPORTS -m comment --comment ns/svc:http -m tcp -p tcp --dport 30080 -j #{ext}",
      "-A #{svc} -m comment --comment \"ns/svc:http cluster IP\" -m tcp -p tcp -d 10.96.0.10 --dport 80 ! -s 10.244.0.0/16 -j KUBE-MARK-MASQ",
      "-A #{ext} -m comment --comment \"pod traffic for ns/svc:http external destinations\" -s 10.244.0.0/16 -j #{svc}",
      "-A #{ext} -m comment --comment \"masquerade LOCAL traffic for ns/svc:http external destinations\" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ",
      "-A #{ext} -j #{svl}",
      "-A #{svc} -m comment --comment \"ns/svc:http -> 10.244.0.5:8080\" -m statistic --mode random --probability 0.5000000000 -j #{sep_local}",
      "-A #{svc} -m comment --comment \"ns/svc:http -> 10.244.1.6:8080\" -j #{sep_remote}",
      "-A #{svl} -m comment --comment \"ns/svc:http -> 10.244.0.5:8080\" -j #{sep_local}",
      "-A #{sep_local} -m comment --comment ns/svc:http -s 10.244.0.5 -j KUBE-MARK-MASQ",
      "-A #{sep_local} -m comment --comment ns/svc:http -m tcp -p tcp -j DNAT --to-destination 10.244.0.5:8080",
      "-A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN",
      "-A KUBE-MARK-MASQ -j MARK --or-mark 0x4000",
      "-A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP",
      "-A KUBE-SERVICES -m comment --comment \"kubernetes service nodeports; NOTE: this must be the last rule in this chain\" -m addrtype --dst-type LOCAL " \
      "-j KUBE-NODEPORTS"
    ].each { |line| assert_includes program.lines.map(&:chomp), line }
    refute_includes program, "-m nfacct", "no nfacct counters exist on a fake adapter"
    assert program.end_with?("COMMIT\n")
    # The jump chains were ensured (EnsureChain then -C / -I per hook).
    inserted = runner.calls.select { |argv| argv.include?("-I") }

    assert_includes inserted,
                    ["iptables", "-w", "5", "-t", "nat", "-I", "PREROUTING", "-m", "comment", "--comment", "kubernetes service portals",
                     "-j", "KUBE-SERVICES"]
    assert_includes inserted,
                    ["iptables", "-w", "5", "-t", "filter", "-I", "FORWARD", "-m", "conntrack", "--ctstate", "NEW", "-m", "comment", "--comment",
                     "kubernetes service portals", "-j", "KUBE-SERVICES"]
    assert_equal(["iptables-restore", "-w", "5", "--noflush", "--counters"], runner.calls.find { |argv| argv.first == "iptables-restore" })
    text = metrics.render

    assert_match(/kubeproxy_sync_proxy_rules_iptables_last\{ip_family="IPv4",table="nat"\} #{program.lines.count do |l|
      l.start_with?("-A") && program.index(l) > program.index("*nat")
    end}/, text)
    assert_match(/kubeproxy_sync_proxy_rules_iptables_total\{ip_family="IPv4",table="filter"\} \d+/, text)
    refute_match(/nftables_sync_failures/, text)
    refute_match(/kubeproxy_sync_proxy_rules_iptables_restore_failures_total\{ip_family="IPv4"\}/, text,
                 "no failure series before a failure")
  end

  def test_partial_sync_skips_unchanged_services_and_full_sync_deletes_stale_chains
    proxy, backend, runner = build
    proxy.apply_service(service)
    proxy.apply_endpoint_slice(slice([["10.244.0.5", "worker-0"]]))
    other = service.merge("metadata" => {"name" => "other", "namespace" => "ns", "uid" => "u2"})
    other["spec"] = other["spec"].merge("clusterIP" => "10.96.0.11", "clusterIPs" => ["10.96.0.11"])
    proxy.apply_service(other)
    backend.attach
    full = runner.programs.last

    assert_includes full,
                    "-A KUBE-SERVICES -m comment --comment \"ns/other:http has no endpoints\" -m tcp -p tcp -d 10.96.0.11 --dport 80 -j REJECT"
    # Partial: only ns/svc changes -> other service's chains are not rewritten.
    proxy.apply_endpoint_slice(slice([["10.244.0.5", "worker-0"], ["10.244.0.7", "worker-0"]]))
    partial = runner.programs.last

    refute_equal full, partial
    assert_includes partial, Iptables.endpoint_chain("ns/svc:http", "TCP", "10.244.0.7:8080")
    assert_equal 1, partial.scan(":KUBE-SVC-").length
    assert_equal 0, backend.last_programs["IPv4"].skipped_nat_rules, "the other service owns no chain rules (no endpoints)"
    # A full sync removes chains no service owns any more.
    runner.existing_chains = %w[KUBE-SERVICES KUBE-SVC-DEADBEEFDEADBEEF KUBE-SEP-DEADBEEFDEADBEEF]
    backend.sync_family!("IPv4", now: Time.now + 4000)
    resync = runner.programs.last

    assert_includes resync, ":KUBE-SVC-DEADBEEFDEADBEEF - [0:0]\n"
    assert_includes resync, "-X KUBE-SVC-DEADBEEFDEADBEEF\n"
    assert_includes resync, "-X KUBE-SEP-DEADBEEFDEADBEEF\n"
    refute_includes resync, "-X KUBE-SERVICES"
  end

  def test_restore_failure_counts_and_forces_a_full_sync
    metrics = Proxy::Metrics.new(mode: :iptables)
    proxy, backend, runner = build(metrics: metrics)
    proxy.apply_service(service)
    proxy.apply_endpoint_slice(slice([["10.244.0.5", "worker-0"]]))
    backend.attach
    runner.fail_restore = true
    error = assert_raises(Proxy::BackendError) { backend.sync_family!("IPv4") }
    assert_match(/iptables-restore failed \(IPv4\)/, error.message)
    text = metrics.render

    assert_match(/kubeproxy_sync_proxy_rules_iptables_restore_failures_total\{ip_family="IPv4"\} 1/, text)
    assert_match(/kubeproxy_sync_proxy_rules_iptables_partial_restore_failures_total\{ip_family="IPv4"\} 1/, text)
    runner.fail_restore = false
    saves_before = runner.calls.count { |argv| argv.first == "iptables-save" }
    backend.sync_family!("IPv4")

    assert_operator runner.calls.count { |argv| argv.first == "iptables-save" }, :>, saves_before, "the retry is a full sync"
    # A failed publish through the engine leaves the model at the previous revision.
    runner.fail_restore = true
    before = backend.revision
    assert_raises(Proxy::BackendError) { proxy.apply_endpoint_slice(slice([["10.244.0.9", "worker-0"]])) }
    assert_equal before, backend.revision
  end

  def test_metrics_mode_registers_the_iptables_families_only_in_iptables_mode
    iptables = Proxy::Metrics.new(mode: :iptables)
    names = iptables.registry.registered_names

    (Proxy::Metrics::IPTABLES_FAMILIES + Proxy::Metrics::IPTABLES_NFACCT_FAMILIES.keys).each { |name| assert_includes names, name }
    refute_includes names, "kubeproxy_sync_proxy_rules_nftables_sync_failures_total"
    iptables.nfacct_counters = -> { {Iptables::CT_STATE_INVALID_COUNTER => [42, 4200]} }
    text = iptables.render

    assert_match(/kubeproxy_iptables_ct_state_invalid_dropped_packets_total 42/, text)
    refute_match(/kubeproxy_iptables_localhost_nodeports_accepted_packets_total [1-9]/, text, "an unknown counter publishes no count")
    nftables = Proxy::Metrics.new

    Proxy::Metrics::IPTABLES_FAMILIES.each { |name| refute_includes nftables.registry.registered_names, name }
    assert_includes nftables.registry.registered_names, "kubeproxy_sync_proxy_rules_nftables_sync_failures_total"
    refute Rubernetes::Observability::Metrics::UNIMPLEMENTED.key?("kube-proxy")
  end

  def test_session_affinity_source_ranges_and_ipv6_rendering
    renderer = Iptables::Renderer.new(family: "IPv6", node_name: "worker-0", node_ips: ["fd00::10"], nfacct_counters: {})
    rule = Proxy::Rule.new(service_key: "ns/svc", service_type: "LoadBalancer", kind: "LoadBalancer", virtual_ip: "2001:db8::5", port: 443, protocol: "TCP",
                           session_affinity: "ClientIP", session_affinity_timeout_seconds: 300,
                           backends: [Proxy::Endpoint.new(address: "fd00:1::5", port: 8443, node_name: "worker-1", ready: true, serving: true, terminating: false)],
                           metadata: {"servicePort" => {"name" => "https"}, "loadBalancerSourceRanges" => ["fd00::/64"]})
    program = renderer.render([rule]).text
    fw = Iptables.firewall_chain("ns/svc:https", "TCP")
    ext = Iptables.external_chain("ns/svc:https", "TCP")
    sep = Iptables.endpoint_chain("ns/svc:https", "TCP", "[fd00:1::5]:8443")

    assert_includes program,
                    "-A KUBE-SERVICES -m comment --comment \"ns/svc:https loadbalancer IP\" -m tcp -p tcp -d 2001:db8::5 --dport 443 -j #{fw}"
    assert_includes program, "-A #{fw} -m comment --comment \"ns/svc:https loadbalancer IP\" -s fd00::/64 -j #{ext}"
    assert_includes program, "-A #{fw} -m comment --comment \"ns/svc:https loadbalancer IP\" -s 2001:db8::5 -j #{ext}",
                    "the node sits inside the source range"
    assert_includes program,
                    "-A KUBE-PROXY-FIREWALL -m comment --comment \"ns/svc:https traffic not accepted by #{fw}\" -m tcp -p tcp -d 2001:db8::5 --dport 443 -j " \
                    "DROP"
    assert_includes program, "-m recent --name #{sep} --rcheck --seconds 300 --reap -j #{sep}"
    assert_includes program, "-m recent --name #{sep} --set -m tcp -p tcp -j DNAT --to-destination [fd00:1::5]:8443"
    assert_includes program, "-m addrtype --dst-type LOCAL ! -d ::1/128 -j KUBE-NODEPORTS"
    refute_includes program, "KUBE-FIREWALL", "localhost nodeports are IPv4 only"
  end

  def test_restore_program_is_accepted_by_iptables_restore
    skip "needs root and iptables-restore" unless Process.uid.zero? && system("iptables-restore --version >/dev/null 2>&1")

    proxy, backend, = build
    proxy.apply_service(service(type: "LoadBalancer", extra: {"externalTrafficPolicy" => "Local", "loadBalancerSourceRanges" => ["192.168.0.0/16"],
                                                              "sessionAffinity" => "ClientIP", "sessionAffinityConfig" => {"clientIP" => {"timeoutSeconds" => 60}}},
                                ports: [{"name" => "http", "port" => 80, "protocol" => "TCP", "targetPort" => 8080, "nodePort" => 30_080}]).tap do |s|
      s["status"] =
        {"loadBalancer" => {"ingress" => [{"ip" => "203.0.113.5"}]}}
    end)
    proxy.apply_endpoint_slice(slice([["10.244.0.5", "worker-0"], ["10.244.1.6", "worker-1"]]))
    program = Iptables::Renderer.new(family: "IPv4", node_name: "worker-0", node_ips: ["192.168.1.10"], cluster_cidr: "10.244.0.0/16",
                                     nfacct_counters: {Iptables::CT_STATE_INVALID_COUNTER => system("nfacct list >/dev/null 2>&1")}).render(backend.rules).text
    stdout, stderr, status = Open3.capture3("iptables-restore", "--test", "--noflush", stdin_data: program)

    assert_predicate status, :success?, "iptables-restore --test rejected the program: #{stderr} #{stdout}\n#{program}"
  end

  def test_nfacct_client_round_trip
    skip "needs root" unless Process.uid.zero?

    client = Iptables::Nfacct.new
    name = "rbn_test_#{Process.pid}"
    skip "nfnetlink_acct unavailable" unless client.ensure(name)

    begin
      counters = client.counters

      assert_equal [0, 0], counters[name]
      assert client.delete(name)
      refute client.counters.key?(name)
    ensure
      client.delete(name)
    end
  end
end
