#!/usr/bin/env ruby
# frozen_string_literal: true

# M4 proxy backend parity probe.
#
# The probe is the production process: it moves itself into a private
# network namespace, builds a node/client/backend veth topology with the
# production rtnetlink code, compiles the shared Service corpus with the
# production proxy, and drives the real eBPF (TC) and nftables datapaths
# through AutoBackend.  An external runner (test/conformance/kubernetes/
# m4_proxy_parity/runner.rb, or the command named by
# RUBERNETES_M4_PROXY_READBACK_COMMAND / RUBERNETES_M4_EBPF_NFT_READBACK_COMMAND)
# generates the packet corpus against each backend, reads the kernel back
# with bpftool/tc/nft, and measures connection survival across the backend
# switch.  Parity is then the runner's kernel-observed verdicts for both
# backends, bound to the production model digests.

require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "socket"
require "time"

require_relative "m4_probe_support"
require_relative "../../test/conformance/kubernetes/m4_proxy_parity/corpus"
require_relative "../../lib/rubernetes/network"
require_relative "../../lib/rubernetes/proxy"
require_relative "../../lib/rubernetes/platform/linux/setns"

module M4ProxyKernelProbe
  RUNNER_ENV_KEYS = %w[RUBERNETES_M4_PROXY_READBACK_COMMAND RUBERNETES_M4_EBPF_NFT_READBACK_COMMAND].freeze
  DEFAULT_RUNNER = [RbConfig.ruby, "test/conformance/kubernetes/m4_proxy_parity/runner.rb"].freeze
  ROOT = File.expand_path("../..", __dir__)
  Corpus = M4ProxyParityCorpus
  TOPOLOGY = Corpus::TOPOLOGY
  SWITCH_CONNECTIONS = 6
  IFA_F_NODAD = 0x02

  class RunnerSession
    attr_reader :command, :pid, :init_response, :stdout_lines

    def initialize(command)
      @command = command
      @stdin, @stdout, @stderr, @thread = Open3.popen3(*command, chdir: ROOT)
      @pid = @thread.pid
      @stdout_lines = []
      @init_response = nil
    end

    def call(phase, **payload)
      @stdin.puts(JSON.generate({"phase" => phase}.merge(payload.transform_keys(&:to_s))))
      @stdin.flush
      line = @stdout.gets
      raise "runner closed its stdout during #{phase}: #{stderr_tail}" if line.nil?

      response = JSON.parse(line, max_nesting: 512)
      @stdout_lines << line.chomp unless phase == "finish"
      unless response["ok"] == true
        raise "runner #{phase} failed: #{response["error"]} #{Array(response["backtrace"]).first(3).join(" | ")}"
      end

      @init_response = response if phase == "init"
      response
    end

    def finish
      document = call("finish")
      @stdin.close
      @thread.join(30)
      document
    end

    def runner_identity
      @init_response.fetch("runner").fetch("identity")
    end

    def runner_digest
      @init_response.fetch("runner").fetch("digest")
    end

    def stderr_tail
      @stderr.read_nonblock(65_536, exception: false).to_s
    rescue IOError
      ""
    end

    def close
      begin
        @stdin.close
      rescue StandardError
        nil
      end
      if @thread.alive?
        begin
          Process.kill("TERM", @pid)
        rescue StandardError
          nil
        end
        @thread.join(5) || begin
          Process.kill("KILL", @pid)
        rescue StandardError
          nil
        end
      end
      begin
        @stdout.close
      rescue StandardError
        nil
      end
      begin
        @stderr.close
      rescue StandardError
        nil
      end
    end
  end

  # AutoBackend's external connection observer, backed by the runner's
  # persistent client connections in the client namespace.
  class RunnerConnectionProbe
    def initialize(session)
      @session = session
      @measurements = []
    end

    attr_reader :measurements

    def external?
      true
    end

    def runner_identity
      @session.runner_identity
    end

    def runner_digest
      @session.runner_digest
    end

    def before_switch(from_backend:, to_backend:)
      response = @session.call("connections_open", count: SWITCH_CONNECTIONS, service: "clusterip-tcp",
                                                   backend: from_backend.name, target: to_backend.name)
      observation = {"connection_ids" => response.fetch("connection_ids"), "connections" => response.fetch("connections"),
                     "backend" => response["backend"], "observed_at" => response["observed_at"]}
      observation.merge("raw_observation_digest" => Rubernetes::Proxy::BackendParity.canonical_trace_digest(observation))
    end

    def after_switch(from_backend:, to_backend:)
      response = @session.call("connections_check", backend: to_backend.name, from: from_backend.name)
      observation = {"connection_ids" => response.fetch("connection_ids"), "checks" => response.fetch("checks"),
                     "alive_count" => response.fetch("alive_count"), "backend" => response["backend"],
                     "observed_at" => response["observed_at"]}
      observation.merge("raw_observation_digest" => Rubernetes::Proxy::BackendParity.canonical_trace_digest(observation))
    end

    def measure_switch(from_backend:, to_backend:, before:, after:, started_at:, switched_at:)
      response = @session.call("measure", from_backend: from_backend, to_backend: to_backend)
      raw = response.fetch("raw_observation")
      result = {
        "active_connections" => response.fetch("active_connections"),
        "lost_connections" => response.fetch("lost_connections"),
        "runner_identity" => response.fetch("runner_identity"),
        "runner_digest" => response.fetch("runner_digest"),
        "raw_observation" => raw,
        "raw_observation_digest" => Rubernetes::Proxy::BackendParity.canonical_trace_digest(raw),
        "connection_ids" => response.fetch("connection_ids"),
        "before" => before, "after" => after, "started_at" => started_at, "switched_at" => switched_at
      }
      @measurements << result
      result
    end
  end

  module_function

  def runner_command
    key = RUNNER_ENV_KEYS.find { |candidate| ENV.key?(candidate) && !ENV.fetch(candidate).strip.empty? }
    key ? Shellwords.split(ENV.fetch(key)) : DEFAULT_RUNNER
  end

  def run(errors)
    setns = Rubernetes::Platform::Linux::Setns.new
    host_netns_inode = File.stat("/proc/self/ns/net").ino
    # Everything below (veths, TC, nftables, sysctls) lives in a private
    # namespace; the host namespace is never touched.
    setns.unshare(flags: Rubernetes::Platform::Linux::Setns::CLONE_NEWNET, resource_id: "m4:proxy:netns")
    node_netns_inode = File.stat("/proc/self/ns/net").ino
    raise "unshare(CLONE_NEWNET) did not produce a private network namespace" if node_netns_inode == host_netns_inode

    netlink = Rubernetes::Network::Netlink.new
    netlink.link_set(name: "lo", up: true)
    keepers = {}
    leases = {}
    dns_server = nil
    proxy = nil
    session = nil
    ebpf_adapter = nil
    nft_adapter = nil
    report = nil
    begin
      %w[client backend].each do |role|
        keepers[role] = spawn_namespace_keeper
        leases[role] = File.open("/proc/#{keepers.fetch(role)}/ns/net", File::RDONLY)
      end
      build_topology(netlink, leases)
      objects = Corpus.objects
      dns_server = start_dns_server(objects)

      kernel_waiver = ENV.fetch("RUBERNETES_M4_KERNEL_WAIVER_REASON", nil)
      ebpf_adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(
        interface: [TOPOLOGY.dig("node_interfaces", "client"), TOPOLOGY.dig("node_interfaces", "backend")],
        complete_semantics: true, kernel_waiver: kernel_waiver
      )
      nft_adapter = Rubernetes::Proxy::NftablesNetlinkAdapter.new(table_name: "rubernetes")
      ebpf_backend = Rubernetes::Proxy::EBPFBackend.new(syscall_adapter: ebpf_adapter)
      nft_backend = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: nft_adapter)

      session = RunnerSession.new(runner_command)
      # The external runner identity authorizes the connection-loss probe, so
      # the session is initialized before the AutoBackend attaches (its first
      # switch already measures connections through the runner).
      init = session.call("init", topology: TOPOLOGY, objects: objects, cases: Corpus.cases,
                                  namespaces: {"node" => "/proc/#{Process.pid}/ns/net",
                                               "client" => "/proc/#{keepers.fetch("client")}/ns/net",
                                               "backend" => "/proc/#{keepers.fetch("backend")}/ns/net"},
                                  probe_pid: Process.pid)
      connection_probe = RunnerConnectionProbe.new(session)
      node_status = NodeStatusRecorder.new
      auto = Rubernetes::Proxy::AutoBackend.new(ebpf: ebpf_backend, nftables: nft_backend, node_status: node_status,
                                                connection_probe: connection_probe)
      verifier_probe = ebpf_backend.last_verifier_probe
      unless verifier_probe.is_a?(Hash) && verifier_probe["accepted"] == true
        errors << "eBPF verifier probe did not accept the Service datapath: #{verifier_probe.inspect[0,
                                                                                                     400]}"
      end
      errors << "AutoBackend did not select eBPF after a successful verifier probe" unless auto.selected_backend == "ebpf"

      proxy = Rubernetes::Proxy::Proxy.new(backend: auto, local_node: Corpus::NODE_NAME,
                                           node_addresses: TOPOLOGY.fetch("node_addresses") + TOPOLOGY.fetch("node_port_addresses").values)
      objects.fetch("services").each { |service| proxy.apply_service(service) }
      objects.fetch("endpoint_slices").each { |slice| proxy.apply_endpoint_slice(slice) }
      proxy.start_health_check_responder(bind_address: "0.0.0.0")
      proxy.attach_backend
      raise "AutoBackend attach did not reach the ready state" unless auto.ready?

      # Sequence: the auto-selected eBPF datapath serves the corpus, the
      # production switch moves live connections to nftables (measured), the
      # nftables datapath serves the corpus, the switch back to eBPF is
      # measured, and the re-attached eBPF program serves the corpus again so
      # the evidence is bound to the program that is live at report time.
      phases = []
      phases << run_corpus_phase(session, "ebpf", ebpf_adapter, nft_adapter, ebpf_backend, nft_backend, errors)
      first_switch = proxy.switch_backend("nftables", reason: "m4 parity: measure eBPF -> nftables connection survival")
      phases << run_corpus_phase(session, "nftables", ebpf_adapter, nft_adapter, ebpf_backend, nft_backend, errors)
      second_switch = proxy.switch_backend("ebpf", reason: "m4 parity: measure nftables -> eBPF connection survival")
      phases << run_corpus_phase(session, "ebpf", ebpf_adapter, nft_adapter, ebpf_backend, nft_backend, errors)
      final = session.finish
      raise "runner did not return a finish document" unless final.is_a?(Hash) && final["ok"] == true

      # Both adapters must hold a live kernel readback while their packet
      # proof is bound; nftables was detached by the switch back to eBPF, so
      # it is re-attached (TC ingress runs first, so the eBPF datapath keeps
      # serving) purely to expose its identity for the report.
      nft_backend.attach unless nft_backend.ready?
      report = build_report(final, phases, [first_switch, second_switch], connection_probe, session, init,
                            ebpf_adapter, nft_adapter, ebpf_backend, nft_backend, auto, node_status, verifier_probe,
                            dns_server, node_netns_inode, errors)
    ensure
      session&.close
      begin
        proxy&.stop_health_check_responder
        proxy&.backend&.detach
      rescue StandardError => error
        errors << "proxy detach failed: #{error.class}: #{error.message}"
      end
      begin
        ebpf_adapter&.detach
        nft_adapter&.detach
      rescue StandardError => error
        errors << "adapter cleanup failed: #{error.class}: #{error.message}"
      end
      dns_server&.stop
      leases.each_value do |lease|
        lease.close
      rescue StandardError
        nil
      end
      keepers.each_value { |pid| terminate(pid) }
    end
    report
  rescue StandardError => error
    errors << "proxy kernel parity probe failed: #{error.class}: #{error.message} @ #{Array(error.backtrace).first(4).join(" | ")}"
    {"measurement_source" => "kernel_blocked", "backends" => [], "parity" => {}, "backend_readback" => {},
     "connection_loss_count" => 0, "connection_loss_measured" => false, "difference_count" => 1}
  end

  class NodeStatusRecorder
    attr_reader :records

    def initialize
      @records = []
    end

    def record_proxy_backend(document)
      @records << document
    end
  end

  # --- topology ---------------------------------------------------------

  def spawn_namespace_keeper
    pid = Process.spawn("unshare", "-n", "--", "sleep", "600", out: File::NULL, err: File::NULL)
    path = "/proc/#{pid}/ns/net"
    own = File.stat("/proc/self/ns/net").ino
    200.times do
      return pid if File.exist?(path) && File.stat(path).ino != own
      raise "namespace keeper exited" if Process.waitpid(pid, Process::WNOHANG)

      sleep(0.01)
    end
    terminate(pid)
    raise "unshare did not produce a child network namespace"
  end

  def terminate(pid)
    Process.kill("TERM", pid)
    Process.wait(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def build_topology(netlink, leases)
    client = TOPOLOGY.fetch("client")
    backend = TOPOLOGY.fetch("backend")
    pod = TOPOLOGY.fetch("pod_interface")
    node_client = TOPOLOGY.dig("node_interfaces", "client")
    node_backend = TOPOLOGY.dig("node_interfaces", "backend")
    netlink.link_add(name: node_client, kind: "veth", peer: pod, up: false, namespace_fd: leases.fetch("client"))
    netlink.link_add(name: node_backend, kind: "veth", peer: pod, up: false, namespace_fd: leases.fetch("backend"))
    netlink.link_set(name: node_client, up: true)
    netlink.link_set(name: node_backend, up: true)
    netlink.address_add(address: "#{client.fetch("gateway_ipv4")}/#{client.fetch("ipv4_prefix")}", name: node_client)
    netlink.address_add(address: "#{client.fetch("gateway_ipv6")}/#{client.fetch("ipv6_prefix")}", name: node_client,
                        ifa_flags: IFA_F_NODAD)
    netlink.address_add(address: "#{backend.fetch("gateway_ipv4")}/#{backend.fetch("ipv4_prefix")}", name: node_backend)
    netlink.address_add(address: "#{backend.fetch("gateway_ipv6")}/#{backend.fetch("ipv6_prefix")}", name: node_backend,
                        ifa_flags: IFA_F_NODAD)

    client_fd = leases.fetch("client")
    netlink.link_set(name: "lo", up: true, namespace_fd: client_fd)
    netlink.link_set(name: pod, up: true, namespace_fd: client_fd)
    netlink.address_add(address: "#{client.fetch("ipv4")}/#{client.fetch("ipv4_prefix")}", name: pod, namespace_fd: client_fd)
    netlink.address_add(address: "#{client.fetch("ipv6")}/#{client.fetch("ipv6_prefix")}", name: pod, namespace_fd: client_fd,
                        ifa_flags: IFA_F_NODAD)
    TOPOLOGY.dig("routes", "client").each do |destination|
      via = destination.include?(":") ? client.fetch("gateway_ipv6") : client.fetch("gateway_ipv4")
      netlink.route_add(destination: destination, via: via, dev: pod, family: destination.include?(":") ? "ipv6" : "ipv4",
                        namespace_fd: client_fd)
    end

    backend_fd = leases.fetch("backend")
    netlink.link_set(name: "lo", up: true, namespace_fd: backend_fd)
    netlink.link_set(name: pod, up: true, namespace_fd: backend_fd)
    backend.fetch("ipv4").each do |ip|
      netlink.address_add(address: "#{ip}/#{backend.fetch("ipv4_prefix")}", name: pod, namespace_fd: backend_fd)
    end
    backend.fetch("ipv6").each do |ip|
      netlink.address_add(address: "#{ip}/#{backend.fetch("ipv6_prefix")}", name: pod, namespace_fd: backend_fd, ifa_flags: IFA_F_NODAD)
    end
    TOPOLOGY.dig("routes", "backend").each do |destination|
      via = destination.include?(":") ? backend.fetch("gateway_ipv6") : backend.fetch("gateway_ipv4")
      netlink.route_add(destination: destination, via: via, dev: pod, family: destination.include?(":") ? "ipv6" : "ipv4",
                        namespace_fd: backend_fd)
    end

    {"net/ipv4/ip_forward" => "1", "net/ipv6/conf/all/forwarding" => "1", "net/ipv4/conf/all/rp_filter" => "0",
     "net/ipv4/conf/default/rp_filter" => "0", "net/ipv4/conf/#{node_client}/rp_filter" => "0",
     "net/ipv4/conf/#{node_backend}/rp_filter" => "0"}.each do |key, value|
      File.write("/proc/sys/#{key}", "#{value}\n")
    end
    wait_for_ipv6(client.fetch("gateway_ipv6"), client.fetch("ipv6"))
  end

  # IPv6 needs neighbour discovery on the fresh veths; poll until the
  # client address answers so the first corpus case does not race it.
  def wait_for_ipv6(_source, target)
    30.times do
      _output, _error, status = Open3.capture3("ping", "-6", "-c", "1", "-W", "1", target)
      return true if status.success?

      sleep(0.1)
    end
    raise "IPv6 path to #{target} did not come up"
  end

  def start_dns_server(objects)
    resolver = Rubernetes::Network::DNS::Resolver.new(domain: Corpus::CLUSTER_DOMAIN, cluster_ip: TOPOLOGY.dig("dns", "address"))
    objects.fetch("services").each { |service| resolver.add_service(service) }
    objects.fetch("endpoint_slices").each { |slice| resolver.add_endpoint_slice(slice) }
    server = Rubernetes::Network::DNS::Server.new(resolver: resolver, bind_addresses: [TOPOLOGY.dig("dns", "address")],
                                                  port: TOPOLOGY.dig("dns", "port"))
    server.start
    server
  end

  # --- phases -----------------------------------------------------------

  def run_corpus_phase(session, backend_name, ebpf_adapter, nft_adapter, ebpf_backend, nft_backend, errors)
    kernel = if backend_name == "ebpf"
               ebpf_kernel_input(ebpf_adapter, ebpf_backend)
             else
               nftables_kernel_input(nft_adapter, nft_backend)
             end
    response = session.call("corpus", backend: backend_name, kernel: kernel)
    if (debug_dir = ENV.fetch("RUBERNETES_M4_PROXY_DEBUG_DIR", nil)) && !debug_dir.empty?
      FileUtils.mkdir_p(debug_dir)
      File.binwrite(File.join(debug_dir, "corpus-#{backend_name}-#{Time.now.utc.strftime("%H%M%S%6N")}.json"), JSON.generate(response))
    end
    unless response["passed"] == true
      failed = Array(response["cases"]).reject { |entry| entry["passed"] == true }
      detail = failed.first(2).map do |entry|
        actual = entry["actual"].is_a?(Hash) ? entry["actual"] : {}
        observation = entry["observation"].is_a?(Hash) ? entry["observation"] : {}
        "#{entry["id"]}: #{(actual["error"] || observation["error"] || actual.to_json).to_s[0, 300]}"
      end
      readback = response["readback"].is_a?(Hash) ? response["readback"] : {}
      readback_detail = readback.reject { |key, _| %w[tools rules maps program filters].include?(key) }.to_json[0, 600]
      errors << "#{backend_name} packet corpus failed: #{Array(response["failed_cases"]).join(", ")}; readback=#{readback["readback"]}; first failures: #{detail.join(" | ")}; readback detail: #{readback_detail}"
    end
    {"backend" => backend_name, "kernel_input" => kernel, "response" => response}
  end

  def ebpf_kernel_input(adapter, backend)
    program = adapter.program
    raise "eBPF adapter has no loaded program" unless program

    service_keys = backend.rules.flat_map do |rule|
      adapter.send(:service_rule_families, rule).map do |family|
        key, = adapter.send(:encode_service_rule_for_family, rule, family)
        {"rule_key" => rule.key, "family" => family, "key_hex" => key.unpack1("H*")}
      end
    end
    {
      "program_id" => program.id, "program_tag" => program.tag,
      "map_ids" => adapter.maps.transform_values(&:id),
      "interfaces" => adapter.links.map { |link| link.fetch(:ifindex) }.uniq.map { |ifindex| interface_name(ifindex) },
      "verifier_log_sha256" => program.verifier_log_sha256,
      "service_keys" => service_keys
    }
  end

  def nftables_kernel_input(adapter, backend)
    bindings = backend.rules.map do |rule|
      endpoints = adapter.send(:endpoints_for, rule)
      families = adapter.send(:endpoint_families, rule, endpoints)
      {"rule_key" => rule.key, "chain" => adapter.send(:service_chain_name, rule),
       "sets" => families.map { |family| adapter.send(:endpoint_set_name, rule, family) }}
    end
    {"table" => adapter.table_name, "chain_bindings" => bindings}
  end

  def interface_name(ifindex)
    Socket.getifaddrs.find { |entry| entry.ifindex == ifindex }&.name || raise("no interface with ifindex #{ifindex}")
  end

  # --- report -----------------------------------------------------------

  def build_report(final, phases, switches, connection_probe, session, init, ebpf_adapter, nft_adapter,
                   ebpf_backend, nft_backend, auto, node_status, verifier_probe, dns_server, node_netns_inode, errors)
    runner = final.fetch("runner")
    packet_capture = final.fetch("packetCapture")
    ebpf_phase = phases.reverse.find { |phase| phase["backend"] == "ebpf" }
    nft_phase = phases.find { |phase| phase["backend"] == "nftables" }
    ebpf_cases = ebpf_phase.fetch("response").fetch("cases")
    nft_cases = nft_phase.fetch("response").fetch("cases")
    ebpf_readback = ebpf_phase.fetch("response").fetch("readback")
    nft_readback = nft_phase.fetch("response").fetch("readback")
    case_ids = Corpus.case_ids
    matrix = case_ids.to_h do |id|
      [id, [ebpf_cases, nft_cases].all? do |cases|
        cases.find do |entry|
          entry["id"] == id
        end&.fetch("passed") == true
      end]
    end

    # Packet-semantics proof for each production adapter, bound to the
    # runner's provenance and the adapter's own kernel readback.
    nft_rules = nft_adapter.last_readback.fetch("rules")
    nft_adapter.verify_packet_semantics!(evidence: {
                                           "executed" => true, "measurementSource" => final.fetch("measurementSource"),
                                           "packetTraceSha256" => final.fetch("packetTraceSha256"), "packetCount" => packet_capture.fetch("packetCount"),
                                           "caseInventorySha256" => Corpus.digest(Corpus.cases),
                                           "runner" => runner, "packetCapture" => packet_capture,
                                           "kernel" => {"table" => {"name" => nft_adapter.table_name}, "rules" => nft_rules,
                                                        "rulesDigest" => nft_adapter.send(:canonical_digest, nft_rules)}
                                         })
    ebpf_adapter.verify_packet_semantics!(evidence: {
                                            readback: true, forward_dnat: true, reverse_snat: true, checksum_recompute: true, matrix: matrix,
                                            measurement_source: final.fetch("measurementSource"), packet_trace_sha256: final.fetch("packetTraceSha256"),
                                            packet_count: packet_capture.fetch("packetCount"),
                                            kernel: {"release" => ebpf_adapter.actual_kernel_release, "program_id" => ebpf_readback.dig("program", "id"),
                                                     "filter_program_ids" => ebpf_readback.fetch("filter_program_ids"),
                                                     "helper_ids" => ebpf_adapter.program.helper_ids,
                                                     "requested_helper_ids" => ebpf_adapter.program.requested_helper_ids},
                                            runner: runner
                                          })

    left_digest = ebpf_backend.digest
    right_digest = nft_backend.digest
    left_rules = ebpf_backend.semantic_snapshot
    right_rules = nft_backend.semantic_snapshot
    errors << "eBPF and nftables backends compiled different rule snapshots" unless left_rules == right_rules

    execution_identity = {"runnerIdentity" => final.fetch("runnerIdentity"), "runnerDigest" => final.fetch("runnerDigest"),
                          "mode" => final.fetch("mode")}
    input_binding = {"leftDigest" => left_digest, "rightDigest" => right_digest, "corpusSha256" => Corpus.corpus_sha256}
    cases = case_ids.map do |id|
      ebpf_case = ebpf_cases.find { |entry| entry["id"] == id }
      nft_case = nft_cases.find { |entry| entry["id"] == id }
      expected = {"ebpf" => ebpf_case.fetch("expected"), "nftables" => nft_case.fetch("expected")}
      actual = {"ebpf" => ebpf_case.fetch("actual"), "nftables" => nft_case.fetch("actual")}
      {"id" => id, "case" => id, "expected" => expected, "actual" => actual,
       "expectedSha256" => M4ProbeSupport.digest(expected), "actualSha256" => M4ProbeSupport.digest(actual),
       "passed" => ebpf_case["passed"] == true && nft_case["passed"] == true && M4ProbeSupport.digest(expected) == M4ProbeSupport.digest(actual),
       "packetTraceSha256" => final.fetch("packetTraceSha256"), "kind" => ebpf_case["kind"], "service" => ebpf_case["service"]}
    end
    inventory = Corpus.cases
    packet_corpus = {
      "executed" => true, "measurementSource" => final.fetch("measurementSource"),
      "runnerIdentity" => final.fetch("runnerIdentity"), "runnerDigest" => final.fetch("runnerDigest"), "mode" => final.fetch("mode"),
      "runner" => runner, "executionIdentity" => execution_identity,
      "executionIdentitySha256" => M4ProbeSupport.digest(execution_identity),
      "inputBinding" => input_binding, "inputBindingSha256" => M4ProbeSupport.digest(input_binding),
      "rawPacketTrace" => final.fetch("rawPacketTrace"), "packetTraceSha256" => final.fetch("packetTraceSha256"),
      "packetCapture" => packet_capture,
      "cases" => cases, "caseInventory" => inventory, "caseInventorySha256" => M4ProbeSupport.digest(inventory)
    }
    ebpf_identity = ebpf_adapter.kernel_identity
    nft_identity = nft_adapter.kernel_identity
    unless ebpf_identity.is_a?(Hash)
      errors << "eBPF adapter did not expose a kernel identity after packet proof: #{ebpf_adapter.production_capability_error}"
    end
    unless nft_identity.is_a?(Hash)
      errors << "nftables adapter did not expose a kernel identity after packet proof: #{nft_adapter.production_capability_error}"
    end
    ebpf_entry = {
      "readback" => ebpf_readback.fetch("readback"), "rules" => left_rules, "rulesDigest" => M4ProbeSupport.digest(left_rules),
      "identity" => ebpf_identity || {}, "identityDigest" => M4ProbeSupport.digest(ebpf_identity || {}),
      "inputDigest" => left_digest, "rulesModelDigest" => left_digest,
      "program" => ebpf_readback.fetch("program"), "maps" => ebpf_readback.fetch("maps"), "filters" => ebpf_readback.fetch("filters"),
      "serviceRuleBindings" => ebpf_readback.fetch("service_rule_bindings"), "tools" => ebpf_readback["tools"],
      "verifierLogSha256" => ebpf_adapter.program.verifier_log_sha256, "verifierLog" => ebpf_adapter.program.verifier_log,
      "sctpCrc32c" => ebpf_adapter.sctp_crc32c_status
    }
    nft_entry = {
      "readback" => nft_readback.fetch("readback"), "rules" => right_rules, "rulesDigest" => M4ProbeSupport.digest(right_rules),
      "identity" => nft_identity || {}, "identityDigest" => M4ProbeSupport.digest(nft_identity || {}),
      "inputDigest" => right_digest, "rulesModelDigest" => right_digest,
      "table" => {"name" => nft_readback.fetch("table"), "family" => nft_readback.fetch("family")},
      "chains" => nft_readback.fetch("chains"), "sets" => nft_readback.fetch("sets"),
      "chainBindings" => nft_readback.fetch("chain_bindings"), "rulesetSha256" => nft_readback.fetch("ruleset_text_sha256"),
      "ruleCount" => nft_readback.fetch("rule_count"), "tools" => nft_readback["tools"]
    }
    kernel_readback = {
      "executed" => true, "measurementSource" => final.fetch("measurementSource"),
      "runnerIdentity" => final.fetch("runnerIdentity"), "runnerDigest" => final.fetch("runnerDigest"), "mode" => final.fetch("mode"),
      "runner" => runner, "executionIdentity" => execution_identity,
      "executionIdentitySha256" => M4ProbeSupport.digest(execution_identity),
      "inputBinding" => input_binding, "inputBindingSha256" => M4ProbeSupport.digest(input_binding),
      "packetTraceSha256" => final.fetch("packetTraceSha256"), "caseInventorySha256" => M4ProbeSupport.digest(inventory),
      "ebpf" => ebpf_entry, "nftables" => nft_entry
    }
    parity_result = Rubernetes::Proxy::BackendParity.production_compare(ebpf_backend, nft_backend,
                                                                        packet_corpus: packet_corpus, kernel_readback: kernel_readback)
    unless parity_result["productionVerified"] == true
      errors << "production parity comparison failed: #{Array(parity_result["evidenceErrors"]).join("; ")}"
    end

    switch_documents = switches.each_with_index.map do |measurement, index|
      raw = connection_probe.measurements.fetch(index)
      {"fromBackend" => measurement.from_backend, "toBackend" => measurement.to_backend,
       "selectedBackendBefore" => measurement.from_backend, "selectedBackendAfter" => measurement.to_backend,
       "startedAt" => measurement.started_at, "switchedAt" => measurement.switched_at, "durationMs" => measurement.duration_ms,
       "activeConnections" => measurement.active_connections, "lostConnections" => measurement.lost_connections,
       "measurementSource" => measurement.measurement_source, "runnerIdentity" => measurement.runner_identity,
       "runnerDigest" => measurement.runner_digest, "rawObservation" => raw.fetch("raw_observation"),
       "rawObservationDigest" => raw.fetch("raw_observation_digest"),
       "before" => {"connectionIDs" => raw.fetch("before").fetch(:connection_ids)},
       "after" => {"connectionIDs" => raw.fetch("after").fetch(:connection_ids)},
       "executed" => true, "reason" => measurement.reason}
    end
    connection_loss_count = switch_documents.sum { |entry| entry.fetch("lostConnections") }

    readback_runner = {
      "mode" => "external", "self_comparison" => false,
      "implementation" => "Ruby stdlib sockets in isolated pod namespaces; tcpdump packet capture; bpftool/tc/nft kernel readback",
      "command" => session.command, "process_id" => session.pid, "runner_sha256" => final.fetch("runnerDigest"),
      "started_at" => runner.fetch("startedAt"), "finished_at" => runner.fetch("finishedAt"),
      "start_time_ticks" => runner["start_time_ticks"], "source" => runner.fetch("source"), "tools" => final["tools"]
    }
    parity_observable = {"ebpf" => cases.map { |entry| {"id" => entry["id"], "actual" => entry.fetch("actual").fetch("ebpf")} },
                         "nftables" => cases.map { |entry| {"id" => entry["id"], "actual" => entry.fetch("actual").fetch("nftables")} }}
    expected_observable = {"ebpf" => cases.map { |entry| {"id" => entry["id"], "actual" => entry.fetch("expected").fetch("ebpf")} },
                           "nftables" => cases.map { |entry| {"id" => entry["id"], "actual" => entry.fetch("expected").fetch("nftables")} }}
    backend_readback = {
      "executed" => true, "runner_sha256" => final.fetch("runnerDigest"), "runner" => readback_runner,
      "ebpf" => {"verified" => ebpf_adapter.production_capable?, "readback" => ebpf_readback.fetch("readback"),
                 "program_id" => ebpf_readback.dig("program", "id"), "program_tag" => ebpf_readback.dig("program", "tag"),
                 "map_id" => ebpf_adapter.maps.fetch("service_rules").id, "map_ids" => ebpf_adapter.maps.transform_values(&:id),
                 "verifier_log_sha256" => ebpf_adapter.program.verifier_log_sha256, "verifier_log" => ebpf_adapter.program.verifier_log,
                 "rules" => left_rules, "filters" => ebpf_readback.fetch("filters"),
                 "service_rule_bindings" => ebpf_readback.fetch("service_rule_bindings"),
                 "sctp_crc32c" => ebpf_adapter.sctp_crc32c_status, "verifier_probe" => verifier_probe},
      "nftables" => {"readback" => nft_readback.fetch("readback"), "family" => nft_readback.fetch("family"),
                     "table" => nft_readback.fetch("table"), "rules" => right_rules,
                     "ruleset_sha256" => nft_readback.fetch("ruleset_text_sha256"), "rule_count" => nft_readback.fetch("rule_count"),
                     "chains" => nft_readback.fetch("chains").map { |chain| chain["name"] },
                     "sets" => nft_readback.fetch("sets").map { |set| set["name"] }},
      "parity" => {"expected_observable" => expected_observable, "actual_observable" => parity_observable,
                   "expected_sha256" => M4ProbeSupport.digest(expected_observable),
                   "actual_sha256" => M4ProbeSupport.digest(parity_observable),
                   "passed" => M4ProbeSupport.digest(expected_observable) == M4ProbeSupport.digest(parity_observable)},
      "connectionSwitch" => switch_documents.first,
      "connectionSwitches" => switch_documents,
      "packetCapture" => packet_capture,
      "namespaces" => final["namespaces"].merge("node_inode" => node_netns_inode),
      "dns" => {"endpoints" => dns_server.endpoints, "counters" => dns_server.counters}
    }
    waivers = []
    waivers << ebpf_adapter.kernel_waiver if ebpf_adapter.sctp_crc32c_waived?
    backends = %w[ebpf nftables].map do |id|
      phase_cases = id == "ebpf" ? ebpf_cases : nft_cases
      {"id" => id, "backend" => id, "passed" => phase_cases.all? { |entry| entry["passed"] == true }, "attempt_count" => 1,
       "measurement_source" => "production_module",
       "packet_trace_sha256" => final.fetch("packetTraceSha256"), "packet_capture_sha256" => packet_capture.fetch("sha256"),
       "case_results" => phase_cases.map do |entry|
         entry.slice("id", "passed", "kind", "service", "family", "protocol", "expected", "actual")
       end,
       "kernel_readback" => id == "ebpf" ? ebpf_entry : nft_entry,
       "rule_digest" => id == "ebpf" ? left_digest : right_digest}
    end
    {
      "measurement_source" => "production_module",
      "adapter_classes" => %w[Rubernetes::Proxy::Proxy Rubernetes::Proxy::AutoBackend Rubernetes::Proxy::EBPFBackend
                              Rubernetes::Proxy::NftablesBackend Rubernetes::Proxy::LinuxEBPFAdapter
                              Rubernetes::Proxy::NftablesNetlinkAdapter],
      "backends" => backends,
      "parity" => {"passed" => parity_result["productionVerified"] == true,
                   "observable_semantics_equal" => parity_result["observableSemanticsEqual"] == true,
                   "comparison_sha256" => M4ProbeSupport.digest(parity_result), "left_digest" => left_digest,
                   "right_digest" => right_digest, "left_rules" => left_rules, "right_rules" => right_rules,
                   "production_capable" => parity_result["productionCapable"] == true,
                   "production_verified" => parity_result["productionVerified"] == true,
                   "measurement_source" => parity_result["measurementSource"],
                   "evidence_errors" => parity_result["evidenceErrors"],
                   "external_observable" => {"packetCorpus" => packet_corpus, "kernelReadback" => kernel_readback}},
      "backend_readback" => backend_readback,
      "auto_backend" => {"selected" => auto.selected_backend, "status" => auto.status.to_h, "node_status_records" => node_status.records,
                         "verifier_probe" => verifier_probe},
      "kernel_waivers" => waivers,
      "waivers" => waivers,
      "sctp_crc32c" => ebpf_adapter.sctp_crc32c_status,
      "connection_loss_count" => connection_loss_count,
      "connection_loss_measured" => true,
      "connection_switches" => switch_documents,
      "difference_count" => cases.count { |entry| entry["passed"] != true },
      "corpus_sha256" => Corpus.corpus_sha256,
      "runner_init" => init.slice("runner", "agents", "capture")
    }
  end
end

if $PROGRAM_NAME == __FILE__
  M4ProbeSupport.run_report(kind: "m4_proxy_backend_parity", adapter_name: "proxy-backend-parity-probe") do |_input, errors|
    M4ProxyKernelProbe.run(errors)
  end
end
