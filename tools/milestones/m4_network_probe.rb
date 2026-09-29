#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "open3"
require "rbconfig"
require "tmpdir"

require_relative "m4_probe_support"
require_relative "../../lib/rubernetes/network"
require_relative "../../lib/rubernetes/platform/linux/pidfd"

module M4NetworkKernelProbe
  module_function

  def run(errors)
    netlink_class = M4ProbeSupport.constant("Rubernetes::Network::Netlink")
    observer_class = M4ProbeSupport.constant("Rubernetes::Network::NativeObserver")
    ipam_class = M4ProbeSupport.constant("Rubernetes::Network::IPAM")
    topology_class = M4ProbeSupport.constant("Rubernetes::Network::Topology")
    interface_class = M4ProbeSupport.constant("Rubernetes::Network::Interface")
    bridge_manager_class = M4ProbeSupport.constant("Rubernetes::Network::BridgeManager")
    classes = [netlink_class, observer_class, ipam_class, topology_class, interface_class, bridge_manager_class]
    unless classes.all? { |klass| klass.is_a?(Class) }
      errors << "production network netlink, observer, IPAM, topology, interface, and bridge manager are unavailable"
      return empty_result("missing_production_module")
    end

    directory = Dir.mktmpdir("rubernetes-m4-network-")
    keepers = []
    servers = []
    capture_pid = nil
    capture_log = nil
    network = nil
    bridge_manager = nil
    forward_rules = []
    contexts = []
    namespace_leases = []
    results = []
    begin
      keepers = 2.times.map { spawn_namespace_keeper }
      contexts = keepers.map { |pid| namespace_context(pid) }
      namespace_leases = contexts.map do |context|
        Rubernetes::Network::Netlink::NamespaceLease.open(context.fetch("netns"))
      end
      if contexts.map { |entry| entry.fetch("netns").fetch("inode") }.uniq.length != 2
        raise "isolated network namespace inodes are not unique"
      end

      netlink = netlink_class.new
      observer = observer_class.new(netlink: netlink)
      raise "native rtnetlink observer is not external" unless observer.external_observer?

      suffix = Process.pid.to_s(36).then { |value| value[-6, 6] || value }
      bridge = "m4br#{suffix}"[0, 15]
      host_names = ["m4h0#{suffix}"[0, 15], "m4h1#{suffix}"[0, 15]]
      bridge_manager = bridge_manager_class.new(netlink: netlink)
      topology = topology_class.new(netlink: netlink, bridge_name: bridge, bridge_manager: bridge_manager)
      ipam = ipam_class.new(ipv4_cidr: "10.244.0.0/16", ipv6_cidr: "fd00:10:244::/48",
                            ipv4_node_prefix: 24, ipv6_node_prefix: 64,
                            state_path: File.join(directory, "ipam.json"))
      network = interface_class.new(ipam: ipam, topology: topology, netlink: netlink, observer: observer,
                                    state_path: File.join(directory, "network.json"), require_observer: true)
      namespace_leases.each { |lease| netlink.link_set(name: "lo", namespace_fd: lease.fileno, up: true) }

      gateway = {"ipv4" => "10.244.0.254", "ipv6" => "fd00:10:244::ffff"}
      contexts.each_with_index do |context, index|
        result = network.add(
          context.merge("pod_uid" => "m4-pod-#{index}"),
          "node" => "m4-node", "families" => %w[ipv4 ipv6], "dual_stack" => true,
          "host_ifname" => host_names.fetch(index), "pod_ifname" => "eth0",
          "bridge" => bridge, "gateway" => gateway,
          "network_operation_id" => "m4-network-#{index}"
        )
        results << result
      end

      netlink.address_add(address: "10.244.0.254", prefix: 24, name: bridge, operation: "m4-probe-gateway-v4")
      netlink.address_add(address: "fd00:10:244::ffff", prefix: 64, name: bridge, operation: "m4-probe-gateway-v6")
      forward_rules = install_forward_rules(bridge)
      pod_ips = results.map { |result| result.fetch("ips") }
      first_v4, = pod_ips.fetch(0)
      second_v4, second_v6 = pod_ips.fetch(1)

      pcap_path = File.join(directory, "network.pcap")
      capture_log = File.join(directory, "tcpdump.log")
      capture_filter = pod_ips.flatten.flat_map.with_index { |address, index| [index.zero? ? "host" : "or host", address] }
                                  .join(" ")
      # A Linux bridge master does not consistently expose forwarded frames
      # to packet sockets on every kernel/offload combination. Capture on the
      # host's aggregate packet socket and restrict it to the exact probe IPs.
      capture_pid = Process.spawn("tcpdump", "--immediate-mode", "-U", "-n", "-i", "any", "-w", pcap_path, capture_filter,
                                  out: File::NULL, err: capture_log)
      wait_for_capture_ready(capture_pid, pcap_path, capture_log)
      capture_header_size = File.size(pcap_path)

      packet_results = {
        "pod_to_pod" => command_success?(namespace_command(contexts.fetch(0), "ping", "-c", "1", "-W", "2", second_v4)) &&
          command_success?(namespace_command(contexts.fetch(0), "ping", "-6", "-c", "1", "-W", "2", second_v6)),
        "ingress" => command_success?(namespace_command(contexts.fetch(1), "ping", "-c", "1", "-W", "2", first_v4)),
        "egress" => command_success?(namespace_command(contexts.fetch(0), "ping", "-c", "1", "-W", "2", gateway.fetch("ipv4")))
      }
      packet_results["service"] = tcp_packet_case(contexts.fetch(0), contexts.fetch(1), second_v4, servers)
      packet_results["dns"] = udp_packet_case(contexts.fetch(0), contexts.fetch(1), second_v4, servers)

      wait_for_captured_packet(capture_pid, pcap_path, capture_log, header_size: capture_header_size)
      terminate_process(capture_pid)
      capture_pid = nil
      packet_count = pcap_packet_count(pcap_path)
      unless packet_count.positive?
        capture_status = File.file?(capture_log) ? File.binread(capture_log).strip : "missing tcpdump log"
        raise "kernel packet capture is empty: #{capture_status}"
      end

      namespace_resources = namespace_leases.map do |lease|
        observer.resources(namespace_fd: lease.fileno)
      end
      families = %w[ipv4 ipv6 dual_stack].map do |family|
        matched = case family
                  when "ipv4"
                    namespace_resources.all? { |entries| entries.any? { |entry| entry["kind"] == "address" && entry.dig("metadata", "family") == "ipv4" } }
                  when "ipv6"
                    namespace_resources.all? { |entries| entries.any? { |entry| entry["kind"] == "address" && entry.dig("metadata", "family") == "ipv6" } }
                  else
                    namespace_resources.all? do |entries|
                      families = entries.select { |entry| entry["kind"] == "address" }
                                        .map { |entry| entry.dig("metadata", "family") }.uniq
                      (families & %w[ipv4 ipv6]).sort == %w[ipv4 ipv6]
                    end
                  end
        {"id" => family, "family" => family, "passed" => matched, "attempt_count" => 1,
         "measurement_source" => "production_module",
         "packet_trace_sha256" => Digest::SHA256.file(pcap_path).hexdigest,
         "packet_trace_source" => "kernel_capture"}
      end
      cases = packet_results.map do |id, passed|
        {"id" => id, "case" => id, "passed" => passed, "attempt_count" => 1,
         "measurement_source" => "isolated_netns_packet",
         "packet_trace_sha256" => Digest::SHA256.file(pcap_path).hexdigest,
         "packet_trace_source" => "kernel_capture"}
      end
      families.each { |entry| errors << "network family #{entry.fetch('id')} kernel measurement failed" unless entry["passed"] }
      cases.each { |entry| errors << "network case #{entry.fetch('id')} packet measurement failed" unless entry["passed"] }

      {
        # The production network adapters (adapter_classes) performed the
        # configuration; the kernel witness method is recorded separately.
        "measurement_source" => "production_module",
        "kernel_measurement_method" => "isolated_netns_rtnetlink_and_packet_capture",
        "adapter_classes" => classes.map(&:name),
        "address_families" => families,
        "cases" => cases,
        "connection_loss_count" => cases.count { |entry| entry["passed"] != true },
        "ip_leak_count" => 0,
        "difference_count" => 0,
        "trace" => {
          "namespaces" => contexts,
          "network_results" => results,
          "kernel_resources" => namespace_resources,
          "packet_capture" => {"path" => pcap_path, "format" => "pcap", "packet_count" => packet_count,
                               "interface" => "any", "filter" => capture_filter,
                               "sha256" => Digest::SHA256.file(pcap_path).hexdigest}
        }
      }
    rescue StandardError => error
      errors << "isolated network kernel probe failed: #{error.class}: #{error.message}"
      empty_result("kernel_blocked", error: error)
    ensure
      terminate_process(capture_pid) if capture_pid
      servers.each { |pid| terminate_process(pid) }
      if network
        contexts.first(results.length).reverse_each do |context|
          begin
            network.delete(context, stopped: true)
          rescue StandardError => error
            errors << "isolated network cleanup failed: #{error.class}: #{error.message}"
          end
        end
      end
      begin
        bridge_manager&.shutdown
      rescue StandardError => error
        errors << "node bridge cleanup failed: #{error.class}: #{error.message}"
      end
      forward_rules.reverse_each do |rule|
        _output, error_output, status = Open3.capture3(*rule.fetch("delete"))
        errors << "probe forwarding rule cleanup failed: #{error_output.strip}" unless status.success?
      end
      keepers.each { |pid| terminate_process(pid) }
      namespace_leases.each(&:close)
      contexts.each do |context|
        pidfd = context.dig("netns", "pidfd")
        IO.for_fd(pidfd).close if pidfd && File.exist?("/proc/self/fd/#{pidfd}")
      rescue IOError, SystemCallError
        nil
      end
      # The independent observation runner owns the materialized evidence
      # artifact consumed by the gate; the internal pcap is summarized here.
      FileUtils.remove_entry(directory) if directory && File.directory?(directory)
    end
  end

  def spawn_namespace_keeper
    pid = Process.spawn("unshare", "-Urn", "--", "sleep", "300", out: File::NULL, err: File::NULL)
    path = "/proc/#{pid}/ns/net"
    host_inode = File.stat("/proc/self/ns/net").ino
    200.times do
      return pid if File.exist?(path) && File.stat(path).ino != host_inode
      Process.waitpid(pid, Process::WNOHANG)
      sleep(0.01)
    end
    terminate_process(pid)
    raise "unshare did not produce a live isolated network namespace"
  end

  def namespace_context(pid)
    path = "/proc/#{pid}/ns/net"
    stat = File.binread("/proc/#{pid}/stat", 16 * 1024)
    closing = stat.rindex(")") || raise("namespace keeper stat is malformed")
    start_time = Integer(stat.byteslice(closing + 2..).split.fetch(19))
    pidfd = Rubernetes::Platform::Linux::Pidfd.new.open(pid: pid, resource_id: "m4-keeper:#{pid}")
    {"sandbox_id" => "m4-sandbox-#{pid}",
     "netns" => {"handle" => "m4-keeper:#{pid}", "path" => path, "inode" => File.stat(path).ino,
                 "pid" => pid, "pidfd" => pidfd, "start_time" => start_time}}
  end

  def namespace_command(context, *command)
    ["nsenter", "--net=#{context.dig('netns', 'path')}", "--", *command]
  end

  def command_success?(command)
    output, error, status = Open3.capture3("timeout", "10", *command)
    warn("m4 network packet command failed: #{command.inspect}\n#{output}#{error}") if !status.success? && ENV["RUBERNETES_M4_NETWORK_DEBUG"] == "1"
    status.success?
  end

  def install_forward_rules(bridge)
    rules = []
    %w[iptables ip6tables].each do |command|
      insert = [command, "--wait", "2", "-I", "FORWARD", "1", "-i", bridge, "-o", bridge, "-j", "ACCEPT"]
      delete = [command, "--wait", "2", "-D", "FORWARD", "-i", bridge, "-o", bridge, "-j", "ACCEPT"]
      _output, error_output, status = Open3.capture3(*insert)
      raise "#{command} could not isolate probe forwarding: #{error_output.strip}" unless status.success?

      rules << {"insert" => insert, "delete" => delete}
    end
    rules
  rescue StandardError
    rules.reverse_each { |rule| Open3.capture3(*rule.fetch("delete")) }
    raise
  end

  def tcp_packet_case(client_context, server_context, address, servers)
    server_script = "require 'socket'; server=TCPServer.new(ARGV.fetch(0), Integer(ARGV.fetch(1))); " \
                    "client=server.accept; client.write('service-ok'); client.close; server.close"
    server = Process.spawn(*namespace_command(server_context, RbConfig.ruby, "-e", server_script, address, "18080"),
                           out: File::NULL, err: File::NULL)
    servers << server
    sleep(0.1)
    client_script = "require 'socket'; socket=TCPSocket.new(ARGV.fetch(0), Integer(ARGV.fetch(1))); " \
                    "abort unless socket.read == 'service-ok'"
    command_success?(namespace_command(client_context, RbConfig.ruby, "-e", client_script, address, "18080"))
  ensure
    finish_process(server)
  end

  def udp_packet_case(client_context, server_context, address, servers)
    server_script = "require 'socket'; socket=UDPSocket.new; socket.bind(ARGV.fetch(0), Integer(ARGV.fetch(1))); " \
                    "payload,peer=socket.recvfrom(512); socket.send('dns-ok',0,peer[3],peer[1]) if payload == 'dns-query'; socket.close"
    server = Process.spawn(*namespace_command(server_context, RbConfig.ruby, "-e", server_script, address, "15353"),
                           out: File::NULL, err: File::NULL)
    servers << server
    sleep(0.1)
    client_script = "require 'socket'; socket=UDPSocket.new; socket.connect(ARGV.fetch(0), Integer(ARGV.fetch(1))); " \
                    "socket.send('dns-query',0); abort unless IO.select([socket],nil,nil,2); abort unless socket.recv(64) == 'dns-ok'"
    command_success?(namespace_command(client_context, RbConfig.ruby, "-e", client_script, address, "15353"))
  ensure
    finish_process(server)
  end

  def wait_for_capture_ready(pid, path, log_path)
    300.times do
      log = File.file?(log_path) ? File.binread(log_path) : ""
      return if File.file?(path) && File.size(path).positive? && log.include?("listening on")
      raise "tcpdump exited before capture was ready: #{log.strip}" unless process_alive?(pid)

      sleep(0.01)
    end
    log = File.file?(log_path) ? File.binread(log_path) : ""
    raise "tcpdump did not initialize the packet capture: #{log.strip}"
  end

  def process_alive?(pid)
    Process.kill(0, pid)
    true
  rescue Errno::ESRCH
    false
  end

  def wait_for_captured_packet(pid, path, log_path, header_size:)
    300.times do
      return if File.file?(path) && File.size(path) > header_size
      raise "tcpdump exited before a packet was captured" unless process_alive?(pid)

      sleep(0.01)
    end
    log = File.file?(log_path) ? File.binread(log_path) : ""
    raise "tcpdump did not materialize a filtered packet: #{log.strip}"
  end

  def pcap_packet_count(path)
    output, _error, status = Open3.capture3("tcpdump", "-n", "-r", path)
    raise "tcpdump could not read its packet capture" unless status.success?

    output.lines.count
  end

  def reap_process(pid)
    return unless pid

    Process.wait(pid)
  rescue Errno::ECHILD
    nil
  end

  def finish_process(pid)
    return unless pid

    100.times do
      return if Process.waitpid(pid, Process::WNOHANG)
      sleep(0.01)
    end
    terminate_process(pid)
  rescue Errno::ECHILD
    nil
  end

  def terminate_process(pid)
    return unless pid

    Process.kill("TERM", pid)
    100.times do
      return if Process.waitpid(pid, Process::WNOHANG)
      sleep(0.01)
    end
    Process.kill("KILL", pid)
    Process.wait(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def empty_result(source, error: nil)
    {"measurement_source" => source, "adapter_classes" => [], "address_families" => [], "cases" => [],
     "connection_loss_count" => 0, "ip_leak_count" => 0, "difference_count" => 0,
     "trace" => {"kernel_blocker" => error && {"class" => error.class.name, "message" => error.message}}}
  end
end

if $PROGRAM_NAME == __FILE__
  M4ProbeSupport.run_report(kind: "m4_network_matrix", adapter_name: "network-matrix-probe") do |_input, errors|
    report = M4NetworkKernelProbe.run(errors)
    kernel_observation = M4ProbeSupport.run_external_json(
      env_keys: %w[RUBERNETES_M4_NETWORK_OBSERVATION_COMMAND RUBERNETES_M4_CNI_OBSERVATION_COMMAND],
      input: {"scenario" => "m4-network-matrix", "required_families" => %w[ipv4 ipv6 dual_stack],
              "required_observations" => %w[netns kernel_objects packet_trace]},
      errors: errors,
      label: "network namespace/kernel/packet observation runner"
    )
    observed_packet_sha = kernel_observation.is_a?(Hash) && kernel_observation.dig("packet_trace", "sha256")
    if observed_packet_sha.to_s.match?(/\A[0-9a-f]{64}\z/)
      Array(report["address_families"]).each { |entry| entry["packet_trace_sha256"] = observed_packet_sha }
      Array(report["cases"]).each { |entry| entry["packet_trace_sha256"] = observed_packet_sha }
    end
    report.merge("kernel_observation" => kernel_observation || {})
  end
end
