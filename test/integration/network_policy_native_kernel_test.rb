# frozen_string_literal: true

require_relative "../test_helper"
require "ipaddr"
require "json"
require "open3"
require "rbconfig"
require "socket"
require "timeout"

# The outer test always creates its own user/network namespace. The complete
# matrix therefore runs without an opt-in environment variable and cannot
# mutate the caller's network namespace or forwarding sysctls.
class NetworkPolicyNativeKernelTest < Minitest::Test
  class CapabilityBlocker < StandardError
    attr_reader :code

    def initialize(code, message)
      @code = String(code)
      super(String(message))
    end
  end

  # The child is intentionally self-contained: it uses the repository's
  # rtnetlink implementation rather than ip(8), and speaks a tiny line
  # protocol to the parent so namespace setup is deterministic.
  POD_SCRIPT = <<~'RUBY'
    require "rubernetes/network"
    require "socket"
    require "timeout"

    include Rubernetes

    ROLE = ENV.fetch("RK_POLICY_ROLE")
    PEER = ENV.fetch("RK_POLICY_PEER")
    GATEWAY_MAC = ENV.fetch("RK_POLICY_GATEWAY_MAC")
    PORTS = [29_081, 29_082, 29_083, 29_084, 29_085].freeze
    SCTP = 132
    TCP = 6
    UDP = 17
    IFA_F_NODAD = 0x02
    V4 = ROLE == "client" ? "10.244.0.2" : "10.244.1.2"
    V4_ALT = ROLE == "client" ? "10.244.0.3" : "10.244.1.3"
    V4_GATEWAY = ROLE == "client" ? "10.244.0.1" : "10.244.1.1"
    V4_REMOTE = ROLE == "client" ? "10.244.1.2" : "10.244.0.2"
    V4_ROUTE = ROLE == "client" ? "10.244.1.0/24" : "10.244.0.0/24"
    V6 = ROLE == "client" ? "fd00:244:0::2" : "fd00:244:1::2"
    V6_ALT = ROLE == "client" ? "fd00:244:0:0:8000::4" : "fd00:244:1::3"
    V6_GATEWAY = ROLE == "client" ? "fd00:244:0::1" : "fd00:244:1::1"
    V6_REMOTE = ROLE == "client" ? "fd00:244:1::2" : "fd00:244:0::2"
    V6_ROUTE = ROLE == "client" ? "fd00:244:1::/64" : "fd00:244:0::/64"

    STDOUT.sync = true
    puts "ready"
    STDIN.gets
    netlink = Rubernetes::Network::Netlink.new
    sockets = []
    threads = []
    open_sockets = {}
    sctp_unavailable = false

    def sockaddr(port, address)
      Socket.sockaddr_in(Integer(port), address)
    end

    def family_number(family)
      family == "ipv6" ? Socket::AF_INET6 : Socket::AF_INET
    end

    def local_address(family, alternate)
      if family == "ipv6"
        alternate ? V6_ALT : V6
      else
        alternate ? V4_ALT : V4
      end
    end

    def remote_address(family)
      family == "ipv6" ? V6_REMOTE : V4_REMOTE
    end

    def protocol_number(protocol)
      {"TCP" => TCP, "UDP" => UDP, "SCTP" => SCTP}.fetch(protocol)
    end

    def close_socket(socket)
      socket.close unless socket.closed?
    rescue IOError, SystemCallError
      nil
    end

    def start_stream_server(address, family, protocol, port, sockets, threads)
      socket = Socket.new(family_number(family), Socket::SOCK_STREAM, protocol_number(protocol))
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
      socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, true) if family == "ipv6"
      socket.bind(sockaddr(port, address))
      socket.listen(16)
      sockets << socket
      threads << Thread.new do
        loop do
          connection, = socket.accept
          Thread.new(connection) do |client|
            begin
              client.write("ready\n")
              loop do
                payload = client.readpartial(4096)
                client.write("echo:#{payload}")
              end
            rescue EOFError, IOError, SystemCallError
              nil
            ensure
              close_socket(client)
            end
          end
        rescue IOError, SystemCallError
          break
        end
      end
    end

    def start_datagram_server(address, family, port, sockets, threads)
      socket = Socket.new(family_number(family), Socket::SOCK_DGRAM, UDP)
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
      socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, true) if family == "ipv6"
      socket.bind(sockaddr(port, address))
      sockets << socket
      threads << Thread.new do
        loop do
          payload, peer = socket.recvfrom(4096)
          socket.send("echo:#{payload}", 0, peer)
        rescue IOError, SystemCallError
          break
        end
      end
    end

    def start_servers(sockets, threads)
      ["ipv4", "ipv6"].each do |family|
        address = family == "ipv6" ? "::" : "0.0.0.0"
        PORTS.each do |port|
          start_stream_server(address, family, "TCP", port, sockets, threads)
        end
        start_datagram_server(address, family, 29_084, sockets, threads)
        begin
          start_stream_server(address, family, "SCTP", 29_085, sockets, threads)
        rescue Errno::EAFNOSUPPORT, Errno::EPROTONOSUPPORT, Errno::ENOPROTOOPT, Errno::EINVAL => error
          warn "sctp_unavailable=#{error.class}:#{error.message}"
          return true
        end
      end
      false
    end

    def stream_probe(family, protocol, port, source, remote)
      socket = Socket.new(family_number(family), Socket::SOCK_STREAM, protocol_number(protocol))
      stage = "socket"
      begin
        stage = "bind"
        socket.bind(sockaddr(0, source))
        stage = "connect"
        Timeout.timeout(0.8) { socket.connect(sockaddr(port, remote)) }
        stage = "handshake"
        ready = Timeout.timeout(0.8) { socket.recv(32) }
        raise "server handshake missing" unless ready.include?("ready")

        stage = "request"
        socket.send("probe", 0)
        stage = "response"
        response = Timeout.timeout(0.8) { socket.recv(64) }
        raise "server response mismatch" unless response == "echo:probe"
        true
      rescue StandardError => error
        raise "#{stage}:#{error.class}:#{error.message}"
      ensure
        close_socket(socket)
      end
    end

    def datagram_probe(family, port, source, remote)
      socket = Socket.new(family_number(family), Socket::SOCK_DGRAM, UDP)
      begin
        socket.bind(sockaddr(0, source))
        socket.send("probe", 0, sockaddr(port, remote))
        readable = IO.select([socket], nil, nil, 0.8)
        raise "datagram response timeout" unless readable

        response, = socket.recvfrom(64)
        raise "server response mismatch" unless response == "echo:probe"
        true
      ensure
        close_socket(socket)
      end
    end

    def probe(family, protocol, port, alternate)
      source = local_address(family, alternate)
      remote = remote_address(family)
      if protocol == "UDP"
        datagram_probe(family, port, source, remote)
      else
        stream_probe(family, protocol, port, source, remote)
      end
    end

    def open_flow(family, port, alternate, source_port: nil)
      socket = Socket.new(family_number(family), Socket::SOCK_STREAM, TCP)
      socket.bind(sockaddr(source_port || 0, local_address(family, alternate)))
      Timeout.timeout(0.8) { socket.connect(sockaddr(port, remote_address(family))) }
      ready = Timeout.timeout(0.8) { socket.recv(32) }
      raise "server handshake missing" unless ready.include?("ready")
      socket
    end

    begin
      netlink.link_set(name: "lo", up: true)
      netlink.link_set(name: PEER, up: true)
      if ROLE == "client"
        netlink.address_add(address: "#{V4}/24", name: PEER)
        netlink.address_add(address: "#{V4_ALT}/24", name: PEER)
        netlink.address_add(address: "#{V6}/64", name: PEER, ifa_flags: IFA_F_NODAD)
        netlink.address_add(address: "#{V6_ALT}/64", name: PEER, ifa_flags: IFA_F_NODAD)
        netlink.neighbor_add(destination: V6_GATEWAY, dev: PEER, lladdr: GATEWAY_MAC, family: "ipv6")
        netlink.route_add(destination: V4_ROUTE, via: V4_GATEWAY, dev: PEER, family: "ipv4")
        netlink.route_add(destination: V6_ROUTE, via: V6_GATEWAY, dev: PEER, family: "ipv6")
      else
        netlink.address_add(address: "#{V4}/24", name: PEER)
        netlink.address_add(address: "#{V4_ALT}/24", name: PEER)
        netlink.address_add(address: "#{V6}/64", name: PEER, ifa_flags: IFA_F_NODAD)
        netlink.address_add(address: "#{V6_ALT}/64", name: PEER, ifa_flags: IFA_F_NODAD)
        netlink.neighbor_add(destination: V6_GATEWAY, dev: PEER, lladdr: GATEWAY_MAC, family: "ipv6")
        netlink.route_add(destination: V4_ROUTE, via: V4_GATEWAY, dev: PEER, family: "ipv4")
        netlink.route_add(destination: V6_ROUTE, via: V6_GATEWAY, dev: PEER, family: "ipv6")
      end
      sctp_unavailable = start_servers(sockets, threads)
      puts "sctp_unavailable" if sctp_unavailable
      puts "configured"

      STDIN.each_line do |line|
        command, family, protocol, port, alternate = line.split
        case command
        when "probe"
          begin
            probe(family, protocol, Integer(port), alternate == "alt")
            puts "probe=allowed"
          rescue StandardError => error
            puts "probe=denied:#{error.class}:#{error.message}"
          end
        when "open"
          begin
            key = "#{family}:#{port}"
            open_sockets[key] = open_flow(family, Integer(port), alternate == "alt")
            puts "opened"
          rescue StandardError => error
            puts "open=denied:#{error.class}"
            close_socket(open_sockets.delete("#{family}:#{port}"))
          end
        when "open-fixed"
          begin
            key = "#{family}:#{port}"
            open_sockets[key] = open_flow(family, Integer(port), false, source_port: Integer(alternate))
            puts "opened"
          rescue StandardError => error
            puts "open=denied:#{error.class}"
            close_socket(open_sockets.delete("#{family}:#{port}"))
          end
        when "send-open"
          begin
            key = "#{family}:#{port}"
            socket = open_sockets.fetch(key)
            socket.send("established", 0)
            response = Timeout.timeout(0.8) { socket.recv(64) }
            puts(response == "echo:established" ? "established=allowed" : "established=denied")
          rescue StandardError => error
            puts "established=denied:#{error.class}"
          end
        when "close"
          key = "#{family}:#{port}"
          close_socket(open_sockets.delete(key))
          puts "closed"
        when "diag"
          addresses = Socket.getifaddrs.filter_map do |entry|
            address = entry.addr
            address.ip? ? "#{entry.name}=#{address.ip_address}" : nil
          end
          puts "diag=#{addresses.join(",")}"
        when "quit"
          break
        else
          puts "error=unknown_command"
        end
      end
    ensure
      open_sockets.each_value { |socket| close_socket(socket) }
      sockets.each { |socket| close_socket(socket) }
      threads.each { |thread| thread.kill rescue nil }
    end
  RUBY

  class NativePacketMatrixRunner
    V4_CLIENT = "10.244.0.2"
    V4_CLIENT_ALT = "10.244.0.3"
    V4_SERVER = "10.244.1.2"
    V4_SERVER_ALT = "10.244.1.3"
    V6_CLIENT = "fd00:244:0::2"
    V6_CLIENT_ALT = "fd00:244:0:0:8000::4"
    V6_SERVER = "fd00:244:1::2"
    V6_SERVER_ALT = "fd00:244:1::3"

    def initialize
      @cells = Rubernetes::Network::NftablesPolicyAdapter::POLICY_PACKET_CASES.to_h { |key| [key, false] }
      @blockers = []
      @failures = []
      @revision = 0
      @sctp_available = true
    end

    def run
      @sctp_available = sctp_socket_available?
      add_blocker("sctp_kernel_protocol_unavailable", "protocol 132 cannot be opened") unless @sctp_available
      Rubernetes::Network::NftablesPolicyAdapter::POLICY_PACKET_CASES.each do |cell|
        next if cell == "sctp" && !@sctp_available

        run_cell(cell)
      end
      gate = Rubernetes::Network::NftablesPolicyAdapter.new(
        table_name: "rkpmatrixgate#{Process.pid}"
      )
      production_capable = false
      if @blockers.empty? && @failures.empty? && @cells.values.all?
        gate.verify_packet_matrix!(matrix: @cells)
        production_capable = gate.production_capable?
      end
      {
        "adapter" => "nftables",
        "cells" => @cells,
        "passed_cells" => @cells.select { |_key, value| value }.keys,
        "blockers" => @blockers,
        "failures" => @failures,
        "cni_oracle" => "not_used",
        "production_capable" => production_capable
      }
    end

    private

    def add_blocker(code, message)
      entry = {"code" => String(code), "message" => String(message)}
      @blockers << entry unless @blockers.include?(entry)
    end

    def sctp_socket_available?
      socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 132)
      socket.close
      true
    rescue Errno::EAFNOSUPPORT, Errno::EPROTONOSUPPORT, Errno::ENOPROTOOPT, Errno::EINVAL
      false
    end

    def run_cell(cell)
      result = case cell
               when "default_deny_ingress"
                 run_default_deny(direction: "Ingress", source: "client", expected: :denied)
               when "default_deny_egress"
                 run_default_deny(direction: "Egress", source: "client", expected: :denied)
               when "selector_ingress"
                 with_fixture do
                   apply([ingress_policy("selector-ingress", from: pod_peer("client"),
                                                             port: 29_081)]) && probe("client", "ipv4", "TCP", 29_081) == :allowed
                 end
               when "selector_egress"
                 with_fixture do
                   apply([egress_policy("selector-egress", to: pod_peer("server"),
                                                           port: 29_081)]) && probe("client", "ipv4", "TCP", 29_081) == :allowed
                 end
               when "namespace_selector"
                 with_fixture do
                   peer = {"namespaceSelector" => {"matchLabels" => {"team" => "client"}},
                           "podSelector" => {"matchLabels" => {"app" => "client"}}}
                   apply([ingress_policy("namespace-selector", from: peer, port: 29_081)]) &&
                     probe("client", "ipv4", "TCP", 29_081) == :allowed
                 end
               when "additive_union"
                 with_fixture do
                   apply([ingress_policy("additive-one", from: pod_peer("client"), port: 29_081),
                          ingress_policy("additive-two", from: pod_peer("client"), port: 29_082)]) &&
                     probe("client", "ipv4", "TCP", 29_081) == :allowed &&
                     probe("client", "ipv4", "TCP", 29_082) == :allowed &&
                     probe("client", "ipv4", "TCP", 29_083) == :denied
                 end
               when "ipblock_except_ipv4"
                 with_fixture do
                   block = {"ipBlock" => {"cidr" => "10.244.0.0/24", "except" => ["10.244.0.2/32"]}}
                   apply([ingress_policy("ipblock-v4", from: block, port: 29_081)]) &&
                     begin
                       alternate = probe("client", "ipv4", "TCP", 29_081, alternate: true)
                       base = probe("client", "ipv4", "TCP", 29_081)
                       raise "ipBlock IPv4 results alternate=#{alternate} base=#{base}" unless alternate == :allowed && base == :denied

                       true
                     end
                 end
               when "ipblock_except_ipv6"
                 with_fixture do
                   block = {"ipBlock" => {"cidr" => "fd00:244:0::/64", "except" => ["fd00:244:0::/65"]}}
                   apply([ingress_policy("ipblock-v6", from: block, port: 29_081)]) &&
                     begin
                       alternate = probe("client", "ipv6", "TCP", 29_081, alternate: true)
                       base = probe("client", "ipv6", "TCP", 29_081)
                       raise "ipBlock IPv6 results alternate=#{alternate} base=#{base}" unless alternate == :allowed && base == :denied

                       true
                     end
                 end
               when "named_port"
                 with_fixture do
                   apply([ingress_policy("named-port-in", from: pod_peer("client"), port: "web"),
                          egress_policy("named-port-out", to: pod_peer("server"), port: "web")]) &&
                     probe("client", "ipv4", "TCP", 29_081) == :allowed
                 end
               when "named_port_egress_all"
                 with_fixture do
                   # The omitted `to` peer is the all-destination case. The
                   # named port must resolve against the destination pod
                   # index, so the client can reach the server's `web` port.
                   apply([egress_policy("named-port-egress-all", to: nil, port: "web")]) &&
                     probe("client", "ipv4", "TCP", 29_081) == :allowed
                 end
               when "end_port"
                 with_fixture do
                   apply([ingress_policy("end-port-in", from: pod_peer("client"), port: 29_081, end_port: 29_082),
                          egress_policy("end-port-out", to: pod_peer("server"), port: 29_081, end_port: 29_082)]) &&
                     probe("client", "ipv4", "TCP", 29_081) == :allowed &&
                     probe("client", "ipv4", "TCP", 29_082) == :allowed &&
                     probe("client", "ipv4", "TCP", 29_083) == :denied
                 end
               when "tcp"
                 with_fixture do
                   apply([ingress_policy("tcp", from: pod_peer("client"), port: 29_081,
                                                protocol: "TCP")]) && probe("client", "ipv4", "TCP", 29_081) == :allowed
                 end
               when "udp"
                 with_fixture do
                   apply([ingress_policy("udp", from: pod_peer("client"), port: 29_084, protocol: "UDP")]) &&
                     probe("client", "ipv4", "UDP", 29_084) == :allowed &&
                     probe("client", "ipv6", "UDP", 29_084) == :allowed
                 end
               when "sctp"
                 with_fixture do
                   apply([ingress_policy("sctp", from: pod_peer("client"), port: 29_085, protocol: "SCTP")]) &&
                     probe("client", "ipv4", "SCTP", 29_085) == :allowed &&
                     probe("client", "ipv6", "SCTP", 29_085) == :allowed
                 end
               when "dual_stack"
                 with_fixture do
                   apply([ingress_policy("dual-stack", from: pod_peer("client"), port: 29_081)]) &&
                     begin
                       v4 = probe("client", "ipv4", "TCP", 29_081)
                       v6 = probe("client", "ipv6", "TCP", 29_081)
                       raise "dual-stack results ipv4=#{v4} ipv6=#{v6}" unless v4 == :allowed && v6 == :allowed

                       true
                     end
                 end
               when "established"
                 with_fixture do
                   apply([ingress_policy("established-allow", from: pod_peer("client"), port: 29_081)])
                   open_flow("client", "ipv4", 29_081)
                   apply([ingress_policy("established-deny", from: nil)])
                   established = command(@children.fetch("client"), "send-open ipv4 TCP 29081")
                   command(@children.fetch("client"), "close ipv4 TCP 29081")
                   raise "established result=#{established} nft=#{nft_dump}" unless established == "established=allowed"

                   true
                 end
               when "atomic_readback"
                 with_fixture do
                   apply([ingress_policy("atomic-allow", from: pod_peer("client"), port: 29_081)])
                   first = @adapter.readback(snapshot: @engine.snapshot.to_h).fetch("verified")
                   allowed = probe("client", "ipv4", "TCP", 29_081) == :allowed
                   apply([ingress_policy("atomic-deny", from: nil)])
                   second = @adapter.readback(snapshot: @engine.snapshot.to_h).fetch("verified")
                   denied = probe("client", "ipv4", "TCP", 29_081) == :denied
                   first && second && allowed && denied
                 end
               when "multi_interface_readback"
                 with_fixture do
                   policies = [
                     ingress_policy("server-in", from: pod_peer("client"), port: 29_081),
                     egress_policy("client-out", to: pod_peer("server"), port: 29_081),
                     ingress_policy("client-in", from: pod_peer("server"), port: 29_081,
                                                 selector: {"app" => "client"}),
                     egress_policy("server-out", to: pod_peer("client"), port: 29_081,
                                                 selector: {"app" => "server"})
                   ]
                   apply(policies.first(2))
                   @adapter.readback(snapshot: @engine.snapshot.to_h)
                   forward = probe("client", "ipv4", "TCP", 29_081) == :allowed
                   forward_detail = @last_probe_line
                   apply(policies.last(2))
                   readback = @adapter.readback(snapshot: @engine.snapshot.to_h)
                   reverse = probe("server", "ipv4", "TCP", 29_081) == :allowed
                   reverse_detail = @last_probe_line
                   rule_count = @engine.snapshot.entries.dig("kernel", "rules").length
                   rule_summary = @engine.snapshot.entries.dig("kernel", "rules").map do |rule|
                     [rule.fetch("direction"), rule.fetch("target"), rule.dig("peer", "ip")]
                   end
                   unless readback.fetch("verified") && readback.fetch("chains").any? && forward && reverse
                     raise "multi-interface readback=#{readback.fetch("verified")} rules=#{rule_count} summary=#{rule_summary.inspect} forward=#{forward}(#{forward_detail}) reverse=#{reverse}(#{reverse_detail})"
                   end

                   true
                 end
               else
                 raise "unknown matrix cell #{cell}"
               end
      if result == true
        @cells[cell] = true
      else
        @failures << {"cell" => cell, "error" => "packet assertion returned false"}
      end
    rescue CapabilityBlocker => error
      add_blocker(error.code, error.message)
    rescue StandardError => error
      @failures << {"cell" => cell, "error" => "#{error.class}: #{error.message}"}
    end

    def run_default_deny(direction:, source:, expected:)
      with_fixture do
        diagnostics = command(@children.fetch(source), "diag")
        baseline_v6 = probe(source, "ipv6", "TCP", 29_081)
        raise "IPv6 baseline path=#{baseline_v6} detail=#{@last_probe_line} #{diagnostics}" unless baseline_v6 == :allowed

        policy = direction == "Ingress" ? ingress_policy("default-deny-ingress", from: nil) : egress_policy("default-deny-egress", to: nil)
        apply([policy]) &&
          probe(source, "ipv4", "TCP", 29_081) == expected &&
          probe(source, "ipv6", "TCP", 29_081) == expected
      end
    end

    def with_fixture
      setup_fixture
      yield
    ensure
      teardown_fixture
    end

    def setup_fixture
      @netlink = Rubernetes::Network::Netlink.new
      @children = {}
      @host_links = []
      @sysctl_values = {}
      set_sysctl("/proc/sys/net/ipv4/ip_forward", "1")
      set_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")
      set_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
      create_endpoint("client", "10.244.0.1", "fd00:244:0::1")
      create_endpoint("server", "10.244.1.1", "fd00:244:1::1")
      @netlink.neighbor_add(destination: V6_SERVER, dev: @children.fetch("server").fetch(:host),
                            lladdr: @children.fetch("server").fetch(:peer_mac), family: "ipv6")
      @netlink.neighbor_add(destination: V6_CLIENT, dev: @children.fetch("client").fetch(:host),
                            lladdr: @children.fetch("client").fetch(:peer_mac), family: "ipv6")
      @netlink.neighbor_add(destination: V6_CLIENT_ALT, dev: @children.fetch("client").fetch(:host),
                            lladdr: @children.fetch("client").fetch(:peer_mac), family: "ipv6")
      @table_name = "rkpol#{Process.pid}#{@revision + 1}"
      @adapter = Rubernetes::Network::NftablesPolicyAdapter.new(table_name: @table_name)
      @engine = Rubernetes::Network::PolicyEngine.new(
        adapter: @adapter,
        pod_index: pod_index,
        namespace_labels: {"apps" => {"team" => "client"}, "services" => {"team" => "server"}}
      )
      # A packet matrix is meaningful only when the fixture's unfiltered
      # forwarding path is already reachable. Existing host/Docker FORWARD
      # policy must be reported as an environment blocker, not multiplied
      # into one indistinguishable failure for every NetworkPolicy cell.
      baseline_v4 = probe("client", "ipv4", "TCP", 29_081)
      baseline_v6 = probe("client", "ipv6", "TCP", 29_081)
      unless baseline_v4 == :allowed && baseline_v6 == :allowed
        diagnostics = command(@children.fetch("client"), "diag")
        raise CapabilityBlocker.new("forwarding_fixture_unavailable",
                                    "baseline ipv4=#{baseline_v4} ipv6=#{baseline_v6} #{diagnostics}")
      end
    rescue Rubernetes::Network::NetlinkError, Errno::EPERM, Errno::EACCES => error
      raise CapabilityBlocker.new("network_namespace_or_veth_unavailable", error.message)
    end

    def teardown_fixture
      begin
        @adapter&.detach
      rescue StandardError
        nil
      end
      # Two passes on purpose: ask every child to quit first, then kill the
      # ones still alive (the kill must not depend on the quit having failed).
      @children&.each_value do |child|
        child[:stdin].write("quit\n") unless child[:stdin].closed?
        child[:stdin].close unless child[:stdin].closed?
      rescue IOError, Errno::EPIPE
        nil
      end
      @children&.each_value do |child|
        Process.kill("TERM", child[:thread].pid) if child[:thread].alive?
      rescue Errno::ESRCH
        nil
      ensure
        child[:thread].join(1)
        begin
          child[:stdout].close
        rescue StandardError
          nil
        end
        begin
          child[:stderr].close
        rescue StandardError
          nil
        end
      end
      @host_links&.each do |name|
        @netlink.link_delete(name: name)
      rescue StandardError
        nil
      end
      @sysctl_values&.each do |path, value|
        File.write(path, value)
      rescue StandardError
        nil
      end
      @children = nil
      @adapter = nil
      @engine = nil
    end

    def set_sysctl(path, value)
      original = File.read(path).strip
      @sysctl_values[path] = original
      File.write(path, "#{value}\n")
    rescue Errno::EACCES, Errno::EPERM, Errno::EROFS => error
      raise CapabilityBlocker.new("sysctl_forwarding_unavailable", "#{path}: #{error.message}")
    rescue Errno::ENOENT => error
      raise CapabilityBlocker.new("sysctl_missing", "#{path}: #{error.message}")
    end

    def create_endpoint(role, host_v4, host_v6)
      token = "#{Process.pid}#{@host_links.length}"
      host_name = "rkp#{token}#{role == "client" ? "c" : "s"}h"
      peer_name = "rkp#{token}#{role == "client" ? "c" : "s"}p"
      @netlink.link_add(name: host_name, kind: "veth", peer: peer_name, up: false)
      @host_links << host_name
      # /sys may remain mounted from the parent namespace after unshare.
      # Rtnetlink is namespace-aware and is the authoritative MAC readback.
      host_mac = @netlink.link_state(name: host_name).fetch("mac")
      peer_mac = @netlink.link_state(name: peer_name).fetch("mac")
      environment = {
        "RK_POLICY_ROLE" => role,
        "RK_POLICY_PEER" => peer_name,
        "RK_POLICY_GATEWAY_MAC" => host_mac
      }
      stdin, stdout, stderr, thread = Open3.popen3(
        environment, "unshare", "-Urn", "--", RbConfig.ruby, "-Ilib", "-e", POD_SCRIPT
      )
      child = {stdin: stdin, stdout: stdout, stderr: stderr, thread: thread, host: host_name,
               host_mac: host_mac, peer_mac: peer_mac}
      @children[role] = child
      ready = Timeout.timeout(2) { stdout.gets }
      unless ready&.strip == "ready"
        error = stderr.read
        raise CapabilityBlocker.new("network_namespace_unavailable", error.empty? ? "child did not report ready" : error)
      end
      namespace = File.open("/proc/#{thread.pid}/ns/net", "rb")
      begin
        before_links = Socket.getifaddrs.map(&:name).uniq
        @netlink.link_set(name: peer_name, namespace_fd: namespace, up: false)
        child[:move_debug] =
          "before=#{before_links.join(",")};after=#{Socket.getifaddrs.map(&:name).uniq.join(",")};child_ns=#{File.readlink("/proc/#{thread.pid}/ns/net")}"
      ensure
        namespace.close
      end
      @netlink.link_set(name: host_name, up: true)
      @netlink.address_add(address: "#{host_v4}/24", name: host_name)
      @netlink.address_add(address: "#{host_v6}/64", name: host_name, ifa_flags: 0x02)
      begin
        stdin.write("go\n")
        stdin.flush
      rescue Errno::EPIPE, IOError => error
        raise "child #{role} exited before go: #{error.message}; move=#{child[:move_debug]}; stderr=#{stderr.read}"
      end
      lines = []
      loop do
        line = Timeout.timeout(2) { stdout.gets }
        if line.nil?
          detail = stderr.read
          raise "child #{role} exited before configuration: #{detail}"
        end
        break if line.strip == "configured"

        lines << line.strip
      end
      if lines.any? { |line| line.start_with?("sctp_unavailable") }
        @sctp_available = false
        add_blocker("sctp_packet_path_unavailable", lines.join("; "))
      end
    rescue Errno::ENOENT => error
      raise CapabilityBlocker.new("unshare_or_namespace_proc_unavailable", error.message)
    rescue Timeout::Error => error
      detail = stderr&.read.to_s
      raise CapabilityBlocker.new("network_namespace_handshake_timeout", "#{error.message}; #{detail}")
    end

    def command(child, line)
      child.fetch(:stdin).write("#{line}\n")
      child.fetch(:stdin).flush
      Timeout.timeout(2) { child.fetch(:stdout).gets.to_s.strip }
    rescue Errno::EPIPE, IOError => error
      status = child.fetch(:thread).alive? ? "running" : child.fetch(:thread).value.inspect
      detail = child.fetch(:stderr).read
      raise "child command failed: #{error.message}; status=#{status}; stderr=#{detail}"
    end

    def probe(role, family, protocol, port, alternate: false)
      line = command(@children.fetch(role), "probe #{family} #{protocol} #{port}#{" alt" if alternate}")
      @last_probe_line = line
      return :allowed if line == "probe=allowed"
      return :denied if line.start_with?("probe=denied:")

      raise "unexpected probe result #{line.inspect}"
    end

    def open_flow(role, family, port, source_port: nil)
      command_name = source_port ? "open-fixed #{family} TCP #{port} #{source_port}" : "open #{family} TCP #{port}"
      result = command(@children.fetch(role), command_name)
      raise "established flow did not open: #{result}" unless result == "opened"
    end

    def apply(policies)
      @revision += 1
      @engine.apply(policies, revision: @revision)
      true
    end

    def nft_dump
      return "nft-unavailable" unless File.executable?("/usr/sbin/nft")

      output, error, status = Open3.capture3("/usr/sbin/nft", "-a", "list", "table", "inet", @table_name.to_s)
      status.success? ? output.lines.grep(/ct |drop|accept|policy/).join(" ") : "nft-error=#{error.strip}"
    rescue StandardError => error
      "nft-error=#{error.class}:#{error.message}"
    end

    def pod_index
      [
        {"namespace" => "apps", "name" => "client", "labels" => {"app" => "client"},
         "ips" => [V4_CLIENT, V6_CLIENT]},
        {"namespace" => "services", "name" => "server", "labels" => {"app" => "server"},
         "ips" => [V4_SERVER, V6_SERVER], "ports" => [{"name" => "web", "port" => 29_081}]}
      ]
    end

    def pod_peer(role)
      {"namespaceSelector" => {},
       "podSelector" => {"matchLabels" => {"app" => role == "client" ? "client" : "server"}}}
    end

    def ingress_policy(name, from:, port: nil, end_port: nil, protocol: "TCP", selector: nil)
      selector ||= {"app" => "server"}
      rule = {}
      rule["from"] = [from] if from
      rule["ports"] = [port_entry(port, end_port: end_port, protocol: protocol)] if port
      policy(name, selector: selector, types: ["Ingress"], ingress: from || port ? [rule] : [])
    end

    def egress_policy(name, to:, port: nil, end_port: nil, protocol: "TCP", selector: nil)
      selector ||= {"app" => "client"}
      rule = {}
      rule["to"] = [to] if to
      rule["ports"] = [port_entry(port, end_port: end_port, protocol: protocol)] if port
      policy(name, selector: selector, types: ["Egress"], egress: to || port ? [rule] : [])
    end

    def policy(name, selector:, types:, ingress: [], egress: [])
      {"metadata" => {"name" => name, "namespace" => selector.fetch("app") == "server" ? "services" : "apps"},
       "spec" => {"podSelector" => {"matchLabels" => selector}, "policyTypes" => types,
                  "ingress" => ingress, "egress" => egress}}
    end

    def port_entry(port, end_port:, protocol:)
      entry = {"protocol" => protocol, "port" => port}
      entry["endPort"] = end_port if end_port
      entry
    end
  end

  class EBPFReverseConntrackKernelRunner < NativePacketMatrixRunner
    FIXED_SOURCE_PORT = 50_000

    def run
      with_fixture do
        apply([
                ingress_policy("reverse-key-ingress", from: pod_peer("client"), port: 29_081),
                # The reverse response targets the client's fixed source port. A
                # reverse-flow hit must bypass this non-matching egress rule.
                egress_policy("reverse-key-egress", to: pod_peer("client"), port: 29_081,
                                                    selector: {"app" => "server"})
              ])
        open_flow("client", "ipv4", 29_081, source_port: FIXED_SOURCE_PORT)
        true
      end
    rescue Rubernetes::Platform::Linux::Error => error
      skippable = [Errno::EPERM::Errno, Errno::EACCES::Errno,
                   Errno::EOPNOTSUPP::Errno, Errno::ENOSYS::Errno]
      raise unless skippable.include?(error.errno)

      raise CapabilityBlocker.new("ebpf_kernel_unavailable", error.message)
    end

    private

    def setup_fixture
      super
      @adapter.detach
      @adapter = Rubernetes::Network::EBPFPolicyAdapter.new(interfaces: [@host_links.fetch(1)])
      @engine = Rubernetes::Network::PolicyEngine.new(
        adapter: @adapter,
        pod_index: pod_index,
        namespace_labels: {"apps" => {"team" => "client"}, "services" => {"team" => "server"}}
      )
    end
  end

  def test_native_nftables_policy_packet_matrix_in_self_contained_namespace
    if ENV["RUBERNETES_NETWORK_POLICY_MATRIX_INNER"] != "1"
      environment = {"RUBERNETES_NETWORK_POLICY_MATRIX_INNER" => "1"}
      output, error, status = Open3.capture3(
        # bpf(2) needs CAP_BPF/CAP_NET_ADMIN in the initial user namespace; a
        # root runner keeps it and only isolates the network namespace.
        environment, "unshare", (Process.euid.zero? ? "-n" : "-Urn"), "--", RbConfig.ruby, "-Itest", "-Ilib", __FILE__,
        "--name", "test_native_nftables_policy_packet_matrix_in_self_contained_namespace"
      )

      assert_predicate status, :success?, "isolated packet matrix failed\n#{output}\n#{error}"
      assert_match(/0 failures, 0 errors, 0 skips/, output)
      skip "the packet matrix ran in the isolated child process above"
    end

    result = NativePacketMatrixRunner.new.run
    puts "NETWORK_POLICY_NATIVE_MATRIX=#{JSON.generate(result)}"

    assert_empty result.fetch("blockers"), result.fetch("blockers").inspect
    assert_empty result.fetch("failures"), result.fetch("failures").inspect
    assert_equal result.fetch("cells").keys.sort, result.fetch("passed_cells").sort
    assert_equal true, result.fetch("production_capable"), result.inspect
  end

  def test_ebpf_policy_reverse_conntrack_key_on_kernel_veth
    if ENV["RUBERNETES_NETWORK_POLICY_EBPF_INNER"] != "1"
      environment = {"RUBERNETES_NETWORK_POLICY_EBPF_INNER" => "1"}
      output, error, status = Open3.capture3(
        # bpf(2) needs CAP_BPF/CAP_NET_ADMIN in the initial user namespace; a
        # root runner keeps it and only isolates the network namespace.
        environment, "unshare", (Process.euid.zero? ? "-n" : "-Urn"), "--", RbConfig.ruby, "-Itest", "-Ilib", __FILE__,
        "--name", "test_ebpf_policy_reverse_conntrack_key_on_kernel_veth"
      )
      skip error.strip if status.exitstatus == 77 && error.start_with?("SKIP:")
      failure_output = "#{output}\n#{error}"
      if !status.success? && failure_output.match?(/Operation not permitted|Permission denied/i)
        skip "missing namespace or eBPF capability: #{failure_output.lines.last(8).join.strip}"
      end

      assert_predicate status, :success?, "isolated eBPF NetworkPolicy test failed: #{error.empty? ? output : error}"
      assert_match(/1 runs, \d+ assertions, 0 failures, 0 errors, 0 skips/, output)
      skip
    end

    result = EBPFReverseConntrackKernelRunner.new.run
    puts "NETWORK_POLICY_EBPF_REVERSE=#{result}"

    assert_equal true, result
  rescue CapabilityBlocker => error
    warn "SKIP: #{error.code}: #{error.message}"
    exit 77
  rescue Errno::ENOENT => error
    flunk "unshare is required for the isolated eBPF NetworkPolicy test: #{error.message}"
  end
end
