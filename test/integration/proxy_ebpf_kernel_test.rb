# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"

class ProxyEBPFKernelTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'
    require "open3"
    require "rubernetes/network"
    require "rubernetes/platform/linux"
    require "rubernetes/proxy"
    require "socket"
    require "timeout"

    include Rubernetes

    SKIPPABLE_ERRNOS = [Errno::EPERM::Errno, Errno::EACCES::Errno, Errno::EOPNOTSUPP::Errno,
                        Errno::ENOSYS::Errno].freeze
    PORT = 29_071
    NODE_PORT = 30_081
    BACKEND_PORT = 29_072
    BACKEND_PORT_V6 = 29_073
    TCP_PORT = 29_074
    BACKEND_TCP_PORT = 29_075
    BACKEND_TCP_PORT_V6 = 29_076
    CLIENT_HOST_IP = "198.18.20.1"
    CLIENT_PEER_IP = "198.18.20.2"
    CLIENT_NETWORK = "198.18.20.0/30"
    CLIENT_HOST_IP_V6 = "fd00:20::1"
    CLIENT_PEER_IP_V6 = "fd00:20::2"
    CLIENT_NETWORK_V6 = "fd00:20::/64"
    BACKEND_HOST_IP = "198.18.30.1"
    BACKEND_PEER_IP = "198.18.30.2"
    BACKEND_EXTRA_IP = "198.18.30.3"
    BACKEND_NETWORK = "198.18.30.0/29"
    BACKEND_HOST_IP_V6 = "fd00:30::1"
    BACKEND_PEER_IP_V6 = "fd00:30::2"
    BACKEND_EXTRA_IP_V6 = "fd00:30::3"
    BACKEND_NETWORK_V6 = "fd00:30::/64"
    SUFFIX = Process.pid.to_s.rjust(6, "0")[-6, 6]
    CLIENT_HOST = "rkpx#{SUFFIX}ch"
    CLIENT_PEER = "rkpx#{SUFFIX}cp"
    BACKEND_HOST = "rkpx#{SUFFIX}bh"
    BACKEND_PEER = "rkpx#{SUFFIX}bp"
    LAYOUT = {
      "service_rules" => {"type" => "hash", "key_size" => 40, "value_size" => 64, "max_entries" => 16},
      "backends" => {"type" => "array_of_structs", "key_size" => 16, "value_size" => 96, "max_entries" => 32},
      "conntrack" => {"type" => "lru_hash", "key_size" => 40, "value_size" => 48, "max_entries" => 16},
      "client_ip_affinity" => {"type" => "lru_hash", "key_size" => 24, "value_size" => 16, "max_entries" => 16},
      "sctp_crc32c" => {"type" => "array", "key_size" => 4, "value_size" => 4, "max_entries" => 256}
    }.freeze

    CHILD_SCRIPT = <<~'CHILD'.freeze
      require "rubernetes/network"
      require "socket"
      require "timeout"

      netlink = Rubernetes::Network::Netlink.new
      role = ENV.fetch("RK_PROXY_ROLE")
      peer = ENV.fetch("RK_PROXY_PEER")
      prefix = Integer(ENV.fetch("RK_PROXY_PREFIX"))
      peer_ip = ENV.fetch("RK_PROXY_PEER_IP")
      peer_ip_v6 = ENV.fetch("RK_PROXY_PEER_IP_V6")
      network = ENV.fetch("RK_PROXY_NETWORK")
      network_v6 = ENV.fetch("RK_PROXY_NETWORK_V6")
      gateway = ENV.fetch("RK_PROXY_GATEWAY")
      gateway_v6 = ENV.fetch("RK_PROXY_GATEWAY_V6")
      gateway_mac = ENV["RK_PROXY_GATEWAY_MAC"]
      remote = ENV.fetch("RK_PROXY_REMOTE")
      remote_v6 = ENV.fetch("RK_PROXY_REMOTE_V6")
      backend_ip = ENV.fetch("RK_PROXY_BACKEND_IP")
      backend_ip_v6 = ENV.fetch("RK_PROXY_BACKEND_IP_V6")
      service_ip = ENV.fetch("RK_PROXY_SERVICE_IP")
      service_ip_v6 = ENV.fetch("RK_PROXY_SERVICE_IP_V6")
      backend_extra_ip = ENV.fetch("RK_PROXY_BACKEND_EXTRA_IP")
      backend_extra_ip_v6 = ENV.fetch("RK_PROXY_BACKEND_EXTRA_IP_V6")
      port = Integer(ENV.fetch("RK_PROXY_PORT"))
      backend_port = Integer(ENV.fetch("RK_PROXY_BACKEND_PORT"))
      backend_port_v6 = Integer(ENV.fetch("RK_PROXY_BACKEND_PORT_V6"))
      node_port = Integer(ENV.fetch("RK_PROXY_NODE_PORT"))
      tcp_port = Integer(ENV.fetch("RK_PROXY_TCP_PORT"))
      backend_tcp_port = Integer(ENV.fetch("RK_PROXY_BACKEND_TCP_PORT"))
      backend_tcp_port_v6 = Integer(ENV.fetch("RK_PROXY_BACKEND_TCP_PORT_V6"))
      STDOUT.sync = true

      def receive_datagram(socket)
        payload, address, _flags, *controls = socket.recvmsg(128, 0, 1024)
        pktinfo = controls.find do |control|
          control.cmsg_is?(Socket::IPPROTO_IP, Socket::IP_PKTINFO) ||
            control.cmsg_is?(Socket::IPPROTO_IPV6, Socket::IPV6_PKTINFO)
        end
        [payload, address, pktinfo]
      end

      def send_datagram(socket, payload, address, pktinfo)
        unless pktinfo
          socket.send(payload, 0, address.ip_address, address.ip_port)
          return
        end

        control = if pktinfo.cmsg_is?(Socket::IPPROTO_IP, Socket::IP_PKTINFO)
                    local, ifindex, spec_dst = pktinfo.ip_pktinfo
                    Socket::AncillaryData.ip_pktinfo(local, ifindex, spec_dst)
                  else
                    local, ifindex = pktinfo.ipv6_pktinfo
                    Socket::AncillaryData.ipv6_pktinfo(local, ifindex)
                  end
        socket.sendmsg(payload, 0, address, control)
      end

      def pktinfo_address(pktinfo)
        return nil unless pktinfo

        if pktinfo.cmsg_is?(Socket::IPPROTO_IP, Socket::IP_PKTINFO)
          pktinfo.ip_pktinfo.fetch(0).ip_address
        else
          pktinfo.ipv6_pktinfo.fetch(0).ip_address
        end
      end

      puts "ready"
      command = STDIN.gets
      gateway_mac ||= command.to_s.strip.split(" ", 2)[1]
      raise "IPv6 gateway MAC was not supplied" unless gateway_mac && !gateway_mac.empty?
      netlink.link_set(name: peer, up: true)
      netlink.address_add(address: "#{peer_ip}/#{prefix}", name: peer)
      netlink.address_add(address: "#{peer_ip_v6}/64", name: peer, ifa_flags: 0x02)
      netlink.address_add(address: "#{backend_extra_ip}/#{prefix}", name: peer) if role == "backend"
      netlink.address_add(address: "#{backend_extra_ip_v6}/64", name: peer, ifa_flags: 0x02) if role == "backend"
      netlink.neighbor_add(destination: gateway_v6, dev: peer, lladdr: gateway_mac, family: "ipv6")
      packet_address = Socket.getifaddrs.find do |entry|
        entry.name == peer && entry.addr && entry.addr.pfamily == Socket::AF_PACKET
      end
      peer_mac = packet_address&.addr&.inspect.to_s[/hwaddr=([0-9a-f:]+)/i, 1]
      raise "could not read veth peer MAC" unless peer_mac && !peer_mac.empty?
      if role == "backend"
        # The backend is a real routed endpoint on a different veth.  This
        # avoids treating a .3/30 broadcast address as a server and exercises
        # the host forwarding path after DNAT.
        netlink.route_add(destination: network, via: gateway, dev: peer, family: "ipv4")
        netlink.route_add(destination: network_v6, via: gateway_v6, dev: peer, family: "ipv6")
        receiver = UDPSocket.new(Socket::AF_INET)
        receiver.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
        receiver.setsockopt(Socket::IPPROTO_IP, Socket::IP_PKTINFO, 1)
        receiver.bind("0.0.0.0", backend_port)
        receiver_v6 = UDPSocket.new(Socket::AF_INET6)
        receiver_v6.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
        receiver_v6.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 1)
        receiver_v6.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVPKTINFO, 1)
        receiver_v6.bind("::", backend_port_v6)
        tcp_server = TCPServer.new("0.0.0.0", backend_tcp_port)
        tcp_server_v6 = TCPServer.new("::", backend_tcp_port_v6)
        puts "peer-ready=#{peer_mac}"
        puts "backend-ready"
        readable = IO.select([receiver], nil, nil, 5.0)
        raise "backend did not receive a DNAT packet" unless readable
        payload, address, pktinfo = receive_datagram(receiver)
        if payload == "baseline"
          send_datagram(receiver, "baseline-reply", address, pktinfo)
          readable = IO.select([receiver], nil, nil, 5.0)
          raise "backend did not receive the service packet after baseline" unless readable
          payload, address, pktinfo = receive_datagram(receiver)
        end
        raise "unexpected packet payload #{payload.inspect}" unless payload == "isolated-tc-packet"
        raise "client source was not preserved through DNAT" unless address.ip_address == remote
        backend_selected_ip = pktinfo_address(pktinfo)
        send_datagram(receiver, "isolated-tc-reply", address, pktinfo)
        readable = IO.select([receiver], nil, nil, 5.0)
        raise "backend did not receive the NodePort packet" unless readable
        payload, address, pktinfo = receive_datagram(receiver)
        raise "unexpected NodePort packet payload #{payload.inspect}" unless payload == "isolated-nodeport"
        send_datagram(receiver, "isolated-nodeport-reply", address, pktinfo)
        readable = IO.select([receiver_v6], nil, nil, 5.0)
        raise "backend did not receive a baseline IPv6 packet" unless readable
        payload, address, pktinfo = receive_datagram(receiver_v6)
        raise "unexpected IPv6 baseline payload #{payload.inspect}" unless payload == "baseline6"
        send_datagram(receiver_v6, "baseline6-reply", address, pktinfo)
        readable = IO.select([receiver_v6], nil, nil, 5.0)
        raise "backend did not receive the IPv6 service packet" unless readable
        payload, address, pktinfo = receive_datagram(receiver_v6)
        raise "unexpected IPv6 packet payload #{payload.inspect}" unless payload == "isolated-tc-packet6"
        raise "IPv6 client source was not preserved through DNAT" unless address.ip_address == remote_v6
        backend_selected_ip_v6 = pktinfo_address(pktinfo)
        send_datagram(receiver_v6, "isolated-tc-reply6", address, pktinfo)
        readable = IO.select([receiver_v6], nil, nil, 5.0)
        raise "backend did not receive the IPv6 NodePort packet" unless readable
        payload, address, pktinfo = receive_datagram(receiver_v6)
        raise "unexpected IPv6 NodePort packet payload #{payload.inspect}" unless payload == "isolated-nodeport6"
        send_datagram(receiver_v6, "isolated-nodeport-reply6", address, pktinfo)
        raise "backend did not receive TCP packet" unless IO.select([tcp_server], nil, nil, 5.0)
        tcp_client = tcp_server.accept
        tcp_payload = tcp_client.read(128)
        raise "unexpected TCP packet payload #{tcp_payload.inspect}" unless tcp_payload == "isolated-tc-tcp"
        raise "TCP client source was not preserved through DNAT" unless tcp_client.peeraddr[3] == remote
        tcp_client.write("isolated-tc-tcp-reply")
        tcp_client.close
        raise "backend did not receive IPv6 TCP packet" unless IO.select([tcp_server_v6], nil, nil, 5.0)
        tcp_client_v6 = tcp_server_v6.accept
        tcp_payload = tcp_client_v6.read(128)
        raise "unexpected IPv6 TCP packet payload #{tcp_payload.inspect}" unless tcp_payload == "isolated-tc-tcp6"
        raise "IPv6 TCP client source was not preserved through DNAT" unless tcp_client_v6.peeraddr[3] == remote_v6
        tcp_client_v6.write("isolated-tc-tcp-reply6")
        tcp_client_v6.close
        puts "backend=dnat:#{backend_selected_ip}:#{backend_port}:source=#{remote}:#{address.ip_port}:backend6=dnat:#{backend_selected_ip_v6}:#{backend_port_v6}:source=#{remote_v6}:tcp=#{backend_tcp_port}:tcp6=#{backend_tcp_port_v6}"
        receiver.close
        receiver_v6.close
        tcp_server.close
        tcp_server_v6.close
      else
        netlink.route_add(destination: network, via: gateway, dev: peer, family: "ipv4")
        netlink.route_add(destination: network_v6, via: gateway_v6, dev: peer, family: "ipv6")
        puts "peer-ready=#{peer_mac}"
        STDIN.gets
        sender = UDPSocket.new(Socket::AF_INET)
        sender.bind(peer_ip, 0)
        source_port = sender.local_address.ip_port
        sender.send("baseline", 0, backend_ip, backend_port)
        ready_sockets = IO.select([sender], nil, nil, 5.0)
        raise "routed veth baseline did not return" unless ready_sockets
        baseline, = sender.recvfrom(128)
        raise "unexpected routed veth baseline #{baseline.inspect}" unless baseline == "baseline-reply"
        puts "baseline=ok"
        sender.send("isolated-tc-packet", 0, service_ip, port)
        ready_sockets = IO.select([sender], nil, nil, 5.0)
        raise "reverse packet did not traverse TC egress" unless ready_sockets
        response, address = sender.recvfrom(128)
        raise "unexpected reverse payload #{response.inspect}" unless response == "isolated-tc-reply"
        raise "reverse SNAT did not restore the Service VIP: address=#{address.inspect} expected=#{service_ip}:#{port}" unless address[3] == service_ip && address[1] == port
        puts "reply4=#{response}:#{address[3]}:#{address[1]}:src=#{source_port}"
        sender.send("isolated-nodeport", 0, service_ip, node_port)
        ready_sockets = IO.select([sender], nil, nil, 5.0)
        raise "NodePort reverse packet did not traverse TC egress" unless ready_sockets
        response, address = sender.recvfrom(128)
        raise "unexpected NodePort reverse payload #{response.inspect}" unless response == "isolated-nodeport-reply"
        raise "NodePort wildcard reverse source was not restored" unless address[3] == service_ip && address[1] == node_port
        puts "nodeport4=#{response}:#{address[3]}:#{address[1]}"
        sender.close
        sender_v6 = UDPSocket.new(Socket::AF_INET6)
        sender_v6.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 1)
        sender_v6.bind("::", 0)
        source_port_v6 = sender_v6.local_address.ip_port
        sender_v6.send("baseline6", 0, backend_ip_v6, backend_port_v6)
        ready_sockets = IO.select([sender_v6], nil, nil, 5.0)
        raise "routed IPv6 veth baseline did not return" unless ready_sockets
        baseline, = sender_v6.recvfrom(128)
        raise "unexpected routed IPv6 veth baseline #{baseline.inspect}" unless baseline == "baseline6-reply"
        sender_v6.send("isolated-tc-packet6", 0, service_ip_v6, port)
        ready_sockets = IO.select([sender_v6], nil, nil, 5.0)
        raise "IPv6 reverse packet did not traverse TC egress" unless ready_sockets
        response, address = sender_v6.recvfrom(128)
        raise "unexpected IPv6 reverse payload #{response.inspect}" unless response == "isolated-tc-reply6"
        raise "IPv6 reverse SNAT did not restore the Service VIP" unless address[3] == service_ip_v6 && address[1] == port
        puts "reply6=#{response}:#{address[3]}:#{address[1]}:src=#{source_port_v6}"
        sender_v6.send("isolated-nodeport6", 0, service_ip_v6, node_port)
        ready_sockets = IO.select([sender_v6], nil, nil, 5.0)
        raise "IPv6 NodePort reverse packet did not traverse TC egress" unless ready_sockets
        response, address = sender_v6.recvfrom(128)
        raise "unexpected IPv6 NodePort reverse payload #{response.inspect}" unless response == "isolated-nodeport-reply6"
        raise "IPv6 NodePort wildcard reverse source was not restored" unless address[3] == service_ip_v6 && address[1] == node_port
        puts "nodeport6=#{response}:#{address[3]}:#{address[1]}"
        sender_v6.close
        tcp_socket = Timeout.timeout(5) { TCPSocket.new(service_ip, tcp_port) }
        tcp_peer = tcp_socket.peeraddr
        tcp_socket.write("isolated-tc-tcp")
        tcp_socket.close_write
        tcp_response = tcp_socket.read(128)
        raise "unexpected TCP reverse payload #{tcp_response.inspect}" unless tcp_response == "isolated-tc-tcp-reply"
        raise "TCP reverse SNAT did not restore the Service VIP" unless tcp_peer[3] == service_ip && tcp_peer[1] == tcp_port
        puts "tcp4=#{tcp_response}:#{tcp_peer[3]}:#{tcp_peer[1]}"
        tcp_socket.close
        tcp_socket_v6 = Timeout.timeout(5) { TCPSocket.new(service_ip_v6, tcp_port) }
        tcp_peer_v6 = tcp_socket_v6.peeraddr
        tcp_socket_v6.write("isolated-tc-tcp6")
        tcp_socket_v6.close_write
        tcp_response = tcp_socket_v6.read(128)
        raise "unexpected IPv6 TCP reverse payload #{tcp_response.inspect}" unless tcp_response == "isolated-tc-tcp-reply6"
        raise "IPv6 TCP reverse SNAT did not restore the Service VIP" unless tcp_peer_v6[3] == service_ip_v6 && tcp_peer_v6[1] == tcp_port
        puts "tcp6=#{tcp_response}:#{tcp_peer_v6[3]}:#{tcp_peer_v6[1]}"
        tcp_socket_v6.close
      end
    CHILD

    def skip_for_capability(error)
      return false if error.respond_to?(:verifier_log)

      errno = error.respond_to?(:errno) ? error.errno : nil
      return false unless SKIPPABLE_ERRNOS.include?(errno)

      warn "SKIP: kernel denied eBPF/veth integration capability (errno #{errno})"
      exit 77
    end

    def set_sysctl(path, value, originals)
      originals[path] = File.read(path).strip
      File.write(path, "#{value}\n")
    rescue Errno::EACCES, Errno::EPERM, Errno::EROFS => error
      raise Rubernetes::Platform::Linux::Error.new(errno: error.errno, operation: "sysctl #{path}")
    rescue Errno::ENOENT => error
      raise Rubernetes::Platform::Linux::Error.new(errno: error.errno, operation: "sysctl #{path}")
    end

    def spawn_child(role:, peer:, prefix:, peer_ip:, peer_ip_v6:, network:, network_v6:, gateway:, gateway_v6:, remote:, remote_v6:, service_ip:, service_ip_v6:)
      environment = {
        "RK_PROXY_ROLE" => role,
        "RK_PROXY_PEER" => peer,
        "RK_PROXY_PREFIX" => prefix.to_s,
        "RK_PROXY_PEER_IP" => peer_ip,
        "RK_PROXY_PEER_IP_V6" => peer_ip_v6,
        "RK_PROXY_NETWORK" => network,
        "RK_PROXY_NETWORK_V6" => network_v6,
        "RK_PROXY_GATEWAY" => gateway,
        "RK_PROXY_GATEWAY_V6" => gateway_v6,
        "RK_PROXY_REMOTE" => remote,
        "RK_PROXY_REMOTE_V6" => remote_v6,
        "RK_PROXY_BACKEND_IP" => BACKEND_PEER_IP,
        "RK_PROXY_BACKEND_EXTRA_IP" => BACKEND_EXTRA_IP,
        "RK_PROXY_BACKEND_EXTRA_IP_V6" => BACKEND_EXTRA_IP_V6,
        "RK_PROXY_BACKEND_IP_V6" => BACKEND_PEER_IP_V6,
        "RK_PROXY_SERVICE_IP" => service_ip,
        "RK_PROXY_SERVICE_IP_V6" => service_ip_v6,
        "RK_PROXY_PORT" => PORT.to_s,
        "RK_PROXY_NODE_PORT" => NODE_PORT.to_s,
        "RK_PROXY_BACKEND_PORT" => BACKEND_PORT.to_s,
        "RK_PROXY_BACKEND_PORT_V6" => BACKEND_PORT_V6.to_s,
        "RK_PROXY_TCP_PORT" => TCP_PORT.to_s,
        "RK_PROXY_BACKEND_TCP_PORT" => BACKEND_TCP_PORT.to_s,
        "RK_PROXY_BACKEND_TCP_PORT_V6" => BACKEND_TCP_PORT_V6.to_s
      }
      stdin, stdout, stderr, thread = Open3.popen3(environment, "unshare", "-n", "--", RbConfig.ruby,
                                                    "-Ilib", "-e", CHILD_SCRIPT)
      ready = Timeout.timeout(3) { stdout.gets }
      unless ready&.strip == "ready"
        detail = stderr.read
        raise "isolated #{role} process did not start: #{detail}"
      end
      {stdin: stdin, stdout: stdout, stderr: stderr, thread: thread}
    rescue Errno::ENOENT, Timeout::Error => error
      raise Rubernetes::Platform::Linux::Error.new(errno: Errno::EPERM::Errno,
                                                   operation: "isolated #{role} namespace: #{error.message}")
    end

    netlink = Rubernetes::Network::Netlink.new
    adapter = nil
    children = {}
    namespaces = []
    host_links = [CLIENT_HOST, BACKEND_HOST]
    originals = {}

    begin
      set_sysctl("/proc/sys/net/ipv4/ip_forward", "1", originals)
      set_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1", originals)
      set_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0", originals)
      set_sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0", originals)
      children[:client] = spawn_child(role: "client", peer: CLIENT_PEER, prefix: 30, peer_ip: CLIENT_PEER_IP,
                                      peer_ip_v6: CLIENT_PEER_IP_V6, network: BACKEND_NETWORK,
                                      network_v6: BACKEND_NETWORK_V6, gateway: CLIENT_HOST_IP,
                                      gateway_v6: CLIENT_HOST_IP_V6, remote: CLIENT_PEER_IP,
                                      remote_v6: CLIENT_PEER_IP_V6, service_ip: CLIENT_HOST_IP,
                                      service_ip_v6: CLIENT_HOST_IP_V6)
      children[:backend] = spawn_child(role: "backend", peer: BACKEND_PEER, prefix: 29, peer_ip: BACKEND_PEER_IP,
                                       peer_ip_v6: BACKEND_PEER_IP_V6, network: CLIENT_NETWORK,
                                       network_v6: CLIENT_NETWORK_V6, gateway: BACKEND_HOST_IP,
                                       gateway_v6: BACKEND_HOST_IP_V6, remote: CLIENT_PEER_IP,
                                       remote_v6: CLIENT_PEER_IP_V6, service_ip: CLIENT_HOST_IP,
                                       service_ip_v6: CLIENT_HOST_IP_V6)

      client_namespace = File.open("/proc/#{children.fetch(:client).fetch(:thread).pid}/ns/net", "rb")
      backend_namespace = File.open("/proc/#{children.fetch(:backend).fetch(:thread).pid}/ns/net", "rb")
      namespaces.concat([client_namespace, backend_namespace])
      # Create each veth only after its destination namespace exists.  The
      # nested VETH_INFO_PEER/IFLA_NET_NS_FD attribute moves the peer during
      # RTM_NEWLINK; link_set(namespace_fd:) would first enter the destination
      # namespace and therefore could not resolve the still-parent-side peer.
      netlink.link_add(name: CLIENT_HOST, kind: "veth", peer: CLIENT_PEER, up: false,
                       namespace_fd: client_namespace)
      netlink.link_add(name: BACKEND_HOST, kind: "veth", peer: BACKEND_PEER, up: false,
                       namespace_fd: backend_namespace)
      mac_for = lambda do |name|
        address = Socket.getifaddrs.find do |entry|
          entry.name == name && entry.addr && entry.addr.pfamily == Socket::AF_PACKET
        end
        address&.addr&.inspect.to_s[/hwaddr=([0-9a-f:]+)/i, 1]
      end
      client_host_mac = mac_for.call(CLIENT_HOST)
      backend_host_mac = mac_for.call(BACKEND_HOST)
      raise "could not read host veth MAC" unless client_host_mac && backend_host_mac
      netlink.link_set(name: CLIENT_HOST, up: true)
      netlink.link_set(name: BACKEND_HOST, up: true)
      netlink.address_add(address: "#{CLIENT_HOST_IP}/30", name: CLIENT_HOST)
      netlink.address_add(address: "#{BACKEND_HOST_IP}/29", name: BACKEND_HOST)
      netlink.address_add(address: "#{CLIENT_HOST_IP_V6}/64", name: CLIENT_HOST, ifa_flags: 0x02)
      netlink.address_add(address: "#{BACKEND_HOST_IP_V6}/64", name: BACKEND_HOST, ifa_flags: 0x02)
      # Disable per-device reverse-path filtering as well; forwarding is
      # intentionally asymmetric while the reverse conntrack rewrite runs.
      [CLIENT_HOST, BACKEND_HOST].each do |name|
        set_sysctl("/proc/sys/net/ipv4/conf/#{name}/rp_filter", "0", originals)
      end

      endpoint = Proxy::Endpoint.new(address: BACKEND_PEER_IP, port: BACKEND_PORT, protocol: "UDP")
      endpoint_extra = Proxy::Endpoint.new(address: BACKEND_EXTRA_IP, port: BACKEND_PORT, protocol: "UDP")
      endpoint_v6 = Proxy::Endpoint.new(address: BACKEND_PEER_IP_V6, port: BACKEND_PORT_V6, protocol: "UDP")
      endpoint_extra_v6 = Proxy::Endpoint.new(address: BACKEND_EXTRA_IP_V6, port: BACKEND_PORT_V6, protocol: "UDP")
      tcp_endpoint = Proxy::Endpoint.new(address: BACKEND_PEER_IP, port: BACKEND_TCP_PORT, protocol: "TCP")
      tcp_endpoint_extra = Proxy::Endpoint.new(address: BACKEND_EXTRA_IP, port: BACKEND_TCP_PORT, protocol: "TCP")
      tcp_endpoint_v6 = Proxy::Endpoint.new(address: BACKEND_PEER_IP_V6, port: BACKEND_TCP_PORT_V6, protocol: "TCP")
      tcp_endpoint_extra_v6 = Proxy::Endpoint.new(address: BACKEND_EXTRA_IP_V6, port: BACKEND_TCP_PORT_V6, protocol: "TCP")
      rule = Proxy::Rule.new(service_key: "default/web", service_type: "ClusterIP", kind: "ClusterIP",
                             virtual_ip: CLIENT_HOST_IP, port: PORT, protocol: "UDP", backends: [endpoint, endpoint_extra],
                             session_affinity: "ClientIP")
      rule_v6 = Proxy::Rule.new(service_key: "default/web", service_type: "ClusterIP", kind: "ClusterIP",
                                virtual_ip: CLIENT_HOST_IP_V6, port: PORT, protocol: "UDP", backends: [endpoint_v6, endpoint_extra_v6],
                                session_affinity: "ClientIP")
      node_rule = Proxy::Rule.new(service_key: "default/web-nodeport", service_type: "NodePort", kind: "NodePort",
                                  virtual_ip: nil, port: PORT, node_port: NODE_PORT, protocol: "UDP",
                                  backends: [endpoint, endpoint_extra])
      node_rule_v6 = Proxy::Rule.new(service_key: "default/web-nodeport", service_type: "NodePort", kind: "NodePort",
                                     virtual_ip: nil, port: PORT, node_port: NODE_PORT, protocol: "UDP",
                                     backends: [endpoint_v6, endpoint_extra_v6])
      tcp_rule = Proxy::Rule.new(service_key: "default/web-tcp", service_type: "ClusterIP", kind: "ClusterIP",
                                 virtual_ip: CLIENT_HOST_IP, port: TCP_PORT, protocol: "TCP", backends: [tcp_endpoint, tcp_endpoint_extra])
      tcp_rule_v6 = Proxy::Rule.new(service_key: "default/web-tcp", service_type: "ClusterIP", kind: "ClusterIP",
                                    virtual_ip: CLIENT_HOST_IP_V6, port: TCP_PORT, protocol: "TCP", backends: [tcp_endpoint_v6, tcp_endpoint_extra_v6])
      backend = Struct.new(:rules).new([rule, rule_v6, node_rule, node_rule_v6, tcp_rule, tcp_rule_v6])
      adapter = Proxy::LinuxEBPFAdapter.new(interface: CLIENT_HOST, map_layout: LAYOUT)
      result = adapter.attach(hook: :tc, backend: backend)
      raise "kernel identity readback was not verified" unless result[:verified]
      raise "both TC directions were not attached" unless result[:links].length == 2
      raise "attach identity verification failed" unless adapter.verify_attach(
        result: result, expected: {program: adapter.compile_program}, backend: backend
      )

      key, value = adapter.send(:encode_service_rule, rule)
      observed = adapter.bpf.map_lookup(map: adapter.maps.fetch("service_rules"), key: key,
                                        resource_id: "test:proxy:service-rule:lookup")
      raise "service rule map readback mismatch" unless observed == value
      backend_key, backend_value = adapter.send(:encode_backend, endpoint,
                                                 token: adapter.send(:service_token, rule), index: 0, family: 4)
      backend_observed = adapter.bpf.map_lookup(map: adapter.maps.fetch("backends"), key: backend_key,
                                                resource_id: "test:proxy:backend-lookup")
      raise "backend map readback mismatch" unless backend_observed == backend_value
      backend_key_extra, backend_value_extra = adapter.send(:encode_backend, endpoint_extra,
                                                             token: adapter.send(:service_token, rule), index: 1, family: 4)
      backend_observed_extra = adapter.bpf.map_lookup(map: adapter.maps.fetch("backends"), key: backend_key_extra,
                                                      resource_id: "test:proxy:backend-extra-lookup")
      raise "second backend map readback mismatch" unless backend_observed_extra == backend_value_extra
      key_v6, value_v6 = adapter.send(:encode_service_rule, rule_v6)
      observed_v6 = adapter.bpf.map_lookup(map: adapter.maps.fetch("service_rules"), key: key_v6,
                                            resource_id: "test:proxy:service-rule-v6-lookup")
      raise "IPv6 service rule map readback mismatch" unless observed_v6 == value_v6
      backend_key_v6, backend_value_v6 = adapter.send(:encode_backend, endpoint_v6,
                                                       token: adapter.send(:service_token, rule_v6), index: 0, family: 6)
      backend_observed_v6 = adapter.bpf.map_lookup(map: adapter.maps.fetch("backends"), key: backend_key_v6,
                                                   resource_id: "test:proxy:backend-v6-lookup")
      raise "IPv6 backend map readback mismatch" unless backend_observed_v6 == backend_value_v6
      backend_key_extra_v6, backend_value_extra_v6 = adapter.send(:encode_backend, endpoint_extra_v6,
                                                                   token: adapter.send(:service_token, rule_v6), index: 1, family: 6)
      backend_observed_extra_v6 = adapter.bpf.map_lookup(map: adapter.maps.fetch("backends"), key: backend_key_extra_v6,
                                                         resource_id: "test:proxy:backend-extra-v6-lookup")
      raise "second IPv6 backend map readback mismatch" unless backend_observed_extra_v6 == backend_value_extra_v6
      node_key, node_value = adapter.send(:encode_service_rule, node_rule)
      node_observed = adapter.bpf.map_lookup(map: adapter.maps.fetch("service_rules"), key: node_key,
                                              resource_id: "test:proxy:nodeport-v4-lookup")
      raise "NodePort service rule map readback mismatch" unless node_observed == node_value
      node_key_v6, node_value_v6 = adapter.send(:encode_service_rule, node_rule_v6)
      node_observed_v6 = adapter.bpf.map_lookup(map: adapter.maps.fetch("service_rules"), key: node_key_v6,
                                                resource_id: "test:proxy:nodeport-v6-lookup")
      raise "IPv6 NodePort service rule map readback mismatch" unless node_observed_v6 == node_value_v6

      children.fetch(:client).fetch(:stdin).write("go #{client_host_mac}\n")
      children.fetch(:client).fetch(:stdin).flush
      children.fetch(:backend).fetch(:stdin).write("go #{backend_host_mac}\n")
      children.fetch(:backend).fetch(:stdin).flush
      backend_stdout = children.fetch(:backend).fetch(:stdout)
      client_peer_ready = Timeout.timeout(3) { children.fetch(:client).fetch(:stdout).gets }
      backend_peer_ready = Timeout.timeout(3) { children.fetch(:backend).fetch(:stdout).gets }
      raise "client veth peer did not become ready: #{children.fetch(:client).fetch(:stderr).read.inspect}" unless client_peer_ready&.start_with?("peer-ready=")
      raise "backend veth peer did not become ready: #{children.fetch(:backend).fetch(:stderr).read.inspect}" unless backend_peer_ready&.start_with?("peer-ready=")
      backend_ready = Timeout.timeout(3) { backend_stdout.gets }
      raise "backend did not become ready" unless backend_ready&.strip == "backend-ready"
      [[CLIENT_PEER_IP_V6, CLIENT_HOST, client_peer_ready.split("=", 2).last.strip],
       [BACKEND_PEER_IP_V6, BACKEND_HOST, backend_peer_ready.split("=", 2).last.strip]].each do |destination, dev, mac|
        begin
          netlink.neighbor_add(destination: destination, dev: dev, lladdr: mac, family: "ipv6")
        rescue Rubernetes::Network::NetlinkError => error
          raise unless error.errno == Errno::EEXIST::Errno
        end
      end
      children.fetch(:client).fetch(:stdin).write("run\n")
      children.fetch(:client).fetch(:stdin).flush
      children.fetch(:backend).fetch(:stdin).write("run\n")
      children.fetch(:backend).fetch(:stdin).flush
      children.fetch(:client).fetch(:stdin).close
      children.fetch(:client)[:stdin] = nil
      baseline = begin
        Timeout.timeout(5) { children.fetch(:client).fetch(:stdout).gets }
      rescue Timeout::Error => error
        children.each do |role, child|
          warn "#{role} baseline timeout alive=#{child.fetch(:thread).alive?} status=#{child.fetch(:thread).value.inspect} stderr=#{child.fetch(:stderr).read.inspect}"
        end
        raise error
      end
      if baseline.nil?
        children.each do |role, child|
          warn "#{role} baseline eof alive=#{child.fetch(:thread).alive?} status=#{child.fetch(:thread).value.inspect} stderr=#{child.fetch(:stderr).read.inspect}"
        end
      end
      raise "routed veth baseline was not reported" unless baseline&.strip == "baseline=ok"
      client_stdout = children.fetch(:client).fetch(:stdout)
      unless IO.select([client_stdout], nil, nil, 5.0)
        details = children.map do |role, child|
          "#{role} alive=#{child.fetch(:thread).alive?} status=#{child.fetch(:thread).value.inspect} stderr=#{child.fetch(:stderr).read.inspect}"
        end.join("; ")
        raise "reply wait timeout: #{details}"
      end
      reply = client_stdout.gets
      unless reply&.strip&.start_with?("reply4=isolated-tc-reply:#{CLIENT_HOST_IP}:#{PORT}")
        details = children.map do |role, child|
          "#{role} status=#{child.fetch(:thread).value.inspect} stderr=#{child.fetch(:stderr).read.inspect}"
        end.join("; ")
        raise "reverse SNAT proof was not reported: #{reply.inspect}; #{details}"
      end
      raise "IPv4 NodePort reply timeout" unless IO.select([client_stdout], nil, nil, 5.0)
      nodeport_reply = client_stdout.gets
      raise "IPv4 NodePort reverse SNAT proof was not reported" unless nodeport_reply&.start_with?("nodeport4=isolated-nodeport-reply:#{CLIENT_HOST_IP}:#{NODE_PORT}")
      raise "IPv6 reply timeout" unless IO.select([client_stdout], nil, nil, 5.0)
      reply6 = client_stdout.gets
      raise "IPv6 reverse SNAT proof was not reported" unless reply6&.start_with?("reply6=isolated-tc-reply6:#{CLIENT_HOST_IP_V6}:#{PORT}")
      raise "IPv6 NodePort reply timeout" unless IO.select([client_stdout], nil, nil, 5.0)
      nodeport_reply6 = client_stdout.gets
      raise "IPv6 NodePort reverse SNAT proof was not reported" unless nodeport_reply6&.start_with?("nodeport6=isolated-nodeport-reply6:#{CLIENT_HOST_IP_V6}:#{NODE_PORT}")
      raise "TCP reply timeout" unless IO.select([client_stdout], nil, nil, 5.0)
      tcp_reply = client_stdout.gets
      raise "TCP reverse SNAT proof was not reported" unless tcp_reply&.start_with?("tcp4=isolated-tc-tcp-reply:#{CLIENT_HOST_IP}:#{TCP_PORT}")
      raise "IPv6 TCP reply timeout" unless IO.select([client_stdout], nil, nil, 5.0)
      tcp_reply6 = client_stdout.gets
      raise "IPv6 TCP reverse SNAT proof was not reported" unless tcp_reply6&.start_with?("tcp6=isolated-tc-tcp-reply6:#{CLIENT_HOST_IP_V6}:#{TCP_PORT}")
      unless IO.select([backend_stdout], nil, nil, 3.0)
        details = children.map do |role, child|
          "#{role} alive=#{child.fetch(:thread).alive?} status=#{child.fetch(:thread).value.inspect} stderr=#{child.fetch(:stderr).read.inspect}"
        end.join("; ")
        raise "backend result timeout: #{details}"
      end
      backend_line = backend_stdout.gets
      expected_backend = /backend=dnat:(#{Regexp.escape(BACKEND_PEER_IP)}|#{Regexp.escape(BACKEND_EXTRA_IP)}):#{BACKEND_PORT}:source=#{Regexp.escape(CLIENT_PEER_IP)}:/
      raise "routed backend DNAT proof was not reported" unless backend_line&.match?(expected_backend)
      expected_backend_v6 = /backend6=dnat:(#{Regexp.escape(BACKEND_PEER_IP_V6)}|#{Regexp.escape(BACKEND_EXTRA_IP_V6)}):#{BACKEND_PORT_V6}:source=#{Regexp.escape(CLIENT_PEER_IP_V6)}/
      raise "routed IPv6 backend DNAT proof was not reported" unless backend_line&.match?(expected_backend_v6)
      raise "routed TCP backend DNAT proof was not reported" unless backend_line.include?("tcp=#{BACKEND_TCP_PORT}:tcp6=#{BACKEND_TCP_PORT_V6}")
      source_port = Integer(reply.split("src=", 2).last)
      source_port_v6 = Integer(reply6.split("src=", 2).last)
      packed_ip = ->(value) { adapter.send(:packed_ip, value) }
      conntrack_key = [4, 17, source_port, PORT, 0].pack("CCS<S<S<") +
                      packed_ip.call(CLIENT_PEER_IP) + packed_ip.call(CLIENT_HOST_IP)
      conntrack_value = adapter.bpf.map_lookup(map: adapter.maps.fetch("conntrack"), key: conntrack_key,
                                               resource_id: "test:proxy:conntrack-v4-lookup")
      raise "IPv4 conntrack state was not created" unless conntrack_value
      conntrack_key_v6 = [6, 17, source_port_v6, PORT, 0].pack("CCS<S<S<") +
                         packed_ip.call(CLIENT_PEER_IP_V6) + packed_ip.call(CLIENT_HOST_IP_V6)
      conntrack_value_v6 = adapter.bpf.map_lookup(map: adapter.maps.fetch("conntrack"), key: conntrack_key_v6,
                                                  resource_id: "test:proxy:conntrack-v6-lookup")
      raise "IPv6 conntrack state was not created" unless conntrack_value_v6
      affinity_key = adapter.send(:service_token, rule) + packed_ip.call(CLIENT_PEER_IP)
      affinity_value = adapter.bpf.map_lookup(map: adapter.maps.fetch("client_ip_affinity"), key: affinity_key,
                                              resource_id: "test:proxy:affinity-v4-lookup")
      raise "IPv4 ClientIP affinity state was not created" unless affinity_value
      affinity_key_v6 = adapter.send(:service_token, rule_v6) + packed_ip.call(CLIENT_PEER_IP_V6)
      affinity_value_v6 = adapter.bpf.map_lookup(map: adapter.maps.fetch("client_ip_affinity"), key: affinity_key_v6,
                                                 resource_id: "test:proxy:affinity-v6-lookup")
      raise "IPv6 ClientIP affinity state was not created" unless affinity_value_v6
      empty_backend = Struct.new(:rules).new([])
      update = adapter.update(backend: empty_backend, diff: :delete)
      raise "map update identity was not verified" unless adapter.verify_update(result: update, backend: empty_backend)
      begin
        adapter.bpf.map_lookup(map: adapter.maps.fetch("service_rules"), key: key,
                               resource_id: "test:proxy:service-rule:deleted-lookup")
      rescue Rubernetes::Platform::Linux::Error => error
        raise unless error.errno == Errno::ENOENT::Errno
      else
        raise "deleted service rule remained in the kernel map"
      end
      children.each do |role, child|
        status = child.fetch(:thread).value
        raise "isolated #{role} process failed: #{child.fetch(:stderr).read}" unless status.success?
      end
    rescue Rubernetes::Platform::Linux::Error => error
      warn "verifier-log=#{error.verifier_log}" if error.respond_to?(:verifier_log)
      skip_for_capability(error)
      raise
    ensure
      adapter&.detach rescue nil
      children.each_value do |child|
        child.fetch(:stdin)&.close rescue nil
        if child.fetch(:thread).alive?
          Process.kill("TERM", child.fetch(:thread).pid) rescue nil
          child.fetch(:thread).join
        end
        child.fetch(:stdout).close rescue nil
        child.fetch(:stderr).close rescue nil
      end
      namespaces.each { |namespace| namespace.close rescue nil }
      host_links.each { |name| netlink.link_delete(name: name) rescue nil }
      originals.each { |path, value| File.write(path, "#{value}\n") rescue nil }
    end
  RUBY

  def test_tc_ebpf_service_dnat_reverse_snat_and_map_readback_on_routed_veth_namespaces
    kernel_version = `uname -r`.scan(/\A(\d+)\.(\d+)/).first&.map!(&:to_i)
    environment = {}
    if kernel_version && (kernel_version <=> [6, 12]).negative?
      # Only the SCTP CRC32c sub-feature is pinned to Linux >= 6.12.  The
      # TCP/UDP DNAT, reverse SNAT, conntrack, and TC readback proof below
      # runs on this kernel under an explicit, recorded waiver instead of a
      # silent skip; the adapter surfaces the waiver in its kernel identity.
      environment["RUBERNETES_M4_KERNEL_WAIVER_REASON"] =
        ENV.fetch("RUBERNETES_M4_KERNEL_WAIVER_REASON",
                  "integration test: host #{`uname -r`.strip} < 6.12; SCTP CRC32c release requirement waived for TCP/UDP datapath proof")
    end

    output, error, status = Open3.capture3(
      environment, "unshare", "-n", "--", RbConfig.ruby, "-Ilib", "-e", KERNEL_SCRIPT
    )
    skip error.strip if status.exitstatus == 77 && error.start_with?("SKIP:")
    if !status.success? && error.match?(/Operation not permitted|Permission denied/i)
      skip "missing CAP_SYS_ADMIN/CAP_NET_ADMIN/CAP_BPF for isolated eBPF test: #{error.strip}"
    end

    assert_predicate status, :success?, "isolated eBPF kernel script failed: #{error.empty? ? output : error}"
  rescue Errno::ENOENT => exception
    flunk "unshare is required for the isolated eBPF integration test: #{exception.message}"
  end
end
