# frozen_string_literal: true

require "open3"
require "rbconfig"
require_relative "../test_helper"

class ProxyServiceAvailabilityTest < Minitest::Test
  PACKET_CHECK = <<~'RUBY'
    require "ipaddr"
    require "socket"
    require "timeout"
    require "rubernetes/proxy"

    proxy = Rubernetes::Proxy
    mode, family = ARGV
    vip, node_ip, endpoint_ip = if family == "IPv4"
                                  %w[192.0.2.10 192.0.2.11 192.0.2.12]
                                else
                                  %w[2001:db8::10 2001:db8::11 2001:db8::12]
                                end
    prefix = family == "IPv4" ? 32 : 128
    system("ip", "link", "set", "lo", "up") or abort "could not bring up loopback"
    [vip, node_ip, endpoint_ip].each do |address|
      system("ip", "addr", "add", "#{address}/#{prefix}", "dev", "lo", "nodad") or abort "could not add #{address}"
    end

    service = {
      "apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "available", "namespace" => "tests"},
      "spec" => {"type" => "NodePort", "clusterIP" => vip, "ipFamilies" => [family],
                 "ports" => [{"port" => 10_800, "targetPort" => 18_080, "nodePort" => 30_080}]}
    }
    compiler = proxy::RuleCompiler.new(local_node: "worker-a", node_addresses: [node_ip])
    sentinel_vip = TCPServer.new(vip, 10_800)
    sentinel_node = TCPServer.new(node_ip, 30_080)
    listener = TCPServer.new(endpoint_ip, 18_080)
    if mode == "nftables"
      adapter = proxy::NftablesNetlinkAdapter.new(table_name: "rk_nft_avail_#{Process.pid}", timeout: 2)
      backend = proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
      sync = lambda do |compiled|
        backend.apply(compiled)
        result = adapter.send_messages([], backend: backend)
        raise "nftables rules did not match kernel readback" unless result.fetch("verified")
      end
    else
      adapter = proxy::Iptables::Adapter.new
      adapter.ensure_jump_chains(family)
      renderer = proxy::Iptables::Renderer.new(family: family, node_name: "worker-a")
      sync = lambda do |compiled|
        program = renderer.render(compiled.rules, existing_chains: adapter.nat_chains(family))
        adapter.restore(program.text, family)
      end
    end

    def refused!(address, port)
      if address.include?(":")
        icmp = Socket.new(Socket::AF_INET6, Socket::SOCK_RAW, Socket::IPPROTO_ICMPV6)
      end
      begin
        Socket.tcp(address, port, connect_timeout: 0.25) { raise "#{address}:#{port} was accepted with no endpoints" }
      rescue Errno::ECONNREFUSED
        nil
      rescue Errno::ETIMEDOUT
        raise unless icmp
      end
      return unless icmp

      # The Linux local TCP socket may time out despite the kernel emitting a
      # port-unreachable ICMPv6 reply. Inspect the quoted destination and port.
      Timeout.timeout(1) do
        loop do
          packet = icmp.recv(128)
          break if packet.start_with?("\x01\x04".b) && packet.byteslice(32, 16) == IPAddr.new(address).hton && packet.byteslice(50, 2) == [port].pack("n")
        end
      end
    ensure
      icmp&.close
    end

    # A service IP or port would otherwise reach its sentinel listener, so a
    # refused connection proves a verdict from the installed rules.
    sync.call(compiler.compile(service, endpoints: [], revision: 1))
    refused!(vip, 10_800)
    refused!(node_ip, 30_080)

    service.fetch("spec").merge!("internalTrafficPolicy" => "Local", "externalTrafficPolicy" => "Local")
    remote = proxy::Endpoint.new(address: endpoint_ip, port: 18_080, node_name: "worker-b")
    sync.call(compiler.compile(service, endpoints: [remote], revision: 2))
    icmp = Socket.new(Socket::AF_INET6, Socket::SOCK_RAW, Socket::IPPROTO_ICMPV6) if family == "IPv6"
    begin
      Socket.tcp(vip, 10_800, connect_timeout: 0.25) { raise "ClusterIP accepted traffic without a local endpoint" }
    rescue Errno::ETIMEDOUT, IO::TimeoutError
      # Upstream drops packets when there are eligible endpoints elsewhere.
    end
    raise "ClusterIP emitted ICMPv6 instead of dropping traffic" if icmp && IO.select([icmp], nil, nil, 0)
    icmp&.close

    Timeout.timeout(2) do
      Socket.tcp(node_ip, 30_080, connect_timeout: 1) do |client|
        endpoint = listener.accept
        endpoint.write("routed")
        raise "host NodePort traffic did not reach the cluster endpoint" unless client.read(6) == "routed"
      ensure
        endpoint&.close
      end
    end

    sync.call(compiler.compile(service, endpoints: [], revision: 3))
    refused!(vip, 10_800)
    refused!(node_ip, 30_080)
    puts "#{mode} #{family} verified refusal, local drop and host short circuit"
  RUBY

  def test_nftables_service_availability_on_ipv4_and_ipv6
    verify_mode("nftables")
  end

  def test_iptables_service_availability_on_ipv4_and_ipv6
    verify_mode("iptables")
  end

  private

  def verify_mode(mode)
    %w[IPv4 IPv6].each do |family|
      output, error, status = Open3.capture3("unshare", "-n", "--", RbConfig.ruby, "-Ilib", "-e", PACKET_CHECK, "--", mode, family)
      skip error.strip if error.match?(/\Aunshare: .*Operation not permitted/)

      assert_predicate status, :success?, "#{mode} #{family}: #{error}#{output}"
      assert_includes output, "#{mode} #{family} verified refusal, local drop and host short circuit"
    end
  end
end
