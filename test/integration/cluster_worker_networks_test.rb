# frozen_string_literal: true

require "open3"
require "rbconfig"
require_relative "../test_helper"

class ClusterWorkerNetworksTest < Minitest::Test
  CHECK = <<~'RUBY'
    require "rubernetes/cluster"
    require "tmpdir"
    require "timeout"

    def execute(*command)
      output, error, status = Open3.capture3(*command)
      raise "#{command.first} failed: #{error}" unless status.success?

      output.strip
    end

    def peer_ip(worker, ip, source = nil)
      client = <<~CODE
        args = ARGV.take(2)
        args += [ARGV[2], 0] if ARGV[2]
        Socket.tcp(*args, connect_timeout: 2) do |socket|
          raise "backend did not respond" unless IO.select([socket], nil, nil, 2)
          puts socket.gets
        end
      CODE
      execute(*worker, RbConfig.ruby, "-rsocket", "-e", client, "--", ip, "30080", *[source].compact)
    end

    install = <<~CODE
      proxy = Rubernetes::Proxy
      node, ip = ARGV
      compiler = proxy::RuleCompiler.new(local_node: node, node_addresses: [ip])
      service = {"metadata" => {"name" => "local-nodeport", "namespace" => "tests"},
                 "spec" => {"type" => "NodePort", "clusterIP" => "10.96.0.23", "externalTrafficPolicy" => "Local",
                            "ports" => [{"port" => 80, "nodePort" => 30080, "targetPort" => 18080}]}}
      endpoint = proxy::Endpoint.new(address: "10.242.0.10", port: 18080, node_name: "worker-b")
      adapter = proxy::NftablesNetlinkAdapter.new(table_name: "worker_source_check")
      backend = proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
      backend.apply(compiler.compile(service, endpoints: [endpoint]))
      raise "nftables readback failed" unless adapter.send_messages([], backend: backend).fetch("verified")
    CODE
    server = <<~CODE
      listener = TCPServer.new("10.242.0.10", 18080)
      STDOUT.sync = true
      puts "ready"
      4.times do
        socket = listener.accept
        socket.puts socket.peeraddr(false).last
        socket.close
      end
    CODE

    Dir.mktmpdir("worker-source-check") do |directory|
      networks = Rubernetes::Cluster::WorkerNetworks.new(directory, [["10.240.0.0/16"], ["10.242.0.0/16"]])
      networks.prepare!
      a, b = [0, 1].map { |index| networks.command(index) }
      execute(*a, "ip", "addr", "add", "10.240.0.1/32", "dev", "lo")
      execute(*a, "ip", "addr", "add", "10.240.0.225/32", "dev", "lo")
      execute(*b, "ip", "addr", "add", "10.242.0.1/32", "dev", "lo")
      execute(*b, "ip", "addr", "add", "10.242.0.10/32", "dev", "lo")
      execute(*a, RbConfig.ruby, "-Ilib", "-rrubernetes/proxy", "-e", install, "--", "worker-a", "10.240.0.1")
      execute(*b, RbConfig.ruby, "-Ilib", "-rrubernetes/proxy", "-e", install, "--", "worker-b", "10.242.0.1")

      ready, writer = IO.pipe
      pid = Process.spawn(*b, RbConfig.ruby, "-rsocket", "-e", server, out: writer)
      writer.close
      raise "backend listener did not start" unless Timeout.timeout(3) { ready.gets } == "ready\n"

      puts "transit=#{peer_ip(a, "10.242.0.1")}"
      execute(*a, "sysctl", "-qw", "net.ipv6.conf.rbn-uplink.dad_transmits=2")
      execute(*a, "ip", "-6", "addr", "add", "fd00:d8::1/128", "dev", "rbn-uplink")
      added = JSON.parse(execute(*a, "ip", "-j", "-6", "address", "show", "to", "fd00:d8::1/128"))
      tentative = added.any? do |link|
        link.fetch("addr_info").any? { |address| address["local"] == "fd00:d8::1" && address["tentative"] }
      end
      raise "IPv6 source is not performing duplicate address detection" unless tentative
      networks.prefer_node_sources!(0, ["10.240.0.1", "fd00:d8::1"])
      puts "cross_worker=#{peer_ip(a, "10.242.0.1")}"
      puts "host_fallback=#{peer_ip(a, "10.240.0.1", "10.240.0.1")}"
      puts "host_alias=#{peer_ip(a, "10.240.0.1", "10.240.0.225")}"
      route = execute(*a, "ip", "-6", "route", "get", "fd00:d8:2::10")
      puts "ipv6_source=#{route[/\bsrc (\S+)/, 1]}"
    ensure
      ready&.close
      writer&.close unless writer&.closed?
      if pid
        Process.kill(:TERM, pid) rescue nil
        Process.wait(pid) rescue nil
      end
      networks&.cleanup!
    end
  RUBY

  def test_local_node_ports_keep_the_advertised_client_ip_across_worker_uplinks
    output, error, status = Open3.capture3("unshare", "-m", "-n", "--propagation", "private", "--", RbConfig.ruby, "-Ilib", "-e", CHECK)
    skip error.strip if error.match?(/\Aunshare: .*Operation not permitted/)

    assert_predicate status, :success?, error
    assert_equal %w[transit=169.254.128.2 cross_worker=10.240.0.1 host_fallback=10.240.0.1 host_alias=169.254.128.2 ipv6_source=fd00:d8::1],
                 output.lines.map(&:strip)
  end
end
