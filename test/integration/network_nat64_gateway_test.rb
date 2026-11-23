# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"

class NetworkNAT64GatewayTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'
    require "open3"
    require "tmpdir"
    require "rubernetes/bootstrap/assembler"

    Wire = Rubernetes::Network::DNS::Wire
    PREFIX = "2001:db8:64::/96"
    UPSTREAM = "198.51.100.53"

    def run(*command)
      system(*command, exception: true)
    end

    def new_namespace
      input, output, child = Open3.popen2("unshare", "--net", RbConfig.ruby, "-e", "puts Process.pid; STDOUT.flush; STDIN.read")
      raise "network namespace failed to start" unless output.wait_readable(5) && Integer(output.gets) == child.pid

      [input, output, child]
    end

    def namespace_commands(pid)
      ["nsenter", "--target", pid.to_s, "--net", "--"]
    end

    Dir.mktmpdir("nat64-") do |directory|
      begin
        pod_ns = new_namespace
        gateway_ns = new_namespace
        pod_pid = pod_ns.last.pid
        gateway_pid = gateway_ns.last.pid
        gateway = namespace_commands(gateway_pid)
        run("ip", "link", "set", "lo", "up")
        run("ip", "addr", "add", "#{UPSTREAM}/32", "dev", "lo")
        run("ip", "link", "add", "node-wan", "type", "veth", "peer", "name", "gateway-wan", "netns", gateway_pid.to_s)
        run("ip", "link", "set", "node-wan", "up")
        run("ip", "-6", "addr", "add", "fd11:2::1/64", "dev", "node-wan", "nodad")
        run("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
        run(*gateway, "ip", "link", "set", "lo", "up")
        run(*gateway, "ip", "addr", "add", "192.0.2.33/32", "dev", "lo")
        run(*gateway, "ip", "link", "set", "gateway-wan", "up")
        run(*gateway, "ip", "-6", "addr", "add", "fd11:2::2/64", "dev", "gateway-wan", "nodad")
        run(*gateway, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
        run(*gateway, "ip", "tuntap", "add", "dev", "nat64", "mode", "tun", "pi")
        run(*gateway, "ip", "link", "set", "nat64", "up")
        run(*gateway, "ip", "-6", "route", "add", PREFIX, "dev", "nat64")
        run(*gateway, "ip", "-4", "route", "add", "192.0.2.128/25", "dev", "nat64")
        run(*gateway, "ip", "-6", "route", "add", "fd11:1::/64", "via", "fd11:2::1")
        run("ip", "-6", "route", "add", PREFIX, "via", "fd11:2::2")
        translator_config = File.join(directory, "tayga.conf")
        File.write(translator_config, <<~CONFIG)
          tun-device nat64
          ipv4-addr 192.0.2.1
          prefix #{PREFIX}
          dynamic-pool 192.0.2.128/25
        CONFIG
        translator = Process.spawn(*gateway, ARGV.fetch(0), "-d", "--config", translator_config)
        File.open(File.join(directory, "server.rb"), "w") do |file|
          file.write('server = TCPServer.new("192.0.2.33", 18080); puts "ready"; STDOUT.flush; server.accept.puts("ipv4 endpoint")')
        end
        ipv4_input, ipv4_server, ipv4_child = Open3.popen2e(*gateway, RbConfig.ruby, "-rsocket", File.join(directory, "server.rb"))
        ipv4_input.close
        raise "IPv4 origin not ready" unless ipv4_server.wait_readable(5) && ipv4_server.gets == "ready\n"

        ipam = Rubernetes::Network::IPAM.new(ipv6_cidr: "fd11:1::/64", ipv6_node_prefix: 64)
        netlink = Rubernetes::Network::Netlink.new
        observer = Rubernetes::Network::NativeObserver.new(netlink: netlink)
        network = Rubernetes::Network::Interface.new(ipam: ipam, netlink: netlink, observer: observer, require_observer: true)

        upstream = UDPSocket.new
        upstream.bind(UPSTREAM, 53)
        requests = Thread.new do
          2.times.map do
            bytes, from = upstream.recvfrom(4096)
            query = Wire.decode(bytes)
            question = query.questions.fetch(0)
            answers = if question.type == Wire::TYPE_A
                        [Wire::Record.new(name: question.name, type: Wire::TYPE_A, klass: Wire::CLASS_IN, ttl: 30, rdata: "192.0.2.33")]
                      else
                        []
                      end
            upstream.send(Wire.encode(Wire::Message.new(id: query.id, qr: true, ra: true, questions: [question], answers: answers)),
                          0, from.fetch(3), from.fetch(1))
            question.type
          end
        end

        process = "rubernetes-agent"
        agent_config = File.join(directory, "agent.yml")
        File.write(agent_config, YAML.dump("processes" => {
          process => {"node_name" => "nat64", "runtime_profile" => "kernel_isolation",
                      "dns" => {"nat64_prefix" => PREFIX, "upstreams" => [UPSTREAM]}}
        }))
        config = Rubernetes::Bootstrap::Config.load(process_name: process, path: agent_config)
        dependencies = Rubernetes::Bootstrap::Container.new.register(:config, config).register(:network, network)
          .register(:api_client, Object.new).register(:logger, nil)
        dns = Rubernetes::Bootstrap::Assembler.new(process_name: process).send(:build_dns_service, dependencies)
        dns.server.start

        pod_netns = "/proc/#{pod_pid}/ns/net"
        pidfd = IO.for_fd(Rubernetes::Platform::Linux::Pidfd.new.open(pid: pod_pid))
        start_time = File.binread("/proc/#{pod_pid}/stat").rpartition(") ").last.split.fetch(19).to_i
        network.add({"sandbox_id" => "nat64-pod", "netns" => {"handle" => "nat64-pod", "path" => pod_netns,
                     "inode" => File.stat(pod_netns).ino, "pid" => pod_pid, "pidfd" => pidfd.fileno, "start_time" => start_time}})

        pod = namespace_commands(pod_pid)
        ipv4_addresses, status = Open3.capture2(*pod, "ip", "-4", "addr", "show", "scope", "global")
        raise "Pod unexpectedly has IPv4" unless status.success? && ipv4_addresses.empty?

        run(*pod, RbConfig.ruby, "-rresolv", "-rsocket", "-e", <<~'CLIENT')
          resolver = Resolv::DNS.new(nameserver: ["fd11:1::1"], search: [], ndots: 1)
          address = resolver.getresource("ipv4.example.test", Resolv::DNS::Resource::IN::AAAA).address.to_s
          abort "unexpected DNS64 record: #{address}" unless address == "2001:db8:64::c000:221"
          result = Socket.tcp(address, 18080, connect_timeout: 5, &:gets)
          abort "IPv4 endpoint did not respond" unless result == "ipv4 endpoint\n"
        CLIENT
        raise "DNS64 query did not fall back to A" unless requests.value == [Wire::TYPE_AAAA, Wire::TYPE_A]
      ensure
        dns&.server&.stop
        requests&.kill&.join
        upstream&.close
        pidfd&.close
        [translator, ipv4_child&.pid].compact.each do |pid|
          Process.kill("TERM", pid)
        rescue Errno::ESRCH
          nil
        end
        Process.wait(translator) if translator
        ipv4_child&.join
        ipv4_server&.close
        [pod_ns, gateway_ns].compact.each do |input, output, child|
          input.close
          output.close
          child.join
        end
      end
    end
  RUBY

  def test_ipv6_only_pod_reaches_an_ipv4_origin_through_an_external_nat64_gateway
    tayga = ENV.fetch("RUBERNETES_TEST_TAYGA", "/usr/sbin/tayga")
    skip("needs TAYGA and /dev/net/tun") unless File.executable?(tayga) && File.chardev?("/dev/net/tun")
    skip("needs a network namespace") unless system("unshare", "--net", "true", out: File::NULL, err: File::NULL)

    lib = File.expand_path("../../lib", __dir__)
    output, status = Open3.capture2e("timeout", "30", "unshare", "--net", RbConfig.ruby, "-I", lib, "-e", KERNEL_SCRIPT, tayga)

    assert_predicate status, :success?, output
  end
end
