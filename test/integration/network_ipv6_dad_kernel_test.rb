# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
require_relative "../test_helper"

class NetworkIPv6DADKernelTest < Minitest::Test
  CHECK = <<~'RUBY'
    require "json"
    require "open3"
    require "tmpdir"
    require "rubernetes"

    class ObservedDAD < Rubernetes::Network::NativeObserver
      attr_reader :states, :identities

      def initialize(...)
        super
        @states = []
        @identities = []
      end

      def ipv6_address_observation(operation)
        super.tap do |observation|
          next unless observation

          state, address = observation
          @states << state if @states.last != state
          @identities << address.fetch("identity") if address && !@identities.include?(address.fetch("identity"))
        end
      end
    end

    def exchange(pid, address)
      server = <<~'SERVER'
        listener = TCPServer.new(ARGV.fetch(0), 0)
        puts listener.addr.fetch(1)
        STDOUT.flush
        socket = listener.accept
        socket.puts("dad-ready")
        socket.close
      SERVER
      Open3.popen2("nsenter", "-t", pid.to_s, "-n", "--", RbConfig.ruby, "-rsocket", "-e", server, address) do |input, output, child|
        input.close
        raise "IPv6 listener did not start" unless output.wait_readable(3)

        port = Integer(output.gets)
        Socket.tcp(address, port, connect_timeout: 2) do |socket|
          raise "IPv6 listener did not reply" unless socket.wait_readable(2) && socket.gets == "dad-ready\n"
        end
        raise "IPv6 listener failed" unless child.value.success?
      end
    end

    def install_bridge(network, netlink, observer, duplicate:)
      network.ensure_node_bridge
      # Keep the otherwise isolated bridge carrier up and wait for the node's
      # own address, independently of the Pod ADD being measured.
      netlink.link_add(name: "fixture-carrier", kind: "dummy", up: true)
      netlink.link_set(name: "fixture-carrier", master: "rbr0")
      address = duplicate ? "fd21:2::2" : "fd21:2::1"
      netlink.address_add(address: "#{address}/64", name: "rbr0") if duplicate
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 4
      loop do
        gateway = observer.resources(kinds: ["address"]).find { |entry| entry.dig("metadata", "address") == address }
        return if gateway&.fetch("metadata")&.values_at("tentative", "dad_failed") == [false, false]

        raise "fixture bridge address did not become ready" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.02
      end
    end

    mode = ARGV.fetch(0)
    transmits = mode == "duplicate" ? 1 : 4
    explicit_timeout = mode == "explicit" ? {readback_timeout: 3.0} : {}
    child_setup = 'ip link set lo up && sysctl -qw net.ipv6.conf.default.dad_transmits="$1" && echo ready && exec sleep 20'
    input, output, child = Open3.popen2("unshare", "-n", "--", "sh", "-c", child_setup, "sandbox", transmits.to_s)
    input.close
    begin
      raise "sandbox namespace did not start" unless output.wait_readable(3) && output.gets == "ready\n"

      pid = child.pid
      path = "/proc/#{pid}/ns/net"
      pidfd = IO.for_fd(Rubernetes::Platform::Linux::Pidfd.new.open(pid: pid))
      process_start = File.binread("/proc/#{pid}/stat").rpartition(") ").last.split.fetch(19).to_i
      sandbox = {"sandbox_id" => "dad-check", "netns" => {"handle" => "dad-check", "path" => path, "inode" => File.stat(path).ino,
                  "pid" => pid, "pidfd" => pidfd.fileno, "start_time" => process_start}}
      Dir.mktmpdir("rubernetes-dad") do |dir|
        netlink = Rubernetes::Network::Netlink.new
        observer = ObservedDAD.new(netlink: netlink)
        ipam = Rubernetes::Network::IPAM.new(ipv6_cidr: "fd21:2::/64", ipv6_node_prefix: 64)
        network = Rubernetes::Network::Interface.new(ipam: ipam, netlink: netlink, observer: observer,
                                                    require_observer: true, state_path: File.join(dir, "network.json"), **explicit_timeout)
        install_bridge(network, netlink, observer, duplicate: mode == "duplicate")
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        error = nil
        begin
          attached = network.add(sandbox)
          address = attached.fetch("ips").first.split("/").first
          exchange(pid, address)
        rescue Rubernetes::Network::EffectError => exception
          error = exception.message
        end
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        puts JSON.generate("trace" => observer.states, "identities" => observer.identities, "elapsed" => elapsed, "error" => error)
      end
    ensure
      pidfd&.close
      Process.kill(:TERM, child.pid) if child.alive?
      child.value
    end
  RUBY

  def test_delayed_native_dad_completes_only_after_the_address_can_serve_ipv6
    result = observe_dad("slow")

    assert_nil result["error"]
    assert_equal %w[tentative ready], result.fetch("trace")
    assert_equal 1, result.fetch("identities").length
    assert_operator result.fetch("elapsed"), :>, 3.0
    assert_operator result.fetch("elapsed"), :<, 7.0
  end

  def test_an_explicit_readback_timeout_stays_fixed_while_dad_is_pending
    result = observe_dad("explicit")

    assert_match(/IPv6 duplicate address detection was still in progress/, result.fetch("error"))
    assert_equal ["tentative"], result.fetch("trace")
    assert_operator result.fetch("elapsed"), :>=, 2.95
    assert_operator result.fetch("elapsed"), :<, 4.2
  end

  def test_dad_failed_rejects_the_address_without_waiting_for_the_timeout
    result = observe_dad("duplicate")

    assert_match(/kernel IPv6 duplicate address detection failed/, result.fetch("error"))
    assert_equal %w[tentative dad_failed], result.fetch("trace")
    assert_equal 1, result.fetch("identities").length
    assert_operator result.fetch("elapsed"), :<, 3.0
  end

  private

  def observe_dad(mode)
    output, error, status = Open3.capture3("timeout", "--kill-after=2s", "18s", "unshare", "-n", "--", RbConfig.ruby, "-Ilib", "-e", CHECK, mode)
    skip error.strip if error.match?(/\Aunshare: .*Operation not permitted/)

    assert_predicate status, :success?, error
    JSON.parse(output)
  end
end
