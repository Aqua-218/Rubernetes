# frozen_string_literal: true

# Network specification: spec/node/network.md §5.9.2–§5.9.5.
# Coverage: namespace-FD scoped link/address/route operations, kernel dump
# readback, and namespace-safe cleanup.  Requires Linux CAP_NET_ADMIN and
# CAP_SYS_ADMIN; the test is skipped only when the host cannot create an
# isolated network namespace.

require_relative "../test_helper"
require "open3"
require "rubernetes/network"

class NetlinkNamespaceTopologyTest < Minitest::Test
  class FailSecondLinkSet
    def initialize(delegate)
      @delegate = delegate
      @link_sets = 0
    end

    def link_set(**parameters)
      @link_sets += 1
      raise Rubernetes::Network::NetlinkError, "injected native link_set failure" if @link_sets == 2

      @delegate.link_set(**parameters)
    end

    def method_missing(name, *, **keywords, &)
      if keywords.empty?
        @delegate.public_send(name, *, &)
      else
        @delegate.public_send(name, *, **keywords, &)
      end
    end

    def respond_to_missing?(name, include_private = false)
      @delegate.respond_to?(name, include_private) || super
    end
  end

  def test_namespace_fd_scopes_ifindex_address_route_and_observer
    skip "Linux only" unless RUBY_PLATFORM.include?("linux")

    # A plain `unshare -n` requires CAP_SYS_ADMIN in the caller's user
    # namespace.  The user+network namespace form gives the child its own
    # capability set on constrained CI while still exercising a real kernel
    # namespace boundary.
    namespace_pid = Process.spawn("unshare", "-Urn", "--", "sleep", "30", %i[out err] => File::NULL)
    namespace_path = "/proc/#{namespace_pid}/ns/net"
    host_namespace_inode = File.stat("/proc/self/ns/net").ino
    100.times do
      break if File.exist?(namespace_path) && File.stat(namespace_path).ino != host_namespace_inode

      sleep 0.02
    end
    skip "unshare is unavailable or denied" unless File.exist?(namespace_path)
    skip "unshare did not create an isolated network namespace" if File.stat(namespace_path).ino == host_namespace_inode

    netlink = Rubernetes::Network::Netlink.new
    observer = Rubernetes::Network::NativeObserver.new(netlink: netlink)
    host_ifname = "rk-ns-host#{Process.pid % 1000}"
    peer_ifname = "rk-ns-peer#{Process.pid % 1000}"
    move_host_ifname = "rk-ns-mvh#{Process.pid % 1000}"
    move_peer_ifname = "rk-ns-mvp#{Process.pid % 1000}"
    vxlan_ifname = "rk-ns-vx#{Process.pid % 1000}"
    route = "198.18.3.0/24"
    ipv6_route = "2001:db8:3::/64"
    File.open(namespace_path, "rb") do |namespace_fd|
      netlink.link_add(name: host_ifname, kind: "veth", peer: peer_ifname, namespace_fd: namespace_fd, up: false)
      netlink.link_set(name: peer_ifname, namespace_fd: namespace_fd, up: true)
      netlink.address_add(address: "198.18.2.1/24", name: peer_ifname, namespace_fd: namespace_fd)
      netlink.address_add(address: "2001:db8:2::1/64", name: peer_ifname, namespace_fd: namespace_fd)
      netlink.route_add(destination: route, dev: peer_ifname, namespace_fd: namespace_fd)
      netlink.route_add(destination: ipv6_route, dev: peer_ifname, namespace_fd: namespace_fd)

      resources = observer.resources(namespace_fd: namespace_fd)
      link = resources.find { |entry| entry["kind"] == "link" && entry.dig("metadata", "name") == peer_ifname }
      addresses = resources.select { |entry| entry["kind"] == "address" && entry.dig("metadata", "ifname") == peer_ifname }
      found_route = resources.find { |entry| entry["kind"] == "route" && entry.dig("metadata", "destination") == route }
      found_ipv6_route = resources.find { |entry| entry["kind"] == "route" && entry.dig("metadata", "destination") == ipv6_route }

      assert link, "peer link must be dumped from the target namespace"
      assert_equal 2, addresses.length, "IPv4 and IPv6 addresses must be dumped from the target namespace"
      assert found_route, "route must be dumped from the target namespace"
      assert found_ipv6_route, "IPv6 route must be dumped from the target namespace"
      address = addresses.find { |entry| entry.dig("metadata", "address") == "198.18.2.1" }

      assert_equal link.fetch("metadata").fetch("ifindex"), address.fetch("metadata").fetch("ifindex")
      assert_equal link.fetch("identity").split(":")[1], address.fetch("identity").split(":")[1]
      assert_equal link.fetch("identity"), observer.identity_for(
        Rubernetes::Network::Operation.new(action: "link_set", resource: "link:#{peer_ifname}", identity: "link",
                                           parameters: {"name" => peer_ifname, "namespace_fd" => namespace_fd})
      )
      assert_equal address.fetch("identity"), observer.identity_for(
        Rubernetes::Network::Operation.new(action: "address_add", resource: "address:test", identity: "address",
                                           parameters: {"address" => "198.18.2.1/24", "interface" => peer_ifname,
                                                        "namespace_fd" => namespace_fd})
      )
      assert_equal found_route.fetch("identity"), observer.identity_for(
        Rubernetes::Network::Operation.new(action: "route_add", resource: "route:test", identity: "route",
                                           parameters: {"destination" => route, "dev" => peer_ifname,
                                                        "namespace_fd" => namespace_fd})
      )

      begin
        netlink.link_add(name: vxlan_ifname, kind: "vxlan", namespace_fd: namespace_fd, dev: "lo",
                         vni: 4096, dstport: 4789, learning: false, mtu: 1450, up: false)
        vxlan = observer.resources(namespace_fd: namespace_fd).find do |entry|
          entry["kind"] == "link" && entry.dig("metadata", "name") == vxlan_ifname
        end

        assert_equal "vxlan", vxlan.dig("metadata", "kind")
        assert_equal 4096, vxlan.dig("metadata", "vni")
        assert_equal 4789, vxlan.dig("metadata", "dstport")
        assert_equal false, vxlan.dig("metadata", "learning")
        assert_equal 1, vxlan.dig("metadata", "underlay_ifindex")
        netlink.fdb_add(mac: "02:aa:bb:cc:dd:ee", destination: "192.0.2.1", dev: vxlan_ifname,
                        namespace_fd: namespace_fd)
        fdb = observer.resources(namespace_fd: namespace_fd).find do |entry|
          entry["kind"] == "fdb" && entry.dig("metadata", "ifname") == vxlan_ifname
        end

        assert fdb, "VXLAN FDB must be dumped from the target namespace"
        assert_equal fdb.fetch("identity"), observer.identity_for(
          Rubernetes::Network::Operation.new(action: "fdb_add", resource: "fdb:test", identity: "fdb",
                                             parameters: {"mac" => "02:aa:bb:cc:dd:ee", "destination" => "192.0.2.1",
                                                          "dev" => vxlan_ifname, "namespace_fd" => namespace_fd})
        )
        netlink.fdb_delete(mac: "02:aa:bb:cc:dd:ee", destination: "192.0.2.1", dev: vxlan_ifname,
                           namespace_fd: namespace_fd)
        netlink.link_delete(name: vxlan_ifname, namespace_fd: namespace_fd)
      rescue Rubernetes::Network::NetlinkError => error
        skip "kernel does not support privileged VXLAN/FDB operations (errno #{error.errno})" if
          [Errno::EOPNOTSUPP::Errno, Errno::EPERM::Errno, Errno::EACCES::Errno].include?(error.errno)
        raise
      end

      # Also exercise the legacy move form: the peer starts in the caller
      # namespace, so link_set must resolve its source ifindex/socket before
      # attaching IFLA_NET_NS_FD. A target-scoped lookup alone is incorrect.
      netlink.link_add(name: move_host_ifname, kind: "veth", peer: move_peer_ifname, up: false)
      netlink.link_set(name: move_peer_ifname, namespace_fd: namespace_fd, up: true)
      moved_peer = observer.resources(namespace_fd: namespace_fd).find do |entry|
        entry["kind"] == "link" && entry.dig("metadata", "name") == move_peer_ifname
      end

      assert moved_peer, "link_set must move a source-namespace veth peer into the target"
      refute(observer.resources.any? { |entry| entry.dig("metadata", "name") == move_peer_ifname })
      netlink.link_delete(name: move_host_ifname)

      netlink.route_delete(destination: route, dev: peer_ifname, namespace_fd: namespace_fd)
      netlink.route_delete(destination: ipv6_route, dev: peer_ifname, namespace_fd: namespace_fd)
      netlink.address_delete(address: "198.18.2.1/24", name: peer_ifname, namespace_fd: namespace_fd)
      netlink.address_delete(address: "2001:db8:2::1/64", name: peer_ifname, namespace_fd: namespace_fd)
    end
    netlink.link_delete(name: host_ifname)
  rescue Rubernetes::Network::NetlinkError => error
    skip "kernel denied isolated namespace operation (errno #{error.errno})" if [Errno::EPERM::Errno, Errno::EACCES::Errno,
                                                                                 Errno::EOPNOTSUPP::Errno].include?(error.errno)
    raise
  ensure
    begin
      netlink&.link_delete(name: host_ifname)
    rescue Rubernetes::Network::NetlinkError
      nil
    end
    begin
      Process.kill("TERM", namespace_pid) if namespace_pid && Process.waitpid(namespace_pid, Process::WNOHANG).nil?
      Process.wait(namespace_pid) if namespace_pid
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
  end

  def test_native_link_set_failure_restores_previous_target_state
    skip "Linux only" unless RUBY_PLATFORM.include?("linux")

    namespace_pid = Process.spawn("unshare", "-Urn", "--", "sleep", "30", %i[out err] => File::NULL)
    namespace_path = "/proc/#{namespace_pid}/ns/net"
    host_namespace_inode = File.stat("/proc/self/ns/net").ino
    100.times do
      break if File.exist?(namespace_path) && File.stat(namespace_path).ino != host_namespace_inode

      sleep 0.02
    end
    skip "unshare is unavailable or denied" unless File.exist?(namespace_path)
    skip "unshare did not create an isolated network namespace" if File.stat(namespace_path).ino == host_namespace_inode

    netlink = Rubernetes::Network::Netlink.new
    observer = Rubernetes::Network::NativeObserver.new(netlink: netlink)
    host_ifname = "rk-fail-h#{Process.pid % 1000}"
    peer_ifname = "rk-fail-p#{Process.pid % 1000}"
    failing = FailSecondLinkSet.new(netlink)
    File.open(namespace_path, "rb") do |namespace_fd|
      netlink.link_add(name: host_ifname, kind: "veth", peer: peer_ifname, namespace_fd: namespace_fd, up: false)
      netlink.link_set(name: peer_ifname, namespace_fd: namespace_fd, up: true, mtu: 1500)
      topology = Rubernetes::Network::Topology.new(netlink: failing)
      operations = [false, false].each_with_index.map do |up, index|
        Rubernetes::Network::Operation.new(
          action: "link_set", resource: "link:#{peer_ifname}", identity: "failure-#{index}",
          parameters: {"name" => peer_ifname, "namespace_fd" => namespace_fd.fileno,
                       "up" => up, "mtu" => 1400 - (index * 100)}
        ).freeze
      end
      plan = Rubernetes::Network::Plan.new(operations: operations, mtu: 1500, backend: nil, revision: 1, metadata: {})
      error = assert_raises(Rubernetes::Network::EffectError) { topology.apply(plan) }
      assert_equal 1, error.applied.length
      topology.rollback(Rubernetes::Network::Plan.new(operations: error.applied, mtu: 1500, backend: nil,
                                                      revision: 1, metadata: {}))
      restored = observer.resources(namespace_fd: namespace_fd).find do |entry|
        entry["kind"] == "link" && entry.dig("metadata", "name") == peer_ifname
      end

      assert_equal true, restored.dig("metadata", "up")
      assert_equal 1500, restored.dig("metadata", "mtu")
    end
  rescue Rubernetes::Network::NetlinkError => error
    skip "kernel denied failure-injection namespace operation (errno #{error.errno})" if
      [Errno::EPERM::Errno, Errno::EACCES::Errno, Errno::EOPNOTSUPP::Errno].include?(error.errno)
    raise
  ensure
    begin
      netlink&.link_delete(name: host_ifname)
    rescue Rubernetes::Network::NetlinkError
      nil
    end
    begin
      Process.kill("TERM", namespace_pid) if namespace_pid && Process.waitpid(namespace_pid, Process::WNOHANG).nil?
      Process.wait(namespace_pid) if namespace_pid
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end
  end
end
