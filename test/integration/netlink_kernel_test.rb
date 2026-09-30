# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"

class NetlinkKernelTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'
    require "open3"
    require "rubernetes/network"

    include Rubernetes::Network

    def run_command(*command)
      output, error, status = Open3.capture3(*command)
      raise "#{command.join(" ")} failed: #{error.empty? ? output : error}" unless status.success?

      output
    end

    netlink = Netlink.new
    dummy = "rk-dummy0"
    host_veth = "rk-veth0"
    peer_veth = "rk-peer0"
    route = "198.18.2.0/24"
    begin
      netlink.link_add(name: dummy, kind: "dummy", up: false)
      File.open("/proc/self/ns/net", "rb") do |namespace|
        netlink.link_add(name: host_veth, kind: "veth", peer: peer_veth, namespace_fd: namespace, up: false)
      end
      netlink.link_set(name: dummy, up: true)
      netlink.link_set(name: peer_veth, up: true)
      netlink.address_add(address: "198.18.1.7/24", name: dummy)
      netlink.route_add(destination: route, dev: dummy, metric: 17)

      run_command("ip", "-o", "link", "show", "dev", dummy)
      run_command("ip", "-o", "link", "show", "dev", host_veth)
      run_command("ip", "-o", "link", "show", "dev", peer_veth)
      address_output = run_command("ip", "-o", "addr", "show", "dev", dummy)
      raise "address was not observable" unless address_output.include?("198.18.1.7/24")
      route_output = run_command("ip", "-o", "route", "show", route)
      raise "route was not observable" unless route_output.include?(dummy)
    rescue Rubernetes::Network::NetlinkError => error
      if [Errno::EPERM::Errno, Errno::EACCES::Errno, Errno::EOPNOTSUPP::Errno].include?(error.errno)
        warn "SKIP: kernel denied rtnetlink capability (errno #{error.errno})"
        exit 77
      end
      warn "#{error.class}: #{error.message}"
      exit 1
    ensure
      begin
        netlink.route_delete(destination: route, dev: dummy, metric: 17)
      rescue Rubernetes::Network::NetlinkError
        nil
      end
      begin
        netlink.address_delete(address: "198.18.1.7/24", name: dummy)
      rescue Rubernetes::Network::NetlinkError
        nil
      end
      begin
        netlink.link_delete(name: host_veth)
      rescue Rubernetes::Network::NetlinkError
        nil
      end
      begin
        netlink.link_delete(name: dummy)
      rescue Rubernetes::Network::NetlinkError
        nil
      end
    end
  RUBY

  def test_mutating_rtnetlink_works_inside_an_isolated_network_namespace
    output, error, status = Open3.capture3("unshare", "-n", "--", RbConfig.ruby, "-Ilib", "-e", KERNEL_SCRIPT)
    skip error.strip if status.exitstatus == 77 && error.start_with?("SKIP:")
    if !status.success? && error.match?(/Operation not permitted|Permission denied/i)
      skip "missing CAP_SYS_ADMIN for isolated network namespace: #{error.strip}"
    end

    assert_predicate status, :success?, "isolated kernel script failed: #{error.empty? ? output : error}"
  rescue Errno::ENOENT => exception
    flunk "unshare is required for the isolated rtnetlink integration test: #{exception.message}"
  end
end
