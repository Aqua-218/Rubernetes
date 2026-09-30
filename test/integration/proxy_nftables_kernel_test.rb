# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"

class ProxyNftablesKernelTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'
    require "rubernetes/proxy"

    begin
      system("ip", "link", "set", "lo", "up") or raise "could not bring up loopback"
      table = "rk_nft_ns_#{Process.pid}"
      adapter = Rubernetes::Proxy::NftablesNetlinkAdapter.new(table_name: table, timeout: 2)
      backend = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
      service = Rubernetes::Proxy::Service.new(
        "metadata" => {"name" => "isolated", "namespace" => "tests"},
        "spec" => {"clusterIP" => "127.0.0.1", "ports" => [{"port" => 80, "targetPort" => 8080}]}
      )
      endpoint = Rubernetes::Proxy::Endpoint.new(address: "127.0.0.2", port: 8080)
      compiled = Rubernetes::Proxy::RuleCompiler.new.compile(service, endpoints: [endpoint], revision: 1)
      backend.apply(compiled)
      result = adapter.send_messages([], backend: backend)
      raise "nftables transaction was not verified" unless result["verified"]

      server = TCPServer.new("127.0.0.2", 8080)
      worker = Thread.new do
        client = server.accept
        client.write("isolated-nft\n")
        client.close
      end
      socket = TCPSocket.new("127.0.0.1", 80)
      raise "isolated packet did not reach the endpoint" unless socket.read(13) == "isolated-nft\n"
      socket.close
      worker.join
      raise "nftables readback was not verified" unless adapter.readback(backend: backend)["verified"]
      puts "isolated-nft-ok"
    ensure
      adapter&.detach(backend: backend) rescue nil
      server&.close unless server&.closed?
    end
  RUBY

  def test_nftables_dnat_and_readback_in_an_isolated_network_namespace
    output, error, status = Open3.capture3(
      "unshare", "-n", "--", RbConfig.ruby, "-Ilib", "-e", KERNEL_SCRIPT
    )
    skip error.strip if status.exitstatus == 77 && error.start_with?("SKIP:")
    if !status.success? && error.match?(/Operation not permitted|Permission denied/i)
      skip "missing CAP_SYS_ADMIN/CAP_NET_ADMIN for isolated nftables test: #{error.strip}"
    end

    assert_predicate status, :success?, "isolated nftables kernel script failed: #{error.empty? ? output : error}"
    assert_includes output, "isolated-nft-ok"
  rescue Errno::ENOENT => exception
    flunk "unshare is required for the isolated nftables integration test: #{exception.message}"
  end
end
