# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class NftablesNetlinkAdapterTest < Minitest::Test
  Adapter = Rubernetes::Proxy::NftablesNetlinkAdapter

  class PipeSocket
    def initialize(bytes)
      @reader, writer = IO.pipe
      writer.write(bytes)
      writer.close
    end

    def to_io
      @reader
    end

    def recv(_length)
      @reader.read
    end

    def close
      @reader.close unless @reader.closed?
    end
  end

  class EmptyTransport
    attr_reader :transactions

    def initialize
      @transactions = []
    end

    def readback(**_options)
      {"table" => nil, "chains" => [], "sets" => [], "set_elements" => [], "rules" => []}
    end

    def send_transaction(messages:, **_options)
      @transactions << messages
      {"messageCount" => messages.length, "acknowledgedSequences" => []}
    end
  end

  def test_default_backend_uses_native_adapter_when_contract_is_available
    backend = Rubernetes::Proxy::NftablesBackend.new
    adapter = backend.instance_variable_get(:@syscall_adapter)

    assert_instance_of Adapter, adapter
    refute adapter.production_capable?
    refute backend.available?
    assert_match(/packet semantics|readback/, adapter.production_capability_error)
  end

  def test_missing_service_contract_is_explicit_and_stable
    adapter = Adapter.new(table_name: "rubernetes_contract_test")

    refute adapter.production_capable?
    assert_equal Adapter::MISSING_SERVICE_CONTRACT, adapter.missing_service_contract
    assert_empty adapter.missing_service_contract
    assert_match(/packet semantics|readback/, adapter.production_capability_error)
  end

  def test_ack_success_requires_a_zero_nlmsg_error_for_each_sequence
    adapter = Adapter.new(timeout: 0.5)
    payload = [0].pack("l<") + ("\0" * 16)
    message = [36, Adapter::NLMSG_ERROR, 0, 17, 0].pack("L<S<S<L<L<") + payload
    socket = PipeSocket.new(message)

    acknowledged = adapter.send(:receive_acknowledgements, socket, sequences: [17])

    assert_equal [17], acknowledged
  ensure
    socket&.close
  end

  def test_ack_error_is_propagated_with_errno_and_sequence
    adapter = Adapter.new(timeout: 0.5)
    payload = [-Errno::EPERM::Errno].pack("l<") + ("\0" * 16)
    message = [36, Adapter::NLMSG_ERROR, 0, 23, 0].pack("L<S<S<L<L<") + payload
    socket = PipeSocket.new(message)

    error = assert_raises(Rubernetes::Proxy::NftablesNetlinkError) do
      adapter.send(:receive_acknowledgements, socket, sequences: [23])
    end

    assert_equal Errno::EPERM::Errno, error.errno
    assert_equal 23, error.sequence
  ensure
    socket&.close
  end

  def test_transaction_without_readback_never_reports_success
    transport = EmptyTransport.new
    adapter = Adapter.new(table_name: "rubernetes_readback_test", transport: transport)
    backend = build_backend(adapter)

    error = assert_raises(Rubernetes::Proxy::NftablesNetlinkError) do
      adapter.send_messages([], backend: backend)
    end

    assert_match(/without matching kernel readback/, error.message)
    refute_empty transport.transactions
  end

  def test_health_check_rule_is_node_local_and_fragment_guard_is_fail_closed
    adapter = Adapter.new(table_name: "rubernetes_semantics_test", transport: Object.new)
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "health", "namespace" => "tests"},
      "spec" => {"type" => "NodePort", "clusterIP" => "10.96.0.3", "externalTrafficPolicy" => "Local",
                  "healthCheckNodePort" => 30099,
                  "ports" => [{"port" => 80, "targetPort" => 8080, "nodePort" => 30080}]}
    )
    endpoint = Rubernetes::Proxy::Endpoint.new(address: "10.1.0.3", port: 8080, node_name: "node-a")
    rules = Rubernetes::Proxy::RuleCompiler.new(local_node: "node-a").compile(service, endpoints: [endpoint]).rules
    objects = adapter.send(:desired_objects, rules)
    health = objects.fetch("rules").find { |entry| entry["action"] == "node_local_responder" }
    assert health
    refute health.fetch("dnat")
    assert_equal 2, objects.fetch("rules").count { |entry| entry["action"] == "drop_fragment" }
    assert_includes objects.fetch("chains").map { |entry| entry.fetch("name") }, "fragment_guard"
  end

  def test_kernel_lifecycle_and_ruleset_readback_when_enabled
    adapter = nil
    backend = nil
    begin
      skip "set RUBERNETES_NFTABLES_KERNEL_TEST=1 for the privileged kernel test" unless ENV["RUBERNETES_NFTABLES_KERNEL_TEST"] == "1"
      skip "kernel lifecycle test requires root" unless Process.uid.zero?

      table_name = "rubernetes_test_#{Process.pid}_#{rand(1_000_000)}"
      adapter = Adapter.new(table_name: table_name, timeout: 2.0)
      backend = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
      service = Rubernetes::Proxy::Service.new(
        "metadata" => {"name" => "web", "namespace" => "tests"},
        "spec" => {"clusterIP" => "10.96.0.1", "ports" => [{"port" => 80, "targetPort" => 8080}]}
      )
      endpoints = ["10.1.0.1", "10.1.0.2"].map do |address|
        Rubernetes::Proxy::Endpoint.new(address: address, port: 8080)
      end
      compiled = Rubernetes::Proxy::RuleCompiler.new.compile(service, endpoints: endpoints, revision: 1)
      backend.apply(compiled)

      result = adapter.send_messages([], backend: backend)
      assert_equal true, result.fetch("verified")
      transaction = result.fetch("transaction")
      assert_equal transaction.fetch("messageCount"), transaction.fetch("acknowledgedSequences").length
      readback = adapter.readback(backend: backend)
      assert_equal true, readback.fetch("verified")
      assert_equal 5, readback.fetch("chains").length
      assert_equal 1, readback.fetch("sets").length
      assert_equal 2, readback.fetch("set_elements").length
      assert_equal 6, readback.fetch("rules").length
    ensure
      begin
        adapter&.detach(backend: backend) if adapter && backend
      rescue Rubernetes::Proxy::NftablesNetlinkError
        # Do not mask the assertion or kernel error with best-effort cleanup.
      end
    end
  end

  def test_kernel_nat_packet_decision_when_enabled
    skip "set RUBERNETES_NFTABLES_PACKET_TEST=1 for the privileged dataplane test" unless ENV["RUBERNETES_NFTABLES_PACKET_TEST"] == "1"
    skip "kernel dataplane test requires root" unless Process.uid.zero?

    adapter = nil
    backend = nil
    server = nil
    worker = nil
    begin
      table_name = "rubernetes_packet_test_#{Process.pid}_#{rand(1_000_000)}"
      adapter = Adapter.new(table_name: table_name, timeout: 2.0)
      backend = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
      service = Rubernetes::Proxy::Service.new(
        "metadata" => {"name" => "packet", "namespace" => "tests"},
        "spec" => {"clusterIP" => "127.0.0.1", "ports" => [{"port" => 80, "targetPort" => 8080}]}
      )
      endpoint = Rubernetes::Proxy::Endpoint.new(address: "127.0.0.2", port: 8080)
      compiled = Rubernetes::Proxy::RuleCompiler.new.compile(service, endpoints: [endpoint], revision: 1)
      backend.apply(compiled)
      result = adapter.send_messages([], backend: backend)

      server = TCPServer.new("127.0.0.2", 8080)
      worker = Thread.new do
        client = server.accept
        client.write("dnat-ok\n")
        client.close
      end
      client = TCPSocket.new("127.0.0.1", 80)
      assert_equal "dnat-ok\n", client.read(8)
      client.close
      assert_equal true, result.fetch("verified")
      assert_equal true, adapter.readback(backend: backend).fetch("verified")
      worker.join
    ensure
      worker&.kill if worker&.alive?
      server&.close unless server&.closed?
      begin
        adapter&.detach(backend: backend) if adapter && backend
      rescue Rubernetes::Proxy::NftablesNetlinkError
        # Do not mask the assertion or kernel error with best-effort cleanup.
      end
    end
  end

  private

  def build_backend(adapter)
    endpoint = Rubernetes::Proxy::Endpoint.new(address: "10.1.0.1", port: 8080)
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "readback", "namespace" => "tests"},
      "spec" => {"clusterIP" => "10.96.0.2", "ports" => [{"port" => 80, "targetPort" => 8080}]}
    )
    compiled = Rubernetes::Proxy::RuleCompiler.new.compile(service, endpoints: [endpoint], revision: 1)
    backend = Rubernetes::Proxy::NftablesBackend.new(netlink_adapter: adapter, test_adapter: true)
    backend.apply(compiled)
    backend
  end
end
