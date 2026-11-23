# frozen_string_literal: true

require "socket"

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/platform/linux/native_adapters"

class ProbeTCPDeadlineTest < Minitest::Test
  class NamespaceWorker
    def initialize(delay:)
      @delay = delay
    end

    def within_namespaces(_handle, only:, timeout:)
      sleep @delay
      yield
    end
  end

  class Runtime
    Namespace = Struct.new(:adapter_handle)
    Sandbox = Struct.new(:namespace)

    def initialize(setup_delay:)
      @sandbox = Sandbox.new(Namespace.new("pod"))
      @connector = Rubernetes::Platform::Linux::NativeAdapters::NamespaceConnector.new(
        process_adapter: nil, cgroup_adapter: nil, namespace_adapter: NamespaceWorker.new(delay: setup_delay)
      )
    end

    def tcp_socket(_id, definition, timeout:, **)
      @connector.tcp_socket(sandbox: @sandbox, container: nil, definition: definition, timeout: timeout)
    end
  end

  def test_a_slow_namespace_helper_keeps_the_full_tcp_dial_budget
    listener = TCPServer.new("127.0.0.1", 0)
    result = probe(listener.local_address.ip_port, setup_delay: 1.1)

    assert_predicate result, :success?
    assert_equal "connected", result.message
  ensure
    listener&.close
  end

  def test_an_unreachable_tcp_endpoint_does_not_inherit_the_setup_margin
    abort_on_overflow = "/proc/sys/net/ipv4/tcp_abort_on_overflow"
    skip "requires Linux to drop connections when the accept queue fills" unless File.file?(abort_on_overflow) && File.read(abort_on_overflow).strip == "0"

    with_full_accept_queue do |port|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = probe(port, setup_delay: 0)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      assert_predicate result, :failed?
      assert_equal "connect timed out", result.message
      assert_operator elapsed, :>=, 0.8
      assert_operator elapsed, :<, 4
    end
  end

  private

  def probe(port, setup_delay:)
    manager = Rubernetes::Node::ProbeManager.new(runtime: Runtime.new(setup_delay: setup_delay))
    manager.check("container", {"tcpSocket" => {"port" => port}, "timeoutSeconds" => 1}, type: "liveness")
  end

  def with_full_accept_queue
    listener = Socket.new(:INET, :STREAM)
    listener.bind(Socket.sockaddr_in(0, "127.0.0.1"))
    listener.listen(0)
    port = listener.local_address.ip_port
    queued = Socket.tcp("127.0.0.1", port, connect_timeout: 1)
    yield port
  ensure
    queued&.close
    listener&.close
  end
end
