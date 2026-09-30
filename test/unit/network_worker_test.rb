# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# The node's Network::Interface runs in a worker process; the agent talks to
# it through a RemoteInterface with the same public methods.
class NetworkWorkerTest < Minitest::Test
  Network = Rubernetes::Network

  class FakeInterface
    attr_reader :policy_engine

    def initialize = @policy_engine = :local_engine

    def add(sandbox, config = nil, **options)
      {"sandbox" => sandbox, "config" => config, "options" => options, "pid" => Process.pid}
    end

    def delete(_sandbox, _config = nil, **_options)
      raise Network::EffectError, "veth is still busy"
    end

    def check(seconds, _config = nil, **)
      sleep seconds
      Process.pid
    end

    def state = raise(IOError, "unmarshallable?")
  end

  def setup
    @remote = Network::Worker.fork_for(FakeInterface.new)
  end

  def teardown
    @remote.instance_variable_get(:@socket).close
    Process.wait(@remote.pid)
  end

  def test_calls_run_in_the_worker_and_return_their_result
    result = @remote.add({"sandbox_id" => "s1"}, {"a" => 1}, request_id: "r1")

    assert_equal({"sandbox_id" => "s1"}, result["sandbox"])
    assert_equal({request_id: "r1"}, result["options"])
    refute_equal Process.pid, result["pid"], "the work happened in the worker"
    assert_equal :local_engine, @remote.policy_engine
    assert_kind_of Network::Interface, @remote
  end

  def test_exceptions_are_raised_in_the_agent
    error = assert_raises(Network::EffectError) { @remote.delete("s1") }
    assert_equal "veth is still busy", error.message
    assert_raises(IOError) { @remote.state }
  end

  def test_concurrent_calls_proceed_in_parallel
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Array.new(4) { Thread.new { @remote.check(0.3) } }.each(&:join)

    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.9
  end

  def test_a_gone_worker_fails_calls_instead_of_hanging
    Process.kill("KILL", @remote.pid)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    sleep 0.05 while @remote.alive? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    assert_raises(Network::Worker::Error) { @remote.add("s1") }
  end
end

# The agent's pidfd number means nothing in the worker, which opens its own
# pidfd for the namespace holder before the interface verifies it.
class NetworkWorkerNamespaceTest < Minitest::Test
  def test_the_holder_pidfd_is_reopened_in_the_worker
    opened = []
    sandbox = {"sandbox_id" => "s", "netns" => {"pid" => Process.pid, "pidfd" => 9999, "path" => "/proc/#{Process.pid}/ns/net"}}
    local = Rubernetes::Network::Worker.localize_namespace(sandbox, opened)
    fd = local.dig("netns", "pidfd")

    refute_equal 9999, fd
    assert_equal "anon_inode:[pidfd]", File.readlink("/proc/self/fd/#{fd}")
    assert_equal 9999, sandbox.dig("netns", "pidfd"), "the caller's value is untouched"
  ensure
    opened.each { |descriptor| IO.for_fd(descriptor).close }
  end

  def test_a_sandbox_without_a_namespace_is_passed_through
    assert_equal "s1", Rubernetes::Network::Worker.localize_namespace("s1", [])
  end
end
