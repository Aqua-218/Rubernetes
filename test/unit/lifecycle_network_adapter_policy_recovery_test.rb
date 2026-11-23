# frozen_string_literal: true

require "test_helper"
require "rubernetes/bootstrap/assembler"

# An agent that restarts after a sandbox was lost must still start: the
# stored network attachment of that Pod has nothing left to enforce policy on.
class LifecycleNetworkAdapterPolicyRecoveryTest < Minitest::Test
  class Lifecycle
    attr_reader :records, :replaced

    def initialize(records, known: records.values.map { |record| record[:sandbox_id] })
      @records = records
      @known = known
      @replaced = []
    end

    def replace_sandbox(sandbox, message:)
      return false unless @known.include?(sandbox)

      @replaced << [sandbox, message]
      true
    end
  end

  class Interface
    def initialize(unconfirmed: []) = @unconfirmed = unconfirmed
    def operation(id) = {"state" => "committed", "result" => {"sandbox_id" => id.delete_prefix("op-"), "ips" => ["10.240.0.9"]}}
    def check(context, _pod) = !@unconfirmed.include?(context.fetch("sandbox_id"))
  end

  class PolicySync
    attr_reader :started

    def start(pods:) = @started = pods
  end

  class Runtime
    def initialize(known:, failure: nil)
      @known = known
      @failure = failure
    end

    def network_sandbox_context(sandbox)
      raise @failure if @failure
      raise Rubernetes::Runtime::Native::Error, "unknown sandbox #{sandbox}" unless @known.include?(sandbox)

      {"sandbox_id" => sandbox, "netns" => {"pid" => Process.pid}}
    end
  end

  def record(sandbox, name)
    {sandbox_id: sandbox, network: {"state" => "committed", "ips" => ["10.240.0.9"], "operation_id" => "op-#{sandbox}"},
     pod: {"metadata" => {"namespace" => "default", "name" => name, "uid" => "uid-#{name}"}, "spec" => {}}}
  end

  def adapter(sync, interface = Interface.new) = Rubernetes::Bootstrap::LifecycleNetworkAdapter.new(interface, policy_sync: sync)

  def test_a_pod_whose_attachment_cannot_be_confirmed_is_rebuilt_and_the_agent_starts
    sync = PolicySync.new
    lifecycle = Lifecycle.new({"a" => record("sandbox-live", "kept"), "b" => record("sandbox-odd", "drifted")})
    runtime = Runtime.new(known: %w[sandbox-live sandbox-odd])

    adapter(sync, Interface.new(unconfirmed: ["sandbox-odd"])).start_policy(lifecycle, runtime: runtime)

    assert_equal ["kept"], sync.started.map { |pod| pod.fetch("name") }
    assert_equal ["sandbox-odd"], lifecycle.replaced.map(&:first)
  end

  def test_an_unconfirmed_attachment_no_pod_answers_for_still_stops_the_start
    sync = PolicySync.new
    lifecycle = Lifecycle.new({"a" => record("sandbox-odd", "drifted")}, known: [])
    runtime = Runtime.new(known: ["sandbox-odd"])

    assert_raises(Rubernetes::Network::OwnershipError) do
      adapter(sync, Interface.new(unconfirmed: ["sandbox-odd"])).start_policy(lifecycle, runtime: runtime)
    end
  end

  def test_a_pod_whose_sandbox_is_gone_is_left_out_and_the_others_are_recovered
    sync = PolicySync.new
    lifecycle = Lifecycle.new({"a" => record("sandbox-live", "kept"), "b" => record("sandbox-lost", "gone")})

    adapter(sync).start_policy(lifecycle, runtime: Runtime.new(known: ["sandbox-live"]))

    assert_equal ["kept"], sync.started.map { |pod| pod.fetch("name") }
  end

  def test_any_other_runtime_failure_still_stops_the_start
    sync = PolicySync.new
    lifecycle = Lifecycle.new({"a" => record("sandbox-live", "kept")})
    runtime = Runtime.new(known: ["sandbox-live"], failure: Rubernetes::Runtime::Native::Error.new("ledger is unreadable"))

    error = assert_raises(Rubernetes::Runtime::Native::Error) { adapter(sync).start_policy(lifecycle, runtime: runtime) }

    assert_includes error.message, "ledger is unreadable"
    assert_nil sync.started
  end
end
