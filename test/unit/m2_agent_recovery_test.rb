# frozen_string_literal: true

# M2 recovery contract tests.
# Specification: spec/node/node-agent.md §5.7 and spec/node/runtime.md §5.8.14.
# Coverage: startup recovery ordering, durable cleanup states, fail-closed
# readiness, and production API node endpoint routing.

require "tmpdir"
require "timeout"

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"
require "rubernetes/node"

class M2AgentRecoveryTest < Minitest::Test
  class API
    attr_reader :nodes, :leases

    def initialize
      @nodes = []
      @leases = []
    end

    def register_node(node)
      @nodes << node
      node
    end

    def renew_lease(lease)
      @leases << lease
      lease
    end
  end

  class FlakyAPI < API
    def initialize
      super
      @failures = 1
    end

    def register_node(node)
      if @failures.positive?
        @failures -= 1
        raise "API is temporarily unavailable"
      end

      super
    end
  end

  class Loop
    attr_reader :events

    def initialize(events)
      @events = events
    end

    def start(**_options)
      @events << :loop_start
      true
    end

    def stop(**_options)
      @events << :loop_stop
      true
    end
  end

  class Lifecycle
    attr_reader :events

    def initialize(events, report: {"ready" => true, "errors" => [], "blocked" => []})
      @events = events
      @report = report
    end

    def recover(**_options)
      @events << :recovery
      @report
    end
  end

  class Runtime
    attr_reader :calls

    def initialize(fail_remove: false)
      @calls = []
      @fail_remove = fail_remove
      @next_container = 0
    end

    def run_sandbox(_pod, **_options)
      @calls << :sandbox
      "sandbox-1"
    end

    def create_container(_sandbox, _spec)
      @next_container += 1
      "container-#{@next_container}"
    end

    def start_container(id)
      @calls << [:start, id]
      true
    end

    def stop_container(id, timeout:)
      @calls << [:stop, id, timeout]
      true
    end

    def remove_container(id)
      @calls << [:remove_container, id]
      true
    end

    def remove_sandbox(id)
      @calls << [:remove_sandbox, id]
      raise "temporary cleanup failure" if @fail_remove

      true
    end
  end

  def pod
    {
      "apiVersion" => "v1",
      "kind" => "Pod",
      "metadata" => {"name" => "recovery", "namespace" => "default", "uid" => "recovery-uid"},
      "spec" => {"containers" => [{"name" => "app", "image" => "example/app"}]}
    }
  end

  # Requirement: the recovery barrier runs before registration and before the
  # SyncLoop can accept Pod events. Mutation target: moving recover after loop.
  def test_node_agent_recovers_before_registration_and_sync_loop
    events = []
    api = API.new
    lifecycle = Lifecycle.new(events)
    loop_ = Loop.new(events)
    agent = Rubernetes::Node::Agent.new(
      node_name: "node-a", api: api, lifecycle: lifecycle, sync_loop: loop_,
      clock: -> { Time.utc(2026, 1, 1) }, sleeper: ->(_seconds) {}
    )

    agent.start

    assert_equal %i[recovery loop_start], events
    assert_equal "node-a", api.nodes.fetch(0).dig("metadata", "name")
    assert_predicate agent, :ready?
    assert_predicate agent, :registered?
  end

  # Requirement: unresolved recovery must not open the worker or register a
  # ready node. Mutation target: ignoring blocked/error recovery fields.
  def test_node_agent_fails_closed_when_recovery_is_incomplete
    events = []
    api = API.new
    lifecycle = Lifecycle.new(events, report: {"ready" => false, "errors" => ["observer unavailable"], "blocked" => ["pod-1"]})
    loop_ = Loop.new(events)
    agent = Rubernetes::Node::Agent.new(node_name: "node-a", api: api, lifecycle: lifecycle, sync_loop: loop_)

    assert_raises(Rubernetes::Runtime::RecoveryRequired) { agent.start }
    refute_predicate agent, :ready?
    refute_predicate agent, :registered?
    assert_equal [:recovery], events
    assert_empty api.nodes
  end

  # Requirement: an identity mismatch is not a successful recovery merely
  # because the runtime reported no exception. Mutation target: accepting a
  # Pod after a mismatched kernel owner was observed.
  def test_node_agent_fails_closed_on_runtime_identity_mismatch
    events = []
    api = API.new
    lifecycle = Lifecycle.new(
      events,
      report: {
        "ready" => true,
        "errors" => [],
        "blocked" => [],
        "identity_mismatch" => [{"kind" => "workspace", "id" => "pod-1"}]
      }
    )
    agent = Rubernetes::Node::Agent.new(
      node_name: "node-a", api: api, lifecycle: lifecycle, sync_loop: Loop.new(events)
    )

    assert_raises(Rubernetes::Runtime::RecoveryRequired) { agent.start }
    refute_predicate agent, :ready?
    refute_predicate agent, :registered?
    assert_empty api.nodes
  end

  # Requirement: a registration retry opens the SyncLoop only after the node
  # is actually registered. Mutation target: leaving the worker permanently
  # closed after a transient API outage, or opening it before registration.
  def test_registration_retry_opens_sync_loop_after_registration
    events = []
    api = FlakyAPI.new
    agent = Rubernetes::Node::Agent.new(
      node_name: "node-a",
      api: api,
      lifecycle: Lifecycle.new(events),
      sync_loop: Loop.new(events),
      sleeper: ->(_seconds) { sleep 0.005 },
      error_handler: ->(_error) {}
    )

    agent.start(lease_thread: true)
    Timeout.timeout(1) { sleep 0.005 until events.include?(:loop_start) }

    assert_predicate agent, :registered?
    assert_predicate agent, :running?
    assert_predicate agent, :ready?
    assert_equal %i[recovery loop_start], events
  ensure
    agent&.stop(reason: "test")
  end

  # Requirement: CleanupPending ownership is retried after stop confirmation
  # without replacing the durable resource identity.
  def test_lifecycle_reconciles_cleanup_pending_on_a_new_agent_instance
    Dir.mktmpdir("m2-node-recovery-") do |directory|
      state_path = File.join(directory, "node-state.json")
      first_runtime = Runtime.new(fail_remove: true)
      first = Rubernetes::Node::Lifecycle.new(runtime: first_runtime, state_store: state_path)
      first.start(pod)
      pending = first.terminate(pod)

      assert_equal "CleanupPending", pending.state
      assert_equal [{"kind" => "sandbox", "id" => "sandbox-1"}], pending.resources

      second_runtime = Runtime.new
      second = Rubernetes::Node::Lifecycle.new(runtime: second_runtime, state_store: state_path)
      report = second.recover

      assert_equal true, report.fetch("ready")
      assert_equal ["recovery-uid"], report.fetch("recovered")
      assert_equal "Removed", second.state(pod)
      assert_empty second.record(pod).fetch(:resources)
      refute(second_runtime.calls.any? { |entry| entry.is_a?(Array) && entry.first == :start })
    end
  end

  # Requirement: production API routes only to a registered AgentService
  # endpoint; unknown nodes and missing endpoints remain unavailable.
  def test_node_resolver_registers_agent_endpoint_and_fails_closed_for_unknown_node
    endpoint = Object.new
    endpoint.define_singleton_method(:logs) { |_container_id, **_options| "ok" }
    resolver = Rubernetes::API::SubresourceBridge::NodeResolver.new
    resolver.register("node-a", endpoint)

    assert_same endpoint, resolver.resolve(node_name: "node-a")
    assert_same endpoint, resolver.call("node-a")
    assert_nil resolver.resolve(node_name: "node-b")
    assert_equal ["node-a"], resolver.names
    assert_raises(ArgumentError) { resolver.register("node-b", Object.new) }
  end

  def test_agent_service_registers_only_a_started_node_endpoint
    events = []
    runtime = Object.new
    runtime.define_singleton_method(:start) { true }
    runtime.define_singleton_method(:reconcile) { true }
    runtime.define_singleton_method(:stop) { true }
    resolver = Rubernetes::API::SubresourceBridge::NodeResolver.new
    service = Rubernetes::Bootstrap::AgentService.new(
      # This case is about node-endpoint registration, not the streaming
      # listener; binding the real kubelet port would make it fail on any host
      # that already runs one.
      config: {"node_name" => "node-a", "streaming" => {"enabled" => false}},
      logger: Object.new,
      runtime: runtime,
      sync_loop: Loop.new(events),
      node_resolver: resolver
    )

    service.start

    assert_same service, resolver.resolve(node_name: "node-a")

    service.stop(reason: "test")

    assert_nil resolver.resolve(node_name: "node-a")
  end

  # Requirement: the production APIServer assembly receives the real node
  # resolver/authentication ports; omitting them must leave SubresourceBridge
  # in its explicit 401/503 fail-closed mode.
  def test_apiserver_assembler_wires_node_resolver_and_authorization_ports
    resolver = Rubernetes::API::SubresourceBridge::NodeResolver.new
    authorizer = ->(**_context) { true }
    identity = ->(_request) { "agent-user" }
    assembly = Rubernetes::Bootstrap::Assembler.new(
      process_name: "rubernetes-apiserver",
      log_io: StringIO.new,
      runtime_adapters: {
        api_node_resolver: resolver,
        api_authorizer: authorizer,
        api_identity_resolver: identity
      }
    ).build

    service = assembly.service

    assert_same resolver, service.node_resolver
    assert_same authorizer, service.authorizer
    assert_same identity, service.identity_resolver
    assert_same resolver, service.api_server.subresource_bridge.node_resolver
    assert_same authorizer, service.api_server.subresource_bridge.authorizer
  end

  def test_agent_assembler_passes_node_resolver_to_agent_service
    resolver = Rubernetes::API::SubresourceBridge::NodeResolver.new
    assembly = Rubernetes::Bootstrap::Assembler.new(
      process_name: "rubernetes-agent",
      log_io: StringIO.new,
      runtime_adapters: {node_resolver: resolver}
    ).build

    assert_same resolver, assembly.service.node_resolver
  end
end
