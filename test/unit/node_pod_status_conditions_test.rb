# frozen_string_literal: true

require "tempfile"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"
require "rubernetes/node"

class NodePodStatusConditionsTest < Minitest::Test
  Node = Rubernetes::Node
  Client = Rubernetes::Client
  PODS = "/api/v1/namespaces/dev/pods"
  POD = "#{PODS}/p".freeze
  STATUS = "#{POD}/status".freeze
  GATE = "example.test/ready"

  class InProcessTransport
    attr_reader :calls
    attr_accessor :before_patch

    def initialize(server)
      @server = server
      @calls = []
    end

    def request(method, path, body:, headers:, query:)
      if method == "PATCH" && (callback = @before_patch)
        @before_patch = nil
        callback.call
      end
      response = @server.call(method: method, path: path, body: body, headers: headers, query: query)
      @calls << [method, path, body.is_a?(String) ? JSON.parse(body) : body, response.status]
      Client::HTTPClient::Response.new(status: response.status, headers: response.headers, body: response.body_json)
    end
  end

  class Runtime
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"
    def create_container(_sandbox, _spec) = "container-1"
    def start_container(_container) = true
  end

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    server = Rubernetes::API::Server.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new, namespace_lifecycle: true)
    @transport = InProcessTransport.new(server)
    @client = Client::KubernetesClient.new(rest_client: @transport)
    @controller = Client::KubernetesClient.new(rest_client: InProcessTransport.new(server))
    @adapter = Node::APIClientAdapter.new(client: @client, node_name: "worker")
    server.call(method: "POST", path: "/api/v1/namespaces", body: {"metadata" => {"name" => "dev"}})
    create_pod
  end

  def test_status_publish_keeps_controller_condition_fields_and_uses_the_snapshot_version
    @controller.patch(POD, {"spec" => {"containers" => [{"name" => "app", "image" => "busybox:1.37"}]}},
                      type: :strategic)
    original = external_gate("True", "ProbeSucceeded")
    pod = update_external(original)
    status = Node::Status.new(reporter: @adapter, clock: -> { Time.utc(2026, 11, 20) })

    result = aggregate(status, pod)
    published = @controller.get(POD)

    assert_equal original, condition(result.to_h, GATE)
    assert_equal original, condition(published.fetch("status"), GATE)
    ready = condition(published.fetch("status"), "Ready")

    assert_equal "True", ready.fetch("status")
    assert_operator ready.fetch("observedGeneration"), :>, original.fetch("observedGeneration")
    assert_equal([["PATCH", STATUS]], @transport.calls.map { |call| call.take(2) })
    assert_equal pod.fetch("metadata").slice("uid", "resourceVersion"), @transport.calls.first.fetch(2).fetch("metadata")
    assert_equal(%w[PodReadyToStartContainers Initialized ContainersReady Ready PodScheduled] + [GATE],
                 published.dig("status", "conditions").map { |entry| entry.fetch("type") })
  end

  def test_aggregation_keeps_condition_order_and_uses_the_last_duplicate
    prior = external_gate("False", "Unready")
    other = {"type" => "example.test/check", "status" => "True"}
    latest = external_gate("True", "Ready")
    published = update_external(prior)
    pod = published.merge("status" => {"conditions" => [prior, other, latest]})

    result = aggregate(Node::Status.new, pod).to_h

    assert_equal [latest, other], result.fetch("conditions").last(2)
    assert_equal "True", condition(result, "Ready").fetch("status")
  end

  def test_a_status_snapshot_with_no_conditions_clears_cached_readiness_gates
    status = Node::Status.new(reporter: @adapter)
    pod = update_external(external_gate("True", "ControllerReady"))

    assert_equal "True", condition(aggregate(status, pod).to_h, "Ready").fetch("status")

    pod = @controller.patch(STATUS, {"status" => {"conditions" => nil}}, type: :merge)

    refute pod.fetch("status").key?("conditions")
    result = aggregate(status, pod).to_h

    assert_nil condition(result, GATE)
    assert_equal %w[False ReadinessGatesNotReady], condition(result, "Ready").values_at("status", "reason")
    published = @controller.get(POD).fetch("status")

    assert_nil condition(published, GATE)
    assert_equal %w[False ReadinessGatesNotReady], condition(published, "Ready").values_at("status", "reason")
  end

  def test_retry_keeps_a_concurrent_gate_update_and_watch_reconciles_readiness
    lifecycle = Node::Lifecycle.new(runtime: Runtime.new, reporter: @adapter)
    workers = Node::PodWorkerPool.new(reconcile: lifecycle.method(:reconcile))
    loop = Node::SyncLoop.new(source: @adapter, node_name: "worker", worker_pool: workers)
    loop.process_event("type" => "ADDED", "object" => @controller.get(POD))

    assert workers.drain(timeout: 5)

    [%w[False True], %w[True False]].each do |current, stale|
      pod = update_external(external_gate(current, "ControllerObserved"))
      loop.process_event("type" => "MODIFIED", "object" => pod)

      assert workers.drain(timeout: 5)
      assert_equal current, condition(@controller.get(POD).fetch("status"), "Ready").fetch("status")

      old = update_external(external_gate(stale, "ControllerChanged"))
      newest = external_gate(current, "ControllerChangedAgain", timestamp: "2026-11-19T00:03:00Z")
      @transport.calls.clear
      @transport.before_patch = -> { update_external(newest) }
      loop.process_event("type" => "MODIFIED", "object" => old)

      assert workers.drain(timeout: 5)

      assert_equal([["PATCH", STATUS, 409], ["GET", POD, 200], ["PATCH", STATUS, 200]],
                   @transport.calls.map { |call| call.values_at(0, 1, 3) })
      reread = @controller.get(POD)

      assert_equal newest, condition(reread.fetch("status"), GATE)

      loop.process_event("type" => "MODIFIED", "object" => reread)

      assert workers.drain(timeout: 5)
      converged = @controller.get(POD).fetch("status")

      assert_equal newest, condition(converged, GATE)
      assert_equal current, condition(converged, "Ready").fetch("status")
    end
  ensure
    workers&.stop
  end

  def test_disabled_feature_gates_leave_existing_conditions_to_their_writers
    status = agent_status_with_gates_disabled
    pod = @controller.get(POD)
    ready_type = "PodReadyToStartContainers"
    restarting_type = "AllContainersRestarting"
    initial = aggregate(status, pod).to_h

    assert_nil condition(initial, ready_type)
    assert_nil condition(initial, restarting_type)

    ready = external_gate("False", "ExternalSandbox").merge("type" => ready_type)
    restarting = external_gate("True", "ExternalRestart").merge("type" => restarting_type)
    update_external(ready)
    pod = update_external(restarting)
    newest = ready.merge("status" => "True", "reason" => "ExternalSandboxReady")
    @transport.before_patch = -> { update_external(newest) }

    result = aggregate(status, pod).to_h

    assert_equal ready, condition(result, ready_type)
    assert_equal restarting, condition(result, restarting_type)
    stored = @controller.get(POD).fetch("status")

    assert_equal newest, condition(stored, ready_type)
    assert_equal restarting, condition(stored, restarting_type)
  end

  def test_terminal_disruption_is_reported_once_and_a_later_external_disruption_survives
    initial = disruption("SchedulerMarked", "2026-11-19T00:00:00Z")
    pod = update_external(initial)
    terminating = disruption("TerminationByKubelet", "2026-11-19T00:01:00Z")
    @adapter.report(pod, "phase" => "Failed", "conditions" => [terminating])
    failed = @controller.get(POD)

    assert_equal terminating, condition(failed.fetch("status"), "DisruptionTarget")

    newest = disruption("ControllerUpdated", "2026-11-19T00:02:00Z")
    update_external(newest)
    @adapter.report(failed, "phase" => "Failed", "conditions" => [terminating])

    assert_equal [newest], @controller.get(POD).dig("status", "conditions")
  end

  def test_an_old_uid_without_a_resource_version_does_not_update_a_replacement
    original = @controller.get(POD)
    @controller.raw("DELETE", POD, body: {"gracePeriodSeconds" => 0}, headers: {"Content-Type" => "application/json"})
    replacement = create_pod
    stale = original.merge("metadata" => original.fetch("metadata").except("resourceVersion"))
    @transport.calls.clear

    @adapter.report(stale, "phase" => "Failed", "conditions" => [])

    refute_equal original.dig("metadata", "uid"), replacement.dig("metadata", "uid")
    assert_equal([["GET", POD]], @transport.calls.map { |call| call.take(2) })
    assert_equal "Pending", @controller.get(POD).dig("status", "phase")
  end

  private

  def agent_status_with_gates_disabled
    client = @client
    assembler = Class.new(Rubernetes::Bootstrap::Assembler) do
      define_method(:build_api_client) { |_process| client }
    end
    Tempfile.create(["rubernetes-status", ".yml"]) do |config|
      config.write(<<~YAML)
        processes:
          rubernetes-agent:
            node_name: worker
            feature_gates:
              PodReadyToStartContainersCondition: false
              RestartAllContainersOnContainerExits: false
      YAML
      config.flush
      assembly = assembler.new(process_name: "rubernetes-agent", config_path: config.path, log_io: StringIO.new).build
      begin
        assembly.service.node_agent.status
      ensure
        assembly.shutdown.close
      end
    end
  end

  def create_pod
    manifest = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p"},
                "spec" => {"nodeName" => "worker", "containers" => [{"name" => "app", "image" => "busybox"}],
                           "readinessGates" => [{"conditionType" => GATE}]}}
    @controller.raw("POST", PODS, body: manifest, headers: {"Content-Type" => "application/json"}).json
  end

  def aggregate(status, pod)
    state = {"containers" => {"app" => {"state" => "running", "ready" => true, "started" => true}}}
    status.aggregate(pod: pod, state: state, phase: "Running", pod_ip: "10.0.0.2", start_time: Time.utc(2026, 11, 19))
  end

  def external_gate(value, reason, timestamp: "2026-11-19T00:00:00Z")
    {"type" => GATE, "status" => value, "reason" => reason, "message" => "Controller observation",
     "lastProbeTime" => timestamp, "lastTransitionTime" => timestamp, "observedGeneration" => 1}
  end

  def disruption(reason, timestamp)
    {"type" => "DisruptionTarget", "status" => "True", "reason" => reason, "lastTransitionTime" => timestamp}
  end

  def update_external(condition)
    pod = @controller.get(POD)
    conditions = pod.dig("status", "conditions").to_a.reject { |entry| entry["type"] == condition["type"] }
    @controller.patch(STATUS, {"status" => {"conditions" => conditions + [condition]}}, type: :merge)
  end

  def condition(status, type)
    status.fetch("conditions").find { |entry| entry["type"] == type }
  end
end
