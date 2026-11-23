# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/runtime/native"

class NodeInitCompletionStatusTest < Minitest::Test
  PODS = "/api/v1/namespaces/default/pods"
  POD = "#{PODS}/with-init".freeze
  STATUS = "#{POD}/status".freeze
  Node = Rubernetes::Node
  Client = Rubernetes::Client

  class InProcessTransport
    def initialize(server) = @server = server

    def request(method, path, body:, headers:, query:)
      response = @server.call(method: method, path: path, body: body, headers: headers, query: query)
      Client::HTTPClient::Response.new(status: response.status, headers: response.headers, body: response.body_json)
    end
  end

  class Runtime
    attr_reader :waited

    def initialize(exit_result)
      @exit_result = exit_result
      @waited = []
    end

    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"
    def create_container(_sandbox, spec) = "test://#{spec.fetch("name")}-id"
    def start_container(_container) = true

    def wait_container(id)
      @waited << id
      @exit_result
    end
  end

  class InventoryRuntime < Runtime
    attr_accessor :container_ids

    def sandbox_container_ids(_sandbox) = @container_ids
  end

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    server = Rubernetes::API::Server.new(registry: registry)
    @client = Client::KubernetesClient.new(rest_client: InProcessTransport.new(server))
    @adapter = Node::APIClientAdapter.new(client: @client, node_name: "worker")
    @now = Time.utc(2026, 11, 20, 1)
  end

  def test_native_init_completion_survives_lifecycle_restart_and_api_readback
    native_exit = Rubernetes::Runtime::Native.allocate.send(:container_exit, 0, nil, nil)
    runtime = Runtime.new(native_exit)
    Dir.mktmpdir("init-completion") do |directory|
      state_path = File.join(directory, "lifecycle.json")
      first = lifecycle(runtime, state_store: state_path)
      first.reconcile(create_pod)
      before = api_init_status

      assert_equal true, before.fetch("ready")
      assert_equal false, before.fetch("started")
      assert_equal 0, before.fetch("restartCount")
      terminated = before.dig("state", "terminated")

      assert_equal({"exitCode" => 0, "reason" => "Completed", "containerID" => "test://init-id",
                    "startedAt" => @now.iso8601, "finishedAt" => @now.iso8601}, terminated)
      assert_equal before.fetch("containerID"), terminated.fetch("containerID")

      @now += 60
      @client.patch(STATUS, {"status" => {"initContainerStatuses" => nil}}, type: :merge)
      recovered = lifecycle(runtime, state_store: state_path)

      assert recovered.recover.fetch("ready")
      recovered.reconcile(@client.get(POD))

      assert_equal before, api_init_status
      assert_equal ["test://init-id"], runtime.waited
    end
  end

  def test_runtime_provided_termination_details_take_precedence
    terminated = {"exitCode" => 0, "reason" => "Completed", "message" => "runtime completion",
                  "containerID" => "test://init-id", "startedAt" => "2026-11-20T00:00:00Z", "finishedAt" => "2026-11-20T00:00:17Z"}
    runtime = InventoryRuntime.new({"state" => "terminated", "exitCode" => 0, "terminated" => terminated})
    Dir.mktmpdir("runtime-init-details") do |directory|
      state_path = File.join(directory, "lifecycle.json")
      lifecycle(runtime, state_store: state_path).reconcile(create_pod)
      runtime.container_ids = %w[test://app-id]
      lifecycle(runtime, state_store: state_path).reconcile(@client.get(POD))

      assert_equal terminated, api_init_status.dig("state", "terminated")
    end
  end

  def test_recovered_init_records_confirmed_runtime_absence_without_restarting_it
    runtime = InventoryRuntime.new({"state" => "terminated", "exitCode" => 0})
    Dir.mktmpdir("missing-init-status") do |directory|
      state_path = File.join(directory, "lifecycle.json")
      lifecycle(runtime, state_store: state_path).reconcile(create_pod)
      before = api_init_status.fetch("state").fetch("terminated")

      runtime.container_ids = %w[test://app-id test://init-id]
      lifecycle(runtime, state_store: state_path).reconcile(@client.get(POD))

      assert_equal before, api_init_status.dig("state", "terminated")

      runtime.container_ids = []
      lifecycle(runtime, state_store: state_path).reconcile(@client.get(POD))

      assert_equal before, api_init_status.dig("state", "terminated")

      runtime.container_ids = %w[test://app-id]
      lifecycle(runtime, state_store: state_path).reconcile(@client.get(POD))
      after = api_init_status.fetch("state").fetch("terminated")

      assert_match(/Unable to get init container status from container runtime/, after.fetch("message"))
      assert_equal before, after.except("message")
      assert_equal ["test://init-id"], runtime.waited
    end
  end

  def test_legacy_completion_preserves_known_facts_when_no_finish_time_was_saved
    runtime = Runtime.new({"state" => "terminated", "exitCode" => 0})
    Dir.mktmpdir("legacy-init-completion") do |directory|
      state_path = File.join(directory, "lifecycle.json")
      lifecycle(runtime, state_store: state_path).reconcile(create_pod)
      data = JSON.parse(File.read(state_path))
      init = data.fetch("records").first.fetch("containers").find { |entry| entry["category"] == "init" }
      init.fetch("status").delete("terminated")
      File.write(state_path, "#{JSON.generate(data)}\n")
      @now += 60
      @client.patch(STATUS, {"status" => {"initContainerStatuses" => nil}}, type: :merge)
      recovered = lifecycle(runtime, state_store: state_path)
      recovered.reconcile(@client.get(POD))

      assert_equal({"exitCode" => 0, "reason" => "Completed", "containerID" => "test://init-id",
                    "startedAt" => "2026-11-20T01:00:00Z"}, api_init_status.dig("state", "terminated"))
    end
  end

  private

  def lifecycle(runtime, **)
    Node::Lifecycle.new(runtime: runtime, reporter: @adapter, clock: -> { @now }, **)
  end

  def create_pod
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "with-init"},
           "spec" => {"nodeName" => "worker", "initContainers" => [{"name" => "init", "image" => "busybox"}],
                      "containers" => [{"name" => "app", "image" => "busybox"}]}}
    @client.raw("POST", PODS, body: pod, headers: {"Content-Type" => "application/json"}).json
  end

  def api_init_status
    @client.get(POD).dig("status", "initContainerStatuses", 0)
  end
end
