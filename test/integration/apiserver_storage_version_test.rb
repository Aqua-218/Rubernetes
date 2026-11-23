# frozen_string_literal: true

require "stringio"

require_relative "../test_helper"
require "rubernetes/bootstrap"

class APIServerStorageVersionTest < Minitest::Test
  API = Rubernetes::API
  BOOTSTRAP = Rubernetes::Bootstrap
  VERSION = "internal.apiserver.k8s.io/v1alpha1"
  ROOT = "/apis/#{VERSION}/storageversions".freeze
  REPORT = "#{ROOT}/core.configmaps".freeze
  CONFIG_MAPS = "/api/v1/namespaces/default/configmaps"
  ADMIN = {"username" => "admin", "groups" => ["system:masters"]}.freeze

  def test_alpha_runtime_serving_and_reporting_are_independent
    disabled = build_server(enabled: false, runtime: false)

    assert_equal 404, call_api(disabled, "GET", ROOT).status
    assert_equal 201, create_config_map(disabled).status

    runtime_only = build_server(enabled: false)

    assert_equal 200, call_api(runtime_only, "GET", ROOT).status
    assert_equal 201, create_config_map(runtime_only).status
    assert_empty call_api(runtime_only, "GET", ROOT).body["items"]
    invalid = call_api(runtime_only, "POST", ROOT, {"metadata" => {"name" => "nodot"}})

    assert_equal 422, invalid.status
    assert_includes invalid.body.dig("details", "causes", 0, "message"), "<group>.<resource>"

    assert_raises(ArgumentError) do
      API::Server.new(feature_gates: {"APIServerIdentity" => false, "StorageVersionAPI" => true})
    end
  end

  def test_pending_reports_gate_writes_and_merge_multiple_server_registrations
    store = Rubernetes::Storage::MemoryStore.new
    server = build_server(store: store)
    blocked = create_config_map(server)

    assert_equal 503, blocked.status
    assert_equal 500, call_api(server, "GET", "/readyz").status
    assert_equal 500, call_api(server, "GET", "/healthz").status
    assert_includes blocked.body["message"], "wait for storage version registration"
    assert_equal 200, call_api(server, "GET", CONFIG_MAPS).status
    assert_equal 201, call_api(server, "POST", "/apis/example.test/v1/widgets", {"metadata" => {"name" => "a"}}).status
    lease = {"metadata" => {"name" => "lease"}, "spec" => {"holderIdentity" => "apiserver"}}

    assert_equal 201, call_api(server, "POST", "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases", lease).status
    assert_equal 503, call_api(server, "POST", "/apis/coordination.k8s.io/v1/namespaces/default/leases", lease).status
    bootstrap = {"username" => "system:apiserver", "groups" => ["system:masters"]}

    assert_equal 201, server.call(method: "POST", path: "/api/v1/namespaces", identity: bootstrap,
                                  body: {"metadata" => {"name" => "system-bootstrap"}}).status

    assert server.publish_storage_versions!("apiserver-a")
    assert_equal 200, call_api(server, "GET", "/readyz").status
    assert_equal 201, create_config_map(server).status
    assert_equal "v1", call_api(server, "GET", REPORT).body.dig("status", "commonEncodingVersion")

    peer = build_server(store: store)

    assert_equal 503, create_config_map(peer).status
    assert peer.publish_storage_versions!("apiserver-b")
    object = call_api(server, "GET", REPORT).body
    entries = object.dig("status", "storageVersions")

    assert_equal(%w[apiserver-a apiserver-b], entries.map { |entry| entry["apiServerID"] })
    assert_equal ["v1"], entries.first["decodableVersions"]
    assert_equal ["v1"], entries.first["servedVersions"]
    assert_equal "True", object.dig("status", "conditions", 0, "status")
    assert peer.publish_storage_versions!("apiserver-b")
    assert_equal object.dig("metadata", "resourceVersion"), call_api(server, "GET", REPORT).body.dig("metadata", "resourceVersion")

    failed_status = object.merge("status" => object["status"].merge("commonEncodingVersion" => "v9"))
    invalid = call_api(server, "PUT", "#{REPORT}/status", failed_status)

    assert_equal 422, invalid.status
    assert_equal "status.commonEncodingVersion", invalid.body.dig("details", "causes", 0, "field")
  end

  def test_controller_manager_gates_and_reconciles_storage_version_garbage_collection
    logger = BOOTSTRAP::StructuredLogger.new(io: StringIO.new, process_name: "storage-version-gc-test")
    server = build_server(enabled: false)
    http = Rubernetes::Transport::HTTPServer.new(server, port: 0).start
    client = Rubernetes::Client::KubernetesClient.new(server: "http://127.0.0.1:#{http.port}", namespace: "default")
    name = "storageversion-garbage-collector-controller"
    config = {"controllers" => [name], "sync" => {"interval_seconds" => 0.01}}

    [config, config.merge("feature_gates" => {"APIServerIdentity" => false, "StorageVersionAPI" => true})].each do |disabled|
      controller = BOOTSTRAP::ControllerManagerService.new(config: disabled, logger: logger, client: client).start

      refute_includes controller.manager.controllers.keys, name
      controller.stop
    end

    lease_path = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases"
    lease = {"metadata" => {"name" => "apiserver-live", "labels" => {"apiserver.kubernetes.io/identity" => "kube-apiserver"}},
             "spec" => {"holderIdentity" => "apiserver-live"}}

    assert_equal 201, call_api(server, "POST", lease_path, lease).status
    created = call_api(server, "POST", ROOT, {"metadata" => {"name" => "core.configmaps"}})

    assert_equal 201, created.status
    entries = %w[apiserver-live apiserver-gone].map do |id|
      {"apiServerID" => id, "encodingVersion" => "v1", "decodableVersions" => ["v1"], "servedVersions" => ["v1"]}
    end
    status = {"storageVersions" => entries, "commonEncodingVersion" => "v1"}

    assert_equal 200, call_api(server, "PUT", "#{REPORT}/status", created.body.merge("status" => status)).status

    enabled = config.merge("feature_gates" => {"StorageVersionAPI" => true})
    controller = BOOTSTRAP::ControllerManagerService.new(config: enabled, logger: logger, client: client).start

    assert_includes controller.manager.controllers.keys, name
    pruned = eventually do
      response = call_api(server, "GET", REPORT)
      response.status == 200 && response.body.dig("status", "storageVersions").map { |entry| entry["apiServerID"] } == ["apiserver-live"]
    end

    assert pruned
    assert_equal 200, call_api(server, "DELETE", "#{lease_path}/apiserver-live").status
    assert(eventually { call_api(server, "GET", REPORT).status == 404 })
  ensure
    controller&.stop
    http&.stop
  end

  def test_production_service_publishes_after_renewing_its_identity_lease
    config = BOOTSTRAP::Config.load(process_name: "rubernetes-apiserver").process.merge(
      "port" => 0,
      "runtime_config" => {VERSION => true},
      "security" => {"feature_gates" => {"StorageVersionAPI" => true}, "authorization" => {"modes" => ["RBAC"]}}
    )
    logger = BOOTSTRAP::StructuredLogger.new(io: StringIO.new, process_name: "storage-version-test")
    service = BOOTSTRAP::APIServerService.new(config: config, logger: logger)

    assert_equal 503, create_config_map(service.api_server).status
    service.start

    report = eventually do
      response = call_api(service.api_server, "GET", REPORT)
      response.body if response.status == 200 && response.body.dig("status", "commonEncodingVersion") == "v1"
    end
    server_id = report.dig("status", "storageVersions", 0, "apiServerID")
    lease = call_api(service.api_server, "GET", "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/#{server_id}")

    assert_equal 200, lease.status
    assert_equal "kube-apiserver", lease.body.dig("metadata", "labels", "apiserver.kubernetes.io/identity")
    assert_equal 201, create_config_map(service.api_server).status
    assert(eventually { call_api(service.api_server, "GET", "/api/v1/namespaces/default/services/kubernetes").status == 200 })
    gc = {"username" => "system:serviceaccount:kube-system:storage-version-garbage-collector",
          "groups" => ["system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"]}

    assert_equal 200, call_api(service.api_server, "GET", ROOT, identity: gc).status
    assert_equal 200, call_api(service.api_server, "PUT", "#{REPORT}/status", report, identity: gc).status
    assert_equal 403, call_api(service.api_server, "POST", ROOT, {"metadata" => {"name" => "core.other"}}, identity: gc).status
    assert_equal 403, call_api(service.api_server, "GET", CONFIG_MAPS, identity: gc).status
  ensure
    service&.stop(reason: "test")
  end

  private

  def build_server(enabled: true, runtime: true, store: Rubernetes::Storage::MemoryStore.new)
    registry = API::Registry.new
    registry.register(API::Resource.new(group: "internal.apiserver.k8s.io", version: "v1alpha1", resource: "storageversions",
                                        kind: "StorageVersion", subresources: {"status" => {verbs: %w[get patch update]}}))
    registry.register(API::Resource.new(group: "coordination.k8s.io", version: "v1", resource: "leases", kind: "Lease", scope: :namespaced))
    registry.register(API::Resource.new(group: "example.test", version: "v1", resource: "widgets", kind: "Widget", custom: true))
    API::Server.new(registry: registry, store: store, feature_gates: {"StorageVersionAPI" => enabled}, namespace_lifecycle: true,
                    runtime_config: {VERSION => runtime})
  end

  def call_api(server, method, path, body = nil, identity: ADMIN)
    server.call(method: method, path: path, body: body, identity: identity)
  end

  def create_config_map(server)
    call_api(server, "POST", CONFIG_MAPS, {"metadata" => {"name" => "report-test"}})
  end

  def eventually
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 8
    loop do
      value = yield
      return value if value

      flunk "storage version was never published" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.05
    end
  end
end
