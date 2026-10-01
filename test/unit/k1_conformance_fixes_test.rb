# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"
require "tmpdir"
require "base64"

# Regressions found by the K1 [Conformance] lane on 2026-09-11.
class K1ConformanceFixesTest < Minitest::Test
  # fieldpath.ExtractContainerResourceValue: an unset divisor is "0" on the wire.
  def test_downward_api_zero_divisor_is_one
    container = {"resources" => {"limits" => {"cpu" => "500m", "memory" => "64Mi"}}}

    assert_equal "1", Rubernetes::Node::FieldRef.resolve_resource("limits.cpu", container, divisor: "0")
    assert_equal "67108864", Rubernetes::Node::FieldRef.resolve_resource("limits.memory", container, divisor: "0")
    assert_equal "64", Rubernetes::Node::FieldRef.resolve_resource("limits.memory", container, divisor: "1Mi")
  end

  # kubelet AtomicWriter links only the first path segment into ..data.
  def test_projected_nested_paths_are_exposed_through_their_first_segment
    Dir.mktmpdir do |dir|
      root = File.join(dir, "vol")
      writer = Rubernetes::Volume::Projection::AtomicWriter.new(root, fsync: false, tmpfs: false)
      writer.write({"path/to/data-2" => "value-2", "top" => "t"})

      assert File.symlink?(File.join(root, "path"))
      assert_equal "..data/path", File.readlink(File.join(root, "path"))
      assert_equal "value-2", File.read(File.join(root, "path/to/data-2"))
      assert_equal "t", File.read(File.join(root, "top"))
      refute File.symlink?(File.join(root, "path/to/data-2"))

      writer.write({"other" => "o"})

      refute_path_exists File.join(root, "path")
      assert_equal "o", File.read(File.join(root, "other"))
    end
  end

  def test_priority_class_value_is_immutable
    old = {"apiVersion" => "scheduling.k8s.io/v1", "kind" => "PriorityClass", "metadata" => {"name" => "p"}, "value" => 100}
    same = old.merge("globalDefault" => true)
    changed = old.merge("value" => 200)

    assert_empty Rubernetes::API::ObjectValidation.validate("PriorityClass", same, old: old, namespaced: false)
    causes = Rubernetes::API::ObjectValidation.validate("PriorityClass", changed, old: old, namespaced: false)

    assert_equal ["value"], causes.map(&:field)
    assert_equal ["Invalid value: 200: field is immutable"], causes.map(&:message)
  end

  # registry strategies: AllowUnconditionalUpdate is true for ConfigMap, false for Lease.
  def test_resource_version_is_required_on_update_only_where_the_strategy_says_so
    config_map = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.ConfigMap")
    lease = Rubernetes::Generated.definition_for("io.k8s.api.coordination.v1.Lease")
    object = {"metadata" => {"name" => "x", "namespace" => "ns"}}

    refute_includes config_map.validator.errors(object.merge("apiVersion" => "v1", "kind" => "ConfigMap"), operation: :update).map(&:kubernetes_field),
                    "metadata.resourceVersion"
    assert_includes lease.validator.errors(object.merge("apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease"),
                                           operation: :update).map(&:kubernetes_field),
                    "metadata.resourceVersion"
  end

  def test_endpoints_resolve_a_named_target_port_against_container_ports
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "default", "uid" => "svc"},
               "spec" => {"selector" => {"app" => "web"}, "ports" => [{"name" => "portname1", "port" => 80, "targetPort" => "dest1"}]}}
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "web-0", "namespace" => "default", "uid" => "p", "labels" => {"app" => "web"}},
           "spec" => {"nodeName" => "n", "containers" => [{"name" => "c", "ports" => [{"name" => "dest1", "containerPort" => 8080}]}]},
           "status" => {"phase" => "Running", "podIP" => "10.0.0.1", "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    endpoints = Rubernetes::Controller::EndpointController.new.plan(service, pods: [pod]).creates.first.object

    assert_equal [{"name" => "portname1", "port" => 8080, "protocol" => "TCP"}], endpoints.dig("subsets", 0, "ports")
  end

  def test_endpoints_of_a_selector_service_are_not_mirrored
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    adapter = Rubernetes::Controller::StoreAdapter.new(store)
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "default", "uid" => "svc"},
               "spec" => {"selector" => {"app" => "web"}, "ports" => [{"port" => 80}]}}
    endpoints = {"apiVersion" => "v1", "kind" => "Endpoints", "metadata" => {"name" => "web", "namespace" => "default", "uid" => "ep"},
                 "subsets" => [{"ports" => [{"port" => 80}], "addresses" => [{"ip" => "10.0.0.2"}]}]}
    adapter.create(service, descriptor: Rubernetes::Controller::ResourceDescriptor.parse("Service"))
    adapter.create(endpoints, descriptor: Rubernetes::Controller::ResourceDescriptor.parse("Endpoints"))
    result = Rubernetes::Controller::EndpointSliceMirroringController.new(store: store).reconcile(endpoints, store: store, apply: true)

    assert_empty result.operations
    assert_empty adapter.list("EndpointSlice", namespace: "default")
  end

  def test_replication_controller_watches_its_own_kind
    definition = Rubernetes::Controller.default_registry.fetch("replicationcontroller-controller")
    kinds = Array(definition.watches).map { |watch| watch.resource.kind }

    assert_includes kinds, "ReplicationController"
  end

  # kube-proxy logs an object it cannot use and keeps consuming the stream.
  def test_proxy_watch_survives_a_callback_failure
    source = Class.new do
      def initialize = @calls = 0

      def watch(**)
        (@calls += 1) == 1 ? [{"type" => "ADDED", "object" => {"bad" => true}}, {"type" => "ADDED", "object" => {"good" => true}}] : []
      end
    end.new
    seen = []
    errors = []
    subscription = Rubernetes::Proxy::WatchSubscription.new(
      source: source,
      callback: lambda { |event|
        raise ArgumentError, "refused" if event["object"]["bad"]

        seen << event["object"]
      },
      error_handler: ->(error) { errors << error.message },
      min_backoff: 0.01, max_backoff: 0.05
    )
    subscription.start
    deadline = Time.now + 5
    sleep 0.01 while seen.empty? && Time.now < deadline
    subscription.close

    assert_equal [{"good" => true}], seen
    assert(errors.any? { |message| message.include?("refused") })
  end

  def test_running_container_status_reports_resources
    status = Rubernetes::Node::Status.new
    definition = {"name" => "c", "image" => "img", "resources" => {"requests" => {"cpu" => "100m"}, "limits" => {"cpu" => "200m"}}}
    running = status.send(:normalize_container_status, definition, {"state" => "running"})

    assert_equal definition["resources"], running["resources"]
    assert_equal({"cpu" => "100m"}, running["allocatedResources"])
    waiting = status.send(:normalize_container_status, definition, {"state" => "waiting"})

    refute waiting.key?("resources")
  end

  class FakeProjectedBackend
    attr_reader :updates, :token

    def initialize(due:, token: :present)
      (@due = due
       @token = token
       @updates = [])
    end

    def token_rotation_due?(_now) = @due
    def service_account_token_source? = true
    def update(**payload) = @updates << payload
  end

  class FakeVolumeManager
    attr_reader :backends, :rotations

    def initialize(backends)
      (@backends = backends
       @rotations = [])
    end

    def rotate_token(id, now:, token:) = @rotations << [id, token]
    def root = "/tmp/fake-volumes"
  end

  def pod_with_volumes
    {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "uid-1"},
     "spec" => {"volumes" => [{"name" => "sa", "projected" => {"sources" => [{"serviceAccountToken" => {"path" => "token"}}]}},
                              {"name" => "cm", "configMap" => {"name" => "settings"}}]}}
  end

  def test_due_projected_tokens_are_rotated_through_the_manager
    backend = FakeProjectedBackend.new(due: true)
    manager = FakeVolumeManager.new("vol-sa" => backend)
    volumes = Rubernetes::Node::PodVolumes.new(volume: manager, root: "/tmp/fake-pods")
    handle = {"mounts" => {"sa" => {"id" => "vol-sa"}}}

    assert_equal ["sa"], volumes.rotate_tokens(pod_with_volumes, handle, now: Time.at(1_800_000_000).utc)
    assert_equal [["vol-sa", "rotate-uid-1-sa-1800000000"]], manager.rotations
  end

  def test_a_backend_without_a_token_is_reprojected_once
    backend = FakeProjectedBackend.new(due: false, token: nil)
    manager = FakeVolumeManager.new("vol-sa" => backend)
    volumes = Rubernetes::Node::PodVolumes.new(volume: manager, root: "/tmp/fake-pods")
    handle = {"mounts" => {"sa" => {"id" => "vol-sa"}}}

    assert_equal ["sa"], volumes.rotate_tokens(pod_with_volumes, handle)
    assert_equal 1, backend.updates.length
    assert_equal [{"serviceAccountToken" => {"path" => "token"}}], backend.updates.first[:sources]
    assert_empty manager.rotations
  end

  def test_config_map_content_changes_are_reprojected_on_sync
    data = {"data" => {"key" => "v1"}}
    reader = Class.new do
      attr_accessor :object

      def get(_resource, _name, namespace:) = @object
    end.new
    reader.object = data
    backend = FakeProjectedBackend.new(due: false)
    manager = FakeVolumeManager.new("vol-cm" => backend)
    volumes = Rubernetes::Node::PodVolumes.new(volume: manager, reader: reader, root: "/tmp/fake-pods")
    handle = {"mounts" => {"cm" => {"id" => "vol-cm"}}}

    assert_empty volumes.refresh_contents(pod_with_volumes, handle) # first pass records
    assert_empty volumes.refresh_contents(pod_with_volumes, handle) # unchanged
    reader.object = {"data" => {"key" => "v2"}}

    assert_equal ["cm"], volumes.refresh_contents(pod_with_volumes, handle)
    assert_equal [{files: {"key" => "v2"}}], backend.updates
  end
end

class K1ConformanceFixesBatch2Test < Minitest::Test
  def rs_and_pods(match_labels)
    rs = {"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "metadata" => {"name" => "web", "namespace" => "default", "uid" => "rs-1"},
          "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "web"}},
                     "template" => {"metadata" => {"labels" => {"app" => "web"}}, "spec" => {"containers" => [{"name" => "c", "image" => "img"}]}}}}
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "web-1", "namespace" => "default", "uid" => "p1", "labels" => match_labels,
                          "ownerReferences" => [{"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "name" => "web", "uid" => "rs-1", "controller" => true,
                                                 "blockOwnerDeletion" => true}]},
           "spec" => {"nodeName" => "n"}, "status" => {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    [rs, pod]
  end

  def test_replicaset_releases_a_pod_whose_labels_stopped_matching
    rs, pod = rs_and_pods({"app" => "other"})
    result = Rubernetes::Controller::ReplicaSetController.new.plan(rs, pods: [pod])
    release = result.operations.find { |operation| operation.action == :update }

    refute_nil release
    assert_empty release.object.dig("metadata", "ownerReferences")
    assert_equal 1, result.operations.count(&:create?), "the released pod no longer counts as a replica"
  end

  def test_replicationcontroller_releases_a_pod_whose_labels_stopped_matching
    rc = {"apiVersion" => "v1", "kind" => "ReplicationController", "metadata" => {"name" => "rc", "namespace" => "default", "uid" => "rc-1"},
          "spec" => {"replicas" => 1, "selector" => {"app" => "web"},
                     "template" => {"metadata" => {"labels" => {"app" => "web"}}, "spec" => {"containers" => [{"name" => "c", "image" => "img"}]}}}}
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "rc-1", "namespace" => "default", "uid" => "p1", "labels" => {"app" => "other"},
                          "ownerReferences" => [{"apiVersion" => "v1", "kind" => "ReplicationController", "name" => "rc", "uid" => "rc-1", "controller" => true}]},
           "spec" => {"nodeName" => "n"}, "status" => {"phase" => "Running"}}
    result = Rubernetes::Controller::ReplicationControllerController.new.plan(rc, pods: [pod])
    release = result.operations.find { |operation| operation.action == :update }

    refute_nil release
    assert_empty release.object.dig("metadata", "ownerReferences")
    assert_equal 1, result.operations.count(&:create?)
  end

  def test_webhook_client_dials_the_resolved_endpoint_and_keeps_the_service_path
    client = Rubernetes::Security::Admission::Plugins::WebhookClient.new(service_resolver: ->(_ns, _name, _port) { ["10.0.0.9", 8443] })
    config = {"service" => {"namespace" => "ns", "name" => "hook", "path" => "/convert", "port" => 443}}

    assert_equal "https://hook.ns.svc:443/convert", client.send(:resolve_url, config)
    assert_equal ["10.0.0.9", 8443], client.send(:resolve_address, config)
    assert_nil client.send(:resolve_address, {"url" => "https://example.test/x"})
  end

  # A Service without endpoints used to fall through to the .svc hostname and
  # fail with getaddrinfo, hiding the real condition from the admission error.
  def test_webhook_call_fails_clearly_when_the_service_has_no_endpoints
    client = Rubernetes::Security::Admission::Plugins::WebhookClient.new(service_resolver: ->(_ns, _name, _port) {})
    config = {"service" => {"namespace" => "ingress-nginx", "name" => "ingress-nginx-controller-admission", "port" => 443}}
    error = assert_raises(Rubernetes::Security::Admission::Error) { client.call(config, {"kind" => "AdmissionReview"}, timeout_seconds: 1) }
    assert_equal "no endpoints available for service ingress-nginx/ingress-nginx-controller-admission", error.message
  end
end

class K1ConformanceFixesBatch3Test < Minitest::Test
  def test_watch_read_timeout_outlives_the_server_side_timeout
    client = Rubernetes::Client::HTTPClient.new(server: "https://127.0.0.1:1")
    http = Net::HTTP.new("127.0.0.1", 1)
    client.send(:configure_http, http, URI("https://127.0.0.1:1/api/v1/pods?watch=true&timeoutSeconds=300"))

    assert_equal 360, http.read_timeout
    client.send(:configure_http, http, URI("https://127.0.0.1:1/api/v1/pods"))

    assert_equal Rubernetes::Client::HTTPClient::DEFAULT_READ_TIMEOUT, http.read_timeout
  end

  def test_reflector_asks_the_server_to_end_each_watch_after_five_to_ten_minutes
    captured = {}
    client = Object.new
    client.define_singleton_method(:watch) do |**options|
      captured.merge!(options)
      []
    end
    client.define_singleton_method(:list) { |**_options| {"items" => [], "metadata" => {"resourceVersion" => "1"}} }
    reflector = Rubernetes::Watch::Reflector.new(client: client, fifo: Rubernetes::Watch::DeltaFIFO.new,
                                                 resource: Rubernetes::Controller::ResourceDescriptor.parse("Pod"))
    reflector.watch_once

    assert_includes 300..600, captured[:timeout_seconds]
  end
end

class K1ConformanceFixesBatch4Test < Minitest::Test
  def pod_with_port(name, port)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "uid" => name, "labels" => {"app" => "web"}},
     "spec" => {"nodeName" => "n", "containers" => [{"name" => "c", "ports" => [{"name" => "example-name", "containerPort" => port}]}]},
     "status" => {"phase" => "Running", "podIP" => "10.0.0.#{port % 100}", "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def test_endpoints_named_target_port_groups_pods_by_resolved_port
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "default", "uid" => "svc"},
               "spec" => {"selector" => {"app" => "web"}, "ports" => [{"name" => "http", "port" => 80, "targetPort" => "example-name"}]}}
    endpoints = Rubernetes::Controller::EndpointController.new.plan(service,
                                                                    pods: [pod_with_port("pod1", 3000),
                                                                           pod_with_port("pod2", 3001)]).creates.first.object
    subsets = endpoints["subsets"]

    assert_equal 2, subsets.length
    assert_equal([3000, 3001], subsets.map { |subset| subset.dig("ports", 0, "port") })
    assert_equal([["10.0.0.0"], ["10.0.0.1"]], subsets.map { |subset| subset["addresses"].map { |address| address["ip"] } })
  end

  def test_garbage_collector_watches_owner_kinds
    definition = Rubernetes::Controller.default_registry.fetch("garbage-collector-controller")
    kinds = Array(definition.watches).map { |watch| watch.resource.kind }

    %w[Pod ReplicationController ReplicaSet Deployment Job].each { |kind| assert_includes kinds, kind }
  end
end

class K1ConformanceFixesBatch5Test < Minitest::Test
  def test_rotated_token_keeps_the_original_lifetime
    provider = Class.new do
      def issue(audience:, pod_uid:, ttl:) = {"token" => "t-#{ttl}-#{rand(1_000_000)}"}
    end.new
    clock = Time.utc(2026, 9, 11, 14, 0)
    now = clock
    rotator = Rubernetes::Volume::Projection::TokenRotator.new(provider: provider, clock: -> { now })
    token = rotator.issue(audience: "", pod_uid: "u", ttl: 3600)
    later = clock + 3000
    now = later
    rotated = rotator.rotate(token, now: later)

    refute_equal token.value, rotated.value
    assert_equal later, rotated.issued_at
    assert_in_delta 3600, rotated.expires_at - rotated.issued_at, 1
  end

  def test_cel_message_construction_builds_nested_maps
    result = Rubernetes::Security::CEL::Evaluator.new.evaluate("Object{spec: Object.spec{replicas: 1337, labels: {'a': 'b'}}}")

    assert_equal({"spec" => {"replicas" => 1337, "labels" => {"a" => "b"}}}, result)
  end
end

class K1ConformanceFixesBatch6Test < Minitest::Test
  def test_sandbox_never_reuses_a_container_id
    sandbox = Rubernetes::Runtime::Native::Sandbox.new(id: "sb", identity: "sb", config: {})
    first = sandbox.create_container(spec: {"name" => "c"})
    sandbox.update_container(first, state: :stopped)
    sandbox.remove_container(first)
    second = sandbox.create_container(spec: {"name" => "c"})

    refute_equal first.id, second.id
  end
end

class K1ConformanceFixesBatch7Test < Minitest::Test
  def test_endpointslice_omits_a_named_target_port_no_pod_exposes
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "default", "uid" => "svc"},
               "spec" => {"selector" => {"app" => "web"}, "ports" => [{"name" => "http", "port" => 80, "targetPort" => "missing"}]}}
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "default", "uid" => "p", "labels" => {"app" => "web"}},
           "spec" => {"nodeName" => "n", "containers" => [{"name" => "c", "ports" => [{"name" => "other", "containerPort" => 9}]}]},
           "status" => {"phase" => "Running", "podIP" => "10.0.0.1", "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    create = Rubernetes::Controller::EndpointSliceController.new.plan(service, pods: [pod]).creates.first

    refute_nil create
    assert_empty Array(create.object["ports"])
    refute(Array(create.object["ports"]).any? { |port| port["port"].to_i.zero? })
  end
end

class K1ConformanceFixesBatch8Test < Minitest::Test
  def test_proxy_service_model_accepts_a_headless_service_with_ip_families
    service = Rubernetes::Proxy::Service.new({"metadata" => {"name" => "h", "namespace" => "d"},
                                              "spec" => {"clusterIP" => "None", "clusterIPs" => ["None"], "ipFamilies" => ["IPv4"],
                                                         "ports" => [{"port" => 80}], "selector" => {"app" => "x"}}})

    assert_empty service.cluster_ips
  end
end
