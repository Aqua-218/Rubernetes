require "base64"
# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

class M3SecondaryControllerBatch1Test < Minitest::Test
  Controller = Rubernetes::Controller
  Store = Rubernetes::Storage::MemoryStore

  # 1.24+ (LegacyServiceAccountTokenNoAutoGeneration): no Secret is minted
  # per ServiceAccount; one a user created with the name annotation is filled in.
  def test_serviceaccount_token_controller_populates_only_annotated_secrets
    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    service_account = object("ServiceAccount", "builder", uid: "sa-1")
    adapter.create(service_account, descriptor: descriptor("ServiceAccount"))
    controller = Controller::ServiceAccountTokenController.new(store: store)

    untouched = controller.reconcile(service_account, store: store, apply: true)

    assert_empty untouched.operations
    assert_empty adapter.list("Secret", namespace: "default")

    secret = object("Secret", "builder-token", uid: "secret-1")
    secret["type"] = "kubernetes.io/service-account-token"
    secret["metadata"]["annotations"] = {"kubernetes.io/service-account.name" => "builder"}
    adapter.create(secret, descriptor: descriptor("Secret"))
    first = controller.reconcile(service_account, store: store, apply: true)
    populated = adapter.find("Secret", name: "builder-token", namespace: "default")
    second = controller.reconcile(service_account, store: store, apply: true)

    assert_equal [:update], first.operations.map(&:action)
    assert_equal "sa-1", populated.dig("metadata", "annotations", "kubernetes.io/service-account.uid")
    assert_equal "default", Base64.strict_decode64(populated.dig("data", "namespace"))
    refute_empty Base64.strict_decode64(populated.dig("data", "token"))
    assert_empty second.operations
  end

  def test_endpointslice_controller_publishes_selected_pods_and_converges
    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    service = object("Service", "web", uid: "svc-1")
    service["spec"] = {"selector" => {"app" => "web"}, "ipFamilies" => ["IPv4"], "ports" => [{"name" => "http", "port" => 80}]}
    pod = pod("web-0", labels: {"app" => "web"}, ip: "10.0.0.1")
    adapter.create(service, descriptor: descriptor("Service"))
    adapter.create(pod, descriptor: descriptor("Pod"))

    controller = Controller::EndpointSliceController.new(store: store)
    first = controller.reconcile(service, store: store, apply: true)
    second = controller.reconcile(adapter.find("Service", name: "web", namespace: "default"),
                                  store: store, apply: true)
    slice = adapter.list("EndpointSlice", namespace: "default").fetch(0)

    assert_equal [:create], first.operations.map(&:action)
    assert_equal ["10.0.0.1"], slice.dig("endpoints", 0, "addresses")
    assert_equal "svc-1", slice.dig("metadata", "ownerReferences", 0, "uid")
    assert_empty second.operations
  end

  def test_endpointslice_mirroring_controller_mirrors_legacy_endpoints_and_converges
    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    endpoints = object("Endpoints", "legacy", uid: "endpoints-1")
    endpoints["subsets"] = [{"ports" => [{"port" => 8080}],
                             "addresses" => [{"ip" => "10.0.0.2"}],
                             "notReadyAddresses" => [{"ip" => "10.0.0.3"}]}]
    adapter.create(endpoints, descriptor: descriptor("Endpoints"))

    controller = Controller::EndpointSliceMirroringController.new(store: store)
    first = controller.reconcile(endpoints, store: store, apply: true)
    second = controller.reconcile(adapter.find("Endpoints", name: "legacy", namespace: "default"),
                                  store: store, apply: true)
    slices = adapter.list("EndpointSlice", namespace: "default")

    assert_equal [:create], first.operations.map(&:action)
    assert_equal 2, slices.fetch(0).fetch("endpoints").length
    assert_equal "endpointslicemirroring-controller.k8s.io",
                 slices.fetch(0).dig("metadata", "labels", "endpointslice.kubernetes.io/managed-by")
    assert_empty second.operations
  end

  def test_replicationcontroller_controller_scales_owned_pods_and_converges
    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    replication_controller = object("ReplicationController", "workers", uid: "rc-1")
    replication_controller["spec"] = {"replicas" => 2, "selector" => {"app" => "worker"},
                                      "template" => {"metadata" => {"labels" => {"app" => "worker"}},
                                                     "spec" => {"containers" => [{"name" => "worker", "image" => "example/worker"}]}}}
    adapter.create(replication_controller, descriptor: descriptor("ReplicationController"))

    controller = Controller::ReplicationControllerController.new(store: store)
    first = controller.reconcile(replication_controller, store: store, apply: true)
    persisted = adapter.find("ReplicationController", name: "workers", namespace: "default")
    second = controller.reconcile(persisted, store: store, apply: true)

    assert_equal 2, adapter.list("Pod", namespace: "default").length
    # The count of two is written in a final batch that runs only after both
    # creates landed, so it never runs ahead of the Pods that exist (the GC
    # orphan spec once read 100 while 60 existed), and one pass still
    # reaches a fixed point.
    assert_equal 2, first.status.fetch("replicas")
    assert_empty second.operations
    assert(adapter.list("Pod", namespace: "default").all? do |pod|
      pod.dig("metadata", "ownerReferences", 0, "uid") == "rc-1"
    end)
  end

  def test_pod_garbage_collector_deletes_oldest_excess_terminal_pods
    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    pods = 3.times.map do |index|
      pod = pod("done-#{index}", ip: nil)
      pod["metadata"]["creationTimestamp"] = "2026-01-01T00:0#{index}:00Z"
      pod["status"] = {"phase" => "Succeeded"}
      adapter.create(pod, descriptor: descriptor("Pod"))
      pod
    end

    controller = Controller::PodGarbageCollectorController.new(store: store)
    first = controller.reconcile(pods.fetch(0), store: store, apply: true, threshold: 1)
    second = controller.plan(pods.fetch(2), store: store, threshold: 1)

    assert_equal 2, first.deletes.length
    assert_equal(%w[done-0 done-1], first.deletes.map { |operation| operation.object.dig("metadata", "name") })
    assert_empty second.operations
  end

  def test_resourcequota_controller_recomputes_usage_status_and_converges
    quota = object("ResourceQuota", "quota", uid: "quota-1")
    quota["spec"] = {"hard" => {"pods" => "3", "requests.cpu" => "2"}}
    pod_value = pod("quota-pod", ip: nil)
    pod_value["spec"]["containers"] = [{"name" => "worker", "resources" => {"requests" => {"cpu" => "500m"}}}]

    result = Controller::ResourceQuotaController.new.plan(quota, objects: [quota, pod_value])

    assert_equal "1", result.status.dig("used", "pods")
    assert_equal "500m", result.status.dig("used", "requests.cpu")
    assert_equal :status_update, result.operations.fetch(0).action
    updated = Controller::Support.deep_copy(quota)
    updated["status"] = result.status
    converged = Controller::ResourceQuotaController.new.plan(updated, objects: [updated, pod_value])

    assert_empty converged.operations
  end

  def test_namespace_controller_deletes_content_then_removes_finalizer
    namespace = object("Namespace", "apps", uid: "ns-1", namespace: nil)
    namespace["metadata"].delete("namespace")
    namespace["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    namespace["spec"] = {"finalizers" => ["kubernetes"]}
    child = object("ConfigMap", "settings", uid: "cm-1")
    child["metadata"]["namespace"] = "apps"

    controller = Controller::NamespaceController.new
    first = controller.plan(namespace, objects: [namespace, child])
    after_content = Controller::Support.deep_copy(namespace)
    after_content["status"] = first.status
    after_content["spec"] = {"finalizers" => ["kubernetes"]}
    second = controller.plan(after_content, objects: [after_content])
    final = Controller::Support.deep_copy(after_content)
    final["status"] = second.status
    final["spec"] = {"finalizers" => []}
    third = controller.plan(final, objects: [final])

    assert_equal %i[delete status_update], first.operations.map(&:action)
    assert_equal [], second.operations.find { |operation| operation.action == :update }.object.dig("spec", "finalizers")
    assert_empty third.operations
  end

  def test_serviceaccount_controller_creates_default_account_and_converges
    namespace = object("Namespace", "apps", uid: "ns-1", namespace: nil)
    namespace["metadata"].delete("namespace")

    controller = Controller::ServiceAccountController.new
    first = controller.plan(namespace, namespaces: [namespace], service_accounts: [])
    second = controller.plan(namespace, namespaces: [namespace],
                                        service_accounts: [first.creates.fetch(0).object])

    assert_equal [:create], first.operations.map(&:action)
    assert_equal "default", first.creates.fetch(0).object.dig("metadata", "name")
    assert_empty second.operations
  end

  # The HPA reads PodMetrics (metrics.k8s.io) for the target's Pods: two
  # Pods at 100% of their request against a 50% target double the scale,
  # and at 50% the scale converges.
  class PodMetricsClient
    def initialize(milli) = @milli = milli

    def get(path, query: nil)
      raise ArgumentError, "unexpected #{path}" unless path == "/apis/metrics.k8s.io/v1beta1/namespaces/default/pods"

      {"items" => %w[web-0 web-1].map do |name|
        {"metadata" => {"name" => name, "namespace" => "default"}, "timestamp" => "2026-01-01T00:00:00Z", "window" => "30s",
         "containers" => [{"name" => "c", "usage" => {"cpu" => "#{@milli}m"}}]}
      end, "query" => query}
    end
  end

  def test_horizontal_pod_autoscaler_scales_target_and_converges
    hpa = object("HorizontalPodAutoscaler", "web-hpa", uid: "hpa-1")
    hpa["metadata"]["generation"] = 4
    hpa["spec"] = {"scaleTargetRef" => {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "web"},
                   "minReplicas" => 1, "maxReplicas" => 6,
                   "metrics" => [{"type" => "Resource", "resource" => {"name" => "cpu",
                                                                       "target" => {"type" => "Utilization", "averageUtilization" => 50}}}]}
    deployment = object("Deployment", "web", uid: "deployment-1")
    deployment["spec"] = {"replicas" => 2, "selector" => {"matchLabels" => {"app" => "web"}}}
    deployment["status"] = {"replicas" => 2}
    pods = %w[web-0 web-1].map do |name|
      {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "labels" => {"app" => "web"}},
       "spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "100m"}}}]},
       "status" => {"phase" => "Running", "startTime" => "2025-12-31T00:00:00Z",
                    "conditions" => [{"type" => "Ready", "status" => "True", "lastTransitionTime" => "2025-12-31T00:00:00Z"}]}}
    end
    scales = Class.new do
      def initialize(target) = @target = target
      def get_scale(descriptor:, **) = Controller::ScaleClient.new.snapshot_for(@target, descriptor: descriptor)
      def build_update(snapshot, replicas) = Controller::ScaleClient.new.build_update(snapshot, replicas)
    end
    clock = -> { Time.utc(2026, 1, 1, 0, 10) }
    first = Controller::HorizontalPodAutoscalerController.new(clock: clock)
      .plan(hpa, pods: pods, scale_client: scales.new(deployment),
                 metrics_client: Controller::MetricsClient.new(client: PodMetricsClient.new(100)))

    assert_equal 4, first.updates.fetch(0).object.dig("spec", "replicas")
    assert_equal 4, first.status.fetch("desiredReplicas")

    persisted_target = Controller::Support.deep_copy(deployment)
    persisted_target["spec"]["replicas"] = 4
    second = Controller::HorizontalPodAutoscalerController.new(clock: clock)
      .plan(hpa.merge("status" => first.status), pods: pods, scale_client: scales.new(persisted_target),
                                                 metrics_client: Controller::MetricsClient.new(client: PodMetricsClient.new(50)))

    assert_empty second.operations.select { |operation| operation.action == :update }, "at the target utilization the scale converges"
  end

  private

  def descriptor(kind)
    Controller::ResourceDescriptor.parse(kind)
  end

  def object(kind, name, uid:, namespace: "default")
    metadata = {"name" => name, "uid" => uid}
    metadata["namespace"] = namespace unless namespace.nil?
    {"apiVersion" => Controller::Support.default_api_version(kind), "kind" => kind,
     "metadata" => metadata}
  end

  def pod(name, labels: {}, ip: "10.0.0.1")
    value = object("Pod", name, uid: "pod-#{name}")
    value["metadata"]["labels"] = labels
    value["spec"] = {"nodeName" => "node-a"}
    value["status"] = {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => "True"}]}
    value["status"]["podIP"] = ip if ip
    value
  end
end
