# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# pkg/quota/v1/evaluator/core/pods.go: "cpu" is requests.cpu, and every
# requests.<name> / limits.<name> -- extended resources such as
# requests.example.com/dongle included -- is summed over the namespace's Pods.
# Only requests.cpu/memory/ephemeral-storage were handled, so "[sig-api-machinery]
# ResourceQuota should create a ResourceQuota and capture the life of a pod."
# waited for ever for cpu: 500m and requests.example.com/dongle: 2 while the
# status stayed at 0, and admission, which trusts status.used, admitted Pods
# past the limit.
class ResourceQuotaComputeUsageTest < Minitest::Test
  Controller = Rubernetes::Controller

  def controller = Controller::ResourceQuotaController.new(store: nil)

  def quota(hard)
    {"apiVersion" => "v1", "kind" => "ResourceQuota",
     "metadata" => {"name" => "q", "namespace" => "ns"}, "spec" => {"hard" => hard}}
  end

  def pod(name, requests: {}, limits: {}, phase: "Running")
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns"},
     "spec" => {"containers" => [{"name" => "c", "image" => "img", "resources" => {"requests" => requests, "limits" => limits}}]},
     "status" => {"phase" => phase}}
  end

  def claim(name, storage:, storage_class: nil)
    spec = {"resources" => {"requests" => {"storage" => storage}}}
    spec["storageClassName"] = storage_class if storage_class
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => name, "namespace" => "ns"}, "spec" => spec}
  end

  def used(hard, objects)
    controller.plan(quota(hard), objects: objects).status.fetch("used")
  end

  def base(value) = controller.send(:quantity_to_base, value)

  def test_bare_compute_names_are_the_pod_requests
    hard = {"cpu" => "1", "memory" => "1Gi", "ephemeral-storage" => "50Gi", "pods" => "5"}
    pods = [pod("a", requests: {"cpu" => "500m", "memory" => "252Mi", "ephemeral-storage" => "30Gi"})]

    result = used(hard, pods)

    assert_equal base("500m"), base(result["cpu"])
    assert_equal base("252Mi"), base(result["memory"])
    assert_equal base("30Gi"), base(result["ephemeral-storage"])
    assert_equal 1, base(result["pods"])
  end

  def test_extended_resource_requests_are_summed
    hard = {"requests.example.com/dongle" => "4", "requests.hugepages-2Mi" => "100Mi"}
    pods = [pod("a", requests: {"example.com/dongle" => "2", "hugepages-2Mi" => "4Mi"}, limits: {"example.com/dongle" => "2"}),
            pod("b", requests: {"example.com/dongle" => "1"}),
            pod("done", requests: {"example.com/dongle" => "1"}, phase: "Succeeded")]

    result = used(hard, pods)

    assert_equal 3, base(result["requests.example.com/dongle"]), "terminal Pods release their usage"
    assert_equal base("4Mi"), base(result["requests.hugepages-2Mi"])
  end

  def test_limits_are_summed_separately_from_requests
    hard = {"limits.cpu" => "4", "requests.cpu" => "2"}
    pods = [pod("a", requests: {"cpu" => "250m"}, limits: {"cpu" => "1"})]

    result = used(hard, pods)

    assert_equal base("1"), base(result["limits.cpu"])
    assert_equal base("250m"), base(result["requests.cpu"])
  end

  def test_storage_class_scoped_claim_usage
    hard = {"gold.storageclass.storage.k8s.io/persistentvolumeclaims" => "2",
            "gold.storageclass.storage.k8s.io/requests.storage" => "10Gi",
            "requests.storage" => "20Gi", "persistentvolumeclaims" => "5"}
    claims = [claim("g1", storage: "1Gi", storage_class: "gold"), claim("g2", storage: "2Gi", storage_class: "gold"),
              claim("s1", storage: "4Gi", storage_class: "silver")]

    result = used(hard, claims)

    assert_equal 2, base(result["gold.storageclass.storage.k8s.io/persistentvolumeclaims"])
    assert_equal base("3Gi"), base(result["gold.storageclass.storage.k8s.io/requests.storage"])
    assert_equal base("7Gi"), base(result["requests.storage"])
    assert_equal 3, base(result["persistentvolumeclaims"])
  end

  # status.used is Quantity.String(), which is what the API server stores:
  # the limit's suffix ("0Gi" under a 10Gi limit) never equalled the stored
  # "0", so every sync rewrote the status and its own watch event queued the
  # next one.
  def test_used_quantities_are_canonical
    usage = used({"requests.storage" => "10Gi", "gold.storageclass.storage.k8s.io/requests.storage" => "10Gi", "memory" => "500Mi"},
                 [claim("a", storage: "512Mi"), claim("b", storage: "512Mi")])
    assert_equal "1Gi", usage["requests.storage"]
    assert_equal "0", usage["gold.storageclass.storage.k8s.io/requests.storage"]
    assert_equal "0", usage["memory"]
  end

end

# resource_quota_controller.go only enqueues a quota whose spec changed; a
# status-only update (the admission plugin's charge, or the controller's own
# write) must not trigger a recompute from informers that may not yet hold the
# object that was just charged.
class ResourceQuotaSkipStatusOnlyEventTest < Minitest::Test
  def controller = Rubernetes::Controller::ResourceQuotaController.new(store: nil)

  def quota(hard:, used: {})
    {"apiVersion" => "v1", "kind" => "ResourceQuota", "metadata" => {"name" => "q", "namespace" => "ns"},
     "spec" => {"hard" => hard}, "status" => {"hard" => hard, "used" => used}}
  end

  def test_a_status_only_update_is_skipped
    before = quota(hard: {"services.nodeports" => "1"}, used: {"services.nodeports" => "0"})
    after = quota(hard: {"services.nodeports" => "1"}, used: {"services.nodeports" => "1"})

    assert controller.skip_event?(after, before)
  end

  def test_a_spec_change_and_an_add_are_not_skipped
    before = quota(hard: {"pods" => "1"})
    after = quota(hard: {"pods" => "2"})

    refute controller.skip_event?(after, before)
    refute controller.skip_event?(after, nil)
  end

  # replenishment_controller.go: a counted kind matters on deletion, on a Pod
  # reaching a terminal phase, and on resync.  Adds and ordinary updates were
  # charged by admission; recomputing on them raced the charge.
  def test_only_deletions_terminal_transitions_and_resyncs_of_counted_kinds_count
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns"}, "spec" => {}}
    running = pod.merge("status" => {"phase" => "Running"})
    succeeded = pod.merge("status" => {"phase" => "Succeeded"})
    deleting = pod.merge("metadata" => pod["metadata"].merge("deletionTimestamp" => "2026-09-21T00:00:00Z"))
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "s", "namespace" => "ns"}, "spec" => {}}

    assert controller.skip_event?(pod, nil, :add)
    assert controller.skip_event?(running, pod, :update), "a status update short of terminal is admission's business"
    assert controller.skip_event?(service, service, :update)
    refute controller.skip_event?(succeeded, running, :update), "a Pod reaching Succeeded releases quota"
    refute controller.skip_event?(deleting, running, :update), "a Pod marked for deletion releases quota"
    assert controller.skip_event?(succeeded, succeeded, :update), "already terminal: nothing new to release"
    refute controller.skip_event?(pod, nil, :delete)
    refute controller.skip_event?(pod, nil, :sync)
  end

  def test_the_quotas_own_add_is_never_skipped
    refute controller.skip_event?(quota(hard: {"pods" => "1"}), nil, :add)
  end
end

# The quota controller must not compute status.used from a lagging informer
# cache: it reads the counted kinds fresh from the API when the adapter can.
class ResourceQuotaFreshReadsTest < Minitest::Test
  # A StoreAdapter subclass, as the production adapter is: adapter_for keeps
  # it instead of wrapping it.
  class RecordingAdapter < Rubernetes::Controller::StoreAdapter
    attr_reader :calls

    def initialize(objects)
      super(Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil))
      @objects = objects
      @calls = []
    end

    def list(kind, namespace: :all, selector: nil, fresh: false)
      @calls << [kind, fresh]
      @objects.select { |o| o["kind"] == kind }
    end

    def all = @objects
  end

  def controller = Rubernetes::Controller::ResourceQuotaController.new(store: nil)

  def quota(hard)
    {"apiVersion" => "v1", "kind" => "ResourceQuota", "metadata" => {"name" => "q", "namespace" => "ns"}, "spec" => {"hard" => hard}}
  end

  def test_only_the_kinds_named_by_the_hard_limits_are_listed_and_fresh
    svc = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "s", "namespace" => "ns"}, "spec" => {"type" => "NodePort", "ports" => [{"port" => 80}]}}
    adapter = RecordingAdapter.new([svc])
    hard = {"services.nodeports" => "1", "services" => "10", "pods" => "5", "cpu" => "1", "count/replicasets.apps" => "5",
            "gold.storageclass.storage.k8s.io/requests.storage" => "10Gi", "resourcequotas" => "1"}

    result = controller.plan(quota(hard), store: adapter)

    assert_equal %w[PersistentVolumeClaim Pod ReplicaSet ResourceQuota Service], adapter.calls.map(&:first).sort
    assert adapter.calls.all? { |_, fresh| fresh }, "every list must bypass the cache"
    assert_equal "1", result.status.dig("used", "services.nodeports")
    assert_equal "1", result.status.dig("used", "services")
  end

  def test_an_unknown_limit_falls_back_to_the_whole_namespace
    adapter = RecordingAdapter.new([])

    controller.plan(quota({"mystery.example.com/things" => "1", "pods" => "1"}), store: adapter)

    assert_empty adapter.calls, "unresolvable kinds fall back to adapter.all"
  end
end
