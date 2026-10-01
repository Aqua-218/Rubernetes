# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

class M3ControllerTest < Minitest::Test
  Controller = Rubernetes::Controller
  Store = Rubernetes::Storage::MemoryStore

  def test_builtin_corpus_and_default_registry_are_complete
    corpus = Controller::BuiltinControllerCorpus

    assert_equal "v1.36.2", corpus::VERSION
    assert_equal 52, corpus.names.length
    assert_equal corpus.names.length, corpus.names.uniq.length
    assert_predicate corpus, :complete?
    assert_equal Controller::BUILTIN_IMPLEMENTATIONS.keys.sort, Controller.default_registry.names
    assert_empty Controller.default_registry.missing_names
    assert_empty Controller.unimplemented_builtin_controllers
    assert_same Controller.default_registry, Controller.default_registry.startup_validate!
  end

  def test_base_controller_is_abstract_and_cannot_be_used_as_a_reconciler
    assert_raises(Controller::MissingReconcileError) { Controller::BaseController.new }
  end

  def test_default_registry_has_no_generic_corpus_fallback
    refute Controller.const_defined?(:CorpusController, false)
    Controller.default_registry.each do |definition|
      refute_nil definition.implementation
      assert_operator definition.implementation, :<=, Controller::BaseController,
                      "#{definition.name} must use a concrete BaseController implementation"
    end
  end

  # Controllers spec C1/C5 and coding standard R-3: a lost leader must be
  # fenced at the adapter effect point before the backing store is mutated.
  def test_reconcile_fence_runs_immediately_before_store_effect
    store = Store.new(history_revisions: nil, history_seconds: nil)
    descriptor = Controller::ResourceDescriptor.parse("ConfigMap")
    resource = object("ConfigMap", "fenced", uid: "fenced-uid")
    Controller::StoreAdapter.new(store).create(resource, descriptor: descriptor)
    controller_class = Class.new(Controller::BaseController) do
      define_method(:plan) do |current, **_options|
        candidate = Controller::Support.deep_copy(current)
        candidate["data"] = {"state" => "changed"}
        Controller::ReconcileResult.new(
          operations: [operation_update(current, candidate, descriptor: Controller::ResourceDescriptor.parse("ConfigMap"))],
          controller: name
        )
      end
    end
    controller = controller_class.new(store: store, name: "fenced-controller")
    revision_before = store.revision

    assert_raises(Controller::LeadershipLostError) do
      controller.reconcile(resource, store: store, apply: true,
                                     leader_guard: -> { raise Controller::LeadershipLostError, "lease lost" })
    end

    assert_equal revision_before, store.revision
    assert_nil Controller::StoreAdapter.new(store).find(descriptor, name: "fenced", namespace: "default").dig("data", "state")
  end

  # Controllers spec C3: ReplicaSet scale-up is capped at 500 and presented
  # to the adapter as exponentially increasing slow-start batches.
  def test_replicaset_slow_start_batches_double_at_the_adapter_boundary
    store = Store.new(history_revisions: nil, history_seconds: nil)
    descriptor = Controller::ResourceDescriptor.parse("ReplicaSet")
    replica_set_value = replica_set(replicas: 7)
    Controller::StoreAdapter.new(store).create(replica_set_value, descriptor: descriptor)
    recording_adapter_class = Class.new(Controller::StoreAdapter) do
      attr_reader :batch_sizes

      def initialize(store)
        super
        @batch_sizes = []
      end

      def apply_batch(operations, fence: nil)
        @batch_sizes << Array(operations).length
        super
      end
    end
    adapter = recording_adapter_class.new(store)
    controller = Controller::ReplicaSetController.new(store: adapter)

    result = controller.reconcile(replica_set_value, store: adapter, apply: true)

    assert_equal [1, 2, 4], result.batches.take(3).map(&:length)
    assert_equal [1, 2, 4, 1], adapter.batch_sizes
    assert_equal 7, adapter.list("Pod", namespace: "default").length
  end

  def test_registry_fails_closed_for_missing_builtin_and_unknown_gvk
    registry = Controller::ControllerRegistry.new(require_corpus: true)
    error = assert_raises(Controller::MissingControllerError) { registry.startup_validate! }
    assert_match "built-in controller corpus", error.message

    open_registry = Controller::ControllerRegistry.new(require_corpus: false)
    assert_raises(Controller::UnknownGVKError) do
      Controller.controller("Unknown", registry: open_registry) do
        watches({"apiVersion" => "apps/v9", "kind" => "Deployment"})
        reconcile { |_resource| nil }
      end
    end
  end

  def test_dsl_generates_owner_index_watch_and_reconcile_wiring
    registry = Controller::ControllerRegistry.new(require_corpus: false)
    definition = Controller.controller("ReplicaSet", registry: registry) do
      owns "Pod"
      watches "Pod", via: :owner_reference
      reconcile { |resource| resource }
    end

    assert_equal "replicaset-controller", definition.name
    assert_equal "Pod", definition.owns.first.dependent.kind
    assert_equal :owner_reference, definition.watches.first.via
    assert definition.watches.first.index_name.start_with?("owner/")
    assert_equal definition, registry.fetch("replicaset-controller")
  end

  def test_dsl_rejects_scope_mismatch_and_global_ownership_cycles
    registry = Controller::ControllerRegistry.new(require_corpus: false)
    assert_raises(Controller::ScopeMismatchError) do
      Controller.controller("ReplicaSet", registry: registry) do
        watches "Pod", scope: :cluster
        reconcile { |_resource| nil }
      end
    end

    a = Controller::ControllerDefinition.new(
      name: "a-controller", kind: Controller::ResourceDescriptor.parse("Deployment"),
      owns: [Controller::OwnershipEdge.new(owner: Controller::ResourceDescriptor.parse("Deployment"),
                                           dependent: Controller::ResourceDescriptor.parse("ReplicaSet"))],
      reconcile_block: ->(_resource) {}
    )
    b = Controller::ControllerDefinition.new(
      name: "b-controller", kind: Controller::ResourceDescriptor.parse("ReplicaSet"),
      owns: [Controller::OwnershipEdge.new(owner: Controller::ResourceDescriptor.parse("ReplicaSet"),
                                           dependent: Controller::ResourceDescriptor.parse("Deployment"))],
      reconcile_block: ->(_resource) {}
    )
    registry.register_many([a, b])
    assert_raises(Controller::OwnershipCycleError) { registry.startup_validate! }
  end

  def test_owner_reference_requires_uid_and_controller_flag
    owner = object("ReplicaSet", "rs", uid: "uid-a")
    owned = object("Pod", "pod", uid: "pod-a", owners: [owner])
    stale = object("Pod", "stale", uid: "pod-b", owners: [owner.merge("metadata" => owner.fetch("metadata").merge("uid" => "uid-old"))])
    non_controller = object("Pod", "other", uid: "pod-c", owners: [owner], controller: false)
    index = Controller::OwnerReferenceIndex.new

    refute index.owned?(owner, stale, controller: true)
    assert index.owned?(owner, owned, controller: true)
    refute index.owned?(owner, non_controller, controller: true)
  end

  def test_deployment_rollout_is_hash_addressed_and_diff_only
    deployment = deployment(replicas: 3, generation: 2)
    result = Controller::DeploymentController.new.plan(deployment, replicasets: [])
    create = result.creates.fetch(0)

    assert_equal "ReplicaSet", create.resource.kind
    assert_equal 3, create.object.dig("spec", "replicas")
    assert_equal create.object.dig("metadata", "labels", "pod-template-hash"),
                 create.object.dig("spec", "selector", "matchLabels", "pod-template-hash")
    assert_equal(1, result.operations.count { |operation| operation.action == :update })
    assert_equal(1, result.operations.count { |operation| operation.action == :status_update })
    assert_equal 0, result.deletes.length
    assert_equal 2, result.status.fetch("observedGeneration")
  end

  def test_replicaset_caps_scale_up_and_prioritizes_pending_unscheduled_deletion
    rs = replica_set(replicas: 600)
    result = Controller::ReplicaSetController.new.plan(rs, pods: [])

    assert_equal 500, result.creates.length

    candidates = [
      pod("running", phase: "Running", node: "node-a", created: "2026-01-01T00:00:01Z"),
      pod("pending", phase: "Pending", node: "node-a", created: "2026-01-01T00:00:02Z"),
      pod("unscheduled", phase: "Pending", node: nil, created: "2026-01-01T00:00:03Z")
    ]
    smaller = replica_set(replicas: 1)
    candidates.each do |candidate|
      candidate["metadata"]["ownerReferences"] = [Controller::Support.owner_reference(smaller)]
      # Owned Pods must still match the selector; ones that do not are released, not scaled down.
      candidate["metadata"]["labels"] = Controller::Support.deep_copy(smaller.dig("spec", "selector", "matchLabels") || {})
    end
    smaller_result = Controller::ReplicaSetController.new.plan(smaller, pods: candidates)

    assert_equal(%w[unscheduled pending], smaller_result.deletes.map { |operation| operation.object.dig("metadata", "name") })
  end

  def test_statefulset_keeps_stable_ordinals_and_scales_down_highest_first
    set = stateful_set(replicas: 2)
    pods = [0, 1, 2].map { |ordinal| pod("db-#{ordinal}", owners: [set], labels: {"controller.kubernetes.io/ordinal" => ordinal.to_s}) }
    result = Controller::StatefulSetController.new.plan(set, pods: pods)

    assert_equal(["db-2"], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
    assert_empty result.creates
  end

  def test_daemonset_assigns_one_pod_per_schedulable_matching_node
    daemon = daemon_set
    nodes = [node("node-a", labels: {"role" => "worker"}), node("node-b", labels: {"role" => "worker"}),
             node("node-c", labels: {"role" => "control"})]
    result = Controller::DaemonSetController.new.plan(daemon, pods: [], nodes: nodes)

    assert(result.creates.all? { |operation| operation.object.dig("spec", "nodeName").nil? })
    assert_equal(%w[node-a node-b], result.creates.map do |operation|
      operation.object.dig("spec", "affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution",
                           "nodeSelectorTerms", 0, "matchFields", 0, "values", 0)
    end)
    assert_equal 2, result.status.fetch("desiredNumberScheduled")
  end

  def test_job_and_cronjob_are_time_and_completion_deterministic
    job = job(replicas: 3)
    result = Controller::JobController.new.plan(job, pods: [])

    assert_equal 1, result.creates.length
    # Upstream only counts terminated Pods that still carry the job-tracking
    # finalizer; a Pod without it was already accounted for.
    completed = pod("job-done", owners: [job], phase: "Succeeded")
    completed["metadata"]["finalizers"] = ["batch.kubernetes.io/job-tracking"]
    complete = Controller::JobController.new.plan(job, pods: [completed, pod("job-running", owners: [job])])

    assert_equal 1, complete.status.fetch("succeeded")
    assert_equal 1, complete.status.fetch("active")
    assert(complete.updates.any? do |operation|
      operation.resource.kind == "Pod" && !operation.object.dig("metadata", "finalizers").include?("batch.kubernetes.io/job-tracking")
    end)

    # Upstream schedules only the most recent unmet time; the Job name is the
    # schedule minute count since the epoch (cronjob/utils.go getJobName).
    cron = cron_job
    cron["metadata"]["creationTimestamp"] = "2025-12-31T00:00:00Z"
    at = Time.utc(2026, 1, 1, 0, 5)
    cron_result = Controller::CronJobController.new(clock: -> { at }).plan(cron, jobs: [], now: at)

    assert_equal 1, cron_result.creates.length
    assert_equal "cron-#{at.to_i / 60}", cron_result.creates.first.object.dig("metadata", "name")
    assert_equal at.iso8601(6), cron_result.status.fetch("lastScheduleTime")
    assert_includes cron_result.events.map { |event| event.fetch("reason") }, "TooManyMissedTimes"
  end

  def test_node_grace_and_taint_evict_only_pods_without_toleration
    n = node("node-a")
    n["status"] =
      {"conditions" => [{"type" => "Ready", "status" => "False", "lastHeartbeatTime" => "2025-12-31T23:54:00Z",
                         "lastTransitionTime" => "2025-12-31T23:54:00Z"}]}
    evict = pod("evict", node: "node-a")
    tolerate = pod("tolerate", node: "node-a")
    tolerate["spec"]["tolerations"] = [{"key" => "node.kubernetes.io/unreachable", "effect" => "NoExecute", "operator" => "Exists"}]
    result = Controller::NodeController.new(clock: -> { Time.utc(2026, 1, 1) }).plan(n, pods: [evict, tolerate], now: Time.utc(2026, 1, 1))

    update = result.operations.find { |operation| operation.action == :update }

    assert_equal "node.kubernetes.io/unreachable", update.object.dig("spec", "taints").first.fetch("key")
    assert_equal(["evict"], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
    # The condition travels through the status subresource (UpdateStatus);
    # the taint update carries the status the node was read with, since the
    # primary URL ignores status anyway.
    status_update = result.operations.find { |operation| operation.action == :status_update }

    refute_nil status_update, "the stale node's Ready condition is written through the status subresource"
    ready = status_update.patch.fetch("conditions").find { |condition| condition["type"] == "Ready" }

    assert_equal "Unknown", ready["status"]
    assert_equal "NodeStatusUnknown", ready["reason"]
    assert_equal "Unknown", update.object.dig("status", "conditions", 0, "status"), "the taint write carries the new status"
    assert_operator result.operations.index(status_update), :<, result.operations.index(update)
    # doNoScheduleTaintingPass: the Unknown condition also yields the
    # unreachable:NoSchedule taint, next to the NoExecute eviction taint.
    taints = update.object.dig("spec", "taints").map { |taint| [taint["key"], taint["effect"]] }

    assert_includes taints, ["node.kubernetes.io/unreachable", "NoSchedule"]
    assert_includes taints, ["node.kubernetes.io/unreachable", "NoExecute"]
  end

  def test_endpoint_controller_separates_ready_and_not_ready_addresses
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "default"},
               "spec" => {"selector" => {"app" => "web"}, "ports" => [{"port" => 80}]}}
    ready = pod("ready", labels: {"app" => "web"}, ip: "10.0.0.1")
    pending = pod("pending", labels: {"app" => "web"}, ip: "10.0.0.2", ready: false)
    endpoint = Controller::EndpointController.new.plan(service, pods: [ready, pending]).creates.first.object

    assert_equal(["10.0.0.1"], endpoint.dig("subsets", 0, "addresses").map { |address| address.fetch("ip") })
    assert_equal(["10.0.0.2"], endpoint.dig("subsets", 0, "notReadyAddresses").map { |address| address.fetch("ip") })
  end

  def test_garbage_collector_detects_cycle_and_orders_foreground_deletion
    parent = object("ConfigMap", "parent", uid: "parent")
    child = object("ConfigMap", "child", uid: "child", owners: [parent])
    grandchild = object("ConfigMap", "grandchild", uid: "grandchild", owners: [child])
    gc = Controller::GarbageCollector.new
    result = gc.deletion_plan(parent, [parent, child, grandchild], propagation_policy: :foreground)

    assert_equal(%w[grandchild child parent], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
    parent["metadata"]["ownerReferences"] = [{"kind" => "ConfigMap", "name" => "child", "uid" => "child"}]
    child["metadata"]["ownerReferences"] = [{"kind" => "ConfigMap", "name" => "parent", "uid" => "parent"}]
    cycle = gc.plan([parent, child])

    assert_empty cycle.operations
    assert_equal "OwnerReferenceCycle", cycle.events.first.fetch("reason")
  end

  def test_lease_election_has_single_writer_and_recovery_after_expiry
    now = Time.utc(2026, 1, 1)
    store = Store.new(history_revisions: nil, history_seconds: nil)
    first = Controller::LeaseElector.new(store: store, identity: "first", clock: -> { now })
    second = Controller::LeaseElector.new(store: store, identity: "second", clock: -> { now })

    assert_equal :acquired, first.step
    assert_equal :follower, second.step
    now += 16

    assert_equal :acquired, second.step
    assert_equal "second", store.list("").items.first.dig("spec", "holderIdentity")
  end

  # A leader whose renewal missed the renew deadline steps down but still
  # holds the lease; it must re-acquire on the next step without waiting for
  # the lease to expire and without counting a leader transition (client-go
  # acquire loop semantics).  Before this rule the elector stayed :lost until
  # an unrelated writer touched the lease.
  def test_lease_holder_reacquires_its_own_lease_after_a_missed_renew_deadline
    now = Time.utc(2026, 1, 1)
    store = Store.new(history_revisions: nil, history_seconds: nil)
    elector = Controller::LeaseElector.new(store: store, identity: "only", clock: -> { now },
                                           lease_duration_seconds: 15, renew_deadline_seconds: 10, retry_period_seconds: 2)

    assert_equal :acquired, elector.step
    transitions = store.list("").items.first.dig("spec", "leaderTransitions")
    now += 11

    assert_equal :lost, elector.step
    refute_predicate elector, :leader?
    assert_equal :acquired, elector.step
    assert_predicate elector, :leader?
    assert_equal transitions, store.list("").items.first.dig("spec", "leaderTransitions")
    # The elector touches the API once per retry period, so a step at the
    # same instant reports the cached decision; the renewal follows once the
    # retry period has passed.
    assert_equal :acquired, elector.step
    now += 2

    assert_equal :renewed, elector.step
  end

  # The endpoints controller's declared kind is Endpoints, so the reconcile
  # loop hands it the Endpoints object once one exists.  The desired state
  # comes from the Service -- its selector picks the Pods -- so planning from
  # an Endpoints object saw an empty selector and left every Service with the
  # empty Endpoints it was created with.
  def test_endpoints_controller_plans_from_the_service_when_handed_its_endpoints
    service = {"apiVersion" => "v1", "kind" => "Service",
               "metadata" => {"name" => "web", "namespace" => "default", "uid" => "svc-uid"},
               "spec" => {"selector" => {"app" => "web"}, "ports" => [{"port" => 80, "targetPort" => 8080}]}}
    ready_pod = {"apiVersion" => "v1", "kind" => "Pod",
                 "metadata" => {"name" => "p1", "namespace" => "default", "uid" => "pod-uid",
                                "labels" => {"app" => "web"}},
                 "spec" => {"nodeName" => "node-a"},
                 "status" => {"podIP" => "10.0.0.5", "phase" => "Running",
                              "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    existing = {"apiVersion" => "v1", "kind" => "Endpoints",
                "metadata" => {"name" => "web", "namespace" => "default",
                               "ownerReferences" => [Controller::Support.owner_reference(service)]},
                "subsets" => []}

    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    adapter.create(service, descriptor: Controller::ResourceDescriptor.parse("Service"))
    adapter.create(ready_pod, descriptor: Controller::ResourceDescriptor.parse("Pod"))
    adapter.create(existing, descriptor: Controller::ResourceDescriptor.parse("Endpoints"))

    result = Controller::EndpointController.new.plan(existing, store: adapter)
    update = result.updates.find { |operation| operation.resource.kind == "Endpoints" }

    refute_nil update, "the Endpoints must be updated from the Service's selector"
    addresses = update.object.fetch("subsets").fetch(0).fetch("addresses")

    assert_equal(["10.0.0.5"], addresses.map { |entry| entry.fetch("ip") })
  end

  private

  def object(kind, name, uid: "uid", namespace: "default", owners: [], controller: true)
    {"apiVersion" => Controller::Support.default_api_version(kind), "kind" => kind,
     "metadata" => {"name" => name, "namespace" => namespace, "uid" => uid,
                    "ownerReferences" => owners.map { |owner| Controller::Support.owner_reference(owner, controller: controller) }.reject(&:empty?)}}
  end

  def pod(name, owners: [], phase: "Running", node: "node-a", labels: {}, created: "2026-01-01T00:00:00Z", ready: true, ip: nil)
    value = object("Pod", name, uid: "uid-#{name}", owners: owners)
    value["metadata"]["creationTimestamp"] = created
    value["metadata"]["labels"] = labels
    value["spec"] = {}
    value["spec"]["nodeName"] = node if node
    value["status"] = {"phase" => phase, "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False"}]}
    value["status"]["podIP"] = ip if ip
    value
  end

  def deployment(replicas:, generation: 1)
    value = object("Deployment", "web", uid: "uid-deployment")
    value["metadata"]["generation"] = generation
    value["spec"] = {"replicas" => replicas, "selector" => {"matchLabels" => {"app" => "web"}},
                     "strategy" => {"type" => "RollingUpdate", "rollingUpdate" => {"maxSurge" => 1, "maxUnavailable" => 0}},
                     "template" => {"metadata" => {"labels" => {"app" => "web"}}, "spec" => {"containers" => [{"name" => "web", "image" => "example/web:1"}]}}}
    value
  end

  def replica_set(replicas:)
    value = object("ReplicaSet", "web", uid: "uid-rs")
    value["spec"] = {"replicas" => replicas, "selector" => {"matchLabels" => {"app" => "web"}},
                     "template" => {"metadata" => {"labels" => {"app" => "web"}}, "spec" => {"containers" => [{"name" => "web", "image" => "example/web:1"}]}}}
    value
  end

  def stateful_set(replicas:)
    value = object("StatefulSet", "db", uid: "uid-set")
    value["spec"] = {"replicas" => replicas, "selector" => {"matchLabels" => {"app" => "db"}},
                     "serviceName" => "db", "template" => {"metadata" => {"labels" => {"app" => "db"}},
                                                           "spec" => {"containers" => [{"name" => "db", "image" => "example/db:1"}]}}}
    value
  end

  def daemon_set
    value = object("DaemonSet", "daemon", uid: "uid-daemon", namespace: "")
    value["metadata"].delete("namespace")
    value["spec"] =
      {"selector" => {"matchLabels" => {"role" => "worker"}},
       "template" => {"metadata" => {"labels" => {"role" => "worker"}},
                      "spec" => {"nodeSelector" => {"role" => "worker"},
                                 "containers" => [{"name" => "daemon", "image" => "example/daemon:1"}]}}}
    value
  end

  def job(replicas:)
    value = object("Job", "batch", uid: "uid-job")
    value["spec"] =
      {"completions" => replicas, "parallelism" => 1,
       "template" => {"metadata" => {"labels" => {"job" => "batch"}}, "spec" => {"containers" => [{"name" => "job", "image" => "example/job:1"}]}}}
    value
  end

  def cron_job
    value = object("CronJob", "cron", uid: "uid-cron")
    value["spec"] =
      {"schedule" => "*/5 * * * *",
       "jobTemplate" => {"spec" => {"template" => {"metadata" => {},
                                                   "spec" => {"containers" => [{"name" => "job", "image" => "example/job:1"}]}}}}}
    value
  end

  def node(name, labels: {})
    value = object("Node", name, uid: "uid-#{name}", namespace: nil)
    value["metadata"].delete("namespace")
    value["metadata"]["labels"] = labels
    value["spec"] = {}
    value["status"] = {"conditions" => [{"type" => "Ready", "status" => "True", "lastHeartbeatTime" => "2026-01-01T00:00:00Z"}]}
    value
  end
end
