# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/controller/infrastructure_storage"
require "rubernetes/bootstrap/control_plane_services"
require "rubernetes/storage/memory_store"

class M3ControllerRuntimeRegressionTest < Minitest::Test
  Controller = Rubernetes::Controller
  Store = Rubernetes::Storage::MemoryStore

  # M3: DaemonSet cleanup must compare each Pod's nodeName with the current
  # eligible-node set. Comparing Node.spec.nodeName deletes healthy Pods.
  def test_daemonset_deletes_only_pods_on_ineligible_nodes
    daemon_set = daemon_set_value
    eligible = node_value("node-a", labels: {"role" => "worker"})
    ineligible = node_value("node-b", labels: {"role" => "control"})
    healthy = pod_value("daemon-a", node: "node-a", owners: [daemon_set])
    stale = pod_value("daemon-b", node: "node-b", owners: [daemon_set])
    revision = Controller::DaemonSetController.new.send(:template_hash, daemon_set)
    healthy["metadata"]["labels"]["controller-revision-hash"] = revision
    stale["metadata"]["labels"]["controller-revision-hash"] = revision

    result = Controller::DaemonSetController.new.plan(
      daemon_set, pods: [healthy, stale], nodes: [eligible, ineligible]
    )

    assert_equal(["daemon-b"], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
    assert_empty result.creates
  end

  def test_daemonset_uses_template_node_selector_for_node_eligibility
    daemon_set = daemon_set_value
    daemon_set["spec"]["selector"] = {"matchLabels" => {"app" => "daemon"}}
    daemon_set["spec"]["template"]["metadata"]["labels"] = {"app" => "daemon"}
    daemon_set["spec"]["template"]["spec"]["nodeSelector"] = {"role" => "worker"}
    nodes = [node_value("node-a", labels: {"role" => "worker"}),
             node_value("node-b", labels: {"role" => "control"})]

    result = Controller::DaemonSetController.new.plan(daemon_set, pods: [], nodes: nodes)

    assert(result.creates.all? { |operation| operation.object.dig("spec", "nodeName").nil? })
    assert_equal(["node-a"], result.creates.map do |operation|
      operation.object.dig("spec", "affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution",
                           "nodeSelectorTerms", 0, "matchFields", 0, "values", 0)
    end)
    assert_equal 1, result.status.fetch("desiredNumberScheduled")
  end

  # M3: Manager registration must execute the immutable definition closure so
  # provider/configuration dependencies captured by a factory remain active.
  def test_manager_register_definition_executes_factory_with_injected_provider
    registry = Controller::ControllerRegistry.new(require_corpus: false)
    definition = Controller::InfrastructureStorageControllerFactory.definition(
      "service-lb-controller", registry: registry
    )
    registry.register(definition)
    store = Store.new(history_revisions: nil, history_seconds: nil)
    provider = Class.new do
      attr_reader :calls

      def initialize
        @calls = []
      end

      def ensure_load_balancer(service, nodes)
        @calls << [service.fetch("metadata").fetch("name"), nodes.length]
        {"ingress" => [{"ip" => "198.51.100.20"}]}
      end
    end.new

    manager = Controller::Manager.new(store: store, identity: "factory-test", registry: registry)
    manager.register_definition(definition, options: {cloud_provider: provider})
    service = service_value("web", type: "LoadBalancer")
    result = manager.controllers.fetch(definition.name).reconcile(service, store: store, apply: false)

    assert_equal [["web", 0]], provider.calls
    assert_equal [{"ip" => "198.51.100.20"}], result.status.dig("loadBalancer", "ingress")
  end

  # M3: Cloud controllers and the real controller-manager startup path must
  # fail closed when an external provider is absent.
  def test_cloud_reconciliation_and_default_manager_fail_closed_without_provider
    service = service_value("web", type: "LoadBalancer")
    node = node_value("node-a", provider_id: "cloud://node-a", pod_cidr: "10.244.0.0/24")

    assert_raises(Controller::ProviderUnavailableError) do
      Controller::ServiceLBController.new.plan(service)
    end
    assert_raises(Controller::ProviderUnavailableError) do
      Controller::NodeRouteController.new.plan(node)
    end
    assert_raises(Controller::ProviderUnavailableError) do
      Controller::CloudNodeLifecycleController.new.plan(node)
    end

    service_runner = Rubernetes::Bootstrap::ControllerManagerService.new(
      config: {}, logger: NullLogger.new, client: Object.new,
      store: Store.new(history_revisions: nil, history_seconds: nil)
    )
    assert_raises(Controller::ProviderUnavailableError) do
      service_runner.send(:build_runtime!)
    end
  end

  # M3: Bootstrap must pass runtime-adapter providers into factory definitions
  # before the first reconcile, not merely accept the process configuration.
  def test_bootstrap_injects_cloud_provider_into_registered_factory
    provider = Class.new do
      attr_reader :calls

      def initialize
        @calls = []
      end

      def ensure_load_balancer(service, _nodes)
        @calls << service.fetch("metadata").fetch("name")
        {"ingress" => [{"hostname" => "lb.example.test"}]}
      end
    end.new
    runner = Rubernetes::Bootstrap::ControllerManagerService.new(
      config: {}, logger: NullLogger.new, client: Object.new,
      store: Store.new(history_revisions: nil, history_seconds: nil),
      runtime_adapters: {cloud_provider: provider}
    )

    runner.send(:build_runtime!)
    controller = runner.manager.controllers.fetch("service-lb-controller")
    result = controller.reconcile(service_value("web", type: "LoadBalancer"),
                                  store: runner.instance_variable_get(:@store), apply: false)

    assert_equal ["web"], provider.calls
    assert_equal "lb.example.test", result.status.dig("loadBalancer", "ingress", 0, "hostname")
  end

  # M3 C5: A transient planner error is isolated to its key and gets the
  # WorkQueue exponential retry; it must not escape and terminate the manager.
  def test_manager_retries_transient_reconcile_errors_per_key
    registry = Controller::ControllerRegistry.new(require_corpus: false)
    now = 0.0
    queue = Rubernetes::Watch::WorkQueue.new(clock: -> { now }, base_delay: 0.005,
                                             bucket_capacity: 100, bucket_rate: 100)
    store = Store.new(history_revisions: nil, history_seconds: nil)
    resource = config_map_value("retry")
    healthy_resource = config_map_value("healthy")
    Controller::StoreAdapter.new(store).create(resource, descriptor: Controller::ResourceDescriptor.parse("ConfigMap"))
    Controller::StoreAdapter.new(store).create(healthy_resource, descriptor: Controller::ResourceDescriptor.parse("ConfigMap"))
    controller_class = Class.new(Controller::BaseController) do
      attr_reader :calls, :reconciled_keys

      def initialize(**)
        @calls = 0
        @reconciled_keys = []
        @failed_retry = false
        super
      end

      def resource_descriptor
        Controller::ResourceDescriptor.parse("ConfigMap")
      end

      def plan(resource, **_options)
        @calls += 1
        if Controller::Support.name(resource) == "retry" && !@failed_retry
          @failed_retry = true
          raise "temporary reconcile failure"
        end

        @reconciled_keys << Controller::Support.name(resource)

        Controller::ReconcileResult.new(operations: [], controller: name,
                                        key: [Controller::Support.namespace(resource), Controller::Support.name(resource)].compact.join("/"))
      end
    end
    controller = controller_class.new(store: store, name: "retry-controller")
    manager = Controller::Manager.new(store: store, identity: "retry-test", registry: registry, queue: queue)
    manager.register(controller)
    manager.enqueue("default/retry", controller: "retry-controller")
    manager.enqueue("default/healthy", controller: "retry-controller")

    first = manager.step

    assert_equal 1, first.fetch(:reconciled)
    assert_equal 2, controller.calls
    assert_instance_of RuntimeError, manager.last_error
    assert_equal 1, queue.num_requeues("default/retry")
    assert_equal 0, queue.num_requeues("default/healthy")

    now += 0.01
    second = manager.step

    assert_equal 1, second.fetch(:reconciled)
    assert_equal 3, controller.calls
    assert_equal 0, queue.num_requeues("default/retry")
  end

  # M3: Owner watches require an exact GVK and the current owner UID. A valid
  # route is retained through processing and removed only after the key is idle.
  def test_owner_watch_rejects_stale_gvk_or_uid_and_clears_valid_route
    registry = Controller::ControllerRegistry.new(require_corpus: false)
    store = Store.new(history_revisions: nil, history_seconds: nil)
    owner = replica_set_value("rs", uid: "rs-current")
    Controller::StoreAdapter.new(store).create(owner, descriptor: Controller::ResourceDescriptor.parse("ReplicaSet"))
    pod = pod_value("child", owners: [], node: "node-a")
    watch = Controller::WatchSpec.new(
      resource: Controller::ResourceDescriptor.parse("Pod"), via: :owner_reference,
      predicate: ->(_object) { true },
      queue_key: ->(object) { [Controller::Support.namespace(object), "rs"].compact.join("/") }
    )
    definition = Controller::ControllerDefinition.new(
      name: "owner-watch-controller", kind: Controller::ResourceDescriptor.parse("ReplicaSet"),
      watches: [watch], reconcile_block: ->(_resource) { Controller::ReconcileResult.new(operations: []) },
      implementation: Controller::BaseController
    )
    controller_class = Class.new(Controller::BaseController) do
      def plan(_resource, **_options)
        Controller::ReconcileResult.new(operations: [], controller: name)
      end
    end
    controller = controller_class.new(store: store, definition: definition, name: definition.name)
    manager = Controller::Manager.new(store: store, identity: "owner-watch-test", registry: registry)
    manager.register(controller)

    pod["metadata"]["ownerReferences"] = [{"apiVersion" => "apps/v1beta1", "kind" => "ReplicaSet",
                                           "name" => "rs", "uid" => "rs-current", "controller" => true}]
    manager.send(:enqueue_for, definition.name, pod)

    assert_empty manager.queue.keys
    assert_empty manager.instance_variable_get(:@queue_routes)

    pod["metadata"]["ownerReferences"] = [{"apiVersion" => "apps/v1", "kind" => "ReplicaSet",
                                           "name" => "rs", "uid" => "rs-stale", "controller" => true}]
    manager.send(:enqueue_for, definition.name, pod)

    assert_empty manager.queue.keys

    pod["metadata"]["ownerReferences"] = [{"apiVersion" => "apps/v1", "kind" => "ReplicaSet",
                                           "name" => "rs", "uid" => "rs-current", "controller" => true}]
    manager.send(:enqueue_for, definition.name, pod)

    assert_equal ["default/rs"], manager.queue.keys
    result = manager.step

    assert_equal 1, result.fetch(:reconciled)
    assert_empty manager.instance_variable_get(:@queue_routes)
  end

  # M3: ReplicaSet adopts matching orphan Pods, but reserves names occupied by
  # Pods controlled by another workload to avoid repeated AlreadyExists errors.
  def test_replicaset_adopts_orphans_and_skips_foreign_generated_name
    replica_set = replica_set_value("web", replicas: 1)
    orphan = pod_value("orphan", labels: {"app" => "web"}, owners: [])
    adoption = Controller::ReplicaSetController.new.plan(replica_set, pods: [orphan])
    adoption_update = adoption.updates.find { |operation| operation.reason == "replicaset pod adoption" }

    refute_nil adoption_update
    assert_equal "rs-current", adoption_update.object.dig("metadata", "ownerReferences", 0, "uid")
    assert_empty adoption.creates

    foreign_owner = deployment_value("other", uid: "foreign")
    foreign = pod_value("web-0", labels: {"app" => "web"}, owners: [foreign_owner])
    collision = Controller::ReplicaSetController.new.plan(replica_set, pods: [foreign])
    created_names = collision.creates.map { |operation| operation.object.dig("metadata", "name") }

    assert_equal 1, created_names.length
    assert_match(/\Aweb-[bcdfghjklmnpqrstvwxz2456789]{5}\z/, created_names.first)
    refute_equal "web-0", created_names.first
    refute(collision.updates.any? { |operation| operation.reason == "replicaset pod adoption" })
  end

  class NullLogger
    def method_missing(_name, *_args, **_kwargs)
      nil
    end

    def respond_to_missing?(_name, _include_private = false)
      true
    end
  end

  private

  def object(kind, name, uid:, namespace: "default")
    {"apiVersion" => Controller::Support.default_api_version(kind), "kind" => kind,
     "metadata" => {"name" => name, "namespace" => namespace, "uid" => uid,
                    "ownerReferences" => []}}
  end

  def daemon_set_value
    value = object("DaemonSet", "daemon", uid: "daemon-current")
    value["spec"] = {"selector" => {"matchLabels" => {"role" => "worker"}},
                     "template" => {"metadata" => {"labels" => {"role" => "worker"}},
                                    "spec" => {"nodeSelector" => {"role" => "worker"},
                                               "containers" => [{"name" => "daemon", "image" => "example/daemon:1"}]}}}
    value
  end

  def replica_set_value(name, replicas: 1, uid: "rs-current")
    value = object("ReplicaSet", name, uid: uid)
    value["spec"] = {"replicas" => replicas, "selector" => {"matchLabels" => {"app" => "web"}},
                     "template" => {"metadata" => {"labels" => {"app" => "web"}},
                                    "spec" => {"containers" => [{"name" => "web", "image" => "example/web:1"}]}}}
    value
  end

  def deployment_value(name, uid:)
    value = object("Deployment", name, uid: uid)
    value["spec"] = {"selector" => {"matchLabels" => {"app" => "other"}}}
    value
  end

  def pod_value(name, node: "node-a", owners: [], labels: {})
    value = object("Pod", name, uid: "pod-#{name}")
    value["metadata"]["labels"] = labels
    value["metadata"]["ownerReferences"] = owners.map { |owner| Controller::Support.owner_reference(owner) }
    value["spec"] = {"nodeName" => node}
    value["status"] = {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => "True"}]}
    value
  end

  def node_value(name, labels: {}, provider_id: nil, pod_cidr: nil)
    value = object("Node", name, uid: "node-#{name}", namespace: nil)
    value["metadata"].delete("namespace")
    value["metadata"]["labels"] = labels
    value["spec"] = {}
    value["spec"]["providerID"] = provider_id if provider_id
    value["spec"]["podCIDR"] = pod_cidr if pod_cidr
    value
  end

  def service_value(name, type:)
    value = object("Service", name, uid: "service-#{name}")
    value["spec"] = {"type" => type}
    value
  end

  def config_map_value(name)
    object("ConfigMap", name, uid: "config-#{name}")
  end
end
