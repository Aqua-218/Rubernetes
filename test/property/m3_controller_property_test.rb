# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/watch"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

class M3ControllerPropertyTest < Minitest::Test
  Controller = Rubernetes::Controller
  Store = Rubernetes::Storage::MemoryStore
  Watch = Rubernetes::Watch

  class ConfigMapController < Controller::BaseController
    attr_reader :calls

    def initialize(**)
      super(name: "configmap-controller", **)
      @calls = []
    end

    def plan(resource, **_options)
      @calls << Controller::Support.name(resource)
      Controller::ReconcileResult.new(
        operations: [], controller: name,
        key: [Controller::Support.namespace(resource), Controller::Support.name(resource)].compact.join("/")
      )
    end
  end

  class ManualInformer
    def on(_event = nil, &handler)
      @handler = handler
      self
    end

    def emit(object, old_object = nil)
      raise "informer handler is not registered" unless @handler

      @handler.call(object, old_object)
    end
  end

  # Fixed-seed state sequence: after a controller has applied its complete
  # diff, observing the persisted state must produce no second mutation.
  def test_fixed_seed_reconcile_is_idempotent_and_diff_only
    random = Random.new(20_260_823)
    descriptor = Controller::ResourceDescriptor.parse("ReplicaSet")

    80.times do |index|
      replicas = random.rand(0..12)
      store = Store.new(history_revisions: nil, history_seconds: nil)
      adapter = Controller::StoreAdapter.new(store)
      replica_set = replica_set("rs-#{index}", replicas)
      adapter.create(replica_set, descriptor: descriptor)
      controller = Controller::ReplicaSetController.new(store: store)

      first = controller.reconcile(replica_set, store: store, apply: true)
      persisted = adapter.find(descriptor, name: Controller::Support.name(replica_set), namespace: "default")
      second = controller.reconcile(persisted, store: store, apply: true)
      persisted_after_status = adapter.find(descriptor, name: Controller::Support.name(replica_set), namespace: "default")
      third = controller.reconcile(persisted_after_status, store: store, apply: true)

      assert_predicate first, :changed?, "initial reconciliation must converge rs-#{index}"
      assert_empty second.creates, "status convergence must not recreate pods for rs-#{index}"
      assert_empty second.deletes, "status convergence must not delete pods for rs-#{index}"
      assert_empty third.operations, "reconcile must be diff-only for rs-#{index}"
      assert_equal replicas, adapter.list("Pod", namespace: "default").length
    end
  end

  def test_fixed_seed_scale_up_never_emits_more_than_the_controller_cap
    random = Random.new(1_136_2)
    controller = Controller::ReplicaSetController.new

    120.times do |index|
      replicas = random.rand(501..1_000)
      result = controller.plan(replica_set("large-#{index}", replicas), pods: [])

      assert_equal 500, result.creates.length
      assert_equal 500, result.creates.map { |operation| operation.object.dig("metadata", "name") }.uniq.length
    end
  end

  def test_owner_index_is_uid_and_controller_safe_across_random_graphs
    random = Random.new(7_042)
    index = Controller::OwnerReferenceIndex.new

    200.times do |offset|
      owner = config_map("owner-#{offset}", "owner-uid-#{random.rand(1_000_000)}")
      child = config_map("child-#{offset}", "child-uid-#{offset}")
      child["metadata"]["ownerReferences"] = [Controller::Support.owner_reference(owner)]
      stale = Marshal.load(Marshal.dump(child))
      stale["metadata"]["ownerReferences"][0]["uid"] = "stale-#{offset}"
      non_controller = Marshal.load(Marshal.dump(child))
      non_controller["metadata"]["ownerReferences"][0]["controller"] = false

      refute index.owned?(owner, stale)
      refute index.owned?(owner, non_controller, controller: true)
      assert index.owned?(owner, child)
    end
  end

  def test_informer_queue_reconcile_and_leader_loss_have_zero_follower_side_effects
    now = Time.utc(2026, 1, 1)
    clock = -> { now }
    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    config = config_map("watched", "config-uid")
    adapter.create(config, descriptor: Controller::ResourceDescriptor.parse("ConfigMap"))
    registry = Controller::ControllerRegistry.new(require_corpus: false)

    first_controller = ConfigMapController.new(store: store)
    second_controller = ConfigMapController.new(store: store)
    first = Controller::Manager.new(
      store: store, identity: "manager-a", registry: registry,
      lease: {clock: clock, lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1}
    )
    second = Controller::Manager.new(
      store: store, identity: "manager-b", registry: registry,
      lease: {clock: clock, lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1}
    )
    first.register(first_controller, name: "configmap-controller")
    second.register(second_controller, name: "configmap-controller")

    informer = Watch::Informer.new(client: Object.new, resource: "configmaps", resync_period: 0)
    first.register_informer("configmap-controller", informer)
    informer.sync(config)
    first_step = first.step

    assert_equal :acquired, first_step.fetch(:election)
    assert_equal 1, first_step.fetch(:reconciled)
    assert_equal ["watched"], first_controller.calls

    now += 5

    assert_equal :renewed, first.step.fetch(:election)
    assert_equal "manager-a",
                 adapter.find("Lease", name: "rubernetes-controller-manager", namespace: "kube-system").dig("spec", "holderIdentity")

    # Once the second manager takes the expired Lease, the former leader must
    # not execute queued work or mutate the store.
    now += 11
    first.enqueue("default/watched")

    assert_equal true, second.step.fetch(:election) == :acquired
    revision_before_follower_step = store.revision

    assert_equal :follower, first.step.fetch(:election)
    assert_equal 1, first_controller.calls.length
    assert_equal revision_before_follower_step, store.revision

    second.enqueue("default/watched")

    assert_equal 1, second.step.fetch(:reconciled)
    assert_equal ["watched"], second_controller.calls
  end

  private

  def config_map(name, uid)
    {"apiVersion" => "v1", "kind" => "ConfigMap",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => uid}, "data" => {}}
  end

  def replica_set(name, replicas)
    {"apiVersion" => "apps/v1", "kind" => "ReplicaSet",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
     "spec" => {"replicas" => replicas,
                "selector" => {"matchLabels" => {"app" => name}},
                "template" => {"metadata" => {"labels" => {"app" => name}},
                               "spec" => {"containers" => [{"name" => "app", "image" => "example/app:1"}]}}}}
  end
end
