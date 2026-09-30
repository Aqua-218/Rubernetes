# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

# A counted-kind event reaches only the quotas of its own namespace.  Fanning
# every Pod event in the cluster out to every quota recomputed each quota
# dozens of times a minute, often inside admission's charge window.
class QuotaNamespaceRoutingTest < Minitest::Test
  Controller = Rubernetes::Controller

  class Recording < Controller::BaseController
    def plan(resource, **_options)
      Controller::ReconcileResult.new(operations: [], controller: name,
                                      key: [Controller::Support.namespace(resource), Controller::Support.name(resource)].join("/"))
    end
  end

  def quota(namespace)
    {"apiVersion" => "v1", "kind" => "ResourceQuota", "metadata" => {"name" => "q", "namespace" => namespace, "uid" => "#{namespace}-uid"},
     "spec" => {"hard" => {"pods" => "5"}}}
  end

  def test_the_builtin_quota_watches_route_counted_kinds_by_namespace
    definition = Controller.default_registry.fetch("resourcequota-controller")
    routes = definition.watches.to_h { |watch| [watch.resource.kind, watch.route] }

    assert_equal :namespace, routes.fetch("Pod")
    assert_equal :namespace, routes.fetch("Service")
    assert_equal :namespace, routes.fetch("ConfigMap")
    assert_equal :namespace, routes.fetch("Secret")
    # Replenishment: a deleted ReplicaSet (or any other counted kind) must
    # recompute the namespace's quotas without waiting for the resync.
    %w[ReplicaSet ReplicationController PersistentVolumeClaim Deployment StatefulSet DaemonSet Job CronJob].each do |kind|
      assert_equal :namespace, routes.fetch(kind), "#{kind} is watched for replenishment"
    end
  end

  def test_a_replica_set_delete_reaches_the_quota_controller
    controller = Rubernetes::Controller::ResourceQuotaController.allocate
    replica_set = {"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "metadata" => {"name" => "rs", "namespace" => "ns"}}

    refute controller.skip_event?(replica_set, nil, :delete), "a delete recomputes usage"
    assert controller.skip_event?(replica_set, nil, :add), "a create was already charged by admission"
  end

  def test_a_pod_event_enqueues_only_the_quotas_of_its_namespace
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    quota_descriptor = Controller::ResourceDescriptor.parse("ResourceQuota")
    adapter.create(quota("default"), descriptor: quota_descriptor)
    adapter.create(quota("other"), descriptor: quota_descriptor)
    watch = Controller::WatchSpec.new(resource: Controller::ResourceDescriptor.parse("Pod"), via: :all, scope: :namespaced,
                                      index_name: "test", predicate: ->(_o) { true },
                                      queue_key: ->(o) { Controller::Support.name(o) }, route: :namespace, selector_source: nil)
    controller = Recording.new(name: "resourcequota-controller", store: store)
    controller.define_singleton_method(:resource_descriptor) { quota_descriptor }
    manager = Controller::Manager.new(store: store, identity: "quota-routing-#{Process.pid}",
                                      registry: Controller::ControllerRegistry.new(require_corpus: false),
                                      lease: {lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1})
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "other", "uid" => "p-uid"}}

    keys = manager.send(:queue_keys_for, controller, watch, pod)

    assert_equal ["other/q"], keys
  end
end

# A status-only update routes its object once; a label change routes the old
# object too so the keys it used to match hear about it.
class RoutingOldObjectTest < Minitest::Test
  Controller = Rubernetes::Controller

  def pod(labels, phase)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u", "labels" => labels},
     "status" => {"phase" => phase}}
  end

  def manager
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    Controller::Manager.new(store: store, identity: "routing-old-#{Process.pid}",
                            registry: Controller::ControllerRegistry.new(require_corpus: false),
                            lease: {lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1})
  end

  def test_status_only_updates_share_a_routing_identity_and_label_changes_do_not
    m = manager
    same = m.send(:routing_identity, pod({"app" => "a"}, "Pending")) == m.send(:routing_identity, pod({"app" => "a"}, "Running"))
    changed = m.send(:routing_identity, pod({"app" => "a"}, "Running")) == m.send(:routing_identity, pod({"app" => "b"}, "Running"))

    assert same
    refute changed
  end
end
