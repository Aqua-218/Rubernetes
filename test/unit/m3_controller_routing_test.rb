# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

class M3ControllerRoutingTest < Minitest::Test
  Controller = Rubernetes::Controller
  Store = Rubernetes::Storage::MemoryStore

  class RoutingImplementation < Controller::BaseController
    def plan(resource, **_options)
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

  def test_builtin_workload_controllers_watch_their_owner_gvk
    required = %w[deployment-controller replicaset-controller statefulset-controller daemonset-controller job-controller cronjob-controller]

    required.each do |name|
      definition = Controller.default_registry.fetch(name)

      assert(definition.watches.any? do |watch|
        watch.via == :all && watch.resource.gvk == definition.kind.gvk
      end, "#{name} must self-watch #{definition.kind.identifier}")
    end
  end

  def test_owner_create_update_and_delete_events_enqueue_the_owner_controller
    descriptor = Controller::ResourceDescriptor.parse("Deployment")
    calls = []
    definition = definition_for(descriptor, [watch_for(descriptor, :all)]) { |resource| calls << resource }
    _store, adapter, manager, informer = runtime(definition)
    deployment = object("Deployment", "demo", uid: "deployment-uid")
    adapter.create(deployment, descriptor: descriptor)

    informer.emit(deployment)

    assert_equal 1, manager.step.fetch(:reconciled)
    assert_equal(["demo"], calls.map { |resource| Controller::Support.name(resource) })

    deployment_update = Marshal.load(Marshal.dump(deployment))
    deployment_update["metadata"]["resourceVersion"] = "2"
    adapter.update(deployment_update, descriptor: descriptor)
    informer.emit(deployment_update, deployment)

    assert_equal 1, manager.step.fetch(:reconciled)
    assert_equal 2, calls.length

    adapter.delete(deployment_update, descriptor: descriptor)
    informer.emit(deployment_update)

    assert manager.queue.queued?("default/demo"), "delete must enqueue the owner key before lookup observes removal"
    manager.step

    assert_equal 2, calls.length, "a deleted owner has no object to reconcile, but its event must still be queued"
  ensure
    manager&.stop
  end

  def test_mismatched_api_version_does_not_fall_through_to_name_only_routing
    descriptor = Controller::ResourceDescriptor.parse("Deployment")
    calls = []
    definition = definition_for(descriptor, [watch_for(descriptor, :all)]) { |resource| calls << resource }
    _store, adapter, manager, informer = runtime(definition)
    deployment = object("Deployment", "demo", uid: "deployment-uid")
    adapter.create(deployment, descriptor: descriptor)

    informer.emit(deployment.merge("apiVersion" => "apps/v2"))

    assert_equal 0, manager.step.fetch(:reconciled)
    assert_empty calls
  ensure
    manager&.stop
  end

  def test_foreign_all_watch_fans_out_to_controller_resources
    daemon_set_descriptor = Controller::ResourceDescriptor.parse("DaemonSet")
    node_descriptor = Controller::ResourceDescriptor.parse("Node")
    calls = []
    definition = definition_for(daemon_set_descriptor,
                                [watch_for(daemon_set_descriptor, :all), watch_for(node_descriptor, :all)]) do |resource|
      calls << resource
    end
    _store, adapter, manager, informer = runtime(definition)
    daemon_set = object("DaemonSet", "demo", uid: "daemon-set-uid")
    adapter.create(daemon_set, descriptor: daemon_set_descriptor)

    informer.emit(object("Node", "node-a", uid: "node-uid"))

    assert_equal 1, manager.step.fetch(:reconciled)
    assert_equal(["demo"], calls.map { |resource| Controller::Support.name(resource) })
  ensure
    manager&.stop
  end

  def test_owner_reference_routing_requires_matching_owner_uid_and_gvk
    deployment_descriptor = Controller::ResourceDescriptor.parse("Deployment")
    pod_descriptor = Controller::ResourceDescriptor.parse("Pod")
    calls = []
    definition = definition_for(deployment_descriptor,
                                [watch_for(pod_descriptor, :owner_reference, owner: deployment_descriptor)]) do |resource|
      calls << resource
    end
    _store, adapter, manager, informer = runtime(definition)
    deployment = object("Deployment", "demo", uid: "deployment-uid")
    adapter.create(deployment, descriptor: deployment_descriptor)

    stale_pod = object("Pod", "pod", uid: "pod-uid")
    stale_pod["metadata"]["ownerReferences"] = [owner_reference(deployment, uid: "stale-owner-uid")]
    informer.emit(stale_pod)

    assert_equal 0, manager.step.fetch(:reconciled)
    assert_empty calls

    valid_pod = Marshal.load(Marshal.dump(stale_pod))
    valid_pod["metadata"]["ownerReferences"] = [owner_reference(deployment)]
    adapter.create(valid_pod, descriptor: pod_descriptor)
    informer.emit(valid_pod)

    assert_equal 1, manager.step.fetch(:reconciled)
    assert_equal(["demo"], calls.map { |resource| Controller::Support.name(resource) })
  ensure
    manager&.stop
  end

  private

  def runtime(definition)
    store = Store.new(history_revisions: nil, history_seconds: nil)
    adapter = Controller::StoreAdapter.new(store)
    registry = Controller::ControllerRegistry.new(require_corpus: false)
    registry.register(definition)
    manager = Controller::Manager.new(
      store: store, identity: "routing-#{Process.pid}-#{object_id}", registry: registry,
      lease: {lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1}
    )
    manager.register_definition(definition, store: store)
    informer = ManualInformer.new
    manager.register_informer(definition.name, informer)
    [store, adapter, manager, informer]
  end

  def definition_for(kind, watches)
    Controller::ControllerDefinition.new(
      name: "#{kind.kind.downcase}-routing-controller", kind: kind, watches: watches,
      reconcile_block: lambda do |resource, _context|
        yield(resource)
        Controller::ReconcileResult.new(operations: [], controller: "routing", key: Controller::Support.name(resource))
      end,
      implementation: RoutingImplementation
    )
  end

  def watch_for(resource, via, owner: nil)
    queue_key = if via == :owner_reference
                  lambda do |object|
                    reference = Controller::Support.owner_references(object).find do |entry|
                      Controller::Support.ref_value(entry, "kind", "") == owner.kind
                    end
                    [Controller::Support.namespace(object), Controller::Support.ref_value(reference, "name", "")].compact.join("/")
                  end
                else
                  ->(object) { [Controller::Support.namespace(object), Controller::Support.name(object)].compact.join("/") }
                end
    Controller::WatchSpec.new(resource: resource, via: via,
                              index_name: "test/#{resource.identifier}/#{via}", queue_key: queue_key)
  end

  def object(kind, name, uid:)
    descriptor = Controller::ResourceDescriptor.parse(kind)
    {"apiVersion" => descriptor.api_version, "kind" => kind,
     "metadata" => {"name" => name, "namespace" => "default", "uid" => uid}}
  end

  def owner_reference(owner, uid: Controller::Support.uid(owner))
    {"apiVersion" => Controller::Support.api_version(owner), "kind" => Controller::Support.kind(owner),
     "name" => Controller::Support.name(owner), "uid" => uid, "controller" => true, "blockOwnerDeletion" => true}
  end
end
