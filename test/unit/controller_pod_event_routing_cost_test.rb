# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

# A mass Pod deletion (the garbage-collector specs delete a hundred-Pod RC)
# held the controller manager's Pod informer back by 9-14 s: for every Pod
# event it GET the Pod's core-group owner from the API (the owner descriptor
# was built as kind "v1/ReplicationController", which no informer cache
# answers) and reconciled every Node in three node-keyed controllers, each
# LISTing kube-node-lease from the API.  A DaemonSet rolling update running
# next heard of its deleted Pod 14 s late.
class ControllerPodEventRoutingCostTest < Minitest::Test
  Controller = Rubernetes::Controller

  def manager
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    Controller::Manager.new(store: store, identity: "pod-routing-#{Process.pid}",
                            registry: Controller::ControllerRegistry.new(require_corpus: false),
                            lease: {lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1})
  end

  def test_a_core_group_owner_resolves_to_the_descriptor_its_informer_cache_is_keyed_by
    m = manager
    core = m.send(:owner_descriptor_for, "v1", "ReplicationController")
    apps = m.send(:owner_descriptor_for, "apps/v1", "ReplicaSet")

    assert_equal Controller::ResourceDescriptor.parse("ReplicationController").identifier, core.identifier
    assert_equal "ReplicationController", core.kind
    assert_equal "replicationcontrollers", core.resource
    assert_equal Controller::ResourceDescriptor.parse("ReplicaSet").identifier, apps.identifier
  end

  def test_node_keyed_controllers_route_a_pod_event_to_its_own_node_only
    registry = Controller.build_default_registry
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns"},
           "spec" => {"nodeName" => "worker-1"}}
    pending = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "q", "namespace" => "ns"}, "spec" => {}}
    %w[node-lifecycle-controller taint-eviction-controller device-taint-eviction-controller].each do |name|
      watch = Array(registry.fetch(name).watches).find { |candidate| candidate.resource.kind == "Pod" }

      assert_equal :self, watch.route, name
      assert_equal "worker-1", watch.queue_key.call(pod), name
      assert_nil watch.queue_key.call(pending), "#{name}: an unbound Pod concerns no node"
    end
  end

  def test_node_lifecycle_reads_node_leases_from_a_watch
    watch = Array(Controller.build_default_registry.fetch("node-lifecycle-controller").watches)
      .find { |candidate| candidate.resource.kind == "Lease" }
    node_lease = {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
                  "metadata" => {"name" => "worker-2", "namespace" => "kube-node-lease"}}
    other = {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
             "metadata" => {"name" => "kube-scheduler", "namespace" => "kube-system"}}

    refute_nil watch
    assert_equal "worker-2", watch.queue_key.call(node_lease)
    assert_nil watch.queue_key.call(other)
  end
end

# An owner removed outright left its dependents to the next ten-second sweep,
# one sweep per link of an ownership chain.  A delete now brings the garbage
# collector's sweep forward and queues a key to carry it.
class ControllerOwnerDeletionSweepTest < Minitest::Test
  Controller = Rubernetes::Controller

  class FakeInformer
    attr_reader :handlers

    def initialize = @handlers = Hash.new { |hash, key| hash[key] = [] }

    def on(event = nil, &handler)
      (event.nil? ? %i[add update delete sync] : Array(event)).each { |name| @handlers[name] << handler }
      self
    end
  end

  class FakeCollector
    attr_reader :expedited

    def initialize = @expedited = 0
    def name = "garbage-collector-controller"
    def resource_descriptor = Controller::ResourceDescriptor.parse({"apiVersion" => "rubernetes.io/v1", "kind" => "GarbageCollector"})

    def expedite_orphan_pass!
      @expedited += 1
      true
    end
  end

  def test_a_delete_expedites_the_sweep
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    manager = Controller::Manager.new(store: store, identity: "owner-delete-#{Process.pid}",
                                      registry: Controller::ControllerRegistry.new(require_corpus: false),
                                      lease: {lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1})
    collector = FakeCollector.new
    manager.instance_variable_get(:@controllers)[collector.name] = collector
    informer = FakeInformer.new
    manager.register_informer("replicaset-controller", informer)
    manager.register_informer("deployment-controller", informer)

    informer.handlers[:delete].each { |handler| handler.call({"metadata" => {"name" => "pod1", "namespace" => "ns"}}, nil, :delete) }

    assert_operator collector.expedited, :>=, 1
    queue = manager.instance_variable_get(:@queue)
    key, = queue.get(timeout: 0.1)

    assert_equal Controller::Manager::OWNER_DELETED_KEY, key
  end
end
