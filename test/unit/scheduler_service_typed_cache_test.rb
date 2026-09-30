# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap/control_plane_services"

# The service normalised, deep-copied and deep-froze every Pod and Node the
# informers reported, threw that snapshot away, kept the raw object, and then
# paid for the conversion again for every Node and every Pod on every
# scheduling cycle -- and a cycle runs per Pod scheduled.  The snapshot is
# now what it keeps.
class SchedulerServiceTypedCacheTest < Minitest::Test
  Service = Rubernetes::Bootstrap::SchedulerService
  Scheduler = Rubernetes::Scheduler

  def service
    subject = Service.allocate
    subject.instance_variable_set(:@mutex, Mutex.new)
    subject.instance_variable_set(:@pods, {})
    subject.instance_variable_set(:@nodes, {})
    subject.instance_variable_set(:@framework, framework)
    subject.instance_variable_set(:@logger, nil)
    subject
  end

  def framework
    queue = Object.new
    queue.define_singleton_method(:promote_unschedulable) { [] }
    queue.define_singleton_method(:delete) { |_pod| nil }
    fake = Object.new
    fake.define_singleton_method(:queue) { queue }
    fake.define_singleton_method(:respond_to?) { |name, *| %i[queue enqueue].include?(name) }
    fake.define_singleton_method(:enqueue) { |_pod, **| nil }
    fake
  end

  def pod(name, node: "")
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "u-#{name}"},
     "spec" => {"nodeName" => node, "schedulerName" => "default-scheduler", "containers" => [{"name" => "c"}]},
     "status" => {"phase" => "Pending"}}
  end

  def node_object(name)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name},
     "spec" => {}, "status" => {"allocatable" => {"cpu" => "4"}, "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def test_observed_pods_and_nodes_are_kept_as_typed_snapshots
    subject = service
    subject.send(:observe_pod, pod("a"))
    subject.send(:observe_node, node_object("n1"))

    stored_pod = subject.instance_variable_get(:@pods).values.first
    stored_node = subject.instance_variable_get(:@nodes).values.first

    assert_kind_of Scheduler::Pod, stored_pod
    assert_kind_of Scheduler::Node, stored_node
    assert_equal "a", stored_pod.name
    assert_equal "n1", stored_node.name
  end

  def test_a_scheduling_cycle_reuses_the_stored_snapshots
    subject = service
    subject.send(:observe_pod, pod("a"))
    stored = subject.instance_variable_get(:@pods).values.first
    normalized = Scheduler::Framework.allocate.send(:normalize_pods, [stored], [])

    assert_same stored, normalized.first, "a stored snapshot must not be rebuilt"
  end

  def test_a_node_whose_scheduling_fields_are_unchanged_does_not_retry_unschedulable
    subject = service
    retries = []
    subject.define_singleton_method(:retry_unschedulable) { |reason, **_fields| retries << reason }
    subject.send(:observe_node, node_object("n1"))

    assert_equal ["node_changed"], retries, "the first sighting always retries"
    subject.send(:observe_node, node_object("n1"))

    assert_equal ["node_changed"], retries, "an unchanged node does not"
    changed = node_object("n1")
    changed["spec"]["unschedulable"] = true
    subject.send(:observe_node, changed)

    assert_equal %w[node_changed node_changed], retries
  end

  def test_deleting_a_pod_removes_its_snapshot
    subject = service
    subject.send(:observe_pod, pod("a"))
    subject.define_singleton_method(:retry_unschedulable) { |*, **| nil }
    subject.send(:delete_pod, pod("a"))

    assert_empty subject.instance_variable_get(:@pods)
  end
end
