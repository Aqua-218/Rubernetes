# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# GangScheduling / GenericWorkload: a PodGroup with a gang policy is
# scheduled as a unit -- all members bind or none do -- with the pod group
# attempt metrics and the PodGroupScheduled condition.
class SchedulerGangSchedulingTest < Minitest::Test
  S = Rubernetes::Scheduler

  def pod(name, group: "gang", cpu: "1")
    S::Pod.new({"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
                "spec" => {"schedulingGroup" => {"podGroupName" => group}, "containers" => [{"name" => "c", "image" => "nginx", "resources" => {"requests" => {"cpu" => cpu}}}]}})
  end

  def node(name, cpu:)
    S::Node.new({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => {}}, "spec" => {},
                 "status" => {"allocatable" => {"cpu" => cpu, "memory" => "8Gi", "pods" => "110"}, "conditions" => [{"type" => "Ready", "status" => "True"}]}})
  end

  def group(min_count)
    {"default/gang" => {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup", "metadata" => {"name" => "gang", "namespace" => "default", "generation" => 1},
                        "spec" => {"schedulingPolicy" => {"gang" => {"minCount" => min_count}}}}}
  end

  def framework
    @binds = []
    @conditions = []
    @metrics = S::Metrics.new
    S::Framework.new(bind: lambda { |pod, node|
      @binds << [pod.name, node.name]
      true
    }, metrics: @metrics, opportunistic_batching: false,
                     feature_gates: {"GangScheduling" => true, "GenericWorkload" => true},
                     pod_group_status: ->(namespace, name, condition) { @conditions << [namespace, name, condition] })
  end

  def line(text, name, labels) = text[/^#{Regexp.escape(name)}#{Regexp.escape(labels)} (\S+)$/, 1]

  def test_a_gang_that_fits_binds_together
    fw = framework
    pods = %w[a b c].map { |name| pod(name) }
    pods.each { |member| fw.enqueue(member) }
    result = fw.schedule_next(nodes: [node("n1", cpu: "2"), node("n2", cpu: "1")], pods: pods, pod_groups: group(3))

    assert_predicate result, :scheduled?, result.inspect
    assert_equal %w[a b c], @binds.map(&:first).sort
    assert_equal 2, @binds.count { |_, node_name| node_name == "n1" }, "the members fill n1 before spilling to n2"
    assert_equal 0, fw.queue.size + fw.queue.unschedulable_size
    text = @metrics.render

    assert_equal "1", line(text, "scheduler_podgroup_schedule_attempts_total", '{profile="default-scheduler",result="scheduled"}')
    assert_equal "1",
                 line(text, "scheduler_podgroup_scheduling_attempt_duration_seconds_count",
                      '{profile="default-scheduler",result="scheduled"}')
    assert_equal "1", line(text, "scheduler_podgroup_scheduling_algorithm_duration_seconds_count", "")
    assert_equal %w[default gang True Scheduled], @conditions.last.first(2) + @conditions.last.last.values_at("status", "reason")
  end

  def test_a_gang_that_does_not_fit_binds_nothing
    fw = framework
    pods = %w[a b c].map { |name| pod(name) }
    pods.each { |member| fw.enqueue(member) }
    result = fw.schedule_next(nodes: [node("n1", cpu: "2")], pods: pods, pod_groups: group(3))

    refute_predicate result, :scheduled?
    assert_empty @binds, "no member binds when the gang does not fit"
    assert_equal 3, fw.queue.unschedulable_size
    if fw.queue.respond_to?(:unschedulable_plugins)
      assert_equal({"GangScheduling" => 3}.keys,
                   fw.queue.unschedulable_plugins.keys.map(&:to_s).uniq.sort & ["GangScheduling"])
    end
    text = @metrics.render

    assert_equal "1", line(text, "scheduler_podgroup_schedule_attempts_total", '{profile="default-scheduler",result="unschedulable"}')
    assert_equal "False", @conditions.last.last["status"]
    assert_equal "Unschedulable", @conditions.last.last["reason"]
    # Room appears: the gang is retried as a unit and binds.
    fw.queue.promote_unschedulable
    result = fw.schedule_next(nodes: [node("n1", cpu: "2"), node("n2", cpu: "2")], pods: pods, pod_groups: group(3))

    assert_predicate result, :scheduled?
    assert_equal 3, @binds.length
  end

  def test_pre_enqueue_holds_the_gang_until_min_count_pods_exist
    fw = framework
    pods = %w[a b].map { |name| pod(name) }
    pods.each { |member| fw.enqueue(member) }
    result = fw.schedule_next(nodes: [node("n1", cpu: "4")], pods: pods, pod_groups: group(3))

    refute_predicate result, :scheduled?
    assert_predicate result, :gated?, "waiting for minCount members is a PreEnqueue gate"
    assert_match(/waiting for minCount pods/, result.reason)
    assert_empty @binds
    assert_equal 2, fw.queue.unschedulable_size
    # Without a PodGroup object the Pod waits for it.
    fw.queue.promote_unschedulable
    result = fw.schedule_next(nodes: [node("n1", cpu: "4")], pods: pods, pod_groups: {})

    assert_predicate result, :gated?
    assert_match(/pod group "gang" to appear/, result.reason)
  end

  def test_pods_without_a_gang_policy_schedule_one_by_one
    fw = framework
    basic = {"default/gang" => {"metadata" => {"name" => "gang", "namespace" => "default"},
                                "spec" => {"schedulingPolicy" => {"basic" => {}}}}}
    pods = %w[a b].map { |name| pod(name) }
    pods.each { |member| fw.enqueue(member) }

    assert_predicate fw.schedule_next(nodes: [node("n1", cpu: "4")], pods: pods, pod_groups: basic), :scheduled?
    assert_equal 1, @binds.length
    assert_equal 1, fw.queue.size
  end

  def test_queue_pop_specific_and_gang_hints
    queue = S::SchedulingQueue.new
    a = pod("a")
    b = pod("b")
    queue.enqueue(a)
    queue.enqueue_unschedulable(b, reason: "x", plugins: ["GangScheduling"])

    assert_equal "b", queue.pop_specific(b).pod.name
    assert_nil queue.pop_specific(b)
    assert_equal 1, queue.in_flight_pods
    assert_equal "a", queue.pop_specific(a).pod.name
    assert_equal 0, queue.size + queue.unschedulable_size
    assert_equal :after_backoff, S::QueueingHints.strategy(a, ["GangScheduling"], "PodAdd", nil, pod("c"))
    assert_equal :skip, S::QueueingHints.strategy(a, ["GangScheduling"], "PodAdd", nil, pod("c", group: "other"))
    assert_equal :after_backoff, S::QueueingHints.strategy(a, ["GangScheduling"], "PodGroupAdd", nil, group(3).values.first)
    assert_equal :skip,
                 S::QueueingHints.strategy(a, ["GangScheduling"], "PodGroupAdd", nil,
                                           {"metadata" => {"name" => "other", "namespace" => "default"}})
  end
end
