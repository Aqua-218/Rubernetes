# frozen_string_literal: true

require "net/http"
require_relative "../test_helper"
require "rubernetes/bootstrap"

# The scheduler assumes a Pod onto its node and posts the Binding from a
# worker, so the next scheduling cycle does not wait for the API round trips.
class SchedulerAsyncBindTest < Minitest::Test
  class Leader
    def step = :leader
    def leader? = true
  end

  class Logger
    attr_reader :entries

    def initialize = @entries = []
    %i[info warn error debug].each { |level| define_method(level) { |event, **fields| @entries << [level, event, fields] } }
  end

  class API
    attr_reader :created

    def initialize(fail_with: nil, gate: nil)
      @created = Queue.new
      @fail_with = fail_with
      @gate = gate
    end

    def create(object, path:, api_version:, **)
      @gate&.pop
      raise @fail_with if @fail_with

      @created << [path, object]
      object
    end

    def patch(*) = raise("no patch")
  end

  # The real framework, noting what is handed back to its queue.
  class Framework < Rubernetes::Scheduler::Framework
    attr_reader :enqueued

    def initialize
      super
      @enqueued = []
    end

    def enqueue(pod, **)
      @enqueued << pod
      super
    end
  end

  def pod
    Rubernetes::Scheduler::Pod.new({"apiVersion" => "v1", "kind" => "Pod",
                                    "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
                                    "spec" => {"containers" => []}})
  end

  def node
    Rubernetes::Scheduler::Node.new({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "n1"}})
  end

  def service(api)
    service = Rubernetes::Bootstrap::SchedulerService.new(config: {}, logger: Logger.new, client: api)
    service.instance_variable_set(:@elector, Leader.new)
    service.instance_variable_set(:@framework, Framework.new)
    service.instance_variable_set(:@running, true)
    service
  end

  def key = %w[ns p u1]

  def scheduled_after_flush(server)
    response = Net::HTTP.new("127.0.0.1", server.port, nil).get("/metrics")

    assert_equal "200", response.code
    Integer(response.body[/^scheduler_pod_scheduled_after_flush_total (\d+)$/, 1])
  end

  def test_only_a_real_binding_after_a_queue_timeout_increments_the_metric
    gate = Queue.new
    subject = service(API.new(gate: gate))
    framework = Rubernetes::Scheduler::Framework.new(bind: subject.method(:bind_pod))
    subject.instance_variable_set(:@framework, framework)
    server = Rubernetes::Bootstrap::ComponentServer.new(component: "kube-scheduler", config: {}, metrics: subject.metrics,
                                                        host: "127.0.0.1", port: 0).start
    live_node = {"metadata" => {"name" => "n1"},
                 "status" => {"allocatable" => {"cpu" => "1", "memory" => "64Mi", "pods" => "10"},
                              "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    now = 0.0
    subject.instance_variable_set(:@clock, -> { now })
    subject.send(:flush_unschedulable_if_due)
    framework.enqueue(pod)
    first = framework.schedule_next(nodes: [], pods: [])

    assert_predicate first, :unschedulable?
    now += Rubernetes::Bootstrap::SchedulerService::UNSCHEDULABLE_FLUSH_SECONDS
    subject.send(:flush_unschedulable_if_due)
    result = framework.schedule_next(nodes: [live_node], pods: [])

    assert_predicate result, :scheduled?
    assert_equal 0, scheduled_after_flush(server), "assuming a Pod does not complete its binding"
    gate << :go
    subject.send(:stop_bind_workers)

    assert_equal 1, scheduled_after_flush(server)
  ensure
    gate << :go if gate
    subject&.send(:stop_bind_workers)
    server&.stop
  end

  def test_event_promotion_does_not_count_as_a_queue_timeout
    subject = service(API.new)
    queue = subject.framework.queue
    queue.enqueue_unschedulable(pod, reason: "waiting for a node")
    subject.send(:retry_unschedulable, "extensions_changed")
    queue.pop
    subject.send(:bind_pod, pod, node)
    subject.send(:stop_bind_workers)

    assert_match(/^scheduler_pod_scheduled_after_flush_total 0$/, subject.metrics.render)
  ensure
    subject&.send(:stop_bind_workers)
  end

  def test_bind_returns_at_once_with_the_pod_assumed_and_the_binding_follows
    gate = Queue.new
    api = API.new(gate: gate)
    subject = service(api)

    bound = subject.send(:bind_pod, pod, node)

    assert_equal "n1", bound.dig("spec", "nodeName")
    assert_equal "n1", subject.instance_variable_get(:@pods).fetch(key).node_name, "the cache sees the assumed placement"
    assert_empty api.created, "the Binding has not been posted yet"

    gate << :go
    path, binding = api.created.pop

    assert_equal "/api/v1/namespaces/ns/pods/p/binding", path
    assert_equal "n1", binding.dig("target", "name")
  ensure
    subject&.send(:stop_bind_workers)
  end

  def test_delayed_pending_watch_events_preserve_a_local_assignment
    gate = Queue.new
    api = API.new(gate: gate)
    subject = service(api)
    subject.send(:bind_pod, pod, node)
    pending = pod.with("status" => {"phase" => "Pending", "resourceClaimStatuses" => [{"name" => "device", "resourceClaimName" => "claim"}]})

    subject.send(:observe_pod, pending.to_h)

    assert_equal "n1", subject.instance_variable_get(:@pods).fetch(key).node_name
    assert_empty subject.framework.enqueued

    gate << :go
    subject.send(:stop_bind_workers)
    subject.send(:observe_pod, pending.to_h)

    assert_equal "n1", subject.instance_variable_get(:@pods).fetch(key).node_name
    assert_empty subject.framework.enqueued
    assert_equal 1, api.created.length
  ensure
    gate << :go if gate && api.created.empty?
    subject&.send(:stop_bind_workers)
  end

  def test_assigned_watch_event_removes_an_active_queue_entry
    subject = service(API.new)
    subject.send(:observe_pod, pod.to_h)

    assert_includes subject.framework.queue, pod

    assigned = pod.with("spec" => pod.spec.merge("nodeName" => node.name))
    subject.send(:observe_pod, assigned.to_h)

    refute_includes subject.framework.queue, pod
  end

  def test_scheduling_informers_follow_pod_groups_when_enabled
    [false, true].each do |enabled|
      config = {"feature_gates" => {"GenericWorkload" => enabled}}
      subject = Rubernetes::Bootstrap::SchedulerService.new(config: config, client: API.new, logger: Logger.new)
      subject.send(:build_cluster_informers!)
      informers = subject.instance_variable_get(:@cluster_informers)

      assert_equal enabled, informers.key?("PodGroup")
      refute informers.key?("Workload")
    end
  end

  def test_a_failed_binding_forgets_the_assumption_and_requeues
    subject = service(API.new(fail_with: "Kubernetes API request POST failed with HTTP 500: boom"))
    original = pod
    subject.framework.queue.enqueue_unschedulable(original, reason: "no feasible nodes")
    subject.framework.queue.promote_unschedulable
    subject.framework.queue.pop
    subject.send(:bind_pod, original, node)
    subject.send(:stop_bind_workers)

    assert_same original, subject.instance_variable_get(:@pods).fetch(key)
    assert_equal [original], subject.framework.enqueued
    assert_match(/^scheduler_pod_scheduled_after_flush_total 0$/, subject.metrics.render)
  end

  def test_a_rejected_binding_does_not_attempt_a_second_write
    api = API.new(fail_with: "Kubernetes API request POST failed with HTTP 403: binding denied")
    api.define_singleton_method(:patch) { |*| raise "a denied binding was patched" }
    subject = service(api)
    error = assert_raises(Rubernetes::Scheduler::BindError) do
      subject.send(:bind_through_api, {}, pod, node)
    end
    assert_includes error.message, "HTTP 403"
  end

  # A deleted Pod's binding fails with 404; requeueing it looped for ever.
  def test_a_pod_that_is_gone_is_dropped_not_requeued
    subject = service(API.new(fail_with: "Kubernetes API request POST /api/v1/namespaces/ns/pods/p/binding failed with HTTP 404: pods \"p\" not found"))
    subject.send(:bind_pod, pod, node)
    subject.send(:stop_bind_workers)

    assert_empty subject.framework.enqueued
    refute subject.instance_variable_get(:@pods).key?(key), "the assumption is forgotten"
  end

  # The delete event arrived while the binding was in flight.
  def test_a_pod_deleted_during_its_binding_is_not_requeued
    gate = Queue.new
    subject = service(API.new(fail_with: "Kubernetes API request POST failed with HTTP 500: boom", gate: gate))
    subject.send(:bind_pod, pod, node)
    subject.instance_variable_get(:@pods).delete(key)
    gate << :go
    subject.send(:stop_bind_workers)

    assert_empty subject.framework.enqueued
    refute subject.instance_variable_get(:@pods).key?(key)
  end

  def test_an_already_bound_pod_is_not_requeued
    subject = service(API.new(fail_with: "Kubernetes API request POST failed with HTTP 409: pod p is already assigned to node n2"))
    subject.send(:bind_pod, pod, node)
    subject.send(:stop_bind_workers)

    assert_empty subject.framework.enqueued
  end

  def test_a_conflict_with_a_concurrent_update_requeues_an_unassigned_pod
    subject = service(API.new(fail_with: "Kubernetes API request POST failed with HTTP 409: the object has been modified"))
    original = pod
    subject.send(:bind_pod, original, node)
    subject.send(:stop_bind_workers)

    assert_same original, subject.instance_variable_get(:@pods).fetch(key)
    assert_equal [original], subject.framework.enqueued
  end
end
