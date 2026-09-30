# frozen_string_literal: true

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

  class Framework
    attr_reader :enqueued

    def initialize = @enqueued = []
    def enqueue(pod) = @enqueued << pod
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

  def test_a_failed_binding_forgets_the_assumption_and_requeues
    subject = service(API.new(fail_with: "Kubernetes API request POST failed with HTTP 500: boom"))
    original = pod
    subject.send(:bind_pod, original, node)
    subject.send(:stop_bind_workers)

    assert_same original, subject.instance_variable_get(:@pods).fetch(key)
    assert_equal [original], subject.framework.enqueued
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
end
