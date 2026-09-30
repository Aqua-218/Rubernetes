# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# pkg/kubelet/preemption (v1.36.2) ported: the tables of preemption_test.go
# (TestHandleAdmissionFailure, TestGetPodsToPreempt,
# TestAdmissionRequirementsDistance, TestAdmissionRequirementsSubtract,
# TestSmallerResourceRequest) and the lifecycle wiring: a critical Pod the
# node's admission refuses for a resource evicts lower-priority Pods
# (Failed / Preempting, DisruptionTarget, Warning event, kubelet_preemptions)
# and is then admitted.
class KubeletPreemptionTest < Minitest::Test
  P = Rubernetes::Node::Preemption
  SYSTEM_CRITICAL = 2_000_000_000

  class Recorder
    attr_reader :events

    def initialize = @events = []

    def record(**event) = @events << event
  end

  class Metrics
    attr_reader :counts

    def initialize = @counts = Hash.new(0)

    def preemption(resource) = @counts[resource] += 1
  end

  def resources(requests: {}, limits: {})
    value = {}
    value["requests"] = requests unless requests.empty?
    value["limits"] = limits unless limits.empty?
    value
  end

  def pod(name, requests: {}, limits: {}, priority: nil, priority_class: nil, namespace: "default", annotations: {})
    spec = {"containers" => [{"name" => "#{name}-container", "resources" => resources(requests: requests, limits: limits)}]}
    spec["priority"] = priority unless priority.nil?
    spec["priorityClassName"] = priority_class if priority_class
    {"metadata" => {"name" => name, "namespace" => namespace, "uid" => "uid-#{name}", "annotations" => annotations}, "spec" => spec}
  end

  # getTestPods.
  def all_pods
    @all_pods ||= {
      "tiny" => pod("tiny", requests: {"cpu" => "1m", "memory" => "1Mi"}),
      "bestEffort" => pod("bestEffort"),
      "cluster-critical" => pod("cluster-critical", requests: {"cpu" => "100m", "memory" => "100Mi"}, namespace: "kube-system",
                                                    priority_class: "system-cluster-critical", priority: SYSTEM_CRITICAL),
      "node-critical" => pod("node-critical", requests: {"cpu" => "100m", "memory" => "100Mi"}, namespace: "kube-system",
                                              priority_class: "system-node-critical", priority: SYSTEM_CRITICAL + 100),
      "burstable" => pod("burstable", requests: {"cpu" => "100m", "memory" => "100Mi"}),
      "guaranteed" => pod("guaranteed", requests: {"cpu" => "100m", "memory" => "100Mi"}, limits: {"cpu" => "100m", "memory" => "100Mi"}),
      "high-request-burstable" => pod("high-request-burstable", requests: {"cpu" => "300m", "memory" => "300Mi"}),
      "high-request-guaranteed" => pod("high-request-guaranteed", requests: {"cpu" => "300m", "memory" => "300Mi"},
                                                                  limits: {"cpu" => "300m", "memory" => "300Mi"})
    }
  end

  # getAdmissionRequirementList(cpu millis, memory Mi, pods).
  def requirements(cpu, memory, pods)
    list = []
    list << P::Requirement.new("cpu", cpu) if cpu.positive?
    list << P::Requirement.new("memory", memory * 1024 * 1024) if memory.positive?
    list << P::Requirement.new("pods", pods) if pods.positive?
    list
  end

  def names(pods) = pods.map { |item| item.dig("metadata", "name") }

  # TestGetPodsToPreempt.
  def test_get_pods_to_preempt
    critical = all_pods["cluster-critical"]
    cases = [
      ["no requirements", critical, [], requirements(0, 0, 0), []],
      ["no pods", critical, [], requirements(0, 0, 1), :error],
      ["equal pods and resources requirements", critical, %w[burstable], requirements(100, 100, 1), %w[burstable]],
      ["higher requirements than pod requests", critical, %w[burstable], requirements(200, 200, 2), :error],
      ["choose between bestEffort and burstable", critical, %w[burstable bestEffort], requirements(0, 0, 1), %w[bestEffort]],
      ["choose between burstable and guaranteed", critical, %w[burstable guaranteed], requirements(0, 0, 1), %w[burstable]],
      ["choose lower request burstable if it meets requirements", critical, %w[bestEffort high-request-burstable burstable],
       requirements(100, 100, 0), %w[burstable]],
      ["choose higher request burstable if lower does not meet requirements", critical, %w[bestEffort burstable high-request-burstable],
       requirements(150, 150, 0), %w[high-request-burstable]],
      ["multiple pods required", critical, %w[bestEffort burstable high-request-burstable guaranteed high-request-guaranteed],
       requirements(350, 350, 0), %w[burstable high-request-burstable]],
      ["evict guaranteed when we have to, and dont evict the extra burstable", critical,
       %w[bestEffort burstable high-request-burstable guaranteed high-request-guaranteed], requirements(0, 550, 0),
       %w[high-request-burstable high-request-guaranteed]],
      ["evict cluster critical pod for node critical pod", all_pods["node-critical"], %w[cluster-critical], requirements(100, 0, 0),
       %w[cluster-critical]],
      ["can not evict node critical pod for cluster critical pod", critical, %w[node-critical], requirements(100, 0, 0), :error]
    ]
    cases.each do |name, preemptor, input, reqs, expected|
      pods = input.map { |key| all_pods.fetch(key) }
      if expected == :error
        assert_raises(P::Error, name) { P.pods_to_preempt(preemptor, pods, reqs) }
      else
        # podListEqual compares the sets (the swap-remove reorders equals).
        assert_equal expected.sort, names(P.pods_to_preempt(preemptor, pods, reqs)).sort, name
      end
    end
  end

  # TestAdmissionRequirementsDistance.
  def test_distance
    assert_in_delta 0, P.distance(requirements(0, 0, 0), all_pods["burstable"])
    assert_in_delta 2, P.distance(requirements(100, 100, 1), all_pods["bestEffort"])
    assert_in_delta 0, P.distance(requirements(100, 100, 1), all_pods["burstable"])
    assert_in_delta 0, P.distance(requirements(50, 50, 0), all_pods["burstable"])
  end

  # TestAdmissionRequirementsSubtract.
  def test_subtract
    to_h = ->(list) { list.to_h { |item| [item.resource, item.quantity] } }

    assert_equal({}, to_h.call(P.subtract(requirements(0, 0, 0), [all_pods["burstable"]])))
    # A Pod always covers 1 of "pods".
    assert_equal({"cpu" => 100, "memory" => 100 * (1024**2)},
                 to_h.call(P.subtract(requirements(100, 100, 1), [all_pods["bestEffort"]])))
    assert_equal({}, to_h.call(P.subtract(requirements(100, 100, 1), [all_pods["burstable"]])))
    assert_equal({}, to_h.call(P.subtract(requirements(50, 50, 0), [all_pods["burstable"]])))
    assert_equal({"cpu" => 100, "memory" => 100 * (1024**2)},
                 to_h.call(P.subtract(requirements(200, 200, 0), [all_pods["burstable"]])))
    assert_equal({}, to_h.call(P.subtract(requirements(0, 0, 1), [all_pods["burstable"]])))
  end

  # TestSmallerResourceRequest.
  def test_smaller_resource_request
    none = pod("no-requests")
    low = pod("low-memory", requests: {"memory" => "50Mi", "cpu" => "100m"})
    high = pod("high-memory", requests: {"memory" => "200Mi", "cpu" => "100m"})
    high_cpu = pod("high-cpu", requests: {"memory" => "50Mi", "cpu" => "200m"})

    refute P.smaller_resource_request?(low, none), "some requests vs no requests should return false"
    assert P.smaller_resource_request?(low, high), "lower memory should return true"
    refute P.smaller_resource_request?(high, high_cpu), "memory priority over CPU"
    assert P.smaller_resource_request?(low, low), "equal resource request should return true"
    assert P.smaller_resource_request?(pod("hs", requests: {"storage" => "300Mi"}), pod("ls", requests: {"storage" => "200Mi"})),
           "resource type other than CPU and memory are ignored"
  end

  def test_critical_and_preemptable
    assert P.critical?(all_pods["cluster-critical"])
    assert P.critical?(pod("static", annotations: {"kubernetes.io/config.source" => "file"}))
    assert P.critical?(pod("mirror", annotations: {"kubernetes.io/config.mirror" => "abc"}))
    refute P.critical?(pod("api", annotations: {"kubernetes.io/config.source" => "api"}))
    refute P.critical?(all_pods["burstable"])
    assert P.preemptable?(all_pods["cluster-critical"], all_pods["burstable"])
    assert P.preemptable?(all_pods["node-critical"], all_pods["cluster-critical"])
    refute P.preemptable?(all_pods["cluster-critical"], all_pods["node-critical"])
    refute P.preemptable?(pod("a", priority: 10), pod("b")), "no priority on the preemptee: not preemptable"
    assert P.preemptable?(pod("a", priority: 10), pod("b", priority: 5))
  end

  def test_resource_request_follows_get_resource_request
    with_overhead = pod("o", requests: {"cpu" => "100m", "memory" => "100Mi"})
    with_overhead["spec"]["overhead"] = {"cpu" => "50m", "memory" => "10Mi"}

    assert_equal 150, P.resource_request(with_overhead, "cpu")
    assert_equal 110 * (1024**2), P.resource_request(with_overhead, "memory")
    # The overhead is not added to a request of zero.
    none = pod("n")
    none["spec"]["overhead"] = {"cpu" => "50m"}

    assert_equal 0, P.resource_request(none, "cpu")
    assert_equal 1, P.resource_request(none, "pods")
    # Pod-level requests replace the containers' sum.
    level = pod("l", requests: {"cpu" => "100m"})
    level["spec"]["resources"] = {"requests" => {"cpu" => "250m"}}

    assert_equal 250, P.resource_request(level, "cpu")
  end

  # TestHandleAdmissionFailure, on our single-decision admission.
  def decision(resource, requested, used, capacity)
    Rubernetes::Node::Admission::Decision.new(
      accepted: false, reason: "OutOf#{resource}", message: "Node didn't have enough resource: #{resource}",
      requested: {}, available: {}, pod: nil,
      details: {"resource" => resource, "requested" => requested, "used" => used, "capacity" => capacity}
    )
  end

  def handler(pods, kill_error: false)
    @killed = []
    @recorder = Recorder.new
    @metrics = Metrics.new
    kill = lambda do |pod, message:, condition:, reason:|
      raise "problem killing pod" if kill_error

      @killed << [pod.dig("metadata", "name"), message, condition, reason]
    end
    P.new(active_pods: -> { pods.map { |key| all_pods.fetch(key) } }, kill_pod: kill, recorder: @recorder, metrics: @metrics)
  end

  def test_handle_admission_failure
    # critical pods cannot be preempted - no other failure reason
    error = assert_raises(P::Error) { handler(%w[cluster-critical]).handle_admission_failure(all_pods["cluster-critical"], decision("pods", 1, 1, 1)) }
    assert_equal "preemption: error finding a set of pods to preempt: no set of running pods found to reclaim resources: [(res: pods, q: 1), ]",
                 error.message
    assert_equal "Unexpected error while attempting to recover from admission failure: #{error.message}", P.unexpected_message(error)
    # non-critical pod should not trigger eviction
    refute handler(%w[burstable]).handle_admission_failure(all_pods["guaranteed"], decision("memory", 1, 0, 0))
    assert_empty @killed
    # best effort pods are not preempted when attempting to free resources
    assert_raises(P::Error) { handler(%w[bestEffort]).handle_admission_failure(all_pods["cluster-critical"], decision("memory", 1, 0, 0)) }
    # multiple pods evicted
    h = handler(%w[cluster-critical bestEffort burstable high-request-burstable guaranteed high-request-guaranteed])

    assert h.handle_admission_failure(all_pods["cluster-critical"], decision("memory", 550 * (1024**2), 0, 0))
    assert_equal %w[high-request-burstable high-request-guaranteed], @killed.map(&:first)
    assert_equal ["Preempted in order to admit critical pod"], @killed.map { |item| item[1] }.uniq
    assert_equal ["Preempting"], @killed.map(&:last).uniq
    condition = @killed.first[2]

    assert_equal({"type" => "DisruptionTarget", "status" => "True", "reason" => "TerminationByKubelet",
                  "message" => "Pod was preempted by Kubelet to accommodate a critical pod."}, condition)
    assert_equal(%w[Preempting Preempting], @recorder.events.map { |event| event[:reason] })
    assert_equal "Warning", @recorder.events.first[:type]
    assert_equal "high-request-burstable", @recorder.events.first[:involved_object]["name"]
    assert_equal({"memory" => 2}, @metrics.counts)
    # multiple pods with eviction error: no error, nothing counted
    h = handler(%w[cluster-critical bestEffort burstable high-request-burstable guaranteed high-request-guaranteed], kill_error: true)

    assert h.handle_admission_failure(all_pods["cluster-critical"], decision("memory", 550 * (1024**2), 0, 0))
    assert_empty @killed
    assert_equal({}, @metrics.counts)
    # a refusal that is not an insufficient resource stands
    other = Rubernetes::Node::Admission::Decision.new(accepted: false, reason: "UnsupportedOS", message: "x", requested: {},
                                                      available: {}, pod: nil, details: {})

    refute handler(%w[burstable]).handle_admission_failure(all_pods["cluster-critical"], other)
  end

  def test_requirement_from_admission_decision
    admission = Rubernetes::Node::Admission.new(node_name: "n", capacity: {"cpu" => "2", "memory" => "4Gi", "pods" => "10"})
    refused = admission.admit(pod("new", requests: {"cpu" => "1500m"}), other_pods: [pod("a", requests: {"cpu" => "1"})])
    requirement = P.requirement_for(refused)

    assert_equal "cpu", requirement.resource
    # GetInsufficientAmount: requested - (capacity - used) = 1500 - (2000 - 1000).
    assert_equal 500, requirement.quantity
    assert_nil P.requirement_for(admission.admit(pod("fits"), other_pods: []))
  end

  # The lifecycle: a refused critical Pod evicts and is admitted on the
  # second judgement; a refused ordinary Pod is not.
  class FakeRuntime
    def create_sandbox(*) = "sb"
    def start_container(*) = {"id" => "c"}
    def method_missing(*) = nil
    def respond_to_missing?(*) = false
  end

  def lifecycle_with(admitted, capacity: {"cpu" => "2", "memory" => "4Gi", "pods" => "10"})
    admission = Rubernetes::Node::Admission.new(node_name: "n", capacity: capacity)
    killed = []
    lifecycle = nil
    preemption = P.new(active_pods: -> { lifecycle.admitted_pods },
                       kill_pod: lambda { |victim, message:, condition:, reason:|
                         killed << victim.dig("metadata", "name")
                         lifecycle.request_eviction(victim.dig("metadata", "uid"), message: message, condition: condition, reason: reason)
                       })
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: FakeRuntime.new, admission: admission, preemption: preemption)
    admitted.each do |item|
      lifecycle.instance_variable_get(:@records)[item.dig("metadata", "uid")] = lifecycle.send(:new_record, item).merge!(state: "Running")
    end
    [lifecycle, killed]
  end

  def test_lifecycle_readmits_a_critical_pod_after_preempting
    running = pod("victim", requests: {"cpu" => "1500m"})
    lifecycle, killed = lifecycle_with([running])
    critical = pod("crit", requests: {"cpu" => "1"}, priority: SYSTEM_CRITICAL, namespace: "kube-system")
    record = lifecycle.send(:new_record, critical)

    assert lifecycle.send(:admit!, critical, record)
    assert_equal %w[victim], killed
    # The victim is being killed: it no longer counts as active.
    refute_includes lifecycle.admitted_pods.map { |item| item.dig("metadata", "name") }, "victim"
  end

  def test_lifecycle_refuses_an_ordinary_pod_and_an_unrecoverable_critical_one
    lifecycle, killed = lifecycle_with([pod("victim", requests: {"cpu" => "1500m"})])
    ordinary = pod("plain", requests: {"cpu" => "1"})
    error = assert_raises(Rubernetes::Node::Lifecycle::LifecycleError) { lifecycle.send(:admit!, ordinary, lifecycle.send(:new_record, ordinary)) }
    assert_match(/OutOfcpu/, error.message)
    assert_empty killed
    # Only a node-critical Pod holds the node: nothing to evict for a cluster-critical one.
    lifecycle, killed = lifecycle_with([pod("node-crit", requests: {"cpu" => "1500m"}, priority: SYSTEM_CRITICAL + 100)])
    critical = pod("crit", requests: {"cpu" => "1"}, priority: SYSTEM_CRITICAL)
    record = lifecycle.send(:new_record, critical)
    error = assert_raises(Rubernetes::Node::Lifecycle::LifecycleError) { lifecycle.send(:admit!, critical, record) }
    assert_equal "UnexpectedAdmissionError", record[:admission_reason]
    assert_match(/Unexpected error while attempting to recover from admission failure: preemption: error finding a set of pods to preempt/,
                 error.message)
    assert_empty killed
  end
end
