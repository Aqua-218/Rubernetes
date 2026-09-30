# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# kube-scheduler (SchedulerAsyncPreemption, NominatedNodeNameForExpectation)
# writes status.nominatedNodeName: with the Unschedulable condition of a Pod
# that preempted (one status write, updatePod), for a Pod whose PreBind has
# work, and cleared for lower-priority Pods a preemption displaces.  The e2e
# async preemption spec waits for the preemptor's nomination while its
# victims are still terminating.
class SchedulerNominationWiringTest < Minitest::Test
  class API
    attr_reader :patches, :types

    def initialize
      @patches = []
    end

    def patch(resource, body, type: nil, namespace: nil, api_version: nil, name: nil, subresource: nil, **_options)
      (@types ||= []) << type
      @patches << [resource, namespace, name, subresource, body]
      {}
    end

    def create(*_arguments, **_options) = {}
  end

  class Leader
    def step = :leader
    def leader? = true
  end

  def service(api)
    service = Rubernetes::Bootstrap::SchedulerService.new(config: {}, logger: nil, client: api)
    service.instance_variable_set(:@elector, Leader.new)
    service.send(:build_runtime!)
    service
  end

  def pod(name)
    Rubernetes::Scheduler::Pod.new("apiVersion" => "v1", "kind" => "Pod",
                                   "metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}"},
                                   "spec" => {"containers" => []})
  end

  def result(nominated)
    Rubernetes::Scheduler::ScheduleResult.new(status: :unschedulable, pod: pod("high"), trace: nil,
                                              filtered: {"a" => {"reason" => "Insufficient cpu"}},
                                              nominated_node: nominated)
  end

  def status_patches(api) = api.patches.select { |entry| entry[3] == "status" }.map(&:last)

  def test_the_preemptor_nomination_goes_with_its_unschedulable_condition
    api = API.new
    scheduler = service(api)
    scheduler.send(:report_unschedulable, result("a"), 1)

    status = status_patches(api).last.fetch("status")

    assert_equal "a", status["nominatedNodeName"]
    assert_equal "Unschedulable", status["conditions"].first["reason"]

    # Same message, nomination unchanged: nothing is written again.
    scheduler.send(:report_unschedulable, result("a"), 1)

    assert_equal 1, status_patches(api).length
    # A cleared nomination is written even with the same message.
    scheduler.send(:report_unschedulable, result(""), 1)

    assert_equal 2, status_patches(api).length
    assert status_patches(api).last["status"].key?("nominatedNodeName")
    assert_nil status_patches(api).last["status"]["nominatedNodeName"]
  end

  # Conditions merge by type (strategic merge, as updatePod sends): a JSON
  # merge patch replaced the Pod's whole condition list.
  def test_conditions_are_written_with_a_strategic_merge_patch
    api = API.new
    scheduler = service(api)
    scheduler.send(:report_unschedulable, result("a"), 1)
    victim = pod("victim")
    scheduler.send(:mark_victim_disrupted, victim)

    assert_equal %i[strategic strategic], api.types
  end

  def test_no_nomination_leaves_the_field_alone
    api = API.new
    service(api).send(:report_unschedulable, result(nil), 1)

    refute status_patches(api).last["status"].key?("nominatedNodeName")
  end

  def test_nominate_and_clear_write_the_status
    api = API.new
    scheduler = service(api)
    scheduler.send(:nominate_pod, pod("prebind"), "worker-1")
    scheduler.send(:clear_pod_nomination, pod("displaced"))

    assert_equal [["pods", "ns", "prebind", "status", {"status" => {"nominatedNodeName" => "worker-1"}}],
                  ["pods", "ns", "displaced", "status", {"status" => {"nominatedNodeName" => nil}}]], api.patches
  end

  def test_the_production_framework_is_wired_for_nominations
    scheduler = service(API.new)
    framework = scheduler.instance_variable_get(:@framework)

    refute_nil framework
    assert_equal :nominate_pod, framework.instance_variable_get(:@nominate_handler).name
    assert_equal :clear_pod_nomination, framework.instance_variable_get(:@clear_nomination_handler).name
    assert framework.instance_variable_get(:@async_preemption)
  end
end
