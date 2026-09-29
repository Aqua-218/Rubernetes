# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# The production scheduler was assembled with a bind handler and nothing else,
# so Framework#apply_preemption! failed closed on every preemption attempt with
# "preemption requires a delete handler".  Preemption therefore never worked in
# a real cluster: a Pod that needed room stayed Pending until something else
# freed a node.  Observed live in the 2026-09-14 K1 run, where the scheduler's
# last_result was {"status": "requeued", "pod": "preemptor-pod",
# "error": "preemption requires a delete handler"}.
#
# Specification: spec/control-plane/scheduler.md §5.6.4 (preemption), upstream
# pkg/scheduler/framework/preemption/executor.go (util.DeletePod per victim).
class M3SchedulerPreemptionWiringTest < Minitest::Test
  class Logger
    attr_reader :events

    def initialize
      @events = []
    end

    def log(level, event, **fields)
      @events << [level, event, fields]
    end

    def respond_to_missing?(*) = true

    def method_missing(name, *args, **fields)
      @events << [name, args.first, fields]
      nil
    end
  end

  class API
    attr_reader :deleted

    def initialize(status: nil)
      @deleted = []
      @status = status
    end

    def delete(resource, name = nil, namespace: nil, api_version: nil, **_options)
      @deleted << [resource, namespace, name, api_version]
      raise api_error(@status) if @status

      {"kind" => "Status", "status" => "Success"}
    end

    private

    def api_error(status)
      response = Struct.new(:status).new(status)
      Rubernetes::Client::APIError.new(
        "Kubernetes API request DELETE /api/v1/namespaces/ns/pods/victim failed with HTTP #{status}",
        response: response
      )
    end
  end

  class Leader
    def step = :leader
    def leader? = true
  end

  class Follower
    def step = :follower
    def leader? = false
  end

  def test_production_scheduler_is_built_with_a_preemption_delete_handler
    service = Rubernetes::Bootstrap::SchedulerService.new(config: {}, logger: Logger.new, client: API.new)
    service.send(:build_runtime!)

    handler = service.framework.instance_variable_get(:@delete_pod_handler)

    refute_nil handler, "preemption is inert without a delete handler"
    assert_equal :delete_victim_pod, handler.name
  end

  def test_victim_is_deleted_through_the_api
    api = API.new
    service = scheduler(api)

    assert_equal true, service.send(:delete_victim_pod, victim)
    assert_equal [["pods", "ns", "victim", "v1"]], api.deleted
  end

  def test_a_victim_that_is_already_gone_is_not_a_failure
    api = API.new(status: 404)
    service = scheduler(api)

    assert_equal true, service.send(:delete_victim_pod, victim)
  end

  def test_other_api_errors_still_fail_the_preemption
    api = API.new(status: 500)
    service = scheduler(api)

    assert_raises(Rubernetes::Client::APIError) { service.send(:delete_victim_pod, victim) }
  end

  def test_a_follower_never_deletes_a_victim
    api = API.new
    service = scheduler(api)
    service.instance_variable_set(:@elector, Follower.new)

    assert_raises(Rubernetes::Controller::LeadershipLostError) { service.send(:delete_victim_pod, victim) }
    assert_empty api.deleted
  end

  private

  def scheduler(api)
    service = Rubernetes::Bootstrap::SchedulerService.new(config: {}, logger: Logger.new, client: api)
    service.instance_variable_set(:@elector, Leader.new)
    service
  end

  def victim
    Rubernetes::Scheduler::Pod.new(
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => "victim", "namespace" => "ns", "uid" => "uid-victim"},
      "spec" => {"containers" => []}
    )
  end
end
