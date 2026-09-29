# frozen_string_literal: true

# The API Priority and Fairness series beyond requests and waits
# (apiserver/pkg/util/flowcontrol/metrics): seats executing and queued, the
# current limit, execution time, queue length after enqueue, estimated
# seats, and the TimingRatioHistograms -- time-weighted (nanoseconds)
# utilisation of each priority level and of the server by request kind.

require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/observability/metrics"

class APIServerFlowControlExtrasMetricsTest < Minitest::Test
  S = Rubernetes::Security

  RULE = [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}],
           "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "namespaces" => ["*"], "clusterScope" => true}]}].freeze
  PLCS = [
    {"metadata" => {"name" => "tiny"}, "spec" => {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => 1,
                                                                                         "limitResponse" => {"type" => "Queue", "queuing" => {"queues" => 1, "handSize" => 1, "queueLengthLimit" => 1}}}}},
    {"metadata" => {"name" => "none"}, "spec" => {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => 1, "limitResponse" => {"type" => "Reject"}}}},
    {"metadata" => {"name" => "exempt"}, "spec" => {"type" => "Exempt"}}
  ].freeze
  SCHEMAS = [{"metadata" => {"name" => "all"}, "spec" => {"matchingPrecedence" => 1, "priorityLevelConfiguration" => {"name" => "tiny"},
                                                           "distinguisherMethod" => {"type" => "ByUser"}, "rules" => RULE}}].freeze

  def setup
    @now = 0.0
    @controller = S::FlowControl::Controller.new(flow_schemas: SCHEMAS, priority_level_configurations: PLCS, read_seats: 2, mutating_seats: 0,
                                                 clock: -> { @now })
    @registry = Rubernetes::Observability::Metrics.new(apiserver: false, component: "kube-apiserver")
    @controller.metrics = @registry
  end

  def attributes(verb)
    user = S::UserInfo.new(name: "a", groups: ["system:authenticated"])
    S::Authorization::Attributes.new(user: user, verb: verb, resource: "pods", api_group: "", namespace: "", name: "", subresource: nil,
                                     path: "/x", resource_request: true)
  end

  def line(text, name, labels) = text[/^#{Regexp.escape(name)}#{Regexp.escape(labels)} (\S+)$/, 1]

  def test_seats_limits_and_time_weighted_utilisation
    @now = 1.0
    ticket = @controller.enter(attributes("get"))
    @now = 3.0
    text = @registry.render
    tiny = '{flow_schema="all",priority_level="tiny"}'
    assert_equal "1", line(text, "apiserver_flowcontrol_current_executing_seats", tiny)
    assert_equal "1", line(text, "apiserver_flowcontrol_work_estimated_seats_count", tiny)
    assert_equal "1", line(text, "apiserver_flowcontrol_current_limit_seats", '{priority_level="tiny"}')
    assert_equal "1", line(text, "apiserver_flowcontrol_current_limit_seats", '{priority_level="none"}')
    assert_nil line(text, "apiserver_flowcontrol_current_limit_seats", '{priority_level="exempt"}')

    # One second idle, two seconds with the level's single seat taken.
    seat = 'apiserver_flowcontrol_priority_level_seat_utilization'
    assert_equal "1000000000", line(text, "#{seat}_bucket", '{phase="executing",priority_level="tiny",le="0"}')
    assert_equal "1000000000", line(text, "#{seat}_bucket", '{phase="executing",priority_level="tiny",le="0.99"}')
    assert_equal "3000000000", line(text, "#{seat}_bucket", '{phase="executing",priority_level="tiny",le="1"}')
    assert_equal "2e+09", line(text, "#{seat}_sum", '{phase="executing",priority_level="tiny"}')
    assert_equal "3000000000", line(text, "#{seat}_count", '{phase="executing",priority_level="tiny"}')
    assert_equal "2e+09", line(text, "apiserver_flowcontrol_priority_level_request_utilization_sum", '{phase="executing",priority_level="tiny"}')
    assert_equal "0", line(text, "apiserver_flowcontrol_priority_level_request_utilization_sum", '{phase="waiting",priority_level="tiny"}')
    assert_equal "2e+09", line(text, "apiserver_flowcontrol_demand_seats_sum", '{priority_level="tiny"}')
    # The server executes at most two requests (tiny's and none's seats).
    assert_equal "1e+09", line(text, "apiserver_flowcontrol_read_vs_write_current_requests_sum", '{phase="executing",request_kind="readOnly"}')
    assert_equal "0", line(text, "apiserver_flowcontrol_read_vs_write_current_requests_sum", '{phase="executing",request_kind="mutating"}')
    assert_match(/^# TYPE apiserver_flowcontrol_read_vs_write_current_requests histogram$/, text)

    @controller.release(ticket)
    text = @registry.render
    assert_equal "0", line(text, "apiserver_flowcontrol_current_executing_seats", tiny)
    assert_equal "1", line(text, "apiserver_flowcontrol_request_execution_seconds_count", '{flow_schema="all",priority_level="tiny",type="regular"}')
  end

  def test_a_queued_request_is_measured_in_the_queue
    first = @controller.enter(attributes("create"))
    waiter = Thread.new { @controller.enter(attributes("create")) }
    Thread.pass until @registry.render.include?('apiserver_flowcontrol_current_inqueue_seats{flow_schema="all",priority_level="tiny"} 1')
    @now = 2.0
    text = @registry.render
    assert_equal "1", line(text, "apiserver_flowcontrol_request_queue_length_after_enqueue_count", '{flow_schema="all",priority_level="tiny"}')
    assert_equal "1", line(text, "apiserver_flowcontrol_request_queue_length_after_enqueue_bucket", '{flow_schema="all",priority_level="tiny",le="10"}')
    # Waiting limit: one queue of one; the whole server queues at most one.
    assert_equal "2e+09", line(text, "apiserver_flowcontrol_priority_level_request_utilization_sum", '{phase="waiting",priority_level="tiny"}')
    assert_equal "2e+09", line(text, "apiserver_flowcontrol_read_vs_write_current_requests_sum", '{phase="waiting",request_kind="mutating"}')
    # One executing plus one waiting seat against a limit of one.
    assert_equal "4e+09", line(text, "apiserver_flowcontrol_demand_seats_sum", '{priority_level="tiny"}')
    @controller.release(first)
    second = waiter.value
    assert_match(/apiserver_flowcontrol_current_inqueue_seats\{flow_schema="all",priority_level="tiny"\} 0$/, @registry.render)
    @controller.release(second)
  end
end
