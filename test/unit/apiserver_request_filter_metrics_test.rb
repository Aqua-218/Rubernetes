# frozen_string_literal: true

# apiserver_request_filter_duration_seconds (endpoints/filterlatency): each
# filter of the handler chain -- authentication, audit, (constrained)
# impersonation, priorityandfairness, authorization -- is observed when it
# hands the request on; a filter that rejects the request is not, except
# authentication, whose failure handler completes it too.

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"
require "json"

class APIServerRequestFilterMetricsTest < Minitest::Test
  Decision = Struct.new(:allowed, :reason, :authorizer) do
    def allowed? = allowed
    def denied? = !allowed
  end

  class Authorizer
    def authorize(attributes)
      Decision.new(attributes.user.name != "mallory", "no", "RBAC")
    end
  end

  def server(**options)
    @metrics = Rubernetes::Observability::Metrics.new
    pipeline = Rubernetes::Security::Pipeline.new(authorizer: Authorizer.new, **options)
    Rubernetes::API::Server.new(store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil),
                                security: pipeline, metrics: @metrics)
  end

  def get(server, user)
    server.call(Rubernetes::API::Request.new(method: "GET", path: "/api/v1/namespaces/default/configmaps", headers: {},
                                             identity: {"username" => user, "groups" => ["system:authenticated"]}))
  end

  def count(filter) = @metrics.render[/^apiserver_request_filter_duration_seconds_count\{filter="#{filter}"\} (\d+)$/, 1].to_i

  def test_each_filter_is_observed_once_it_hands_the_request_on
    api = server
    2.times { get(api, "alice") }
    get(api, "mallory")

    assert_equal 3, count("authentication")
    assert_equal 3, count("audit")
    assert_equal 3, count("constrainedimpersonation")
    assert_equal 0, count("impersonation")
    # mallory was refused by the authorizer.
    assert_equal 2, count("authorization")
    # No flow control configured: the max-in-flight filter is not tracked.
    assert_equal 0, count("priorityandfairness")
    text = @metrics.render
    assert_match(/^apiserver_request_filter_duration_seconds_bucket\{filter="audit",le="0\.0001"\} \d+$/, text)
    assert_match(/^# HELP apiserver_request_filter_duration_seconds \[ALPHA\] Request filter latency distribution in seconds, for each filter type$/, text)
  end

  def test_flow_control_is_the_priorityandfairness_filter
    bootstrap = ->(name) { JSON.parse(File.read(File.expand_path("../../schema/kubernetes/v1.36.2-defaults/bootstrap/#{name}.json", __dir__)))["items"] }
    flow_control = Rubernetes::Security::FlowControl::Controller.new(flow_schemas: bootstrap.call("flowschemas"),
                                                                    priority_level_configurations: bootstrap.call("prioritylevelconfigurations"))
    api = server(flow_control: flow_control)
    get(api, "alice")
    get(api, "mallory")
    # APF runs after authorization here, so only the allowed request reaches it.
    assert_equal 1, count("priorityandfairness")
  end

  def test_the_legacy_impersonation_filter_without_constrained_impersonation
    api = server(constrained_impersonation: false)
    get(api, "alice")
    assert_equal 1, count("impersonation")
    assert_equal 0, count("constrainedimpersonation")
  end
end
