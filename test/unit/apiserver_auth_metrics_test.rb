# frozen_string_literal: true

# The API server's authentication and authorization metrics
# (endpoints/filters/metrics.go): authentication_attempts and
# authentication_duration_seconds by result (success / failure),
# authenticated_user_requests by compressed username, and
# authorization_attempts_total / authorization_duration_seconds by
# allowed / denied / no-opinion.

require_relative "../test_helper"
require_relative "../support/security_pipeline_harness"

class APIServerAuthMetricsTest < Minitest::Test
  include SecurityPipelineHarness

  def metrics_text
    @server.call(request("GET", "/metrics", token: "alice-token"))
    @server.instance_variable_get(:@metrics).render
  end

  def test_auth_attempts_are_counted_by_result
    @server.call(request("GET", "/api/v1/namespaces/default/pods", token: "alice-token"))
    @server.call(request("GET", "/api/v1/namespaces/default/pods", token: "bob-token"))
    @server.call(request("GET", "/api/v1/namespaces/default/pods", token: "nope"))
    text = @server.instance_variable_get(:@metrics).render
    assert_match(/^authentication_attempts\{result="success"\} 2/, text)
    assert_match(/^authentication_attempts\{result="failure"\} 1/, text)
    assert_match(/^authentication_duration_seconds_count\{result="success"\} 2/, text)
    assert_match(/^authenticated_user_requests\{username="other"\} 2/, text)
    assert_match(/^authorization_attempts_total\{result="allowed"\} 1/, text)
    assert_match(/^authorization_attempts_total\{result="no-opinion"\} 1/, text)
    assert_match(/^authorization_duration_seconds_bucket\{result="allowed",le="0.001"\}/, text)
    # InstrumentedAuthorizer: the deciding authorizer's type and name; a
    # request no authorizer decided is not counted.
    assert_match(/^apiserver_authorization_decisions_total\{decision="allowed",name="rbac",type="RBAC"\} 1$/, text)
    refute_match(/apiserver_authorization_decisions_total\{decision="denied"/, text)
  end

  def test_admission_and_audit_metrics
    @server.call(request("POST", "/api/v1/namespaces/default/pods", token: "alice-token", body: pod("fine")))
    @server.call(request("POST", "/api/v1/namespaces/default/pods", token: "alice-token", body: pod("forbidden-pod")))
    text = @server.instance_variable_get(:@metrics).render
    assert_match(/^apiserver_admission_step_admission_duration_seconds_count\{operation="CREATE",rejected="false",type="admit"\} 2/, text)
    assert_match(/^apiserver_admission_step_admission_duration_seconds_count\{operation="CREATE",rejected="false",type="validate"\} 1/, text)
    assert_match(/^apiserver_admission_step_admission_duration_seconds_count\{operation="CREATE",rejected="true",type="validate"\} 1/, text)
    assert_match(/^apiserver_admission_controller_admission_duration_seconds_count\{name="RejectNamedPods",operation="CREATE",rejected="true",type="validate"\} 1/, text)
    assert_match(/^apiserver_admission_controller_admission_duration_seconds_count\{name="LabelEverything",operation="CREATE",rejected="false",type="admit"\} 2/, text)
    assert_match(/^apiserver_audit_level_total\{level="RequestResponse"\} 2/, text)
    assert_match(/^apiserver_audit_event_total \d+/, text)
  end
end
