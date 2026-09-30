# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require_relative "../support/security_pipeline_harness"
require "rubernetes/api"
require "rubernetes/security"

# The API core with the full security pipeline: authentication, RBAC
# authorization, flow control, admission and audit around real requests.
class APISecurityPipelineTest < Minitest::Test
  include SecurityPipelineHarness

  def test_unauthenticated_requests_get_401_except_anonymous_paths
    response = @server.call(request("GET", "/api/v1/namespaces/default/pods"))

    assert_equal 401, response.status
    assert_equal "Bearer", response.header("www-authenticate")
    assert_equal "Unauthorized", response.body["reason"]
    assert_equal 200, @server.call(request("GET", "/healthz")).status
    wrong = @server.call(request("GET", "/api/v1/namespaces/default/pods", token: "nope"))

    assert_equal 401, wrong.status
  end

  def test_rbac_forbids_with_kube_apiserver_message_and_allows_bound_user
    denied = @server.call(request("GET", "/api/v1/namespaces/default/pods", token: "bob-token"))

    assert_equal 403, denied.status
    assert_equal 'pods is forbidden: User "bob" cannot list resource "pods" in API group "" in the namespace "default"',
                 denied.body["message"]
    assert_equal "Forbidden", denied.body["reason"]
    allowed = @server.call(request("GET", "/api/v1/namespaces/default/pods", token: "alice-token"))

    assert_equal 200, allowed.status
    refute_nil allowed.header("audit-id")
    secrets = @server.call(request("GET", "/api/v1/namespaces/default/secrets", token: "alice-token"))

    assert_equal 403, secrets.status
    assert_equal 'secrets is forbidden: User "alice" cannot list resource "secrets" in API group "" in the namespace "default"',
                 secrets.body["message"]
  end

  def test_admission_mutates_then_validates_and_audit_records_every_stage
    created = @server.call(request("POST", "/api/v1/namespaces/default/pods", token: "alice-token", body: pod("web")))

    assert_equal 201, created.status, created.body.inspect
    assert_equal "LabelEverything", created.body.dig("metadata", "labels", "admitted-by")
    rejected = @server.call(request("POST", "/api/v1/namespaces/default/pods", token: "alice-token", body: pod("forbidden-pod")))

    assert_equal 403, rejected.status
    assert_match(/name is reserved/, rejected.body["message"])
    stages = @audit.events.map { |event| [event["stage"], event["verb"], event.dig("responseStatus", "code")] }

    assert_includes stages, ["ResponseComplete", "create", 201]
    assert_includes stages, ["ResponseComplete", "create", 403]
    complete = @audit.events.find { |event| event["stage"] == "ResponseComplete" && event.dig("responseStatus", "code") == 201 }

    assert_equal "alice", complete.dig("user", "username")
    assert_equal "web", complete.dig("requestObject", "metadata", "name")
    assert_equal "LabelEverything", complete.dig("responseObject", "metadata", "labels", "admitted-by")
    assert_equal "pods", complete.dig("objectRef", "resource")
    # audit.AddAuditAnnotations: what admission annotated reaches the
    # request's audit event, a rejected request included.
    assert_equal "web", complete.dig("annotations", "reject-named-pods.example.com/checked")
    refused = @audit.events.find { |event| event["stage"] == "ResponseComplete" && event.dig("responseStatus", "code") == 403 }

    assert_equal "forbidden-pod", refused.dig("annotations", "reject-named-pods.example.com/checked")
  end

  def test_subject_access_review_uses_the_configured_authorizer
    review = {"apiVersion" => "authorization.k8s.io/v1", "kind" => "SubjectAccessReview",
              "spec" => {"user" => "alice", "resourceAttributes" => {"verb" => "list", "resource" => "pods", "namespace" => "x"}}}
    # SAR creation itself needs authorization; bob lacks it, alice has none either -> use anonymous-free path by binding alice? Only pods are bound,
    # so exercise the adapter directly and the endpoint denial.
    denied = @server.call(request("POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", token: "alice-token", body: review))

    assert_equal 403, denied.status
    status = @pipeline.review_adapter.authorize({"username" => "x"}, review["spec"])

    assert_equal true, status["allowed"]
    status = @pipeline.review_adapter.authorize({"username" => "x"}, review["spec"].merge("user" => "bob"))

    assert_equal false, status["allowed"]
    rules = @pipeline.review_adapter.rules_for({"username" => "alice"}, "default")

    assert_equal 1, rules["resourceRules"].length
  end

  def test_flow_control_rejections_are_429_with_retry_after
    plcs = [{"metadata" => {"name" => "tiny"},
             "spec" => {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => 1, "limitResponse" => {"type" => "Reject"}}}}]
    schemas = [{"metadata" => {"name" => "all"}, "spec" => {"matchingPrecedence" => 1, "priorityLevelConfiguration" => {"name" => "tiny"},
                                                            "rules" => [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}], "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "namespaces" => ["*"], "clusterScope" => true}]}]}}]
    controller = S::FlowControl::Controller.new(flow_schemas: schemas, priority_level_configurations: plcs, read_seats: 1,
                                                mutating_seats: 0)
    pipeline = S::Pipeline.new(authenticator: @pipeline.authenticator, authorizer: @pipeline.authorizer, flow_control: controller)
    server = API::Server.new(store: @store, security: pipeline)
    attributes = S::Authorization::Attributes.new(user: S::UserInfo.new(name: "alice"), verb: "get", resource: "pods", namespace: "default")
    held = controller.enter(attributes)
    response = server.call(request("GET", "/api/v1/namespaces/default/pods", token: "alice-token"))

    assert_equal 429, response.status
    assert_equal "TooManyRequests", response.body["reason"]
    refute_nil response.header("retry-after")
    controller.release(held)

    assert_equal 200, server.call(request("GET", "/api/v1/namespaces/default/pods", token: "alice-token")).status
  end
end
