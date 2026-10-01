# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/api"

class SecurityAuditFlowControlTest < Minitest::Test
  S = Rubernetes::Security

  def user(name, groups: [])
    S::UserInfo.new(name: name, groups: groups + ["system:authenticated"])
  end

  def attributes(user, verb:, resource: nil, group: "", namespace: "", name: "", subresource: nil, path: "/x")
    S::Authorization::Attributes.new(user: user, verb: verb, resource: resource, api_group: group, namespace: namespace, name: name,
                                     subresource: subresource, path: path, resource_request: !resource.nil?)
  end

  def bootstrap(name)
    JSON.parse(File.read("schema/kubernetes/v1.36.2-defaults/bootstrap/#{name}.json"))["items"]
  end

  def test_audit_policy_first_match_wins_and_secrets_are_redacted
    policy = S::Audit::Policy.from_h({"apiVersion" => "audit.k8s.io/v1", "kind" => "Policy",
                                      "rules" => [{"level" => "None", "users" => ["system:kube-proxy"], "verbs" => ["watch"]},
                                                  {"level" => "RequestResponse",
                                                   "resources" => [{"group" => "", "resources" => %w[secrets]}]},
                                                  {"level" => "Metadata", "omitStages" => ["RequestReceived"]}]})
    proxy = attributes(user("system:kube-proxy"), verb: "watch", resource: "endpoints")

    assert_equal "None", policy.evaluate(proxy).first
    secret = attributes(user("a"), verb: "create", resource: "secrets", namespace: "ns", name: "s")
    level, omitted, = policy.evaluate(secret)

    assert_equal "RequestResponse", level
    assert_empty omitted
    other = attributes(user("a"), verb: "get", path: "/api")

    assert_equal ["Metadata", ["RequestReceived"]], policy.evaluate(other).first(2)

    backend = S::Audit::MemoryBackend.new
    request = Rubernetes::API::Request.new(method: "POST", path: "/api/v1/namespaces/ns/secrets",
                                           headers: {"authorization" => "Bearer secret-token", "user-agent" => "kubectl/1.36"}, remote_address: "10.0.0.9:4444")
    context = S::Audit::Context.new(policy: policy, backend: backend, attributes: secret, request: request, audit_id: "id-1")
    context.request_object = {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "s"}, "data" => {"password" => "cGFzcw=="}}
    context.request_received
    context.response_complete(Rubernetes::API::Response.new(status: 201, body: {"kind" => "Secret", "data" => {"password" => "cGFzcw=="}}),
                              response_object: {"kind" => "Secret", "data" => {"password" => "x"}})

    assert_equal(%w[RequestReceived ResponseComplete], backend.events.map { |event| event["stage"] })
    complete = backend.events.last

    assert_equal "id-1", complete["auditID"]
    assert_equal 201, complete.dig("responseStatus", "code")
    assert_nil complete.dig("requestObject", "data"), "secret data must not be recorded"
    assert_nil complete.dig("responseObject", "data")
    assert_equal ["10.0.0.9"], complete["sourceIPs"]
    refute_includes JSON.generate(backend.events), "secret-token"
  end

  def test_log_backend_is_bounded_and_records_overflow
    Dir.mktmpdir do |dir|
      backend = S::Audit::LogBackend.new(path: File.join(dir, "audit.log"), max_queue: 2)
      backend.instance_variable_get(:@worker).kill
      3.times { |i| backend.process({"auditID" => "e#{i}", "stage" => "ResponseComplete"}) }

      assert_equal 1, backend.dropped
      assert_path_exists File.join(dir, "audit.log.overflow")
      backend.close
    end
  end

  def test_apf_classifies_with_bootstrap_flow_schemas_and_limits_seats
    controller = S::FlowControl::Controller.new(flow_schemas: bootstrap("flowschemas"), priority_level_configurations: bootstrap("prioritylevelconfigurations"),
                                                read_seats: 4, mutating_seats: 2)
    admin = attributes(user("root", groups: %w[system:masters]), verb: "get", resource: "pods", namespace: "a")

    assert_equal "exempt", controller.classify(admin).dig("metadata", "name")
    ticket = controller.enter(admin)

    assert ticket.exempt
    node = attributes(user("system:node:n1", groups: %w[system:nodes]), verb: "get", resource: "nodes")

    assert_equal "system-node-high", controller.classify(node).dig("metadata", "name")
    node_pods = attributes(user("system:node:n1", groups: %w[system:nodes]), verb: "list", resource: "pods", namespace: "a")

    assert_equal "system-nodes", controller.classify(node_pods).dig("metadata", "name")
    sa = attributes(S::UserInfo.service_account(namespace: "kube-system", name: "deployment-controller"), verb: "list", resource: "pods",
                                                                                                          namespace: "x")

    assert_equal "kube-system-service-accounts", controller.classify(sa).dig("metadata", "name")
    anyone = attributes(user("alice"), verb: "get", resource: "pods", namespace: "a")

    assert_equal "global-default", controller.classify(anyone).dig("metadata", "name")
    probe = attributes(user("anon", groups: %w[system:unauthenticated]), verb: "get", path: "/healthz")

    assert_equal "probes", controller.classify(probe).dig("metadata", "name")
    watch = attributes(user("alice"), verb: "watch", resource: "pods", namespace: "a")

    assert controller.enter(watch).exempt, "watches are long-running and not seated"

    tickets = []
    level = controller.priority_levels["global-default"]
    level.seats.times { tickets << controller.enter(anyone) }

    assert_equal level.seats, level.inflight
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    releaser = Thread.new do
      sleep 0.05
      controller.release(tickets.shift)
    end
    waited = controller.enter(anyone)
    releaser.join

    assert_operator waited.queued_seconds, :>, 0.0
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5.0
    tickets.each { |t| controller.release(t) }
    controller.release(waited)

    assert_equal 0, level.inflight
  end

  def test_apf_rejects_when_queue_is_full
    plcs = [{"metadata" => {"name" => "tiny"},
             "spec" => {"type" => "Limited",
                        "limited" => {"nominalConcurrencyShares" => 1,
                                      "limitResponse" => {"type" => "Queue",
                                                          "queuing" => {"queues" => 1, "handSize" => 1, "queueLengthLimit" => 1}}}}}]
    schemas = [{"metadata" => {"name" => "all"}, "spec" => {"matchingPrecedence" => 1, "priorityLevelConfiguration" => {"name" => "tiny"}, "distinguisherMethod" => {"type" => "ByUser"},
                                                            "rules" => [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}], "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "namespaces" => ["*"], "clusterScope" => true}]}]}}]
    controller = S::FlowControl::Controller.new(flow_schemas: schemas, priority_level_configurations: plcs, read_seats: 1,
                                                mutating_seats: 0)
    a = attributes(user("a"), verb: "get", resource: "pods")
    first = controller.enter(a)
    waiter = Thread.new { controller.enter(a) }
    sleep 0.05
    error = assert_raises(S::FlowControl::RejectedError) { controller.enter(a) }
    assert_operator error.retry_after, :>=, 1
    controller.release(first)
    second = waiter.value
    controller.release(second)
  end

  def test_apf_metrics_follow_the_flowcontrol_families
    plcs = [{"metadata" => {"name" => "tiny"}, "spec" => {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => 1, "limitResponse" => {"type" => "Queue", "queuing" => {"queues" => 1, "handSize" => 1, "queueLengthLimit" => 1}}}}},
            {"metadata" => {"name" => "none"},
             "spec" => {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => 1, "limitResponse" => {"type" => "Reject"}}}}]
    rule = [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}],
             "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["pods"], "namespaces" => ["*"],
                                  "clusterScope" => true}]}]
    schemas = [{"metadata" => {"name" => "pods"}, "spec" => {"matchingPrecedence" => 1, "priorityLevelConfiguration" => {"name" => "tiny"}, "distinguisherMethod" => {"type" => "ByUser"}, "rules" => rule}},
               {"metadata" => {"name" => "rest"}, "spec" => {"matchingPrecedence" => 2, "priorityLevelConfiguration" => {"name" => "none"},
                                                             "rules" => [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}], "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "namespaces" => ["*"], "clusterScope" => true}]}]}}]
    controller = S::FlowControl::Controller.new(flow_schemas: schemas, priority_level_configurations: plcs, read_seats: 2,
                                                mutating_seats: 0)
    registry = Rubernetes::Observability::Metrics.new(apiserver: false)
    controller.metrics = registry
    a = attributes(user("a"), verb: "get", resource: "pods")
    first = controller.enter(a)
    text = registry.render

    assert_includes text, 'apiserver_flowcontrol_current_executing_requests{flow_schema="pods",priority_level="tiny"} 1'
    assert_includes text, 'apiserver_flowcontrol_dispatched_requests_total{flow_schema="pods",priority_level="tiny"} 1'
    assert_includes text, 'apiserver_flowcontrol_nominal_limit_seats{priority_level="tiny"} 1'
    waiter = Thread.new { controller.enter(a) }
    sleep 0.05

    assert_includes registry.render, 'apiserver_flowcontrol_current_inqueue_requests{flow_schema="pods",priority_level="tiny"} 1'
    assert_raises(S::FlowControl::RejectedError) { controller.enter(a) }
    assert_includes registry.render,
                    'apiserver_flowcontrol_rejected_requests_total{flow_schema="pods",priority_level="tiny",reason="queue-full"} 1'
    controller.release(first)
    controller.release(waiter.value)
    text = registry.render

    assert_includes text, 'apiserver_flowcontrol_current_executing_requests{flow_schema="pods",priority_level="tiny"} 0'
    assert_includes text, 'apiserver_flowcontrol_current_inqueue_requests{flow_schema="pods",priority_level="tiny"} 0'
    assert_includes text,
                    'apiserver_flowcontrol_request_wait_duration_seconds_count{execute="true",flow_schema="pods",priority_level="tiny"} 2'
    held = controller.enter(attributes(user("b"), verb: "get", resource: "nodes"))
    assert_raises(S::FlowControl::RejectedError) { controller.enter(attributes(user("c"), verb: "get", resource: "nodes")) }
    assert_includes registry.render,
                    'apiserver_flowcontrol_rejected_requests_total{flow_schema="rest",priority_level="none",reason="concurrency-limit"} 1'
    controller.release(held)
  end

  def test_pipeline_orders_authentication_before_authorization_and_audits
    users = S::Authentication::StaticTokenFile.new(S::Authentication::StaticTokenFile.parse("tok,alice,1\n"))
    authenticator = S::Authentication::Union.new(authenticators: [users])
    authorizer = S::Authorization::Union.new(authorizers: [S::Authorization::AlwaysDeny.new])
    policy = S::Audit::Policy.from_h({"apiVersion" => "audit.k8s.io/v1", "kind" => "Policy", "rules" => [{"level" => "Metadata"}]})
    backend = S::Audit::MemoryBackend.new
    pipeline = S::Pipeline.new(authenticator: authenticator, authorizer: authorizer, audit_policy: policy, audit_backend: backend)
    route = Rubernetes::API::Router::Route.new(kind: :resource, operation: :list, group: "", version: "v1",
                                               resource: Rubernetes::API::Resource.new(group: "", version: "v1", resource: "pods", kind: "Pod",
                                                                                       scope: :namespaced), namespace: "ns", collection: true,
                                               path: "/api/v1/namespaces/ns/pods")
    bad = Rubernetes::API::Request.new(method: "GET", path: "/api/v1/namespaces/ns/pods", headers: {"authorization" => "Bearer wrong"})
    # An unrecognised bearer token is an invalid credential (401), never anonymous.
    error = assert_raises(S::Pipeline::Unauthorized) { pipeline.enter(bad, route) }
    assert_match(/invalid bearer token/, error.message)
    assert_equal 401, backend.events.last.dig("responseStatus", "code")
    assert_equal "true", backend.events.last.dig("annotations", "authentication.k8s.io/failed")
    anonymous = Rubernetes::API::Request.new(method: "GET", path: "/api/v1/namespaces/ns/pods")
    assert_raises(S::Pipeline::Forbidden) { pipeline.enter(anonymous, route) }
    good = Rubernetes::API::Request.new(method: "GET", path: "/api/v1/namespaces/ns/pods",
                                        headers: {"authorization" => "Bearer tok", "audit-id" => "client-id"})
    assert_raises(S::Pipeline::Forbidden) { pipeline.enter(good, route) }
    assert_equal "alice", backend.events.last.dig("user", "username")
    assert_equal "client-id", backend.events.last["auditID"]
    assert_equal "list", backend.events.last["verb"]
    allow = S::Pipeline.new(authenticator: authenticator,
                            authorizer: S::Authorization::Union.new(authorizers: [S::Authorization::AlwaysAllow.new]), audit_policy: policy,
                            audit_backend: backend)
    entry = allow.enter(good, route)

    assert_equal "alice", entry.request.identity["username"]
    assert_equal "pods", entry.attributes.resource
    allow.exit(entry, Rubernetes::API::Response.new(status: 200, body: {}))

    assert_equal "ResponseComplete", backend.events.last["stage"]
  end
end
