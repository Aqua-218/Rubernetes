# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"

# ConstrainedImpersonation (k8s.io/apiserver/pkg/endpoints/filters/
# impersonation): the five modes, their caches, the legacy filter used with
# the gate off, and the pipeline wiring (authorization, audit, headers).
class ConstrainedImpersonationTest < Minitest::Test
  S = Rubernetes::Security
  I = S::Impersonation
  API = Rubernetes::API
  AUTHN = "authentication.k8s.io"
  ANY = ["*"] * 6

  # Allows exactly the [verb, group, resource, subresource, name, namespace]
  # tuples it was given ("*" matches anything) and records every check.
  class RuleAuthorizer
    attr_reader :checks

    def initialize(*rules)
      @rules = rules
      @checks = []
    end

    def authorize(attributes)
      @checks << attributes
      tuple = [attributes.verb, attributes.api_group, attributes.resource.to_s, attributes.subresource, attributes.name,
               attributes.namespace]
      allowed = @rules.any? do |rule|
        rule.each_with_index.all? { |value, index| value == "*" || value == tuple[index] }
      end
      allowed ? S::Authorization::Decision.allow : S::Authorization::Decision.no_opinion("no rule")
    end
  end

  def alice
    S::UserInfo.new(name: "alice", groups: %w[system:authenticated])
  end

  def request_attributes(user = alice, verb: "list", resource: "pods", namespace: "default", name: "")
    S::Authorization::Attributes.new(user: user, verb: verb, api_group: "", api_version: "v1", resource: resource,
                                     namespace: namespace, name: name, resource_request: true,
                                     path: "/api/v1/namespaces/#{namespace}/#{resource}")
  end

  def wanted(name, uid: "", groups: [], extra: {})
    I::Wanted.new(name: name, uid: uid, groups: groups, extra: extra)
  end

  def tracker(*rules)
    authorizer = RuleAuthorizer.new(*rules)
    [I::Tracker.new(authorizer), authorizer]
  end

  def state_check(state, who, attributes = request_attributes)
    state.check(I::CacheKey.new(who, attributes), who, attributes.user)
  end

  def test_user_info_mode_needs_impersonate_on_the_request_and_impersonate_on_the_user
    t, authorizer = tracker(["impersonate-on:user-info:list", "", "pods", "", "", "default"],
                            ["impersonate:user-info", AUTHN, "users", "", "bob", ""])
    result = t.impersonate(wanted("bob"), request_attributes)
    assert_equal "bob", result.user.name
    assert_equal %w[system:authenticated], result.user.groups
    assert_equal "impersonate:user-info", result.constraint
    verbs = authorizer.checks.map(&:verb)
    assert_includes verbs, "impersonate-on:user-info:list"
    assert_includes verbs, "impersonate:user-info"
  end

  def test_legacy_impersonate_is_the_last_mode_and_has_no_constraint
    t, = tracker(["impersonate", "", "users", "", "bob", ""])
    result = t.impersonate(wanted("bob"), request_attributes)
    assert_equal "bob", result.user.name
    assert_equal "", result.constraint
  end

  def test_denied_everywhere_reports_the_first_error
    t, = tracker
    error = assert_raises(I::Forbidden) { t.impersonate(wanted("bob"), request_attributes) }
    assert_equal 'pods is forbidden: User "alice" cannot impersonate-on:user-info:list resource "pods" in API group "" ' \
                 'in the namespace "default": no rule', error.message
  end

  def test_the_impersonate_on_check_passing_but_the_identity_check_failing
    t, = tracker(["impersonate-on:user-info:list", "*", "*", "*", "*", "*"])
    error = assert_raises(I::Forbidden) { t.impersonate(wanted("bob"), request_attributes) }
    assert_equal 'users.authentication.k8s.io "bob" is forbidden: User "alice" cannot impersonate:user-info resource "users" ' \
                 'in API group "authentication.k8s.io" at the cluster scope: no rule', error.message
    assert_equal({"name" => "bob", "group" => AUTHN, "kind" => "users"}, error.details)
  end

  def test_arbitrary_node_checks_the_nodes_resource_and_fixes_the_groups
    t, authorizer = tracker(["impersonate-on:arbitrary-node:get", "*", "*", "*", "*", "*"],
                            ["impersonate:arbitrary-node", AUTHN, "nodes", "", "n1", ""])
    result = t.impersonate(wanted("system:node:n1"), request_attributes(verb: "get", name: "p"))
    assert_equal "system:node:n1", result.user.name
    assert_equal %w[system:nodes system:authenticated], result.user.groups
    assert_equal "impersonate:arbitrary-node", result.constraint
    assert(authorizer.checks.none? { |check| check.resource == "users" })
  end

  def test_serviceaccount_mode_gives_the_service_account_groups
    t, = tracker(["impersonate-on:serviceaccount:list", "*", "*", "*", "*", "*"],
                 ["impersonate:serviceaccount", AUTHN, "serviceaccounts", "", "builder", "ci"])
    result = t.impersonate(wanted("system:serviceaccount:ci:builder"), request_attributes)
    assert_equal %w[system:serviceaccounts system:serviceaccounts:ci system:authenticated], result.user.groups
    assert_equal "impersonate:serviceaccount", result.constraint
  end

  def associated_rules
    [["impersonate-on:associated-node:get", "*", "*", "*", "*", "*"], ["impersonate:associated-node", AUTHN, "nodes", "", "*", ""]]
  end

  def agent(node)
    S::UserInfo.new(name: "system:serviceaccount:kube-system:agent", groups: %w[system:serviceaccounts],
                    extra: {"authentication.kubernetes.io/node-name" => [node], "authentication.kubernetes.io/pod-name" => ["agent-x"]})
  end

  def test_associated_node_sees_extra_keys_only_and_a_wildcard_node_name
    t, authorizer = tracker(*associated_rules)
    result = t.impersonate(wanted("system:node:n1"), request_attributes(agent("n1"), verb: "get", name: "p"))
    assert_equal "system:node:n1", result.user.name
    assert_equal %w[system:nodes system:authenticated], result.user.groups
    assert_equal "impersonate:associated-node", result.constraint
    authorizer.checks.each do |check|
      assert_equal({"authentication.kubernetes.io/associated-node-keys" =>
                     %w[authentication.kubernetes.io/node-name authentication.kubernetes.io/pod-name]}, check.user.extra)
    end
    # Another node than the requester's: associated-node does not apply and
    # nothing else is granted.
    other, = tracker(*associated_rules)
    assert_raises(I::Forbidden) { other.impersonate(wanted("system:node:n2"), request_attributes(agent("n1"), verb: "get", name: "p")) }
  end

  def test_associated_node_cache_is_shared_across_nodes_but_keeps_each_name
    t, authorizer = tracker(*associated_rules)
    first = t.impersonate(wanted("system:node:n1"), request_attributes(agent("n1"), verb: "get", name: "p"))
    assert_equal "system:node:n1", first.user.name
    checks = authorizer.checks.length
    second = t.impersonate(wanted("system:node:n2"), request_attributes(agent("n2"), verb: "get", name: "p"))
    assert_equal "system:node:n2", second.user.name
    assert_equal checks, authorizer.checks.length, "the second node reused the cached decision"
  end

  def test_constrained_modes_refuse_masters_and_node_groups
    masters = wanted("bob", groups: %w[system:masters])
    error = assert_raises(I::Forbidden) do
      state_check(I::ModeState.new(RuleAuthorizer.new(ANY), "impersonate:user-info", true), masters)
    end
    assert_match(/impersonating the system:masters group is not allowed/, error.message)
    assert_match(/groups.authentication.k8s.io "system:masters" is forbidden/, error.message)
    # The legacy verb still allows it: the tracker falls through to legacy.
    t, = tracker(ANY)
    assert_equal "", t.impersonate(masters, request_attributes).constraint
    node = wanted("system:node:n1", groups: %w[g])
    error = assert_raises(I::Forbidden) do
      state_check(I::ModeState.new(RuleAuthorizer.new(ANY), "impersonate:arbitrary-node", true), node)
    end
    assert_match(/when impersonating a node, cannot impersonate groups \["g"\]/, error.message)
  end

  def test_many_groups_try_a_wildcard_check_first
    authorizer = RuleAuthorizer.new(["impersonate:user-info", AUTHN, "groups", "", "*", ""], ["impersonate:user-info", AUTHN, "users", "", "bob", ""])
    result = state_check(I::ModeState.new(authorizer, "impersonate:user-info", true), wanted("bob", groups: %w[a b c d]))
    assert_equal %w[a b c d system:authenticated], result.user.groups
    assert_equal ["*"], authorizer.checks.select { |check| check.resource == "groups" }.map(&:name)
  end

  def test_extra_keys_are_validated_in_constrained_modes
    state = I::ModeState.new(RuleAuthorizer.new(ANY), "impersonate:user-info", true)
    [["nodomain", /must be a domain-prefixed path/], ["Example.com/x", /subdomain must consist of lower case/],
     ["example.com/X", /non-lowercase key/]].each do |key, pattern|
      error = assert_raises(I::Forbidden) { state_check(state, wanted("bob", extra: {key => ["v"]})) }
      assert_match pattern, error.message
    end
    assert_raises(I::Forbidden) { state_check(state, wanted("bob", extra: {"example.com/x" => [""]})) }
    assert_equal({"example.com/x" => ["v"]}, state_check(state, wanted("bob", extra: {"example.com/x" => ["v"]})).user.extra)
  end

  def test_second_identical_request_is_served_from_the_cache
    t, authorizer = tracker(["impersonate-on:user-info:list", "*", "*", "*", "*", "*"], ["impersonate-on:user-info:get", "*", "*", "*", "*", "*"],
                            ["impersonate:user-info", "*", "*", "*", "*", "*"])
    t.impersonate(wanted("bob"), request_attributes)
    before = authorizer.checks.length
    t.impersonate(wanted("bob"), request_attributes)
    assert_equal before, authorizer.checks.length
    # Another request re-checks impersonate-on but reuses the identity decision.
    t.impersonate(wanted("bob"), request_attributes(verb: "get", name: "p"))
    assert_equal ["impersonate-on:user-info:get"], authorizer.checks[before..].map(&:verb)
  end

  def test_expiring_cache_forgets_after_the_ttl
    now = 100.0
    cache = I::ExpiringCache.new(ttl: 10.0, clock: -> { now })
    cache.set([:k], :v)
    assert_equal :v, cache.get([:k])
    now = 110.5
    assert_nil cache.get([:k])
  end

  def test_legacy_filter_checks_core_resources_and_authentication_group_uids
    authorizer = RuleAuthorizer.new(["impersonate", "", "serviceaccounts", "", "builder", "ci"], ["impersonate", AUTHN, "uids", "", "u-1", ""],
                                    ["impersonate", AUTHN, "userextras", "scopes", "view", ""])
    result = I::LegacyFilter.new(authorizer).impersonate(wanted("system:serviceaccount:ci:builder", uid: "u-1", extra: {"scopes" => ["view"]}),
                                                         request_attributes)
    assert_equal %w[system:serviceaccounts system:serviceaccounts:ci system:authenticated], result.user.groups
    assert_equal "u-1", result.user.uid
    assert_equal({"scopes" => ["view"]}, result.user.extra)
    anonymous = I::LegacyFilter.new(nil).impersonate(wanted("system:anonymous"), request_attributes)
    assert_equal %w[system:unauthenticated], anonymous.user.groups
  end

  def test_headers_parse_groups_extras_and_reject_a_missing_user
    headers = Rubernetes::Transport::Headers.new
    headers.add("Impersonate-User", "bob")
    headers.add("Impersonate-Group", "a, b")
    headers.add("Impersonate-Group", "c")
    headers.add("Impersonate-Extra-Example.com%2fscopes", "view")
    headers.add("Impersonate-Uid", "u-1")
    request = API::Request.new(method: "GET", path: "/api/v1/pods", headers: headers)
    who = I.wanted_user(request)
    assert_equal "bob", who.name
    assert_equal ["a, b", "c"], who.groups
    assert_equal({"example.com/scopes" => ["view"]}, who.extra)
    assert_equal "u-1", who.uid
    refute I.requested?(I.strip_headers(request))
    missing = API::Request.new(method: "GET", path: "/api/v1/pods", headers: {"impersonate-group" => "a"})
    error = assert_raises(I::BadRequest) { I.wanted_user(missing) }
    assert_equal 'requested &user.DefaultInfo{Name:"", UID:"", Groups:[]string{"a"}, Extra:map[string][]string(nil)} ' \
                 "without impersonating a user name", error.message
    assert_nil I.wanted_user(API::Request.new(method: "GET", path: "/api/v1/pods"))
  end

  def test_filter_records_attempt_and_authorization_metrics
    metrics = Rubernetes::Observability::Metrics.new
    filter = I::Filter.new(RuleAuthorizer.new(["impersonate-on:user-info:list", "*", "*", "*", "*", "*"], ["impersonate:user-info", "*", "*", "*", "*", "*"]))
    filter.metrics = metrics
    filter.impersonate(wanted("bob"), request_attributes)
    text = metrics.render
    assert_match(/apiserver_impersonation_attempts_total\{decision="allowed",mode="user-info"\} 1/, text)
    assert_match(/apiserver_impersonation_authorization_attempts_total\{decision="allowed",mode="user-info"\} 2/, text)
  end

  # --- through the API server and RBAC -------------------------------------

  def rbac_server(rules, constrained: true)
    source = Object.new
    roles = [{"metadata" => {"name" => "impersonator"}, "rules" => rules},
             {"metadata" => {"name" => "reader"}, "rules" => [{"apiGroups" => [""], "resources" => %w[pods], "verbs" => %w[list]}]},
             {"metadata" => {"name" => "system:basic-user"},
              "rules" => [{"apiGroups" => [AUTHN], "resources" => %w[selfsubjectreviews], "verbs" => %w[create]}]}]
    bindings = [{"metadata" => {"name" => "impersonator"}, "roleRef" => {"kind" => "ClusterRole", "name" => "impersonator"},
                 "subjects" => [{"kind" => "User", "name" => "alice"}]},
                {"metadata" => {"name" => "reader"}, "roleRef" => {"kind" => "ClusterRole", "name" => "reader"},
                 "subjects" => [{"kind" => "User", "name" => "bob"}]},
                {"metadata" => {"name" => "system:basic-user"}, "roleRef" => {"kind" => "ClusterRole", "name" => "system:basic-user"},
                 "subjects" => [{"kind" => "Group", "name" => "system:authenticated"}]}]
    source.define_singleton_method(:cluster_roles) { roles }
    source.define_singleton_method(:cluster_role_bindings) { bindings }
    source.define_singleton_method(:roles) { |_ns| [] }
    source.define_singleton_method(:role_bindings) { |_ns| [] }
    tokens = S::Authentication::StaticTokenFile.new(S::Authentication::StaticTokenFile.parse("alice-token,alice,1\n"))
    @audit = S::Audit::MemoryBackend.new
    policy = S::Audit::Policy.from_h({"apiVersion" => "audit.k8s.io/v1", "kind" => "Policy", "rules" => [{"level" => "Metadata"}]})
    pipeline = S::Pipeline.new(authenticator: S::Authentication::Union.new(authenticators: [tokens]),
                               authorizer: S::Authorization::Union.new(authorizers: [S::Authorization::RBAC.new(source: source)]),
                               audit_policy: policy, audit_backend: @audit, constrained_impersonation: constrained)
    registry = API::Registry.new
    registry.register(API::Resource.new(group: AUTHN, version: "v1", resource: "selfsubjectreviews", kind: "SelfSubjectReview",
                                        scope: :cluster, verbs: %w[create]))
    registry.register(API::Resource.new(group: "authorization.k8s.io", version: "v1", resource: "subjectaccessreviews",
                                        kind: "SubjectAccessReview", scope: :cluster, verbs: %w[create]))
    API::Server.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil),
                    security: pipeline)
  end

  def list_pods_as(server, user)
    server.call(API::Request.new(method: "GET", path: "/api/v1/namespaces/default/pods",
                                 headers: {"authorization" => "Bearer alice-token", "impersonate-user" => user}))
  end

  def test_rbac_constrained_impersonation_authorizes_as_the_impersonated_user_and_audits_both
    server = rbac_server([{"apiGroups" => [""], "resources" => %w[pods], "verbs" => %w[impersonate-on:user-info:list]},
                          {"apiGroups" => [AUTHN], "resources" => %w[users], "resourceNames" => %w[bob carol], "verbs" => %w[impersonate:user-info]}])
    response = list_pods_as(server, "bob")
    assert_equal 200, response.status, response.body.inspect
    complete = @audit.events.find { |event| event["stage"] == "ResponseComplete" }
    assert_equal "alice", complete.dig("user", "username")
    assert_equal "bob", complete.dig("impersonatedUser", "username")
    assert_equal({"impersonationConstraint" => "impersonate:user-info"}, complete["authenticationMetadata"])
    # carol may be impersonated but has no pod access: authorization runs as
    # the impersonated user.
    denied = list_pods_as(server, "carol")
    assert_equal 403, denied.status
    assert_equal 'pods is forbidden: User "carol" cannot list resource "pods" in API group "" in the namespace "default"', denied.body["message"]
    stranger = list_pods_as(server, "dave")
    assert_equal 403, stranger.status
    assert_match(/users.authentication.k8s.io "dave" is forbidden: User "alice" cannot impersonate:user-info/, stranger.body["message"])
    assert_equal "users", stranger.body.dig("details", "kind")
  end

  def test_rbac_request_scope_limits_constrained_impersonation
    server = rbac_server([{"apiGroups" => [""], "resources" => %w[pods], "verbs" => %w[impersonate-on:user-info:get]},
                          {"apiGroups" => [AUTHN], "resources" => %w[users], "verbs" => %w[impersonate:user-info]}])
    response = list_pods_as(server, "bob")
    assert_equal 403, response.status
    assert_match(/cannot impersonate-on:user-info:list resource "pods"/, response.body["message"])
  end

  def test_legacy_impersonate_verb_still_works_and_gate_off_uses_the_legacy_filter
    rules = [{"apiGroups" => [""], "resources" => %w[users], "verbs" => %w[impersonate]}]
    [true, false].each do |constrained|
      server = rbac_server(rules, constrained: constrained)
      assert_equal 200, list_pods_as(server, "bob").status
      complete = @audit.events.find { |event| event["stage"] == "ResponseComplete" }
      assert_equal "bob", complete.dig("impersonatedUser", "username")
      assert_nil complete["authenticationMetadata"]
    end
  end

  # The SelfSubjectReview conformance spec impersonates with a plain extra
  # key: user-info refuses it, the admin's legacy verb then allows it, and
  # every repeated Impersonate-* header survives as its own value.
  def test_self_subject_review_conformance_identity_falls_through_to_legacy
    server = rbac_server([{"apiGroups" => ["*"], "resources" => ["*"], "verbs" => ["*"]}])
    headers = Rubernetes::Transport::Headers.new
    {"Authorization" => "Bearer alice-token", "Content-Type" => "application/json", "Impersonate-User" => "jane-doe",
     "Impersonate-Uid" => "uniq-id"}.each { |name, value| headers.add(name, value) }
    %w[system:authenticated developers].each { |group| headers.add("Impersonate-Group", group) }
    %w[python javascript].each { |language| headers.add("Impersonate-Extra-Known-Languages", language) }
    body = JSON.generate({"apiVersion" => "authentication.k8s.io/v1", "kind" => "SelfSubjectReview"})
    response = server.call(API::Request.new(method: "POST", path: "/apis/authentication.k8s.io/v1/selfsubjectreviews", headers: headers, body: body))
    assert_equal 201, response.status, response.body.inspect
    user = response.body.dig("status", "userInfo")
    assert_equal "jane-doe", user["username"]
    assert_equal "uniq-id", user["uid"]
    assert_equal %w[system:authenticated developers], user["groups"]
    assert_equal({"known-languages" => %w[python javascript]}, user["extra"])
    assert_nil @audit.events.find { |event| event["stage"] == "ResponseComplete" }["authenticationMetadata"]
  end

  # "[sig-auth] SubjectReview should support SubjectReview API operations":
  # the SubjectAccessReview answer must match what the impersonated request
  # really gets.  A server built with only the pipeline used to answer every
  # review "allowed".
  def test_subject_access_review_agrees_with_the_impersonated_request
    server = rbac_server([{"apiGroups" => ["*"], "resources" => ["*"], "verbs" => ["*"]}])
    review = lambda do |user, groups|
      body = JSON.generate({"apiVersion" => "authorization.k8s.io/v1", "kind" => "SubjectAccessReview",
                            "spec" => {"user" => user, "groups" => groups,
                                       "resourceAttributes" => {"verb" => "list", "resource" => "pods", "namespace" => "default", "version" => "v1"}}})
      response = server.call(API::Request.new(method: "POST", path: "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                                              headers: {"authorization" => "Bearer alice-token", "content-type" => "application/json"}, body: body))
      assert_equal 201, response.status, response.body.inspect
      response.body.dig("status", "allowed")
    end
    sa = "system:serviceaccount:default:e2e"
    sa_groups = %w[system:authenticated system:serviceaccounts system:serviceaccounts:default]
    assert_equal false, review.call(sa, sa_groups)
    assert_equal true, review.call("bob", [])
    headers = Rubernetes::Transport::Headers.new
    {"Authorization" => "Bearer alice-token", "Impersonate-User" => sa, "Impersonate-Uid" => "u-1"}.each { |name, value| headers.add(name, value) }
    sa_groups.each { |group| headers.add("Impersonate-Group", group) }
    listed = server.call(API::Request.new(method: "GET", path: "/api/v1/namespaces/default/pods", headers: headers))
    assert_equal 403, listed.status
    assert_equal 200, list_pods_as(server, "bob").status
  end

  def test_missing_user_header_is_a_bad_request
    server = rbac_server([])
    response = server.call(API::Request.new(method: "GET", path: "/api/v1/namespaces/default/pods",
                                            headers: {"authorization" => "Bearer alice-token", "impersonate-group" => "g"}))
    assert_equal 400, response.status
    assert_equal "BadRequest", response.body["reason"]
  end
end
