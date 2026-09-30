# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/security/authorization"

class SecurityAuthorizationTest < Minitest::Test
  S = Rubernetes::Security
  Z = S::Authorization

  class MemorySource
    attr_accessor :cluster_roles, :cluster_role_bindings, :namespaced_roles, :namespaced_role_bindings

    def initialize
      @cluster_roles = []
      @cluster_role_bindings = []
      @namespaced_roles = Hash.new { |hash, key| hash[key] = [] }
      @namespaced_role_bindings = Hash.new { |hash, key| hash[key] = [] }
    end

    def roles(namespace) = @namespaced_roles[namespace]
    def role_bindings(namespace) = @namespaced_role_bindings[namespace]
  end

  def user(name, groups: [], extra: {})
    S::UserInfo.new(name: name, groups: groups + ["system:authenticated"], extra: extra)
  end

  def attributes(user, verb:, resource: nil, group: "", namespace: "", name: "", subresource: nil, path: nil)
    Z::Attributes.new(user: user, verb: verb, resource: resource, api_group: group, namespace: namespace, name: name,
                      subresource: subresource, path: path, resource_request: !resource.nil?)
  end

  def role(name, rules, kind: "ClusterRole", namespace: nil, labels: {}, aggregation: nil)
    object = {"kind" => kind, "metadata" => {"name" => name, "labels" => labels}, "rules" => rules}
    object["metadata"]["namespace"] = namespace if namespace
    object["aggregationRule"] = aggregation if aggregation
    object
  end

  def binding(name, role_kind, role_name, subjects, kind: "ClusterRoleBinding", namespace: nil)
    object = {"kind" => kind, "metadata" => {"name" => name}, "roleRef" => {"kind" => role_kind, "name" => role_name},
              "subjects" => subjects}
    object["metadata"]["namespace"] = namespace if namespace
    object
  end

  def test_rbac_matches_rules_through_bindings_aggregation_and_service_account_subjects
    source = MemorySource.new
    source.cluster_roles << role("pod-reader", [{"apiGroups" => [""], "resources" => %w[pods], "verbs" => %w[get list]}],
                                 labels: {"aggregate" => "true"})
    source.cluster_roles << role("view-all", [], aggregation: {"clusterRoleSelectors" => [{"matchLabels" => {"aggregate" => "true"}}]})
    source.cluster_roles << role("log-reader", [{"apiGroups" => [""], "resources" => %w[pods/log], "verbs" => %w[get]}])
    source.cluster_role_bindings << binding("viewers", "ClusterRole", "view-all", [{"kind" => "Group", "name" => "viewers"}])
    source.namespaced_roles["team"] << role("deployer",
                                            [{"apiGroups" => %w[apps], "resources" => %w[deployments], "verbs" => %w[*], "resourceNames" => %w[web]}], kind: "Role", namespace: "team")
    source.namespaced_role_bindings["team"] << binding("deployer", "Role", "deployer",
                                                       [{"kind" => "ServiceAccount", "name" => "ci", "namespace" => "team"}], kind: "RoleBinding", namespace: "team")
    source.namespaced_role_bindings["team"] << binding("logs", "ClusterRole", "log-reader", [{"kind" => "User", "name" => "dev"}],
                                                       kind: "RoleBinding", namespace: "team")
    rbac = Z::RBAC.new(source: source)

    viewer = user("v", groups: %w[viewers])

    assert_predicate rbac.authorize(attributes(viewer, verb: "list", resource: "pods", namespace: "any")), :allowed?,
                     "aggregated rule via group binding"
    assert_predicate rbac.authorize(attributes(viewer, verb: "delete", resource: "pods")), :no_opinion?
    ci = S::UserInfo.service_account(namespace: "team", name: "ci")

    assert_predicate rbac.authorize(attributes(ci, verb: "patch", resource: "deployments", group: "apps", namespace: "team", name: "web")),
                     :allowed?
    assert_predicate rbac.authorize(attributes(ci, verb: "patch", resource: "deployments", group: "apps", namespace: "team", name: "other")), :no_opinion?,
                     "resourceNames restricts"
    assert_predicate rbac.authorize(attributes(ci, verb: "patch", resource: "deployments", group: "apps", namespace: "elsewhere", name: "web")), :no_opinion?,
                     "namespaced binding does not leak"
    dev = user("dev")

    assert_predicate rbac.authorize(attributes(dev, verb: "get", resource: "pods", subresource: "log", namespace: "team")), :allowed?
    assert_predicate rbac.authorize(attributes(dev, verb: "get", resource: "pods", namespace: "team")), :no_opinion?,
                     "pods/log does not grant pods"
    resources, non_resources = rbac.rules_for(viewer, "team")

    assert_equal 1, resources.length
    assert_empty non_resources
  end

  def test_rbac_non_resource_urls_and_wildcards
    source = MemorySource.new
    source.cluster_roles << role("discovery",
                                 [{"nonResourceURLs" => %w[/healthz /api/*], "verbs" => %w[get]},
                                  {"apiGroups" => %w[*], "resources" => %w[*], "verbs" => %w[watch]}])
    source.cluster_role_bindings << binding("all", "ClusterRole", "discovery", [{"kind" => "Group", "name" => "system:authenticated"}])
    rbac = Z::RBAC.new(source: source)
    anyone = user("x")

    assert_predicate rbac.authorize(attributes(anyone, verb: "get", path: "/healthz")), :allowed?
    assert_predicate rbac.authorize(attributes(anyone, verb: "get", path: "/api/v1")), :allowed?
    assert_predicate rbac.authorize(attributes(anyone, verb: "post", path: "/healthz")), :no_opinion?
    assert_predicate rbac.authorize(attributes(anyone, verb: "watch", resource: "secrets", group: "", namespace: "kube-system")), :allowed?
  end

  def test_node_authorizer_uses_the_pod_reference_graph
    pods = [{"metadata" => {"name" => "web", "namespace" => "team"},
             "spec" => {"serviceAccountName" => "web-sa", "nodeName" => "node-a",
                        "volumes" => [{"secret" => {"secretName" => "tls"}}, {"persistentVolumeClaim" => {"claimName" => "data"}}],
                        "containers" => [{"env" => [{"valueFrom" => {"configMapKeyRef" => {"name" => "cfg"}}}]}]}}]
    graph = Object.new
    graph.define_singleton_method(:pods_on_node) { |node| node == "node-a" ? pods : [] }
    graph.define_singleton_method(:persistent_volume_claim) { |_ns, name| name == "data" ? {"spec" => {"volumeName" => "pv-1"}} : nil }
    graph.define_singleton_method(:persistent_volume) do |name|
      name == "pv-1" ? {"spec" => {"claimRef" => {"namespace" => "team", "name" => "data"}}} : nil
    end
    node = Z::Node.new(graph: graph)
    kubelet = user("system:node:node-a", groups: %w[system:nodes])

    assert_predicate node.authorize(attributes(kubelet, verb: "get", resource: "secrets", namespace: "team", name: "tls")), :allowed?
    assert_predicate node.authorize(attributes(kubelet, verb: "get", resource: "configmaps", namespace: "team", name: "cfg")), :allowed?
    assert_predicate node.authorize(attributes(kubelet, verb: "get", resource: "persistentvolumes", name: "pv-1")), :allowed?
    # Upstream answers NoOpinion, never Deny: another authorizer may decide.
    assert_predicate node.authorize(attributes(kubelet, verb: "get", resource: "secrets", namespace: "team", name: "other")), :no_opinion?
    assert_predicate node.authorize(attributes(kubelet, verb: "list", resource: "secrets", namespace: "team")), :no_opinion?
    assert_predicate node.authorize(attributes(kubelet, verb: "update", resource: "nodes", subresource: "status", name: "node-a")),
                     :allowed?
    # authorizeNode allows any status write; NodeRestriction admission limits it to the node's own.
    assert_predicate node.authorize(attributes(kubelet, verb: "update", resource: "nodes", subresource: "status", name: "node-b")),
                     :allowed?
    assert_predicate node.authorize(attributes(kubelet, verb: "get", resource: "nodes", name: "node-b")), :no_opinion?
    assert_predicate node.authorize(attributes(kubelet, verb: "update", resource: "leases", group: "coordination.k8s.io",
                                                        namespace: "kube-node-lease", name: "node-a")), :allowed?
    assert_predicate node.authorize(attributes(kubelet, verb: "create", resource: "certificatesigningrequests",
                                                        group: "certificates.k8s.io")), :allowed?
    other = user("system:node:node-b", groups: %w[system:nodes])

    assert_predicate node.authorize(attributes(other, verb: "get", resource: "secrets", namespace: "team", name: "tls")), :no_opinion?
    assert_predicate node.authorize(attributes(user("alice"), verb: "get", resource: "secrets", namespace: "team", name: "tls")),
                     :no_opinion?
  end

  def test_abac_policies
    abac = Z::ABAC.new(Z::ABAC.parse(<<~JSONL))
      {"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user": "alice", "namespace": "*", "resource": "*", "apiGroup": "*"}}
      {"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"group": "readers", "readonly": true, "namespace": "public", "resource": "pods", "apiGroup": ""}}
      {"apiVersion": "abac.authorization.kubernetes.io/v1beta1", "kind": "Policy", "spec": {"user": "*", "nonResourcePath": "/version"}}
    JSONL
    assert_predicate abac.authorize(attributes(user("alice"), verb: "delete", resource: "pods", namespace: "x")), :allowed?
    reader = user("bob", groups: %w[readers])

    assert_predicate abac.authorize(attributes(reader, verb: "get", resource: "pods", namespace: "public")), :allowed?
    assert_predicate abac.authorize(attributes(reader, verb: "delete", resource: "pods", namespace: "public")), :no_opinion?
    assert_predicate abac.authorize(attributes(reader, verb: "get", resource: "pods", namespace: "private")), :no_opinion?
    assert_predicate abac.authorize(attributes(user("zed"), verb: "get", path: "/version")), :allowed?
    assert_raises(S::ConfigurationError) { Z::ABAC.parse('{"kind":"Policy","apiVersion":"v1"}') }
  end

  def test_webhook_authorizer_honours_allowed_denied_and_failure_policy
    seen = []
    transport = lambda do |body|
      review = JSON.parse(body)
      seen << review
      verb = review.dig("spec", "resourceAttributes", "verb")
      status = case verb
               when "get" then {"allowed" => true}
               when "delete" then {"denied" => true, "reason" => "no"}
               else {}
               end
      [200, {"status" => status}]
    end
    webhook = Z::Webhook.new(transport: transport)

    assert_predicate webhook.authorize(attributes(user("a"), verb: "get", resource: "pods")), :allowed?
    assert_predicate webhook.authorize(attributes(user("a"), verb: "delete", resource: "pods")), :denied?
    assert_predicate webhook.authorize(attributes(user("a"), verb: "list", resource: "pods")), :no_opinion?
    webhook.authorize(attributes(user("a"), verb: "get", resource: "pods"))

    assert_equal 3, seen.length, "allowed decisions are cached"
    assert_equal "authorization.k8s.io/v1", seen.first["apiVersion"]
    broken = Z::Webhook.new(transport: ->(_body) { raise IOError, "down" }, failure_policy: "Deny")

    assert_predicate broken.authorize(attributes(user("a"), verb: "get", resource: "pods")), :denied?
  end

  def test_union_stops_at_first_decision_and_privileged_group
    deny_all = Z::AlwaysDeny.new
    allow_all = Z::AlwaysAllow.new
    ordered = Z::Union.new(authorizers: [deny_all, allow_all])

    assert_predicate ordered.authorize(attributes(user("a"), verb: "get", resource: "pods")), :denied?
    assert_predicate ordered.authorize(attributes(user("root", groups: %w[system:masters]), verb: "get", resource: "pods")), :allowed?
    assert_equal %w[AlwaysDeny AlwaysAllow], ordered.modes
    node_only = Z::Union.new(authorizers: [Z::Node.new(graph: Object.new.tap { |g| g.define_singleton_method(:pods_on_node) { |_| [] } })])

    assert_predicate node_only.authorize(attributes(user("a"), verb: "get", resource: "pods")), :no_opinion?
  end
end
