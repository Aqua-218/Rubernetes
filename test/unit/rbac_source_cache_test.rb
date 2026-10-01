# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/storage/memory_store"

# The RBAC authorizer listed every ClusterRole and binding out of the store on
# every request -- some 70 roles and 150 bindings copied each time, 10 ms of a
# GET that otherwise takes 5, and 30 ms on a loaded apiserver.  The store
# source now keeps them until the RBAC key spaces change, which the store
# reports through revision_under(prefix).
class RBACSourceCacheTest < Minitest::Test
  A = Rubernetes::Security::Authorization
  UserInfo = Rubernetes::Security::UserInfo

  class CountingStore < SimpleDelegator
    attr_reader :lists

    def initialize(store)
      super
      @lists = Hash.new(0)
    end

    def list(prefix = "", **)
      @lists[prefix] += 1
      __getobj__.list(prefix, **)
    end
  end

  KEY_FOR = ->(resource, namespace) { namespace ? "registry/#{resource}/#{namespace}/" : "registry/#{resource}/" }

  def role(name, namespace: nil, kind: "ClusterRole")
    metadata = {"name" => name}
    metadata["namespace"] = namespace if namespace
    {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => kind, "metadata" => metadata,
     "rules" => [{"apiGroups" => [""], "resources" => ["pods"], "verbs" => ["get"]}]}
  end

  def binding(name, role_kind:, role_name:, user:, namespace: nil)
    kind = namespace ? "RoleBinding" : "ClusterRoleBinding"
    metadata = {"name" => name}
    metadata["namespace"] = namespace if namespace
    {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => kind, "metadata" => metadata,
     "roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => role_kind, "name" => role_name},
     "subjects" => [{"kind" => "User", "name" => user}]}
  end

  def attributes(user_name, namespace: "ns")
    A::Attributes.new(user: UserInfo.new(name: user_name, groups: ["system:authenticated"]), verb: "get",
                      path: "/api/v1/namespaces/#{namespace}/pods/x", namespace: namespace, api_group: "", api_version: "v1",
                      resource: "pods", subresource: "", name: "x", resource_request: true)
  end

  def setup
    @memory = Rubernetes::Storage::MemoryStore.new
    @memory.create("registry/clusterroles/_cluster/pod-reader", role("pod-reader"))
    @memory.create("registry/clusterrolebindings/_cluster/alice-reads",
                   binding("alice-reads", role_kind: "ClusterRole", role_name: "pod-reader", user: "alice"))
    @store = CountingStore.new(@memory)
    @source = A::StoreRBACSource.new(@store, key_for: KEY_FOR)
    @rbac = A::RBAC.new(source: @source)
  end

  def test_repeated_authorizations_list_the_store_once
    3.times { assert_predicate @rbac.authorize(attributes("alice")), :allowed? }
    3.times { refute_predicate @rbac.authorize(attributes("bob")), :allowed? }
    assert_equal 1, @store.lists["registry/clusterroles/"]
    assert_equal 1, @store.lists["registry/clusterrolebindings/"]
    assert_equal 1, @store.lists["registry/roles/ns/"]
    assert_equal 1, @store.lists["registry/rolebindings/ns/"]
  end

  def test_a_new_binding_is_seen_at_once
    refute_predicate @rbac.authorize(attributes("bob")), :allowed?
    @memory.create("registry/rolebindings/ns/bob-reads",
                   binding("bob-reads", role_kind: "ClusterRole", role_name: "pod-reader", user: "bob", namespace: "ns"))

    assert_predicate @rbac.authorize(attributes("bob")), :allowed?
    refute_predicate @rbac.authorize(attributes("bob", namespace: "other")), :allowed?, "a RoleBinding grants in its namespace only"
  end

  def test_a_deleted_binding_stops_granting_at_once
    assert_predicate @rbac.authorize(attributes("alice")), :allowed?
    @memory.delete("registry/clusterrolebindings/_cluster/alice-reads")

    refute_predicate @rbac.authorize(attributes("alice")), :allowed?
  end

  def test_writes_to_other_resources_do_not_invalidate
    @rbac.authorize(attributes("alice"))
    20.times { |index| @memory.create("registry/pods/ns/p#{index}", {"metadata" => {"name" => "p#{index}", "namespace" => "ns"}}) }
    @rbac.authorize(attributes("alice"))

    assert_equal 1, @store.lists["registry/clusterroles/"]
  end

  def test_a_store_without_key_space_revisions_is_listed_every_time
    plain = Object.new
    lists = Hash.new(0)
    memory = @memory
    plain.define_singleton_method(:list) do |prefix = "", **options|
      lists[prefix] += 1
      memory.list(prefix, **options)
    end
    rbac = A::RBAC.new(source: A::StoreRBACSource.new(plain, key_for: KEY_FOR))

    2.times { assert_predicate rbac.authorize(attributes("alice")), :allowed? }
    assert_equal 2, lists["registry/clusterroles/"]
  end

class RBACSourceCacheScopeTest < RBACSourceCacheTest
  def test_a_namespaced_binding_write_keeps_the_cluster_cache
    # bob has no cluster grant, so his check walks the namespaced lists too.
    refute_predicate @rbac.authorize(attributes("bob")), :allowed?
    @memory.create("registry/rolebindings/other/x",
                   binding("x", role_kind: "ClusterRole", role_name: "pod-reader", user: "carol", namespace: "other"))

    refute_predicate @rbac.authorize(attributes("bob")), :allowed?
    assert_equal 1, @store.lists["registry/clusterroles/"], "a RoleBinding write must not re-list ClusterRoles"
    assert_equal 2, @store.lists["registry/rolebindings/ns/"], "but the namespaced lists are refreshed"
  end
end
