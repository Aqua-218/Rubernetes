# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"

# DRAResourceClaimGranularStatusAuthorization: changing a ResourceClaim's
# allocation/reservedFor needs resourceclaims/binding, and changing a
# driver's status.devices needs arbitrary-node:<verb> (or associated-node for
# a service account on the allocated node) on resourceclaims/driver.
class ResourceClaimStatusAuthorizationTest < Minitest::Test
  S = Rubernetes::Security
  API = Rubernetes::API
  PATH = "/apis/resource.k8s.io/v1/namespaces/team/resourceclaims"

  def server(rules)
    source = Object.new
    roles = [{"metadata" => {"name" => "writer"}, "rules" => [{"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceclaims resourceclaims/status],
                                                               "verbs" => %w[get create update patch]}] + rules}]
    bindings = [{"metadata" => {"name" => "writer"}, "roleRef" => {"kind" => "ClusterRole", "name" => "writer"},
                 "subjects" => [{"kind" => "User", "name" => "driver"}, {"kind" => "User", "name" => "admin-setup"}]}]
    source.define_singleton_method(:cluster_roles) { roles }
    source.define_singleton_method(:cluster_role_bindings) { bindings }
    source.define_singleton_method(:roles) { |_ns| [] }
    source.define_singleton_method(:role_bindings) { |_ns| [] }
    tokens = S::Authentication::StaticTokenFile.new(S::Authentication::StaticTokenFile.parse("d,driver,1\n"))
    pipeline = S::Pipeline.new(authenticator: S::Authentication::Union.new(authenticators: [tokens]),
                               authorizer: S::Authorization::Union.new(authorizers: [S::Authorization::RBAC.new(source: source)]))
    registry = API::Registry.new
    registry.register(API::Resource.new(group: "resource.k8s.io", version: "v1", resource: "resourceclaims", kind: "ResourceClaim",
                                        scope: :namespaced, subresources: %w[status]))
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    API::Server.new(registry: registry, store: store, security: pipeline).tap do |api|
      @unsecured = API::Server.new(registry: registry, store: store)
      @unsecured.call(API::Request.new(method: "POST", path: "/api/v1/namespaces", headers: {"content-type" => "application/json"},
                                       body: JSON.generate({"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})))
      @unsecured.call(API::Request.new(method: "POST", path: PATH, headers: {"content-type" => "application/json"},
                                       body: JSON.generate({"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim",
                                                            "metadata" => {"name" => "c"}, "spec" => {}})))
      @api = api
    end
  end

  def put_status(status)
    current = JSON.parse(JSON.generate(@unsecured.call(API::Request.new(method: "GET", path: "#{PATH}/c")).body))
    current["status"] = status
    @api.call(API::Request.new(method: "PUT", path: "#{PATH}/c/status", headers: {"authorization" => "Bearer d", "content-type" => "application/json"},
                               body: JSON.generate(current)))
  end

  ALLOCATION = {"devices" => {"results" => [{"request" => "r", "driver" => "gpu.example", "pool" => "p", "device" => "d0"}]},
                "nodeSelector" => {"nodeSelectorTerms" => [{"matchFields" => [{"key" => "metadata.name", "operator" => "In",
                                                                               "values" => ["n1"]}]}]}}.freeze
  DEVICES = [{"driver" => "gpu.example", "pool" => "p", "device" => "d0", "conditions" => [{"type" => "Ready", "status" => "True"}]}].freeze

  def test_allocation_needs_the_binding_subresource
    server([])
    denied = put_status({"allocation" => ALLOCATION})

    assert_equal 422, denied.status, denied.body.inspect
    assert_match(%r{changing status.allocation or status.reservedFor requires resource="resourceclaims/binding", verb="update"},
                 denied.body["message"])
    server([{"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceclaims/binding], "verbs" => %w[update]}])

    assert_equal 200, put_status({"allocation" => ALLOCATION}).status
  end

  def test_device_status_needs_the_driver_subresource_for_that_driver
    binding = {"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceclaims/binding], "verbs" => %w[update]}
    server([binding])

    assert_equal 200, put_status({"allocation" => ALLOCATION}).status
    denied = put_status({"allocation" => ALLOCATION, "devices" => DEVICES})

    assert_equal 422, denied.status
    assert_match(%r{changing status.devices requires resource="resourceclaims/driver", verb="\[arbitrary-node:update\]"},
                 denied.body["message"])
    server([binding, {"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceclaims/driver], "resourceNames" => %w[other.example],
                      "verbs" => %w[arbitrary-node:update]}])

    assert_equal 200, put_status({"allocation" => ALLOCATION}).status
    assert_equal 422, put_status({"allocation" => ALLOCATION, "devices" => DEVICES}).status
    server([binding, {"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceclaims/driver], "resourceNames" => %w[gpu.example],
                      "verbs" => %w[arbitrary-node:update]}])

    assert_equal 200, put_status({"allocation" => ALLOCATION}).status
    assert_equal 200, put_status({"allocation" => ALLOCATION, "devices" => DEVICES}).status
  end

  def test_unchanged_allocation_needs_nothing_extra
    server([{"apiGroups" => ["resource.k8s.io"], "resources" => %w[resourceclaims/binding], "verbs" => %w[update]}])
    put_status({"allocation" => ALLOCATION})
    server([])
    # Re-seeded: the claim is created without status by server(); give it one.
    @unsecured.call(API::Request.new(method: "PUT", path: "#{PATH}/c/status", headers: {"content-type" => "application/json"},
                                     body: JSON.generate(JSON.parse(JSON.generate(@unsecured.call(API::Request.new(method: "GET", path: "#{PATH}/c")).body)).merge("status" => {"allocation" => ALLOCATION}))))

    assert_equal 200, put_status({"allocation" => ALLOCATION}).status
  end

  def test_modified_drivers
    server([])
    old = {"devices" => DEVICES}

    assert_empty @api.send(:claim_device_status_drivers, old, {"devices" => DEVICES})
    assert_equal ["gpu.example"], @api.send(:claim_device_status_drivers, old, {"devices" => []})
    user = S::UserInfo.new(name: "system:serviceaccount:kube-system:gpu", extra: {"authentication.kubernetes.io/node-name" => ["n1"]})

    assert @api.send(:claim_node_service_account?, user, ALLOCATION)
    refute @api.send(:claim_node_service_account?, S::UserInfo.new(name: "driver"), ALLOCATION)
  end
end
