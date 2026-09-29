# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security/cel"

# Two apiservers over one store, each installing CRDs only from its own
# writes (no watch).  A custom resource request reaching the peer right
# after the CRD was created elsewhere must not answer 404: the peer
# re-reads that group's definitions on a route miss.
class CRDPeerCatchUpTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @creator = build_server
    @peer = build_server
  end

  def build_server
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions", kind: "CustomResourceDefinition",
                                        scope: :cluster, subresources: [{resource: "status", verbs: %w[get patch update]}]))
    registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    openapi = API::OpenAPIRepository.new
    manager = API::CRD::Manager.new(registry: registry, store: @store, openapi: openapi, cel: Rubernetes::Security::CEL::Evaluator.new)
    API::Server.new(registry: registry, store: @store, crd_manager: manager, openapi_repository: openapi)
  end

  def call(server, method, path, body: nil)
    headers = body ? {"content-type" => "application/json"} : {}
    server.call(API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body),
                                 identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def crd
    schema = {"type" => "object", "properties" => {
      "spec" => {"type" => "object", "required" => ["size"],
                 "properties" => {"size" => {"type" => "integer"}, "color" => {"type" => "string", "default" => "blue"}}}
    }}
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "widgets.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget"},
                "versions" => [{"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema}}]}}
  end

  def widget
    {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "w1", "namespace" => "team"}, "spec" => {"size" => 2}}
  end

  def test_peer_serves_custom_resource_created_through_another_apiserver
    call(@creator, "POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    assert_equal 201, call(@creator, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd).status

    created = call(@peer, "POST", "/apis/example.com/v1/namespaces/team/widgets", body: widget)
    assert_equal 201, created.status, created.body.inspect
    assert_equal "blue", created.body.dig("spec", "color"), "the peer applies the CRD's defaulting"
  end

  def test_peer_discovery_lists_group_version_created_elsewhere
    assert_equal 201, call(@creator, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd).status

    listing = call(@peer, "GET", "/apis/example.com/v1")
    assert_equal 200, listing.status, listing.body.inspect
    assert_includes listing.body["resources"].map { |resource| resource["name"] }, "widgets"
  end

  def test_unknown_group_still_answers_not_found
    assert_equal 404, call(@peer, "GET", "/apis/nothing.example.com/v1/things").status
  end

  def test_deleted_definition_is_not_resurrected_on_peer
    assert_equal 201, call(@creator, "POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd).status
    call(@creator, "DELETE", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    until call(@creator, "GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com").status == 404
      flunk "CRD never removed" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.05
    end
    assert_equal 404, call(@peer, "GET", "/apis/example.com/v1/namespaces/team/widgets").status
  end
end
