# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "logger"
require "rubernetes/api"
require "rubernetes/storage/memory_store"
require "rubernetes/bootstrap/api_server_service"

# A CRD written through one apiserver replica is served by every replica:
# each runs its own reconciler over the shared store, the way every
# kube-apiserver runs its own CRD informer.
class APIServerDynamicAPIReconcilerTest < Minitest::Test
  API = Rubernetes::API

  def replica(store)
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions",
                                        kind: "CustomResourceDefinition", scope: :cluster,
                                        subresources: [{resource: "status", verbs: %w[get patch update]}]))
    registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    openapi = API::OpenAPIRepository.new
    manager = API::CRD::Manager.new(registry: registry, store: store, openapi: openapi)
    server = API::Server.new(registry: registry, store: store, crd_manager: manager, openapi_repository: openapi)
    [registry, manager, server]
  end

  def crd(served: true)
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "gadgets.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => "gadgets", "singular" => "gadget", "kind" => "Gadget", "listKind" => "GadgetList"},
                "versions" => [{"name" => "v1", "served" => served, "storage" => true,
                                "schema" => {"openAPIV3Schema" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}}}]}}
  end

  def eventually(timeout = 5)
    deadline = Time.now + timeout
    sleep 0.05 until yield || Time.now > deadline
    assert yield
  end

  def test_a_replica_serves_crds_written_through_another
    store = Rubernetes::Storage::MemoryStore.new
    _registry_a, _manager_a, server_a = replica(store)
    registry_b, manager_b, = replica(store)
    service = Rubernetes::Bootstrap::APIServerService.allocate
    service.instance_variable_set(:@store, store)
    service.instance_variable_set(:@registry, registry_b)
    service.instance_variable_set(:@crd_manager, manager_b)
    service.instance_variable_set(:@aggregator, API::Aggregator.new)
    service.instance_variable_set(:@logger, Logger.new(nil))
    service.send(:start_dynamic_api_reconciler)

    call = lambda do |method, path, body|
      server_a.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                     body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
    end
    assert_equal 201, call.("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", crd).status
    eventually { registry_b.find_gvr(group: "example.com", version: "v1", resource: "gadgets") }

    assert_equal 200, call.("DELETE", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/gadgets.example.com", {}).status
    eventually { registry_b.find_gvr(group: "example.com", version: "v1", resource: "gadgets").nil? }
  ensure
    service&.instance_variable_set(:@stopping, true)
    service&.instance_variable_get(:@dynamic_api_thread)&.join(2)
  end

  def test_resyncing_an_unchanged_crd_never_unregisters_it
    store = Rubernetes::Storage::MemoryStore.new
    registry, manager, = replica(store)
    manager.sync(crd)
    resource = registry.find_gvr(group: "example.com", version: "v1", resource: "gadgets")
    manager.sync(crd.merge("status" => {"conditions" => []}))
    assert_same resource, registry.find_gvr(group: "example.com", version: "v1", resource: "gadgets")
  end
end
