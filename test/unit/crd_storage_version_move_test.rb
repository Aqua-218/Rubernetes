# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# A custom resource's storage key names no version.  etcd holds one object per
# custom resource at /registry/<group>/<plural>/<namespace>/<name> whatever
# version it was written in (apiextensions-apiserver builds its storage prefix
# from the CRD's group and plural alone), and the apiserver converts whatever
# it finds there to the version the client asked for -- existing objects are
# never rewritten when a CRD's storage version moves.
#
# Keying storage by the CRD's CURRENT storage version instead made every
# existing object vanish the moment that version moved, which is exactly what
# "[sig-api-machinery] CustomResourceConversionWebhook should be able to
# convert a non homogeneous list of CRs" does: it creates one object, patches
# the CRD's storage version from v1 to v2, creates a second object, and then
# lists both.  The list came back with one.
class CRDStorageVersionMoveTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @registry = API::Registry.new(resources: [], defaults: false)
    @registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1",
                                         resource: "customresourcedefinitions", kind: "CustomResourceDefinition",
                                         scope: :cluster,
                                         subresources: [{resource: "status", verbs: %w[get patch update]}]))
    @registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace",
                                         scope: :cluster))
    @openapi = API::OpenAPIRepository.new
    @crd_manager = API::CRD::Manager.new(registry: @registry, store: @store, openapi: @openapi)
    @server = API::Server.new(registry: @registry, store: @store, crd_manager: @crd_manager,
                              openapi_repository: @openapi)
    call("POST", "/api/v1/namespaces",
         body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
  end

  def call(method, path, body: nil, headers: {})
    headers = {"content-type" => "application/json"}.merge(headers) if body
    @server.call(API::Request.new(method: method, path: path, headers: headers,
                                  body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def open_schema
    {"openAPIV3Schema" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}}
  end

  def crd(storage:)
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
     "metadata" => {"name" => "widgets.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget",
                            "listKind" => "WidgetList"},
                "versions" => %w[v1 v2].map do |name|
                  {"name" => name, "served" => true, "storage" => name == storage, "schema" => open_schema}
                end}}
  end

  def wait_until(seconds: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      return true if yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.05
    end
  end

  def create_widget(version, name)
    response = call("POST", "/apis/example.com/#{version}/namespaces/team/widgets",
                    body: {"apiVersion" => "example.com/#{version}", "kind" => "Widget",
                           "metadata" => {"name" => name}, "hostPort" => "localhost:8080"})

    assert_equal(201, response.status, response.body.inspect)
    response.body
  end

  def list_names(version)
    response = call("GET", "/apis/example.com/#{version}/namespaces/team/widgets")

    assert_equal(200, response.status, response.body.inspect)
    response.body.fetch("items").map { |item| item.dig("metadata", "name") }.sort
  end

  def establish!(storage:)
    response = call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd(storage: storage))

    assert_includes([201, 409], response.status, response.body.inspect)
    assert(wait_until { call("GET", "/apis/example.com/v1/namespaces/team/widgets").status == 200 })
  end

  def move_storage_to_v2!
    current = call("GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com").body
    response = call("PUT", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com",
                    body: crd(storage: "v2").merge("metadata" => current.fetch("metadata")))

    assert_equal(200, response.status, response.body.inspect)
  end

  def test_an_object_survives_a_storage_version_move
    establish!(storage: "v1")
    create_widget("v1", "before")
    move_storage_to_v2!
    create_widget("v2", "after")

    assert_equal(%w[after before], list_names("v1"))
    assert_equal(%w[after before], list_names("v2"))
  end

  # Both versions are served from one stored object, so a get in either version
  # finds it whichever version it was written in.
  def test_either_version_reads_the_same_object
    establish!(storage: "v1")
    create_widget("v1", "before")
    move_storage_to_v2!

    %w[v1 v2].each do |version|
      response = call("GET", "/apis/example.com/#{version}/namespaces/team/widgets/before")

      assert_equal(200, response.status, response.body.inspect)
      assert_equal("example.com/#{version}", response.body.fetch("apiVersion"))
    end
  end

  def test_the_storage_key_names_no_version
    establish!(storage: "v1")
    create_widget("v1", "before")

    stored = @store.get("registry/example.com/#{API::Resource::CUSTOM_STORAGE_VERSION}/widgets/team/before")

    assert_equal("example.com/v1", stored.fetch("apiVersion"), "written in the storage version")
    assert_empty(@store.list("registry/example.com/v1/widgets").items)
  end
end
