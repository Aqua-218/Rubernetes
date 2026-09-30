# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/bootstrap"

# pkg/registry/apps/statefulset/strategy.go dropStatefulSetDisabledFields
# (v1.36.2): MaxUnavailableStatefulSet is Beta and off, so a new
# rollingUpdate.maxUnavailable is dropped -- on create, and on an update of a
# StatefulSet that did not use it already.
class StatefulSetDisabledFieldsTest < Minitest::Test
  PATH = "/apis/apps/v1/namespaces/ns/statefulsets"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    now = Time.utc(2026)
    @server = Rubernetes::API::Server.new(registry: registry, store: Rubernetes::API::MemoryStore.new(clock: -> { now }), clock: -> { now },
                                          openapi_repository: Rubernetes::API::OpenAPIRepository.new)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})
  end

  def call(method, path, body)
    response = @server.call(Rubernetes::API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                                         body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
    body = response.body
    [response.status, body.is_a?(Hash) ? Marshal.load(Marshal.dump(body)) : JSON.parse(Array(body).join)]
  end

  def stateful_set(rolling)
    {"apiVersion" => "apps/v1", "kind" => "StatefulSet", "metadata" => {"name" => "s"},
     "spec" => {"serviceName" => "s", "selector" => {"matchLabels" => {"a" => "b"}},
                "template" => {"metadata" => {"labels" => {"a" => "b"}}, "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}},
                "updateStrategy" => {"type" => "RollingUpdate", "rollingUpdate" => rolling}}}
  end

  def test_max_unavailable_is_dropped_on_create_and_update
    status, created = call("POST", PATH, stateful_set({"maxUnavailable" => 2}))

    assert_equal 201, status
    refute created.dig("spec", "updateStrategy", "rollingUpdate").key?("maxUnavailable")
    updated = created.merge("spec" => created["spec"].merge("updateStrategy" => {"type" => "RollingUpdate",
                                                                                 "rollingUpdate" => {"maxUnavailable" => 3,
                                                                                                     "partition" => 0}}))
    status, body = call("PUT", "#{PATH}/s", updated)

    assert_equal 200, status
    refute body.dig("spec", "updateStrategy", "rollingUpdate").key?("maxUnavailable")
  end
end
