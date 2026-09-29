# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"

# A ManagedFieldsEntry is keyed by (manager, operation, subresource) upstream.
# Ours once ignored the subresource, so one manager's ownership set was shared
# between the main resource and /status.  A controller that applies both --
# every workload controller does -- then had its status apply, whose object is
# metadata identity plus status, read as "this manager no longer applies any of
# those fields": applying status DELETED the annotations and labels the very
# same manager had applied moments earlier.  Reproduced live on 2026-09-15,
# where the deployment controller's revision annotation vanished from every
# Deployment and conformance reported "doesn't have the required revision set".
# Exercised through the API server's structured-merge-diff field manager.
class ManagedFieldsSubresourceTest < Minitest::Test
  API = Rubernetes::API
  PATH = "/apis/apps/v1/namespaces/ns/deployments/d"

  def setup
    @now = Time.utc(2026, 1, 1)
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new(clock: -> { @now }), clock: -> { @now },
                              openapi_repository: API::OpenAPIRepository.new)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})
  end

  def call(method, path, body = nil, content_type: "application/json")
    headers = body ? {"content-type" => content_type} : {}
    response = @server.call(API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body),
                                             identity: {"username" => "admin", "groups" => ["system:masters"]}))
    body = response.body
    body = body.is_a?(Hash) ? Marshal.load(Marshal.dump(body)) : JSON.parse(Array(body).join)
    [response.status, body]
  end

  def apply(object, manager:, subresource: nil)
    path = subresource ? "#{PATH}/#{subresource}" : PATH
    status, body = call("PATCH", "#{path}?fieldManager=#{manager}&force=true", object, content_type: "application/apply-patch+yaml")
    assert_includes [200, 201], status, body.inspect
    body
  end

  def deployment(annotations: {})
    {"apiVersion" => "apps/v1", "kind" => "Deployment",
     "metadata" => {"name" => "d", "namespace" => "ns", "annotations" => annotations},
     "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "d"}},
                "template" => {"metadata" => {"labels" => {"app" => "d"}}, "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}}}}
  end

  def status(fields)
    {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "d", "namespace" => "ns"}, "status" => fields}
  end

  def entries(object)
    object.dig("metadata", "managedFields").map { |entry| [entry["manager"], entry["operation"], entry["subresource"]] }
  end

  def test_a_status_apply_keeps_the_same_managers_main_resource_fields
    apply(deployment(annotations: {"deployment.kubernetes.io/revision" => "1"}), manager: "controller-manager")
    after = apply(status({"replicas" => 1}), manager: "controller-manager", subresource: "status")

    assert_equal("1", after.dig("metadata", "annotations", "deployment.kubernetes.io/revision"))
    assert_equal(1, after.dig("status", "replicas"))
    assert_includes(entries(after), ["controller-manager", "Apply", "status"])
    assert_includes(entries(after), ["controller-manager", "Apply", nil])
  end

  def test_the_main_resource_apply_still_releases_fields_it_stops_applying
    apply(deployment(annotations: {"a" => "1", "b" => "2"}), manager: "controller-manager")
    after = apply(deployment(annotations: {"a" => "1"}), manager: "controller-manager")

    assert_equal({"a" => "1"}, after.dig("metadata", "annotations"))
  end

  def test_a_status_apply_releases_only_status_fields
    apply(deployment(annotations: {"kept" => "yes"}), manager: "owner")
    apply(status({"replicas" => 1, "readyReplicas" => 1}), manager: "controller-manager", subresource: "status")
    after = apply(status({"replicas" => 1}), manager: "controller-manager", subresource: "status")

    assert_equal({"kept" => "yes"}, after.dig("metadata", "annotations"))
    refute(after.fetch("status").key?("readyReplicas"))
  end

  # Two managers applying to different subresources own their fields
  # independently; neither entry is dropped when the other writes.
  def test_entries_for_other_subresources_survive
    apply(deployment(annotations: {"a" => "1"}), manager: "one")
    after = apply(status({"replicas" => 2}), manager: "two", subresource: "status")

    assert_includes(entries(after), ["one", "Apply", nil])
    assert_includes(entries(after), ["two", "Apply", "status"])
  end
end
