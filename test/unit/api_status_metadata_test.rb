# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class APIStatusMetadataTest < Minitest::Test
  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry)
  end

  def test_pod_status_can_set_labels_and_finalizers_but_retains_owners
    owner = {"apiVersion" => "v1", "kind" => "ConfigMap", "name" => "old", "uid" => "df213df9-abca-4745-b600-a2da674d7640"}
    collection = "/api/v1/namespaces/default/pods"
    create(collection, "v1", "Pod", {"containers" => [{"name" => "app", "image" => "worker"}]}, "ownerReferences" => [owner])
    fields = {"labels" => {"source" => "agent"}, "finalizers" => ["example.test/new"], "ownerReferences" => nil}
    result = patch(collection, fields)

    assert_equal fields["labels"], result["labels"]
    assert_equal fields["finalizers"], result["finalizers"]
    assert_equal [owner], result["ownerReferences"]
  end

  def test_deployment_status_put_keeps_labels_and_removes_omitted_annotations
    collection = "/apis/apps/v1/namespaces/default/deployments"
    labels = {"app" => "worker"}
    template = {"metadata" => {"labels" => labels}, "spec" => {"containers" => [{"name" => "app", "image" => "worker"}]}}
    deployed = create(collection, "apps/v1", "Deployment", {"selector" => {"matchLabels" => labels}, "template" => template},
                      "labels" => labels, "annotations" => {"source" => "old"})
    updated = deployed.merge("metadata" => deployed.fetch("metadata").except("labels", "annotations"))
    response = @server.call(method: "PUT", path: "#{collection}/sample/status", body: updated)

    assert_equal 200, response.status
    assert_equal labels, response.body.dig("metadata", "labels")
    refute response.body.fetch("metadata").key?("annotations")
  end

  def test_flow_schema_status_patch_retains_metadata
    collection = "/apis/flowcontrol.apiserver.k8s.io/v1/flowschemas"
    initial = {"labels" => {"source" => "old"}, "annotations" => {"origin" => "old"}}
    create(collection, "flowcontrol.apiserver.k8s.io/v1", "FlowSchema", {"priorityLevelConfiguration" => {"name" => "catch-all"}}, initial)
    meta = patch(collection, {"labels" => nil, "annotations" => {"origin" => "new"}})

    assert_equal initial, meta.slice(*initial.keys)
  end

  private

  def create(collection, version, kind, spec, metadata)
    object = {"apiVersion" => version, "kind" => kind, "metadata" => metadata.merge("name" => "sample"), "spec" => spec}
    response = @server.call(method: "POST", path: collection, body: object)

    assert_equal 201, response.status, response.body.inspect
    response.body
  end

  def patch(collection, fields)
    response = @server.call(method: "PATCH", path: "#{collection}/sample/status", body: {"metadata" => fields},
                            headers: {"content-type" => "application/merge-patch+json"})

    assert_equal 200, response.status, response.body.inspect
    response.body.fetch("metadata")
  end
end
