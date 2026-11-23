# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/crd_aggregation_harness"

class CRDStatusStrategyTest < Minitest::Test
  include CRDAggregationHarness

  ITEMS = "/apis/example.com/v1/namespaces/team/tasks"
  TASK = {"apiVersion" => "example.com/v1", "kind" => "Task", "metadata" => {"name" => "demo"},
          "status" => {"phase" => "New"}}.freeze

  def test_update_and_patch_restore_the_creation_time_after_mutating_admission
    register_crd(status_subresource: false)
    created = call("POST", ITEMS, body: TASK).body
    timestamp = created.dig("metadata", "creationTimestamp")
    mutate = lambda do |request, _route, _operation, object, *_args, **_options|
      metadata = object.fetch("metadata").merge("creationTimestamp" => "2001-01-01T00:00:00Z",
                                                "labels" => {"method" => request.method})
      object.merge("metadata" => metadata)
    end
    @server.stub(:admit_mutating, mutate) do
      replaced = call("PUT", "#{ITEMS}/demo", body: created)
      patched = call("PATCH", "#{ITEMS}/demo", body: {}, headers: {"content-type" => "application/merge-patch+json"})

      [replaced, patched].zip(%w[PUT PATCH]).each do |response, method|
        assert_equal 200, response.status, response.body.inspect
        assert_equal timestamp, response.body.dig("metadata", "creationTimestamp")
        assert_equal method, response.body.dig("metadata", "labels", "method")
      end
    end
  end

  def test_writes_on_the_main_resource_can_change_status_without_a_status_subresource
    register_crd(status_subresource: false)
    created = call("POST", ITEMS, body: TASK)

    assert_equal(201, created.status)
    assert_equal("New", created.body.dig("status", "phase"))

    queued = change_status("#{ITEMS}/demo", "Queued")

    assert_equal(200, queued.status)
    assert_equal("Queued", queued.body.dig("status", "phase"))
    assert_equal(2, queued.body.dig("metadata", "generation"))

    finished = call("PUT", "#{ITEMS}/demo", body: queued.body.merge("status" => {"phase" => "Completed"}))

    assert_equal(200, finished.status)
    assert_equal("Completed", finished.body.dig("status", "phase"))
    assert_equal(3, finished.body.dig("metadata", "generation"))
  end

  def test_status_subresource_excludes_status_from_main_resource_writes
    register_crd(status_subresource: true)
    created = call("POST", ITEMS, body: TASK)

    assert_equal(201, created.status)
    refute(created.body.key?("status"))
    refute(change_status("#{ITEMS}/demo", "Incorrect").body.key?("status"))

    queued = change_status("#{ITEMS}/demo/status", "Queued")

    assert_equal(200, queued.status)
    assert_equal("Queued", queued.body.dig("status", "phase"))
    assert_equal("Queued", change_status("#{ITEMS}/demo", "Incorrect").body.dig("status", "phase"))
    assert_equal(1, queued.body.dig("metadata", "generation"))
  end

  def test_status_copies_only_the_custom_status_and_rejects_strategic_merge
    register_crd(status_subresource: true)
    created = call("POST", ITEMS, body: TASK)
    path = "#{ITEMS}/demo/status"
    patch = {"metadata" => {"uid" => "stale", "labels" => {"changed" => "yes"}}, "status" => {"phase" => "Ready"}}
    updated = call("PATCH", path, body: patch, headers: {"content-type" => "application/merge-patch+json"})

    assert_equal 200, updated.status
    assert_equal "Ready", updated.body.dig("status", "phase")
    assert_equal created.body.dig("metadata", "uid"), updated.body.dig("metadata", "uid")
    refute updated.body.fetch("metadata").key?("labels")

    [path, "#{ITEMS}/demo"].each do |member|
      rejected = call("PATCH", member, body: {}, headers: {"content-type" => "application/strategic-merge-patch+json"})

      assert_equal 415, rejected.status
      refute_includes rejected.body.fetch("message"), "strategic-merge-patch"
    end
    cleared = call("PATCH", path, body: {"status" => nil}, headers: {"content-type" => "application/merge-patch+json"})

    assert_equal 200, cleared.status
    refute cleared.body.key?("status")
  end

  private

  def register_crd(status_subresource:)
    call("POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    schema = {"type" => "object", "properties" => {"status" => {"type" => "object", "properties" => {"phase" => {"type" => "string"}}}}}
    version = {"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema}}
    version["subresources"] = {"status" => {}} if status_subresource
    crd = {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "tasks.example.com"},
           "spec" => {"group" => "example.com", "scope" => "Namespaced", "versions" => [version],
                      "names" => {"plural" => "tasks", "singular" => "task", "kind" => "Task"}}}

    assert_equal(201, call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd).status)
    assert(wait_until { call("GET", ITEMS).status == 200 })
  end

  def change_status(path, phase)
    call("PATCH", path, body: {"status" => {"phase" => phase}}, headers: {"content-type" => "application/merge-patch+json"})
  end
end
