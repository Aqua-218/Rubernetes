# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# ?dryRun=All runs admission and validation and returns the object that WOULD
# have been stored, without storing it.  Not honouring it made
# "[sig-cli] Kubectl client Kubectl server-side dry-run" write the object for
# real, which is the opposite of what the verb means.
class APIDryRunTest < Minitest::Test
  Server = Rubernetes::API::Server

  def request(values)
    Rubernetes::API::Request.new(method: "POST", path: "/api/v1/namespaces/ns/configmaps", query: values)
  end

  def server
    server = Server.allocate
    server.instance_variable_set(:@clock, -> { Time.at(0).utc })
    server.instance_variable_set(:@uid_generator, -> { "uid-fixed" })
    server
  end

  def test_delete_collection_previews_selected_objects_and_checks_preconditions
    api = Server.new
    path = "/api/v1/namespaces/dev/configmaps"
    call = ->(method, url, body = nil) { api.call(Rubernetes::API::Request.new(method: method, path: url, body: body)) }
    object = {"metadata" => {"name" => "first", "labels" => {"group" => "preview"}}}
    created = call.call("POST", path, object)
    selector = "#{path}?labelSelector=group%3Dpreview"
    options = {"apiVersion" => "v1", "kind" => "DeleteOptions", "dryRun" => ["All"]}

    assert_equal 201, created.status
    assert_equal 409, call.call("POST", "#{path}?dryRun=All", object).status
    assert_equal 422, call.call("DELETE", selector, options.merge("dryRun" => ["other"])).status
    assert_equal 400, call.call("DELETE", selector, "{").status
    assert_equal 400, call.call("DELETE", selector, {"preconditions" => []}).status
    assert_equal 409, call.call("DELETE", selector, options.merge("preconditions" => {"uid" => "another-uid"})).status

    list = call.call("DELETE", selector, options)

    assert_equal 200, list.status
    assert_equal "ConfigMapList", list.body["kind"]
    assert_equal([created.body["metadata"]], list.body["items"].map { |item| item["metadata"] })
    assert_equal created.body, call.call("GET", "#{path}/first").body
    assert_equal 200, call.call("DELETE", selector).status
    assert_equal 404, call.call("GET", "#{path}/first").status
  end

  def test_dry_run_delete_with_a_finalizer_only_marks_the_preview
    api = Server.new
    path = "/api/v1/namespaces/dev/configmaps"
    object = {"metadata" => {"name" => "protected", "finalizers" => ["example.com/cleanup"]}}
    original = api.call(Rubernetes::API::Request.new(method: "POST", path: path, body: object))
    preview = api.call(Rubernetes::API::Request.new(method: "DELETE", path: "#{path}/protected?dryRun=All"))
    stored = api.call(Rubernetes::API::Request.new(method: "GET", path: "#{path}/protected"))

    assert_equal 200, preview.status
    refute_nil preview.body.dig("metadata", "deletionTimestamp")
    assert_equal 0, preview.body.dig("metadata", "deletionGracePeriodSeconds")
    assert_equal original.body, stored.body
  end

  def test_mistyped_delete_options_cannot_remove_the_object
    api = Server.new
    path = "/api/v1/namespaces/dev/configmaps"
    member = "#{path}/protected"
    created = api.call(method: "POST", path: path, body: {"metadata" => {"name" => "protected"}})

    [member, path].each do |target|
      unsupported = api.call(method: "DELETE", path: target, headers: {"Content-Type" => "text/plain"}, body: "{}")
      invalid = api.call(method: "DELETE", path: target, body: {"apiVersion" => 7, "kind" => "DeleteOptions"})

      assert_equal 415, unsupported.status
      assert_equal 400, invalid.status
    end
    assert_equal created.body, api.call(method: "GET", path: member).body
  end

  def test_dry_run_all_is_recognised
    assert server.send(:dry_run?, request("dryRun" => ["All"]))
  end

  def test_no_dry_run_parameter_is_not_a_dry_run
    refute server.send(:dry_run?, request({}))
    refute server.send(:dry_run?, request("dryRun" => []))
  end

  def test_an_unknown_dry_run_value_is_not_all
    refute server.send(:dry_run?, request("dryRun" => ["true"]))
    refute server.send(:dry_run?, request("dryRun" => [""]))
  end

  def test_the_preview_fills_in_what_the_server_owns
    object = {"apiVersion" => "v1", "kind" => "ConfigMap",
              "metadata" => {"name" => "c"}, "data" => {"k" => "v"}}
    preview = server.send(:dry_run_view, object, "ns")

    refute preview.fetch("metadata").key?("resourceVersion")
    assert_equal({"name" => "c"}, object.fetch("metadata"))
    assert_equal "ns", preview.dig("metadata", "namespace")
    assert_equal "uid-fixed", preview.dig("metadata", "uid")
    refute_nil preview.dig("metadata", "creationTimestamp")
    assert_equal({"k" => "v"}, preview["data"])
  end

  def test_the_preview_does_not_overwrite_what_the_client_set
    object = {"apiVersion" => "v1", "kind" => "ConfigMap",
              "metadata" => {"name" => "c", "namespace" => "other", "uid" => "client-uid", "resourceVersion" => "14"}}
    preview = server.send(:dry_run_view, object, "ns")

    assert_equal "other", preview.dig("metadata", "namespace")
    assert_equal "14", preview.dig("metadata", "resourceVersion")
    assert_equal "client-uid", preview.dig("metadata", "uid")
  end

  def test_a_cluster_scoped_preview_gets_no_namespace
    preview = server.send(:dry_run_view, {"metadata" => {"name" => "n"}}, :cluster)

    assert_nil preview.dig("metadata", "namespace")
  end
end
