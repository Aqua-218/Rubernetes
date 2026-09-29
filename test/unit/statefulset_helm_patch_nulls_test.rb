# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/bootstrap"

# `helm upgrade` re-sends a StatefulSet whose volumeClaimTemplates carry
# `annotations: null` / `selector: null` and no defaulted volumeMode.  The
# strategic patch replaces that list verbatim; the nulls have to vanish (the
# typed decode upstream) and the defaults apply before
# ValidateStatefulSetUpdate compares it with the stored template -- or every
# upgrade of a chart with a StatefulSet is Forbidden (GitLab's gitaly was).
class StatefulSetHelmPatchNullsTest < Minitest::Test
  PATH = "/apis/apps/v1/namespaces/ns/statefulsets"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    now = Time.utc(2026)
    @server = Rubernetes::API::Server.new(registry: registry, store: Rubernetes::API::MemoryStore.new(clock: -> { now }), clock: -> { now },
                                          openapi_repository: Rubernetes::API::OpenAPIRepository.new)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})
  end

  def call(method, path, body, content_type: "application/json")
    response = @server.call(Rubernetes::API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                                         body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
    body = response.body
    [response.status, body.is_a?(Hash) ? Marshal.load(Marshal.dump(body)) : JSON.parse(Array(body).join)]
  end

  def test_a_strategic_patch_with_null_fields_does_not_change_immutable_fields
    claim = {"metadata" => {"name" => "data", "labels" => {"app" => "db"}},
             "spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}}}
    body = {"apiVersion" => "apps/v1", "kind" => "StatefulSet", "metadata" => {"name" => "db"},
            "spec" => {"serviceName" => "db", "selector" => {"matchLabels" => {"app" => "db"}},
                       "template" => {"metadata" => {"labels" => {"app" => "db"}},
                                      "spec" => {"containers" => [{"name" => "db", "image" => "db:1"}]}},
                       "volumeClaimTemplates" => [claim]}}
    status, created = call("POST", PATH, body)
    assert_equal 201, status, created.inspect
    assert_equal "Filesystem", created.dig("spec", "volumeClaimTemplates", 0, "spec", "volumeMode"), "defaulted on create"

    rendered = {"metadata" => {"name" => "data", "labels" => {"app" => "db"}, "annotations" => nil},
                "spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}, "selector" => nil}}
    patch = {"spec" => {"volumeClaimTemplates" => [rendered],
                        "template" => {"spec" => {"containers" => [{"name" => "db", "image" => "db:2"}]}}}}
    status, patched = call("PATCH", "#{PATH}/db", patch, content_type: "application/strategic-merge-patch+json")
    assert_equal 200, status, patched.inspect
    assert_equal "db:2", patched.dig("spec", "template", "spec", "containers", 0, "image")
    template = patched.dig("spec", "volumeClaimTemplates", 0)
    refute template["metadata"].key?("annotations"), template.inspect
    refute template["spec"].key?("selector"), template.inspect
    assert_equal "Filesystem", template.dig("spec", "volumeMode")

    # A real change to the template is still refused.
    changed = {"spec" => {"volumeClaimTemplates" => [rendered.merge("spec" => rendered["spec"].merge("resources" => {"requests" => {"storage" => "2Gi"}}))]}}
    status, refused = call("PATCH", "#{PATH}/db", changed, content_type: "application/strategic-merge-patch+json")
    assert_equal 422, status, refused.inspect
    assert_match(/fields other than/, refused["message"].to_s)
  end
end
