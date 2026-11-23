# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require_relative "../support/crd_aggregation_harness"
require "rubernetes/api"
require "rubernetes/security/cel"

# CustomResourceDefinitions and API aggregation through the in-process API core.
class APICRDAggregationTest < Minitest::Test
  include CRDAggregationHarness

  def test_definition_cleanup_waits_for_instance_finalizers_and_remains_served_after_restart
    definitions = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"
    definition = "#{definitions}/widgets.example.com"
    widgets = "/apis/example.com/v1/namespaces/default/widgets"
    hold = "example.com/hold"
    object = {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "held", "finalizers" => [hold]}, "spec" => {"size" => 2}}
    headers = {"content-type" => "application/merge-patch+json"}
    descriptor = crd
    descriptor["metadata"]["finalizers"] = [hold]

    assert_equal 201, call("POST", definitions, body: descriptor).status
    assert_equal 201, call("POST", widgets, body: object).status
    assert_equal 201, call("POST", widgets, body: object.merge("metadata" => {"name" => "free"})).status
    assert_equal 200, call("DELETE", "#{definition}?dryRun=All").status
    assert_nil call("GET", "#{widgets}/held").body.dig("metadata", "deletionTimestamp")

    assert_equal 200, call("DELETE", definition).status
    assert(wait_until { call("GET", "#{widgets}/held").body.dig("metadata", "deletionTimestamp") && call("GET", "#{widgets}/free").status == 404 })
    held = call("GET", "#{widgets}/held").body.fetch("metadata")

    assert_equal [hold], held["finalizers"]
    assert_equal 0, held["deletionGracePeriodSeconds"]
    assert_equal 2, held["generation"]

    # Rebuild discovery and the API handler over the same durable objects.
    @registry = build_registry
    @openapi = API::OpenAPIRepository.new
    @crd_manager = API::CRD::Manager.new(registry: @registry, store: @store, openapi: @openapi, cel: Rubernetes::Security::CEL::Evaluator.new)
    @crd_manager.bootstrap!([call("GET", definition).body])
    @server = API::Server.new(registry: @registry, store: @store, crd_manager: @crd_manager, openapi_repository: @openapi)

    assert_equal 200, call("GET", "#{widgets}/held").status
    other = object.merge("metadata" => {"name" => "new"})

    assert_equal 403, call("POST", widgets, body: other).status
    apply_headers = {"content-type" => "application/apply-patch+yaml"}

    assert_equal 403, call("PATCH", "#{widgets}/new?fieldManager=test", body: other, headers: apply_headers).status

    assert_equal 200, call("PATCH", "#{widgets}/held", body: {"metadata" => {"finalizers" => []}}, headers: headers).status
    assert(wait_until { call("GET", definition).body.dig("metadata", "finalizers") == [hold] })
    assert_equal 404, call("GET", "#{widgets}/held").status
    condition = call("GET", definition).body.dig("status", "conditions").find { |item| item["type"] == "Terminating" }

    assert_equal %w[False InstanceDeletionCompleted], condition.values_at("status", "reason")
    assert_equal [hold], call("DELETE", definition).body.dig("metadata", "finalizers")
    assert_equal 200, call("PATCH", definition, body: {"metadata" => {"finalizers" => []}}, headers: headers).status
    wait_for_crd_removal("widgets.example.com")
  end

  def test_custom_writes_require_a_scoped_url_and_a_resource_version_on_replace
    path = "/apis/example.com/v1/namespaces/default/widgets"
    member = "#{path}/one"
    widget = {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "one"}, "spec" => {"size" => 1}}

    assert_equal 201, call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd).status
    assert_equal 404, call("POST", "/apis/example.com/v1/widgets", body: widget).status
    assert_equal 201, call("POST", member, body: widget).status
    named = widget.merge("metadata" => {"name" => "two"})

    assert_equal "two", call("POST", member, body: named).body.dig("metadata", "name")
    assert_equal 422, call("POST", member, body: widget.except("metadata")).status
    replacement = widget.merge("spec" => {"size" => 2})
    refused = call("PUT", member, body: replacement)

    assert_equal 422, refused.status
    assert_equal "metadata.resourceVersion", refused.body.dig("details", "causes", 0, "field")
    current = call("GET", member).body

    assert_equal 1, current.dig("spec", "size")
    assert_equal 200, call("PUT", member, body: current.merge("spec" => {"size" => 2})).status
  end

  def test_crd_lifecycle_serves_validates_defaults_prunes_and_cleans_up
    call("POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    created = call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd)

    assert_equal 201, created.status, created.body.inspect
    stored = call("GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com").body

    assert_equal "True", stored["status"]["conditions"].find { |c| c["type"] == "Established" }["status"]
    assert_equal ["v1"], stored["status"]["storedVersions"]
    groups = call("GET", "/apis").body["groups"].map { |group| group["name"] }

    assert_includes groups, "example.com"
    resources = call("GET", "/apis/example.com/v1").body["resources"].map { |resource| resource["name"] }

    assert_includes resources, "widgets"
    assert_includes resources, "widgets/status"
    openapi = call("GET", "/openapi/v3/apis/example.com/v1").body

    assert openapi["paths"].key?("/apis/example.com/v1/namespaces/{namespace}/widgets")
    assert call("GET", "/openapi/v3").body["paths"].key?("apis/example.com/v1")

    invalid = call("POST", "/apis/example.com/v1/namespaces/team/widgets",
                   body: {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "w1"}, "spec" => {"size" => 0}})

    assert_equal 422, invalid.status
    assert_match(/spec.size/, invalid.body["message"])
    too_big = call("POST", "/apis/example.com/v1/namespaces/team/widgets",
                   body: {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "w1"}, "spec" => {"size" => 8}})

    assert_equal 422, too_big.status
    assert_match(/large widgets must be red/, too_big.body["message"])
    ok = call("POST", "/apis/example.com/v1/namespaces/team/widgets",
              body: {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "w1"},
                     "spec" => {"size" => 3, "junk" => "x", "tags" => ["a"]}, "unknown" => 1})

    assert_equal 201, ok.status, ok.body.inspect
    assert_equal "blue", ok.body.dig("spec", "color"), "defaulting"
    refute ok.body["spec"].key?("junk"), "pruning"
    refute ok.body.key?("unknown")
    assert_equal "team", ok.body.dig("metadata", "namespace")
    listed = call("GET", "/apis/example.com/v1/namespaces/team/widgets").body

    assert_equal "WidgetList", listed["kind"]
    assert_equal 1, listed["items"].length
    status = call("PUT", "/apis/example.com/v1/namespaces/team/widgets/w1/status",
                  body: ok.body.merge("status" => {"ready" => true}, "spec" => {"size" => 9}))

    assert_equal 200, status.status, status.body.inspect
    after = call("GET", "/apis/example.com/v1/namespaces/team/widgets/w1").body

    assert_equal true, after.dig("status", "ready")
    assert_equal 3, after.dig("spec", "size"), "status subresource never changes spec"
    patched = call("PATCH", "/apis/example.com/v1/namespaces/team/widgets/w1", body: {"spec" => {"color" => "red", "size" => 7}},
                                                                               headers: {"content-type" => "application/merge-patch+json"})

    assert_equal 200, patched.status, patched.body.inspect
    deleted = call("DELETE", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com")

    assert_equal 200, deleted.status, deleted.body.inspect
    # apiextensions: the delete marks the CRD terminating with the cleanup
    # finalizer and returns the object; the finalizer controller removes it.
    assert_includes deleted.body.dig("metadata", "finalizers"), "customresourcecleanup.apiextensions.k8s.io"
    assert_equal "Terminating", deleted.body.dig("status", "conditions").last["type"]
    wait_for_crd_removal("widgets.example.com")

    assert_equal 404, call("GET", "/apis/example.com/v1/namespaces/team/widgets/w1").status
    refute_includes call("GET", "/apis").body["groups"].map { |group| group["name"] }, "example.com"
    assert_empty @store.list("registry/example.com/v1/widgets").items, "custom resources are cleaned up with the CRD"
  end

  def test_non_structural_schema_is_rejected_and_multi_version_none_conversion_serves_both
    bad = crd
    bad["spec"]["versions"][0]["schema"] =
      {"openAPIV3Schema" => {"type" => "object", "properties" => {"spec" => {"properties" => {"x" => {}}}}}}
    response = call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: bad)

    assert_equal 201, response.status
    stored = call("GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com").body

    assert_equal "True", stored["status"]["conditions"].find { |c| c["type"] == "NonStructuralSchema" }["status"]
    assert_equal "False", stored["status"]["conditions"].find { |c| c["type"] == "Established" }["status"]
    call("DELETE", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com")
    wait_for_crd_removal("widgets.example.com")

    call("POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    v2 = {"name" => "v2", "served" => true, "storage" => false,
          "schema" => {"openAPIV3Schema" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}}}
    multi = call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd(extra_versions: [v2]))

    assert_equal 201, multi.status, multi.body.inspect
    created = call("POST", "/apis/example.com/v2/namespaces/team/widgets",
                   body: {"apiVersion" => "example.com/v2", "kind" => "Widget", "metadata" => {"name" => "w2"}, "spec" => {"size" => 2}})

    assert_equal 201, created.status, created.body.inspect
    assert_equal "example.com/v2", created.body["apiVersion"]
    via_v1 = call("GET", "/apis/example.com/v1/namespaces/team/widgets/w2").body

    assert_equal "example.com/v1", via_v1["apiVersion"]
    assert_equal 2, via_v1.dig("spec", "size")
    # A custom resource's storage key names no version: etcd holds one object
    # per custom resource whatever version it was written in, and the apiserver
    # converts it on read (apiextensions-apiserver builds its storage prefix
    # from the CRD's group and plural alone).  Keying by the CRD's current
    # storage version made every existing object vanish the moment that version
    # moved.
    stored_key = "registry/example.com/#{Rubernetes::API::Resource::CUSTOM_STORAGE_VERSION}/widgets/team/w2"

    assert_equal "example.com/v1", @store.get(stored_key)["apiVersion"], "written in the storage version"
    assert_empty @store.list("registry/example.com/v1/widgets").items
    assert_empty @store.list("registry/example.com/v2/widgets").items
    versions = call("GET", "/apis/example.com").body["versions"].map { |version| version["version"] }

    assert_equal %w[v1 v2], versions.sort
  end

  def test_aggregated_apiservice_is_proxied_with_identity_headers_and_merged_into_discovery
    apiservice = {"apiVersion" => "apiregistration.k8s.io/v1", "kind" => "APIService", "metadata" => {"name" => "v1beta1.metrics.example"},
                  "spec" => {"group" => "metrics.example", "version" => "v1beta1",
                             "service" => {"namespace" => "kube-system", "name" => "metrics", "port" => 443},
                             "groupPriorityMinimum" => 100, "versionPriority" => 100, "insecureSkipTLSVerify" => true}}
    response = call("POST", "/apis/apiregistration.k8s.io/v1/apiservices", body: apiservice)

    assert_equal 201, response.status, response.body.inspect
    assert_equal({}, response.body["status"])
    # The available controller needs the Service and a ready EndpointSlice
    # before it probes the backend; until then proxying answers 503.
    assert(wait_until { condition_reason(response.body.dig("metadata", "name")) == "ServiceNotFound" })
    assert_equal 503, call("GET", "/apis/metrics.example/v1beta1/nodes").status
    call("POST", "/api/v1/namespaces/kube-system/services",
         body: {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "metrics"},
                "spec" => {"ports" => [{"port" => 443, "targetPort" => 4443}], "selector" => {"app" => "metrics"}}})
    slice = call("POST", "/apis/discovery.k8s.io/v1/namespaces/kube-system/endpointslices",
                 body: {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
                        "metadata" => {"name" => "metrics-1", "labels" => {"kubernetes.io/service-name" => "metrics"}},
                        "addressType" => "IPv4", "ports" => [{"port" => 4443}],
                        "endpoints" => [{"addresses" => ["10.0.0.9"], "conditions" => {"ready" => true}}]})

    assert_equal 201, slice.status, slice.body.inspect
    assert wait_until(seconds: 15) {
      condition_reason("v1beta1.metrics.example") == "Passed"
    }, "availability controller must observe the backend"
    assert_includes call("GET", "/apis").body["groups"].map { |group| group["name"] }, "metrics.example"
    assert_equal "metrics.example", call("GET", "/apis/metrics.example").body["name"]
    list = call("GET", "/apis/metrics.example/v1beta1").body

    assert_equal "NodeMetrics", list["resources"].first["kind"]
    proxied = call("GET", "/apis/metrics.example/v1beta1/nodes", headers: {"authorization" => "Bearer secret"})

    assert_equal 200, proxied.status, proxied.body.inspect
    assert_equal "admin", proxied.body["seenUser"]
    assert_nil proxied.body["authorization"], "the bearer token never reaches the aggregated backend"
    call("DELETE", "/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.example")

    refute_includes call("GET", "/apis").body["groups"].map { |group| group["name"] }, "metrics.example"
  end
end
