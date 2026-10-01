# frozen_string_literal: true

# Deprecated API versions (endpoints/deprecation, apiextensions crdHandler,
# v1.36.2): a request to a deprecated built-in kind gets kube-apiserver's
# "<gv> <Kind> is deprecated in vX.Y+, unavailable in vX.Z+; use ..." Warning
# and sets apiserver_requested_deprecated_apis; a deprecated CRD version gets
# its deprecationWarning or "<group>/<version> <Kind> is deprecated".

require_relative "../test_helper"
require_relative "../support/crd_aggregation_harness"

class APIDeprecationWarningTest < Minitest::Test
  include CRDAggregationHarness

  def build_registry
    registry = super
    registry.register(API::Resource.new(group: "storage.k8s.io", version: "v1beta1", resource: "volumeattributesclasses",
                                        kind: "VolumeAttributesClass", scope: :cluster))
    registry.register(API::Resource.new(group: "storage.k8s.io", version: "v1", resource: "volumeattributesclasses",
                                        kind: "VolumeAttributesClass", scope: :cluster))
    registry
  end

  def test_deprecated_builtin_versions_warn_and_count
    # --runtime-config=storage.k8s.io/v1beta1=true: the beta is off by default.
    @server = API::Server.new(registry: @registry, store: @store, crd_manager: @crd_manager, aggregator: @aggregator,
                              openapi_repository: @openapi, runtime_config: {"storage.k8s.io/v1beta1" => "true"})
    response = call("GET", "/apis/storage.k8s.io/v1beta1/volumeattributesclasses")

    assert_equal 200, response.status
    assert_equal '299 - "storage.k8s.io/v1beta1 VolumeAttributesClass is deprecated in v1.34+, unavailable in v1.37+; use storage.k8s.io/v1 ' \
                 'VolumeAttributesClass"',
                 response.header("warning")
    assert_nil call("GET", "/apis/storage.k8s.io/v1/volumeattributesclasses").header("warning")
    text = @server.instance_variable_get(:@metrics).render

    assert_includes text,
                    'apiserver_requested_deprecated_apis{group="storage.k8s.io",removed_release="1.37",resource="volumeattributesclasses",subresource="",' \
                    'version="v1beta1"} 1'
  end

  def test_deprecated_crd_versions_carry_their_warning
    call("POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    definition = crd
    definition["spec"]["versions"].first["storage"] = false
    definition["spec"]["versions"].first["deprecated"] = true
    definition["spec"]["versions"] << {"name" => "v2", "served" => true, "storage" => true, "deprecated" => true, "deprecationWarning" => "v2 is going away",
                                       "schema" => {"openAPIV3Schema" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}}}
    definition["spec"]["versions"] << {"name" => "v3", "served" => true, "storage" => false,
                                       "schema" => {"openAPIV3Schema" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}}}

    assert_equal 201, call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: definition).status
    assert(wait_until { call("GET", "/apis/example.com/v3/namespaces/team/widgets").status == 200 })
    assert_equal '299 - "example.com/v1 Widget is deprecated"',
                 call("GET", "/apis/example.com/v1/namespaces/team/widgets").header("warning")
    assert_equal '299 - "v2 is going away"', call("GET", "/apis/example.com/v2/namespaces/team/widgets").header("warning")
    assert_nil call("GET", "/apis/example.com/v3/namespaces/team/widgets").header("warning")
  end
end
