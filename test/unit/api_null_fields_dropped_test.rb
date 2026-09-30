# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/crd_aggregation_harness"

# A JSON null for a map, list or pointer field of a built-in type decodes to
# "absent" in kube-apiserver and is never served back ("annotations": null is
# not on the wire).  We stored and served such nulls verbatim: a Helm chart's
# `annotations: null` in a Job template reached every Pod the Job created and
# crashed the node's admission check.
class APINullFieldsDroppedTest < Minitest::Test
  include CRDAggregationHarness

  def test_null_metadata_maps_and_spec_fields_of_builtins_are_dropped
    body = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "nulls", "namespace" => "default", "annotations" => nil, "labels" => nil},
            "spec" => {"selector" => nil, "ports" => [{"port" => 80}]}}
    response = call("POST", "/api/v1/namespaces/default/services", body: body)

    assert_equal 201, response.status, response.body.inspect
    stored = call("GET", "/api/v1/namespaces/default/services/nulls").body

    refute stored["metadata"].key?("annotations"), stored["metadata"].inspect
    refute stored["metadata"].key?("labels"), stored["metadata"].inspect
    refute stored["spec"].key?("selector"), stored["spec"].inspect
    assert_equal 80, stored.dig("spec", "ports", 0, "port")
  end

  def test_a_custom_resource_keeps_its_own_null_handling
    crd_body = crd(name: "widgets.example.com")

    assert_equal 201, call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd_body).status
    assert(wait_until { call("GET", "/apis/example.com/v1/namespaces/default/widgets").status == 200 })
    widget = {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "w", "namespace" => "default", "annotations" => nil},
              "spec" => {"size" => 3}}
    response = call("POST", "/apis/example.com/v1/namespaces/default/widgets", body: widget)

    assert_equal 201, response.status, response.body.inspect
    refute response.body["metadata"].key?("annotations"), "metadata is typed for every kind"
  end
end
