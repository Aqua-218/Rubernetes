# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"

# A CRD whose OpenAPI schema describes a Pod-shaped resource lists property
# NAMES such as exec/httpGet/tcpSocket/sleep under a `postStart.properties`
# map and a `restartPolicy` property with its own enum.  The Pod-template
# walkers (probe handlers, Job restart policy, container enums) read those
# maps as objects and refused Argo Workflows' CRDs with "may not specify
# more than 1 handler type" and "valid values: OnFailure, Never".  Upstream
# apiextensions validates the schema structurally only.
class CRDPodShapedSchemaTest < Minitest::Test
  def definition = Rubernetes::Generated.definition_for("io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition")

  HANDLER = {"type" => "object", "properties" => {
    "exec" => {"type" => "object", "properties" => {"command" => {"type" => "array", "items" => {"type" => "string"}}}},
    "httpGet" => {"type" => "object", "properties" => {"port" => {"x-kubernetes-int-or-string" => true}}},
    "tcpSocket" => {"type" => "object", "properties" => {"port" => {"x-kubernetes-int-or-string" => true}}},
    "sleep" => {"type" => "object", "properties" => {"seconds" => {"type" => "integer"}}}
  }}.freeze

  CONTAINER = {"type" => "object", "properties" => {
    "name" => {"type" => "string"},
    "image" => {"type" => "string"},
    "restartPolicy" => {"type" => "string", "enum" => %w[Always]},
    "imagePullPolicy" => {"type" => "string"},
    "lifecycle" => {"type" => "object", "properties" => {"postStart" => HANDLER, "preStop" => HANDLER}},
    "livenessProbe" => HANDLER.merge("properties" => HANDLER["properties"].merge("grpc" => {"type" => "object"})),
    "resources" => {"type" => "object", "properties" => {"limits" => {"type" => "object", "additionalProperties" => {"type" => "string"}}}}
  }}.freeze

  def crd
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
     "metadata" => {"name" => "workflowtasksets.argoproj.io"},
     "spec" => {"group" => "argoproj.io", "scope" => "Namespaced",
                "names" => {"plural" => "workflowtasksets", "singular" => "workflowtaskset", "kind" => "WorkflowTaskSet", "listKind" => "WorkflowTaskSetList"},
                "versions" => [{"name" => "v1alpha1", "served" => true, "storage" => true,
                                "schema" => {"openAPIV3Schema" => {"type" => "object", "properties" => {
                                  "spec" => {"type" => "object", "properties" => {
                                    "restartPolicy" => {"type" => "string", "enum" => %w[Always OnFailure Never]},
                                    "tasks" => {"type" => "object", "additionalProperties" => {"type" => "object", "properties" => {
                                      "container" => CONTAINER,
                                      "sidecars" => {"type" => "array", "items" => CONTAINER},
                                      "selector" => {"type" => "object", "properties" => {"matchLabels" => {"type" => "object"}}}
                                    }}}
                                  }},
                                  "status" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}
                                }}}}]}}
  end

  def test_pod_shaped_crd_schema_is_accepted
    errors = definition.validator.errors(crd, operation: :create).map(&:to_s)

    assert_empty errors
  end

  def test_crd_rules_outside_the_schema_still_apply
    bad = crd
    bad["spec"]["scope"] = "Bogus"
    errors = definition.validator.errors(bad, operation: :create).map(&:to_s)

    assert errors.any? { |error| error.include?("spec.scope") }, errors.inspect
  end

  def test_a_real_pod_still_reports_several_probe_handlers
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "default"},
           "spec" => {"containers" => [{"name" => "c", "image" => "busybox",
                                        "livenessProbe" => {"exec" => {"command" => ["true"]}, "httpGet" => {"port" => 80}}}]}}
    errors = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod").validator.errors(pod, operation: :create).map(&:to_s)

    assert errors.any? { |error| error.include?("may not specify more than 1 handler type") }, errors.inspect
  end
end
