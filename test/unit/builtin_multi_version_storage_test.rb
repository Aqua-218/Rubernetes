# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# A built-in resource served in several versions is one stored object.  Each
# version had its own storage, so an HPA created through autoscaling/v2 was
# absent from autoscaling/v1 (kubectl autoscale writes v2; older clients read
# v1), and a DRA driver on resource.k8s.io/v1beta1 saw no v1 slices.
class BuiltinMultiVersionStorageTest < Minitest::Test
  API = Rubernetes::API

  def setup
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    {"autoscaling" => [%w[v1 v2], "horizontalpodautoscalers", "HorizontalPodAutoscaler", :namespaced],
     "resource.k8s.io" => [%w[v1 v1beta1], "resourceslices", "ResourceSlice", :cluster]}.each do |group, (versions, resource, kind, scope)|
      storage = API::BuiltinConversion.storage_version(group, resource, versions, default_served: lambda { |version|
        (version.start_with?("v1") && !version.include?("beta")) || version == "v2"
      })
      converter = API::BuiltinConversion::Converter.new(group: group, resource: resource)
      versions.each do |version|
        registry.register(API::Resource.new(group: group, version: version, resource: resource, kind: kind, scope: scope,
                                            storage_version: storage, converter: converter))
      end
    end
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, namespace_lifecycle: true,
                              runtime_config: {"resource.k8s.io/v1beta1" => "true"})
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
  end

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, body: body))
  end

  def test_storage_version_prefers_a_default_served_version
    assert_equal "v2", API::BuiltinConversion.storage_version("autoscaling", "horizontalpodautoscalers", %w[v1 v2])
    assert_equal "v1", API::BuiltinConversion.storage_version("admissionregistration.k8s.io", "mutatingadmissionpolicies",
                                                              %w[v1 v1alpha1 v1beta1], default_served: ->(version) { version == "v1" })
    assert_equal "v1beta1", API::BuiltinConversion.storage_version("admissionregistration.k8s.io", "mutatingadmissionpolicies",
                                                                   %w[v1 v1alpha1 v1beta1])
  end

  def test_an_hpa_written_in_v2_is_read_in_v1_and_back
    created = call("POST", "/apis/autoscaling/v2/namespaces/dev/horizontalpodautoscalers",
                   {"apiVersion" => "autoscaling/v2", "kind" => "HorizontalPodAutoscaler", "metadata" => {"name" => "web"},
                    "spec" => {"scaleTargetRef" => {"kind" => "Deployment", "name" => "web", "apiVersion" => "apps/v1"}, "minReplicas" => 1,
                               "maxReplicas" => 5,
                               "metrics" => [{"type" => "Resource", "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => 70}}},
                                             {"type" => "Pods",
                                              "pods" => {"metric" => {"name" => "qps"},
                                                         "target" => {"type" => "AverageValue", "averageValue" => "10"}}}]}})

    assert_equal 201, created.status, created.body.inspect

    v1 = call("GET", "/apis/autoscaling/v1/namespaces/dev/horizontalpodautoscalers/web")

    assert_equal 200, v1.status, v1.body.inspect
    assert_equal "autoscaling/v1", v1.body["apiVersion"]
    assert_equal 70, v1.body.dig("spec", "targetCPUUtilizationPercentage")
    others = JSON.parse(v1.body.dig("metadata", "annotations", "autoscaling.alpha.kubernetes.io/metrics"))

    assert_equal [{"type" => "Pods", "pods" => {"metricName" => "qps", "targetAverageValue" => "10"}}], others

    listed = call("GET", "/apis/autoscaling/v1/namespaces/dev/horizontalpodautoscalers")

    assert_equal(["web"], listed.body["items"].map { |item| item.dig("metadata", "name") })

    # A v1 update keeps the v2-only metric (it rides in the annotation).
    v1_object = v1.body.merge("spec" => v1.body["spec"].merge("maxReplicas" => 7))
    updated = call("PUT", "/apis/autoscaling/v1/namespaces/dev/horizontalpodautoscalers/web", v1_object)

    assert_equal 200, updated.status, updated.body.inspect
    v2 = call("GET", "/apis/autoscaling/v2/namespaces/dev/horizontalpodautoscalers/web").body

    assert_equal 7, v2.dig("spec", "maxReplicas")
    assert_equal(%w[Pods Resource], v2.dig("spec", "metrics").map { |metric| metric["type"] })
    refute v2.dig("metadata", "annotations").to_h.key?("autoscaling.alpha.kubernetes.io/metrics")
  end

  def test_a_v1beta1_slice_is_a_v1_slice
    created = call("POST", "/apis/resource.k8s.io/v1beta1/resourceslices",
                   {"apiVersion" => "resource.k8s.io/v1beta1", "kind" => "ResourceSlice", "metadata" => {"name" => "s"},
                    "spec" => {"driver" => "gpu.example.com", "nodeName" => "n1", "pool" => {"name" => "p", "generation" => 1, "resourceSliceCount" => 1},
                               "devices" => [{"name" => "gpu-0", "basic" => {"attributes" => {"model" => {"string" => "a100"}}}}]}})

    assert_equal 201, created.status, created.body.inspect

    v1 = call("GET", "/apis/resource.k8s.io/v1/resourceslices/s").body

    assert_equal [{"name" => "gpu-0", "attributes" => {"model" => {"string" => "a100"}}}], v1.dig("spec", "devices")
    assert_equal(["s"], call("GET", "/apis/resource.k8s.io/v1/resourceslices").body["items"].map { |item| item.dig("metadata", "name") })
    watched = call("GET", "/apis/resource.k8s.io/v1beta1/resourceslices?watch=true&timeoutSeconds=0").body.to_a

    assert_equal "resource.k8s.io/v1beta1", watched.first["object"]["apiVersion"]
    assert_equal({"attributes" => {"model" => {"string" => "a100"}}}, watched.first["object"].dig("spec", "devices", 0, "basic"))
  end
end
