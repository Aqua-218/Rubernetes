# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class HPAScaleSubresourceTest < Minitest::Test
  PATH = "/apis/apps/v1/namespaces/dev/deployments/test/scale"

  class Client
    attr_reader :calls

    def initialize(discovery: {})
      @calls = []
      @discovery = discovery
    end

    def get(path)
      @calls << [:get, path]
      return @discovery.fetch(path) if @discovery.key?(path)

      {"apiVersion" => "autoscaling/v1", "kind" => "Scale",
       "metadata" => {"name" => "test", "namespace" => "dev", "uid" => "scale-target", "resourceVersion" => "7"},
       "spec" => {"replicas" => 1}, "status" => {"replicas" => 1, "selector" => "app=test"}}
    end

    def update(object, path:)
      @calls << [:update, path, object]
      object
    end
  end

  def test_controller_reads_and_updates_only_the_scale_subresource
    client = Client.new
    target = Rubernetes::Controller::ResourceDescriptor.parse("Deployment")
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: [target])
    controller = Rubernetes::Controller::HorizontalPodAutoscalerController.new
    hpa = {"apiVersion" => "autoscaling/v2", "kind" => "HorizontalPodAutoscaler",
           "metadata" => {"name" => "test", "namespace" => "dev"},
           "spec" => {"scaleTargetRef" => {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "test"},
                      "minReplicas" => 2, "maxReplicas" => 2}}
    operation = controller.plan(hpa, store: adapter).operations.find(&:update?)
    result = adapter.apply(operation, fence: -> { client.calls << [:fence] })

    assert_equal([[:get, PATH], [:fence], [:update, PATH, result]], client.calls)
    assert_equal(["Scale", "7", "scale-target", 2],
                 [result["kind"], result.dig("metadata", "resourceVersion"), result.dig("metadata", "uid"), result.dig("spec", "replicas")])
  end

  def test_custom_scale_uses_discovered_plural_and_exact_version
    discovery_path = "/apis/scale.example.com/v2"
    scale_path = "#{discovery_path}/namespaces/dev/fleets/test/scale"
    discovery = {"resources" => [{"kind" => "Deployment", "name" => "fleets", "namespaced" => true},
                                 {"kind" => "Scale", "name" => "fleets/scale", "group" => "autoscaling", "version" => "v1"}]}
    client = Client.new(discovery: {discovery_path => discovery})
    target = Rubernetes::Controller::ResourceDescriptor.parse("Deployment")
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: [target])
    controller = Rubernetes::Controller::HorizontalPodAutoscalerController.new
    hpa = {"apiVersion" => "autoscaling/v2", "kind" => "HorizontalPodAutoscaler",
           "metadata" => {"name" => "test", "namespace" => "dev"},
           "spec" => {"scaleTargetRef" => {"apiVersion" => "scale.example.com/v2", "kind" => "Deployment", "name" => "test"},
                      "minReplicas" => 2, "maxReplicas" => 2}}
    operation = controller.plan(hpa, store: adapter).operations.find(&:update?)
    actual = adapter.apply(operation)

    assert_equal [[:get, discovery_path], [:get, scale_path], [:update, scale_path, actual]], client.calls
    assert_equal 2, actual.dig("spec", "replicas")
  end
end
