# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# A controller's status write takes the verb its upstream counterpart uses
# (and the bootstrap RBAC grants): UpdateStatus -- a PUT conditional on the
# resourceVersion it computed from -- for most, including
# resource_quota_controller.go, whose recompute that started before a Service
# was admitted must conflict rather than overwrite admission's charge; a
# status patch for the pod GC; a forced status apply under its own field
# manager for the resourceclaim controller.
class StoreAdapterConditionalStatusTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter
  Operation = Struct.new(:action, :resource, :object, :patch, keyword_init: true)

  class FakeClient
    attr_reader :applies, :updates, :patches

    def initialize
      @applies = []
      @updates = []
      @patches = []
    end

    def apply(object, **options)
      @applies << [object, options]
      object
    end

    def update(object, **options)
      @updates << [object, options]
      object
    end

    def patch(*args, **options)
      @patches << [args, options]
      args[1]
    end
  end

  class Cache
    def initialize(objects) = @objects = objects
    def list = @objects
    def get(name, namespace: nil) = @objects.find { |o| o.dig("metadata", "name") == name && o.dig("metadata", "namespace") == namespace }
  end

  def adapter(kind, object)
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse(kind)
    adapter = Adapter.new(client: FakeClient.new, resource_descriptors: [descriptor])
    adapter.caches = {descriptor.identifier => Cache.new([object])}
    [adapter, descriptor]
  end

  def quota
    {"apiVersion" => "v1", "kind" => "ResourceQuota",
     "metadata" => {"name" => "q", "namespace" => "ns", "uid" => "u1", "resourceVersion" => "41"},
     "spec" => {"hard" => {"pods" => "2"}}, "status" => {"hard" => {"pods" => "2"}, "used" => {"pods" => "0"}}}
  end

  def test_a_quota_status_update_carries_the_version_it_was_computed_from
    adapter, descriptor = adapter("ResourceQuota", quota)

    Rubernetes::Controller::Support.with_controller("resourcequota-controller") do
      adapter.apply(Operation.new(action: :status_update, resource: descriptor, object: quota,
                                  patch: {"hard" => {"pods" => "2"}, "used" => {"pods" => "1"}}))
    end

    body, options = adapter.client.updates.first
    assert_equal "41", body.dig("metadata", "resourceVersion")
    assert_equal({"pods" => "1"}, body.dig("status", "used"))
    assert_equal "status", options[:subresource]
    assert_empty adapter.client.applies
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u2", "resourceVersion" => "7"},
     "spec" => {}, "status" => {"phase" => "Pending"}}
  end

  def test_the_pod_gc_patches_status
    adapter, descriptor = adapter("Pod", pod)
    Rubernetes::Controller::Support.with_controller("pod-garbage-collector-controller") do
      adapter.apply(Operation.new(action: :status_update, resource: descriptor, object: pod, patch: {"phase" => "Failed"}))
    end
    args, options = adapter.client.patches.first
    assert_equal({"status" => {"phase" => "Failed"}, "metadata" => {"uid" => "u2"}}, args[1])
    assert_equal :strategic, options[:type]
    assert_equal "status", options[:subresource]
  end

  def test_the_resourceclaim_controller_applies_pod_status_as_its_manager
    adapter, descriptor = adapter("Pod", pod)
    Rubernetes::Controller::Support.with_controller("resourceclaim-controller") do
      adapter.apply(Operation.new(action: :status_update, resource: descriptor, object: pod, patch: {"resourceClaimStatuses" => []}))
    end
    _body, options = adapter.client.applies.first
    assert_equal "ResourceClaimController", options[:field_manager]
    assert_equal true, options[:force]
  end
end

# Update then UpdateStatus of one object in one batch, both planned from the
# version read: the second write is sent with the version the first
# produced, as upstream issues it from the object Update returned.
class StoreAdapterWriteSuccessorTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter
  Operation = Struct.new(:action, :resource, :object, :patch, keyword_init: true)

  class Client < StoreAdapterConditionalStatusTest::FakeClient
    def update(object, **options)
      super
      object.merge("metadata" => object["metadata"].merge("resourceVersion" => (object.dig("metadata", "resourceVersion").to_i + 1).to_s))
    end
  end

  def test_status_after_update_uses_the_updated_version
    deployment = {"apiVersion" => "apps/v1", "kind" => "Deployment",
                  "metadata" => {"name" => "d", "namespace" => "ns", "uid" => "u", "resourceVersion" => "5"},
                  "spec" => {"replicas" => 1}, "status" => {"replicas" => 0}}
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("Deployment")
    adapter = Adapter.new(client: Client.new, resource_descriptors: [descriptor])
    adapter.caches = {descriptor.identifier => StoreAdapterConditionalStatusTest::Cache.new([deployment])}
    changed = Marshal.load(Marshal.dump(deployment))
    changed["metadata"]["annotations"] = {"deployment.kubernetes.io/revision" => "1"}
    Rubernetes::Controller::Support.with_controller("deployment-controller") do
      adapter.update(changed, descriptor: descriptor, existing: deployment)
      adapter.apply(Operation.new(action: :status_update, resource: descriptor, object: deployment, patch: {"replicas" => 1}))
    end
    versions = adapter.client.updates.map { |body, _| body.dig("metadata", "resourceVersion") }
    assert_equal %w[5 6], versions
    assert_equal "status", adapter.client.updates.last.last[:subresource]
  end
end
