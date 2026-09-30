# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# The resourceclaim controller deallocates a claim with UpdateStatus and then
# removes its finalizer with Update on the object that returned.  A forced
# status apply could not drop status.allocation (the scheduler owns it), and
# the finalizer update, still carrying the pre-status resourceVersion,
# conflicted on every retry -- a hot 409 loop.
class StoreAdapterClaimStatusReplaceTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter
  Operation = Struct.new(:action, :resource, :object, :patch, keyword_init: true)

  class FakeClient
    attr_reader :updates, :applies

    def initialize
      @updates = []
      @applies = []
      @version = 50
    end

    def apply(object, **options) = (@applies << [object, options]) && object

    def update(object, namespace: nil, subresource: nil)
      @updates << [Marshal.load(Marshal.dump(object)), subresource]
      current = @version.to_s
      raise Rubernetes::Client::APIError.new("conflict", response: Struct.new(:status).new(409)) if object.dig("metadata",
                                                                                                               "resourceVersion") != current

      @version += 1
      object.merge("metadata" => object["metadata"].merge("resourceVersion" => @version.to_s))
    end

    def get(*, **) = nil
  end

  class Cache
    def initialize(objects) = @objects = objects
    def list = @objects
    def get(name, namespace: nil) = @objects.find { |o| o.dig("metadata", "name") == name && o.dig("metadata", "namespace") == namespace }
    def apply_event(*) = nil
  end

  def claim
    {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim",
     "metadata" => {"name" => "c", "namespace" => "ns", "uid" => "u1", "resourceVersion" => "50",
                    "finalizers" => ["resource.kubernetes.io/delete-protection"]},
     "spec" => {"devices" => {"requests" => []}},
     "status" => {"allocation" => {"devices" => {"results" => []}}, "reservedFor" => [{"resource" => "pods", "name" => "p", "uid" => "p1"}]}}
  end

  def test_deallocation_replaces_the_status_and_the_finalizer_update_follows_it
    descriptor = Rubernetes::Controller::AdvancedMiscSupport::RESOURCE_CLAIM
    adapter = Adapter.new(client: FakeClient.new, resource_descriptors: [descriptor])
    adapter.caches = {descriptor.identifier => Cache.new([claim])}

    status = {"reservedFor" => []}
    updated = Marshal.load(Marshal.dump(claim))
    updated["metadata"]["finalizers"] = []
    updated["status"] = status
    adapter.apply_batch([Operation.new(action: :status_update, resource: descriptor, object: claim, patch: status),
                         Operation.new(action: :update, resource: descriptor, object: updated)])

    assert_empty adapter.client.applies, "no server-side apply of a claim status"
    (status_body, status_sub), (object_body, object_sub) = adapter.client.updates

    assert_equal "status", status_sub
    assert_equal({"reservedFor" => []}, status_body["status"], "allocation is gone from the replaced status")
    assert_equal "50", status_body.dig("metadata", "resourceVersion")
    assert_nil object_sub
    assert_equal "51", object_body.dig("metadata", "resourceVersion"), "rebased onto the status write"
    assert_equal [], object_body.dig("metadata", "finalizers")
  end
end
