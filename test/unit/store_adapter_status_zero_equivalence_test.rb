# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# Controllers write every counter, zero included, while a stored status may
# omit zeros.  The two are the same status: no write is issued for it, and a
# real change still is.
class StoreAdapterStatusZeroEquivalenceTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter
  Operation = Struct.new(:action, :resource, :object, :patch, keyword_init: true)

  class FakeClient
    attr_reader :applies

    def initialize = @applies = []

    # UpdateStatus, the replicaset controller's write.
    def update(object, **options)
      @applies << [object, options]
      object
    end
  end

  class Cache
    def initialize(objects) = @objects = objects
    def list = @objects
    def get(name, namespace: nil) = @objects.find { |o| o.dig("metadata", "name") == name && o.dig("metadata", "namespace") == namespace }
  end

  def replica_set(status)
    {"apiVersion" => "apps/v1", "kind" => "ReplicaSet",
     "metadata" => {"name" => "rs", "namespace" => "ns", "uid" => "u1", "resourceVersion" => "7"},
     "spec" => {"replicas" => 1}, "status" => status}
  end

  def adapter_for(object)
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("ReplicaSet")
    client = FakeClient.new
    adapter = Adapter.new(client: client, resource_descriptors: [descriptor])
    adapter.caches = {descriptor.identifier => Cache.new([object])}
    [adapter, descriptor, client]
  end

  def test_explicit_zeros_against_omitted_zeros_are_not_a_change
    stored = replica_set({"replicas" => 1, "observedGeneration" => 1})
    adapter, descriptor, client = adapter_for(stored)

    adapter.apply(Operation.new(action: :status_update, resource: descriptor, object: stored,
                                patch: {"replicas" => 1, "observedGeneration" => 1, "readyReplicas" => 0, "availableReplicas" => 0}))

    assert_empty client.applies
  end

  def test_a_counter_dropping_to_zero_is_written
    stored = replica_set({"replicas" => 1, "readyReplicas" => 1, "observedGeneration" => 1})
    adapter, descriptor, client = adapter_for(stored)

    adapter.apply(Operation.new(action: :status_update, resource: descriptor, object: stored,
                                patch: {"replicas" => 1, "observedGeneration" => 1, "readyReplicas" => 0, "availableReplicas" => 0}))

    assert_equal 1, client.applies.length
    assert_equal 0, client.applies.first.first.dig("status", "readyReplicas"), "the zero must be sent explicitly, not omitted"
  end
end
