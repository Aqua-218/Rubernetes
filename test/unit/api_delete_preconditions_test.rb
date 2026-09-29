# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# DELETE pinned the resourceVersion the handler happened to read, so deleting
# an object that anything else was writing -- a CronJob whose status the
# controller updates, a Pod whose status the kubelet updates -- failed with
# "expected resourceVersion N, current is M".  No upstream cluster returns
# that for a plain DELETE: the registry checks UID/resourceVersion ONLY when
# the client sends DeleteOptions.Preconditions
# (registry/generic/registry/store.go#Delete).  Seen live in the 2026-09-14 K1
# run: [sig-apps] CronJob ForbidConcurrent failed at cronjob.go:162 with
# "Failed to delete CronJob forbid: expected resourceVersion 1124, current is 1130",
# and upstream's deleteCronJob sends no preconditions at all.
class APIDeletePreconditionsTest < Minitest::Test
  Patch = Rubernetes::API::Patch

  class Store
    attr_reader :deletes, :objects

    def initialize(object)
      @objects = {object.dig("metadata", "name") => object}
      @deletes = []
    end

    def get(resource:, namespace:, name:, **)
      @objects.fetch(name) { raise Rubernetes::Storage::MemoryStore::NotFound.new(name) }
    end

    # A CronJob owns Jobs, so its DELETE first marks it deleting (a write
    # that moves the resourceVersion) before removing it.
    def update(resource:, namespace:, name:, object:, resource_version: nil, **)
      stored = @objects.fetch(name).dig("metadata", "resourceVersion").to_s
      raise Rubernetes::Storage::MemoryStore::Conflict.new(name, "conflict", resource_version: stored) if resource_version && resource_version.to_s != stored

      updated = Marshal.load(Marshal.dump(object))
      updated["metadata"]["resourceVersion"] = (Integer(stored) + 1).to_s
      @objects[name] = updated
    end

    def delete(resource:, namespace:, name:, resource_version: nil, **)
      current = @objects.fetch(name)
      stored = current.dig("metadata", "resourceVersion").to_s
      if resource_version && resource_version.to_s != stored
        raise Rubernetes::Storage::MemoryStore::Conflict.new(
          name, "expected resourceVersion #{resource_version}, current is #{stored}",
          resource_version: stored
        )
      end
      @deletes << [name, resource_version]
      @objects.delete(name)
      current
    end
  end

  def object(resource_version: "1130", uid: "uid-1")
    {"apiVersion" => "batch/v1", "kind" => "CronJob",
     "metadata" => {"name" => "forbid", "namespace" => "ns",
                    "resourceVersion" => resource_version, "uid" => uid}}
  end

  # The handler reads the object, then other writers bump it; the store is
  # asked to delete whatever is current unless the client pinned a version.
  def test_a_plain_delete_does_not_pin_the_resource_version
    store = Store.new(object)
    server = server_for(store)

    server.send(:delete_response, request(body: nil), route)

    assert_equal [["forbid", nil]], store.deletes
  end

  def test_preconditions_resource_version_is_honoured
    store = Store.new(object(resource_version: "1130"))
    server = server_for(store)

    assert_raises(Rubernetes::API::Status::Conflict) do
      server.send(:delete_response,
                  request(body: {"preconditions" => {"resourceVersion" => "1124"}}), route)
    end
    assert_empty store.deletes
  end

  def test_preconditions_uid_is_honoured
    store = Store.new(object(uid: "uid-1"))
    server = server_for(store)

    error = assert_raises(Rubernetes::API::Status::Conflict) do
      server.send(:delete_response, request(body: {"preconditions" => {"uid" => "uid-other"}}), route)
    end
    assert_includes error.message, "UID in precondition"
    assert_empty store.deletes
  end

  def test_a_matching_precondition_deletes
    store = Store.new(object(resource_version: "1130", uid: "uid-1"))
    server = server_for(store)

    server.send(:delete_response,
                request(body: {"preconditions" => {"resourceVersion" => "1130", "uid" => "uid-1"}}), route)

    # The precondition matched 1130; the removal is pinned to the version
    # the deleting mark wrote on top of it.
    assert_equal [["forbid", "1131"]], store.deletes
  end

  private

  def route
    Struct.new(:resource, :name, :namespace).new(resource_descriptor, "forbid", "ns")
  end

  def resource_descriptor
    Struct.new(:resource, :kind, :group, :version, :namespaced).new("cronjobs", "CronJob", "batch", "v1", true)
  end

  def request(body:)
    Struct.new(:body, :query, :headers, :method).new(body.nil? ? nil : JSON.generate(body), {}, {}, "DELETE")
  end

  def server_for(store)
    server = Rubernetes::API::Server.allocate
    server.instance_variable_set(:@store, store)
    server.instance_variable_set(:@clock, -> { Time.now.utc })
    server.instance_variable_set(:@crd_manager, nil)
    server.define_singleton_method(:storage_namespace) { |*| "ns" }
    server.define_singleton_method(:admit_mutating) { |*| nil }
    server.define_singleton_method(:admit_validating) { |*| nil }
    server.define_singleton_method(:crd_resource?) { |*| false }
    server.define_singleton_method(:blocking_finalizers) { |*| [] }
    server.define_singleton_method(:cascade_delete_dependents) { |*| nil }
    server.define_singleton_method(:orphan_deletion?) { |*| false }
    server.define_singleton_method(:after_commit) { |*| nil }
    server.define_singleton_method(:release_registry_allocations) { |*| nil }
    server.define_singleton_method(:resource_details) { |*| {} }
    server.define_singleton_method(:json_response) { |value| value }
    server.define_singleton_method(:request_body) do |request|
      request.body.nil? ? nil : JSON.parse(request.body)
    end
    server.define_singleton_method(:query) { |*| nil }
    server
  end
end
