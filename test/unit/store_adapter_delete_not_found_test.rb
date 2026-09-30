# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# A delete planned from the informer cache can find its object already gone:
# the garbage collector, the StatefulSet controller or the namespace deleter
# got there first.  Upstream controllers treat NotFound on a delete as done.
# Raising instead failed the whole namespace reconcile over one missing
# ControllerRevision, and the namespace stayed Terminating for hours.
class StoreAdapterDeleteNotFoundTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter
  Client = Rubernetes::Client

  class FakeClient
    attr_reader :deletes

    def initialize(status)
      @status = status
      @deletes = []
    end

    def delete(resource, name, namespace: nil, api_version: nil, **_options)
      @deletes << [resource, name, namespace]
      return {"kind" => "Status", "status" => "Success"} if @status == 200

      response = Client::HTTPClient::Response.new(status: @status, headers: {}, body: "")
      raise Client::APIError.new("#{resource} #{name.inspect} not found", response: response)
    end
  end

  class RecordingCache
    attr_reader :deleted

    def initialize
      @deleted = []
    end

    def delete(object)
      @deleted << object.dig("metadata", "name")
    end
  end

  def adapter(status)
    Adapter.new(client: FakeClient.new(status), resource_descriptors: [Rubernetes::Controller::ResourceDescriptor.parse("Pod")])
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}}
  end

  def test_a_404_on_delete_counts_as_deleted
    adapter = adapter(404)
    cache = RecordingCache.new
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("Pod")
    adapter.caches = {descriptor.identifier => cache}

    assert_nil adapter.delete(pod, descriptor: Rubernetes::Controller::ResourceDescriptor.parse("Pod"))
    assert_equal [%w[pods p ns]], adapter.client.deletes
    assert_equal ["p"], cache.deleted, "the cache entry goes, exactly as after a successful immediate delete"
  end

  def test_other_api_errors_still_raise
    adapter = adapter(500)

    assert_raises(Client::APIError) { adapter.delete(pod, descriptor: Rubernetes::Controller::ResourceDescriptor.parse("Pod")) }
  end

  def test_a_successful_delete_is_unchanged
    adapter = adapter(200)

    result = adapter.delete(pod, descriptor: Rubernetes::Controller::ResourceDescriptor.parse("Pod"))

    assert_equal "Status", result["kind"]
  end
end
