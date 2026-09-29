# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/controller"

# garbagecollector attemptToDeleteItem: a dependent whose only owner the API
# server no longer has (404 on a live read) is deleted.  Exercised through the
# production adapter, the way the controller manager runs the sweep.
class GCDanglingOwnerSweepTest < Minitest::Test
  class API
    attr_reader :deleted

    def initialize(pods)
      @pods = pods
      @deleted = []
    end

    def get(resource, name = nil, namespace: nil, api_version: nil, **_options)
      if resource.to_s == "pods"
        return @pods.find { |pod| pod.dig("metadata", "name") == name } if name
        return {"items" => @pods, "metadata" => {"resourceVersion" => "1"}}
      end
      return {"items" => [], "metadata" => {"resourceVersion" => "1"}} if name.nil?

      raise Rubernetes::Client::APIError.new("#{resource} \"#{name}\" not found",
                                             response: Struct.new(:status, :body, :headers).new(404, "", {}))
    end

    def delete(resource, name, **_options)
      @deleted << [resource.to_s, name]
      {}
    end
  end

  def test_a_pod_whose_owner_is_gone_is_collected_by_the_sweep
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "orphan", "namespace" => "default", "uid" => "p1",
                          "ownerReferences" => [{"apiVersion" => "v1", "kind" => "ReplicationController",
                                                 "name" => "ghost", "uid" => "rc-gone", "controller" => true}]}}
    client = API.new([pod])
    descriptors = %w[Pod ReplicationController GarbageCollector].map { |kind| Rubernetes::Controller::ResourceDescriptor.parse(kind) }
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: descriptors)
    controller = Rubernetes::Controller::GarbageCollectorController.new(store: adapter, definition: nil) rescue
                 Rubernetes::Controller::GarbageCollectorController.new(store: adapter)

    result = controller.plan_orphans("default/orphan", store: adapter)

    refute_nil result, "the sweep must run"
    assert_equal [["pods", "orphan"]], result.operations.map { |op| [op.resource.resource, Rubernetes::Controller::Support.name(op.object)] }
  end
end
