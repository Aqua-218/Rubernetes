# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# PodControllerRefManager canAdoptFunc: adoption is refused once a fresh read
# shows the controller being deleted, so an orphaning delete's released Pods
# are not re-owned (and then garbage collected) by a stale cache.
class ControllerAdoptionGuardTest < Minitest::Test
  class Adapter < Rubernetes::Controller::StoreAdapter
    attr_accessor :live

    def find_live(_descriptor, name:, namespace: nil)
      live
    end
  end

  def rc(deleting: false)
    object = {"apiVersion" => "v1", "kind" => "ReplicationController",
              "metadata" => {"name" => "rc", "namespace" => "ns", "uid" => "rc-1"},
              "spec" => {"replicas" => 1, "selector" => {"app" => "a"},
                         "template" => {"metadata" => {"labels" => {"app" => "a"}}, "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}}}}
    object["metadata"]["deletionTimestamp"] = "2026-09-16T00:00:00Z" if deleting
    object
  end

  def test_pods_are_adopted_while_the_controller_is_alive_and_not_once_it_is_deleting
    orphan = {"apiVersion" => "v1", "kind" => "Pod",
              "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "p-1", "labels" => {"app" => "a"}},
              "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}, "status" => {"phase" => "Running"}}
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    adapter = Adapter.new(store)
    controller = Rubernetes::Controller::ReplicationControllerController.new(store: store)

    adapter.live = rc
    adopting = controller.plan(rc, store: adapter, pods: [orphan])

    assert adopting.operations.any? { |op|
      op.action == :update && op.reason.to_s.include?("adoption")
    }, adopting.operations.map(&:reason).inspect

    adapter.live = rc(deleting: true)
    refusing = controller.plan(rc, store: adapter, pods: [orphan])

    refute refusing.operations.any? { |op| op.reason.to_s.include?("adoption") }, refusing.operations.map(&:reason).inspect
  end
end
