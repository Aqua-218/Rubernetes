# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/watch"
require "rubernetes/controller"

# The controller manager's store adapter writes a created object straight
# into the informer cache.  The object's own ADDED watch event then arrives
# carrying the very version already in the cache; judging it stale dropped
# it, and the controller for that kind never heard of the object.
class InformerWriteThroughAddTest < Minitest::Test
  class Client
    def initialize(items) = @items = items
    def list(**_o) = {"metadata" => {"resourceVersion" => "10"}, "items" => @items}
    def watch(**_o) = [].each
  end

  def rs(rv)
    {"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "metadata" => {"name" => "web-abc", "namespace" => "ns", "resourceVersion" => rv}}
  end

  def test_an_added_event_for_a_written_through_object_still_reaches_handlers
    informer = Rubernetes::Watch::Informer.new(client: Client.new([]), resource: Rubernetes::Controller::ResourceDescriptor.parse("ReplicaSet"), namespace: :all)
    informer.run_once
    seen = []
    informer.on { |object, _old = nil, type = nil| seen << [type, object.dig("metadata", "resourceVersion")] }

    informer.indexer.upsert(rs("5338"))                    # write-through after a create
    informer.fifo.add(rs("5338"), resource_version: "5338")
    informer.send(:drain_fifo)

    assert_equal [[:add, "5338"]], seen, "the informer must deliver the object's own ADDED event"
  end

  def test_a_genuinely_older_event_is_still_dropped
    informer = Rubernetes::Watch::Informer.new(client: Client.new([]), resource: Rubernetes::Controller::ResourceDescriptor.parse("ReplicaSet"), namespace: :all)
    informer.run_once
    seen = []
    informer.on { |object, _old = nil, type = nil| seen << object.dig("metadata", "resourceVersion") }

    informer.fifo.add(rs("5340"), resource_version: "5340")
    informer.send(:drain_fifo)
    informer.fifo.update(rs("5339"), resource_version: "5339")
    informer.send(:drain_fifo)

    assert_equal ["5340"], seen
  end
end
