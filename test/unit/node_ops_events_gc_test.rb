# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/event_recorder"
require "rubernetes/node/garbage_collector"

class NodeOpsEventsGcTest < Minitest::Test
  def test_event_recorder_aggregates_repeated_events
    recorder = Rubernetes::Node::EventRecorder.new(
      publish: false,
      clock: -> { Time.utc(2026, 1, 1) },
      uid_generator: -> { "event-uid" }
    )
    object = {"kind" => "Pod", "metadata" => {"name" => "pod", "namespace" => "default", "uid" => "pod-uid"}}

    first = recorder.record(involved_object: object, reason: "Started", message: "container started")
    second = recorder.record(involved_object: object, reason: "Started", message: "container started")

    assert_equal(1, first["count"])
    assert_equal(2, second["count"])
    assert_equal(1, recorder.events.length)
    assert_equal("event-uid", second.dig("metadata", "uid"))
    assert_equal(2, second.dig("series", "count"))
  end

  def test_gc_keeps_running_container_images_and_removes_old_terminated_entries
    removed_containers = []
    removed_images = []
    runtime = Object.new
    runtime.define_singleton_method(:remove_container) { |id| removed_containers << id }
    image_store = Object.new
    image_store.define_singleton_method(:remove_image) { |id| removed_images << id }
    gc = Rubernetes::Node::GarbageCollector.new(
      runtime: runtime,
      image_store: image_store,
      container_policy: {"max_per_pod" => 1, "min_age_seconds" => 0},
      image_policy: {"min_age_seconds" => 0, "high_threshold_percent" => 80, "low_threshold_percent" => 50}
    )
    containers = [
      {"id" => "old", "podName" => "pod", "state" => "exited", "finishedAt" => "2025-01-01T00:00:00Z", "image" => "sha:old"},
      {"id" => "new", "podName" => "pod", "state" => "exited", "finishedAt" => "2025-01-02T00:00:00Z", "image" => "sha:new"},
      {"id" => "running", "podName" => "live", "state" => "running", "image" => "sha:live"}
    ]
    images = [
      {"id" => "sha:old", "sizeBytes" => 100, "lastUsed" => "2025-01-01T00:00:00Z"},
      {"id" => "sha:new", "sizeBytes" => 100, "lastUsed" => "2025-01-02T00:00:00Z"},
      {"id" => "sha:live", "sizeBytes" => 100, "lastUsed" => "2025-01-01T00:00:00Z"}
    ]

    report = gc.run(containers: containers, images: images, disk_usage: {"usedBytes" => 900, "capacityBytes" => 1000},
                    now: Time.utc(2026, 1, 1))

    assert_equal(["old"], removed_containers)
    assert_equal(["sha:old", "sha:new"], removed_images)
    assert_equal(["sha:live"], images.reject { |image| removed_images.include?(image["id"]) }.map { |image| image["id"] })
    assert_equal(["old"], report.containers.map { |container| container["id"] })
  end
end
