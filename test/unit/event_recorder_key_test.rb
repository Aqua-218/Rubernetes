# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/event_recorder"

# client-go tools/record/events_cache.go: an Event's count grows only for an
# identical event (getEventKey includes involvedObject.fieldPath and the
# message); similar events with distinct messages are combined into one
# "(combined from similar events)" Event from the tenth on.  Keying on the
# reason alone merged every container's Created/Started/Pulling record of a
# Pod into the first init container's Event, whose fieldPath then named that
# init container for all of them.
class EventRecorderKeyTest < Minitest::Test
  def setup
    @now = Time.utc(2026, 9, 29, 6, 0, 0)
    @recorder = Rubernetes::Node::EventRecorder.new(publish: false, clock: -> { @now })
  end

  def pod(field_path)
    {"kind" => "Pod", "metadata" => {"name" => "kas", "namespace" => "gitlab", "uid" => "u"}, "fieldPath" => field_path}
  end

  def test_events_of_different_containers_are_distinct_records
    first = @recorder.record(involved_object: pod("spec.containers{certificates}"), reason: "Created",
                             message: "Created container: certificates")
    second = @recorder.record(involved_object: pod("spec.containers{kas}"), reason: "Created", message: "Created container: kas")
    again = @recorder.record(involved_object: pod("spec.containers{kas}"), reason: "Created", message: "Created container: kas")

    assert_equal 1, first["count"]
    assert_equal 1, second["count"]
    assert_equal 2, again["count"]
    assert_equal "spec.containers{kas}", again.dig("involvedObject", "fieldPath")
    assert_equal 2, @recorder.events.length
    refute_equal first.dig("metadata", "name"), second.dig("metadata", "name")
  end

  def test_same_field_path_with_a_different_message_is_a_new_event
    @recorder.record(involved_object: pod("spec.containers{kas}"), reason: "Pulling", message: "Pulling image \"a\"")
    other = @recorder.record(involved_object: pod("spec.containers{kas}"), reason: "Pulling", message: "Pulling image \"b\"")

    assert_equal 1, other["count"]
    assert_equal 2, @recorder.events.length
  end

  def test_ten_similar_events_with_distinct_messages_are_combined
    events = (1..12).map do |i|
      @now += 1
      @recorder.record(involved_object: pod("spec.containers{kas}"), reason: "Unhealthy", message: "probe failed: attempt #{i}")
    end
    events[0, 9].each_with_index do |event, i|
      assert_equal "probe failed: attempt #{i + 1}", event["message"]
      assert_equal 1, event["count"]
    end
    assert_equal "(combined from similar events): probe failed: attempt 10", events[9]["message"]
    assert_equal 1, events[9]["count"]
    assert_equal "(combined from similar events): probe failed: attempt 12", events[11]["message"]
    assert_equal 3, events[11]["count"], "later similar events grow the combined Event"
    assert_equal 10, @recorder.events.length
  end

  def test_the_aggregate_window_resets
    10.times { |i| @recorder.record(involved_object: pod("spec.containers{kas}"), reason: "Unhealthy", message: "m#{i}") }
    @now += 601
    fresh = @recorder.record(involved_object: pod("spec.containers{kas}"), reason: "Unhealthy", message: "late")

    assert_equal "late", fresh["message"]
  end
end
