# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A StatefulSet recreates a Pod under the same name.  While the old record is
# still being torn down, exec/logs/attach must resolve to the NEW Pod's
# container; the first match sent "kubectl exec ss2-1" to the removed Pod's
# container ("unknown container ...-1") for as long as the spec retried.
class StreamingPodRecordPrefersLiveTest < Minitest::Test
  class Lifecycle
    attr_reader :records

    def initialize(records) = @records = records
  end

  def record(uid, state, container_id)
    {uid: uid, state: state,
     pod: {"metadata" => {"namespace" => "ns", "name" => "ss2-1", "uid" => uid}},
     containers: [{name: "webserver", id: container_id, started: state == "Running"}]}
  end

  def server(records)
    Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(records))
  end

  def test_the_live_record_wins_over_a_removed_one_with_the_same_name
    records = {"old" => record("old", "Removed", "podold.container-1"), "new" => record("new", "Running", "podnew.container-1")}

    assert_equal "podnew.container-1", server(records).send(:resolve_container_id, "ns", "ss2-1", "webserver")
    assert_equal "podnew.container-1", server(records.to_a.reverse.to_h).send(:resolve_container_id, "ns", "ss2-1", "webserver")
  end

  def test_a_lone_stopping_record_is_still_found
    records = {"old" => record("old", "Stopping", "podold.container-1")}

    assert_equal "podold.container-1", server(records).send(:resolve_container_id, "ns", "ss2-1", "webserver")
  end
end
