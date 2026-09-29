# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# Several threads compute and report one Pod's status.  A status computed
# before another must never be delivered after it: a probe's snapshot, taken
# while a resize was running, reported PodResizeInProgress after the resize's
# own completed report, and the condition stayed on the Pod ("[sig-node] Pod
# InPlace Resize ... unexpected resize condition type PodResizeInProgress
# found in pod status", round 92).
class NodeStatusReportOrderTest < Minitest::Test
  Status = Rubernetes::Node::Status

  class Reporter
    attr_reader :reports

    def initialize = @reports = Queue.new
    def report(_pod, status) = @reports << status
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u", "generation" => 2},
     "spec" => {"nodeName" => "node-a", "containers" => [{"name" => "c", "image" => "img"}]}, "status" => {}}
  end

  def aggregate(status, resize)
    status.aggregate(pod: pod, state: {"containers" => {"c" => {"state" => "running", "ready" => true, "started" => true}}, "initContainers" => {}},
                     phase: "Running", start_time: Time.at(1_699_999_000).utc, pod_ip: "10.0.0.1", pod_ips: ["10.0.0.1"],
                     resize_conditions: resize ? [{"type" => "PodResizeInProgress", "observedGeneration" => 2}] : [])
  end

  def resize_types(status) = Array(status["conditions"]).map { |condition| condition["type"] }.grep(/PodResize/)

  def test_a_status_computed_earlier_is_not_delivered_after_a_later_one
    reporter = Reporter.new
    status = Status.new(reporter: reporter)
    # The older computation (resize still running) is slow to finish; the
    # newer one (resize completed) overtakes it.
    status.define_singleton_method(:first_start_time) do |*arguments|
      sleep 0.3 if Thread.current[:slow]
      super(*arguments)
    end

    older = Thread.new do
      Thread.current[:slow] = true
      aggregate(status, true)
    end
    sleep 0.05
    aggregate(status, false)
    older.join

    delivered = []
    delivered << reporter.reports.pop until reporter.reports.empty?
    assert_equal [], resize_types(delivered.last), "the last report is the completed resize"
    assert_equal 1, delivered.length, "the stale in-progress status is dropped, not sent late"
    assert_equal [], resize_types(status["u"].to_h)
  end
end
