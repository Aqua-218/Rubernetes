# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# The controller manager records its controllers' Events (they were only
# journaled): core/v1 Events with the upstream source component, the
# reconciled object as the involved object unless the event names another,
# aggregated, and spam-filtered like client-go (25 per object, then one per
# five minutes).
class ControllerEventPublishingTest < Minitest::Test
  Service = Rubernetes::Bootstrap::ControllerManagerService
  Result = Struct.new(:controller, :events)

  class Client
    attr_reader :created

    def initialize = @created = []
    def create(event, **) = (@created << event) && event
  end

  def service(now)
    service = Service.allocate
    service.instance_variable_set(:@client, Client.new)
    service.instance_variable_set(:@clock, -> { now.call })
    service.instance_variable_set(:@logger, nil)
    service.define_singleton_method(:log) { |*| nil }
    service
  end

  def pdb
    {"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget",
     "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1", "resourceVersion" => "7"}}
  end

  def flush(service)
    service.instance_variable_get(:@controller_event_recorders).each_value do |recorder|
      recorder.client.flush
    end
  end

  def test_events_are_recorded_with_the_upstream_component
    time = Time.utc(2026, 9, 23, 12)
    subject = service(-> { time })
    subject.send(:publish_controller_events, pdb,
                 Result.new("disruption-controller", [{"type" => "Normal", "reason" => "NoPods", "message" => "No matching pods found"},
                                                      {"type" => "Warning", "reason" => "NotDeleted", "message" => "gone?",
                                                       "involvedObject" => {"apiVersion" => "v1", "kind" => "Pod", "namespace" => "ns",
                                                                            "name" => "p", "uid" => "pu"}}]))
    flush(subject)
    created = subject.instance_variable_get(:@client).created

    assert_equal(%w[NoPods NotDeleted], created.map { |event| event["reason"] })
    assert_equal({"component" => "controllermanager"}, created.first["source"])
    assert_equal({"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget", "namespace" => "ns", "name" => "web", "uid" => "u1",
                  "resourceVersion" => "7"}.slice("apiVersion", "kind", "namespace", "name", "uid"),
                 created.first["involvedObject"].slice("apiVersion", "kind", "namespace", "name", "uid"))
    assert_equal "Pod", created.last.dig("involvedObject", "kind")
    refute created.first.key?("eventTime"), "core/v1 events, as record.EventRecorder writes"
  end

  def test_one_object_gets_at_most_25_events_then_one_per_five_minutes
    time = Time.utc(2026, 9, 23, 12)
    subject = service(-> { time })
    30.times do |index|
      subject.send(:publish_controller_events, pdb, Result.new("deployment-controller",
                                                               [{"type" => "Normal", "reason" => "R#{index}", "message" => "m"}]))
    end
    flush(subject)

    assert_equal 25, subject.instance_variable_get(:@client).created.length
    time += 300
    subject.send(:publish_controller_events, pdb,
                 Result.new("deployment-controller", [{"type" => "Normal", "reason" => "Later", "message" => "m"}]))
    flush(subject)

    assert_equal "Later", subject.instance_variable_get(:@client).created.last["reason"]
  end
end
