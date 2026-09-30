# frozen_string_literal: true

# kube-aggregator's available controller metrics: aggregator_unavailable_apiservice
# (1 while unavailable, set on every sync) and
# aggregator_unavailable_apiservice_total{name,reason}, counted when an
# APIService goes from available to unavailable.

require_relative "../test_helper"
require "rubernetes/api"

class AggregatorAvailabilityMetricsTest < Minitest::Test
  def test_gauge_and_transition_counter
    server = Rubernetes::API::Server.new(store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil))
    metrics = server.instance_variable_get(:@metrics)
    up = {"type" => "Available", "status" => "True", "reason" => "Passed"}
    down = {"type" => "Available", "status" => "False", "reason" => "FailedDiscoveryCheck"}
    server.send(:observe_apiservice_availability, "v1.wardle.example.com", nil, down)
    text = metrics.render

    assert_includes text, 'aggregator_unavailable_apiservice{name="v1.wardle.example.com"} 1'
    refute_includes text, "aggregator_unavailable_apiservice_total{", "Unknown -> False is not a transition from available"
    server.send(:observe_apiservice_availability, "v1.wardle.example.com", down, up)

    assert_includes metrics.render, 'aggregator_unavailable_apiservice{name="v1.wardle.example.com"} 0'
    server.send(:observe_apiservice_availability, "v1.wardle.example.com", up, down)
    server.send(:observe_apiservice_availability, "v1.wardle.example.com", down, down)
    text = metrics.render

    assert_includes text, 'aggregator_unavailable_apiservice_total{name="v1.wardle.example.com",reason="FailedDiscoveryCheck"} 1'
    assert_includes text, 'aggregator_unavailable_apiservice{name="v1.wardle.example.com"} 1'
  end
end
