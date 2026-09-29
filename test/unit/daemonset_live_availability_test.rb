# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# A rolling update replaces an old Pod the cache calls unavailable without
# counting it against maxUnavailable, so it asks the live object first: a
# cache one step behind a readiness change otherwise deleted every Pod of
# the DaemonSet at once.
class DaemonSetLiveAvailabilityTest < Minitest::Test
  Controller = Rubernetes::Controller::DaemonSetController

  class Adapter < Rubernetes::Controller::StoreAdapter
    def initialize(live) = @live = live
    def find_live(_descriptor, name:, namespace: nil) = @live[name]
  end

  def pod(name, ready:)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns"},
     "status" => {"phase" => "Running",
                  "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False",
                                    "lastTransitionTime" => "2026-09-23T00:00:00Z"}]}}
  end

  def sync(live)
    controller = Controller.allocate
    controller.define_singleton_method(:store) { Adapter.new(live) }
    controller.define_singleton_method(:min_ready_seconds) { |_ds| 0 }
    sync = Controller::Sync.allocate
    sync.instance_variable_set(:@c, controller)
    sync.instance_variable_set(:@ds, {})
    sync.instance_variable_set(:@now, Time.utc(2026, 9, 23, 1))
    sync
  end

  def test_a_pod_the_cache_thinks_unavailable_but_is_ready_live_counts_as_available
    stale = pod("a", ready: false)
    assert sync({"a" => pod("a", ready: true)}).send(:old_pod_available?, stale)
  end

  def test_a_pod_unavailable_live_too_is_replaceable
    stale = pod("a", ready: false)
    refute sync({"a" => pod("a", ready: false)}).send(:old_pod_available?, stale)
    refute sync({}).send(:old_pod_available?, stale), "a Pod already gone is not available"
  end
end
