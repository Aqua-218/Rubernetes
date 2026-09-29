# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# The core/v1 Event `source` selectable field is computed from the internal
# object and falls back to reportingController when source.component is empty
# (pkg/registry/core/event/strategy.go#ToSelectableFields).  Without the
# fallback, `--field-selector source=X` matched nothing for every Event the
# events.k8s.io/v1 API wrote, which is what fails [sig-instrumentation]
# Events API at events.go:124.
class APIEventFieldSelectorTest < Minitest::Test
  FieldSelector = Rubernetes::API::Selector

  def core_event
    {"apiVersion" => "v1", "kind" => "Event",
     "metadata" => {"name" => "core", "namespace" => "ns"},
     "reason" => "Test", "type" => "Normal",
     "source" => {"component" => "test-controller", "host" => "node-a"}}
  end

  def events_api_event
    {"apiVersion" => "events.k8s.io/v1", "kind" => "Event",
     "metadata" => {"name" => "eventsapi", "namespace" => "ns"},
     "reason" => "Test", "type" => "Normal",
     "reportingController" => "test-controller", "reportingInstance" => "test-node"}
  end

  def sourceless_event
    {"apiVersion" => "v1", "kind" => "Event",
     "metadata" => {"name" => "bare", "namespace" => "ns"}, "reason" => "Test"}
  end

  def select(object, selector)
    FieldSelector.parse(selector).matches?(object)
  end

  def test_source_matches_the_core_source_component
    assert select(core_event, "source=test-controller")
    refute select(core_event, "source=other")
  end

  def test_source_falls_back_to_reporting_controller
    assert select(events_api_event, "source=test-controller"),
           "an Event written through events.k8s.io must still be selectable by source"
    refute select(events_api_event, "source=other")
  end

  def test_source_prefers_the_explicit_source_component
    event = events_api_event.merge("deprecatedSource" => {"component" => "explicit"})

    assert select(event, "source=explicit")
    refute select(event, "source=test-controller")
  end

  def test_reporting_component_maps_to_the_reporting_controller
    assert select(events_api_event, "reportingComponent=test-controller")
    assert select(core_event.merge("reportingComponent" => "kubelet"), "reportingComponent=kubelet")
  end

  def test_an_unset_selectable_field_still_matches_its_zero_value
    assert select(sourceless_event, "source=")
    refute select(sourceless_event, "source=test-controller")
  end
end
