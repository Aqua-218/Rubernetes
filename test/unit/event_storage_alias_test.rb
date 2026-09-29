# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# core/v1 Events and events.k8s.io/v1 Events are two wire shapes over ONE
# stored object upstream (pkg/apis/events/v1/conversion.go).  Ours were two
# separate stores, so an Event written through one API was invisible to the
# other -- which the conformance spec "Events API should ensure that an event
# can be fetched, patched, deleted, and listed" crosses deliberately: it
# creates through events.k8s.io/v1 and then lists through core/v1 with
# `--field-selector source=test-controller`.
class EventStorageAliasTest < Minitest::Test
  API = Rubernetes::API

  CORE_EVENTS = {group: "", version: "v1", resource: "events", kind: "Event", scope: :namespaced,
                 short_names: ["ev"]}.freeze
  NEW_EVENTS = {group: "events.k8s.io", version: "v1", resource: "events", kind: "Event",
                scope: :namespaced, short_names: ["ev"]}.freeze

  def setup
    resources = [CORE_EVENTS, NEW_EVENTS].map do |entry|
      API::Resource.new(**entry,
                        **API::EventConversion.alias_options_for(entry[:group], entry[:version], entry[:resource]))
    end
    resources << API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace",
                                   scope: :cluster)
    @server = API::Server.new(registry: API::Registry.new(resources: resources, defaults: false),
                              store: API::MemoryStore.new)
  end

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, body: body))
  end

  def new_event(name, controller: "test-controller")
    {"apiVersion" => "events.k8s.io/v1", "kind" => "Event",
     "metadata" => {"name" => name, "namespace" => "default", "labels" => {"testevent-constant" => "true"}},
     "regarding" => {"namespace" => "default", "kind" => "Pod", "name" => "target"},
     "eventTime" => "2017-09-19T13:49:16.000000Z",
     "note" => "This is #{name}", "action" => "Do", "reason" => "Test", "type" => "Normal",
     "reportingController" => controller, "reportingInstance" => "test-node"}
  end

  def core_event(name, component: "core-controller")
    {"apiVersion" => "v1", "kind" => "Event",
     "metadata" => {"name" => name, "namespace" => "default"},
     "involvedObject" => {"namespace" => "default", "kind" => "Pod", "name" => "target"},
     "reason" => "Test", "message" => "core note", "type" => "Normal", "count" => 2,
     "reportingComponent" => component, "source" => {"component" => component}}
  end

  def test_an_event_created_through_events_k8s_io_is_readable_through_core_v1
    assert_equal(201, call("POST", "/apis/events.k8s.io/v1/namespaces/default/events", new_event("event-test")).status)

    fetched = call("GET", "/api/v1/namespaces/default/events/event-test")
    assert_equal(200, fetched.status)
    assert_equal("v1", fetched.body.fetch("apiVersion"))
    assert_equal("This is event-test", fetched.body.fetch("message"))
    assert_equal("target", fetched.body.dig("involvedObject", "name"))
    assert_equal("test-controller", fetched.body.fetch("reportingComponent"))
    refute(fetched.body.key?("note"))
    refute(fetched.body.key?("regarding"))
  end

  def test_an_event_created_through_core_v1_is_readable_through_events_k8s_io
    assert_equal(201, call("POST", "/api/v1/namespaces/default/events", core_event("core-event")).status)

    fetched = call("GET", "/apis/events.k8s.io/v1/namespaces/default/events/core-event")
    assert_equal(200, fetched.status)
    assert_equal("events.k8s.io/v1", fetched.body.fetch("apiVersion"))
    assert_equal("core note", fetched.body.fetch("note"))
    assert_equal("target", fetched.body.dig("regarding", "name"))
    assert_equal(2, fetched.body.fetch("deprecatedCount"))
    assert_equal("core-controller", fetched.body.dig("deprecatedSource", "component"))
  end

  # pkg/registry/core/event/strategy.go ToSelectableFields: `source` falls back
  # to the reporting controller, which is what the conformance spec selects on
  # after creating the Event through the other API.
  def test_core_v1_field_selectors_match_an_events_k8s_io_event
    call("POST", "/apis/events.k8s.io/v1/namespaces/default/events", new_event("event-test"))
    call("POST", "/apis/events.k8s.io/v1/namespaces/default/events", new_event("other-event", controller: "elsewhere"))

    listed = call("GET", "/api/v1/namespaces/default/events?fieldSelector=source%3Dtest-controller")
    assert_equal(200, listed.status)
    assert_equal(["event-test"], listed.body.fetch("items").map { |item| item.dig("metadata", "name") })
    # List items carry the core shape, not the one they were written in.
    assert_equal("This is event-test", listed.body.fetch("items").first.fetch("message"))
  end

  def test_events_k8s_io_field_selectors_match_a_core_v1_event
    call("POST", "/api/v1/namespaces/default/events", core_event("core-event"))

    listed = call("GET", "/apis/events.k8s.io/v1/namespaces/default/events?fieldSelector=reportingController%3Dcore-controller")
    assert_equal(200, listed.status)
    assert_equal(["core-event"], listed.body.fetch("items").map { |item| item.dig("metadata", "name") })
  end

  def test_both_apis_list_the_same_events_in_their_own_shape
    call("POST", "/apis/events.k8s.io/v1/namespaces/default/events", new_event("event-test"))
    call("POST", "/api/v1/namespaces/default/events", core_event("core-event"))

    core_names = call("GET", "/api/v1/namespaces/default/events").body.fetch("items")
                                                                  .map { |item| item.dig("metadata", "name") }
    new_names = call("GET", "/apis/events.k8s.io/v1/namespaces/default/events").body.fetch("items")
                                                                              .map { |item| item.dig("metadata", "name") }

    assert_equal(%w[core-event event-test], core_names.sort)
    assert_equal(core_names.sort, new_names.sort)
  end

  def test_deleting_through_one_api_removes_it_from_the_other
    call("POST", "/apis/events.k8s.io/v1/namespaces/default/events", new_event("event-test"))

    assert_equal(200, call("DELETE", "/api/v1/namespaces/default/events/event-test").status)
    assert_equal(404, call("GET", "/apis/events.k8s.io/v1/namespaces/default/events/event-test").status)
  end

  def test_patching_through_events_k8s_io_updates_the_shared_object
    call("POST", "/apis/events.k8s.io/v1/namespaces/default/events", new_event("event-test"))

    patched = @server.call(API::Request.new(
                             method: "PATCH",
                             path: "/apis/events.k8s.io/v1/namespaces/default/events/event-test",
                             headers: {"content-type" => "application/merge-patch+json"},
                             body: {"note" => "updated note"}
                           ))
    assert_equal(200, patched.status)
    assert_equal("updated note", patched.body.fetch("note"))
    assert_equal("updated note", call("GET", "/api/v1/namespaces/default/events/event-test").body.fetch("message"))
  end
end
