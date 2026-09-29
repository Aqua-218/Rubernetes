# frozen_string_literal: true

module Rubernetes
  module API
    # core/v1 Event and events.k8s.io/v1 Event are two wire shapes over ONE
    # stored object.  Upstream keeps a single internal core.Event and converts
    # at the edge (pkg/apis/events/v1/conversion.go), so an Event written
    # through either API is visible through the other -- which conformance
    # relies on: "Events API should ensure that an event can be fetched,
    # patched, deleted, and listed" creates through events.k8s.io/v1 and then
    # lists through core/v1 with `--field-selector source=test-controller`.
    #
    # The stored shape here is core/v1, matching the internal type upstream
    # converts both group-versions into.
    module EventConversion
      API_VERSION = "events.k8s.io/v1"
      STORAGE_API_VERSION = "v1"
      KIND = "Event"

      # events.k8s.io/v1 field -> core/v1 field.  Everything not listed
      # (eventTime, series, action, related, reason, type, reportingInstance,
      # metadata) has the same name in both shapes.
      FIELD_MAP = {
        "regarding" => "involvedObject",
        "note" => "message",
        "deprecatedSource" => "source",
        "deprecatedFirstTimestamp" => "firstTimestamp",
        "deprecatedLastTimestamp" => "lastTimestamp",
        "deprecatedCount" => "count",
        "reportingController" => "reportingComponent"
      }.freeze

      REVERSE_FIELD_MAP = FIELD_MAP.invert.freeze

      # The registry entries that are served over core/v1 Events' storage.
      # api_server_service builds the production registry from this; tests
      # build theirs from the same table so both see one behaviour.
      def self.alias_options_for(group, version, resource)
        return {} unless group.to_s == "events.k8s.io" && resource.to_s == "events" && version.to_s == "v1"

        {storage_group: "", storage_version: "v1", wire_converter: self}
      end

      module_function

      # events.k8s.io/v1 -> the stored core/v1 shape.
      def to_storage(object)
        rename(object, FIELD_MAP, STORAGE_API_VERSION)
      end

      # The stored core/v1 shape -> events.k8s.io/v1.
      def from_storage(object)
        rename(object, REVERSE_FIELD_MAP, API_VERSION)
      end

      def rename(object, mapping, api_version)
        return object unless object.is_a?(Hash)

        result = {}
        object.each do |key, value|
          name = key.to_s
          result[mapping.fetch(name, name)] = value
        end
        result["apiVersion"] = api_version
        result["kind"] = KIND
        result
      end
    end
  end
end
