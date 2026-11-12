# frozen_string_literal: true

module Rubernetes
  module Schema
    # Event, for both API groups: pkg/apis/core/validation/events.go.
    module KubernetesValidator
      module_function

      # definition is nil when cross_field_errors is called without one.
      def events_group_definition?(definition)
        !definition.nil? && definition.name.to_s.start_with?("io.k8s.api.events.")
      end

      # pkg/apis/core/validation/events.go ValidateEventCreate/ValidateEventUpdate.
      # core/v1 requests run legacyValidateEvent only; events.k8s.io requests
      # add ObjectMeta, series, eventTime, type and deprecated-field checks.
      # The wire object of events.k8s.io uses the renamed fields (regarding,
      # note, deprecated*); error paths use the internal field names.
      def event_errors(root, operation = :create, old = nil, events_group: false)
        issues = event_legacy_errors(root, events_group)
        return issues unless events_group

        if operation == :update && old.is_a?(Hash)
          issues.concat(event_series_errors(root, events_group)) if event_field(root, "series", events_group) != event_field(old, "series", events_group)
          %w[involvedObject reason message source firstTimestamp lastTimestamp count reason type eventTime action related
             reportingController reportingInstance].each do |name|
            next if event_field(root, name, events_group) == event_field(old, name, events_group)

            issues << issue([name], :invalid, "field is immutable")
          end
          return issues
        end

        issues.concat(event_series_errors(root, events_group))
        issues << issue(%w[eventTime], :required, "") if blank?(fetch(root, "eventTime"))
        type = fetch(root, "type").to_s
        issues << issue(%w[type], :invalid, "has invalid value: #{type}") unless %w[Normal Warning].include?(type)
        issues << issue(%w[firstTimestamp], :invalid, "needs to be unset") unless blank?(event_field(root, "firstTimestamp", events_group))
        issues << issue(%w[lastTimestamp], :invalid, "needs to be unset") unless blank?(event_field(root, "lastTimestamp", events_group))
        count = event_field(root, "count", events_group)
        issues << issue(%w[count], :invalid, "needs to be unset") if count.is_a?(Integer) && count != 0
        source = event_field(root, "source", events_group)
        if source.is_a?(Hash) && (!blank?(fetch(source, "component")) || !blank?(fetch(source, "host")))
          issues << issue(%w[source], :invalid, "needs to be unset")
        end
        issues
      end

      EVENT_WIRE_FIELDS = {
        "involvedObject" => "regarding", "message" => "note", "count" => "deprecatedCount",
        "firstTimestamp" => "deprecatedFirstTimestamp", "lastTimestamp" => "deprecatedLastTimestamp",
        "source" => "deprecatedSource", "reportingComponent" => "reportingController"
      }.freeze

      def event_field(root, name, events_group)
        key = if events_group
                EVENT_WIRE_FIELDS.fetch(name, name)
              else
                (name == "reportingController" ? "reportingComponent" : name)
              end
        fetch(root, key)
      end

      def event_series_errors(root, _events_group)
        series = fetch(root, "series")
        return [] unless series.is_a?(Hash)

        issues = []
        count = fetch(series, "count")
        issues << issue(["series.count"], :invalid, "should be at least 2") unless count.is_a?(Integer) && count >= 2
        issues << issue(["series.lastObservedTime"], :required, "") if blank?(fetch(series, "lastObservedTime"))
        issues
      end

      def event_legacy_errors(root, events_group)
        metadata = fetch(root, "metadata")
        metadata = {} unless metadata.is_a?(Hash)
        namespace = fetch(metadata, "namespace").to_s
        involved = event_field(root, "involvedObject", events_group)
        involved = {} unless involved.is_a?(Hash)
        involved_namespace = fetch(involved, "namespace").to_s
        reporting_field = events_group ? "reportingController" : "reportingComponent"
        issues = []
        if blank?(fetch(root, "eventTime"))
          if involved_namespace.empty?
            issues << issue(%w[involvedObject namespace], :invalid, "does not match event.namespace") unless namespace.empty? || namespace == "default"
          elsif namespace != involved_namespace
            issues << issue(%w[involvedObject namespace], :invalid, "does not match event.namespace")
          end
        else
          if involved_namespace.empty? && namespace != "default" && namespace != "kube-system"
            issues << issue(%w[involvedObject namespace], :invalid, "does not match event.namespace")
          end
          reporting = event_field(root, "reportingController", events_group).to_s
          issues << issue([reporting_field], :required, "") if reporting.empty?
          issues.concat(qualified_name_messages(reporting).map { |message| issue([reporting_field], :invalid, message) })
          instance = fetch(root, "reportingInstance").to_s
          issues << issue(%w[reportingInstance], :required, "") if instance.empty?
          issues << issue(%w[reportingInstance], :invalid, "can have at most 128 characters") if instance.length > 128
          action = fetch(root, "action").to_s
          issues << issue(%w[action], :required, "") if action.empty?
          issues << issue(%w[action], :invalid, "can have at most 128 characters") if action.length > 128
          reason = fetch(root, "reason").to_s
          issues << issue(%w[reason], :required, "") if reason.empty?
          issues << issue(%w[reason], :invalid, "can have at most 128 characters") if reason.length > 128
          message = event_field(root, "message", events_group).to_s
          issues << issue(%w[message], :invalid, "can have at most 1024 characters") if message.length > 1024
        end
        issues.concat(dns1123_subdomain_messages(namespace).map { |message| issue(%w[namespace], :invalid, message) })
        issues
      end
    end
  end
end
