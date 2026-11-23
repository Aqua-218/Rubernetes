# frozen_string_literal: true

require "date"
require "time"
require_relative "../cron_schedule"
require_relative "manifest_input"

module Rubernetes
  module Rubectl
    # Compute nominal starts locally with the same parser as the controller.
    module CronPreview
      RFC3339 = /\A\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)\z/i
      DEFAULT_COUNT = 5
      MAX_COUNT = 100

      module_function

      def start_time(value)
        raise Client::UsageError, "--from is required for cron" if value.nil?

        if RFC3339.match?(value)
          year, month, day = value[0, 10].split("-").map(&:to_i)
          return Time.iso8601(value).utc if Date.valid_date?(year, month, day, Date::GREGORIAN)
        end
        raise Client::UsageError, "--from must be an RFC3339 timestamp with a UTC offset"
      end

      def for_manifest(input, from:, count:, namespace:)
        resource = input.resource
        return nil unless resource.values_at("apiVersion", "kind") == ["batch/v1", "CronJob"]

        spec = resource["spec"]
        invalid(input, "spec must be an object") unless spec.is_a?(Hash)
        expression, zone_name = spec.values_at("schedule", "timeZone")
        invalid(input, "spec.schedule must be a string") unless expression.is_a?(String)
        invalid(input, "spec.timeZone must be a string") unless zone_name.nil? || zone_name.is_a?(String)

        zone = CronTimeZone.timestamp_zone(zone_name)
        schedule = CronSchedule.parse(expression, time_zone: expression.include?("TZ") ? nil : zone_name)
        metadata = resource["metadata"].is_a?(Hash) ? resource["metadata"].slice("name", "generateName", "namespace") : {}
        metadata["namespace"] = namespace if namespace
        {"apiVersion" => "batch/v1", "kind" => "CronJob", "metadata" => metadata, "suspended" => spec["suspend"] == true,
         "nextRuns" => next_runs(schedule, from, zone, count)}
      rescue CronSchedule::ParseError => error
        invalid(input, error.message)
      rescue TZInfo::InvalidTimezoneIdentifier
        invalid(input, "unknown time zone #{zone_name.inspect}")
      end

      def next_runs(schedule, from, zone, count)
        times = []
        cursor = from
        count.times do
          cursor = schedule.next_after(cursor)
          break unless cursor

          local = CronTimeZone.local_time(cursor, zone)
          times << (local.utc_offset.zero? ? local.getutc : local).iso8601
        end
        times
      end

      def invalid(input, message)
        # Schedule text can come from a Ruby variable. Keep diagnostics on
        # one line so the originating declaration remains unambiguous.
        details = message.gsub(/[[:cntrl:]]/) { |character| character.dump[1...-1] }
        raise ManifestInput::Invalid.new(details, input)
      end
    end
  end
end
