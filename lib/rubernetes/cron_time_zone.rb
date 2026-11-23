# frozen_string_literal: true

require "tzinfo"

module Rubernetes
  module CronTimeZone
    NAME_COMPONENT = /\A[A-Za-z._0-9+-]{1,14}\z/
    LEGACY_OFFSET = /\A[+-](?:[01]\d|2[0-3]):[0-5]\d\z/

    module_function

    def validation_errors(name)
      return ["timeZone must be nil or non-empty string"] if name.empty?

      valid_name = name.split("/", -1).all? do |part|
        NAME_COMPONENT.match?(part) && !part.start_with?("-") && !%w[. ..].include?(part)
      end
      return ["unknown time zone #{name}"] unless valid_name

      errors = []
      errors << "timeZone must be an explicit time zone as defined in https://www.iana.org/time-zones" if name.casecmp?("Local")
      # Go has a built-in "Local" location even without a zoneinfo entry.
      TZInfo::Timezone.get(name) unless name == "Local"
      errors
    rescue TZInfo::InvalidTimezoneIdentifier
      errors << "unknown time zone #{name}"
    end

    def validation_error(name) = validation_errors(name).first

    def resolve(name)
      return nil if name.nil? || name.empty?
      return name if LEGACY_OFFSET.match?(name) # Read older CronJobs with fixed offsets.
      return TZInfo::Timezone.get("UTC") if name == "Z"

      TZInfo::Timezone.get(name)
    end

    def local_time(time, zone)
      case zone
      when nil then time.getlocal
      when String then time.getlocal(zone)
      else zone.utc_to_local(time)
      end
    end

    # Go's time.LoadLocation("") uses UTC; an explicitly stored "Local"
    # still refers to the controller's local zone.
    def timestamp_zone(name)
      return "UTC" if name.nil? || name.empty?
      return nil if name == "Local"

      resolve(name)
    end
  end
end
