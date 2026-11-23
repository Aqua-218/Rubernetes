# frozen_string_literal: true

require_relative "../../cron_schedule"
require_relative "../../cron_time_zone"

module Rubernetes
  module Schema
    module KubernetesValidator
      CRONJOB_NAME_MAX = 52
      CRONJOB_POLICIES = %w[Allow Forbid Replace].freeze

      module_function

      # ValidateCronJobSpec checks scheduling before descending into the Job
      # template, and checks history limits after the template.
      def cronjob_schedule_errors(root, old)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        old_spec = fetch(old, "spec")
        issues = cron_schedule_errors(spec, old_spec)
        issues.concat(cron_nonnegative_errors(spec, %w[startingDeadlineSeconds]))
        zone = fetch(spec, "timeZone")
        if zone.is_a?(String) && zone != fetch(old_spec, "timeZone")
          CronTimeZone.validation_errors(zone).each { |message| issues << issue(%w[spec timeZone], :invalid, message) }
        end
        policy = fetch(spec, "concurrencyPolicy")
        if policy.is_a?(String) && !policy.empty? && !CRONJOB_POLICIES.include?(policy)
          issues << issue(%w[spec concurrencyPolicy], :unsupported, unsupported_detail(CRONJOB_POLICIES))
        end
        issues
      end

      def cronjob_history_and_name_errors(root, operation)
        issues = cron_nonnegative_errors(fetch(root, "spec"), %w[successfulJobsHistoryLimit failedJobsHistoryLimit])
        name = fetch(fetch(root, "metadata"), "name")
        message = cronjob_name_error(name) if operation == :create
        issues << issue(%w[metadata name], :invalid, message) if message
        issues
      end

      def cronjob_name_error(name)
        "must be no more than #{CRONJOB_NAME_MAX} characters" if name.is_a?(String) && name.bytesize > CRONJOB_NAME_MAX
      end

      def cron_nonnegative_errors(spec, fields)
        fields.filter_map do |field|
          value = fetch(spec, field)
          issue(["spec", field], :invalid, IS_NEGATIVE_ERROR_MSG) if value.is_a?(Integer) && value.negative?
        end
      end

      def cron_schedule_errors(spec, old_spec)
        schedule = fetch(spec, "schedule")
        path = %w[spec schedule]
        return [issue(path, :required, "")] if schedule.nil? || schedule == ""
        return [] unless schedule.is_a?(String)

        issues = []
        begin
          CronSchedule.parse(schedule)
        rescue CronSchedule::ParseError => error
          issues << issue(path, :invalid, error.message)
        end
        if schedule.include?("TZ")
          if !fetch(old_spec, "schedule").to_s.include?("TZ")
            issues << issue(path, :invalid, "cannot use TZ or CRON_TZ in schedule, use timeZone field instead")
          elsif !fetch(spec, "timeZone").nil?
            issues << issue(path, :invalid, "cannot use both timeZone field and TZ or CRON_TZ in schedule")
          end
        end
        issues
      end
    end
  end
end
