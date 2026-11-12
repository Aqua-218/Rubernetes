# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class CronJobController < WorkloadController
        private

        def supported_time_zone?(value)
          text = value.to_s
          text.empty? || %w[UTC Etc/UTC Z].include?(text) || text.match?(/\A[+-]\d{2}:\d{2}\z/)
        end

        def time_zone_offset(value)
          text = value.to_s
          text.match?(/\A[+-]\d{2}:\d{2}\z/) ? text : "+00:00"
        end

        def cron_fields(schedule)
          expression = schedule.to_s.strip
          case expression
          when "@hourly" then expression = "0 * * * *"
          when "@daily", "@midnight" then expression = "0 0 * * *"
          when "@weekly" then expression = "0 0 * * 0"
          when "@monthly" then expression = "0 0 1 * *"
          when "@yearly", "@annually" then expression = "0 0 1 1 *"
          end
          fields = expression.split(/\s+/)
          return nil unless fields.length == 5
          return nil unless [[0, 0..59], [1, 0..23], [2, 1..31], [3, 1..12], [4, 0..6]].all? do |index, range|
            cron_field_valid?(fields[index], range)
          end

          fields
        end

        def cron_field_valid?(field, range)
          return true if ["*", "?"].include?(field)

          field.split(",").all? do |part|
            base, step = part.split("/", 2)
            next false if step && !step.match?(/\A\d+\z/)
            next true if base == "*"

            first, last = base.split("-", 2)
            [first, last].compact.all? { |value| value.match?(/\A\d+\z/) && range.cover?(Integer(value)) }
          end
        end

        # cron.Schedule.Next: the first minute strictly after `after` that
        # matches every field.  Day-of-month and day-of-week are OR-ed when
        # both are restricted, as in robfig/cron's standard parser.
        def cron_next(fields, after, offset, limit_days: 366)
          minute, hour, day, month, weekday = fields
          cursor = after.getlocal(offset)
          cursor = Time.new(cursor.year, cursor.month, cursor.day, cursor.hour, cursor.min, 0, offset) + 60
          deadline = cursor + (limit_days * 86_400)
          while cursor <= deadline
            day_match = cron_field_match?(day, cursor.day, 1..31)
            weekday_match = cron_field_match?(weekday, cursor.wday, 0..6)
            day_restricted = day != "*" && day != "?"
            weekday_restricted = weekday != "*" && weekday != "?"
            calendar_match = day_restricted && weekday_restricted ? (day_match || weekday_match) : (day_match && weekday_match)
            if calendar_match && cron_field_match?(month, cursor.month, 1..12) &&
               cron_field_match?(hour, cursor.hour, 0..23) && cron_field_match?(minute, cursor.min, 0..59)
              return cursor.utc
            end

            cursor += 60
          end
          nil
        end

        # utils.go mostRecentScheduleTime + nextScheduleTime: the single most
        # recent unmet schedule, with a TooManyMissedTimes warning past 100.
        def next_schedule_time(cron_job, status, now, fields, offset, events)
          earliest = earliest_schedule_time(cron_job, status, now)
          t1 = cron_next(fields, earliest, offset)
          return [nil, 0] if t1.nil? || now < t1

          t2 = cron_next(fields, t1, offset)
          return [t1, 0] if t2.nil? || now < t2

          between = (t2 - t1).round
          raise ArgumentError, "time difference between two schedules is less than 1 second" if between < 1

          missed = ((now - t1).to_i / between) + 1
          potential_earliest = t1 + ((missed - 2) * between)
          most_recent = nil
          cursor = cron_next(fields, potential_earliest, offset)
          while cursor && cursor <= now
            most_recent = cursor
            cursor = cron_next(fields, cursor, offset)
          end
          if missed > 100
            events << {"type" => "Warning", "reason" => "TooManyMissedTimes",
                       "message" => "too many missed start times. Set or decrease .spec.startingDeadlineSeconds or check clock skew"}
          end
          [most_recent, missed]
        end

        # utils.go nextScheduleTimeDuration
        def next_schedule_delay(cron_job, status, now, fields, offset)
          earliest = earliest_schedule_time(cron_job, status, now)
          next_time = cron_next(fields, [earliest, now].max, offset)
          return nil if next_time.nil?

          [(next_time - now) + NEXT_SCHEDULE_DELAY_SECONDS, 0.0].max
        end

        # The time schedules are counted from: the last one started (else the
        # CronJob's creation), but no earlier than the starting deadline allows.
        def earliest_schedule_time(cron_job, status, now)
          earliest = Support.parse_time(status["lastScheduleTime"]) || Support.creation_time(cron_job) || Time.at(0).utc
          starting_deadline = Support.value(Support.spec(cron_job), "startingDeadlineSeconds", nil)
          return earliest if starting_deadline.nil?

          [earliest, now - Support.integer(starting_deadline, 0)].max
        end

        def cron_field_match?(field, value, range)
          return true if ["*", "?"].include?(field)

          field.split(",").any? do |part|
            if part.include?("/")
              base, raw_step = part.split("/", 2)
              step = Integer(raw_step)
              next false unless step.positive?

              first, last = if base == "*"
                              [range.begin, range.end]
                            elsif base.include?("-")
                              base.split("-", 2).map(&:to_i)
                            else
                              [Integer(base), Integer(base)]
                            end
              value.between?(first, last) && ((value - first) % step).zero?
            elsif part.include?("-")
              first, last = part.split("-", 2).map(&:to_i)
              value.between?(first, last)
            else
              Integer(part) == value
            end
          end
        rescue ArgumentError
          false
        end
      end
    end
  end
end
