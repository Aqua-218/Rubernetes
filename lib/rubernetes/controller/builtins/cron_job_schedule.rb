# frozen_string_literal: true

require_relative "../../cron_schedule"

module Rubernetes
  module Controller
    module Builtins
      class CronJobController < WorkloadController
        class InvalidSchedule < ArgumentError; end

        private

        # Kubernetes uses the deadline only when deciding which start is due.
        # Requeue timing counts from the last nominal start (or creation).
        def next_schedule_time(sync, schedule)
          _, latest, missed = most_recent_schedule_time(sync, schedule, include_deadline: true)
          if latest && missed > 100
            sync.events << {"type" => "Warning", "reason" => "TooManyMissedTimes",
                            "message" => "too many missed start times. Set or decrease .spec.startingDeadlineSeconds or check clock skew"}
          end
          latest
        end

        def next_schedule_delay(sync, schedule)
          earliest, latest, missed = most_recent_schedule_time(sync, schedule, include_deadline: false)
          anchor = latest || (missed.zero? ? earliest : sync.now)
          schedule_delay(schedule, anchor, sync.now)
        rescue InvalidSchedule
          schedule_delay(schedule, sync.now, sync.now)
        end

        def schedule_delay(schedule, anchor, now)
          next_time = schedule.next_after(anchor)
          [(next_time - now) + NEXT_SCHEDULE_DELAY_SECONDS, 0.0].max if next_time
        end

        # Kubernetes estimates the missed count from the first two starts, then
        # walks the schedule from near the estimated latest start. Starting
        # there preserves the initial phase of intervals such as @every 90s.
        def most_recent_schedule_time(sync, schedule, include_deadline:)
          earliest = earliest_schedule_time(sync, include_deadline: include_deadline)
          first = schedule.next_after(earliest)
          raise InvalidSchedule, "time difference between two schedules is less than 1 second" unless first
          return [earliest, nil, 0] if sync.now < first

          second = schedule.next_after(first)
          return [earliest, first, 0] if second && sync.now < second

          between = second && (second - first).round
          raise InvalidSchedule, "time difference between two schedules is less than 1 second" if between.nil? || between < 1

          missed = ((sync.now - first).to_i / between) + 1
          potential_earliest = first + ((missed - 2) * between)
          latest = nil
          cursor = schedule.next_after(potential_earliest)
          while cursor && cursor <= sync.now
            latest = cursor
            cursor = schedule.next_after(cursor)
          end
          [earliest, latest, missed]
        end

        def earliest_schedule_time(sync, include_deadline:)
          earliest = Support.parse_time(sync.status["lastScheduleTime"]) || Support.creation_time(sync.cron_job) || Time.at(0).utc
          starting_deadline = Support.value(Support.spec(sync.cron_job), "startingDeadlineSeconds", nil)
          return earliest unless include_deadline && !starting_deadline.nil?

          [earliest, sync.now - Support.integer(starting_deadline, 0)].max
        end
      end
    end
  end
end
