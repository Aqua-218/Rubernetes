# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/cron_schedule"
require "rubernetes/controller"

class CronScheduleTest < Minitest::Test
  Schedule = Rubernetes::CronSchedule
  Controller = Rubernetes::Controller::CronJobController

  def test_standard_descriptors_and_named_fields
    after = at("2026-01-15T14:26:55.5Z")

    {
      "@hourly" => "2026-01-15T15:00:00Z", "@midnight" => "2026-01-16T00:00:00Z",
      "@daily" => "2026-01-16T00:00:00Z", "@weekly" => "2026-01-18T00:00:00Z",
      "@monthly" => "2026-02-01T00:00:00Z", "@yearly" => "2027-01-01T00:00:00Z",
      "@annually" => "2027-01-01T00:00:00Z", "0 7 * FeB mOn-FrI" => "2026-02-02T07:00:00Z",
      "5/15 * * * *" => "2026-01-15T14:35:00Z"
    }.each do |expression, expected|
      assert_equal at(expected), Schedule.parse(expression).next_after(after), expression
    end
  end

  def test_wildcard_lists_and_stepped_days_use_cron_day_matching
    after = at("2026-01-05T00:00:00Z")

    assert_equal at("2026-01-09T00:00:00Z"), Schedule.parse("0 0 *,15 * fri").next_after(after)
    assert_equal at("2026-01-09T00:00:00Z"), Schedule.parse("0 0 */1 * fri").next_after(after)
    assert_equal at("2026-01-07T00:00:00Z"), Schedule.parse("0 0 ?/2 * fri").next_after(after)
    assert_equal at("2026-01-06T00:00:00Z"), Schedule.parse("0 0 1-31 * fri").next_after(after)
  end

  def test_calendar_reaches_leap_day_and_bounds_impossible_dates
    assert_equal at("2028-02-29T00:00:00Z"), Schedule.parse("0 0 29 feb *").next_after(at("2025-03-01T00:00:00Z"))
    assert_nil Schedule.parse("0 0 29 feb *").next_after(at("2096-03-01T00:00:00Z"))
    assert_nil Schedule.parse("0 0 31 feb *").next_after(at("2026-01-01T00:00:00Z"))
    assert_nil Schedule.parse(", * * * *").next_after(at("2026-01-01T00:00:00Z"))
  end

  def test_daylight_saving_gap_and_repeated_hour
    spring = Schedule.parse("30 2 * * *", time_zone: "America/New_York")

    assert_equal at("2026-03-09T06:30:00Z"), spring.next_after(at("2026-03-08T05:00:00Z"))

    fall = Schedule.parse("CRON_TZ=America/New_York 30 1 * * *")
    first = fall.next_after(at("2026-11-01T04:00:00Z"))

    assert_equal at("2026-11-01T05:30:00Z"), first
    assert_equal at("2026-11-01T06:30:00Z"), fall.next_after(first)
    assert_equal at("2026-01-02T00:00:00+05:30"), Schedule.parse("@daily").next_after(at("2026-01-01T14:20:00+05:30"))
  end

  def test_zone_with_a_skipped_midnight_and_historical_subminute_offset
    zone = "America/Sao_Paulo"
    midnight = Schedule.parse("@daily", time_zone: zone)
    stepped = Schedule.parse("5/15 * * * *", time_zone: zone)

    assert_equal at("2018-11-05T02:00:00Z"), midnight.next_after(at("2018-11-04T02:55:00Z"))
    assert_equal at("1890-03-10T07:26:28Z"), stepped.next_after(at("1890-03-10T07:00:00Z"))
  end

  def test_every_uses_elapsed_time_and_rounds_like_go
    after = at("2026-03-08T06:59:59.9Z")

    assert_equal at("2026-03-08T08:30:00Z"), Schedule.parse("TZ=America/New_York @every 1h30m1.5s").next_after(after)
    assert_equal at("2026-03-08T07:00:00Z"), Schedule.parse("@every -4m").next_after(after)
    assert_equal at("2026-03-08T07:00:00Z"), Schedule.parse("@every 900µs").next_after(after)
    assert_equal at("2026-03-08T07:00:00Z"), Schedule.parse("@every +0").next_after(after)
  end

  def test_parser_reports_the_pinned_go_failure_details
    {
      "" => "empty spec string", "* * *" => "expected exactly 5 fields, found 3: [* * *]",
      "0 0 * * 7" => "end of range (7) above maximum (6): 7",
      "6-4 * * * *" => "beginning of range (6) beyond end of range (4): 6-4",
      "*/0 * * * *" => "step of range should be a positive number: */0",
      "@every 15" => 'failed to parse duration @every 15: time: missing unit in duration "15"',
      "@every 1d" => 'failed to parse duration @every 1d: time: unknown unit "d" in duration "1d"',
      "TZ=UTC" => "invalid schedule format: runtime error: slice bounds out of range [:-1]",
      "CRON_TZ=Asia/Unknown @daily" => "provided bad location Asia/Unknown: unknown time zone Asia/Unknown"
    }.each do |expression, message|
      error = assert_raises(Schedule::ParseError, expression) { Schedule.parse(expression) }
      assert_equal message, error.message
    end
  end

  def test_controller_keeps_interval_phase_when_requeueing_and_applying_deadlines
    resource = cron_job("@every 90s", created: "2026-01-01T00:00:17Z")
    now = at("2026-01-01T00:01:55Z")
    result = Controller.new.plan(resource, jobs: [], now: now)

    assert_equal "2026-01-01T00:01:47.000000Z", result.status.fetch("lastScheduleTime")
    assert_in_delta 82.1, result.requeue_after

    resource["spec"]["startingDeadlineSeconds"] = 20
    result = Controller.new.plan(resource, jobs: [], now: now)

    assert_empty result.creates
    assert_in_delta 82.1, result.requeue_after
  end

  def test_controller_emits_distinct_instants_and_offsets_during_a_fold
    resource = cron_job("30 1 * * *", created: "2026-11-01T04:45:00Z", zone: "America/New_York")
    now = at("2026-11-01T05:30:00Z")
    first = Controller.new.plan(resource, jobs: [], now: now)

    assert_in_delta 3_600.1, first.requeue_after
    assert_equal "2026-11-01T01:30:00-04:00", timestamp_annotation(first)

    resource["status"] = first.status
    second = Controller.new.plan(resource, jobs: [], now: now + 3_600)

    assert_equal "2026-11-01T01:30:00-05:00", timestamp_annotation(second)
    refute_equal first.creates.first.object.dig("metadata", "name"), second.creates.first.object.dig("metadata", "name")
  end

  def test_controller_distinguishes_malformed_schedules_from_impossible_dates
    created = "2026-01-01T00:00:00Z"
    now = at("2026-02-01T00:00:00Z")
    malformed = Controller.new.plan(cron_job("@every 4", created: created), jobs: [], now: now)
    impossible = Controller.new.plan(cron_job("0 0 31 feb *", created: created), jobs: [], now: now)

    assert_equal "UnparseableSchedule", malformed.events.first.fetch("reason")
    assert_includes malformed.events.first.fetch("message"), 'time: missing unit in duration "4"'
    assert_equal "InvalidSchedule", impossible.events.first.fetch("reason")
    assert_nil impossible.requeue_after
    assert_empty impossible.creates
  end

  private

  def timestamp_annotation(result)
    result.creates.first.object.dig("metadata", "annotations", "batch.kubernetes.io/cronjob-scheduled-timestamp")
  end

  def cron_job(schedule, created:, zone: nil)
    spec = {"schedule" => schedule, "jobTemplate" => {"spec" => {"template" => {"spec" => {
      "containers" => [{"name" => "job", "image" => "example/job:1"}], "restartPolicy" => "Never"
    }}}}}
    spec["timeZone"] = zone if zone
    {"apiVersion" => "batch/v1", "kind" => "CronJob", "metadata" => {
      "name" => "sample", "namespace" => "default", "uid" => "uid-cron", "creationTimestamp" => created
    }, "spec" => spec}
  end

  def at(value) = Time.iso8601(value)
end
