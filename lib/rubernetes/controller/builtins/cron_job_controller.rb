# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class CronJobController < WorkloadController
        DESCRIPTOR = ResourceDescriptor.parse("CronJob")
        JOB = ResourceDescriptor.parse("Job")

        SCHEDULED_TIMESTAMP_ANNOTATION = "batch.kubernetes.io/cronjob-scheduled-timestamp"
        DEFAULT_SUCCESSFUL_JOBS_HISTORY_LIMIT = 3
        DEFAULT_FAILED_JOBS_HISTORY_LIMIT = 1
        NEXT_SCHEDULE_DELAY_SECONDS = 0.1
        JOB_DELETE_OPTIONS = {"propagationPolicy" => "Background"}.freeze

        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          super
        end

        # What one pass over a CronJob works on: the Jobs it owns, the active
        # list being rebuilt, and the writes, events and status it accumulates.
        Sync = Struct.new(:cron_job, :now, :status, :owned_jobs, :active, :operations, :events, keyword_init: true)

        # pkg/controller/cronjob/cronjob_controllerv2.go sync: history cleanup,
        # then syncCronJob for the most recent unmet schedule time.
        def plan(cron_job, store: nil, jobs: nil, now: nil, **_options)
          adapter = store || @adapter
          jobs ||= list_children(adapter, JOB, Support.namespace(cron_job))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          sync = Sync.new(cron_job: cron_job, now: now, status: Support.deep_copy(Support.status(cron_job)),
                          owned_jobs: owned(cron_job, jobs), operations: [], events: [])
          # The stored list is what the previous sync saw; it is used to decide
          # which transitions to report.  The list this sync publishes is
          # rebuilt from the Jobs actually observed, because a pure planner
          # cannot know the uid of a Job it has only asked to create: writing
          # a uid-less placeholder and then matching on uid dropped every
          # reference on the following sync, leaving status.active empty for
          # good -- which also disabled the Forbid concurrency policy.
          previous_active = Array(sync.status["active"]).grep(Hash).map { |reference| Support.deep_copy(reference) }

          # A completed Job still supplies its completion time in the sync
          # that deletes it, even when the history limit is zero.
          cleanup_finished_jobs(cron_job, sync.owned_jobs, previous_active, sync.operations, sync.events)

          # syncCronJob: reconcile the active list against the observed Jobs.
          sync.active = sync.owned_jobs.reject { |job| job_finished_type(job) }.map { |job| job_reference(job) }
          report_job_transitions(sync, previous_active)
          requeue_after = schedule_job(sync)

          if sync.active.empty?
            sync.status.delete("active")
          else
            sync.status["active"] = sync.active
          end
          planned = result(cron_job, sync.operations, status: sync.status, events: sync.events, force_status: !cron_job.key?("status"))
          with_requeue(planned, requeue_after)
        end

        def scale(cron_job, _replicas, **)
          plan(cron_job, **)
        end

        def delete(cron_job, jobs: nil, store: nil, orphan: false)
          adapter = store || @adapter
          jobs ||= list_children(adapter, JOB, Support.namespace(cron_job))
          operations = orphan ? [] : owned(cron_job, jobs).map { |job| operation_delete(job, descriptor: JOB, reason: "cronjob deletion") }
          operations << operation_delete(cron_job, descriptor: DESCRIPTOR, reason: "cronjob deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        private

        # Events for what changed since the previous sync's active list: a Job
        # nobody listed, a listed Job that finished, a listed Job that is gone.
        # A completed Job also advances status.lastSuccessfulTime.
        def report_job_transitions(sync, previous_active)
          sync.owned_jobs.each do |job|
            # A reference this planner wrote before the Job existed carries no
            # uid, so a Job it did create is recognised by name as well.
            in_active = previous_active.any? { |reference| references_job?(reference, job) }
            finished_type = job_finished_type(job)
            if !in_active && finished_type.nil?
              sync.events << {"type" => "Warning", "reason" => "UnexpectedJob",
                              "message" => "Saw a job that the controller did not create or forgot: #{Support.name(job)}"}
            elsif finished_type
              if in_active
                sync.events << {"type" => "Normal", "reason" => "SawCompletedJob",
                                "message" => "Saw completed job: #{Support.name(job)}, condition: #{finished_type}"}
              end
              record_last_successful_time(sync.status, job) if finished_type == "Complete"
            end
          end
          # A Job the previous sync listed as active that no longer exists is
          # reported once; the rebuilt list already excludes it.
          children = sync.owned_jobs.to_h { |job| [Support.uid(job), job] }
          previous_active.each do |reference|
            uid = Support.ref_value(reference, "uid", nil).to_s
            next if uid.empty? || children.key?(uid)

            sync.events << {"type" => "Normal", "reason" => "MissingJob",
                            "message" => "Active job went missing: #{Support.ref_value(reference, "name", "")}"}
          end
        end

        def references_job?(reference, job)
          uid = Support.ref_value(reference, "uid", nil).to_s
          uid.empty? ? Support.ref_value(reference, "name", "").to_s == Support.name(job) : uid == Support.uid(job)
        end

        def record_last_successful_time(status, job)
          completion_time = Support.parse_time(Support.value(Support.status(job), "completionTime", nil))
          last_successful = Support.parse_time(status["lastSuccessfulTime"])
          return unless completion_time && (last_successful.nil? || completion_time > last_successful)

          status["lastSuccessfulTime"] = Support.value(Support.status(job), "completionTime", nil)
        end

        # syncCronJob's scheduling half: validates the time zone, schedule and
        # concurrency policy, starts the Job for the most recent unmet schedule
        # time if one is due, and returns the delay until the next schedule
        # time (nil when the CronJob is not being scheduled).
        def schedule_job(sync)
          cron_job = sync.cron_job
          spec_value = Support.spec(cron_job)
          return nil if Support.metadata(cron_job).key?("deletionTimestamp")

          time_zone = Support.value(spec_value, "timeZone", nil)
          zone = begin
            CronTimeZone.timestamp_zone(time_zone)
          rescue TZInfo::InvalidTimezoneIdentifier
            sync.events << {"type" => "Warning", "reason" => "UnknownTimeZone",
                            "message" => "invalid timeZone: #{time_zone.inspect}: unknown time zone #{time_zone}"}
            return nil
          end
          return nil if Support.value(spec_value, "suspend", false) == true

          expression = Support.value(spec_value, "schedule", "").to_s
          schedule = parse_schedule(sync, expression, time_zone)
          scheduled_at = next_schedule_time(sync, schedule)
          policy = Support.value(spec_value, "concurrencyPolicy", "Allow").to_s
          raise ArgumentError, "unsupported CronJob concurrencyPolicy #{policy.inspect}" unless %w[Allow Forbid Replace].include?(policy)

          start_due_job(sync, scheduled_at, policy, zone)
          next_schedule_delay(sync, schedule)
        rescue CronSchedule::ParseError => error
          sync.events << {"type" => "Warning", "reason" => "UnparseableSchedule", "message" => "unparseable schedule: #{expression.inspect} : #{error.message}"}
          nil
        rescue InvalidSchedule => error
          sync.events << {"type" => "Warning", "reason" => "InvalidSchedule", "message" => "invalid schedule: #{expression} : #{error.message}"}
          nil
        end

        def parse_schedule(sync, expression, time_zone)
          if expression.include?("TZ")
            sync.events << {"type" => "Warning", "reason" => "UnsupportedSchedule",
                            "message" => "CRON_TZ or TZ used in schedule #{expression.inspect} is not officially supported, " \
                                         "see https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/ for more details"}
            time_zone = nil
          end
          CronSchedule.parse(expression, time_zone: time_zone)
        end

        # Starts the Job for +scheduled_at+ unless there is nothing to start,
        # its starting deadline passed, it was already started, or the Forbid
        # policy holds it back behind a running Job.
        def start_due_job(sync, scheduled_at, policy, zone)
          return if scheduled_at.nil? # No unmet start time.

          starting_deadline = Support.value(Support.spec(sync.cron_job), "startingDeadlineSeconds", nil)
          if !starting_deadline.nil? && scheduled_at + Support.integer(starting_deadline, 0) < sync.now
            sync.events << {"type" => "Warning", "reason" => "MissSchedule",
                            "message" => "Missed scheduled time to start a job: #{scheduled_at.utc.strftime("%a, %d %b %Y %H:%M:%S %z")}"}
            return
          end
          # This scheduled time was already processed.
          return if sync.active.any? { |reference| Support.ref_value(reference, "name", "") == job_name(sync.cron_job, scheduled_at) } ||
                    Support.parse_time(sync.status["lastScheduleTime"]) == scheduled_at

          if policy == "Forbid" && sync.active.any?
            sync.events << {"type" => "Normal", "reason" => "JobAlreadyActive",
                            "message" => "Not starting job because prior execution is running and concurrency policy is Forbid"}
            return
          end

          replace_active_jobs(sync) if policy == "Replace"
          start_job(sync, scheduled_at, zone)
          sync.status["lastScheduleTime"] = scheduled_at.utc.iso8601(6)
        end

        # concurrencyPolicy Replace: the running Jobs make way for the new one.
        def replace_active_jobs(sync)
          children = sync.owned_jobs.to_h { |job| [Support.uid(job), job] }
          sync.active.each do |reference|
            job = children[Support.ref_value(reference, "uid", nil).to_s]
            next unless job

            sync.operations << operation_delete(job, descriptor: JOB, reason: "cronjob replace", options: JOB_DELETE_OPTIONS)
            sync.events << {"type" => "Normal", "reason" => "SuccessfulDelete", "message" => "Deleted job #{Support.name(job)}"}
          end
          sync.active = []
        end

        # Creates the Job for +scheduled_at+, or lists the one that already
        # carries its name, and adds it to the active list.
        def start_job(sync, scheduled_at, zone)
          candidate = job_from_template(sync.cron_job, scheduled_at, zone)
          existing = sync.owned_jobs.find { |job| Support.name(job) == Support.name(candidate) }
          if existing
            sync.active << job_reference(existing) unless sync.active.any? do |reference|
              Support.ref_value(reference, "uid", nil).to_s == Support.uid(existing)
            end
            return
          end

          # metrics.CronJobCreationSkew: the new Job's creationTimestamp
          # (whole seconds) less the time it was scheduled for.
          sync.operations << operation_create(candidate, owner: sync.cron_job, descriptor: JOB,
                                                         reason: "cron schedule").observed do |succeeded, _|
            next unless succeeded

            ControllerMetrics.observe("cronjob_controller_job_creation_skew_duration_seconds",
                                      Time.at(Time.now.to_i).utc - scheduled_at)
          end
          sync.events << {"type" => "Normal", "reason" => "SuccessfulCreate", "message" => "Created job #{Support.name(candidate)}"}
          sync.active << job_reference(candidate)
        end

        # cleanupFinishedJobs / removeOldestJobs: finished Jobs beyond the
        # history limits are deleted oldest-first by status.startTime.
        def cleanup_finished_jobs(cron_job, jobs, active, operations, events)
          spec_value = Support.spec(cron_job)
          successful_limit = Support.integer(Support.value(spec_value, "successfulJobsHistoryLimit", DEFAULT_SUCCESSFUL_JOBS_HISTORY_LIMIT),
                                             DEFAULT_SUCCESSFUL_JOBS_HISTORY_LIMIT)
          failed_limit = Support.integer(Support.value(spec_value, "failedJobsHistoryLimit", DEFAULT_FAILED_JOBS_HISTORY_LIMIT),
                                         DEFAULT_FAILED_JOBS_HISTORY_LIMIT)
          successful = jobs.select { |job| job_finished_type(job) == "Complete" }
          failed = jobs.select { |job| job_finished_type(job) == "Failed" }
          [[successful, successful_limit], [failed, failed_limit]].each do |group, limit|
            to_delete = group.length - limit
            next if to_delete <= 0

            group.sort_by { |job| job_start_sort_key(job) }.first(to_delete).each do |job|
              operations << operation_delete(job, descriptor: JOB, reason: "cronjob history limit", options: JOB_DELETE_OPTIONS)
              events << {"type" => "Normal", "reason" => "SuccessfulDelete", "message" => "Deleted job #{Support.name(job)}"}
              active.reject! { |reference| references_job?(reference, job) }
            end
          end
        end

        def job_start_sort_key(job)
          start = Support.parse_time(Support.value(Support.status(job), "startTime", nil))
          [start ? 0 : 1, start ? start.to_f : 0.0, Support.name(job)]
        end

        def job_finished_type(job)
          condition = Array(Support.value(Support.status(job), "conditions", [])).find do |value|
            %w[Complete Failed].include?(Support.value(value, "type", "").to_s) && Support.value(value, "status", "").to_s == "True"
          end
          condition && Support.value(condition, "type", "").to_s
        end

        # getJobName: the schedule time in minutes since the epoch keeps the
        # name deterministic for one nominal start time.
        def job_name(cron_job, scheduled_at)
          "#{Support.name(cron_job)}-#{scheduled_at.to_i / 60}"
        end

        # getJobFromTemplate2
        def job_from_template(cron_job, scheduled_at, zone)
          job_template = Support.value(Support.spec(cron_job), "jobTemplate", {})
          job_template = {} unless job_template.is_a?(Hash)
          job_metadata = Support.value(job_template, "metadata", {})
          job_metadata = {} unless job_metadata.is_a?(Hash)
          labels = Support.value(job_metadata, "labels", {})
          annotations = Support.value(job_metadata, "annotations", {})
          local = CronTimeZone.local_time(scheduled_at, zone)
          timestamp = (local.utc_offset.zero? ? local.utc : local).iso8601
          metadata = {"name" => job_name(cron_job, scheduled_at), "namespace" => Support.namespace(cron_job),
                      "annotations" => (annotations.is_a?(Hash) ? Support.deep_copy(annotations) : {}).merge(
                        SCHEDULED_TIMESTAMP_ANNOTATION => timestamp
                      )}
          metadata["labels"] = Support.deep_copy(labels) if labels.is_a?(Hash) && !labels.empty?
          job_spec = Support.value(job_template, "spec", {})
          candidate = {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => metadata,
                       "spec" => job_spec.is_a?(Hash) ? Support.deep_copy(job_spec) : {}}
          with_owner_metadata(candidate, cron_job)
        end

        def job_reference(job)
          reference = {"apiVersion" => "batch/v1", "kind" => "Job", "name" => Support.name(job),
                       "namespace" => Support.namespace(job), "uid" => Support.uid(job),
                       "resourceVersion" => Support.value(Support.metadata(job), "resourceVersion", nil)}
          reference.reject { |_key, value| value.nil? || value.to_s.empty? }
        end
      end
    end
  end
end
