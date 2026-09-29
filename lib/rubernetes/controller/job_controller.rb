# frozen_string_literal: true

require "set"
require "time"
require_relative "support"
require_relative "types"

module Rubernetes
  module Controller
    module Builtins
      # Job controller following pkg/controller/job at Kubernetes v1.36.2.
      #
      # The planner is pure: it derives the complete desired write set from the
      # Job, its owned Pods, and the supplied clock.  Upstream keeps a small
      # in-memory backoff store; here the same information is recomputed from
      # the observed Pod finish times so a leader hand-over cannot lose it.
      class JobController < WorkloadController
        DESCRIPTOR = ResourceDescriptor.parse("Job")
        POD = WorkloadController::POD
        LABEL_PREFIX = "batch.kubernetes.io/".freeze
        TRACKING_FINALIZER = "#{LABEL_PREFIX}job-tracking".freeze
        COMPLETION_INDEX_ANNOTATION = "#{LABEL_PREFIX}job-completion-index".freeze
        INDEX_FAILURE_COUNT_ANNOTATION = "#{LABEL_PREFIX}job-index-failure-count".freeze
        INDEX_IGNORED_FAILURE_COUNT_ANNOTATION = "#{LABEL_PREFIX}job-index-ignored-failure-count".freeze
        COMPLETION_INDEX_ENV = "JOB_COMPLETION_INDEX".freeze
        JOB_CONTROLLER_NAME = "kubernetes.io/job-controller".freeze
        UNKNOWN_COMPLETION_INDEX = -1
        # pkg/controller/job/job_controller.go:76-86
        DEFAULT_POD_FAILURE_BACKOFF_SECONDS = 10.0
        MAX_POD_FAILURE_BACKOFF_SECONDS = 600.0
        MAX_UNCOUNTED_PODS = 500
        MAX_POD_CREATE_DELETE_PER_SYNC = 500
        SLOW_START_INITIAL_BATCH_SIZE = 1
        # apps validation: backoffLimit defaults to MaxInt32 when only per-index
        # limits are declared (pkg/apis/batch/v1/defaults.go).
        BACKOFF_LIMIT_WITH_PER_INDEX = 2**31 - 1
        POD_PHASE_ORDINAL = {"Pending" => 0, "Unknown" => 1, "Running" => 2}.freeze

        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          super(**options)
        end

        def orphan_cleanup?
          true
        end

        # pkg/controller/job/job_controller.go syncOrphanPod: a Pod that still
        # carries the tracking finalizer after its Job is gone has no sync
        # left to release it.  Kubernetes removes the finalizer so the Pod can
        # actually be deleted -- without this the Pod stays Terminating and
        # its namespace never leaves Terminating either.
        def plan_orphans(key, store: nil)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          return nil unless adapter

          namespace, _, job_name = key.to_s.partition("/")
          return nil if namespace.empty? || job_name.empty?

          # syncOrphanPod removes the tracking finalizer from any Pod that has
          # it and is not controlled by a live Job -- it checks the Pod's
          # controllerRef and nothing else, because a Pod whose Job was deleted
          # with --cascade=orphan has had its owner reference STRIPPED and no
          # longer names the Job at all.  Matching on the Job's name instead
          # left exactly those Pods holding the finalizer for ever: Succeeded,
          # Terminating, and unremovable, which also keeps their namespace
          # from finishing its own deletion.
          orphans = list_children(adapter, POD, namespace).select do |pod|
            tracking_finalizer?(pod) &&
              (orphaned_by?(pod, job_name, adapter) || unowned_tracked_pod?(pod, adapter))
          end
          return nil if orphans.empty?

          operations = orphans.map do |pod|
            candidate = Support.deep_copy(pod)
            candidate["metadata"] ||= {}
            candidate["metadata"]["finalizers"] =
              Array(candidate["metadata"]["finalizers"]).reject { |value| value == TRACKING_FINALIZER }
            operation_update(pod, candidate, descriptor: POD, reason: "orphan job tracking finalizer removal")
          end
          ReconcileResult.new(operations: operations, status: nil, batches: nil, events: [],
                              controller: name, key: key.to_s)
        end

        def plan(job, store: nil, pods: nil, now: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= list_children(adapter, POD, Support.namespace(job))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          return result(job, []) if finished?(job)
          if externally_managed?(job)
            count_external_job(job)
            return result(job, [])
          end

          completion_mode = Support.value(Support.spec(job), "completionMode", "NonIndexed").to_s
          unless %w[NonIndexed Indexed].include?(completion_mode)
            return result(job, [], events: [event("Warning", "UnknownCompletionMode",
                                                     "Skipped Job sync because completion mode is unknown")])
          end

          all_pods = Array(pods)
          owned_pods = owned(job, all_pods)
          release = release_operations(job, owned_pods)
          owned_pods -= release.fetch(:pods)
          adoption = adoption_operations(job, all_pods)
          owned_pods += adoption.fetch(:pods)
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          instrument(job, Sync.new(self, job, owned_pods, now).run(release.fetch(:operations) + adoption.fetch(:operations)), started, completion_mode)
        end

        # job/metrics: the sync (by what it did), the Pods it creates, and --
        # once the status write went through -- the Pods and indexes that
        # finished and the Job itself finishing.
        def instrument(job, planned, started, completion_mode)
          creates = planned.operations.select { |operation| operation.create? && operation.resource.kind == "Pod" }
          deletes = planned.operations.select { |operation| operation.delete? && operation.resource.kind == "Pod" }
          action = if deletes.any? then "pods_deleted"
                   elsif creates.any? then "pods_created"
                   else "tracking"
                   end
          labels = {"completion_mode" => completion_mode, "result" => "success", "action" => action}
          ControllerMetrics.observe("job_controller_job_sync_duration_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
          ControllerMetrics.increment("job_controller_job_syncs_total", labels)
          reason = creation_reason(job)
          old_status = Support.status(job)
          planned.map_operations do |operation|
            if creates.include?(operation)
              operation.observed do |succeeded, _|
                ControllerMetrics.increment("job_controller_job_pods_creation_total", {"reason" => reason, "status" => succeeded ? "succeeded" : "failed"})
              end
            elsif operation.action == :status_update && operation.resource.kind == "Job"
              operation.observed { |succeeded, _| record_status_counters(job, old_status, operation.patch || planned.status, completion_mode) if succeeded }
            else
              operation
            end
          end
        end

        # recordJobPodsCreationTotal with JobPodReplacementPolicy (GA).
        def creation_reason(job)
          status = Support.status(job)
          failed = Support.integer(Support.value(status, "failed", 0), 0)
          terminating = Support.integer(Support.value(status, "terminating", 0), 0)
          if Support.value(Support.spec(job), "podReplacementPolicy", "TerminatingOrFailed").to_s == "Failed" && failed.positive?
            "recreate_failed"
          elsif failed.positive? || terminating.positive?
            "recreate_terminating_or_failed"
          else
            "new"
          end
        end

        # recordJobPodFinished / recordJobFinished.
        def record_status_counters(job, old_status, new_status, completion_mode)
          return unless new_status.is_a?(Hash)

          if indexed?(job)
            count = Support.integer(Support.value(Support.spec(job), "completions", 0), 0)
            backoff = backoff_limit_per_index?(job) ? "perIndex" : "global"
            total = ->(status, field) { intervals_total(parse_indexes(Support.value(status, field, nil), count)) }
            succeeded = total.call(new_status, "completedIndexes") - total.call(old_status, "completedIndexes")
            ControllerMetrics.increment("job_controller_job_finished_indexes_total", {"status" => "succeeded", "backoffLimit" => backoff}, by: succeeded)
            if backoff_limit_per_index?(job)
              failed_indexes = total.call(new_status, "failedIndexes") - total.call(old_status, "failedIndexes")
              ControllerMetrics.increment("job_controller_job_finished_indexes_total", {"status" => "failed", "backoffLimit" => backoff}, by: failed_indexes) if failed_indexes.positive?
            end
          else
            succeeded = Support.integer(Support.value(new_status, "succeeded", 0), 0) - Support.integer(Support.value(old_status, "succeeded", 0), 0)
          end
          ControllerMetrics.increment("job_controller_job_pods_finished_total", {"completion_mode" => completion_mode, "result" => "succeeded"}, by: succeeded)
          failed = Support.integer(Support.value(new_status, "failed", 0), 0) - Support.integer(Support.value(old_status, "failed", 0), 0)
          ControllerMetrics.increment("job_controller_job_pods_finished_total", {"completion_mode" => completion_mode, "result" => "failed"}, by: failed)
          finished = Array(Support.value(new_status, "conditions", [])).find do |condition|
            %w[Complete Failed].include?(Support.value(condition, "type", "").to_s) && Support.value(condition, "status", "").to_s == "True"
          end
          was = Array(Support.value(old_status, "conditions", [])).any? do |condition|
            %w[Complete Failed].include?(Support.value(condition, "type", "").to_s) && Support.value(condition, "status", "").to_s == "True"
          end
          return if finished.nil? || was

          result = Support.value(finished, "type", "") == "Complete" ? "succeeded" : "failed"
          ControllerMetrics.increment("job_controller_jobs_finished_total",
                                      {"completion_mode" => completion_mode, "result" => result, "reason" => Support.value(finished, "reason", "").to_s})
        end

        # addJob: a Job another controller manages, once.
        EXTERNAL_JOBS = Set.new
        EXTERNAL_JOBS_MUTEX = Mutex.new

        def count_external_job(job)
          first = EXTERNAL_JOBS_MUTEX.synchronize { EXTERNAL_JOBS.add?(Support.uid(job).to_s) }
          ControllerMetrics.increment("job_controller_jobs_by_external_controller_total",
                                      {"controller_name" => Support.value(Support.spec(job), "managedBy", "").to_s}) if first
        end

        def scale(job, replicas, pods: nil, store: nil)
          candidate = Support.deep_copy(job)
          candidate["spec"] ||= {}
          candidate["spec"]["parallelism"] = Integer(replicas)
          plan(candidate, pods: pods, store: store)
        end

        def delete(job, pods: nil, store: nil, orphan: false)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= list_children(adapter, POD, Support.namespace(job))
          operations = orphan ? [] : owned(job, pods).map { |pod| operation_delete(pod, descriptor: POD, reason: "job deletion") }
          operations << operation_delete(job, descriptor: DESCRIPTOR, reason: "job deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        # ---- shared predicates -------------------------------------------------

        def finished?(job)
          Array(Support.value(Support.status(job), "conditions", [])).any? do |condition|
            %w[Complete Failed].include?(Support.value(condition, "type", "").to_s) &&
              Support.value(condition, "status", "").to_s == "True"
          end
        end

        def externally_managed?(job)
          managed_by = Support.value(Support.spec(job), "managedBy", nil)
          !managed_by.nil? && managed_by.to_s != JOB_CONTROLLER_NAME
        end

        def indexed?(job)
          Support.value(Support.spec(job), "completionMode", "NonIndexed").to_s == "Indexed"
        end

        def backoff_limit_per_index?(job)
          !Support.value(Support.spec(job), "backoffLimitPerIndex", nil).nil?
        end

        def suspended?(job)
          Support.value(Support.spec(job), "suspend", false) == true
        end

        def completions(job)
          raw = Support.value(Support.spec(job), "completions", nil)
          return nil if raw.nil?

          value = Support.integer(raw, 0)
          raise ArgumentError, "completions must be non-negative" if value.negative?
          value
        end

        def parallelism(job)
          value = Support.integer(Support.value(Support.spec(job), "parallelism", 1), 1)
          raise ArgumentError, "parallelism must be non-negative" if value.negative?
          value
        end

        def backoff_limit(job)
          raw = Support.value(Support.spec(job), "backoffLimit", nil)
          return backoff_limit_per_index?(job) ? BACKOFF_LIMIT_WITH_PER_INDEX : 6 if raw.nil?

          value = Support.integer(raw, 6)
          raise ArgumentError, "backoffLimit must be non-negative" if value.negative?
          value
        end

        def pod_failure_policy(job)
          policy = Support.value(Support.spec(job), "podFailurePolicy", nil)
          policy.is_a?(Hash) ? policy : nil
        end

        # pkg/controller/job/job_controller.go:2270
        def only_replace_failed_pods?(job)
          policy = Support.value(Support.spec(job), "podReplacementPolicy", nil).to_s
          policy == "Failed" || !pod_failure_policy(job).nil?
        end

        def pod_phase(pod)
          Support.value(Support.status(pod), "phase", "").to_s
        end

        def pod_terminal?(pod)
          %w[Succeeded Failed].include?(pod_phase(pod))
        end

        def pod_deleting?(pod)
          !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?
        end

        # controller.IsPodActive
        def pod_active?(pod)
          !pod_terminal?(pod) && !pod_deleting?(pod)
        end

        # controller.IsPodTerminating
        def pod_terminating?(pod)
          !pod_terminal?(pod) && pod_deleting?(pod)
        end

        def pod_ready?(pod)
          condition = Support.condition(pod, "Ready")
          !condition.nil? && Support.value(condition, "status", "").to_s == "True"
        end

        # The Pod names a controlling Job that the store no longer holds.
        def orphaned_by?(pod, job_name, adapter)
          reference = Support.owner_references(pod).find do |owner|
            flag = Support.ref_value(owner, "controller", false)
            (flag == true || flag.to_s.casecmp("true").zero?) &&
              Support.ref_value(owner, "kind", "").to_s == "Job" &&
              Support.ref_value(owner, "name", "").to_s == job_name.to_s
          end
          return false unless reference

          adapter.find(DESCRIPTOR, name: job_name.to_s, namespace: Support.namespace(pod)).nil?
        end

        # True when no live Job controls this Pod: either it has no controlling
        # Job reference at all, or the Job it names is gone.
        def unowned_tracked_pod?(pod, adapter)
          reference = Support.owner_references(pod).find do |owner|
            flag = Support.ref_value(owner, "controller", false)
            (flag == true || flag.to_s.casecmp("true").zero?) &&
              Support.ref_value(owner, "kind", "").to_s == "Job"
          end
          return true if reference.nil?

          adapter.find(DESCRIPTOR, name: Support.ref_value(reference, "name", "").to_s,
                                   namespace: Support.namespace(pod)).nil?
        end

        def tracking_finalizer?(pod)
          Array(Support.value(Support.metadata(pod), "finalizers", [])).include?(TRACKING_FINALIZER)
        end

        # pkg/controller/job/job_controller.go:2169
        def pod_failed?(pod, job)
          return true if pod_phase(pod) == "Failed"
          return false if only_replace_failed_pods?(job)

          pod_deleting?(pod) && pod_phase(pod) != "Succeeded"
        end

        def completion_index(pod)
          raw = Support.annotations(pod)[COMPLETION_INDEX_ANNOTATION]
          return UNKNOWN_COMPLETION_INDEX if raw.nil?

          value = Integer(raw.to_s, 10)
          value.negative? ? UNKNOWN_COMPLETION_INDEX : value
        rescue ArgumentError, TypeError
          UNKNOWN_COMPLETION_INDEX
        end

        def index_failure_count(pod)
          parse_int32(Support.annotations(pod)[INDEX_FAILURE_COUNT_ANNOTATION])
        end

        def index_ignored_failure_count(pod)
          parse_int32(Support.annotations(pod)[INDEX_IGNORED_FAILURE_COUNT_ANNOTATION])
        end

        def index_absolute_failure_count(pod)
          index_failure_count(pod) + index_ignored_failure_count(pod)
        end

        def parse_int32(raw)
          return 0 if raw.nil?

          value = Integer(raw.to_s, 10)
          value.negative? || value > 2**31 - 1 ? 0 : value
        rescue ArgumentError, TypeError
          0
        end

        # pkg/controller/job/backoff_utils.go:174
        def finish_time(pod)
          from_containers(pod) || from_ready_false(pod) || from_deletion(pod) || Support.creation_time(pod) || Time.at(0).utc
        end

        # pkg/controller/job/pod_failure_policy.go:36
        # Returns [job_failure_message, count_failed, action].
        def match_pod_failure_policy(policy, pod)
          return [nil, true, nil] if policy.nil?

          Array(Support.value(policy, "rules", [])).each_with_index do |rule, index|
            action = Support.value(rule, "action", "").to_s
            exit_codes = Support.value(rule, "onExitCodes", nil)
            conditions = Support.value(rule, "onPodConditions", nil)
            if exit_codes.is_a?(Hash)
              container_status = match_on_exit_codes(pod, exit_codes)
              next unless container_status

              case action
              when "Ignore" then return [nil, false, "Ignore"]
              when "FailIndex" then return [nil, true, "FailIndex"]
              when "Count" then return [nil, true, "Count"]
              when "FailJob"
                code = Support.value(Support.value(Support.value(container_status, "state", {}), "terminated", {}), "exitCode", 0)
                message = "Container #{Support.value(container_status, 'name', '')} for pod #{Support.namespace(pod)}/#{Support.name(pod)} " \
                          "failed with exit code #{code} matching #{action} rule at index #{index}"
                return [message, true, "FailJob"]
              end
            elsif !conditions.nil?
              condition = match_on_pod_conditions(pod, Array(conditions))
              next unless condition

              case action
              when "Ignore" then return [nil, false, "Ignore"]
              when "FailIndex" then return [nil, true, "FailIndex"]
              when "Count" then return [nil, true, "Count"]
              when "FailJob"
                message = "Pod #{Support.namespace(pod)}/#{Support.name(pod)} has condition #{Support.value(condition, 'type', '')} " \
                          "matching #{action} rule at index #{index}"
                return [message, true, "FailJob"]
              end
            end
          end
          [nil, true, nil]
        end

        # ---- ordered interval helpers (indexed_job_utils.go) ------------------

        def parse_indexes(text, completions)
          return [] if text.nil? || text.to_s.empty?

          result = []
          text.to_s.split(",").each do |interval|
            limits = interval.split("-")
            first = Integer(limits.fetch(0), 10)
            break if first >= completions

            last = limits.length > 1 ? Integer(limits.fetch(1), 10) : first
            last = completions - 1 if last >= completions
            if result.any? && result.last[1] == first - 1
              result.last[1] = last
            else
              result << [first, last]
            end
          rescue ArgumentError, TypeError, IndexError
            # A corrupted interval is skipped, matching the upstream tolerance
            # for user-edited status strings.
            next
          end
          result
        end

        def intervals_with_indexes(intervals, indexes)
          merge_intervals(intervals, indexes.sort.map { |index| [index, index] })
        end

        def merge_intervals(left, right)
          result = []
          i = 0
          j = 0
          append = lambda do |interval|
            last = result.last
            if last && last[1] >= interval[0] - 1
              last[1] = [last[1], interval[1]].max
            else
              result << interval.dup
            end
          end
          while i < left.length && j < right.length
            if left[i][0] < right[j][0]
              append.call(left[i])
              i += 1
            else
              append.call(right[j])
              j += 1
            end
          end
          left[i..].to_a.each { |interval| append.call(interval) }
          right[j..].to_a.each { |interval| append.call(interval) }
          result
        end

        def intervals_total(intervals)
          intervals.sum { |first, last| last - first + 1 }
        end

        def intervals_include?(intervals, index)
          intervals.any? { |first, last| index >= first && index <= last }
        end

        def intervals_to_s(intervals)
          intervals.map { |first, last| first == last ? first.to_s : "#{first}-#{last}" }.join(",")
        end

        def event(type, reason, message)
          {"type" => type, "reason" => reason, "message" => message}
        end

        def new_condition(type, status, reason, message, now)
          condition = {"type" => type, "status" => status,
                       "lastProbeTime" => now.utc.iso8601(6), "lastTransitionTime" => now.utc.iso8601(6)}
          condition["reason"] = reason unless reason.to_s.empty?
          condition["message"] = message unless message.to_s.empty?
          condition
        end

        # pkg/controller/job/job_controller.go:2154
        def ensure_condition_status(list, type, status, reason, message, now)
          values = Array(list).map { |condition| Support.deep_copy(condition) }
          index = values.index { |condition| Support.value(condition, "type", "").to_s == type }
          if index
            current = values.fetch(index)
            unchanged = Support.value(current, "status", "").to_s == status &&
                        Support.value(current, "reason", "").to_s == reason.to_s &&
                        Support.value(current, "message", "").to_s == message.to_s
            return [values, false] if unchanged

            values[index] = new_condition(type, status, reason, message, now)
            return [values, true]
          end
          return [values, false] if status == "False"

          [values + [new_condition(type, status, reason, message, now)], true]
        end

        def find_condition(list, type)
          Array(list).find { |condition| Support.value(condition, "type", "").to_s == type }
        end

        # Exposed so a Sync can build create/delete/update operations through
        # the inherited BaseController helpers.
        public :operation_create, :operation_delete, :operation_update, :operation_status, :pod_for, :result

        private

        # ReleasePod: an owned Pod whose labels stopped matching the selector
        # loses this Job's owner reference and its tracking finalizer, so
        # another controller may adopt it and it is no longer counted.
        def release_operations(job, owned_pods)
          selector = Support.value(Support.spec(job), "selector", nil)
          return {pods: [], operations: []} if selector.nil? || (selector.is_a?(Hash) && selector.empty?)

          released = Array(owned_pods).reject { |pod| Support.selector_matches?(selector, pod) }
          operations = released.filter_map do |pod|
            candidate = Support.deep_copy(pod)
            candidate["metadata"] ||= {}
            candidate["metadata"]["ownerReferences"] = Support.owner_references(pod).map { |reference| Support.deep_copy(reference) }.reject do |reference|
              Support.ref_value(reference, "uid", nil).to_s == Support.uid(job).to_s
            end
            finalizers = Array(candidate["metadata"]["finalizers"]) - [TRACKING_FINALIZER]
            if finalizers.empty?
              candidate["metadata"].delete("finalizers")
            else
              candidate["metadata"]["finalizers"] = finalizers
            end
            operation_update(pod, candidate, descriptor: POD, reason: "job pod release")
          end
          {pods: released, operations: operations}
        end

        def adoption_operations(job, pods)
          selector = Support.value(Support.spec(job), "selector", nil)
          return {pods: [], operations: []} if selector.nil? || (selector.is_a?(Hash) && selector.empty?)
          return {pods: [], operations: []} if pod_deleting?(job)

          adoptable = pods.select do |pod|
            Support.namespace(pod).to_s == Support.namespace(job).to_s &&
              !pod_deleting?(pod) &&
              Support.selector_matches?(selector, pod) &&
              Support.owner_references(pod).none? do |reference|
                flag = Support.ref_value(reference, "controller", false)
                flag == true || flag.to_s.casecmp("true").zero?
              end
          end
          adopted = adoptable.map do |pod|
            candidate = Support.deep_copy(pod)
            candidate["metadata"] ||= {}
            references = Support.owner_references(candidate).map { |reference| Support.deep_copy(reference) }
            references << Support.owner_reference(job)
            candidate["metadata"]["ownerReferences"] = references
            finalizers = Array(candidate["metadata"]["finalizers"]).dup
            finalizers << TRACKING_FINALIZER unless finalizers.include?(TRACKING_FINALIZER)
            candidate["metadata"]["finalizers"] = finalizers
            candidate
          end
          {pods: adopted, operations: adopted.each_with_index.filter_map do |candidate, index|
            operation_update(adoptable.fetch(index), candidate, descriptor: POD, reason: "job pod adoption")
          end}
        end

        def from_containers(pod)
          status = Support.status(pod)
          finish = latest_finish_time(nil, Array(Support.value(status, "containerStatuses", [])))
          return nil if finish == :unfinished

          sidecars = Array(Support.value(Support.spec(pod), "initContainers", [])).filter_map do |container|
            Support.value(container, "name", nil) if Support.value(container, "restartPolicy", "").to_s == "Always"
          end
          sidecar_statuses = Array(Support.value(status, "initContainerStatuses", [])).select do |container|
            sidecars.include?(Support.value(container, "name", nil))
          end
          finish = latest_finish_time(finish, sidecar_statuses)
          finish == :unfinished ? nil : finish
        end

        def latest_finish_time(previous, statuses)
          finish = previous
          statuses.each do |container|
            terminated = Support.value(Support.value(container, "state", {}), "terminated", nil)
            finished_at = terminated && Support.parse_time(Support.value(terminated, "finishedAt", nil))
            return :unfinished if finished_at.nil?

            finish = finished_at if finish.nil? || finish < finished_at
          end
          finish
        end

        def from_ready_false(pod)
          condition = Support.condition(pod, "Ready")
          return nil unless condition && Support.value(condition, "status", "").to_s == "False"

          Support.parse_time(Support.value(condition, "lastTransitionTime", nil))
        end

        def from_deletion(pod)
          metadata = Support.metadata(pod)
          deletion = Support.parse_time(Support.value(metadata, "deletionTimestamp", nil))
          return nil unless deletion

          deletion - Support.integer(Support.value(metadata, "deletionGracePeriodSeconds", 0), 0)
        end

        def match_on_exit_codes(pod, requirement)
          status = Support.status(pod)
          match_container_list(Array(Support.value(status, "containerStatuses", [])), requirement) ||
            match_container_list(Array(Support.value(status, "initContainerStatuses", [])), requirement)
        end

        def match_container_list(statuses, requirement)
          container_name = Support.value(requirement, "containerName", nil)
          statuses.find do |container|
            terminated = Support.value(Support.value(container, "state", {}), "terminated", nil)
            next false if terminated.nil?
            next false unless container_name.nil? || container_name.to_s == Support.value(container, "name", "").to_s

            code = Support.integer(Support.value(terminated, "exitCode", 0), 0)
            next false if code.zero?

            values = Array(Support.value(requirement, "values", [])).map { |value| Support.integer(value, 0) }
            case Support.value(requirement, "operator", "").to_s
            when "In" then values.include?(code)
            when "NotIn" then !values.include?(code)
            else false
            end
          end
        end

        def match_on_pod_conditions(pod, patterns)
          Array(Support.value(Support.status(pod), "conditions", [])).find do |condition|
            patterns.any? do |pattern|
              Support.value(pattern, "type", "").to_s == Support.value(condition, "type", "").to_s &&
                Support.value(pattern, "status", "").to_s == Support.value(condition, "status", "").to_s
            end
          end
        end

        # One reconcile pass.  It mirrors syncJob, manageJob, and
        # trackJobStatusAndRemoveFinalizers, but returns the write set instead
        # of issuing API calls.
        class Sync
          def initialize(controller, job, pods, now)
            @c = controller
            @job = job
            @pods = pods
            @now = now
            @operations = []
            @events = []
            @requeue_after = nil
          end

          def run(preliminary_operations)
            @operations.concat(preliminary_operations)
            job = @job
            status = Support.deep_copy(Support.status(job))
            status["uncountedTerminatedPods"] = {} unless status["uncountedTerminatedPods"].is_a?(Hash)
            uncounted_succeeded = Set.new(Array(status["uncountedTerminatedPods"]["succeeded"]).map(&:to_s))
            uncounted_failed = Set.new(Array(status["uncountedTerminatedPods"]["failed"]).map(&:to_s))
            active_pods = @pods.select { |pod| @c.pod_active?(pod) }
            active = active_pods.length
            ready = active_pods.count { |pod| @c.pod_ready?(pod) }
            terminating = @pods.count { |pod| @c.pod_terminating?(pod) }
            indexed = @c.indexed?(job)
            completions = @c.completions(job)
            raise ArgumentError, "Indexed Jobs require spec.completions" if indexed && completions.nil?

            new_succeeded = valid_pods(uncounted_succeeded) { |pod| @c.pod_phase(pod) == "Succeeded" }
            new_failed = valid_pods(uncounted_failed) { |pod| @c.pod_failed?(pod, job) }
            succeeded = Support.integer(status["succeeded"], 0) + new_succeeded.length + uncounted_succeeded.length
            failed = Support.integer(status["failed"], 0) + non_ignored_failed_count(new_failed) + uncounted_failed.length

            suspended = @c.suspended?(job)
            status["startTime"] = @now.utc.iso8601(6) if status["startTime"].nil? && !suspended
            start_time = Support.parse_time(status["startTime"])

            finished = nil
            exceeds_backoff = failed > @c.backoff_limit(job)
            finished = success_criteria_met_condition(status)
            if finished.nil?
              failure_target = @c.find_condition(status["conditions"], "FailureTarget")
              if failure_target && Support.value(failure_target, "status", "").to_s == "True"
                finished = @c.new_condition("Failed", "True", Support.value(failure_target, "reason", ""),
                                            Support.value(failure_target, "message", ""), @now)
              elsif (message = fail_job_message)
                finished = @c.new_condition("FailureTarget", "True", "PodFailurePolicy", message, @now)
              end
            end
            if finished.nil?
              if exceeds_backoff || past_backoff_limit_on_failure?
                finished = @c.new_condition("FailureTarget", "True", "BackoffLimitExceeded",
                                            "Job has reached the specified backoff limit", @now)
              elsif past_active_deadline?(start_time, suspended)
                finished = @c.new_condition("FailureTarget", "True", "DeadlineExceeded",
                                            "Job was active longer than specified deadline", @now)
              elsif active_deadline_seconds && !suspended && start_time
                @requeue_after = [active_deadline_seconds - (@now - start_time), 0.0].max
              end
            end

            prev_succeeded_indexes = []
            succeeded_indexes = []
            failed_indexes = nil
            delayed_deletion = {}
            if indexed
              prev_succeeded_indexes = @c.parse_indexes(status["completedIndexes"], completions)
              succeeded_indexes = calculate_succeeded_indexes(prev_succeeded_indexes, completions)
              succeeded = @c.intervals_total(succeeded_indexes)
              if @c.backoff_limit_per_index?(job)
                failed_indexes = calculate_failed_indexes(completions)
                if finished.nil?
                  max_failed = Support.value(Support.spec(job), "maxFailedIndexes", nil)
                  failed_total = @c.intervals_total(failed_indexes)
                  if !max_failed.nil? && failed_total > Support.integer(max_failed, 0)
                    finished = @c.new_condition("FailureTarget", "True", "MaxFailedIndexesExceeded",
                                                "Job has exceeded the specified maximal number of failed indexes", @now)
                  elsif failed_total.positive? && failed_total + @c.intervals_total(succeeded_indexes) >= completions
                    finished = @c.new_condition("FailureTarget", "True", "FailedIndexes", "Job has failed indexes", @now)
                  end
                end
                delayed_deletion = pods_with_delayed_deletion_per_index(active_pods, succeeded_indexes, failed_indexes, completions)
              end
              if finished.nil?
                message, met = match_success_policy(completions, succeeded_indexes)
                finished = @c.new_condition("SuccessCriteriaMet", "True", "SuccessPolicy", message, @now) if met
              end
            end

            suspend_condition_changed = false
            deleted_pods = []
            if finished
              deleted_pods = active_pods
              active -= deleted_pods.length
              terminating += deleted_pods.length
              ready -= deleted_pods.count { |pod| @c.pod_ready?(pod) }
            else
              manage_called = false
              if !@c.pod_deleting?(job)
                manage_called = true
                active, deleted_pods = manage_job(active_pods, succeeded, succeeded_indexes, failed_indexes,
                                                  delayed_deletion, terminating, completions)
                terminating += deleted_pods.length
                ready -= deleted_pods.count { |pod| @c.pod_ready?(pod) }
              end
              complete = if completions.nil?
                           succeeded.positive? && active.zero?
                         else
                           succeeded >= completions && active.zero?
                         end
              if complete
                finished = @c.new_condition("SuccessCriteriaMet", "True", "CompletionsReached",
                                            "Reached expected number of succeeded pods", @now)
              elsif manage_called
                if suspended
                  status["conditions"], changed = @c.ensure_condition_status(status["conditions"], "Suspended", "True",
                                                                             "JobSuspended", "Job suspended", @now)
                  if changed
                    suspend_condition_changed = true
                    @events << @c.event("Normal", "Suspended", "Job suspended")
                    # MutableSchedulingDirectivesForSuspendedJobs (beta, on):
                    # the deadline timer must not run while suspended.
                    status.delete("startTime")
                  end
                else
                  status["conditions"], changed = @c.ensure_condition_status(status["conditions"], "Suspended", "False",
                                                                             "JobResumed", "Job resumed", @now)
                  if changed
                    suspend_condition_changed = true
                    @events << @c.event("Normal", "Resumed", "Job resumed")
                    status["startTime"] = @now.utc.iso8601(6)
                  end
                end
              end
            end

            status["active"] = active
            status["ready"] = ready
            status["terminating"] = terminating
            track_status_and_remove_finalizers(status, finished, deleted_pods, uncounted_succeeded, uncounted_failed,
                                               prev_succeeded_indexes, succeeded_indexes, failed_indexes,
                                               delayed_deletion, indexed, completions, suspend_condition_changed)
          end

          private

          def active_deadline_seconds
            raw = Support.value(Support.spec(@job), "activeDeadlineSeconds", nil)
            raw.nil? ? nil : Support.integer(raw, 0).to_f
          end

          def past_active_deadline?(start_time, suspended)
            deadline = active_deadline_seconds
            return false if deadline.nil? || start_time.nil? || suspended

            (@now - start_time) >= deadline
          end

          # pkg/controller/job/job_controller.go:1690
          def past_backoff_limit_on_failure?
            return false unless Support.value(Support.value(template, "spec", {}), "restartPolicy", "").to_s == "OnFailure"

            restarts = @pods.sum do |pod|
              next 0 unless %w[Running Pending].include?(@c.pod_phase(pod))

              status = Support.status(pod)
              (Array(Support.value(status, "initContainerStatuses", [])) + Array(Support.value(status, "containerStatuses", []))).sum do |container|
                Support.integer(Support.value(container, "restartCount", 0), 0)
              end
            end
            limit = @c.backoff_limit(@job)
            limit.zero? ? restarts.positive? : restarts >= limit
          end

          def template
            value = Support.value(Support.spec(@job), "template", {})
            value.is_a?(Hash) ? value : {}
          end

          def success_criteria_met_condition(status)
            condition = @c.find_condition(status["conditions"], "SuccessCriteriaMet")
            condition if condition && Support.value(condition, "status", "").to_s == "True"
          end

          def success_criteria_met?(condition)
            !condition.nil? && Support.value(condition, "type", "").to_s == "SuccessCriteriaMet" &&
              Support.value(condition, "status", "").to_s == "True"
          end

          # pkg/controller/job/job_controller.go:1738
          def fail_job_message
            policy = @c.pod_failure_policy(@job)
            return nil if policy.nil?

            @pods.each do |pod|
              next unless @c.pod_failed?(pod, @job)

              message, = @c.match_pod_failure_policy(policy, pod)
              return message if message
            end
            nil
          end

          def non_ignored_failed_count(failed_pods)
            policy = @c.pod_failure_policy(@job)
            return failed_pods.length if policy.nil?

            failed_pods.count do |pod|
              _message, count_failed, _action = @c.match_pod_failure_policy(policy, pod)
              count_failed
            end
          end

          # pkg/controller/job/job_controller.go:2064
          def valid_pods(uncounted)
            completions = @c.completions(@job)
            @pods.select do |pod|
              next false unless @c.tracking_finalizer?(pod)
              next false if uncounted&.include?(Support.uid(pod).to_s)

              if @c.indexed?(@job)
                index = @c.completion_index(pod)
                next false if index == UNKNOWN_COMPLETION_INDEX || index >= completions
              end
              yield(pod)
            end
          end

          def calculate_succeeded_indexes(previous, completions)
            new_indexes = @pods.filter_map do |pod|
              index = @c.completion_index(pod)
              next unless @c.pod_phase(pod) == "Succeeded" && index != UNKNOWN_COMPLETION_INDEX &&
                          index < completions && @c.tracking_finalizer?(pod)

              index
            end.uniq
            @c.intervals_with_indexes(previous, new_indexes)
          end

          def calculate_failed_indexes(completions)
            previous = @c.parse_indexes(Support.value(Support.status(@job), "failedIndexes", nil), completions)
            new_indexes = @pods.filter_map do |pod|
              index = @c.completion_index(pod)
              next unless index != UNKNOWN_COMPLETION_INDEX && index < completions &&
                          @c.tracking_finalizer?(pod) && index_failed?(pod)

              index
            end.uniq
            @c.intervals_with_indexes(previous, new_indexes)
          end

          # pkg/controller/job/indexed_job_utils.go:98
          def index_failed?(pod)
            counted = false
            if @c.pod_failed?(pod, @job)
              policy = @c.pod_failure_policy(@job)
              if policy
                _message, count_failed, action = @c.match_pod_failure_policy(policy, pod)
                return true if action == "FailIndex"

                counted = count_failed
              else
                counted = true
              end
            end
            counted && @c.index_failure_count(pod) >= Support.integer(Support.value(Support.spec(@job), "backoffLimitPerIndex", 0), 0)
          end

          # pkg/controller/job/indexed_job_utils.go:323
          def pods_with_delayed_deletion_per_index(active_pods, succeeded_indexes, failed_indexes, completions)
            active_indexes = Set.new(active_pods.map { |pod| @c.completion_index(pod) }.reject { |index| index == UNKNOWN_COMPLETION_INDEX })
            result = {}
            valid_pods(nil) do |pod|
              next false unless @c.pod_failed?(pod, @job)

              index = @c.completion_index(pod)
              next false if index == UNKNOWN_COMPLETION_INDEX || index >= completions
              next false if @c.intervals_include?(succeeded_indexes, index) ||
                            (failed_indexes && @c.intervals_include?(failed_indexes, index)) || active_indexes.include?(index)

              current = result[index]
              if current.nil? ||
                 (@c.index_absolute_failure_count(current) <= @c.index_absolute_failure_count(pod) &&
                  @c.finish_time(pod) >= @c.finish_time(current))
                result[index] = pod
              end
              false
            end
            result
          end

          # pkg/controller/job/success_policy.go:29
          def match_success_policy(completions, succeeded_indexes)
            policy = Support.value(Support.spec(@job), "successPolicy", nil)
            return ["", false] if policy.nil? || succeeded_indexes.empty?

            Array(Support.value(policy, "rules", [])).each_with_index do |rule, index|
              rule_indexes = Support.value(rule, "succeededIndexes", nil)
              rule_count = Support.value(rule, "succeededCount", nil)
              if !rule_indexes.nil?
                required = @c.parse_indexes(rule_indexes, completions)
                next if required.empty?

                if succeeded_indexes_rule_matches?(required, succeeded_indexes, rule_count)
                  return ["Matched rules at index #{index}", true]
                end
              elsif !rule_count.nil? && @c.intervals_total(succeeded_indexes) >= Support.integer(rule_count, 0)
                return ["Matched rules at index #{index}", true]
              end
            end
            ["", false]
          end

          def succeeded_indexes_rule_matches?(rule_indexes, succeeded_indexes, succeeded_count)
            contains = 0
            rule_pointer = 0
            succeeded_pointer = 0
            while rule_pointer < rule_indexes.length && succeeded_pointer < succeeded_indexes.length
              rule = rule_indexes[rule_pointer]
              current = succeeded_indexes[succeeded_pointer]
              overlap = [rule[1], current[1]].min - [rule[0], current[0]].max + 1
              contains += overlap if overlap.positive?
              if current[1] < rule[1]
                succeeded_pointer += 1
              elsif current[1] > rule[1]
                rule_pointer += 1
              else
                succeeded_pointer += 1
                rule_pointer += 1
              end
            end
            contains == @c.intervals_total(rule_indexes) ||
              (!succeeded_count.nil? && contains >= Support.integer(succeeded_count, 0))
          end

          # pkg/controller/job/job_controller.go:1775
          # Returns [active, deleted_pods].
          def manage_job(active_pods, succeeded, succeeded_indexes, failed_indexes, delayed_deletion, terminating, completions)
            active = active_pods.length
            job = @job
            if @c.suspended?(job)
              victims = active_pods_for_removal(active_pods, active, completions)
              return [active - victims.length, victims]
            end

            parallelism = @c.parallelism(job)
            want_active = if completions.nil?
                            succeeded.positive? ? active : parallelism
                          else
                            [[completions - succeeded, parallelism].min, 0].max
                          end
            rm_at_least = [active - want_active, 0].max
            victims = active_pods_for_removal(active_pods, rm_at_least, completions).first(MAX_POD_CREATE_DELETE_PER_SYNC)
            if victims.any?
              # Deletion and creation never share a sync; deletion wins.
              return [active - victims.length, victims]
            end

            terminating_count = @c.only_replace_failed_pods?(job) ? terminating : 0
            diff = want_active - terminating_count - active
            return [active, []] unless diff.positive?

            unless @c.backoff_limit_per_index?(job)
              remaining = backoff_remaining_seconds
              if remaining.positive?
                @requeue_after = [@requeue_after, remaining].compact.min
                return [active, []]
              end
            end
            diff = [diff, MAX_POD_CREATE_DELETE_PER_SYNC].min
            indexes_to_add = []
            if @c.indexed?(job)
              indexes_to_add = first_pending_indexes(active_pods, succeeded_indexes, failed_indexes, diff, completions)
              if @c.backoff_limit_per_index?(job)
                indexes_to_add, remaining = creation_info_for_independent_indexes(indexes_to_add, delayed_deletion)
                if remaining.positive?
                  @requeue_after = [@requeue_after, remaining].compact.min
                  return [active, []]
                end
              end
              diff = indexes_to_add.length
            end
            create_pods(diff, indexes_to_add, delayed_deletion, active)
            [active + diff, []]
          end

          # Slow-start batches mirror the upstream create loop so an adapter can
          # stop early when the first batch fails.
          def create_pods(count, indexes_to_add, delayed_deletion, active)
            job = @job
            base_template = Support.deep_copy(template)
            add_completion_index_env!(base_template) if @c.indexed?(job)
            count.times do |slot|
              index = indexes_to_add.empty? ? UNKNOWN_COMPLETION_INDEX : indexes_to_add.fetch(slot)
              candidate = @c.pod_for(job, name: nil, template_value: base_template)
              metadata = candidate["metadata"]
              metadata.delete("name")
              metadata["generateName"] = "#{Support.name(job)}-"
              finalizers = Array(Support.value(Support.value(base_template, "metadata", {}), "finalizers", [])).dup
              finalizers << TRACKING_FINALIZER unless finalizers.include?(TRACKING_FINALIZER)
              metadata["finalizers"] = finalizers
              identity = "#{Support.uid(job)}:slot:#{active + slot}"
              if index != UNKNOWN_COMPLETION_INDEX
                metadata["annotations"] = (metadata["annotations"] || {}).merge(COMPLETION_INDEX_ANNOTATION => index.to_s)
                metadata["labels"] = (metadata["labels"] || {}).merge(COMPLETION_INDEX_ANNOTATION => index.to_s)
                candidate["spec"]["hostname"] = "#{Support.name(job)}-#{index}"
                metadata["generateName"] = pod_generate_name_with_index(Support.name(job), index)
                identity = "#{Support.uid(job)}:index:#{index}"
                if @c.backoff_limit_per_index?(job)
                  failure_count, ignored_count = new_index_failure_counts(delayed_deletion[index])
                  metadata["annotations"][INDEX_FAILURE_COUNT_ANNOTATION] = failure_count.to_s
                  metadata["annotations"][INDEX_IGNORED_FAILURE_COUNT_ANNOTATION] = ignored_count.to_s if ignored_count.positive?
                end
              end
              @operations << @c.operation_create(candidate, owner: job, descriptor: POD, reason: "job pod creation",
                                                 operation_key: "registry/v1/pods/#{Support.namespace(job)}/#{identity}")
              @events << @c.event("Normal", "SuccessfulCreate", "Created pod: #{Support.name(job)}-#{active + slot}-pending")
            end
          end

          def add_completion_index_env!(pod_template)
            spec = pod_template["spec"] ||= {}
            %w[initContainers containers].each do |key|
              next unless spec[key].is_a?(Array)

              spec[key].each do |container|
                next unless container.is_a?(Hash)

                env = Array(container["env"]).dup
                next if env.any? { |variable| Support.value(variable, "name", "").to_s == COMPLETION_INDEX_ENV }

                env << {"name" => COMPLETION_INDEX_ENV,
                        "valueFrom" => {"fieldRef" => {"fieldPath" => "metadata.annotations['#{COMPLETION_INDEX_ANNOTATION}']"}}}
                container["env"] = env
              end
            end
          end

          # names.MaxGeneratedNameLength = 63 - 5
          def pod_generate_name_with_index(job_name, index)
            suffix = "-#{index}-"
            prefix = "#{job_name}#{suffix}"
            max = 58
            return prefix if prefix.length <= max

            "#{prefix[0, max - suffix.length]}#{suffix}"
          end

          # pkg/controller/job/indexed_job_utils.go:360
          def new_index_failure_counts(replaced_pod)
            return [0, 0] if replaced_pod.nil?

            failure_count = @c.index_failure_count(replaced_pod)
            ignored_count = @c.index_ignored_failure_count(replaced_pod)
            policy = @c.pod_failure_policy(@job)
            if policy
              _message, count_failed, _action = @c.match_pod_failure_policy(policy, replaced_pod)
              count_failed ? failure_count += 1 : ignored_count += 1
            else
              failure_count += 1
            end
            [failure_count, ignored_count]
          end

          # pkg/controller/job/indexed_job_utils.go:247
          def first_pending_indexes(active_pods, succeeded_indexes, failed_indexes, count, completions)
            return [] if count.zero?

            active_indexes = indexes_of(active_pods)
            non_pending = @c.intervals_with_indexes(succeeded_indexes, active_indexes)
            if @c.only_replace_failed_pods?(@job)
              terminating_indexes = indexes_of(@pods.select { |pod| @c.pod_terminating?(pod) })
              non_pending = @c.intervals_with_indexes(non_pending, terminating_indexes)
            end
            non_pending = @c.merge_intervals(non_pending, failed_indexes) if failed_indexes
            result = []
            candidate = 0
            non_pending.each do |first, last|
              while candidate < completions && result.length < count && candidate < first
                result << candidate
                candidate += 1
              end
              candidate = last + 1 if candidate < last + 1
            end
            while candidate < completions && result.length < count
              result << candidate
              candidate += 1
            end
            result
          end

          def indexes_of(pods)
            pods.map { |pod| @c.completion_index(pod) }.reject { |index| index == UNKNOWN_COMPLETION_INDEX }.uniq
          end

          # pkg/controller/job/job_controller.go:1991
          def creation_info_for_independent_indexes(indexes_to_add, delayed_deletion)
            ready_now = []
            minimum_remaining = nil
            indexes_to_add.each do |index|
              remaining = remaining_time_per_index(delayed_deletion[index])
              if remaining.zero?
                ready_now << index
              elsif minimum_remaining.nil? || remaining < minimum_remaining
                minimum_remaining = remaining
              end
            end
            return [ready_now, 0.0] if ready_now.any?

            [ready_now, minimum_remaining || 0.0]
          end

          def remaining_time_per_index(last_failed_pod)
            return 0.0 if last_failed_pod.nil?

            remaining_time_for_failures(@c.index_absolute_failure_count(last_failed_pod) + 1, @c.finish_time(last_failed_pod))
          end

          # pkg/controller/job/backoff_utils.go:95 recomputed from Pod finish
          # times: failures observed after the most recent success.
          def backoff_remaining_seconds
            succeeded_times = @pods.select { |pod| @c.pod_phase(pod) == "Succeeded" }.map { |pod| @c.finish_time(pod) }
            last_success = succeeded_times.max
            failure_times = @pods.select { |pod| @c.pod_failed?(pod, @job) }.map { |pod| @c.finish_time(pod) }
            failure_times.select! { |time| time > last_success } if last_success
            return 0.0 if failure_times.empty?

            remaining_time_for_failures(failure_times.length, failure_times.max)
          end

          # pkg/controller/job/backoff_utils.go:258
          def remaining_time_for_failures(failures_count, last_failure_time)
            return 0.0 if failures_count.zero? || last_failure_time.nil?

            backoff = DEFAULT_POD_FAILURE_BACKOFF_SECONDS
            (1...failures_count).each do
              backoff *= 2
              if backoff >= MAX_POD_FAILURE_BACKOFF_SECONDS
                backoff = MAX_POD_FAILURE_BACKOFF_SECONDS
                break
              end
            end
            elapsed = @now - last_failure_time
            return 0.0 if backoff < elapsed

            backoff - elapsed
          end

          # pkg/controller/job/job_controller.go:2013
          def active_pods_for_removal(active_pods, rm_at_least, completions)
            rm = []
            left = active_pods
            if @c.indexed?(@job)
              rm, left = duplicated_index_pods_for_removal(active_pods, completions)
            end
            if rm.length < rm_at_least
              rm += left.sort_by { |pod| active_pod_sort_key(pod) }.first(rm_at_least - rm.length)
            end
            rm
          end

          # pkg/controller/job/indexed_job_utils.go:295
          def duplicated_index_pods_for_removal(pods, completions)
            rm = []
            left = []
            pods.group_by { |pod| @c.completion_index(pod) }.sort_by { |index, _| index }.each do |index, group|
              if index == UNKNOWN_COMPLETION_INDEX || index >= completions
                rm.concat(group)
              elsif group.length == 1
                left.concat(group)
              else
                ordered = group.sort_by { |pod| active_pod_sort_key(pod) }
                rm.concat(ordered[0...-1])
                left << ordered.last
              end
            end
            [rm, left]
          end

          # controller.ActivePods ordering: unassigned, then Pending < Unknown <
          # Running, not-ready first, most recently ready first, more restarts
          # first, newest creation first.
          def active_pod_sort_key(pod)
            ready = @c.pod_ready?(pod)
            ready_time = if ready
                           Support.parse_time(Support.value(Support.condition(pod, "Ready"), "lastTransitionTime", nil))
                         end
            restarts = Array(Support.value(Support.status(pod), "containerStatuses", [])).map do |container|
              Support.integer(Support.value(container, "restartCount", 0), 0)
            end.max || 0
            created = Support.creation_time(pod)
            [
              Support.value(Support.spec(pod), "nodeName", "").to_s.empty? ? 0 : 1,
              POD_PHASE_ORDINAL.fetch(@c.pod_phase(pod), 3),
              ready ? 1 : 0,
              ready_time ? -ready_time.to_f : -Float::INFINITY,
              -restarts,
              created ? -created.to_f : -Float::INFINITY,
              Support.name(pod)
            ]
          end

          # pkg/controller/job/job_controller.go:1331
          def track_status_and_remove_finalizers(status, finished, deleted_pods, uncounted_succeeded, uncounted_failed,
                                                 prev_succeeded_indexes, succeeded_indexes, failed_indexes,
                                                 delayed_deletion, indexed, completions, needs_flush)
            job = @job
            uncounted = status["uncountedTerminatedPods"]
            uncounted["succeeded"] = Array(uncounted["succeeded"]).map(&:to_s)
            uncounted["failed"] = Array(uncounted["failed"]).map(&:to_s)
            uids_with_finalizer = Set.new(@pods.select { |pod| @c.tracking_finalizer?(pod) }.map { |pod| Support.uid(pod).to_s })
            needs_flush = true if clean_uncounted_without_finalizers!(status, uids_with_finalizer)

            ordered_pods = indexed ? @pods.sort_by { |pod| @c.completion_index(pod) } : @pods
            pods_to_remove_finalizer = []
            new_succeeded_indexes = []
            reached_max_uncounted = false
            ordered_pods.each do |pod|
              next unless @c.tracking_finalizer?(pod)

              uid = Support.uid(pod).to_s
              consider_failed = @c.pod_failed?(pod, job)
              next unless can_remove_finalizer?(pod, finished, consider_failed, delayed_deletion)

              pods_to_remove_finalizer << pod
              if @c.pod_phase(pod) == "Succeeded" && !uncounted_failed.include?(uid)
                if indexed
                  index = @c.completion_index(pod)
                  if index != UNKNOWN_COMPLETION_INDEX && index < completions && !@c.intervals_include?(prev_succeeded_indexes, index)
                    new_succeeded_indexes << index
                    needs_flush = true
                  end
                elsif !uncounted_succeeded.include?(uid)
                  needs_flush = true
                  uncounted["succeeded"] << uid
                end
              elsif consider_failed || (finished && !success_criteria_met?(finished))
                index = @c.completion_index(pod)
                if !uncounted_failed.include?(uid) && (!indexed || (index != UNKNOWN_COMPLETION_INDEX && index < completions))
                  policy = @c.pod_failure_policy(job)
                  if policy
                    _message, count_failed, action = @c.match_pod_failure_policy(policy, pod)
                    # job_controller_pod_failures_handled_by_failure_policy_total{action}:
                    # one per failed Pod a podFailurePolicy rule decided on.
                    ControllerMetrics.increment("job_controller_pod_failures_handled_by_failure_policy_total", {"action" => action}) if action
                    if count_failed
                      needs_flush = true
                      uncounted["failed"] << uid
                    end
                  else
                    needs_flush = true
                    uncounted["failed"] << uid
                  end
                end
              end
              if new_succeeded_indexes.length + uncounted["succeeded"].length + uncounted["failed"].length >= MAX_UNCOUNTED_PODS
                reached_max_uncounted = true
                break
              end
            end

            if indexed
              succeeded_indexes = @c.intervals_with_indexes(succeeded_indexes, new_succeeded_indexes.uniq)
              indexes_text = @c.intervals_to_s(succeeded_indexes)
              needs_flush = true if indexes_text != status["completedIndexes"].to_s
              status["succeeded"] = @c.intervals_total(succeeded_indexes)
              status["completedIndexes"] = indexes_text
              failed_text = failed_indexes.nil? ? nil : @c.intervals_to_s(failed_indexes)
              if status["failedIndexes"] != failed_text
                status["failedIndexes"] = failed_text
                needs_flush = true
              end
            end

            final_condition = finished
            if finished && Support.value(finished, "type", "").to_s == "FailureTarget"
              status["conditions"] = Array(status["conditions"]) + [finished]
              needs_flush = true
              final_condition = @c.new_condition("Failed", "True", Support.value(finished, "reason", ""),
                                                 Support.value(finished, "message", ""), @now)
            end
            if success_criteria_met?(finished)
              if success_criteria_met_condition(status).nil?
                status["conditions"] = Array(status["conditions"]) + [finished]
                needs_flush = true
              end
              final_condition = @c.new_condition("Complete", "True", Support.value(finished, "reason", ""),
                                                 Support.value(finished, "message", ""), @now)
            end

            # The interim status carries the uncounted UIDs and interim
            # conditions before any finalizer is removed, so a crash between the
            # two writes cannot lose a terminated Pod.
            interim_status = compact_status(status)
            interim_operation = @c.operation_status(job, interim_status, descriptor: DESCRIPTOR, reason: "job interim status")
            @operations << interim_operation if interim_operation && needs_flush

            # Finalizers are cleared before the Pod delete so an API server
            # without finalizer-driven garbage collection still removes the Pod.
            # job_controller_terminated_pods_tracking_finalizer_total: "add"
            # for each terminated Pod seen holding the tracking finalizer,
            # "delete" as the finalizer comes off.
            unless pods_to_remove_finalizer.empty?
              ControllerMetrics.increment("job_controller_terminated_pods_tracking_finalizer_total", {"event" => "add"}, by: pods_to_remove_finalizer.length)
              ControllerMetrics.increment("job_controller_terminated_pods_tracking_finalizer_total", {"event" => "delete"}, by: pods_to_remove_finalizer.length)
            end
            pods_to_remove_finalizer.each do |pod|
              candidate = Support.deep_copy(pod)
              candidate["metadata"] ||= {}
              candidate["metadata"]["finalizers"] = Array(candidate["metadata"]["finalizers"]).reject { |value| value == TRACKING_FINALIZER }
              @operations << @c.operation_update(pod, candidate, descriptor: POD, reason: "job tracking finalizer removal")
              uids_with_finalizer.delete(Support.uid(pod).to_s)
            end
            # Pods removed by manageJob (excess or suspended) keep their
            # finalizer, so their terminal state is still counted on a later
            # sync; pods removed because the Job finished were released above.
            deleted_pods.each do |pod|
              @operations << @c.operation_delete(pod, descriptor: POD, reason: "job pod removal")
              @events << @c.event("Normal", "SuccessfulDelete", "Deleted pod: #{Support.name(pod)}")
            end

            clean_uncounted_without_finalizers!(status, uids_with_finalizer)
            job_finished = !reached_max_uncounted && enact_job_finished!(status, final_condition)
            final_status = compact_status(status)
            record_job_finished(final_status, final_condition) if job_finished
            final_operation = @c.operation_status(job, final_status, descriptor: DESCRIPTOR, reason: "job status")
            if final_operation && (interim_operation.nil? || !needs_flush || interim_status != final_status)
              @operations << final_operation
            end
            ReconcileResult.new(operations: @operations, status: final_status, events: @events, controller: @c.name,
                                key: [Support.namespace(job), Support.name(job)].compact.join("/"),
                                requeue_after: @requeue_after)
          end

          # pkg/controller/job/job_controller.go:1481
          def can_remove_finalizer?(pod, finished, consider_failed, delayed_deletion)
            return true if @c.pod_deleting?(@job) || finished || @c.pod_phase(pod) == "Succeeded"
            return false unless consider_failed

            if @c.backoff_limit_per_index?(@job)
              index = @c.completion_index(pod)
              if index != UNKNOWN_COMPLETION_INDEX
                delayed = delayed_deletion[index]
                return false if delayed && Support.uid(delayed) == Support.uid(pod)
              end
            end
            true
          end

          # pkg/controller/job/job_controller.go:1565
          def clean_uncounted_without_finalizers!(status, uids_with_finalizer)
            uncounted = status["uncountedTerminatedPods"]
            updated = false
            %w[succeeded failed].each do |key|
              current = Array(uncounted[key]).map(&:to_s)
              retained = current.select { |uid| uids_with_finalizer.include?(uid) }
              next if retained.length == current.length

              updated = true
              status[key] = Support.integer(status[key], 0) + (current.length - retained.length)
              uncounted[key] = retained
            end
            updated
          end

          # pkg/controller/job/job_controller.go:1631
          def enact_job_finished!(status, condition)
            return false if condition.nil?

            uncounted = status["uncountedTerminatedPods"]
            return false if Array(uncounted["succeeded"]).any? || Array(uncounted["failed"]).any?
            return false if Support.integer(status["terminating"], 0).positive?

            status["conditions"], = @c.ensure_condition_status(status["conditions"], Support.value(condition, "type", ""),
                                                                Support.value(condition, "status", ""),
                                                                Support.value(condition, "reason", ""),
                                                                Support.value(condition, "message", ""), @now)
            if Support.value(condition, "type", "").to_s == "Complete"
              status["completionTime"] = Support.value(condition, "lastTransitionTime", @now.utc.iso8601(6))
            end
            true
          end

          # pkg/controller/job/job_controller.go:1657
          def record_job_finished(status, condition)
            if Support.value(condition, "type", "").to_s == "Complete"
              completions = @c.completions(@job)
              if !completions.nil? && Support.integer(status["succeeded"], 0) > completions
                @events << @c.event("Warning", "TooManySucceededPods", "Too many succeeded pods running after completion count reached")
              end
              @events << @c.event("Normal", "Completed", "Job completed")
            else
              @events << @c.event("Warning", Support.value(condition, "reason", ""), Support.value(condition, "message", ""))
            end
          end

          # JobStatus JSON: active/succeeded/failed/completedIndexes/conditions
          # are omitempty; ready/terminating/uncountedTerminatedPods are
          # pointers that upstream always populates.
          def compact_status(status)
            candidate = Support.deep_copy(status)
            # Counters are written explicitly, zero included: a status apply
            # that leaves a counter out does not clear it (see
            # DeploymentController#compact_status).
            %w[active succeeded failed].each { |key| candidate[key] = Support.integer(candidate[key], 0) }
            candidate.delete("completedIndexes") if candidate["completedIndexes"].to_s.empty?
            candidate.delete("failedIndexes") if candidate["failedIndexes"].nil?
            candidate.delete("conditions") if Array(candidate["conditions"]).empty?
            candidate.delete("startTime") if candidate["startTime"].nil?
            uncounted = candidate["uncountedTerminatedPods"]
            if uncounted.is_a?(Hash)
              uncounted.delete("succeeded") if Array(uncounted["succeeded"]).empty?
              uncounted.delete("failed") if Array(uncounted["failed"]).empty?
            end
            candidate["ready"] = Support.integer(candidate["ready"], 0)
            candidate["terminating"] = Support.integer(candidate["terminating"], 0)
            candidate
          end
        end
      end
    end
  end
end
