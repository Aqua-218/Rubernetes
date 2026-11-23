# frozen_string_literal: true

require "time"
require_relative "job_status_indexes"

module Rubernetes
  module Schema
    module KubernetesValidator
      # batch's status strategy validates transitions against what was last
      # persisted. An unrelated write can proceed on a historical Job whose
      # fields would fail the newer transition checks.
      class JobStatusUpdate
        def initialize(job, old)
          @spec = job["spec"].is_a?(Hash) ? job["spec"] : {}
          @status = job["status"].is_a?(Hash) ? job["status"] : {}
          stored = old&.fetch("status", nil)
          @previous = stored.is_a?(Hash) ? stored : {}
          @conditions = true_conditions(@status)
          @old_conditions = true_conditions(@previous)
          @complete = @conditions.include?("Complete")
          @failed = @conditions.include?("Failed")
          @finished = @complete || @failed
          @finished_changed = @finished != @old_conditions.intersect?(%w[Complete Failed])
        end

        def errors
          @issues = []
          %w[active succeeded failed ready terminating].each do |field|
            invalid(field, IS_NEGATIVE_ERROR_MSG) if count(@status, field).negative?
          end
          validate_uncounted_uids
          validate_terminal_conditions
          validate_finished_counts
          @issues.concat(KubernetesValidator.job_status_index_errors(@spec, @status, @previous))
          if @finished && (@finished_changed || changed?("terminating")) && count(@status, "terminating").positive?
            invalid("terminating", "terminating>0 is invalid for finished job")
          end
          ready = @status["ready"]
          if ready.is_a?(Integer) && ready > count(@status, "active") && (changed?("ready") || count_changed?("active"))
            invalid("ready", "cannot set more ready pods than active")
          end
          validate_success_criteria
          validate_transitions
          @issues
        end

        private

        def validate_uncounted_uids
          pending = @status["uncountedTerminatedPods"]
          return unless pending.is_a?(Hash)

          seen = {}
          %w[succeeded failed].each do |field|
            Array(pending[field]).each_with_index do |uid, index|
              path = ["status", "uncountedTerminatedPods", field, index.to_s]
              if uid == ""
                @issues << ValidationIssue.new(path: path, code: :invalid, value: uid, message: "must not be empty")
              elsif seen[uid]
                @issues << ValidationIssue.new(path: path, code: :duplicate, value: uid, message: "")
              else
                seen[uid] = true
              end
            end
          end
        end

        def validate_terminal_conditions
          conditions_error("cannot set Complete=True and Failed=true conditions") if @complete && @failed && condition_changed?("Complete", "Failed")
          if @complete && @conditions.include?("FailureTarget") && condition_changed?("Complete", "FailureTarget")
            conditions_error("cannot set Complete=True and FailureTarget=true conditions")
          end
          if condition_changed?("Complete") || time_changed?("completionTime")
            if @complete && @status["completionTime"].nil?
              required("completionTime", "completionTime is required for Complete jobs")
            elsif !@complete && @status["completionTime"]
              invalid_time("completionTime", "cannot set completionTime when there is no Complete=True condition")
            end
          end
          if time_changed?("startTime") || time_changed?("completionTime")
            start = timestamp(@status, "startTime")
            finish = timestamp(@status, "completionTime")
            invalid_time("completionTime", "must be equal to or after `startTime`") if start && finish && finish < start
          end
          if @failed && !@conditions.include?("FailureTarget") && (condition_changed?("Failed") || changed?("failedIndexes"))
            conditions_error("cannot set Failed=True condition without the FailureTarget=true condition")
          end
          return unless @complete && !@conditions.include?("SuccessCriteriaMet") && condition_changed?("Complete", "SuccessCriteriaMet")

          conditions_error("cannot set Complete=True condition without the SuccessCriteriaMet=true condition")
        end

        def validate_finished_counts
          return unless @finished

          invalid("active", "active>0 is invalid for finished job") if count(@status, "active").positive? && (@finished_changed || count_changed?("active"))
          if @status["startTime"].nil? && (@finished_changed || time_changed?("startTime")) && !(@spec["suspend"] && @spec["completions"] == 0)
            required("startTime", "startTime is required for finished job")
          end
          pending = @status["uncountedTerminatedPods"]
          if pending.is_a?(Hash) && (@finished_changed || changed?("uncountedTerminatedPods")) &&
             %w[succeeded failed].any? { |key| Array(pending[key]).any? }
            invalid("uncountedTerminatedPods", "must be empty for finished job", {"Succeeded" => pending["succeeded"], "Failed" => pending["failed"]})
          end
        end

        def validate_success_criteria
          if @conditions.include?("SuccessCriteriaMet")
            conditions_error("cannot set SuccessCriteriaMet=True and Failed=true conditions") if @failed
            conditions_error("cannot set SuccessCriteriaMet=True and FailureTarget=true conditions") if @conditions.include?("FailureTarget")
          elsif @complete && @spec["successPolicy"]
            conditions_error("cannot set Complete=True for Job with SuccessPolicy unless SuccessCriteriaMet=True")
          end
        end

        def validate_transitions
          %w[Failed Complete FailureTarget].each do |type|
            conditions_error("cannot disable the terminal #{type}=True condition") if @old_conditions.include?(type) && !@conditions.include?(type)
          end
          elastic = @spec["completionMode"] == "Indexed" && @spec["completions"] == @spec["parallelism"]
          %w[failed succeeded].each do |field|
            next if field == "succeeded" && elastic

            current = count(@status, field)
            invalid(field, "cannot decrease the #{field} counter", current) if current < count(@previous, field)
          end
          invalid_time("completionTime", "field is immutable") if @previous["completionTime"] && @status["completionTime"] && time_changed?("completionTime")
          if @previous["startTime"] && time_changed?("startTime") && !@spec["suspend"] && !resuming?
            invalid_time("startTime", "field is immutable for unsuspended job once set")
          end
          if @old_conditions.include?("SuccessCriteriaMet") && !@conditions.include?("SuccessCriteriaMet")
            conditions_error("cannot disable the SuccessCriteriaMet=True condition")
          elsif @old_conditions.include?("Complete") && !@old_conditions.include?("SuccessCriteriaMet") && @conditions.include?("SuccessCriteriaMet")
            conditions_error("cannot set SuccessCriteriaMet=True for Job already has Complete=true conditions")
          end
        end

        def resuming?
          @old_conditions.include?("Suspended") && Array(@status["conditions"]).any? do |entry|
            entry.is_a?(Hash) && entry["type"] == "Suspended" && entry["status"] == "False"
          end
        end

        def true_conditions(status)
          Array(status["conditions"]).filter_map { |entry| entry["type"] if entry.is_a?(Hash) && entry["status"] == "True" }
        end

        def count(status, field)
          value = status[field]
          value.is_a?(Integer) ? value : 0
        end

        def count_changed?(field) = count(@status, field) != count(@previous, field)
        def changed?(field) = @status[field] != @previous[field]
        def condition_changed?(*types) = types.any? { |type| @conditions.include?(type) != @old_conditions.include?(type) }
        def time_changed?(field) = timestamp(@status, field) != timestamp(@previous, field)

        def timestamp(status, field)
          value = status[field]
          Time.iso8601(value) if value.is_a?(String)
        rescue ArgumentError
          nil
        end

        def invalid_time(field, message)
          invalid(field, message, timestamp(@status, field)&.utc&.iso8601)
        end

        def invalid(field, message, value = @status[field])
          @issues << ValidationIssue.new(path: ["status", field], code: :invalid, value: value, message: message, use_object_value: false)
        end

        def required(field, message)
          @issues << ValidationIssue.new(path: ["status", field], code: :required, message: message)
        end

        def conditions_error(message)
          @issues << ValidationIssue.new(path: %w[status conditions], code: :invalid, message: message, omit_value: true)
        end
      end
    end
  end
end
