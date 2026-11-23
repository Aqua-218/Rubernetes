# frozen_string_literal: true

require_relative "../../go_string"

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      def job_status_index_errors(spec, status, previous)
        completed = fetch(status, "completedIndexes") || ""
        failed = fetch(status, "failedIndexes")
        return [] unless completed.is_a?(String) && (failed.nil? || failed.is_a?(String))

        completed_changed = completed != (fetch(previous, "completedIndexes") || "")
        failed_changed = failed != fetch(previous, "failedIndexes")
        return [] unless completed_changed || failed_changed

        completions = fetch(spec, "completions")
        backoff = fetch(spec, "backoffLimitPerIndex")
        completed_path = %w[status completedIndexes]
        failed_path = %w[status failedIndexes]
        completed_intervals = job_status_intervals(completed, completions)
        failed_intervals = job_status_intervals(failed, completions)
        issues = []
        if completed_changed && (error = job_status_interval_format_error(completed_intervals))
          issues << job_status_index_issue(completed_path, completed, "error parsing completedIndexes: #{error}")
        end
        if failed_changed && !backoff.nil? && (error = job_status_interval_format_error(failed_intervals))
          issues << valued_issue(failed_path, go_value(InternalPodSpec.go_string(failed)), "error parsing failedIndexes: #{error}")
        end
        if completed_changed && !completed.empty? && fetch(spec, "completionMode") != "Indexed"
          issues << job_status_index_issue(completed_path, completed, "cannot set non-empty completedIndexes when non-indexed completion mode")
        end
        if failed_changed && backoff.nil? && !failed.nil?
          issues << job_status_index_issue(failed_path, failed, "cannot set non-null failedIndexes when backoffLimitPerIndex is null")
        end
        if (overlap = job_status_interval_overlap(completed_intervals, failed_intervals))
          issues << job_status_index_issue(failed_path, failed, "failedIndexes and completedIndexes overlap at index: #{overlap}")
        end
        issues
      end

      def job_status_intervals(indexes, completions)
        return [] if indexes.nil? || indexes.empty? || !completions.is_a?(Integer)

        indexes.split(",", -1).map { |fragment| job_status_interval(fragment, completions) }
      end

      def job_status_interval(fragment, completions)
        parts = fragment.split("-", -1)
        if parts.length > 2
          return "the fragment #{job_status_index_quote(fragment)} violates the requirement that an index interval can have at most two parts separated by '-'"
        end

        lower = job_status_index_number(parts.first.to_s, completions)
        return lower if lower.is_a?(String)
        return [lower, lower] if parts.length == 1

        upper = job_status_index_number(parts.last, completions)
        return upper if upper.is_a?(String)
        return "non-increasing order, previous: #{lower}, current: #{upper}" if lower >= upper

        [lower, upper]
      end

      def job_status_index_number(text, completions)
        if text.match?(/\A\+?[0-9]+\z/)
          significant = text.sub(/\A\+?0*/, "")
          if significant.length <= 19 && (number = significant.to_i) <= 9_223_372_036_854_775_807
            return number if number < completions

            return "too large index: #{job_status_index_quote(text)}"
          end
        end
        "cannot convert string to integer for index: #{job_status_index_quote(text)}"
      end

      def job_status_interval_format_error(intervals)
        previous = nil
        intervals.each do |interval|
          return interval if interval.is_a?(String)

          lower, upper = interval
          return "non-increasing order, previous: #{previous}, current: #{lower}" if previous && previous >= lower

          previous = upper
        end
        nil
      end

      def job_status_interval_overlap(completed, failed)
        return if completed.empty? || failed.empty?

        # Invalid fragments are reported by format validation. Keep the remaining
        # intervals in input order for the separate overlap check.
        completed = completed.grep(Array)
        failed = failed.grep(Array)
        completed_pos = failed_pos = 0
        while (completed_interval = completed[completed_pos]) && (failed_interval = failed[failed_pos])
          completed_start, completed_end = completed_interval
          failed_start, failed_end = failed_interval
          return [completed_start, failed_start].max if completed_start <= failed_end && failed_start <= completed_end

          if completed_start <= failed_start
            completed_pos += 1
          else
            failed_pos += 1
          end
        end
        nil
      end

      def job_status_index_issue(path, value, message)
        valued_issue(path, go_value(job_status_index_quote(value)), message)
      end

      def job_status_index_quote(text) = GoString.quote(text)
    end
  end
end
