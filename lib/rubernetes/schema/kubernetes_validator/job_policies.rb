# frozen_string_literal: true

require_relative "job_status_indexes"

module Rubernetes
  module Schema
    module KubernetesValidator
      JOB_FAILURE_ACTIONS = %w[Count FailIndex FailJob Ignore].freeze
      JOB_FAILURE_OPERATORS = %w[In NotIn].freeze
      JOB_FAILURE_CONDITION_STATUSES = %w[False True Unknown].freeze
      JOB_POLICY_MAX_RULES = 20
      JOB_FAILURE_MAX_CONDITIONS = 20
      JOB_FAILURE_MAX_EXIT_CODES = 255
      JOB_SUCCESS_INDEXES_MAX_BYTES = 64 * 1024

      module_function

      def job_policy_errors(spec, path)
        issues = []
        failure = fetch(spec, "podFailurePolicy")
        issues.concat(job_failure_policy_errors(spec, failure, path + ["podFailurePolicy"])) if failure.is_a?(Hash)
        success = fetch(spec, "successPolicy")
        issues.concat(job_success_policy_errors(spec, success, path + ["successPolicy"])) if success.is_a?(Hash)
        issues
      end

      def job_failure_policy_errors(spec, policy, path)
        rules = Array(fetch(policy, "rules"))
        path += ["rules"]
        issues = job_policy_length_errors(path, rules.length, JOB_POLICY_MAX_RULES)
        template = value_at_path(spec, %w[template spec])
        names = %w[containers initContainers].flat_map do |field|
          Array(fetch(template, field)).map { |entry| fetch(entry, "name").to_s }
        end
        per_index = !fetch(spec, "backoffLimitPerIndex").nil?
        rules.each_with_index do |rule, index|
          issues.concat(job_failure_rule_errors(rule, path + [index.to_s], names, per_index))
        end
        issues
      end

      def job_failure_rule_errors(rule, path, names, per_index)
        action = fetch(rule, "action").to_s
        action_path = path + ["action"]
        issues = job_policy_enum_errors(action_path, action, JOB_FAILURE_ACTIONS)
        issues << valued_issue(action_path, action, "requires the backoffLimitPerIndex to be set") if action == "FailIndex" && !per_index
        exits = fetch(rule, "onExitCodes")
        conditions = Array(fetch(rule, "onPodConditions"))
        issues.concat(job_failure_exit_errors(exits, path + ["onExitCodes"], names)) unless exits.nil?
        issues.concat(job_failure_condition_errors(conditions, path + ["onPodConditions"])) unless conditions.empty?

        detail = if exits.nil? && conditions.empty?
                   "specifying one of OnExitCodes and OnPodConditions is required"
                 elsif !exits.nil? && !conditions.empty?
                   "specifying both OnExitCodes and OnPodConditions is not supported"
                 end
        issues << ValidationIssue.new(path: path, code: :invalid, message: detail, omit_value: true) if detail
        issues
      end

      def job_failure_exit_errors(exits, path, names)
        operator = fetch(exits, "operator").to_s
        issues = job_policy_enum_errors(path + ["operator"], operator, JOB_FAILURE_OPERATORS)
        name = fetch(exits, "containerName")
        if name.is_a?(String) && !names.include?(name)
          issues << valued_issue(path + ["containerName"], go_value(job_status_index_quote(name)),
                                 "must be one of the container or initContainer names in the pod template")
        end
        values = fetch(exits, "values")
        issues.concat(job_failure_value_errors(values, path + ["values"], operator))
      end

      def job_failure_value_errors(values, path, operator)
        items = Array(values)
        return [valued_issue(path, values, "at least one value is required")] if items.empty?

        issues = job_policy_length_errors(path, items.length, JOB_FAILURE_MAX_EXIT_CODES)
        seen = Set.new
        ordered = true
        previous = nil
        items.each_with_index do |value, index|
          next unless value.nil? || value.is_a?(Integer)

          value ||= 0
          value_path = path + [index.to_s]
          issues << valued_issue(value_path, value, "must not be 0 for the In operator") if operator == "In" && value.zero?
          issues << ValidationIssue.new(path: value_path, code: :duplicate, message: "", value: value) unless seen.add?(value)
          ordered = false if previous && previous > value
          previous = value
        end
        issues << valued_issue(path, items.map { |value| value || 0 }, "must be ordered") unless ordered
        issues
      end

      def job_failure_condition_errors(conditions, path)
        issues = job_policy_length_errors(path, conditions.length, JOB_FAILURE_MAX_CONDITIONS)
        conditions.each_with_index do |condition, index|
          pattern_path = path + [index.to_s]
          name = fetch(condition, "type").to_s
          qualified_name_messages(name, label_key: true).each do |message|
            issues << valued_issue(pattern_path + ["type"], go_value(job_status_index_quote(name)), message)
          end
          status = job_failure_condition_status(condition)
          issues.concat(job_policy_enum_errors(pattern_path + ["status"], status, JOB_FAILURE_CONDITION_STATUSES))
        end
        issues
      end

      def job_failure_condition_status(condition)
        status = fetch(condition, "status").to_s
        status.empty? ? "True" : status
      end

      def job_success_policy_errors(spec, policy, path)
        if fetch(spec, "completionMode") != "Indexed"
          return [valued_issue(path, job_policy_display(job_success_policy_value(policy)), "requires indexed completion mode")]
        end

        rules = Array(fetch(policy, "rules"))
        path += ["rules"]
        return [issue(path, :required, "at least one rules must be specified when the successPolicy is specified")] if rules.empty?

        issues = job_policy_length_errors(path, rules.length, JOB_POLICY_MAX_RULES)
        completions = fetch(spec, "completions")
        rules.each_with_index do |rule, index|
          issues.concat(job_success_rule_errors(rule, path + [index.to_s], completions))
        end
        issues
      end

      def job_success_rule_errors(rule, path, completions)
        count = fetch(rule, "succeededCount")
        indexes = fetch(rule, "succeededIndexes")
        return [issue(path, :required, "at least one of succeededCount or succeededIndexes must be specified")] if count.nil? && indexes.nil?

        issues = []
        total = job_success_index_count(indexes, path + ["succeededIndexes"], completions, issues) if indexes.is_a?(String)
        return issues unless count.is_a?(Integer)

        count_path = path + ["succeededCount"]
        issues << valued_issue(count_path, count, IS_NEGATIVE_ERROR_MSG) if count.negative?
        if completions.is_a?(Integer) && count > completions
          issues << valued_issue(count_path, count, "must be less than or equal to #{completions} (the number of specified completions)")
        end
        if total && count > total
          issues << valued_issue(count_path, count, "must be less than or equal to #{total} (the number of indexes in the specified succeededIndexes field)")
        end
        issues
      end

      def job_success_index_count(indexes, path, completions, issues)
        issues << issue(path, :too_long, "may not be more than #{JOB_SUCCESS_INDEXES_MAX_BYTES} bytes") if indexes.bytesize > JOB_SUCCESS_INDEXES_MAX_BYTES
        return unless completions.is_a?(Integer)

        intervals = job_status_intervals(indexes, completions)
        detail = job_status_interval_format_error(intervals)
        if detail
          issues << job_status_index_issue(path, indexes, "error parsing succeededIndexes: #{detail}")
          return 0
        end
        intervals.sum { |lower, upper| upper - lower + 1 }
      end

      def job_policy_enum_errors(path, value, supported)
        if value.empty?
          choices = supported.map(&:inspect).join(" ")
          return [issue(path, :required, "valid values: [#{choices}]")]
        end
        return [] if supported.include?(value)

        [job_unsupported_value(path, job_policy_display(value), supported)]
      end

      def job_policy_length_errors(path, length, maximum)
        return [] if length <= maximum

        [ValidationIssue.new(path: path, code: :too_many, value: length, kubernetes_type: "Too many", message: "must have at most #{maximum} items")]
      end

      def job_policy_immutable_errors(field, current, previous)
        return [] if current == previous

        converter = method(field == "podFailurePolicy" ? :job_failure_policy_value : :job_success_policy_value)
        current_value = converter.call(current)
        previous_value = converter.call(previous)
        return [] if current.nil? == previous.nil? && semantic_value(current_value) == semantic_value(previous_value)

        [valued_issue(["spec", field], job_policy_display(current_value), "field is immutable")]
      end

      def job_success_policy_value(policy)
        return unless policy.is_a?(Hash)

        rules = fetch(policy, "rules")
        return {"Rules" => nil} unless rules.is_a?(Array)

        {"Rules" => rules.map do |rule|
          {"SucceededIndexes" => fetch(rule, "succeededIndexes"), "SucceededCount" => fetch(rule, "succeededCount")}
        end}
      end

      def job_failure_policy_value(policy)
        return unless policy.is_a?(Hash)

        rules = fetch(policy, "rules")
        return {"Rules" => nil} unless rules.is_a?(Array)

        {"Rules" => rules.map do |rule|
          raw_conditions = fetch(rule, "onPodConditions")
          conditions = if raw_conditions.is_a?(Array)
                         raw_conditions.map do |condition|
                           {"Type" => fetch(condition, "type").to_s, "Status" => job_failure_condition_status(condition)}
                         end
                       end
          {"Action" => fetch(rule, "action").to_s, "OnExitCodes" => job_failure_exit_value(fetch(rule, "onExitCodes")), "OnPodConditions" => conditions}
        end}
      end

      def job_failure_exit_value(value)
        return unless value.is_a?(Hash)

        values = fetch(value, "values")
        values = values.map { |item| item || 0 } if values.is_a?(Array)
        {"ContainerName" => fetch(value, "containerName"), "Operator" => fetch(value, "operator").to_s, "Values" => values}
      end

      def job_policy_display(value)
        go_value(InternalPodSpec.compact(value))
      end
    end
  end
end
