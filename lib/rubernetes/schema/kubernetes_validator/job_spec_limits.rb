# frozen_string_literal: true

module Rubernetes
  module Schema
    # JobSpec constraints shared by Job and CronJob templates, following batch validation order.
    module KubernetesValidator
      JOB_NONNEGATIVE_FIELDS = %w[
        parallelism completions activeDeadlineSeconds backoffLimit ttlSecondsAfterFinished backoffLimitPerIndex maxFailedIndexes
      ].freeze
      JOB_COMPLETION_MODES = %w[NonIndexed Indexed].freeze
      JOB_RESTART_POLICIES = %w[OnFailure Never].freeze
      JOB_POD_REPLACEMENT_POLICIES = %w[Failed TerminatingOrFailed].freeze
      INDEXED_JOB_MAX_PARALLELISM = 100_000
      INDEXED_JOB_MAX_FAILED_INDEXES = 100_000
      INDEXED_JOB_COMPLETIONS_SOFT_LIMIT = 100_000
      INDEXED_JOB_HIGH_COMPLETIONS_LIMIT = 10_000

      module_function

      def job_spec_limit_errors(spec, path)
        issues = JOB_NONNEGATIVE_FIELDS.filter_map do |field|
          value = fetch(spec, field)
          valued_issue(path + [field], value, IS_NEGATIVE_ERROR_MSG) if value.is_a?(Integer) && value.negative?
        end
        if fetch(spec, "backoffLimitPerIndex").nil? && !fetch(spec, "maxFailedIndexes").nil?
          issues << issue(path + ["backoffLimitPerIndex"], :required, "when maxFailedIndexes is specified")
        end
        issues.concat(job_completion_mode_errors(spec, path))
      end

      def job_completion_mode_errors(spec, path)
        mode = fetch(spec, "completionMode")
        case mode
        when "Indexed"
          indexed_job_limit_errors(spec, path)
        when nil, "NonIndexed"
          %w[backoffLimitPerIndex maxFailedIndexes].filter_map do |field|
            value = fetch(spec, field)
            valued_issue(path + [field], value, "requires indexed completion mode") if value.is_a?(Integer)
          end
        when String
          [job_unsupported_value(path + ["completionMode"], mode, JOB_COMPLETION_MODES)]
        else
          []
        end
      end

      def indexed_job_limit_errors(spec, path)
        issues = []
        completions = fetch(spec, "completions")
        issues << issue(path + ["completions"], :required, "when completion mode is Indexed") if completions.nil?
        issues.concat(job_upper_limit(spec, path, "parallelism", INDEXED_JOB_MAX_PARALLELISM,
                                      "must be less than or equal to #{INDEXED_JOB_MAX_PARALLELISM} when completion mode is Indexed"))
        issues.concat(job_upper_limit(spec, path, "maxFailedIndexes", completions, "must be less than or equal to completions")) if completions.is_a?(Integer)
        issues.concat(job_upper_limit(spec, path, "maxFailedIndexes", INDEXED_JOB_MAX_FAILED_INDEXES))
        if completions.is_a?(Integer) && completions > INDEXED_JOB_COMPLETIONS_SOFT_LIMIT && !fetch(spec, "backoffLimitPerIndex").nil?
          issues.concat(job_high_completions_errors(spec, path))
        end
        issues
      end

      def job_high_completions_errors(spec, path)
        issues = []
        if fetch(spec, "maxFailedIndexes").nil?
          issues << issue(path + ["maxFailedIndexes"], :required, "must be specified when completions is above #{INDEXED_JOB_COMPLETIONS_SOFT_LIMIT}")
        end
        detail = "must be less than or equal to #{INDEXED_JOB_HIGH_COMPLETIONS_LIMIT} when completions are above " \
                 "#{INDEXED_JOB_COMPLETIONS_SOFT_LIMIT} and used with backoff limit per index"
        issues.concat(job_upper_limit(spec, path, "parallelism", INDEXED_JOB_HIGH_COMPLETIONS_LIMIT, detail))
        issues.concat(job_upper_limit(spec, path, "maxFailedIndexes", INDEXED_JOB_HIGH_COMPLETIONS_LIMIT, detail))
      end

      def job_upper_limit(spec, path, field, limit, detail = "must be less than or equal to #{limit}")
        value = fetch(spec, field)
        return [] unless value.is_a?(Integer) && value > limit

        [valued_issue(path + [field], value, detail)]
      end

      def job_pod_replacement_policy_errors(spec, path)
        policy = fetch(spec, "podReplacementPolicy")
        return [] unless policy.is_a?(String)

        supported = fetch(spec, "podFailurePolicy").is_a?(Hash) ? ["Failed"] : JOB_POD_REPLACEMENT_POLICIES
        return [] if supported.include?(policy)

        [job_unsupported_value(path + ["podReplacementPolicy"], policy, supported)]
      end

      def job_pod_template_admission_errors(spec, path, template_issues)
        pod_spec = value_at_path(spec, %w[template spec])
        pod_path = path + %w[template spec]
        restart_path = pod_path + ["restartPolicy"]
        issues = template_issues.reject { |candidate| candidate.path == restart_path }
        containers = fetch(pod_spec, "containers")
        containers_path = pod_path + ["containers"]
        if (containers.nil? || containers == []) && issues.none? { |candidate| candidate.path == containers_path }
          issues.unshift(issue(containers_path, :required, ""))
        end
        restart = fetch(pod_spec, "restartPolicy")
        issues.concat(job_restart_policy_errors(spec, restart, restart_path))
      end

      def job_restart_policy_errors(spec, restart, path)
        case restart
        when nil, "", "Always"
          [issue(path, :required, 'valid values: "OnFailure", "Never"')]
        when "Never"
          []
        when "OnFailure"
          return [] unless fetch(spec, "podFailurePolicy").is_a?(Hash)

          [valued_issue(path, restart, 'only "Never" is supported when podFailurePolicy is specified')]
        when String
          [job_unsupported_value(path, restart, ["Always"] + JOB_RESTART_POLICIES),
           job_unsupported_value(path, restart, JOB_RESTART_POLICIES)]
        else
          []
        end
      end

      def job_unsupported_value(path, value, supported)
        ValidationIssue.new(path: path, code: :unsupported, value: value, kubernetes_type: "Unsupported value",
                            message: unsupported_detail(supported))
      end
    end
  end
end
