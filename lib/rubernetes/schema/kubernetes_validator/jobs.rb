# frozen_string_literal: true

require_relative "../job_selector"
require_relative "job_policies"
require_relative "job_spec_limits"

module Rubernetes
  module Schema
    # batch Job and CronJob (pkg/apis/batch/validation): schedule, success and
    # pod failure policies, restart policy, and what a Job update may change.
    module KubernetesValidator
      module_function

      def job_family_errors(root, kind, old: nil, template_issues: [])
        spec = fetch(root, "spec")
        return template_issues unless spec.is_a?(Hash)

        if kind == "CronJob"
          job_spec = fetch(fetch(spec, "jobTemplate"), "spec")
          path = %w[spec jobTemplate spec]
        else
          job_spec = spec
          path = ["spec"]
        end
        return job_pod_template_admission_errors(job_spec, path, template_issues) unless job_spec.is_a?(Hash)

        issues = job_spec_limit_errors(job_spec, path)
        issues.concat(job_policy_errors(job_spec, path))
        issues.concat(job_pod_replacement_policy_errors(job_spec, path))
        issues.concat(job_pod_template_admission_errors(job_spec, path, template_issues))
        if kind == "CronJob"
          selector = fetch(job_spec, "selector")
          issues << valued_issue(path + ["selector"], workload_selector_value(selector), "`selector` will be auto-generated") if selector.is_a?(Hash)
          issues << issue(path + ["manualSelector"], :unsupported, unsupported_detail(%w[nil false])) if fetch(job_spec, "manualSelector") == true
        elsif fetch(job_spec, "manualSelector") == true || !fetch(fetch(root, "metadata"), "uid").to_s.empty?
          issues.concat(job_selector_errors(job_spec, old: old))
        end
        issues
      end

      def generated_job_selector_errors(root, old)
        spec = fetch(root, "spec")
        selector = fetch(spec, "selector")
        metadata = fetch(root, "metadata")
        return [] unless selector.is_a?(Hash) && fetch(spec, "manualSelector") != true && !fetch(metadata, "uid").to_s.empty?

        labels_path = %w[spec template metadata labels]
        labels = workload_label_map(value_at_path(root, labels_path))
        prior = workload_label_map(value_at_path(old, labels_path)) || {}
        prefixed = old.nil? || (prior.key?(JobSelector::JOB_NAME) && prior.key?(JobSelector::CONTROLLER_UID))
        expected = JobSelector.expected(fetch(metadata, "name"), fetch(metadata, "uid"), prefixed: prefixed)
        issues = []
        expected.each do |key, value|
          path = labels_path + ["[#{key}]"]
          if !labels&.key?(key)
            issues << issue(path, :required, "must be '#{value}'")
          elsif labels[key] != value
            issues << valued_issue(path, labels, "must be '#{value}'")
          end
        end
        if label_selector_errors(selector, %w[spec selector]).empty? && !workload_selector_matches?(selector, expected)
          issues << valued_issue(%w[spec selector], workload_selector_value(selector), "`selector` not auto-generated")
        end
        issues
      end

      def job_selector_errors(spec, old: nil)
        selector = fetch(spec, "selector")
        path = %w[spec selector]
        issues = selector.nil? ? [issue(path, :required, "")] : label_selector_errors(selector, path)
        if !issues.empty? && !selector.nil?
          return issues unless legacy_job_selector_values?(old)

          # These values are tolerated on update, but LabelSelectorAsSelector
          # still cannot convert the selector for a template match.
          return label_selector_errors(selector, path, allow_invalid_expression_values: true)
        end
        return issues unless selector.nil? || selector.is_a?(Hash)

        labels = fetch(fetch(fetch(spec, "template"), "metadata"), "labels")
        unless workload_selector_matches?(selector, labels || {})
          issues << valued_issue(%w[spec template metadata labels], workload_label_map(labels), "`selector` does not match template `labels`")
        end
        issues
      end

      def legacy_job_selector_values?(old)
        return true if workload_selector_has_invalid_expression_value?(value_at_path(old, %w[spec selector]))

        affinity = value_at_path(old, %w[spec template spec affinity])
        %w[podAffinity podAntiAffinity].any? do |field|
          terms = fetch(affinity, field)
          required = Array(fetch(terms, "requiredDuringSchedulingIgnoredDuringExecution"))
          preferred = Array(fetch(terms, "preferredDuringSchedulingIgnoredDuringExecution"))
          (required + preferred.map { |entry| fetch(entry, "podAffinityTerm") }).any? do |term|
            %w[labelSelector namespaceSelector].any? do |selector|
              !label_selector_errors(fetch(term, selector), []).empty?
            end
          end
        end
      end

      def job_update_errors(root, old)
        spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless old.is_a?(Hash)

        issues = job_completions_update_errors(root, old, :update)
        selector = workload_selector_value(fetch(spec, "selector"))
        old_selector = workload_selector_value(fetch(old_spec, "selector"))
        issues << valued_issue(%w[spec selector], selector, "field is immutable") unless selector == old_selector
        issues.concat(job_template_update_errors(root, old, :update))
        %w[completionMode podFailurePolicy backoffLimitPerIndex managedBy successPolicy].each do |field|
          after = fetch(spec, field)
          before = fetch(old_spec, field)
          if %w[podFailurePolicy successPolicy].include?(field)
            issues.concat(job_policy_immutable_errors(field, after, before))
          elsif after != before
            issues << valued_issue(["spec", field], after, "field is immutable")
          end
        end
        issues
      end

      # ValidateJobUpdate observes the generated selector/labels only after
      # PrepareForUpdate.  Empty semantic fixtures split into two upstream
      # branches: a zero selector is checked for generated labels, while a
      # missing selector emits the parent Required/Invalid pair twice (the
      # strategy validates both old and new Job specs).  This helper is only
      # called by the explicit oracle preparation lane; ordinary client
      # validation never assumes a server UID or generated labels.
      def job_prepared_update_errors(root, metadata)
        issues = []
        spec = fetch(root, "spec")
        # pkg/registry/batch/job generateSelector runs only for jobs without
        # manualSelector; a manual selector is validated as supplied.
        return issues if spec.is_a?(Hash) && fetch(spec, "manualSelector") == true

        if spec.is_a?(Hash) && spec.key?("selector")
          issues << issue(%w[metadata uid], :required, "") if blank?(fetch(metadata, "uid"))
          labels = fetch(fetch(fetch(spec, "template"), "metadata"), "labels")
          if !labels.is_a?(Hash) || labels.empty?
            %w[controller-uid job-name].each do |name|
              expected = name == "job-name" ? fetch(metadata, "name").to_s : ""
              issues << issue(["spec", "template", "metadata", "labels", "[#{name}]"], :required, "must be '#{expected}'")
            end
          end
        else
          2.times do
            issues << issue(%w[spec selector], :required, "")
            issues << issue(%w[spec template metadata labels], :invalid,
                            "`selector` does not match template `labels`")
          end
        end
        issues
      end

      # validateCompletions (pkg/apis/batch/validation/validation.go:902):
      # completions is immutable for a non-indexed Job, and an indexed Job may
      # only change it in tandem with parallelism.  Nothing enforced it.
      def job_completions_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless spec.is_a?(Hash) && old_spec.is_a?(Hash)

        completions = fetch(spec, "completions")
        return [] if completions == fetch(old_spec, "completions")

        return [issue(%w[spec completions], :invalid, "field is immutable")] unless fetch(spec, "completionMode").to_s == "Indexed"
        return [] if completions.nil?
        return [] if completions == fetch(spec, "parallelism")

        [issue(%w[spec completions], :invalid, "can only be modified in tandem with spec.parallelism")]
      end

      # validatePodTemplateUpdate (pkg/apis/batch/validation/validation.go):
      # a Job's pod template is immutable, except that a suspended Job with no
      # active Pods that never started (or carries the JobSuspended condition,
      # shouldAllowMutablePodTemplate) may change its scheduling directives
      # (MutableSchedulingDirectivesForSuspendedJobs, Beta on) and its
      # containers' resources (MutablePodResourcesForSuspendedJobs, Beta on).
      def job_template_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        new_spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless new_spec.is_a?(Hash) && old_spec.is_a?(Hash)

        template = fetch(new_spec, "template") || {}
        old_template = semantic_value(fetch(old_spec, "template")) || {}
        unless suspended_job_template_mutable?(old, old_spec)
          return [] if (semantic_value(template) || {}) == old_template

          value = InternalPodSpec.convert_template(template, keep_empty: true)
          return [valued_issue(%w[spec template], go_value(InternalPodSpec.compact(value)), "field is immutable")]
        end

        old_template = with_scheduling_directives_of(semantic_value(template) || {}, old_template)
        job_template_resource_only_errors(template, old_template)
      end

      # shouldAllowMutablePodTemplate: the old Job is suspended, has no active
      # Pods, and never started or carries the JobSuspended condition.
      def suspended_job_template_mutable?(old, old_spec)
        return false unless fetch(old_spec, "suspend") == true

        status = fetch(old, "status")
        status = {} unless status.is_a?(Hash)
        not_started = blank?(fetch(status, "startTime"))
        suspended_condition = Array(fetch(status, "conditions")).any? do |condition|
          condition.is_a?(Hash) && fetch(condition, "type") == "JobSuspended" && fetch(condition, "status") == "True"
        end
        (not_started || suspended_condition) && fetch(status, "active").to_i.zero?
      end

      # Ignore scheduling-only differences before comparing pod resources.
      # The mutable resource path compares the PodSpec; template metadata
      # still has its ordinary validation, including selector agreement.
      def with_scheduling_directives_of(template, old_template)
        new_pod = template["spec"] || {}
        old_pod = (old_template["spec"] ||= {})
        new_affinity = new_pod["affinity"]
        if new_affinity.nil? && old_pod["affinity"]
          old_pod["affinity"].delete("nodeAffinity")
          old_pod.delete("affinity") if old_pod["affinity"].empty?
        elsif new_affinity && old_pod["affinity"].nil?
          old_pod["affinity"] = {"nodeAffinity" => new_affinity["nodeAffinity"]}.compact
        elsif new_affinity
          if new_affinity.key?("nodeAffinity")
            old_pod["affinity"]["nodeAffinity"] =
              new_affinity["nodeAffinity"]
          else
            old_pod["affinity"].delete("nodeAffinity")
          end
        end
        %w[nodeSelector tolerations schedulingGates].each do |field|
          new_pod.key?(field) ? old_pod[field] = new_pod[field] : old_pod.delete(field)
        end
        semantic_value(old_template) || {}
      end

      # validatePodResourceUpdatesOnly: only container resources may differ.
      def job_template_resource_only_errors(template, old_template)
        new_pod = fetch(template, "spec") || {}
        old_pod = deep_copy_value(old_template["spec"] || {})
        %w[containers initContainers].each do |field|
          new_containers = Array(new_pod[field])
          old_containers = Array(old_pod[field])
          next unless new_containers.length == old_containers.length

          new_containers.each_with_index do |container, index|
            next unless container.is_a?(Hash) && old_containers[index].is_a?(Hash) && container["name"] == old_containers[index]["name"]

            if container.key?("resources")
              old_containers[index]["resources"] =
                container["resources"]
            else
              old_containers[index].delete("resources")
            end
          end
        end
        return [] if semantic_value(new_pod) == semantic_value(old_pod)

        value = InternalPodSpec.convert_spec(new_pod, keep_empty: true)
        [valued_issue(%w[spec template spec], go_value(InternalPodSpec.compact(value)), "field is immutable")]
      end

      # Job's REST PrepareForCreate/PrepareForUpdate generates the
      # controller selector before ValidateJob runs.  The generated
      # selector is invalid without the server UID, so the pinned oracle
      # observes metadata.uid Required on the prepared fixture.  Keep this
      # opt-in: public create/update validation must not require the
      # server-assigned UID from an ordinary client request.
      def job_strategy_prepare_errors(root, operation)
        job_spec = fetch(root, "spec")
        return [] if job_spec.is_a?(Hash) && fetch(job_spec, "manualSelector") == true

        metadata = fetch(root, "metadata")
        metadata = {} unless metadata.is_a?(Hash)
        case operation
        when :create then blank?(fetch(metadata, "uid")) ? [issue(%w[metadata uid], :required, "")] : []
        when :update then job_prepared_update_errors(root, metadata)
        else []
        end
      end

      # Both ValidateJob and ValidateJobSpecUpdate validate the desired spec.
      # Generation checks and immutability each run in only one of the passes.
      def repeat_job_spec_issues!(issues, spec_start)
        issues.concat(issues.drop(spec_start).select { |candidate| candidate.path.first == "spec" })
      end

      # pkg/apis/batch/validation ValidateJob: an Indexed job's highest pod
      # hostname (<name>-<completions-1>) must be a DNS label.
      def indexed_job_hostname_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash) && fetch(spec, "completionMode").to_s == "Indexed"

        completions = fetch(spec, "completions")
        return [] unless completions.is_a?(Integer) && completions.positive?

        metadata = fetch(root, "metadata")
        name = metadata.is_a?(Hash) ? fetch(metadata, "name").to_s : ""
        hostname = "#{name}-#{completions - 1}"
        return [] if dns1123_label_messages(hostname).empty?

        [issue(%w[metadata name], :invalid, "will not able to create pod with invalid DNS label: #{hostname}")]
      end

      private_class_method :suspended_job_template_mutable?, :with_scheduling_directives_of, :job_template_resource_only_errors
    end
  end
end
