# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      SCHEDULING_DECLARATIVE_KINDS = %w[PodGroup Workload].freeze
      SCHEDULING_VALIDATION_FEATURES = {
        "TopologyAwareWorkloadScheduling" => %w[schedulingConstraints],
        "DRAWorkloadResourceClaims" => %w[resourceClaims],
        "WorkloadAwarePreemption" => %w[disruptionMode priorityClassName priority]
      }.freeze

      module_function

      def prepare_scheduling_validation(object, old, kind, options, subresource)
        spec = fetch(object, "spec")
        old_spec = fetch(old, "spec")
        if subresource.to_s == "status"
          status = fetch(object, "status")
          if status.is_a?(Hash) && !options.include?("DRAWorkloadResourceClaims") && Array(fetch(old_spec, "resourceClaims")).empty?
            return object.merge("status" => status.except("resourceClaimStatuses"))
          end

          return object
        end

        if kind == "PodGroup"
          object = object.merge("status" => {}) if old.nil?
          return object unless spec.is_a?(Hash)

          spec = prepare_scheduling_spec(spec, old_spec, options)
          spec = spec.merge("disruptionMode" => "Pod") if options.include?("WorkloadAwarePreemption") && spec["disruptionMode"].nil?
          object.merge("spec" => spec)
        else
          templates = fetch(spec, "podGroupTemplates")
          return object unless templates.is_a?(Array)

          previous = Array(fetch(old_spec, "podGroupTemplates"))
          prepared = templates.each_with_index.map do |template, index|
            template.is_a?(Hash) ? prepare_scheduling_spec(template, previous[index], options) : template
          end
          object.merge("spec" => spec.merge("podGroupTemplates" => prepared))
        end
      end

      def prepare_scheduling_spec(spec, previous, options)
        disabled = SCHEDULING_VALIDATION_FEATURES.flat_map do |gate, fields|
          next [] if options.include?(gate)

          fields.reject do |field|
            value = fetch(previous, field)
            case field
            when "resourceClaims" then !Array(value).empty?
            when "priorityClassName" then !value.to_s.empty?
            else !value.nil?
            end
          end
        end
        spec.except(*disabled)
      end

      def declarative_scheduling_errors(root, old, kind, operation, options, subresource)
        schema = "io.k8s.api.scheduling.v1alpha2.#{kind}"
        issues = []
        issues.concat(pod_group_status_errors(root)) if subresource.to_s == "status" && kind == "PodGroup"
        findings = DeclarativeRules.new(operation: operation, options: options).evaluate(schema, root, old)
        issues.concat(findings.filter_map { |finding| finding.issue unless finding.stage })
      end

      def pod_group_status_errors(root)
        status = fetch(root, "status")
        conditions = Array(fetch(status, "conditions"))
        issues = meta_conditions_errors(conditions, %w[status conditions])
        names = Array(value_at_path(root, %w[spec resourceClaims])).map { |claim| fetch(claim, "name").to_s }
        Array(fetch(status, "resourceClaimStatuses")).each_with_index do |claim, index|
          next if names.include?(fetch(claim, "name").to_s)

          issues << issue(["status", "resourceClaimStatuses", index.to_s, "name"], :invalid,
                          "must match the name of an entry in `spec.resourceClaims`")
        end
        issues
      end
    end
  end
end
