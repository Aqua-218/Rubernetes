# frozen_string_literal: true

module Rubernetes
  module Schema
    # scheduling.k8s.io v1alpha2 Workload and PodGroup: the declarative
    # validation of staging/src/k8s.io/api/scheduling/v1alpha2/types.go (+k8s: tags).
    module KubernetesValidator
      module_function

      def scheduling_policy_errors(policy, path)
        policy = {} unless policy.is_a?(Hash)
        members = %w[basic gang].select { |member| fetch(policy, member).is_a?(Hash) }
        issues = []
        if members.empty?
          issues << issue(path, :invalid, "must specify one of: `basic`, `gang`")
        elsif members.length > 1
          issues << issue(path, :invalid, "must specify exactly one of: `basic`, `gang`")
        end
        gang = fetch(policy, "gang")
        if gang.is_a?(Hash)
          count = fetch(gang, "minCount")
          if count.nil?
            issues << issue(path + %w[gang minCount], :required, "")
          elsif count.is_a?(Integer) && count < 1
            issues << issue(path + %w[gang minCount], :invalid, "must be greater than or equal to 1")
          end
        end
        issues
      end

      def pod_group_resource_claims_errors(claims, path)
        return [] unless claims.is_a?(Array)

        issues = []
        issues << issue(path, :too_many, "must have at most 4 items") if claims.length > 4
        claims.each_with_index do |claim, index|
          next unless claim.is_a?(Hash)

          base = path + [index.to_s]
          name = fetch(claim, "name").to_s
          if name.empty?
            issues << issue(base + ["name"], :required, "")
          else
            issues.concat(invalid_messages(base + ["name"], dns1123_label_messages(name)))
          end
          members = %w[resourceClaimName resourceClaimTemplateName].reject { |member| fetch(claim, member).nil? }
          if members.empty?
            issues << issue(base, :invalid, "must specify one of: `resourceClaimName`, `resourceClaimTemplateName`")
          elsif members.length > 1
            issues << issue(base, :invalid, "must specify exactly one of: `resourceClaimName`, `resourceClaimTemplateName`")
          end
          members.each do |member|
            issues.concat(invalid_messages(base + [member], dns1123_subdomain_messages(fetch(claim, member))))
          end
        end
        issues
      end

      def pod_group_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        ref = fetch(spec, "podGroupTemplateRef")
        if ref.is_a?(Hash)
          workload = fetch(ref, "workload")
          if workload.is_a?(Hash)
            name = fetch(workload, "workloadName").to_s
            if name.empty?
              issues << issue(%w[spec podGroupTemplateRef workload workloadName], :required, "")
            else
              issues.concat(invalid_messages(%w[spec podGroupTemplateRef workload workloadName], dns1123_subdomain_messages(name)))
            end
            template = fetch(workload, "podGroupTemplateName").to_s
            if template.empty?
              issues << issue(%w[spec podGroupTemplateRef workload podGroupTemplateName], :required, "")
            else
              issues.concat(invalid_messages(%w[spec podGroupTemplateRef workload podGroupTemplateName], dns1123_label_messages(template)))
            end
          else
            issues << issue(%w[spec podGroupTemplateRef], :invalid, "must specify one of: `workload`")
          end
        end
        issues.concat(scheduling_policy_errors(fetch(spec, "schedulingPolicy"), %w[spec schedulingPolicy]))
        issues.concat(pod_group_resource_claims_errors(fetch(spec, "resourceClaims"), %w[spec resourceClaims]))
        issues
      end

      def workload_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        controller = fetch(spec, "controllerRef")
        if controller.is_a?(Hash)
          group = fetch(controller, "apiGroup").to_s
          issues.concat(invalid_messages(%w[spec controllerRef apiGroup], dns1123_subdomain_messages(group))) unless group.empty?
          %w[kind name].each do |field|
            value = fetch(controller, field).to_s
            if value.empty?
              issues << issue(["spec", "controllerRef", field], :required, "")
            else
              issues.concat(invalid_messages(["spec", "controllerRef", field], path_segment_name_messages(value)))
            end
          end
        end
        templates = fetch(spec, "podGroupTemplates")
        if !templates.is_a?(Array) || templates.empty?
          issues << issue(%w[spec podGroupTemplates], :required, "")
          return issues
        end
        issues << issue(%w[spec podGroupTemplates], :too_many, "must have at most 8 items") if templates.length > 8
        templates.each_with_index do |template, index|
          next unless template.is_a?(Hash)

          base = ["spec", "podGroupTemplates", index.to_s]
          name = fetch(template, "name").to_s
          if name.empty?
            issues << issue(base + ["name"], :required, "")
          else
            issues.concat(invalid_messages(base + ["name"], dns1123_label_messages(name)))
          end
          issues.concat(scheduling_policy_errors(fetch(template, "schedulingPolicy"), base + ["schedulingPolicy"]))
          issues.concat(pod_group_resource_claims_errors(fetch(template, "resourceClaims"), base + ["resourceClaims"]))
        end
        issues
      end
    end
  end
end
