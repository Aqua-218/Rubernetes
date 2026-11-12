# frozen_string_literal: true

module Rubernetes
  module Schema
    # ValidatingAdmissionPolicyBinding and MutatingAdmissionPolicyBinding.
    module KubernetesValidator
      module_function

      def policy_binding_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        required(spec, "policyName", ["spec"], issues)
        actions = fetch(spec, "validationActions")
        if !actions.is_a?(Array) || actions.empty?
          issues << issue(%w[spec validationActions], :required, "at least one validation action is required")
        else
          actions.each_with_index do |action, index|
            next if %w[Deny Warn Audit].include?(action.to_s)

            issues << issue(["spec", "validationActions", index.to_s], :unsupported,
                            "supported values: \"Audit\", \"Deny\", \"Warn\"")
          end
        end

        match_resources = fetch(spec, "matchResources")
        if match_resources.is_a?(Hash)
          %w[matchResourceRules excludeResourceRules].each do |collection|
            rules = fetch(match_resources, collection)
            next unless rules.is_a?(Array)

            rules.each_with_index do |rule, index|
              issues.concat(admission_rule_presence_errors(rule, ["spec", "matchResources", collection, index.to_s])) if rule.is_a?(Hash)
            end
          end
        end
        param_ref = fetch(spec, "paramRef")
        if param_ref.is_a?(Hash)
          if blank?(fetch(param_ref, "name")) && !fetch(param_ref, "selector").is_a?(Hash)
            issues << issue(%w[spec paramRef], :required, "one of name or selector must be specified")
          end
          action = fetch(param_ref, "parameterNotFoundAction")
          if blank?(action)
            issues << issue(%w[spec paramRef parameterNotFoundAction], :required, "")
          elsif !%w[Allow Deny].include?(action.to_s)
            issues << issue(%w[spec paramRef parameterNotFoundAction], :unsupported,
                            "supported values: \"Allow\", \"Deny\"")
          end
        end
        issues
      end

      # pkg/apis/admissionregistration/validation validateMutatingAdmissionPolicyBindingSpec
      def mutating_policy_binding_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        policy_name = fetch(spec, "policyName").to_s
        if policy_name.empty?
          issues << issue(%w[spec policyName], :required, "")
        else
          issues.concat(invalid_messages(%w[spec policyName], dns1123_subdomain_messages(policy_name)))
        end
        issues.concat(param_ref_errors(fetch(spec, "paramRef"), %w[spec paramRef]))
        issues.concat(match_resources_errors(fetch(spec, "matchResources"), %w[spec matchResources]))
        issues.concat(mutating_operations_errors(fetch(spec, "matchResources"), %w[spec matchResources]))
        issues
      end

      # pkg/apis/admissionregistration/validation validateParamRef
      def param_ref_errors(ref, path)
        return [] unless ref.is_a?(Hash)

        issues = []
        name = fetch(ref, "name").to_s
        selector = fetch(ref, "selector")
        unless name.empty?
          issues.concat(invalid_messages(path + ["name"], path_segment_name_messages(name)))
          issues << issue(path + ["name"], :forbidden, "name and selector are mutually exclusive") if selector.is_a?(Hash)
        end
        if selector.is_a?(Hash)
          issues.concat(label_selector_errors(selector, path + ["selector"]))
          issues << issue(path + ["selector"], :forbidden, "name and selector are mutually exclusive") unless name.empty?
        end
        issues << issue(path, :required, "one of name or selector must be specified") if name.empty? && !selector.is_a?(Hash)
        action = fetch(ref, "parameterNotFoundAction")
        if !action.nil? && action.to_s.empty?
          issues << issue(path + ["parameterNotFoundAction"], :required, "")
        elsif !action.nil? && !%w[Deny Allow].include?(action.to_s)
          issues << issue(path + ["parameterNotFoundAction"], :unsupported, unsupported_detail(%w[Deny Allow]))
        end
        issues
      end
    end
  end
end
