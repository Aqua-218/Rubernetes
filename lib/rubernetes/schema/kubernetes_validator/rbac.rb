# frozen_string_literal: true

module Rubernetes
  module Schema
    # Role, ClusterRole and their bindings (pkg/apis/rbac/validation).
    module KubernetesValidator
      module_function

      # Role and RoleBinding were never validated at all -- only their
      # cluster-scoped twins were -- so a namespaced Role could hold rules
      # that upstream rejects outright.
      def rbac_errors(root, kind)
        %w[ClusterRole Role].include?(kind) ? role_errors(root, kind) : binding_subject_errors(root)
      end

      def role_errors(root, kind)
        issues = []
        aggregation = fetch(root, "aggregationRule")
        if aggregation.is_a?(Hash)
          selectors = fetch(aggregation, "clusterRoleSelectors")
          unless selectors.is_a?(Array) && !selectors.empty?
            issues << issue(%w[aggregationRule clusterRoleSelectors], :required,
                            "at least one clusterRoleSelector required if aggregationRule is non-nil")
          end
        end
        rules = fetch(root, "rules")
        return issues unless rules.is_a?(Array)

        rules.each_with_index do |rule, index|
          policy_rule_errors(rule, ["rules", index.to_s], kind, issues) if rule.is_a?(Hash)
        end
        issues
      end

      # ValidatePolicyRule (pkg/apis/rbac/validation/validation.go:106):
      # every rule needs at least one verb, a namespaced rule cannot
      # carry nonResourceURLs, and a rule may not mix resources with
      # non-resource URLs.  None of that was checked, so a Role could
      # be stored with rules that grant nothing and silently deny.
      def policy_rule_errors(rule, base, kind, issues)
        verbs = fetch(rule, "verbs")
        issues << issue(base + ["verbs"], :required, "verbs must contain at least one value") if !verbs.is_a?(Array) || verbs.empty?
        non_resource = fetch(rule, "nonResourceURLs")
        has_non_resource = non_resource.is_a?(Array) && !non_resource.empty?
        resources = fetch(rule, "resources")
        has_resources = resources.is_a?(Array) && !resources.empty?
        if has_non_resource
          if kind == "Role"
            issues << issue(base + ["nonResourceURLs"], :invalid,
                            "namespaced rules cannot apply to non-resource URLs")
          end
          if has_resources
            issues << issue(base + ["nonResourceURLs"], :invalid,
                            "rules cannot apply to both regular resources and non-resource URLs")
          end
          return
        end
        required(rule, "apiGroups", base, issues, "resource rules must supply at least one api group")
        required(rule, "resources", base, issues, "resource rules must supply at least one resource")
      end

      def binding_subject_errors(root)
        subjects = fetch(root, "subjects")
        return [] unless subjects.is_a?(Array)

        subjects.each_with_index.filter_map do |subject, index|
          next unless subject.is_a?(Hash)

          kind_value = fetch(subject, "kind")
          next if %w[Group ServiceAccount User].include?(kind_value.to_s)

          issue(["subjects", index.to_s, "kind"], :unsupported,
                "supported values: \"ServiceAccount\", \"User\", \"Group\"")
        end
      end

      # ValidateRoleBinding / ValidateClusterRoleBinding: the roleRef.  Runs
      # with the zero-value root rules (zero_value_roots.rb) because that is
      # where upstream's error list has it: ahead of every other rule, and
      # only for a binding without a `spec` key -- the type has none.
      def role_ref_errors(root, kind)
        role_ref = fetch(root, "roleRef")
        role_ref = {} unless role_ref.is_a?(Hash)
        allowed = kind == "ClusterRoleBinding" ? %w[ClusterRole] : %w[Role ClusterRole]
        issues = []
        api_group = fetch(role_ref, "apiGroup")
        if !blank?(api_group) && api_group.to_s != "rbac.authorization.k8s.io"
          issues << issue(%w[roleRef apiGroup], :unsupported, "supported values: \"rbac.authorization.k8s.io\"")
        end
        issues << issue(%w[roleRef kind], :unsupported, unsupported_detail(allowed)) unless allowed.include?(fetch(role_ref, "kind").to_s)
        issues << issue(%w[roleRef name], :required, "") if blank?(fetch(role_ref, "name"))
        issues
      end

      private_class_method :role_errors, :policy_rule_errors, :binding_subject_errors
    end
  end
end
