# frozen_string_literal: true

module Rubernetes
  module Schema
    # API Priority and Fairness: FlowSchema and PriorityLevelConfiguration
    # (pkg/apis/flowcontrol/validation).
    module KubernetesValidator
      module_function

      FLOWCONTROL_VERBS = %w[create delete deletecollection get list patch proxy update watch].freeze

      def flow_schema_errors(root, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        distinguisher = fetch(spec, "distinguisherMethod")
        if distinguisher.is_a?(Hash)
          type = fetch(distinguisher, "type")
          unless %w[ByNamespace ByUser].include?(type.to_s)
            issues << issue(%w[spec distinguisherMethod type], :unsupported,
                            "supported values: \"ByNamespace\", \"ByUser\"")
          end
        end

        priority = fetch(spec, "priorityLevelConfiguration")
        priority = {} unless priority.is_a?(Hash)
        required(priority, "name", %w[spec priorityLevelConfiguration], issues,
                 "must reference a priority level")
        flowcontrol_condition_type_errors(root, issues) if operation == :update

        rules = fetch(spec, "rules")
        return issues unless rules.is_a?(Array)

        rules.each_with_index do |rule, index|
          flow_schema_rule_errors(rule, ["spec", "rules", index.to_s], issues) if rule.is_a?(Hash)
        end
        issues
      end

      # Every status condition of an updated object names its type.
      def flowcontrol_condition_type_errors(root, issues)
        status = fetch(root, "status")
        conditions = status.is_a?(Hash) ? fetch(status, "conditions") : nil
        return unless conditions.is_a?(Array)

        conditions.each_with_index do |condition, index|
          next unless condition.is_a?(Hash)

          required(condition, "type", ["status", "conditions", index.to_s], issues)
        end
      end

      # ValidateFlowSchemaPolicyRulesWithSubjects.
      def flow_schema_rule_errors(rule, path, issues)
        flow_schema_subject_errors(fetch(rule, "subjects"), path, issues)
        resources = fetch(rule, "resourceRules")
        non_resources = fetch(rule, "nonResourceRules")
        if (!resources.is_a?(Array) || resources.empty?) &&
           (!non_resources.is_a?(Array) || non_resources.empty?)
          issues << issue(path, :required, "at least one of resourceRules and nonResourceRules has to be non-empty")
        end
        if resources.is_a?(Array)
          resources.each_with_index do |resource_rule, index|
            flow_schema_resource_rule_errors(resource_rule, path + ["resourceRules", index.to_s], issues) if resource_rule.is_a?(Hash)
          end
        end
        return unless non_resources.is_a?(Array)

        non_resources.each_with_index do |non_resource_rule, index|
          next unless non_resource_rule.is_a?(Hash)

          flow_schema_non_resource_rule_errors(non_resource_rule, path + ["nonResourceRules", index.to_s], issues)
        end
      end

      def flow_schema_subject_errors(subjects, path, issues)
        if !subjects.is_a?(Array) || subjects.empty?
          issues << issue(path + ["subjects"], :required, "subjects must contain at least one value")
          return
        end

        subjects.each_with_index do |subject, subject_index|
          next unless subject.is_a?(Hash)

          kind = fetch(subject, "kind")
          next if %w[Group ServiceAccount User].include?(kind.to_s)

          issues << issue(path + ["subjects", subject_index.to_s, "kind"], :unsupported,
                          "supported values: \"Group\", \"ServiceAccount\", \"User\"")
        end
      end

      def flow_schema_resource_rule_errors(resource_rule, resource_path, issues)
        namespaces = fetch(resource_rule, "namespaces")
        unless fetch(resource_rule, "clusterScope") == true || (namespaces.is_a?(Array) && !namespaces.empty?)
          issues << issue(resource_path + ["namespaces"], :required,
                          "resource rules that are not cluster scoped must supply at least one namespace")
        end
        flowcontrol_verbs_errors(fetch(resource_rule, "verbs"), resource_path, issues)
      end

      def flow_schema_non_resource_rule_errors(non_resource_rule, non_resource_path, issues)
        urls = fetch(non_resource_rule, "nonResourceURLs")
        if !urls.is_a?(Array) || urls.empty?
          issues << issue(non_resource_path + ["nonResourceURLs"], :required, "")
        elsif urls.any? { |url| url.to_s == "*" }
          # ValidateFlowSchemaNonResourcePolicyRule: a wildcard entry is
          # checked only for being the sole entry.  The per-path rules
          # are not applied to it -- "*" is not a path.
          if urls.length > 1
            issues << issue(non_resource_path + ["nonResourceURLs"], :invalid,
                            "if '*' is present, must not specify other non-resource URLs")
          end
        else
          urls.each_with_index do |url, url_index|
            detail = non_resource_url_path_error(url)
            next if detail.nil?

            issues << issue(non_resource_path + ["nonResourceURLs", url_index.to_s], :invalid, detail)
          end
        end
        flowcontrol_verbs_errors(fetch(non_resource_rule, "verbs"), non_resource_path, issues)
      end

      def flowcontrol_verbs_errors(verbs, path, issues)
        if verbs.is_a?(Array) && !verbs.empty?
          flowcontrol_verb_issue(verbs, path).then { |entry| issues << entry if entry }
        else
          issues << issue(path + ["verbs"], :required, "")
        end
      end

      # ValidateNonResourceURLPath.  Returns nil when the path is valid.
      def non_resource_url_path_error(url)
        path = url.to_s
        return "must not be empty" if path.empty?
        return nil if path == "/"
        return "must start with slash" unless path.start_with?("/")
        return "must not contain white-space" if path.include?(" ")
        return "must not contain double slash" if path.include?("//")

        wildcards = path.count("*")
        return "wildcard can only do suffix matching" if wildcards > 1 || (wildcards == 1 && path[-2..] != "/*")

        nil
      end

      # ValidateFlowSchema{Resource,NonResource}PolicyRule verb handling: a "*"
      # present alongside other verbs is its own error, and suppresses the
      # supported-values check that upstream never reaches in that case.
      def flowcontrol_verb_issue(verbs, path)
        if verbs.any? { |verb| verb.to_s == "*" }
          return nil if verbs.length == 1

          return issue(path + ["verbs"], :invalid, "if '*' is present, must not specify other verbs")
        end

        return nil if verbs.all? { |verb| FLOWCONTROL_VERBS.include?(verb.to_s) }

        issue(path + ["verbs"], :unsupported,
              "supported values: #{FLOWCONTROL_VERBS.map { |verb| JSON.generate(verb) }.join(", ")}")
      end

      def priority_level_errors(root, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        type = fetch(spec, "type")
        known_type = %w[Exempt Limited].include?(type.to_s)
        issues = []
        issues << issue(%w[spec type], :unsupported, "supported values: \"Exempt\", \"Limited\"") unless known_type
        # ValidatePriorityLevelConfigurationSpec: only the mandatory "exempt"
        # level is of type Exempt.
        metadata = fetch(root, "metadata")
        name = metadata.is_a?(Hash) ? fetch(metadata, "name").to_s : ""
        if known_type && ((name == "exempt") != (type.to_s == "Exempt"))
          issues << issue(%w[spec type], :invalid, "must be 'Exempt' if and only if `name` is 'exempt'")
        end
        flowcontrol_condition_type_errors(root, issues) if operation == :update
        issues
      end

      private_class_method :flowcontrol_condition_type_errors, :flow_schema_rule_errors, :flow_schema_subject_errors,
                           :flow_schema_resource_rule_errors, :flow_schema_non_resource_rule_errors, :flowcontrol_verbs_errors
    end
  end
end
