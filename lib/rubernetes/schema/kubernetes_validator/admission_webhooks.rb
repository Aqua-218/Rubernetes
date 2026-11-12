# frozen_string_literal: true

module Rubernetes
  module Schema
    # Mutating/ValidatingWebhookConfiguration: each webhook entry
    # (pkg/apis/admissionregistration/validation validateValidatingWebhook and
    # validateMutatingWebhook).
    module KubernetesValidator
      module_function

      def webhook_errors(root, _kind, operation = :create)
        webhooks = fetch(root, "webhooks")
        return [] unless webhooks.is_a?(Array)

        webhooks.each_with_index.flat_map do |webhook, index|
          next [] unless webhook.is_a?(Hash)

          path = ["webhooks", index.to_s]
          errors = webhook_review_version_errors(webhook, path, operation)
          errors.concat(webhook_client_config_errors(webhook, path))
          errors.concat(webhook_name_errors(webhook, path))
          errors.concat(webhook_side_effects_errors(webhook, path, operation))
          errors.concat(webhook_match_condition_errors(webhook, path)) unless operation == :update
          errors.concat(webhook_rule_errors(webhook, path))
        end
      end

      def webhook_review_version_errors(webhook, path, operation)
        versions = fetch(webhook, "admissionReviewVersions")
        field = path + ["admissionReviewVersions"]
        return [issue(field, :required, "must specify one of v1, v1beta1")] if !versions.is_a?(Array) || versions.empty?

        errors = []
        if operation == :create && versions.none? { |version| %w[v1 v1beta1].include?(version.to_s) }
          errors << issue(field, :invalid, "must include at least one of v1, v1beta1")
        end
        versions.each_with_index do |version, version_index|
          next if version.is_a?(String) && version.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)

          errors << issue(field + [version_index.to_s], :invalid, DNS1035_LABEL_MSG)
        end
        errors
      end

      def webhook_client_config_errors(webhook, path)
        client = fetch(webhook, "clientConfig")
        return [] if client.is_a?(Hash) && blank?(fetch(client, "url")) != blank?(fetch(client, "service"))

        [issue(path + ["clientConfig"], :required, "exactly one of url or service is required")]
      end

      def webhook_name_errors(webhook, path)
        name = fetch(webhook, "name")
        return [issue(path + ["name"], :required, "")] if blank?(name)
        return [] unless name.to_s.split(".").length < 3

        [issue(path + ["name"], :invalid, "should be a domain with at least three segments separated by dots")]
      end

      def webhook_side_effects_errors(webhook, path, operation)
        side_effects = fetch(webhook, "sideEffects")
        allowed = operation == :update ? %w[None NoneOnDryRun Some Unknown] : %w[None NoneOnDryRun]
        return [issue(path + ["sideEffects"], :required, "must specify one of #{allowed.join(", ")}")] if blank?(side_effects)
        return [] if allowed.include?(side_effects.to_s)

        [issue(path + ["sideEffects"], :unsupported, unsupported_detail(allowed))]
      end

      # Validated on create only.
      def webhook_match_condition_errors(webhook, path)
        conditions = fetch(webhook, "matchConditions")
        return [] unless conditions.is_a?(Array)

        conditions.each_with_index.filter_map do |condition, condition_index|
          next unless condition.is_a?(Hash)

          expression = fetch(condition, "expression")
          next unless expression.is_a?(String) && !expression.strip.empty?

          # validateMatchConditionsExpression: the trimmed expression,
          # compiled by the strict stateless compiler (no params).
          expression_path = path + ["matchConditions", condition_index.to_s, "expression"]
          cel_compile_issue(expression_path, expression.strip, compiler: policy_expression_compiler,
                                                               return_types: cel_return_types(:bool), has_params: false,
                                                               has_authorizer: true)
        end
      end

      def webhook_rule_errors(webhook, path)
        rules = fetch(webhook, "rules")
        return [] unless rules.is_a?(Array)

        rules.each_with_index.flat_map do |rule, rule_index|
          rule.is_a?(Hash) ? admission_rule_presence_errors(rule, path + ["rules", rule_index.to_s]) : []
        end
      end

      # A rule's four lists must each name something.
      def admission_rule_presence_errors(rule, path)
        %w[apiGroups apiVersions operations resources].filter_map do |field|
          value = fetch(rule, field)
          issue(path + [field], :required, "") unless value.is_a?(Array) && !value.empty?
        end
      end

      private_class_method :webhook_review_version_errors, :webhook_client_config_errors, :webhook_name_errors,
                           :webhook_side_effects_errors, :webhook_match_condition_errors, :webhook_rule_errors
    end
  end
end
