# frozen_string_literal: true

require_relative "../api/status"
require_relative "../api/selectors"
require_relative "../schema/validator"
require_relative "../schema/kubernetes_validator"

module Rubernetes
  module Manifest
    module DisruptionBudget
      SELECTOR_OPERATORS = {"In" => :in, "NotIn" => :not_in, "Exists" => :exists, "DoesNotExist" => :not_exists}.freeze
      PDB_CONVERSION_LABEL = "pdb.kubernetes.io/deprecated-v1beta1-empty-selector-match"

      def disruption_budget(workload, max_unavailable: nil, min_available: nil, name: nil)
        raise Error, "disruption_budget expects a workload declared in this manifest" unless result.any? { |resource| resource.equal?(workload) }

        thresholds = {"maxUnavailable" => max_unavailable, "minAvailable" => min_available}.compact
        raise Error, "disruption_budget requires exactly one of max_unavailable: or min_available:" unless thresholds.size == 1

        field, threshold = thresholds.first
        unless disruption_threshold?(threshold)
          raise Error, "disruption_budget #{Schema.underscore(field)} must be an integer from 0 to 2147483647 or a percentage from 0% to 100%"
        end

        workload_name, namespace = workload.fetch("metadata").values_at("name", "namespace")
        selector = disruption_selector(workload, "#{workload.fetch("kind")}/#{workload_name}")
        budget = thresholds.merge("selector" => selector)
        resource(api_version: "policy/v1", kind: "PodDisruptionBudget", name: name || workload_name, namespace: namespace) do
          spec budget
        end
      end

      private

      def disruption_threshold?(value)
        case value
        when Integer then value.between?(0, 2_147_483_647)
        when String then value.match?(/\A0*(?:[0-9]{1,2}|100)%\z/)
        else false
        end
      end

      def disruption_selector(workload, target)
        labels = workload.dig("spec", "template", "metadata", "labels") || {}
        selector = disruption_workload_selector(workload, labels)
        validate_disruption_selector!(selector, labels, target)
        selector
      end

      def disruption_workload_selector(workload, labels)
        selector = workload.dig("spec", "selector") || {}
        case workload.values_at("apiVersion", "kind")
        in ["v1", "ReplicationController"] then {"matchLabels" => selector.empty? ? labels : selector}
        in ["apps/v1", "Deployment" | "ReplicaSet" | "StatefulSet"] then selector
        else raise Error, "disruption_budget expects a Deployment, ReplicaSet, StatefulSet or ReplicationController"
        end
      end

      def validate_disruption_selector!(selector, labels, target)
        match_labels = selector["matchLabels"] || {}
        expressions = selector["matchExpressions"] || []
        raise Error, "#{target} needs a nonempty Pod selector for a disruption budget" if match_labels.empty? && expressions.empty?

        if match_labels.value?(nil) || expressions.any? { |expression| expression.nil? || Array(expression["values"]).include?(nil) }
          raise Error, "#{target} selector cannot contain null label values or expressions"
        end
        if expressions.any? { |expression| expression["key"] == PDB_CONVERSION_LABEL }
          raise Error, "#{target} selector uses #{PDB_CONVERSION_LABEL.inspect}, which the PDB API reserves for conversion"
        end

        issue = Rubernetes::Schema::KubernetesValidator.label_selector_errors(selector, %w[spec selector]).first
        raise Error, "#{target} has an invalid selector: #{issue.message}" if issue

        matches = match_labels.all? { |key, value| labels[key] == value } && expressions.all? do |expression|
          key = expression.fetch("key")
          operator = SELECTOR_OPERATORS.fetch(expression.fetch("operator"))
          requirement = API::Selector::Requirement.new(key: key, operator: operator, values: expression["values"])
          requirement.matches?(labels[key], present: labels.key?(key))
        end
        raise Error, "#{target} selector does not match its Pod labels" unless matches
      end
    end
  end
end
