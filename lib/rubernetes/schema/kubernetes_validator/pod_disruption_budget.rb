# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      PDB_THRESHOLDS = %w[minAvailable maxUnavailable].freeze
      PDB_EVICTION_POLICIES = %w[AlwaysAllow IfHealthyBudget].freeze
      PDB_STATUS_FIELDS = %w[disruptionsAllowed currentHealthy desiredHealthy expectedPods].freeze
      PDB_ZERO_STATUS = PDB_STATUS_FIELDS.to_h { |field| [field, 0] }.freeze
      PDB_INT32 = (-(2**31)...(2**31))
      PDB_PERCENT_SYNTAX = "a valid percent string must be a numeric string followed by an ending '%' " \
                           "(e.g. '1%',  or '93%', regex used for validation is '[0-9]+%')"

      module_function

      def pdb_v1?(definition)
        definition.kind == "PodDisruptionBudget" && definition.group == "policy" && definition.version == "v1"
      end

      # Both the spec and status are value structs in the wire object. The
      # subresource strategy has already restored the fields outside the route.
      def prepare_pod_disruption_budget(root, status_update:)
        spec = fetch(root, "spec") || {}
        spec = pod_disruption_budget_spec_defaults(spec) unless status_update
        root.merge("spec" => spec, "status" => pod_disruption_budget_status_defaults(fetch(root, "status")))
      end

      def pod_disruption_budget_spec_defaults(spec)
        return spec unless spec.is_a?(Hash)

        spec = spec.compact
        selector = fetch(spec, "selector")
        spec["selector"] = workload_selector_value(selector) if selector.is_a?(Hash)
        spec
      end

      def pod_disruption_budget_status_defaults(status)
        return PDB_ZERO_STATUS if status.nil?
        return status unless status.is_a?(Hash)

        result = PDB_ZERO_STATUS.merge(status.compact)
        result.delete("observedGeneration") if result["observedGeneration"] == 0
        result.delete("disruptedPods") if result["disruptedPods"] == {}
        conditions = result["conditions"]
        if conditions == []
          result.delete("conditions")
        elsif conditions.is_a?(Array)
          result["conditions"] = conditions.map do |condition|
            next condition unless condition.is_a?(Hash)

            item = condition.compact
            item.delete("observedGeneration") if item["observedGeneration"] == 0
            item["message"] ||= ""
            item
          end
        end
        result
      end

      # Thresholds use the IntOrString union, whose integer arm is int32.
      def pod_disruption_budget_wire_errors(root)
        {"spec" => PDB_THRESHOLDS, "status" => PDB_STATUS_FIELDS}.flat_map do |parent, fields|
          object = fetch(root, parent)
          fields.filter_map do |field|
            value = fetch(object, field)
            next unless value.is_a?(Integer) && !PDB_INT32.cover?(value)

            ValidationIssue.new(path: [parent, field], code: :type, value: value, message: "integer is out of range", expected: :int32)
          end
        end
      end

      # pkg/apis/policy/validation ValidatePodDisruptionBudgetSpec.
      def pod_disruption_budget_errors(root, old)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        if PDB_THRESHOLDS.none? { |field| fetch(spec, field).nil? }
          value = {"MinAvailable" => fetch(spec, "minAvailable"), "Selector" => workload_selector_value(fetch(spec, "selector")),
                   "MaxUnavailable" => fetch(spec, "maxUnavailable"), "UnhealthyPodEvictionPolicy" => fetch(spec, "unhealthyPodEvictionPolicy")}
          issues << valued_issue(["spec"], go_value(InternalPodSpec.compact(value)), "minAvailable and maxUnavailable cannot be both set")
        end
        PDB_THRESHOLDS.each do |field|
          issues.concat(pod_disruption_budget_threshold_errors(fetch(spec, field), ["spec", field]))
        end
        selector_path = %w[spec selector]
        previous = value_at_path(old, selector_path)
        legacy = label_selector_errors(previous, selector_path, wire_values: true).any?
        issues.concat(label_selector_errors(fetch(spec, "selector"), selector_path, allow_invalid_expression_values: legacy, wire_values: true))
        policy = fetch(spec, "unhealthyPodEvictionPolicy")
        if policy.is_a?(String) && !PDB_EVICTION_POLICIES.include?(policy)
          issues << job_unsupported_value(%w[spec unhealthyPodEvictionPolicy], go_value(InternalPodSpec.go_string(policy)), PDB_EVICTION_POLICIES)
        end
        issues
      end

      def pod_disruption_budget_threshold_errors(value, path)
        return [valued_issue(path, value, IS_NEGATIVE_ERROR_MSG)] if value.is_a?(Integer) && value.negative?
        return [] unless value.is_a?(String)

        detail = if !value.match?(/\A[0-9]+%\z/)
                   PDB_PERCENT_SYNTAX
                 elsif value.sub(/\A0+/, "").bytesize > 4 || value.to_i > 100
                   "must not be greater than 100%"
                 end
        detail ? [valued_issue(path, go_value(InternalPodSpec.go_string(value)), detail)] : []
      end

      def pod_disruption_budget_status_errors(root)
        status = fetch(root, "status")
        issues = meta_conditions_errors(Array(fetch(status, "conditions")), %w[status conditions], wire_values: true)
        PDB_STATUS_FIELDS.each do |field|
          value = fetch(status, field)
          issues << valued_issue(["status", field], value, IS_NEGATIVE_ERROR_MSG) if value.is_a?(Integer) && value.negative?
        end
        issues
      end
    end
  end
end
