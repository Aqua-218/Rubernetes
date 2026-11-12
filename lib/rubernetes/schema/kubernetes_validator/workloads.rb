# frozen_string_literal: true

module Rubernetes
  module Schema
    # apps workload controllers and PodDisruptionBudget: selector/template
    # agreement, the fields each Update function freezes, and the PDB spec.
    module KubernetesValidator
      module_function

      def selector_errors(root, kind)
        return [] unless %w[Deployment DaemonSet ReplicaSet StatefulSet ReplicationController].include?(kind)

        issues = []
        spec = fetch(root, "spec")
        if spec.is_a?(Hash)
          selector = fetch(spec, "selector")
          template = fetch(spec, "template")
          issues << issue(%w[spec selector], :required, "") if selector.nil? && !(kind == "DaemonSet" && (spec.key?("updateStrategy") || spec.key?("template")))
          if template.nil?
            if kind == "ReplicationController"
              issues << issue(%w[spec template], :required, "")
            else
              issues << issue(%w[spec template metadata labels], :invalid,
                              "`selector` does not match template `labels`")
              issues << issue(%w[spec template spec containers], :required, "")
            end
          end
        end
        walk(root) do |value, path|
          next unless value.is_a?(Hash)

          selector = fetch(value, "selector")
          template = fetch(value, "template")
          if selector.is_a?(Hash) && selector.empty?
            detail = if kind == "ReplicaSet"
                       "empty selector is invalid for deployment"
                     else
                       "empty selector is invalid for #{kind.downcase}"
                     end
            issues << issue(path + ["selector"], :invalid, detail)
            next
          end
          next unless selector.is_a?(Hash) && template.is_a?(Hash)

          labels = fetch(fetch(template, "metadata"), "labels")
          next unless labels.is_a?(Hash)

          match_labels = fetch(selector, "matchLabels")
          next unless match_labels.is_a?(Hash)
          next if match_labels.all? { |key, val| labels[key.to_s] == val }

          issues << issue(path + %w[selector], :invalid, "`selector` does not match template `labels`")
        end
        issues
      end

      # ValidateStatefulSetUpdate: only replicas, ordinals, template,
      # updateStrategy, revisionHistoryLimit, persistentVolumeClaimRetentionPolicy
      # and minReadySeconds may change (pkg/apis/apps/validation/validation.go:268).
      STATEFUL_SET_MUTABLE_FIELDS = %w[replicas ordinals template updateStrategy
                                       revisionHistoryLimit persistentVolumeClaimRetentionPolicy
                                       minReadySeconds].freeze

      def stateful_set_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        mask = lambda do |object|
          spec = fetch(object, "spec")
          next nil unless spec.is_a?(Hash)

          value = deep_copy_value(spec)
          STATEFUL_SET_MUTABLE_FIELDS.each { |field| value.delete(field) }
          # apiequality.Semantic.DeepEqual on the typed object: a nil-valued
          # field is the same as an absent one.
          without_nil_fields(value)
        end
        return [] if mask.call(root) == mask.call(old)

        [issue(%w[spec], :forbidden,
               "updates to statefulset spec for fields other than 'replicas', 'ordinals', " \
               "'template', 'updateStrategy', 'revisionHistoryLimit', " \
               "'persistentVolumeClaimRetentionPolicy' and 'minReadySeconds' are forbidden")]
      end

      # Removes what was reported below spec.template.spec: a StatefulSet
      # update does not validate the pod template it retains.
      def drop_stateful_set_template_issues!(issues)
        issues.reject! do |candidate|
          candidate.path.length >= 4 && candidate.path[0, 3] == %w[spec template spec]
        end
      end

      # ValidateImmutableField, applied per kind exactly where upstream applies
      # it (pkg/apis/*/validation/validation.go).  None of these were enforced,
      # so a StorageClass's provisioner or a Node's podCIDR could be rewritten
      # in place, which upstream refuses.
      IMMUTABLE_FIELDS = {
        "StorageClass" => [%w[provisioner], %w[parameters], %w[reclaimPolicy], %w[volumeBindingMode]],
        # ValidateJobUpdate (pkg/apis/batch/validation/validation.go:627-633).
        "Job" => [%w[spec selector], %w[spec completionMode], %w[spec podFailurePolicy],
                  %w[spec backoffLimitPerIndex], %w[spec managedBy], %w[spec successPolicy]],
        # ValidateDaemonSetSpecUpdate / ValidateDeploymentUpdate /
        # ValidateReplicaSetUpdate: the selector is immutable
        # (pkg/apis/apps/validation/validation.go:403,712,767), and a
        # ControllerRevision's data is immutable (line 366).
        "DaemonSet" => [%w[spec selector]],
        "Deployment" => [%w[spec selector]],
        "ReplicaSet" => [%w[spec selector]],
        "ControllerRevision" => [%w[data]],
        "CSINode" => [],
        "IngressClass" => []
      }.freeze

      def immutable_field_errors(root, old, kind, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        Array(IMMUTABLE_FIELDS[kind]).filter_map do |path|
          before = path.reduce(old) { |value, key| value.is_a?(Hash) ? value[key] : nil }
          after = path.reduce(root) { |value, key| value.is_a?(Hash) ? value[key] : nil }
          next nil if before == after

          issue(path, :invalid, "field is immutable")
        end
      end

      # pkg/apis/policy/validation ValidatePodDisruptionBudgetSpec
      def pod_disruption_budget_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        if !fetch(spec, "minAvailable").nil? && !fetch(spec, "maxUnavailable").nil?
          issues << issue(%w[spec], :invalid, "minAvailable and maxUnavailable cannot be both set")
        end
        policy = fetch(spec, "unhealthyPodEvictionPolicy")
        if !policy.nil? && !%w[AlwaysAllow IfHealthyBudget].include?(policy.to_s)
          issues << issue(%w[spec unhealthyPodEvictionPolicy], :unsupported, unsupported_detail(%w[AlwaysAllow IfHealthyBudget]))
        end
        issues
      end
    end
  end
end
