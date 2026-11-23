# frozen_string_literal: true

require_relative "../../label_requirement"

module Rubernetes
  module Schema
    # apps workload controllers: selector/template
    # agreement, the fields each Update function freezes, and the PDB spec.
    module KubernetesValidator
      module_function

      def replication_controller_count_errors(root)
        spec = fetch(root, "spec")
        replicas = fetch(spec, "replicas")
        fields = []
        ready_seconds = fetch(spec, "minReadySeconds")
        fields << issue(%w[spec minReadySeconds], :invalid, IS_NEGATIVE_ERROR_MSG) if ready_seconds.is_a?(Integer) && ready_seconds.negative?
        if replicas.nil?
          fields << issue(%w[spec replicas], :required, "")
        elsif replicas.is_a?(Integer) && replicas.negative?
          fields << issue(%w[spec replicas], :invalid, IS_NEGATIVE_ERROR_MSG)
        end
        fields
      end

      def deployment_replica_errors(root)
        replicas = fetch(fetch(root, "spec"), "replicas")
        return [] unless replicas.is_a?(Integer) && replicas.negative?

        [issue(%w[spec replicas], :invalid, IS_NEGATIVE_ERROR_MSG)]
      end

      WORKLOAD_SELECTOR_PATH = %w[spec selector].freeze
      WORKLOAD_TEMPLATE_PATH = %w[spec template].freeze
      WORKLOAD_TEMPLATE_LABELS_PATH = %w[spec template metadata labels].freeze
      WORKLOAD_SELECTOR_NAMES = {"Deployment" => "deployment", "ReplicaSet" => "deployment",
                                 "StatefulSet" => "statefulset", "DaemonSet" => "daemonset"}.freeze

      def selector_errors(root, kind, old: nil)
        return [] unless kind == "ReplicationController" || WORKLOAD_SELECTOR_NAMES.key?(kind)

        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        selector = fetch(spec, "selector")
        return [] unless selector.nil? || selector.is_a?(Hash)

        template = fetch(spec, "template")
        labels = workload_label_map(value_at_path(template, %w[metadata labels]))
        return replication_controller_selector_errors(selector, template, labels) if kind == "ReplicationController"

        parsed = workload_selector_value(selector)
        issues, convertible = apps_selector_validation(kind, parsed, old: old)
        issues << valued_issue(WORKLOAD_TEMPLATE_LABELS_PATH, labels, SELECTOR_LABELS_MISMATCH) if convertible && !workload_selector_matches?(parsed, labels)
        issues << issue(%w[spec template spec containers], :required, "") if fetch(template, "spec").nil? && (convertible || kind == "DaemonSet")
        issues
      end

      def skip_app_template_validation?(kind, issues)
        return false if kind == "DaemonSet" || !WORKLOAD_SELECTOR_NAMES.key?(kind)

        # An invalid parsed selector has specific syntax causes below
        # spec.selector. The nil and empty selector cases still validate the template.
        issues.any? { |candidate| candidate.path.length > 2 && candidate.path[0, 2] == WORKLOAD_SELECTOR_PATH }
      end

      def replication_controller_selector_errors(selector, template, labels)
        selector = workload_label_map(selector) || {}
        issues = []
        issues << issue(WORKLOAD_SELECTOR_PATH, :required, "") if selector.empty?
        if template.nil?
          issues << issue(%w[spec template], :required, "")
        elsif !workload_label_map_matches?(selector, labels || {})
          issues << valued_issue(WORKLOAD_TEMPLATE_LABELS_PATH, labels, SELECTOR_LABELS_MISMATCH)
        end
        issues << issue(%w[spec template spec containers], :required, "") if template.is_a?(Hash) && fetch(template, "spec").nil?
        issues
      end

      def apps_selector_validation(kind, selector, old:)
        if selector.nil?
          # ValidateDaemonSetSpec reports only template mismatch for a nil selector.
          errors = kind == "DaemonSet" ? [] : [issue(WORKLOAD_SELECTOR_PATH, :required, "")]
          return [errors, true]
        end
        if selector.empty?
          kind_name = WORKLOAD_SELECTOR_NAMES.fetch(kind)
          return [[valued_issue(WORKLOAD_SELECTOR_PATH, selector, "empty selector is invalid for #{kind_name}")], true]
        end

        syntax = label_selector_errors(selector, WORKLOAD_SELECTOR_PATH)
        return [syntax, true] if syntax.empty?

        if kind == "DaemonSet"
          old_selector = value_at_path(old, WORKLOAD_SELECTOR_PATH)
          if workload_selector_has_invalid_expression_value?(old_selector)
            syntax = label_selector_errors(selector, WORKLOAD_SELECTOR_PATH, allow_invalid_expression_values: true)
          end
        else
          message = kind == "StatefulSet" ? "" : "invalid label selector"
          syntax << valued_issue(WORKLOAD_SELECTOR_PATH, selector, message)
        end
        [syntax, false]
      end

      # The API's typed metav1.LabelSelector omits empty slices and maps when
      # field.Invalid renders its BadValue. Map keys are serialized in order.
      def workload_selector_value(selector)
        return nil unless selector.is_a?(Hash)

        canonical = {}
        labels = workload_label_map(fetch(selector, "matchLabels"))
        canonical["matchLabels"] = labels if labels && !labels.empty?
        expressions = Array(fetch(selector, "matchExpressions")).map do |entry|
          expression = {"key" => fetch(entry, "key").to_s, "operator" => fetch(entry, "operator").to_s}
          values = Array(fetch(entry, "values")).map(&:to_s)
          expression["values"] = values unless values.empty?
          expression
        end
        canonical["matchExpressions"] = expressions unless expressions.empty?
        canonical
      end

      def workload_selector_matches?(selector, labels)
        return false unless selector.is_a?(Hash)

        labels = workload_label_map(labels) || {}
        matching = workload_label_map(fetch(selector, "matchLabels")) || {}
        workload_label_map_matches?(matching, labels) && Array(fetch(selector, "matchExpressions")).all? do |expression|
          key = fetch(expression, "key").to_s
          values = Array(fetch(expression, "values")).map(&:to_s)
          LabelRequirement.matches?(fetch(expression, "operator").to_s, labels[key], values, present: labels.key?(key))
        end
      end

      def workload_label_map(labels)
        return nil unless labels.is_a?(Hash)

        labels.to_h { |key, value| [key.to_s, value.to_s] }.sort.to_h
      end

      def workload_label_map_matches?(selector, labels)
        selector.all? { |key, value| labels.key?(key) && labels[key] == value }
      end

      def workload_selector_has_invalid_expression_value?(selector)
        Array(fetch(selector, "matchExpressions")).any? do |expression|
          Array(fetch(expression, "values")).any? { |value| !label_value_messages(value).empty? }
        end
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
    end
  end
end
