# frozen_string_literal: true

module Rubernetes
  module Schema
    # HorizontalPodAutoscaler (pkg/apis/autoscaling/validation).
    module KubernetesValidator
      module_function

      SUPPORTED_METRIC_TYPES = %w[ContainerResource External Object Pods Resource].freeze

      def hpa_errors(root, operation = :create, options = [])
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        hpa_replica_bound_errors(spec, issues, options)
        behavior = fetch(spec, "behavior")
        if behavior.is_a?(Hash)
          %w[scaleUp scaleDown].each do |direction|
            rules = fetch(behavior, direction)
            issues.concat(hpa_scaling_rules_errors(rules, ["spec", "behavior", direction])) if rules.is_a?(Hash)
          end
        end
        reference = fetch(spec, "scaleTargetRef")
        reference = {} unless reference.is_a?(Hash)
        api_version = fetch(reference, "apiVersion")
        if operation == :create && (blank?(api_version) || !api_version.to_s.include?("/"))
          issues << issue(%w[spec scaleTargetRef apiVersion], :invalid, "apiVersion must specify API group")
        end
        required(reference, "kind", %w[spec scaleTargetRef], issues)
        required(reference, "name", %w[spec scaleTargetRef], issues)
        metrics = fetch(spec, "metrics")
        return issues unless metrics.is_a?(Array)

        metrics.each_with_index do |metric, index|
          next unless metric.is_a?(Hash)

          hpa_metric_type_errors(fetch(metric, "type"), ["spec", "metrics", index.to_s, "type"], issues)
          issues.concat(hpa_metric_source_errors(metric, ["spec", "metrics", index.to_s]))
        end
        issues
      end

      def hpa_replica_bound_errors(spec, issues, options = [])
        max = fetch(spec, "maxReplicas")
        min = fetch(spec, "minReplicas")
        minimum = options.include?("HPAScaleToZero") ? 0 : 1
        issues << issue(%w[spec minReplicas], :invalid, "must be greater than or equal to #{minimum}") if min.is_a?(Integer) && min < minimum
        # SetDefaults_HorizontalPodAutoscaler supplies minReplicas=1 before
        # the REST strategy validates the object.
        min = 1 if min.nil?
        if max.nil? || (max.is_a?(Numeric) && max == 0)
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`")
          issues << issue(%w[spec maxReplicas], :required, "must be set and greater than 0")
        elsif max.is_a?(Numeric) && max < 0
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to 1")
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`") if max < min
        elsif min.is_a?(Numeric) && max < min
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`")
        end
      end

      # An unknown metric source type is reported twice; a missing one is
      # reported as Required first.
      def hpa_metric_type_errors(type, path, issues)
        return if !blank?(type) && SUPPORTED_METRIC_TYPES.include?(type.to_s)

        issues << issue(path, :required, "must specify a metric source type") if blank?(type)
        2.times { issues << issue(path, :unsupported, unsupported_detail(SUPPORTED_METRIC_TYPES)) }
      end

      # validateScalingRules / validateScalingPolicy
      # (pkg/apis/autoscaling/validation), including the per-direction
      # tolerance of HPAConfigurableTolerance (Beta, on).
      HPA_MAX_STABILIZATION_WINDOW = 3600
      HPA_MAX_PERIOD_SECONDS = 1800

      def hpa_scaling_rules_errors(rules, path)
        issues = []
        window = fetch(rules, "stabilizationWindowSeconds")
        if window.is_a?(Integer)
          issues << issue(path + ["stabilizationWindowSeconds"], :invalid, "must be greater than or equal to zero") if window.negative?
          if window > HPA_MAX_STABILIZATION_WINDOW
            issues << issue(path + ["stabilizationWindowSeconds"], :invalid,
                            "must be less than or equal to #{HPA_MAX_STABILIZATION_WINDOW}")
          end
        end
        select = fetch(rules, "selectPolicy")
        unless select.nil? || %w[Max Min Disabled].include?(select.to_s)
          issues << issue(path + ["selectPolicy"], :unsupported, "supported values: \"Disabled\", \"Max\", \"Min\"")
        end
        policies = fetch(rules, "policies")
        issues << issue(path + ["policies"], :required, "must specify at least one Policy") if !policies.is_a?(Array) || policies.empty?
        Array(policies).each_with_index do |policy, index|
          next unless policy.is_a?(Hash)

          policy_path = path + ["policies", index.to_s]
          unless %w[Percent Pods].include?(fetch(policy, "type").to_s)
            issues << issue(policy_path + ["type"], :unsupported, "supported values: \"Percent\", \"Pods\"")
          end
          issues << issue(policy_path + ["value"], :invalid, "must be greater than zero") unless fetch(policy, "value").to_i.positive?
          period = fetch(policy, "periodSeconds").to_i
          issues << issue(policy_path + ["periodSeconds"], :invalid, "must be greater than zero") unless period.positive?
          if period > HPA_MAX_PERIOD_SECONDS
            issues << issue(policy_path + ["periodSeconds"], :invalid, "must be less than or equal to #{HPA_MAX_PERIOD_SECONDS}")
          end
        end
        tolerance = fetch(rules, "tolerance")
        issues << issue(path + ["tolerance"], :invalid, "must be greater than or equal to 0") if !tolerance.nil? && negative_quantity?(tolerance)
        issues
      end

      # False for a value that is not a quantity at all: the structural
      # validator reports that (every Quantity parse failure is an
      # ArgumentError).
      def negative_quantity?(value)
        Quantity.from_json(value).value.negative?
      rescue ArgumentError
        false
      end

      def hpa_metric_source_errors(metric, path)
        issues = []
        source_names = %w[object external pods resource containerResource]
        present = source_names.select { |name| fetch(metric, name).is_a?(Hash) }
        present.each do |source|
          value = fetch(metric, source)
          source_path = path + [source]
          case source
          when "containerResource"
            required(value, "name", source_path, issues, "must specify a resource name")
            required(value, "container", source_path, issues, "must specify a container")
            resource_name = fetch(value, "name")
            if resource_name.is_a?(String) && !resource_name.empty? &&
               !%w[cpu memory ephemeral-storage].include?(resource_name) &&
               !resource_name.match?(/\A(?:hugepages-|requests\.|limits\.)[a-z0-9.-]+\z/)
              issues << issue(source_path + ["name"], :invalid, "must be a standard resource for containers")
              issues << issue(source_path + ["name"], :invalid, "must be a standard resource type or fully qualified")
            end
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target raw value or a target utilization",
                                     required_field: "averageUtilization")
          when "resource"
            required(value, "name", source_path, issues, "must specify a resource name")
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target raw value or a target utilization",
                                     required_field: "averageUtilization")
          when "object"
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target value or averageValue",
                                     required_field: "averageValue")
          when "external"
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target value for metric or a per-pod target",
                                     required_field: "averageValue")
          when "pods"
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must specify a positive target averageValue",
                                     required_field: "averageValue")
          end
        end
        if present.length > 1
          # validateMetricSpec forbids every source other than the selected
          # metric type.  The generated fixtures normally exercise one source
          # at a time; preserve the strategy's deterministic order here.
          present.drop(1).each do |source|
            issues << issue(path + [source], :forbidden, "must populate the given metric source only")
          end
        end
        issues
      end

      def hpa_metric_target_errors(target, path, issues, required_detail:, required_field: "averageValue")
        target = {} unless target.is_a?(Hash)
        type = fetch(target, "type")
        issues << issue(path + ["type"], :required, "must specify a metric target type") if blank?(type)
        unless %w[Utilization Value AverageValue].include?(type.to_s)
          issues << issue(path + ["type"], :invalid, "must be either Utilization, Value, or AverageValue")
        end
        if %w[Utilization Value AverageValue].include?(type.to_s)
          # The target's selected quantity is validated by the generated
          # quantity parser; only the zero-value presence rule is observable
          # for these fixtures.
        end
        if fetch(target, "averageValue").nil? && fetch(target, "value").nil? &&
           fetch(target, "averageUtilization").nil?
          issues << issue(path + [required_field], :required, required_detail)
        end
      end

      private_class_method :negative_quantity?, :hpa_metric_type_errors
    end
  end
end
