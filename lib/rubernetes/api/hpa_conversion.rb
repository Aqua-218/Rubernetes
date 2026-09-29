# frozen_string_literal: true

require "json"

module Rubernetes
  module API
    # autoscaling/v1 <-> autoscaling/v2 HorizontalPodAutoscaler, the port of
    # pkg/apis/autoscaling/v1/conversion.go (v1.36.2) with the internal type
    # standing in as the v2 shape (v2 converts to it field for field, and
    # drops the round-trip annotations both ways).
    #
    # v1 carries only a CPU utilisation target; everything else rides in
    # annotations: the other metric specs and statuses as v1 JSON, the
    # behavior as the internal Go struct's JSON (no json tags, so the Go
    # field names), and the conditions.
    module HPAConversion
      V1 = "autoscaling/v1"
      V2 = "autoscaling/v2"
      METRIC_SPECS = "autoscaling.alpha.kubernetes.io/metrics"
      METRIC_STATUSES = "autoscaling.alpha.kubernetes.io/current-metrics"
      CONDITIONS = "autoscaling.alpha.kubernetes.io/conditions"
      BEHAVIOR = "autoscaling.alpha.kubernetes.io/behavior"
      TOLERANCE_SCALE_DOWN = "autoscaling.alpha.kubernetes.io/scale-down-tolerance"
      TOLERANCE_SCALE_UP = "autoscaling.alpha.kubernetes.io/scale-up-tolerance"
      ROUND_TRIP = [METRIC_SPECS, BEHAVIOR, TOLERANCE_SCALE_DOWN, TOLERANCE_SCALE_UP, METRIC_STATUSES, CONDITIONS].freeze
      DEFAULT_CPU_UTILIZATION = 80

      module_function

      # Converts between the two served shapes; other versions pass through.
      def convert(object, to_version:)
        return object unless object.is_a?(Hash)

        from = object["apiVersion"].to_s
        return object if from == to_version

        case [from, to_version]
        when [V1, V2] then to_v2(object)
        when [V2, V1] then to_v1(object)
        else object
        end
      end

      # Lists convert item by item.
      def convert_list(list, to_version:)
        return convert(list, to_version: to_version) unless list.is_a?(Hash) && list["items"].is_a?(Array)

        list.merge("apiVersion" => to_version, "items" => list["items"].map { |item| convert(item.merge("apiVersion" => item["apiVersion"] || list["apiVersion"]), to_version: to_version) })
      end

      # ------------------------------------------------------------ v1 -> v2

      def to_v2(object)
        result = deep_copy(object)
        result["apiVersion"] = V2
        spec = object["spec"].is_a?(Hash) ? object["spec"] : {}
        status = object["status"].is_a?(Hash) ? object["status"] : nil
        annotations = object.dig("metadata", "annotations").is_a?(Hash) ? object.dig("metadata", "annotations") : {}

        out_spec = {}
        out_spec["scaleTargetRef"] = deep_copy(spec["scaleTargetRef"]) if spec.key?("scaleTargetRef")
        out_spec["minReplicas"] = spec["minReplicas"] unless spec["minReplicas"].nil?
        out_spec["maxReplicas"] = spec["maxReplicas"] if spec.key?("maxReplicas")
        metrics = nil
        unless spec["targetCPUUtilizationPercentage"].nil?
          metrics = [cpu_metric(spec["targetCPUUtilizationPercentage"])]
        end
        if annotations.key?(METRIC_SPECS) && (others = parse_json_array(annotations[METRIC_SPECS]))
          converted = others.map { |metric| v1_metric_spec_to_v2(metric) }
          converted << metrics.first if metrics
          metrics = converted
        end
        if annotations.key?(BEHAVIOR) && (behavior = parse_json_object(annotations[BEHAVIOR]))
          decoded = internal_behavior_to_v2(behavior)
          out_spec["behavior"] = v2_behavior_defaults(decoded) unless decoded.empty?
        end
        metrics = [cpu_metric(DEFAULT_CPU_UTILIZATION)] if metrics.nil? || metrics.empty?
        out_spec["metrics"] = metrics
        result["spec"] = out_spec

        # The v2 status is a struct (always present) and currentMetrics is not
        # omitempty: null without metrics.
        begin
          status ||= {}
          out_status = {}
          %w[observedGeneration lastScaleTime].each { |key| out_status[key] = status[key] unless status[key].nil? }
          # v2 currentReplicas is omitempty; desiredReplicas is not.
          out_status["currentReplicas"] = status["currentReplicas"].to_i unless status["currentReplicas"].to_i.zero?
          out_status["desiredReplicas"] = status["desiredReplicas"].to_i
          out_status["currentMetrics"] = nil
          unless status["currentCPUUtilizationPercentage"].nil?
            out_status["currentMetrics"] = [{"type" => "Resource",
                                             "resource" => {"name" => "cpu", "current" => {"averageUtilization" => status["currentCPUUtilizationPercentage"]}}}]
          end
          if annotations.key?(METRIC_STATUSES) && (statuses = parse_json_array(annotations[METRIC_STATUSES]))
            out_status["currentMetrics"] = statuses.map { |metric| v1_metric_status_to_v2(metric) }
          end
          if annotations.key?(CONDITIONS) && (conditions = parse_json_array(annotations[CONDITIONS]))
            out_status["conditions"] = conditions.map { |condition| v1_condition(condition) }
          end
          result["status"] = out_status
        end
        drop_round_trip(result)
      end

      # SetDefaults_HorizontalPodAutoscalerBehavior, which every read of the
      # stored v2 object applies.
      def v2_behavior_defaults(behavior)
        {"scaleUp" => scaling_rules(behavior["scaleUp"], Schema::Defaulting::HPA_SCALE_UP_RULES),
         "scaleDown" => scaling_rules(behavior["scaleDown"], Schema::Defaulting::HPA_SCALE_DOWN_RULES)}
      end

      def scaling_rules(from, defaults)
        rules = deep_copy(defaults)
        return rules unless from.is_a?(Hash)

        %w[selectPolicy stabilizationWindowSeconds policies tolerance].each { |key| rules[key] = deep_copy(from[key]) unless from[key].nil? }
        rules
      end

      def cpu_metric(utilization)
        {"type" => "Resource", "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => utilization}}}
      end

      # encoding/json field matching is case-insensitive.
      def field(hash, name)
        return nil unless hash.is_a?(Hash)
        return hash[name] if hash.key?(name)

        hash.find { |key, _| key.to_s.casecmp?(name) }&.last
      end

      def v1_metric_spec_to_v2(metric)
        out = {"type" => field(metric, "type").to_s}
        if (object = field(metric, "object"))
          average = field(object, "averageValue")
          target_value = field(object, "targetValue") || "0"
          target = if average.nil?
                     {"type" => "Value", "value" => target_value}
                   else
                     {"type" => "AverageValue", "averageValue" => average}.tap do |entry|
                       entry["value"] = target_value unless zero_quantity?(target_value)
                     end
                   end
          out["object"] = {"describedObject" => cross_reference(field(object, "target")), "target" => target,
                           "metric" => identifier(field(object, "metricName"), field(object, "selector"))}
        end
        if (pods = field(metric, "pods"))
          out["pods"] = {"metric" => identifier(field(pods, "metricName"), field(pods, "selector")),
                         "target" => {"type" => "AverageValue", "averageValue" => field(pods, "targetAverageValue") || "0"}}
        end
        if (resource = field(metric, "resource"))
          out["resource"] = {"name" => field(resource, "name").to_s,
                             "target" => resource_target(field(resource, "targetAverageUtilization"), field(resource, "targetAverageValue"))}
        end
        if (container = field(metric, "containerResource"))
          out["containerResource"] = {"name" => field(container, "name").to_s, "container" => field(container, "container").to_s,
                                      "target" => resource_target(field(container, "targetAverageUtilization"),
                                                                  field(container, "targetAverageValue"))}
        end
        if (external = field(metric, "external"))
          value = field(external, "targetValue")
          target = {"type" => value.nil? ? "AverageValue" : "Value"}
          target["value"] = value unless value.nil?
          target["averageValue"] = field(external, "targetAverageValue") unless field(external, "targetAverageValue").nil?
          out["external"] = {"metric" => identifier(field(external, "metricName"), field(external, "metricSelector")), "target" => target}
        end
        out
      end

      def resource_target(utilization, average)
        target = {"type" => utilization.nil? ? "AverageValue" : "Utilization"}
        target["averageValue"] = average unless average.nil?
        target["averageUtilization"] = utilization unless utilization.nil?
        target
      end

      def v1_metric_status_to_v2(metric)
        out = {"type" => field(metric, "type").to_s}
        if (object = field(metric, "object"))
          current = {"value" => field(object, "currentValue") || "0"}
          current["averageValue"] = field(object, "averageValue") unless field(object, "averageValue").nil?
          out["object"] = {"metric" => identifier(field(object, "metricName"), field(object, "selector")), "current" => current,
                           "describedObject" => cross_reference(field(object, "target"))}
        end
        if (pods = field(metric, "pods"))
          out["pods"] = {"metric" => identifier(field(pods, "metricName"), field(pods, "selector")),
                         "current" => {"averageValue" => field(pods, "currentAverageValue") || "0"}}
        end
        if (resource = field(metric, "resource"))
          out["resource"] = {"name" => field(resource, "name").to_s,
                             "current" => resource_current(field(resource, "currentAverageUtilization"), field(resource, "currentAverageValue"))}
        end
        if (container = field(metric, "containerResource"))
          out["containerResource"] = {"name" => field(container, "name").to_s, "container" => field(container, "container").to_s,
                                      "current" => resource_current(field(container, "currentAverageUtilization"),
                                                                    field(container, "currentAverageValue"))}
        end
        if (external = field(metric, "external"))
          current = {"value" => field(external, "currentValue") || "0"}
          current["averageValue"] = field(external, "currentAverageValue") unless field(external, "currentAverageValue").nil?
          out["external"] = {"metric" => identifier(field(external, "metricName"), field(external, "metricSelector")), "current" => current}
        end
        out
      end

      def resource_current(utilization, average)
        current = {"averageValue" => average || "0"}
        current["averageUtilization"] = utilization unless utilization.nil?
        current
      end

      def identifier(name, selector)
        result = {"name" => name.to_s}
        result["selector"] = selector unless selector.nil?
        result
      end

      def cross_reference(reference)
        reference = reference.is_a?(Hash) ? reference : {}
        result = {"kind" => field(reference, "kind").to_s, "name" => field(reference, "name").to_s}
        api_version = field(reference, "apiVersion").to_s
        result["apiVersion"] = api_version unless api_version.empty?
        result
      end

      def v1_condition(condition)
        result = {"type" => field(condition, "type").to_s, "status" => field(condition, "status").to_s}
        time = field(condition, "lastTransitionTime")
        result["lastTransitionTime"] = time unless time.nil?
        %w[reason message].each do |key|
          value = field(condition, key).to_s
          result[key] = value unless value.empty?
        end
        result
      end

      # The internal HorizontalPodAutoscalerBehavior's JSON (Go field names).
      def internal_behavior_to_v2(behavior)
        result = {}
        {"ScaleUp" => "scaleUp", "ScaleDown" => "scaleDown"}.each do |go_name, name|
          rules = field(behavior, go_name)
          next unless rules.is_a?(Hash)

          out = {}
          window = field(rules, "StabilizationWindowSeconds")
          out["stabilizationWindowSeconds"] = window unless window.nil?
          select = field(rules, "SelectPolicy")
          out["selectPolicy"] = select unless select.nil?
          policies = field(rules, "Policies")
          unless policies.nil?
            out["policies"] = Array(policies).map do |policy|
              {"type" => field(policy, "Type").to_s, "value" => field(policy, "Value").to_i, "periodSeconds" => field(policy, "PeriodSeconds").to_i}
            end
          end
          tolerance = field(rules, "Tolerance")
          out["tolerance"] = tolerance unless tolerance.nil?
          result[name] = out
        end
        result
      end

      # ------------------------------------------------------------ v2 -> v1

      def to_v1(object)
        result = deep_copy(object)
        result["apiVersion"] = V1
        spec = object["spec"].is_a?(Hash) ? object["spec"] : {}
        status = object["status"].is_a?(Hash) ? object["status"] : {}
        metrics = Array(spec["metrics"])

        out_spec = {}
        out_spec["scaleTargetRef"] = deep_copy(spec["scaleTargetRef"]) if spec.key?("scaleTargetRef")
        out_spec["minReplicas"] = spec["minReplicas"] unless spec["minReplicas"].nil?
        out_spec["maxReplicas"] = spec["maxReplicas"] if spec.key?("maxReplicas")
        cpu = metrics.find { |metric| cpu_utilization_metric?(metric) }
        out_spec["targetCPUUtilizationPercentage"] = cpu.dig("resource", "target", "averageUtilization") if cpu
        result["spec"] = out_spec

        out_status = {}
        %w[observedGeneration lastScaleTime].each { |key| out_status[key] = status[key] unless status[key].nil? }
        out_status["currentReplicas"] = status["currentReplicas"].to_i
        out_status["desiredReplicas"] = status["desiredReplicas"].to_i
        Array(status["currentMetrics"]).each do |metric|
          next unless metric["type"] == "Resource" && metric["resource"].is_a?(Hash) && metric.dig("resource", "name") == "cpu"

          utilization = metric.dig("resource", "current", "averageUtilization")
          out_status["currentCPUUtilizationPercentage"] = utilization unless utilization.nil?
        end
        result["status"] = out_status

        metadata = result["metadata"].is_a?(Hash) ? result["metadata"] : (result["metadata"] = {})
        annotations = (metadata["annotations"].is_a?(Hash) ? metadata["annotations"] : {}).reject { |key, _| ROUND_TRIP.include?(key) }
        others = metrics.reject { |metric| cpu_utilization_metric?(metric) }
        annotations[METRIC_SPECS] = go_json(others.map { |metric| v2_metric_spec_to_v1(metric) }) unless others.empty?
        current = Array(status["currentMetrics"])
        annotations[METRIC_STATUSES] = go_json(current.map { |metric| v2_metric_status_to_v1(metric) }) unless current.empty?
        annotations[BEHAVIOR] = go_json(v2_behavior_to_internal(spec["behavior"])) if spec["behavior"].is_a?(Hash)
        conditions = Array(status["conditions"])
        annotations[CONDITIONS] = go_json(conditions.map { |condition| v2_condition_to_v1(condition) }) unless conditions.empty?
        if annotations.empty?
          metadata.delete("annotations")
        else
          metadata["annotations"] = annotations
        end
        result
      end

      def cpu_utilization_metric?(metric)
        metric["type"] == "Resource" && metric["resource"].is_a?(Hash) && metric.dig("resource", "name") == "cpu" &&
          !metric.dig("resource", "target", "averageUtilization").nil?
      end

      # v1 MetricSpec in Go struct order, omitempty as tagged.
      def v2_metric_spec_to_v1(metric)
        out = {"type" => metric["type"].to_s}
        if (object = metric["object"]).is_a?(Hash)
          target = object["target"] || {}
          entry = {"target" => v1_cross_reference(object["describedObject"]), "metricName" => object.dig("metric", "name").to_s,
                   "targetValue" => target["value"] || "0"}
          entry["selector"] = object.dig("metric", "selector") unless object.dig("metric", "selector").nil?
          entry["averageValue"] = target["averageValue"] unless target["averageValue"].nil?
          out["object"] = entry
        end
        if (pods = metric["pods"]).is_a?(Hash)
          entry = {"metricName" => pods.dig("metric", "name").to_s, "targetAverageValue" => pods.dig("target", "averageValue") || "0"}
          entry["selector"] = pods.dig("metric", "selector") unless pods.dig("metric", "selector").nil?
          out["pods"] = entry
        end
        if (resource = metric["resource"]).is_a?(Hash)
          entry = {"name" => resource["name"].to_s}
          entry["targetAverageUtilization"] = resource.dig("target", "averageUtilization") unless resource.dig("target", "averageUtilization").nil?
          entry["targetAverageValue"] = resource.dig("target", "averageValue") unless resource.dig("target", "averageValue").nil?
          out["resource"] = entry
        end
        if (container = metric["containerResource"]).is_a?(Hash)
          entry = {"name" => container["name"].to_s}
          entry["targetAverageUtilization"] = container.dig("target", "averageUtilization") unless container.dig("target", "averageUtilization").nil?
          entry["targetAverageValue"] = container.dig("target", "averageValue") unless container.dig("target", "averageValue").nil?
          entry["container"] = container["container"].to_s
          out["containerResource"] = entry
        end
        if (external = metric["external"]).is_a?(Hash)
          entry = {"metricName" => external.dig("metric", "name").to_s}
          entry["metricSelector"] = external.dig("metric", "selector") unless external.dig("metric", "selector").nil?
          entry["targetValue"] = external.dig("target", "value") unless external.dig("target", "value").nil?
          entry["targetAverageValue"] = external.dig("target", "averageValue") unless external.dig("target", "averageValue").nil?
          out["external"] = entry
        end
        out
      end

      def v2_metric_status_to_v1(metric)
        out = {"type" => metric["type"].to_s}
        if (object = metric["object"]).is_a?(Hash)
          entry = {"target" => v1_cross_reference(object["describedObject"]), "metricName" => object.dig("metric", "name").to_s,
                   "currentValue" => object.dig("current", "value") || "0"}
          entry["selector"] = object.dig("metric", "selector") unless object.dig("metric", "selector").nil?
          entry["averageValue"] = object.dig("current", "averageValue") unless object.dig("current", "averageValue").nil?
          out["object"] = entry
        end
        if (pods = metric["pods"]).is_a?(Hash)
          entry = {"metricName" => pods.dig("metric", "name").to_s, "currentAverageValue" => pods.dig("current", "averageValue") || "0"}
          entry["selector"] = pods.dig("metric", "selector") unless pods.dig("metric", "selector").nil?
          out["pods"] = entry
        end
        if (resource = metric["resource"]).is_a?(Hash)
          entry = {"name" => resource["name"].to_s}
          entry["currentAverageUtilization"] = resource.dig("current", "averageUtilization") unless resource.dig("current", "averageUtilization").nil?
          entry["currentAverageValue"] = resource.dig("current", "averageValue") || "0"
          out["resource"] = entry
        end
        if (container = metric["containerResource"]).is_a?(Hash)
          entry = {"name" => container["name"].to_s}
          entry["currentAverageUtilization"] = container.dig("current", "averageUtilization") unless container.dig("current", "averageUtilization").nil?
          entry["currentAverageValue"] = container.dig("current", "averageValue") || "0"
          entry["container"] = container["container"].to_s
          out["containerResource"] = entry
        end
        if (external = metric["external"]).is_a?(Hash)
          entry = {"metricName" => external.dig("metric", "name").to_s}
          entry["metricSelector"] = external.dig("metric", "selector") unless external.dig("metric", "selector").nil?
          entry["currentValue"] = external.dig("current", "value") || "0"
          entry["currentAverageValue"] = external.dig("current", "averageValue") unless external.dig("current", "averageValue").nil?
          out["external"] = entry
        end
        out
      end

      def v1_cross_reference(reference)
        reference = reference.is_a?(Hash) ? reference : {}
        result = {"kind" => reference["kind"].to_s, "name" => reference["name"].to_s}
        result["apiVersion"] = reference["apiVersion"].to_s unless reference["apiVersion"].to_s.empty?
        result
      end

      def v2_condition_to_v1(condition)
        result = {"type" => condition["type"].to_s, "status" => condition["status"].to_s,
                  "lastTransitionTime" => condition["lastTransitionTime"]}
        %w[reason message].each { |key| result[key] = condition[key].to_s unless condition[key].to_s.empty? }
        result
      end

      def v2_behavior_to_internal(behavior)
        {"ScaleUp" => internal_rules(behavior["scaleUp"]), "ScaleDown" => internal_rules(behavior["scaleDown"])}
      end

      def internal_rules(rules)
        return nil unless rules.is_a?(Hash)

        policies = rules["policies"].nil? ? nil : Array(rules["policies"]).map do |policy|
          {"Type" => policy["type"].to_s, "Value" => policy["value"].to_i, "PeriodSeconds" => policy["periodSeconds"].to_i}
        end
        {"StabilizationWindowSeconds" => rules["stabilizationWindowSeconds"], "SelectPolicy" => rules["selectPolicy"],
         "Policies" => policies, "Tolerance" => rules["tolerance"]}
      end

      # ------------------------------------------------------------ helpers

      def drop_round_trip(object)
        annotations = object.dig("metadata", "annotations")
        return object unless annotations.is_a?(Hash) && ROUND_TRIP.any? { |key| annotations.key?(key) }

        kept = annotations.reject { |key, _| ROUND_TRIP.include?(key) }
        if kept.empty?
          object["metadata"].delete("annotations")
        else
          object["metadata"]["annotations"] = kept
        end
        object
      end

      def zero_quantity?(value)
        Schema::Quantity.from_json(value).zero?
      rescue StandardError
        false
      end

      def parse_json_array(text)
        value = JSON.parse(text.to_s)
        value.nil? ? [] : (value.is_a?(Array) ? value : nil)
      rescue JSON::ParserError
        nil
      end

      def parse_json_object(text)
        value = JSON.parse(text.to_s)
        value.is_a?(Hash) ? value : nil
      rescue JSON::ParserError
        nil
      end

      # encoding/json output in insertion order: HTML-safe escaping.
      def go_json(value)
        case value
        when Hash then "{#{value.map { |key, item| "#{TablePrinter::JSONPath.go_json_string(key)}:#{go_json(item)}" }.join(",")}}"
        when Array then "[#{value.map { |item| go_json(item) }.join(",")}]"
        when String then TablePrinter::JSONPath.go_json_string(value)
        when Float then TablePrinter::JSONPath.go_float(value, :json)
        when nil then "null"
        else value.to_s
        end
      end

      def deep_copy(value)
        case value
        when Hash then value.to_h { |key, item| [key, deep_copy(item)] }
        when Array then value.map { |item| deep_copy(item) }
        else value
        end
      end
    end
  end
end

require_relative "../schema/quantity"
require_relative "../schema/defaulting"
require_relative "table_printer/json_path"
