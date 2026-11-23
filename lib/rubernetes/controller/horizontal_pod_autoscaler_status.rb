# frozen_string_literal: true

module Rubernetes
  module Controller
    module HorizontalPodAutoscalerStatus
      private

      def independent_metrics?(hpa)
        Array(hpa.dig("spec", "metrics")).any? { |metric| %w[Object External].include?(metric["type"]) }
      end

      def compute_from_zero?(hpa, enabled, minimum)
        scaled_to_zero = Array(hpa.dig("status", "conditions")).any? do |condition|
          condition["type"] == "ScaledToZero" && condition["status"] == "True"
        end
        return true if enabled && scaled_to_zero && (minimum.positive? || independent_metrics?(hpa))

        set_condition(hpa, "ScalingActive", "False", "ScalingDisabled", "scaling is disabled since the replica count of the target is zero")
        remove_condition(hpa, "ScaledToZero") unless enabled
        false
      end

      def record_zero_condition(hpa, enabled, desired, minimum)
        return remove_condition(hpa, "ScaledToZero") unless enabled

        if desired.zero? && minimum.zero? && independent_metrics?(hpa)
          set_condition(hpa, "ScaledToZero", "True", "ScaledToZero", "the HPA controller scaled the workload to zero")
        else
          set_condition(hpa, "ScaledToZero", "False", "NotScaledToZero", "the HPA controller did not scale the workload to zero")
        end
      end

      def set_status(hpa, current, desired, statuses, rescale)
        status = hpa["status"]
        updated = {"currentReplicas" => current, "desiredReplicas" => desired}
        updated["lastScaleTime"] = status["lastScaleTime"] if status["lastScaleTime"]
        updated["lastScaleTime"] = @clock.call.utc.strftime("%Y-%m-%dT%H:%M:%SZ") if rescale
        # CurrentMetrics: one entry per metric spec, empty for a metric that
        # could not be computed.
        updated["currentMetrics"] = statuses unless statuses.nil? || statuses.empty?
        updated["conditions"] = status["conditions"] if status["conditions"]
        observed = Support.value(Support.metadata(hpa), "generation", nil)
        updated["observedGeneration"] = observed unless observed.nil?
        hpa["status"] = updated
      end

      # setConditionInList.
      def set_condition(hpa, type, status, reason, message)
        conditions = (hpa["status"]["conditions"] ||= [])
        existing = conditions.find { |condition| condition["type"] == type }
        unless existing
          existing = {"type" => type}
          conditions << existing
        end
        existing["lastTransitionTime"] = @clock.call.utc.strftime("%Y-%m-%dT%H:%M:%SZ") if existing["status"] != status
        existing["status"] = status
        existing["reason"] = reason
        existing["message"] = message
        existing
      end

      def remove_condition(hpa, type)
        conditions = hpa["status"]["conditions"]
        conditions&.reject! { |condition| condition["type"] == type }
      end
    end
  end
end
