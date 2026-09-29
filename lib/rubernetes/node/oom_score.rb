# frozen_string_literal: true

require_relative "../resource_helpers"

module Rubernetes
  module Node
    # pkg/kubelet/qos/policy.go GetContainerOOMScoreAdjust (v1.36.2): the
    # oom_score_adj a container's processes run with, so the kernel's OOM
    # killer takes BestEffort before Burstable before Guaranteed.  Containers
    # used to inherit the agent's own value, every one equal.
    module OOMScore
      KUBELET = -999
      GUARANTEED = -997
      BEST_EFFORT = 1000
      SYSTEM_CRITICAL_PRIORITY = 2 * 1_000_000_000
      SYSTEM_NODE_CRITICAL = "system-node-critical"

      module_function

      def container_adjust(pod, container, memory_capacity:)
        capacity = Integer(memory_capacity)
        raise ArgumentError, "memory capacity must be positive" unless capacity.positive?
        return GUARANTEED if node_critical?(pod)

        case ResourceHelpers.pod_qos(pod)
        when "Guaranteed" then return GUARANTEED
        when "BestEffort" then return BEST_EFFORT
        end

        request = memory_request(container)
        remaining = 0
        adjust = if ResourceHelpers.pod_level_requests_set?(pod)
                   remaining = remaining_pod_memory_per_container(pod)
                   1000 - truncate(1000 * (request + remaining), capacity)
                 else
                   1000 - truncate(1000 * request, capacity)
                 end
        if sidecar?(pod, container)
          minimum = min_regular_memory(pod) + (ResourceHelpers.pod_level_requests_set?(pod) ? remaining : 0)
          adjust = [adjust, 1000 - truncate(1000 * minimum, capacity)].min
        end
        return 1000 + GUARANTEED if adjust < 1000 + GUARANTEED
        return adjust - 1 if adjust == BEST_EFFORT

        adjust
      end

      # Go integer division truncates toward zero.
      def truncate(numerator, denominator) = (numerator.to_r / denominator).truncate

      def memory_request(container)
        quantity = ResourceHelpers.resource_list(container.is_a?(Hash) ? container.dig("resources", "requests") : nil)["memory"]
        quantity ? quantity.value.ceil : 0
      end

      def sidecar?(pod, container)
        container["restartPolicy"].to_s == "Always" &&
          ResourceHelpers.containers(pod, "initContainers").any? { |candidate| candidate["name"] == container["name"] }
      end

      def min_regular_memory(pod)
        ResourceHelpers.containers(pod, "containers").map { |container| memory_request(container) }.min || 0
      end

      # remainingPodMemReqPerContainer: pod-level memory request the containers
      # do not claim, shared equally by every regular and init container.
      def remaining_pod_memory_per_container(pod)
        pod_request = ResourceHelpers.resource_list(ResourceHelpers.pod_resources(pod)&.dig("requests"))["memory"]
        return 0 if pod_request.nil? || pod_request.zero?

        count = ResourceHelpers.containers(pod, "containers").length + ResourceHelpers.containers(pod, "initContainers").length
        return 0 if count.zero?

        aggregate = ResourceHelpers.aggregate_container_requests(pod)["memory"]
        truncate(pod_request.value.ceil - (aggregate ? aggregate.value.ceil : 0), count)
      end

      # types.IsNodeCriticalPod: a critical Pod (static, mirror or of system
      # priority) of the system-node-critical class.
      def node_critical?(pod)
        spec = ResourceHelpers.spec(pod)
        return false unless spec["priorityClassName"].to_s == SYSTEM_NODE_CRITICAL

        annotations = pod.dig("metadata", "annotations") || {}
        source = annotations["kubernetes.io/config.source"]
        static = !source.nil? && source != "api"
        mirror = annotations.key?("kubernetes.io/config.mirror")
        static || mirror || spec["priority"].to_i >= SYSTEM_CRITICAL_PRIORITY
      end
    end
  end
end
