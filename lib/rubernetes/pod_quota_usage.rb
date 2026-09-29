# frozen_string_literal: true

require "time"
require_relative "resource_helpers"

module Rubernetes
  # pkg/quota/v1/evaluator/core/pods.go PodUsageFunc (v1.36.2): what a Pod
  # charges against a ResourceQuota.  The quota admission plugin and the
  # quota controller both use this, so they cannot disagree about a Pod.
  # Requests/limits come from ResourceHelpers (sidecars, overhead, pod-level
  # resources and in-place-resize status all included).  Values are Rational.
  module PodQuotaUsage
    DEVICE_CLASS_PREFIX = "deviceclass.resource.kubernetes.io/"

    module_function

    ONE = Schema::Quantity.parse("1")

    def usage(pod, now: Time.now.utc)
      quantities(pod, now: now).transform_values(&:value)
    end

    # As #usage, with each value a Schema::Quantity in the format a Go
    # Quantity.Add of these would keep (for the canonical status.used).
    def quantities(pod, now: Time.now.utc)
      result = {"count/pods" => ONE}
      return result unless charged?(pod, now: now)

      requests = ResourceHelpers.pod_requests(pod, use_status_resources: true)
      limits = ResourceHelpers.pod_limits(pod, use_status_resources: true)
      result.merge(compute_usage(requests, limits))
    end

    # podComputeUsageHelper.
    def compute_usage(requests, limits)
      result = {"pods" => ONE}
      %w[cpu memory ephemeral-storage].each do |name|
        if requests.key?(name)
          result[name] = requests[name]
          result["requests.#{name}"] = requests[name]
        end
        result["limits.#{name}"] = limits[name] if limits.key?(name)
      end
      requests.each do |name, value|
        if name.start_with?(ResourceHelpers::HUGE_PAGES_PREFIX)
          result[name] = value
          result["requests.#{name}"] = value
        end
        result["requests.#{name}"] = value if extended_resource?(name) || name.start_with?(DEVICE_CLASS_PREFIX)
      end
      result
    end

    # QuotaV1Pod: a terminal Pod, or one stuck terminating past its grace
    # period, is not charged.
    def charged?(pod, now: Time.now.utc)
      phase = ResourceHelpers.status(pod)["phase"].to_s
      return false if %w[Failed Succeeded].include?(phase)

      metadata = pod["metadata"] || {}
      deletion = metadata["deletionTimestamp"]
      grace = metadata["deletionGracePeriodSeconds"]
      return true if deletion.nil? || grace.nil?

      now <= Time.parse(deletion.to_s) + Integer(grace)
    rescue ArgumentError
      true
    end

    # v1helper.IsExtendedResourceName.
    def extended_resource?(name)
      name = name.to_s
      return false if !name.include?("/") || name.include?("kubernetes.io/") || name.start_with?("requests.")

      prefix, local = "requests.#{name}".split("/", 2)
      prefix.length <= 253 && local.to_s.length.between?(1, 63) &&
        prefix.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/) &&
        local.match?(/\A([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z/)
    end

    # enforcePodContainerConstraints: with cpu/memory quota'd, each container
    # must request (and, for limits.*, limit) them -- unless the Pod sets
    # pod-level resources.  Returns {resource => [container names]}.
    def missing_container_constraints(pod, required)
      return {} if ResourceHelpers.pod_level_resources_set?(pod)

      tracked = %w[cpu memory requests.cpu requests.memory limits.cpu limits.memory] & Array(required).map(&:to_s)
      return {} if tracked.empty?

      (ResourceHelpers.containers(pod, "containers") + ResourceHelpers.containers(pod, "initContainers")).each_with_object({}) do |container, missing|
        requests = ResourceHelpers.resource_list(container.dig("resources", "requests"))
        limits = ResourceHelpers.resource_list(container.dig("resources", "limits"))
        tracked.each do |name|
          base = name.sub(/\A(requests|limits)\./, "")
          present = name.start_with?("limits.") ? limits.key?(base) : requests.key?(base)
          (missing[name] ||= []) << container["name"].to_s unless present
        end
      end
    end
  end
end
