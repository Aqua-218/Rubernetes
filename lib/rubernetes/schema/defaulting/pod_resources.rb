# frozen_string_literal: true

require_relative "../../resource_helpers"

module Rubernetes
  module Schema
    class Defaulting
      private

      def default_pod_level_resources(pod, spec)
        resources = spec["resources"]
        requests = resources["requests"].is_a?(Hash) ? resources["requests"] : nil
        limits = resources["limits"].is_a?(Hash) ? resources["limits"] : nil
        return if (limits.nil? || limits.empty?) && (requests.nil? || requests.empty?)

        helpers = Rubernetes::ResourceHelpers
        # defaultHugePagePodLimits: a hugepage limit set only on containers
        # becomes the pod's, unless the pod requests that hugepage size.
        pod_limits = limits ? limits.dup : {}
        helpers.aggregate_container_limits(pod).each do |name, quantity|
          next unless name.start_with?(helpers::HUGE_PAGES_PREFIX)
          next if requests&.key?(name) || pod_limits.key?(name)

          pod_limits[name] = quantity.to_s
        end
        resources["limits"] = pod_limits unless pod_limits.empty?
        return if pod_limits.empty?

        # defaultPodRequests: overcommittable requests default to the
        # containers' aggregate, anything else to the pod-level limit.
        pod_requests = requests ? requests.dup : {}
        helpers.aggregate_container_requests(pod).each do |name, quantity|
          next unless helpers.supported_pod_level_resource?(name) && !name.start_with?(helpers::HUGE_PAGES_PREFIX)

          pod_requests[name] = quantity.to_s unless pod_requests.key?(name)
        end
        pod_limits.each do |name, value|
          pod_requests[name] = value if !pod_requests.key?(name) && helpers.supported_pod_level_resource?(name)
        end
        resources["requests"] = pod_requests unless pod_requests.empty?
      end
    end
  end
end
