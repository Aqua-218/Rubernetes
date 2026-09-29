# frozen_string_literal: true

require "json"
require_relative "../resource_helpers"

module Rubernetes
  module Node
    # In-place Pod resize, node side (v1.36.2): what the kubelet publishes about
    # a Pod's pod-level resources (kubelet_pods.go generateAPIPodStatus,
    # convertToAPIPodLevelResourcesStatus), the resize event messages
    # (events/resize.go) and the cgroup read-back conversions (cm/helpers_linux.go).
    module PodResize
      MIN_SHARES = 2
      MIN_MILLI_CPU_LIMIT = 10
      SHARES_PER_CPU = 1024

      module_function

      # status.allocatedResources: resourcehelper.PodRequests of the allocated Pod.
      def allocated_resources(pod)
        ResourceHelpers.to_json_list(ResourceHelpers.pod_requests(pod))
      end

      # getEffectiveAllocatedResources: the pod-level spec with requests and
      # limits replaced by PodRequests / PodLimits.
      def effective_allocated_resources(pod)
        resources = Helpers.deep_copy(ResourceHelpers.pod_resources(pod) || {})
        resources["requests"] = ResourceHelpers.to_json_list(ResourceHelpers.pod_requests(pod))
        resources["limits"] = ResourceHelpers.to_json_list(ResourceHelpers.pod_limits(pod))
        resources
      end

      # convertToAPIPodLevelResourcesStatus.  +cgroup+ is the Pod cgroup as
      # read back ({"cpu.weight", "cpu.max", "memory.max"}) or nil; +previous+
      # the status.resources published before, used when a value cannot be read.
      def status_resources(pod, phase:, cgroup:, previous: nil, previous_phase: nil)
        return effective_allocated_resources(pod) unless phase.to_s == "Running"

        preserve = phase.to_s == "Running" && previous_phase.to_s == "Running" && previous.is_a?(Hash)
        resources = Helpers.deep_copy(ResourceHelpers.pod_resources(pod) || {})
        requests = (resources["requests"] ||= {})
        limits = (resources["limits"] ||= {})
        keep = lambda do |section, name|
          value = preserve ? previous.dig(section, name) : nil
          (section == "requests" ? requests : limits)[name] = value unless value.nil?
        end
        cpu_request = cgroup && cpu_request_from(cgroup["cpu.weight"])
        allocated_cpu = ResourceHelpers.resource_list(requests)["cpu"]
        if cpu_request
          requests["cpu"] = milli_quantity(cpu_request) if cpu_request > MIN_SHARES || (allocated_cpu && allocated_cpu.milli_value > MIN_SHARES)
        else
          keep.call("requests", "cpu")
        end
        unless requests.key?("memory")
          aggregated = ResourceHelpers.pod_requests(pod)["memory"]
          requests["memory"] = aggregated.to_s if aggregated
        end
        keep.call("requests", "memory")
        cpu_limit = cgroup && cpu_limit_from(cgroup["cpu.max"])
        allocated_cpu_limit = ResourceHelpers.resource_list(limits)["cpu"]
        if cpu_limit
          limits["cpu"] = milli_quantity(cpu_limit) if cpu_limit > MIN_MILLI_CPU_LIMIT || (allocated_cpu_limit && allocated_cpu_limit.milli_value > MIN_MILLI_CPU_LIMIT)
        else
          keep.call("limits", "cpu")
        end
        memory_limit = cgroup && memory_limit_from(cgroup["memory.max"])
        if memory_limit
          limits["memory"] = binary_quantity(memory_limit)
        else
          keep.call("limits", "memory")
        end
        resources
      end

      # cgroup v2 cpu.weight -> cpu.shares (libcontainer ConvertCPUWeightToShares
      # inverse used by the kubelet's cgroup manager) -> milli-CPU (SharesToMilliCPU).
      def cpu_request_from(weight)
        return nil if weight.nil? || weight.to_s.strip.empty?

        value = Integer(weight.to_s.strip)
        return nil unless value.positive?

        shares = (((value - 1) * 262_142) / 9999) + 2
        return nil unless shares.positive?

        milli = shares >= MIN_SHARES ? (shares * 1000.0 / SHARES_PER_CPU).ceil : 0
        milli.positive? ? milli : nil
      rescue ArgumentError
        nil
      end

      # cpu.max "<quota> <period>" -> QuotaToMilliCPU; "max" is no limit.
      def cpu_limit_from(value)
        quota, period = value.to_s.split
        return nil if quota.nil? || period.to_i <= 0 || quota == "max"

        milli = (Integer(quota) * 1000) / Integer(period)
        milli.positive? ? milli : nil
      rescue ArgumentError
        nil
      end

      def memory_limit_from(value)
        text = value.to_s.strip
        return nil if text.empty? || text == "max"

        bytes = Integer(text)
        bytes.positive? ? bytes : nil
      rescue ArgumentError
        nil
      end

      def milli_quantity(milli) = Schema::Quantity.new(Rational(milli, 1000), :decimal_si).to_s
      def binary_quantity(bytes) = Schema::Quantity.new(Rational(bytes, 1), :binary_si).to_s

      # events/resize.go podResizeMessage: "<prefix>: {json summary}".
      def message(prefix, pod, generation, error = "")
        summary = {}
        %w[initContainers containers].each do |field|
          entries = ResourceHelpers.containers(pod, field).map do |container|
            entry = {"name" => container["name"].to_s}
            resources = container["resources"]
            entry["resources"] = resources if resources.is_a?(Hash) && !resources.empty?
            entry
          end
          summary[field] = entries unless entries.empty?
        end
        summary["generation"] = Integer(generation || 0)
        summary["error"] = error unless error.to_s.empty?
        "#{prefix}: #{JSON.generate(summary)}"
      end

      # Did the resources a resize can change differ between two Pods?
      def resources_changed?(allocated, desired)
        normalize = lambda do |pod|
          spec = ResourceHelpers.spec(pod)
          [ResourceHelpers.resource_list(ResourceHelpers.pod_resources(pod)&.dig("requests")).transform_values(&:value),
           ResourceHelpers.resource_list(ResourceHelpers.pod_resources(pod)&.dig("limits")).transform_values(&:value),
           %w[containers initContainers].map do |field|
             Array(spec[field]).map do |container|
               [ResourceHelpers.resource_list(container.dig("resources", "requests")).transform_values(&:value),
                ResourceHelpers.resource_list(container.dig("resources", "limits")).transform_values(&:value)]
             end
           end]
        end
        normalize.call(allocated) != normalize.call(desired)
      end

      # guaranteedPodResourceResizeRequired: a resizable container (every
      # container and init container, InPlacePodVerticalScalingInitContainers
      # being on) whose request for +resource+ differs from its allocation.
      def container_request_changed?(allocated, desired, resource)
        allocated_spec = ResourceHelpers.spec(allocated)
        current = %w[containers initContainers].flat_map { |field| Array(allocated_spec[field]) }.to_h { |container| [container["name"], container] }
        desired_spec = ResourceHelpers.spec(desired)
        %w[containers initContainers].flat_map { |field| Array(desired_spec[field]) }.any? do |container|
          wanted = ResourceHelpers.resource_list(container.dig("resources", "requests"))[resource]&.value
          old = current[container["name"]]
          had = old && ResourceHelpers.resource_list(old.dig("resources", "requests"))[resource]&.value
          wanted.to_r != had.to_r
        end
      end

      # podResizesAdmitHandler with the default gates (InPlacePodVerticalScaling
      # and InPlacePodLevelResourcesVerticalScaling on, the Exclusive CPU /
      # memory ones off): [reason_detail, message] for a resize that can
      # never be applied, nil otherwise.
      def infeasible(allocated, desired, cpu_policy:, memory_policy:)
        return nil unless ResourceHelpers.pod_qos(desired) == "Guaranteed"

        if cpu_policy.to_s == "static" && container_request_changed?(allocated, desired, "cpu")
          return ["guaranteed_pod_cpu_manager_static_policy", %(Resize is infeasible for Guaranteed Pods alongside CPU Manager policy "static")]
        end
        if memory_policy.to_s == "Static" && container_request_changed?(allocated, desired, "memory")
          return ["guaranteed_pod_memory_manager_static_policy", %(Resize is infeasible for Guaranteed Pods alongside Memory Manager policy "Static")]
        end
        nil
      end

      def pod_level_changed?(allocated, desired)
        list = ->(pod, kind) { ResourceHelpers.resource_list(ResourceHelpers.pod_resources(pod)&.dig(kind)).transform_values(&:value) }
        list.call(allocated, "requests") != list.call(desired, "requests") || list.call(allocated, "limits") != list.call(desired, "limits")
      end
    end
  end
end
