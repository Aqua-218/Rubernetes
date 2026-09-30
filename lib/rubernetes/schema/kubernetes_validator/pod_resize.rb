# frozen_string_literal: true

require_relative "../../resource_helpers"

module Rubernetes
  module Schema
    # pkg/apis/core/validation ValidatePodResize (v1.36.2), the validation of
    # the pods/resize subresource.  The generic pod update rule used to run
    # instead, so a pod-level resize was refused outright and a container
    # resize could change the QoS class, drop requests, or add
    # ephemeral-storage.
    module KubernetesValidator
      module_function

      def pod_resize_errors(root, old)
        return [] unless old.is_a?(Hash)

        new_spec = fetch(root, "spec") || {}
        old_spec = fetch(old, "spec") || {}
        if (old.dig("metadata", "annotations") || {}).key?("kubernetes.io/config.mirror")
          return [issue([], :forbidden, "static pods cannot be resized")]
        end
        return [issue([], :forbidden, "windows pods cannot be resized")] if old_spec.dig("os", "name").to_s == "windows"

        helpers = Rubernetes::ResourceHelpers
        issues = []
        old_qos = old.dig("status", "qosClass").to_s
        old_qos = helpers.qos_class(old) if old_qos.empty?
        if old_qos != helpers.qos_class(root)
          issues << ValidationIssue.new(path: ["spec"], code: :invalid, value: root.dig("status", "qosClass").to_s,
                                        message: "Pod QOS Class may not change as a result of resizing", kubernetes_type: "Invalid value")
        end
        issues << issue(["spec"], :forbidden, "Pod running on node without support for resize") unless resize_request_supported?(old)

        munged = deep_copy_value(new_spec)
        if resize_pod_level_set?(old_spec) || resize_pod_level_set?(new_spec)
          issues.concat(pod_level_resize_errors(new_spec, old_spec, munged))
        end
        unless Array(old.dig("status", "nodeAllocatableResourceClaimStatuses")).empty?
          issues << issue(["spec"], :forbidden, "pods with node allocatable resource claims cannot be resized")
        end

        ordering = resize_ordering_errors(new_spec, old_spec)
        return issues + ordering unless ordering.empty?

        Array(old_spec["initContainers"]).each_with_index do |container, index|
          issues.concat(container_resize_errors(new_spec["initContainers"][index], container,
                                                ["spec", "initContainers", index.to_s, "resources"]))
        end
        Array(old_spec["containers"]).each_with_index do |container, index|
          issues.concat(container_resize_errors(new_spec["containers"][index], container, ["spec", "containers", index.to_s, "resources"]))
        end

        munged["containers"] = Array(munged["containers"]).each_with_index.map do |container, index|
          dropped = drop_cpu_memory_from_container(container, old_spec["containers"][index])
          unless semantic_equal?(dropped, old_spec["containers"][index])
            issues << issue(["spec"], :forbidden, "only cpu and memory resources are mutable")
          end
          dropped
        end
        if munged.key?("initContainers")
          munged["initContainers"] = Array(munged["initContainers"]).each_with_index.map do |container, index|
            old_container = old_spec["initContainers"][index]
            restartable = container["restartPolicy"].to_s == "Always"
            modified = !semantic_equal?(container, old_container)
            dropped = drop_cpu_memory_from_container(container, old_container)
            unless semantic_equal?(dropped, old_container)
              issues << issue(["spec", "initContainers", index.to_s], :forbidden, "only cpu and memory resources for init or sidecar containers are mutable")
            end
            if modified && !restartable && Array(dropped["resizePolicy"]).any? do |policy|
              policy["restartPolicy"].to_s == "RestartContainer"
            end
              issues << issue(["spec", "initContainers", index.to_s], :forbidden,
                              "non-sidecar init containers with a resize policy of RestartContainer cannot be resized")
            end
            dropped
          end
        end
        return issues unless issues.empty?

        semantic_equal?(munged, old_spec) ? [] : [issue(["spec"], :forbidden, "only cpu and memory resources are mutable")]
      end

      # isPodResizeRequestSupported: a running container must report its
      # resources (the node supports resize).
      def resize_request_supported?(pod)
        running = Array(pod.dig("status", "containerStatuses")).find { |status| status.is_a?(Hash) && status.dig("state", "running") }
        running.nil? || !running["resources"].nil?
      end

      def resize_pod_level_set?(spec)
        resources = spec["resources"]
        resources.is_a?(Hash) && ((resources["requests"] || {}).length + (resources["limits"] || {}).length).positive?
      end

      # validatePodLevelResourcesResize (mutates +munged+ like podSpecToMutate).
      def pod_level_resize_errors(new_spec, old_spec, munged)
        old_resources = old_spec["resources"]
        new_resources = new_spec["resources"]
        return [issue(%w[spec resources], :forbidden, "pod-level resources cannot be removed")] if old_resources && new_resources.nil?

        issues = []
        if old_resources.is_a?(Hash)
          if resources_removed?(new_resources&.dig("requests"), old_resources["requests"])
            issues << issue(%w[spec resources requests], :forbidden, "pod-level resource requests cannot be removed")
          end
          if resources_removed?(new_resources&.dig("limits"), old_resources["limits"])
            issues << issue(%w[spec resources limits], :forbidden, "pod-level resource limits cannot be removed")
          end
        end
        munged_resources = drop_cpu_memory_requirement_updates(munged["resources"], old_resources)
        if munged_resources.nil?
          munged.delete("resources")
        else
          munged["resources"] = munged_resources
        end
        unless semantic_equal?(munged_resources, old_resources)
          issues << issue(["spec"], :forbidden, "only cpu and memory resources are mutable at pod-level")
        end
        issues
      end

      def resize_ordering_errors(new_spec, old_spec)
        issues = []
        {"containers" => "containers", "initContainers" => "initContainers"}.each do |field, label|
          new_list = Array(new_spec[field])
          old_list = Array(old_spec[field])
          if new_list.length == old_list.length
            old_list.each_with_index do |container, index|
              next if new_list[index]["name"] == container["name"]

              issues << issue(["spec", field, index.to_s, "name"], :forbidden, "#{label} may not be renamed or reordered on resize")
            end
          else
            issues << issue(["spec", field], :forbidden, "#{label} may not be added or removed on resize")
          end
        end
        issues
      end

      # validateContainerResize.
      def container_resize_errors(new_container, old_container, path)
        issues = []
        new_resources = new_container["resources"] || {}
        old_resources = old_container["resources"] || {}
        issues << issue(path + ["requests"], :forbidden, "resource requests cannot be removed") if resources_removed?(
          new_resources["requests"], old_resources["requests"]
        )
        issues << issue(path + ["limits"], :forbidden, "resource limits cannot be removed") if resources_removed?(new_resources["limits"],
                                                                                                                  old_resources["limits"])
        issues
      end

      def resources_removed?(list, old_list)
        list = {} unless list.is_a?(Hash)
        old_list = {} unless old_list.is_a?(Hash)
        old_list.length > list.length || old_list.keys.any? { |name| !list.key?(name) }
      end

      # dropCPUMemoryUpdates: +list+ with cpu/memory put back to +old_list+'s.
      def drop_cpu_memory_updates(list, old_list)
        return nil if list.nil? && old_list.nil?

        result = list.is_a?(Hash) ? list.dup : {}
        result.delete("cpu")
        result.delete("memory")
        result["cpu"] = old_list["cpu"] if old_list.is_a?(Hash) && old_list.key?("cpu")
        result["memory"] = old_list["memory"] if old_list.is_a?(Hash) && old_list.key?("memory")
        result
      end

      def drop_cpu_memory_from_container(container, old_container)
        result = deep_copy_value(container)
        resources = container["resources"] || {}
        old_resources = old_container["resources"] || {}
        dropped = {}
        limits = drop_cpu_memory_updates(resources["limits"], old_resources["limits"])
        requests = drop_cpu_memory_updates(resources["requests"], old_resources["requests"])
        dropped["limits"] = limits unless limits.nil?
        dropped["requests"] = requests unless requests.nil?
        result["resources"] = dropped
        result
      end

      def drop_cpu_memory_requirement_updates(resources, old_resources)
        return nil if resources.nil?

        result = deep_copy_value(resources)
        old_requests = old_resources.is_a?(Hash) ? old_resources["requests"] : nil
        old_limits = old_resources.is_a?(Hash) ? old_resources["limits"] : nil
        requests = drop_cpu_memory_updates(result["requests"], old_requests)
        limits = drop_cpu_memory_updates(result["limits"], old_limits)
        requests.nil? ? result.delete("requests") : result["requests"] = requests
        limits.nil? ? result.delete("limits") : result["limits"] = limits
        if old_resources.nil? && (result["requests"] || {}).empty? && (result["limits"] || {}).empty? && Array(result["claims"]).empty?
          return nil
        end

        result
      end

      # apiequality.Semantic.DeepEqual on the JSON form: empty and absent
      # maps/lists are equal, quantities compare by value.
      def semantic_equal?(left, right)
        semantic_form(left) == semantic_form(right)
      end

      def semantic_form(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, item), result|
            normalized = semantic_form(item)
            result[key.to_s] = normalized unless normalized.nil? || (normalized.respond_to?(:empty?) && normalized.empty?)
          end
        when Array then value.map { |item| semantic_form(item) }
        when String
          if value.match?(/\A[+-]?\d/)
            begin
              Quantity.parse(value).value
            rescue StandardError
              value
            end
          else
            value
          end
        else value
        end
      end
    end
  end
end
