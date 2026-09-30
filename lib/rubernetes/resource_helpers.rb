# frozen_string_literal: true

require_relative "schema/quantity"

module Rubernetes
  # Port of k8s.io/component-helpers/resource (v1.36.2) and
  # pkg/apis/core/v1/helper/qos: how much a Pod requests and may use, and its
  # QoS class, including pod-level resources (spec.resources, PodLevelResources)
  # and the status-based effective values in-place resize relies on.  Every
  # component that sizes a Pod -- API server (qosClass, validation), scheduler,
  # node admission, runtime cgroups, quota, LimitRanger -- goes through here so
  # they cannot disagree.
  #
  # Pods are JSON hashes; resource lists come back as {name => Schema::Quantity}.
  module ResourceHelpers
    Quantity = Schema::Quantity
    SUPPORTED_POD_LEVEL = %w[cpu memory].freeze
    HUGE_PAGES_PREFIX = "hugepages-"
    QOS_RESOURCES = %w[cpu memory].freeze

    module_function

    def supported_pod_level_resources = (SUPPORTED_POD_LEVEL + ["hugepages-"]).freeze

    def supported_pod_level_resource?(name)
      SUPPORTED_POD_LEVEL.include?(name.to_s) || name.to_s.start_with?(HUGE_PAGES_PREFIX)
    end

    def spec(pod)
      value = pod.is_a?(Hash) ? (pod["spec"] || pod[:spec]) : nil
      value.is_a?(Hash) ? value : {}
    end

    def status(pod)
      value = pod.is_a?(Hash) ? (pod["status"] || pod[:status]) : nil
      value.is_a?(Hash) ? value : {}
    end

    def pod_resources(pod)
      value = spec(pod)["resources"]
      value.is_a?(Hash) ? value : nil
    end

    def pod_level_resources_set?(pod) = pod_level_requests_set?(pod) || pod_level_limits_set?(pod)

    def pod_level_requests_set?(pod)
      list = pod_resources(pod)&.dig("requests")
      list.is_a?(Hash) && list.keys.any? { |name| supported_pod_level_resource?(name) }
    end

    def pod_level_limits_set?(pod)
      list = pod_resources(pod)&.dig("limits")
      list.is_a?(Hash) && list.keys.any? { |name| supported_pod_level_resource?(name) }
    end

    # {name => Quantity} from a JSON resource list; unparsable values are skipped.
    def resource_list(value)
      return {} unless value.is_a?(Hash)

      value.each_with_object({}) do |(name, quantity), result|
        result[name.to_s] = quantity.is_a?(Quantity) ? quantity : Quantity.from_json(quantity)
      rescue Quantity::ParseError
        next
      end
    end

    def to_json_list(list) = list.transform_values(&:to_s)

    def add!(list, other)
      other.each do |name, quantity|
        list[name] = list.key?(name) ? Quantity.new(list[name].value + quantity.value, list[name].format) : quantity
      end
      list
    end

    def max!(list, other)
      other.each { |name, quantity| list[name] = quantity if !list.key?(name) || quantity.value > list[name].value }
      list
    end

    def max_of(first, *others)
      others.each_with_object(first ? first.dup : {}) { |other, result| max!(result, other || {}) }
    end

    def sidecar?(container) = container.is_a?(Hash) && container["restartPolicy"].to_s == "Always"

    def containers(pod, field) = Array(spec(pod)[field]).grep(Hash)

    def container_statuses(pod)
      (Array(status(pod)["containerStatuses"]) + Array(status(pod)["initContainerStatuses"]))
        .grep(Hash).to_h { |entry| [entry["name"].to_s, entry] }
    end

    # IsPodResizeInfeasible / IsPodResizeDeferred.
    def resize_pending_reason(pod)
      condition = Array(status(pod)["conditions"]).find { |entry| entry.is_a?(Hash) && entry["type"] == "PodResizePending" }
      condition && condition["reason"].to_s
    end

    def resize_infeasible?(pod) = resize_pending_reason(pod) == "Infeasible"
    def resize_deferred?(pod) = resize_pending_reason(pod) == "Deferred"

    def effective_requests(pod, spec_list, actuated, allocated)
      return max_of(actuated, allocated) if resize_infeasible?(pod)

      max_of(spec_list, actuated, allocated)
    end

    def effective_limits(pod, spec_list, actuated)
      return actuated.dup if resize_infeasible?(pod)

      max_of(spec_list, actuated)
    end

    # AggregateContainerRequests: regular containers and sidecars add up,
    # each non-sidecar init container runs alone next to the sidecars started
    # before it, and the Pod needs the larger of the two.
    def aggregate_container_requests(pod, use_status_resources: false, non_missing: nil, container_fn: nil)
      aggregate(pod, "requests", use_status_resources: use_status_resources, non_missing: non_missing, container_fn: container_fn)
    end

    def aggregate_container_limits(pod, use_status_resources: false, container_fn: nil)
      aggregate(pod, "limits", use_status_resources: use_status_resources, container_fn: container_fn)
    end

    def aggregate(pod, kind, use_status_resources:, non_missing: nil, container_fn: nil)
      statuses = use_status_resources ? container_statuses(pod) : {}
      effective = lambda do |container|
        list = resource_list(container.dig("resources", kind))
        observed = statuses[container["name"].to_s]
        if observed && observed["resources"].is_a?(Hash)
          actuated = resource_list(observed["resources"][kind])
          list = if kind == "requests"
                   effective_requests(pod, list, actuated, resource_list(observed["allocatedResources"]))
                 else
                   effective_limits(pod, list, actuated)
                 end
        end
        if non_missing && !non_missing.empty?
          list = list.dup
          non_missing.each { |name, quantity| list[name] = quantity unless list.key?(name) }
        end
        list
      end

      result = {}
      containers(pod, "containers").each do |container|
        list = effective.call(container)
        container_fn&.call(list, :containers)
        add!(result, list)
      end
      restartable = {}
      init_max = {}
      containers(pod, "initContainers").each do |container|
        # Only a sidecar's status is consulted: a finished init container
        # holds nothing.
        list = sidecar?(container) || !use_status_resources ? effective.call(container) : resource_list(container.dig("resources", kind))
        if non_missing && !non_missing.empty? && !sidecar?(container) && use_status_resources
          non_missing.each { |name, quantity| list[name] = quantity unless list.key?(name) }
        end
        if sidecar?(container)
          add!(result, list)
          add!(restartable, list)
          list = restartable.dup
        else
          list = add!(list.dup, restartable)
        end
        container_fn&.call(list, :init_containers)
        max!(init_max, list)
      end
      max!(result, init_max)
    end

    # PodRequests: pod-level requests replace the aggregate for the resources
    # they name; the overhead is added on top.
    def pod_requests(pod, use_status_resources: false, exclude_overhead: false, skip_pod_level: false,
                     skip_container_level: false, in_place_pod_level_resize: true, non_missing: nil, container_fn: nil)
      requests = if skip_container_level
                   {}
                 else
                   aggregate_container_requests(pod, use_status_resources: use_status_resources,
                                                     non_missing: non_missing, container_fn: container_fn)
                 end
      if !skip_pod_level && pod_level_requests_set?(pod)
        spec_requests = resource_list(pod_resources(pod)["requests"])
        effective = nil
        if in_place_pod_level_resize && use_status_resources && status(pod)["resources"].is_a?(Hash)
          effective = effective_requests(pod, spec_requests, resource_list(status(pod)["resources"]["requests"]),
                                         resource_list(status(pod)["allocatedResources"]))
        end
        spec_requests.each do |name, quantity|
          next unless supported_pod_level_resource?(name)

          requests[name] = effective ? (effective[name] || quantity) : quantity
        end
      end
      add!(requests, resource_list(spec(pod)["overhead"])) unless exclude_overhead
      requests
    end

    # PodLimits: pod-level limits replace the aggregate; the overhead is added
    # only to a limit that is set.
    def pod_limits(pod, use_status_resources: false, exclude_overhead: false, skip_pod_level: false,
                   in_place_pod_level_resize: true, container_fn: nil)
      limits = aggregate_container_limits(pod, use_status_resources: use_status_resources, container_fn: container_fn)
      if !skip_pod_level && pod_level_resources_set?(pod)
        spec_limits = resource_list(pod_resources(pod)["limits"])
        effective = nil
        if in_place_pod_level_resize && use_status_resources && status(pod)["resources"].is_a?(Hash)
          effective = effective_limits(pod, spec_limits, resource_list(status(pod)["resources"]["limits"]))
        end
        spec_limits.each do |name, quantity|
          next unless supported_pod_level_resource?(name)

          limits[name] = effective ? (effective[name] || quantity) : quantity
        end
      end
      unless exclude_overhead
        resource_list(spec(pod)["overhead"]).each do |name, quantity|
          limits[name] = Quantity.new(limits[name].value + quantity.value, limits[name].format) if limits.key?(name) && !limits[name].zero?
        end
      end
      limits
    end

    # qos.ComputePodQOS (PodLevelResources on): pod-level resources, when the
    # Pod has any, decide alone.
    def qos_class(pod, pod_level_resources: true)
      requests = {}
      limits = {}
      guaranteed = true
      resources = pod_resources(pod)
      if pod_level_resources && resources
        add_qos!(requests, resource_list(resources["requests"]))
        pod_limits_list = resource_list(resources["limits"])
        unless pod_limits_list.empty?
          add_qos!(limits, pod_limits_list)
          guaranteed = false unless QOS_RESOURCES.all? { |name| pod_limits_list.key?(name) }
        end
      else
        (containers(pod, "containers") + containers(pod, "initContainers")).each do |container|
          add_qos!(requests, resource_list(container.dig("resources", "requests")))
          found = add_qos!(limits, resource_list(container.dig("resources", "limits")))
          guaranteed = false unless QOS_RESOURCES.all? { |name| found.include?(name) }
        end
      end
      return "BestEffort" if requests.empty? && limits.empty?

      guaranteed = requests.all? { |name, quantity| limits.key?(name) && limits[name].value == quantity.value } if guaranteed
      guaranteed && requests.length == limits.length ? "Guaranteed" : "Burstable"
    end

    # GetPodQOS: the published class wins.
    def pod_qos(pod)
      published = status(pod)["qosClass"].to_s
      published.empty? ? qos_class(pod) : published
    end

    # processResourceList: positive quantities of cpu/memory only; returns
    # the names it added.
    def add_qos!(list, other)
      added = []
      other.each do |name, quantity|
        next unless QOS_RESOURCES.include?(name) && quantity.sign.positive?

        added << name
        list[name] = list.key?(name) ? Quantity.new(list[name].value + quantity.value, list[name].format) : quantity
      end
      added
    end
  end
end
