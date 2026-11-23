# frozen_string_literal: true

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"
require_relative "endpoint_slice_objects"
require_relative "endpoint_slice_metrics"
require_relative "endpoint_slice_hints"

module Rubernetes
  module Controller
    # Publishes selector-backed Services as discovery.k8s.io/v1 EndpointSlices.
    # Each slice is independently addressable, capped at the v1.36.2 API
    # limit, and only slices carrying this controller's managed-by label (or a
    # matching Service owner reference) are eligible for mutation.
    class EndpointSliceController < BaseController
      SERVICE = ResourceDescriptor.parse("Service")
      POD = ResourceDescriptor.parse("Pod")
      NODE = ResourceDescriptor.parse("Node")
      # pkg/controller/endpointslice/endpointslice_controller.go ControllerName.
      # Conformance reads this label back off the slice and fails on anything
      # else, so the value is part of the API contract, not a free-form tag.
      MANAGED_BY = "endpointslice-controller.k8s.io"
      # kube-controller-manager --max-endpoints-per-slice (default 100; the
      # API allows 1000 per slice).
      ENDPOINT_LIMIT = 100

      include SecondarySupport
      include EndpointSliceObjects

      def plan(service, store: nil, pods: nil, nodes: nil, endpoint_slices: nil, **_options)
        planned = plan_service(service, store: store, pods: pods, nodes: nodes, endpoint_slices: endpoint_slices)
        # trackSync.
        ControllerMetrics.increment("endpoint_slice_controller_syncs", {"result" => "success"})
        planned
      rescue StandardError
        ControllerMetrics.increment("endpoint_slice_controller_syncs", {"result" => "error"})
        raise
      end

      def plan_service(service, store: nil, pods: nil, nodes: nil, endpoint_slices: nil)
        adapter = adapter_for(store)
        orphaned = orphaned_slice_result(service, adapter)
        return orphaned if orphaned

        service = resolve_service(service, adapter)
        namespace = Support.namespace(service)
        pods ||= list_for(adapter, POD, namespace: namespace)
        endpoint_slices ||= list_for(adapter, ENDPOINT_SLICE, namespace: namespace)
        managed_slices = managed_slices_for(service, endpoint_slices)
        selected = selected_pods(service, pods)
        nodes ||= list_for(adapter, NODE) if adapter && !selected.empty?
        desired_groups = endpoint_groups(service, selected, nodes)
        hints = EndpointSliceHints.new(auto: self.class.hints_enabled?(service),
                                       distribution: Support.value(Support.spec(service), "trafficDistribution", nil), nodes: nodes)
        operations = reconcile_slices(service, managed_slices, desired_groups, selected, hints)
        operations = record_sync(service, managed_slices, desired_groups, operations)
        status = {
          "endpoints" => desired_groups.values.sum(&:length),
          "conditions" => desired_groups.transform_values do |endpoints|
            endpoints.map do |endpoint|
              Support.deep_copy(endpoint.fetch("conditions", {}))
            end
          end
        }
        events = if operations.empty?
                   []
                 else
                   [{"type" => "Normal", "reason" => "EndpointSliceUpdated",
                     "message" => "service #{Support.name(service)} EndpointSlices reconciled"}]
                 end
        # A Pod readiness event that races the Service's own arrival in the
        # informer cache maps to no Service key and is lost; the next event
        # for that Pod may never come.  Re-planning from the cache every 15 s
        # is cheap and closes that window ("[sig-network] Services should
        # serve a basic endpoint from pods" saw its Pod missing for 2 min).
        ReconcileResult.new(operations: operations, status: status, events: events,
                            controller: name, key: object_key_for(service), requeue_after: RESYNC_SECONDS)
      end

      RESYNC_SECONDS = 15.0

      # endpointslice/metrics Cache: per Service its endpoints, its slices
      # and the slices an ideal packing needs, and its trafficDistribution;
      # the gauges are the sums (process-wide, as the plan and orphan paths
      # use separate instances).
      SERVICE_CACHE = EndpointSliceMetrics.new("endpoint_slice_controller", track_traffic: true)
      TRAFFIC_DISTRIBUTIONS = EndpointSliceHints::DISTRIBUTIONS

      def self.hints_enabled?(service)
        annotations = Support.annotations(service)
        value = annotations.fetch("service.kubernetes.io/topology-aware-hints") { annotations["service.kubernetes.io/topology-mode"] }
        %w[Auto auto].include?(value.to_s)
      end

      def record_sync(service, existing, desired_groups, operations)
        key = "#{Support.namespace(service)}/#{Support.name(service)}"
        endpoint_key = lambda { |endpoint|
          [Array(Support.value(endpoint, "addresses", [])).sort, Support.value(Support.value(endpoint, "targetRef", {}), "uid", "")]
        }
        before = existing.flat_map { |slice| Array(Support.value(slice, "endpoints", [])) }.map(&endpoint_key)
        after = desired_groups.values.flatten.map(&endpoint_key)
        ControllerMetrics.observe("endpoint_slice_controller_endpoints_added_per_sync", (after - before).length)
        ControllerMetrics.observe("endpoint_slice_controller_endpoints_removed_per_sync", (before - after).length)
        creates = operations.count(&:create?)
        deletes = operations.count(&:delete?)
        endpoints = after.length
        desired = desired_groups.values.sum { |group| group.empty? ? 0 : (group.length + ENDPOINT_LIMIT - 1) / ENDPOINT_LIMIT }
        hints = self.class.hints_enabled?(service)
        traffic = Support.value(Support.spec(service), "trafficDistribution", nil)
        traffic = nil unless TRAFFIC_DISTRIBUTIONS.include?(traffic.to_s) && !hints
        SERVICE_CACHE.update(key, {endpoints: endpoints, slices: existing.length + creates - deletes, desired: [desired, 1].max, traffic: traffic})
        ControllerMetrics.observe("endpoint_slice_controller_endpointslices_changed_per_sync", operations.length,
                                  {"topology" => hints ? "Auto" : "Disabled", "traffic_distribution" => traffic.to_s})
        SERVICE_CACHE.observe_changes(operations)
      end

      def forget_service(key)
        SERVICE_CACHE.update(key, nil)
      end

      alias reconcile_service plan

      private

      # A slice this controller manages whose Service is gone is deleted
      # (upstream's syncService deletes every managed slice once the Service
      # lister reports NotFound).  Raising "service was not found" instead left
      # the key retrying with backoff until the garbage collector happened to
      # sweep the slice, and "[sig-network] EndpointSlice should create and
      # delete EndpointSlices for a Service with a selector that matches no
      # pods" gave up first.
      def orphaned_slice_result(resource, adapter)
        return nil if adapter.nil? || Support.kind(resource) == "Service"

        service_name = Support.labels(resource)[SERVICE_LABEL]
        return nil if service_name.to_s.empty?
        return nil if find_for(adapter, SERVICE, service_name, namespace: Support.namespace(resource))

        operations = if Support.labels(resource)[MANAGED_BY_LABEL] == MANAGED_BY
                       [operation_delete(resource, descriptor: ENDPOINT_SLICE,
                                                   reason: "service deleted")]
                     else
                       []
                     end
        forget_service("#{Support.namespace(resource)}/#{service_name}")
        ReconcileResult.new(operations: operations, status: {}, events: [], controller: name,
                            key: [Support.namespace(resource), Support.name(resource)].compact.join("/"))
      end

      def resolve_service(resource, adapter)
        return resource if Support.kind(resource) == "Service"

        service_name = Support.labels(resource)[SERVICE_LABEL]
        raise ArgumentError, "EndpointSlice reconciliation requires a Service or service-name label" if service_name.to_s.empty?

        service = find_for(adapter, SERVICE, service_name, namespace: Support.namespace(resource))
        raise StoreError, "service #{service_name.inspect} was not found" unless service

        service
      end

      def selected_pods(service, pods)
        selector = Support.unwrap_match_labels(Support.value(Support.spec(service), "selector", {}))
        return [] if selector.nil? || selector == {} || selector.to_s.empty?

        namespace = Support.namespace(service).to_s
        matches = Support.selector_predicate(selector)

        Array(pods).select do |pod|
          next false unless Support.namespace(pod).to_s == namespace
          next false unless matches.call(pod)

          Support.pod_in_endpoints?(pod, include_terminating: true)
        end.sort_by { |pod| [Support.name(pod), Support.uid(pod).to_s] }
      end

      # staging/src/k8s.io/endpointslice/utils.go getAddressTypesForService:
      # the Service's ipFamilies; without them (an object from an older API
      # server) the family of its clusterIP, and for a headless Service both.
      def service_address_types(service)
        spec = Support.spec(service)
        families = Array(Support.value(spec, "ipFamilies", [])).map(&:to_s) & %w[IPv4 IPv6]
        return families unless families.empty?

        cluster_ip = Support.value(spec, "clusterIP", "").to_s
        return [cluster_ip.include?(":") ? "IPv6" : "IPv4"] if !cluster_ip.empty? && cluster_ip != "None"

        %w[IPv4 IPv6]
      end

      # One group per address type the Service supports (reconciler.go
      # reconciles each addressType on its own), each endpoint carrying the
      # Pod's addresses of that family (getEndpointAddresses).  A Pod with no
      # address of a family is absent from that family's slices.  Taking only
      # the first Pod IP left a dual-stack cluster with IPv4 slices for every
      # Service, including IPv6-only ones, which then had no endpoints at all.
      def endpoint_groups(service, pods, nodes = nil)
        groups = service_address_types(service).to_h { |address_type| [address_type, []] }
        publish_not_ready = Support.value(Support.spec(service), "publishNotReadyAddresses", false) == true
        nodes_by_name = nodes&.to_h { |node| [Support.name(node), node] }
        Array(pods).each do |pod|
          node_name = Support.value(Support.spec(pod), "nodeName").to_s
          node = nodes_by_name&.[](node_name)
          next if nodes_by_name && node.nil? && !publish_not_ready

          ips = Support.pod_endpoint_ips(pod)
          endpoint = endpoint_metadata(pod, service, node_name, node, publish_not_ready)
          groups.each_key do |address_type|
            addresses = ips.select { |ip| (address_type == "IPv6") == ip.include?(":") }
            next if addresses.empty?

            groups[address_type] << endpoint.merge("addresses" => addresses)
          end
        end
        groups.each_value do |endpoints|
          endpoints.sort_by! do |endpoint|
            [endpoint.fetch("addresses").first, Support.value(endpoint["targetRef"], "name", "")]
          end
        end
        groups
      end

      def endpoint_metadata(pod, service, node_name, node, publish_not_ready)
        serving = ready_condition_status(pod)
        terminating = Support.terminating_endpoint_pod?(pod)
        ready = publish_not_ready || (serving && !terminating)
        target = {"kind" => "Pod", "namespace" => Support.namespace(pod),
                  "name" => Support.name(pod), "uid" => Support.uid(pod)}
        target.delete("namespace") if target["namespace"].to_s.empty?
        target.delete("uid") if target["uid"].to_s.empty?
        zone = Support.labels(node)[EndpointSliceHints::ZONE]
        {"conditions" => {"ready" => ready, "serving" => serving, "terminating" => terminating},
         "targetRef" => target, "hostname" => Support.endpoint_hostname(pod, service),
         "nodeName" => node_name.empty? ? nil : node_name, "zone" => zone.to_s.empty? ? nil : zone}.compact
      end

      # Upstream groups endpoints by their resolved port set (a named
      # targetPort resolves per Pod), so Pods exposing the name on different
      # container ports land in different slices.
      def reconcile_slices(service, existing, desired_groups, selected_pods, hints)
        operations = []
        placeholders = []
        pods_by_name = Array(selected_pods).to_h { |pod| [Support.name(pod), pod] }
        existing_by_type = existing.group_by { |slice| Support.value(slice, "addressType", "IPv4").to_s }
        desired_groups.each do |address_type, endpoints|
          slices = existing_by_type.delete(address_type) || []
          pairs = candidate_slices(service, address_type, endpoints, pods_by_name, slices)
          if pairs.empty? && service_has_selector?(service)
            # Keep one empty slice of each supported family, including its API-assigned name.
            index = slices.index { |slice| Array(Support.value(slice, "ports")).empty? && Array(Support.value(slice, "endpoints")).empty? }
            kept = index && slices.delete_at(index)
            placeholders << reconcile_placeholder(service, address_type, kept)
          end
          hints.assign(pairs)
          pairs.each do |candidate, current|
            operation = reconcile_slice(service, candidate, current)
            operations << operation if operation
          end
          slices.drop(pairs.length).each do |slice|
            operations << operation_delete(slice, descriptor: ENDPOINT_SLICE,
                                                  reason: "stale service EndpointSlice")
          end
        end
        existing_by_type.values.flatten.each do |slice|
          operations << operation_delete(slice, descriptor: ENDPOINT_SLICE,
                                                reason: "empty service EndpointSlice")
        end
        operations.concat(placeholders.compact)
      end

      def candidate_slices(service, address_type, endpoints, pods_by_name, existing)
        by_ports = endpoints.group_by do |endpoint|
          pod = pods_by_name[Support.value(endpoint["targetRef"], "name", "")]
          Support.service_endpoint_ports(service, pod, include_empty_name: true)
        end
        chunks = by_ports.sort_by { |ports, _| ports.map { |port| port["port"].to_i } }.flat_map do |ports, group|
          group.each_slice(ENDPOINT_LIMIT).map { |chunk| [ports, chunk] }
        end
        chunks.each_with_index.map do |(ports, endpoints), index|
          [endpoint_slice(service, address_type, ports, endpoints, index), existing[index]]
        end
      end

      def reconcile_slice(service, candidate, current)
        if current
          operation_update(current, preserve_slice_metadata(current, candidate), descriptor: ENDPOINT_SLICE,
                                                                                 reason: "service endpoint membership")
        else
          operation_create(candidate, owner: service, descriptor: ENDPOINT_SLICE, reason: "service endpoint membership")
        end
      end

      def reconcile_placeholder(service, address_type, current)
        placeholder = endpoint_slice(service, address_type, [], [], 0)
        return operation_create(placeholder, owner: service, descriptor: ENDPOINT_SLICE, reason: "placeholder EndpointSlice") unless current

        labels = Support.labels(placeholder)
        return if labels == Support.labels(current)

        metadata = Support.metadata(current).merge("labels" => labels)
        operation_update(current, current.merge("metadata" => metadata), descriptor: ENDPOINT_SLICE, reason: "service placeholder labels")
      end

      def service_has_selector?(service)
        selector = Support.unwrap_match_labels(Support.value(Support.spec(service), "selector", {}))
        selector.is_a?(Hash) && !selector.empty?
      end

      def endpoint_slice(service, address_type, ports, endpoints, index)
        digest = canonical_hash({"service" => Support.uid(service), "type" => address_type})[0, 10]
        name = "#{Support.name(service)}-#{digest}-#{index}"
        build_slice(service, name, Support.service_endpoint_labels(service), address_type, ports, endpoints)
      end
    end
  end
end
