# frozen_string_literal: true

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # Publishes selector-backed Services as discovery.k8s.io/v1 EndpointSlices.
    # Each slice is independently addressable, capped at the v1.36.2 API
    # limit, and only slices carrying this controller's managed-by label (or a
    # matching Service owner reference) are eligible for mutation.
    class EndpointSliceController < BaseController
      SERVICE = ResourceDescriptor.parse("Service")
      POD = ResourceDescriptor.parse("Pod")
      ENDPOINT_SLICE = ResourceDescriptor.parse("EndpointSlice")
      # pkg/controller/endpointslice/endpointslice_controller.go ControllerName.
      # Conformance reads this label back off the slice and fails on anything
      # else, so the value is part of the API contract, not a free-form tag.
      MANAGED_BY = "endpointslice-controller.k8s.io"
      SERVICE_LABEL = "kubernetes.io/service-name"
      MANAGED_BY_LABEL = "endpointslice.kubernetes.io/managed-by"
      # kube-controller-manager --max-endpoints-per-slice (default 100; the
      # API allows 1000 per slice).
      ENDPOINT_LIMIT = 100

      include SecondarySupport

      def plan(service, store: nil, pods: nil, endpoint_slices: nil, **_options)
        planned = plan_service(service, store: store, pods: pods, endpoint_slices: endpoint_slices)
        # trackSync.
        ControllerMetrics.increment("endpoint_slice_controller_syncs", {"result" => "success"})
        planned
      rescue StandardError
        ControllerMetrics.increment("endpoint_slice_controller_syncs", {"result" => "error"})
        raise
      end

      def plan_service(service, store: nil, pods: nil, endpoint_slices: nil)
        adapter = adapter_for(store)
        orphaned = orphaned_slice_result(service, adapter)
        return orphaned if orphaned

        service = resolve_service(service, adapter)
        namespace = Support.namespace(service)
        pods ||= list_for(adapter, POD, namespace: namespace)
        endpoint_slices ||= list_for(adapter, ENDPOINT_SLICE, namespace: namespace)
        managed_slices = managed_slices_for(service, endpoint_slices)
        selected = selected_pods(service, pods)
        desired_groups = endpoint_groups(service, selected)
        operations = reconcile_slices(service, managed_slices, desired_groups, selected)
        operations = record_sync(service, managed_slices, desired_groups, operations)
        status = {
          "endpoints" => desired_groups.values.sum(&:length),
          "conditions" => desired_groups.transform_values { |endpoints| endpoints.map { |endpoint| Support.deep_copy(endpoint.fetch("conditions", {})) } }
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
      SERVICE_CACHE = {}
      SERVICE_CACHE_MUTEX = Mutex.new
      TRAFFIC_DISTRIBUTIONS = %w[PreferClose PreferSameZone PreferSameNode].freeze

      def self.hints_enabled?(service)
        annotations = Support.annotations(service)
        value = annotations.fetch("service.kubernetes.io/topology-aware-hints") { annotations["service.kubernetes.io/topology-mode"] }
        %w[Auto auto].include?(value.to_s)
      end

      def record_sync(service, existing, desired_groups, operations)
        key = "#{Support.namespace(service)}/#{Support.name(service)}"
        endpoint_key = ->(endpoint) { [Array(Support.value(endpoint, "addresses", [])).sort, Support.value(Support.value(endpoint, "targetRef", {}), "uid", "")] }
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
        SERVICE_CACHE_MUTEX.synchronize do
          SERVICE_CACHE[key] = {endpoints: endpoints, slices: existing.length + creates - deletes, desired: [desired, 1].max, traffic: traffic}
          publish_cache
        end
        ControllerMetrics.observe("endpoint_slice_controller_endpointslices_changed_per_sync", operations.length,
                                  {"topology" => hints ? "Auto" : "Disabled", "traffic_distribution" => traffic.to_s})
        operations.map do |operation|
          change = if operation.create? then "create"
                   elsif operation.delete? then "delete"
                   else "update"
                   end
          operation.observed { |succeeded, _| ControllerMetrics.increment("endpoint_slice_controller_changes", {"operation" => change}) if succeeded }
        end
      end

      def forget_service(key)
        SERVICE_CACHE_MUTEX.synchronize do
          publish_cache if SERVICE_CACHE.delete(key)
        end
      end

      # Must hold SERVICE_CACHE_MUTEX.
      def publish_cache
        values = SERVICE_CACHE.values
        ControllerMetrics.set("endpoint_slice_controller_num_endpoint_slices", values.sum { |entry| entry[:slices] })
        ControllerMetrics.set("endpoint_slice_controller_desired_endpoint_slices", values.sum { |entry| entry[:desired] })
        ControllerMetrics.set("endpoint_slice_controller_endpoints_desired", values.sum { |entry| entry[:endpoints] })
        Controller.metrics&.reset("endpoint_slice_controller_services_count_by_traffic_distribution")
        values.filter_map { |entry| entry[:traffic] }.tally.each do |traffic, count|
          ControllerMetrics.set("endpoint_slice_controller_services_count_by_traffic_distribution", count, {"traffic_distribution" => traffic})
        end
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

        operations = Support.labels(resource)[MANAGED_BY_LABEL] == MANAGED_BY ? [operation_delete(resource, descriptor: ENDPOINT_SLICE, reason: "service deleted")] : []
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
        selector = Support.value(Support.spec(service), "selector", {})
        selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && Support.value(selector, "matchLabels", nil)
        return [] if selector.nil? || selector == {} || selector.to_s.empty?

        publish_not_ready = Support.value(Support.spec(service), "publishNotReadyAddresses", false) == true
        Array(pods).select do |pod|
          next false unless Support.namespace(pod).to_s == Support.namespace(service).to_s
          next false unless Support.selector_matches?(selector, pod)
          next false if Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil? == false && !pod_has_endpoint_ip?(pod)

          publish_not_ready || pod_has_endpoint_ip?(pod)
        end.sort_by { |pod| [Support.name(pod), Support.uid(pod).to_s] }
      end

      def pod_has_endpoint_ip?(pod)
        ip = Support.value(Support.status(pod), "podIP", nil)
        ip = Array(Support.value(Support.status(pod), "podIPs", [])).first if ip.to_s.empty?
        !ip.to_s.empty?
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
      def endpoint_groups(service, pods)
        groups = service_address_types(service).to_h { |address_type| [address_type, []] }
        publish_not_ready = Support.value(Support.spec(service), "publishNotReadyAddresses", false) == true
        Array(pods).each do |pod|
          ips = Array(Support.value(Support.status(pod), "podIPs", [])).filter_map { |entry| Support.value(entry, "ip", nil) }
          pod_ip = Support.value(Support.status(pod), "podIP", nil)
          ips = [pod_ip] if ips.empty? && !pod_ip.to_s.empty?
          groups.each_key do |address_type|
            addresses = ips.map(&:to_s).select { |ip| (address_type == "IPv6") == ip.include?(":") }
            next if addresses.empty?

            ready = publish_not_ready || ready_condition_status(pod)
            conditions = {"ready" => ready, "serving" => ready,
                          "terminating" => !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?}
            endpoint = {"addresses" => addresses, "conditions" => conditions,
                        "targetRef" => {"kind" => "Pod", "namespace" => Support.namespace(pod).to_s,
                                        "name" => Support.name(pod), "uid" => Support.uid(pod)}}
            node_name = Support.value(Support.spec(pod), "nodeName", nil)
            endpoint["nodeName"] = node_name.to_s unless node_name.to_s.empty?
            endpoint["targetRef"].delete("uid") if Support.uid(pod).to_s.empty?
            endpoint["targetRef"].delete("namespace") if endpoint["targetRef"]["namespace"].to_s.empty?
            groups[address_type] << endpoint
          end
        end
        groups.each_value { |endpoints| endpoints.sort_by! { |endpoint| [endpoint.fetch("addresses").first, Support.value(endpoint.dig("targetRef"), "name", "")] } }
        groups
      end

      def endpoint_ports(service, pods)
        Array(Support.value(Support.spec(service), "ports", [])).filter_map do |port|
          target = Support.value(port, "targetPort", nil)
          target = Support.value(port, "port", nil) if target.nil?
          next if target.nil?
          endpoint_port = {}
          # endpointslice util getEndpointPorts always sets Name -- to "" for
          # an unnamed Service port -- and the API server keeps it.  Leaving
          # the key out made every sync of such a Service differ from the
          # stored slice: each reconcile rewrote it, the rewrite's own watch
          # event queued the next one, and "[sig-network] Service endpoints
          # latency should not be very high" drowned the controller in 200
          # Services updating their slices forever (median 26 s).
          endpoint_port["name"] = Support.value(port, "name", nil).to_s
          endpoint_port["protocol"] = Support.value(port, "protocol", "TCP").to_s
          if target.to_s.match?(/\A-?\d+\z/)
            endpoint_port["port"] = Integer(target)
          else
            named_port = Array(pods).flat_map do |pod|
              Array(Support.value(Support.spec(pod), "containers", [])).flat_map do |container|
                Array(Support.value(container, "ports", [])).filter_map do |container_port|
                  container_port if Support.value(container_port, "name", "").to_s == target.to_s
                end
              end
            end.first
            # podutil.FindPort: a named targetPort that no selected Pod
            # exposes yields no endpoint port at all -- never a port 0, which
            # is invalid on the wire and made the node DNS resolver refuse the
            # whole EndpointSlice stream.
            resolved = named_port ? Support.integer(Support.value(named_port, "containerPort", nil), 0) : 0
            next nil unless resolved.positive?

            endpoint_port["port"] = resolved
          end
          next nil unless endpoint_port["port"].to_i.positive?

          app_protocol = Support.value(port, "appProtocol", nil)
          endpoint_port["appProtocol"] = app_protocol.to_s unless app_protocol.to_s.empty?
          endpoint_port
        rescue ArgumentError
          nil
        end
      end

      def managed_slices_for(service, endpoint_slices)
        Array(endpoint_slices).select do |slice|
          labels = Support.labels(slice)
          next false unless labels[SERVICE_LABEL].to_s == Support.name(service)

          labels[MANAGED_BY_LABEL].to_s == MANAGED_BY ||
            owner_matches?(service, slice, controller: true)
        end.sort_by { |slice| [Support.value(slice, "addressType", "IPv4").to_s, Support.name(slice)] }
      end

      # Upstream groups endpoints by their resolved port set (a named
      # targetPort resolves per Pod), so Pods exposing the name on different
      # container ports land in different slices.
      def reconcile_slices(service, existing, desired_groups, selected_pods)
        operations = []
        pods_by_name = Array(selected_pods).to_h { |pod| [Support.name(pod), pod] }
        existing_by_type = existing.group_by { |slice| Support.value(slice, "addressType", "IPv4").to_s }
        desired_groups.each do |address_type, endpoints|
          by_ports = endpoints.group_by do |endpoint|
            pod = pods_by_name[Support.value(endpoint["targetRef"], "name", "")]
            endpoint_ports(service, pod ? [pod] : selected_pods)
          end
          slices = existing_by_type.delete(address_type) || []
          chunk_index = 0
          chunks = by_ports.sort_by { |ports, _| ports.map { |port| port["port"].to_i } }.flat_map do |ports, group|
            group.each_slice(ENDPOINT_LIMIT).map { |chunk| [ports, chunk] }
          end
          chunks.each do |ports, chunk|
            index = chunk_index
            chunk_index += 1
            candidate = endpoint_slice(service, address_type, ports, chunk, index)
            current = slices[index]
            if current
              candidate = preserve_slice_metadata(current, candidate)
              update = operation_update(current, candidate, descriptor: ENDPOINT_SLICE,
                                        reason: "service endpoint membership")
              operations << update if update
            else
              operations << operation_create(candidate, owner: service, descriptor: ENDPOINT_SLICE,
                                              reason: "service endpoint membership")
            end
          end
          slices.drop(chunks.length).each do |slice|
            operations << operation_delete(slice, descriptor: ENDPOINT_SLICE,
                                            reason: "stale service EndpointSlice")
          end
        end
        existing_by_type.values.flatten.each do |slice|
          operations << operation_delete(slice, descriptor: ENDPOINT_SLICE,
                                          reason: "empty service EndpointSlice")
        end
        operations = add_placeholder_slice(service, existing, operations)
        operations
      end

      # "When no endpoint slices would usually exist, we need to add a
      # placeholder" (staging/src/k8s.io/endpointslice/reconciler.go).  A
      # Service with a selector always owns at least one EndpointSlice, even
      # when it matches no Pods; the conformance spec
      # "[sig-network] EndpointSlice should create and delete EndpointSlices
      # for a Service with a selector that matches no pods" lists slices by
      # kubernetes.io/service-name and requires one to appear.  Without this we
      # created nothing and deleted every slice the Service had.
      #
      # An existing placeholder is KEPT rather than deleted and recreated,
      # which is what upstream's placeholderSliceCompare check is for.
      #
      # One placeholder per address type the Service supports: upstream
      # reconciles each addressType separately, so a dual-stack Service with
      # no Pods owns an IPv4 and an IPv6 placeholder.
      def add_placeholder_slice(service, existing, operations)
        return operations unless service_has_selector?(service)

        service_address_types(service).each do |address_type|
          type_of = ->(object) { Support.value(object, "addressType", "IPv4").to_s }
          next if operations.any? { |operation| operation.action == :create && type_of.call(operation.object) == address_type }

          slices = existing.select { |slice| type_of.call(slice) == address_type }
          deletes = operations.select { |operation| operation.action == :delete && slices.any? { |slice| same_object?(operation.object, slice) } }
          next unless deletes.length == slices.length

          placeholder = endpoint_slice(service, address_type, [], [], 0)
          kept = slices.find { |slice| placeholder_equivalent?(slice, placeholder) }
          operations = if kept
                         # Do not churn: drop the delete that would remove the placeholder.
                         operations.reject { |operation| operation.action == :delete && same_object?(operation.object, kept) }
                       else
                         operations + [operation_create(placeholder, owner: service, descriptor: ENDPOINT_SLICE,
                                                         reason: "placeholder EndpointSlice")]
                       end
        end
        operations
      end

      def service_has_selector?(service)
        selector = Support.value(Support.spec(service), "selector", {})
        selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && Support.value(selector, "matchLabels", nil)
        selector.is_a?(Hash) && !selector.empty?
      end

      # A placeholder is an owned slice of the same address type carrying no
      # ports and no endpoints; its generated name may differ from the one we
      # would pick now, which must not force a delete/recreate.
      def placeholder_equivalent?(slice, placeholder)
        Support.value(slice, "addressType", "IPv4").to_s == Support.value(placeholder, "addressType", "IPv4").to_s &&
          Array(Support.value(slice, "ports", [])).empty? &&
          Array(Support.value(slice, "endpoints", [])).empty?
      end

      def same_object?(left, right)
        return false unless left && right

        Support.name(left).to_s == Support.name(right).to_s &&
          Support.namespace(left).to_s == Support.namespace(right).to_s
      end

      def endpoint_slice(service, address_type, ports, endpoints, index)
        digest = canonical_hash({"service" => Support.uid(service), "type" => address_type})[0, 10]
        name = "#{Support.name(service)}-#{digest}-#{index}"
        candidate = {
          "apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
          "metadata" => {"name" => name, "namespace" => Support.namespace(service),
                         "labels" => {SERVICE_LABEL => Support.name(service), MANAGED_BY_LABEL => MANAGED_BY}},
          "addressType" => address_type, "ports" => Support.deep_copy(ports),
          "endpoints" => Support.deep_copy(endpoints)
        }
        ensure_owner_reference(candidate, service)
      end

      def preserve_slice_metadata(current, candidate)
        merged = Support.deep_copy(candidate)
        merged["metadata"] = Support.deep_copy(Support.metadata(current)).merge(Support.deep_copy(candidate.fetch("metadata")))
        merged["addressType"] = Support.value(current, "addressType", Support.value(candidate, "addressType", "IPv4"))
        merged["metadata"]["ownerReferences"] = Support.deep_copy(candidate.dig("metadata", "ownerReferences"))
        merged
      end
    end
  end
end
