# frozen_string_literal: true

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # Mirrors legacy Endpoints objects into EndpointSlices.  The
    # endpointslice.kubernetes.io/managed-by label is the ownership boundary:
    # EndpointSlices from the selector-based controller or from users are
    # never rewritten by this controller.
    class EndpointSliceMirroringController < BaseController
      ENDPOINTS = ResourceDescriptor.parse("Endpoints")
      SERVICE = ResourceDescriptor.parse("Service")
      ENDPOINT_SLICE = ResourceDescriptor.parse("EndpointSlice")
      SERVICE_LABEL = "kubernetes.io/service-name"
      MANAGED_BY_LABEL = "endpointslice.kubernetes.io/managed-by"
      MANAGED_BY = "endpointslicemirroring-controller.k8s.io"
      SKIP_MIRROR_LABEL = "endpointslice.kubernetes.io/skip-mirror"
      ENDPOINT_LIMIT = 1_000

      include SecondarySupport

      def plan(endpoints, store: nil, endpoint_slices: nil, **_options)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        plan_endpoints(endpoints, store: store, endpoint_slices: endpoint_slices)
      ensure
        # syncEndpoints: whole milliseconds, in seconds.
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_endpoints_sync_duration",
                                  ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).floor / 1000.0)
      end

      def plan_endpoints(endpoints, store: nil, endpoint_slices: nil)
        adapter = adapter_for(store)
        endpoints = resolve_endpoints(endpoints, adapter)
        namespace = Support.namespace(endpoints)
        endpoint_slices ||= list_for(adapter, ENDPOINT_SLICE, namespace: namespace)
        managed = managed_slices_for(endpoints, endpoint_slices)
        desired_groups = skip_mirror?(endpoints) || selector_service?(endpoints, adapter) ? {} : endpoint_groups(endpoints)
        operations = reconcile_slices(endpoints, managed, desired_groups)
        operations = record_sync(endpoints, managed, desired_groups, operations)
        status = {"endpoints" => desired_groups.values.sum(&:length)}
        events = if operations.empty?
                   []
                 else
                   [{"type" => "Normal", "reason" => "EndpointSliceMirrored",
                     "message" => "Endpoints #{Support.name(endpoints)} mirrored to EndpointSlices"}]
                 end
        ReconcileResult.new(operations: operations, status: status, events: events,
                            controller: name, key: object_key_for(endpoints))
      end

      # The Endpoints object is gone, so its mirror has to go with it.
      #
      # Upstream's mirroring controller owns each mirrored EndpointSlice by the
      # ENDPOINTS object (endpointslicemirroring/reconciler.go sets an owner
      # reference to it), and it also handles the deletion itself: its queue
      # gets the Endpoints key on a delete and it removes the slices.  Leaving
      # it to the garbage collector instead makes the removal wait for the next
      # sweep, and "[sig-network] EndpointSliceMirroring should mirror a custom
      # Endpoints resource through create update and delete" allows twelve
      # seconds for it.
      def plan_orphans(key, store: nil)
        namespace, _, name = key.to_s.partition("/")
        return nil if namespace.empty? || name.empty?

        adapter = adapter_for(store)
        return nil if adapter.nil?
        # Only once the Endpoints really is gone; a key whose object is merely
        # not in this controller's cache is not a deletion.
        return nil if find_for(adapter, ENDPOINTS, name, namespace: namespace)

        slices = list_for(adapter, ENDPOINT_SLICE, namespace: namespace).select do |slice|
          labels = Support.labels(slice)
          labels[SERVICE_LABEL].to_s == name && labels[MANAGED_BY_LABEL].to_s == MANAGED_BY
        end
        forget_endpoints(key.to_s)
        return nil if slices.empty?

        operations = slices.map do |slice|
          operation_delete(slice, descriptor: ENDPOINT_SLICE, reason: "mirrored Endpoints deleted").observed do |succeeded, _|
            ControllerMetrics.increment("endpoint_slice_mirroring_controller_changes", {"operation" => "delete"}) if succeeded
          end
        end
        ReconcileResult.new(operations: operations, controller: name_for_result, key: key.to_s)
      end

      # endpointslicemirroring/metrics Cache (process-wide).
      ENDPOINTS_CACHE = {}
      ENDPOINTS_CACHE_MUTEX = Mutex.new

      # reconcile: addresses skipped, endpoints added / updated / removed,
      # each slice written, and the cache's gauges.
      def record_sync(endpoints, existing, desired_groups, operations)
        total = Array(Support.value(endpoints, "subsets", [])).sum do |subset|
          Array(Support.value(subset, "addresses", [])).length + Array(Support.value(subset, "notReadyAddresses", [])).length
        end
        wanted = desired_groups.values.flatten
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_addresses_skipped_per_sync", [total - wanted.length, 0].max) unless desired_groups.empty?
        before = existing.flat_map { |slice| Array(Support.value(slice, "endpoints", [])) }.to_h { |endpoint| [Array(endpoint["addresses"]).first, endpoint] }
        after = wanted.to_h { |endpoint| [Array(endpoint["addresses"]).first, endpoint] }
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_endpoints_added_per_sync", (after.keys - before.keys).length)
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_endpoints_updated_per_sync",
                                  after.count { |address, endpoint| before.key?(address) && before[address] != endpoint })
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_endpoints_removed_per_sync", (before.keys - after.keys).length)
        slices = existing.length + operations.count(&:create?) - operations.count(&:delete?)
        desired = desired_groups.values.sum { |group| group.empty? ? 0 : (group.length + ENDPOINT_LIMIT - 1) / ENDPOINT_LIMIT }
        ENDPOINTS_CACHE_MUTEX.synchronize do
          ENDPOINTS_CACHE["#{Support.namespace(endpoints)}/#{Support.name(endpoints)}"] = {slices: slices, desired: desired, endpoints: wanted.length}
          publish_cache
        end
        operations.map do |operation|
          change = if operation.create? then "create"
                   elsif operation.delete? then "delete"
                   else "update"
                   end
          operation.observed { |succeeded, _| ControllerMetrics.increment("endpoint_slice_mirroring_controller_changes", {"operation" => change}) if succeeded }
        end
      end

      def forget_endpoints(key)
        ENDPOINTS_CACHE_MUTEX.synchronize { publish_cache if ENDPOINTS_CACHE.delete(key) }
      end

      def publish_cache
        values = ENDPOINTS_CACHE.values
        ControllerMetrics.set("endpoint_slice_mirroring_controller_num_endpoint_slices", values.sum { |entry| entry[:slices] })
        ControllerMetrics.set("endpoint_slice_mirroring_controller_desired_endpoint_slices", values.sum { |entry| entry[:desired] })
        ControllerMetrics.set("endpoint_slice_mirroring_controller_endpoints_desired", values.sum { |entry| entry[:endpoints] })
      end

      private

      def name_for_result
        respond_to?(:name) ? name : "endpointslice-mirroring-controller"
      end

      def resolve_endpoints(resource, adapter)
        return resource if Support.kind(resource) == "Endpoints"
        service_name = Support.labels(resource)[SERVICE_LABEL]
        candidate = find_for(adapter, ENDPOINTS, service_name, namespace: Support.namespace(resource))
        raise StoreError, "Endpoints #{service_name.inspect} was not found" unless candidate

        candidate
      end

      # Upstream shouldMirror: a Service with a selector already gets its
      # EndpointSlices from the endpointslice controller; mirroring its
      # Endpoints too would publish every endpoint twice (and, through the
      # proxy, at the Service port instead of the target port).
      def selector_service?(endpoints, adapter)
        service = find_for(adapter, SERVICE, Support.name(endpoints), namespace: Support.namespace(endpoints))
        return false if service.nil?

        selector = Support.value(Support.spec(service), "selector", nil)
        selector.is_a?(Hash) && !selector.empty?
      rescue StandardError
        false
      end

      def skip_mirror?(endpoints)
        value = Support.labels(endpoints)[SKIP_MIRROR_LABEL] || Support.annotations(endpoints)[SKIP_MIRROR_LABEL]
        value.to_s.casecmp("true").zero?
      end

      def endpoint_groups(endpoints)
        groups = Hash.new { |hash, key| hash[key] = [] }
        subsets = Array(Support.value(endpoints, "subsets", []))
        subsets.each do |subset|
          ports = Array(Support.value(subset, "ports", []))
          Array(Support.value(subset, "addresses", [])).each do |address|
            add_endpoint(groups, address, ready: true)
          end
          Array(Support.value(subset, "notReadyAddresses", [])).each do |address|
            add_endpoint(groups, address, ready: false)
          end
          # Retain ports as an attribute attached to the group.  Endpoints
          # allows a different port set per subset; the reconciler combines
          # them deterministically before writing each slice.
          groups.each_value { |endpoints_for_type| endpoints_for_type.each { |endpoint| endpoint["_ports"] ||= Support.deep_copy(ports) } }
        end
        groups.each_value do |endpoints_for_type|
          endpoints_for_type.each { |endpoint| endpoint.delete("_ports") }
          endpoints_for_type.sort_by! { |endpoint| [endpoint.fetch("addresses").first, Support.value(endpoint.dig("targetRef"), "name", "")] }
        end
        groups
      end

      def add_endpoint(groups, address, ready:)
        ip = Support.value(address, "ip", nil)
        hostname = Support.value(address, "hostname", nil)
        value = ip || hostname
        return if value.to_s.empty?

        address_type = if ip.to_s.include?(":")
                         "IPv6"
                       elsif ip
                         "IPv4"
                       else
                         "FQDN"
                       end
        endpoint = {"addresses" => [value.to_s],
                    "conditions" => {"ready" => ready, "serving" => ready, "terminating" => false}}
        target_ref = Support.value(address, "targetRef", nil)
        endpoint["targetRef"] = Support.deep_copy(target_ref) if target_ref.is_a?(Hash)
        endpoint["hostname"] = hostname.to_s if hostname
        groups[address_type] << endpoint
      end

      def managed_slices_for(endpoints, endpoint_slices)
        Array(endpoint_slices).select do |slice|
          labels = Support.labels(slice)
          labels[SERVICE_LABEL].to_s == Support.name(endpoints) &&
            labels[MANAGED_BY_LABEL].to_s == MANAGED_BY
        end.sort_by { |slice| [Support.value(slice, "addressType", "IPv4").to_s, Support.name(slice)] }
      end

      def reconcile_slices(endpoints, existing, desired_groups)
        operations = []
        existing_by_type = existing.group_by { |slice| Support.value(slice, "addressType", "IPv4").to_s }
        desired_groups.each do |address_type, endpoints_for_type|
          chunks = endpoints_for_type.each_slice(ENDPOINT_LIMIT).to_a
          slices = existing_by_type.delete(address_type) || []
          chunks.each_with_index do |chunk, index|
            candidate = endpoint_slice(endpoints, address_type, chunk, index)
            current = slices[index]
            if current
              candidate = preserve_metadata(current, candidate)
              update = operation_update(current, candidate, descriptor: ENDPOINT_SLICE,
                                        reason: "legacy Endpoints mirror")
              operations << update if update
            else
              operations << operation_create(candidate, owner: endpoints, descriptor: ENDPOINT_SLICE,
                                              reason: "legacy Endpoints mirror")
            end
          end
          slices.drop(chunks.length).each do |slice|
            operations << operation_delete(slice, descriptor: ENDPOINT_SLICE,
                                            reason: "stale mirrored EndpointSlice")
          end
        end
        existing_by_type.values.flatten.each do |slice|
          operations << operation_delete(slice, descriptor: ENDPOINT_SLICE,
                                          reason: "empty mirrored EndpointSlice")
        end
        operations
      end

      def endpoint_slice(endpoints, address_type, endpoint_values, index)
        digest = canonical_hash({"endpoints" => Support.uid(endpoints), "type" => address_type})[0, 10]
        candidate = {
          "apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
          "metadata" => {"name" => "#{Support.name(endpoints)}-mirror-#{digest}-#{index}",
                         "namespace" => Support.namespace(endpoints),
                         "labels" => {SERVICE_LABEL => Support.name(endpoints), MANAGED_BY_LABEL => MANAGED_BY}},
          "addressType" => address_type, "ports" => mirrored_ports(endpoints),
          "endpoints" => Support.deep_copy(endpoint_values)
        }
        ensure_owner_reference(candidate, endpoints)
      end

      def mirrored_ports(endpoints)
        ports = Array(Support.value(endpoints, "subsets", [])).flat_map do |subset|
          Array(Support.value(subset, "ports", []))
        end.uniq { |port| Support.canonical(port) }
        ports.map do |port|
          result = {}
          name = Support.value(port, "name", nil)
          result["name"] = name.to_s unless name.to_s.empty?
          result["protocol"] = Support.value(port, "protocol", "TCP").to_s
          result["port"] = Integer(Support.value(port, "port", 0))
          app_protocol = Support.value(port, "appProtocol", nil)
          result["appProtocol"] = app_protocol.to_s unless app_protocol.to_s.empty?
          result
        rescue ArgumentError
          nil
        end.compact
      end

      def preserve_metadata(current, candidate)
        merged = Support.deep_copy(candidate)
        merged["metadata"] = Support.deep_copy(Support.metadata(current)).merge(Support.deep_copy(candidate.fetch("metadata")))
        merged["addressType"] = Support.value(current, "addressType", candidate["addressType"])
        merged["metadata"]["ownerReferences"] = Support.deep_copy(candidate.dig("metadata", "ownerReferences"))
        merged
      end
    end
  end
end
