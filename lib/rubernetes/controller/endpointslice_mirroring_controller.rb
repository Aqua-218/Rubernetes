# frozen_string_literal: true

require_relative "../schema/kubernetes_validator/ip_fields"
require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"
require_relative "endpoint_slice_objects"
require_relative "endpoint_slice_metrics"

module Rubernetes
  module Controller
    # Mirrors legacy Endpoints objects into EndpointSlices.  The
    # endpointslice.kubernetes.io/managed-by label is the ownership boundary:
    # EndpointSlices from the selector-based controller or from users are
    # never rewritten by this controller.
    class EndpointSliceMirroringController < BaseController
      ENDPOINTS = ResourceDescriptor.parse("Endpoints")
      SERVICE = ResourceDescriptor.parse("Service")
      MANAGED_BY = "endpointslicemirroring-controller.k8s.io"
      SKIP_MIRROR_LABEL = "endpointslice.kubernetes.io/skip-mirror"
      ENDPOINT_LIMIT = 1_000

      include SecondarySupport
      include EndpointSliceObjects

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
        operations = reconcile_slices(endpoints, managed, desired_groups, reserved_names: endpoint_slices.to_set { |slice| Support.name(slice) })
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
        ReconcileResult.new(operations: operations, controller: name, key: key.to_s)
      end

      # endpointslicemirroring/metrics Cache (process-wide).
      ENDPOINTS_CACHE = EndpointSliceMetrics.new("endpoint_slice_mirroring_controller")

      # reconcile: addresses skipped, endpoints added / updated / removed,
      # each slice written, and the cache's gauges.
      def record_sync(endpoints, existing, desired_groups, operations)
        total = Array(Support.value(endpoints, "subsets", [])).sum do |subset|
          Array(Support.value(subset, "addresses", [])).length + Array(Support.value(subset, "notReadyAddresses", [])).length
        end
        wanted = desired_groups.values.flatten
        unless desired_groups.empty?
          ControllerMetrics.observe("endpoint_slice_mirroring_controller_addresses_skipped_per_sync",
                                    [total - wanted.length, 0].max)
        end
        before = endpoint_memberships(existing.map { |slice| [slice_group(slice), Array(Support.value(slice, "endpoints", []))] })
        after = endpoint_memberships(desired_groups)
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_endpoints_added_per_sync", (after.keys - before.keys).length)
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_endpoints_updated_per_sync",
                                  after.count { |address, endpoint| before.key?(address) && before[address] != endpoint })
        ControllerMetrics.observe("endpoint_slice_mirroring_controller_endpoints_removed_per_sync", (before.keys - after.keys).length)
        slices = existing.length + operations.count(&:create?) - operations.count(&:delete?)
        ENDPOINTS_CACHE.update("#{Support.namespace(endpoints)}/#{Support.name(endpoints)}",
                               {slices: slices, desired: desired_groups.length, endpoints: wanted.length})
        ENDPOINTS_CACHE.observe_changes(operations)
      end

      def forget_endpoints(key)
        ENDPOINTS_CACHE.update(key, nil)
      end

      private

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
        indexed = {}
        by_port = Hash.new { |hash, port| hash[port] = {} }
        Array(Support.value(endpoints, "subsets", [])).each do |subset|
          addresses = subset_addresses(subset, indexed)
          next if addresses.empty?

          ports = normalized_ports(Support.value(subset, "ports"))
          ports = [nil] if ports.empty?
          ports.each { |port| by_port[port].merge!(addresses) { |_, before, after| before && after } }
        end

        # Repack equally served ports together. An address may offer a
        # different set of ports or have different readiness on each port.
        groups = Hash.new { |hash, key| hash[key] = [] }
        by_port.group_by { |_, addresses| addresses }.each do |addresses, mappings|
          ports = normalized_ports(mappings.filter_map(&:first))
          addresses.sort_by { |key, ready| [ready ? 0 : 1, key] }.first(ENDPOINT_LIMIT).each do |key, ready|
            address_type, endpoint = indexed.fetch(key)
            groups[[address_type, ports]] << endpoint.merge("conditions" => {"ready" => ready, "serving" => ready, "terminating" => false})
          end
        end
        groups.transform_values do |values|
          values.to_h { |endpoint| [endpoint_identity(endpoint), endpoint] }.sort_by(&:first).map(&:last)
        end
      end

      def subset_addresses(subset, indexed)
        {"addresses" => true, "notReadyAddresses" => false}.each_with_object({}) do |(field, ready), addresses|
          Array(Support.value(subset, field)).each do |address|
            ip = Support.value(address, "ip").to_s
            uid = Support.value(Support.value(address, "targetRef"), "uid").to_s
            key = [ip, uid]
            endpoint = indexed[key] ||= mirrored_address(address, ip)
            addresses[key] = ready if endpoint
          end
        end
      end

      def mirrored_address(address, ip)
        parsed = Schema::KubernetesValidator.sloppy_ip(ip)&.first
        return unless parsed

        parsed = parsed.native if parsed.ipv4_mapped?
        endpoint = {"addresses" => [parsed.to_s], "nodeName" => Support.value(address, "nodeName"),
                    "targetRef" => Support.value(address, "targetRef")}.compact
        hostname = Support.value(address, "hostname").to_s
        endpoint["hostname"] = hostname unless hostname.empty?
        [parsed.ipv4? ? "IPv4" : "IPv6", endpoint]
      end

      def endpoint_identity(endpoint)
        target = Support.value(endpoint, "targetRef")
        [Array(Support.value(endpoint, "addresses")).sort, Support.value(endpoint, "hostname").to_s,
         Support.value(target, "namespace").to_s, Support.value(target, "name").to_s]
      end

      def endpoint_memberships(groups)
        groups.flat_map do |group, endpoints|
          endpoints.map { |endpoint| [[group, endpoint_identity(endpoint)], endpoint] }
        end.to_h
      end

      def reconcile_slices(endpoints, existing, desired_groups, reserved_names:)
        operations = []
        existing_by_group = existing.group_by { |slice| slice_group(slice) }
        missing = {}
        desired_groups.sort_by { |group, _| Support.digest(group) }.each do |group, endpoint_values|
          current = existing_by_group.fetch(group, []).shift
          if current
            operations << update_slice(endpoints, group, endpoint_values, current)
          else
            missing[group] = endpoint_values
          end
        end

        stale = existing_by_group.values.flatten.group_by { |slice| Support.value(slice, "addressType", "IPv4").to_s }
        missing.each do |group, endpoint_values|
          # EndpointSlice addressType is immutable. Reuse a stale slice only
          # in the same family, after reserving every exact port-map match.
          current = stale.fetch(group.first, []).shift
          if current
            operations << update_slice(endpoints, group, endpoint_values, current)
          else
            name = reserve_slice_name(endpoints, group, reserved_names)
            candidate = endpoint_slice(endpoints, group, endpoint_values, name)
            operations << operation_create(candidate, owner: endpoints, descriptor: ENDPOINT_SLICE, reason: "legacy Endpoints mirror")
          end
        end
        stale.values.flatten.each do |slice|
          operations << operation_delete(slice, descriptor: ENDPOINT_SLICE, reason: "stale mirrored EndpointSlice")
        end
        operations.compact
      end

      def slice_group(slice)
        [Support.value(slice, "addressType", "IPv4").to_s, normalized_ports(Support.value(slice, "ports"))]
      end

      def update_slice(endpoints, group, endpoint_values, current)
        candidate = endpoint_slice(endpoints, group, endpoint_values, Support.name(current))
        operation_update(current, preserve_slice_metadata(current, candidate), descriptor: ENDPOINT_SLICE, reason: "legacy Endpoints mirror")
      end

      def reserve_slice_name(endpoints, group, reserved_names)
        digest = canonical_hash([Support.uid(endpoints), group])[0, 10]
        # EndpointSlice names are DNS subdomains, with a maximum of 253 bytes.
        stem = Support.name(endpoints).byteslice(0, 223).sub(/[^a-z0-9]+\z/, "")
        0.step do |index|
          name = "#{stem}-mirror-#{digest}-#{index}"
          return name if reserved_names.add?(name)
        end
      end

      def endpoint_slice(endpoints, group, endpoint_values, name)
        address_type, ports = group
        build_slice(endpoints, name, Support.labels(endpoints), address_type, ports, endpoint_values)
      end

      def normalized_ports(ports)
        normalized = Array(ports).filter_map do |port|
          number = Integer(Support.value(port, "port"), exception: false)
          next unless number && number.positive?

          protocol = Support.value(port, "protocol").to_s
          app_protocol = Support.value(port, "appProtocol").to_s
          result = {"name" => Support.value(port, "name").to_s, "port" => number, "protocol" => protocol.empty? ? "TCP" : protocol}
          result["appProtocol"] = app_protocol unless app_protocol.empty?
          result
        end
        normalized.uniq.sort_by { |port| [port["name"], port["protocol"], port["port"], port["appProtocol"].to_s] }
      end
    end
  end
end
