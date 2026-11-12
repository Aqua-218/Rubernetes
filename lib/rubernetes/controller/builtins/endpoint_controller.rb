# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class EndpointController < BaseController
        SERVICE = ResourceDescriptor.parse("Service")
        POD = ResourceDescriptor.parse("Pod")
        ENDPOINTS = ResourceDescriptor.parse("Endpoints")

        def plan(resource, store: nil, pods: nil, endpoints: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          # This controller's declared kind is Endpoints, so the reconcile
          # loop resolves a queue key to the Endpoints object -- but the
          # desired state is derived from the *Service*: its selector picks
          # the Pods and its ports shape the subsets.  Planning from an
          # Endpoints object silently produced an empty selector, so every
          # Service ended up with an Endpoints that was created once, empty,
          # and never updated again.
          service = resource
          if Support.kind(resource).to_s == "Endpoints"
            endpoints ||= resource
            service = adapter&.find(SERVICE, name: Support.name(resource), namespace: Support.namespace(resource))
            return orphaned_endpoints_deletion(resource) if service.nil?
          end
          pods ||= adapter ? adapter.list(POD, namespace: Support.namespace(service)) : []
          endpoints ||= adapter ? adapter.find(ENDPOINTS, name: Support.name(service), namespace: Support.namespace(service)) : nil
          selector = Support.value(Support.spec(service), "selector", {})
          selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && Support.value(selector, "matchLabels", nil)
          # endpoints_controller.go syncService: "services without a selector
          # receive no endpoints from this controller; the user is responsible
          # for the Endpoints object".  Creating an empty one raced the user:
          # "[sig-network] EndpointSliceMirroring should mirror a custom
          # Endpoints resource" got AlreadyExists on its own Endpoints.
          return ReconcileResult.new(operations: [], status: {}, controller: name, key: reconcile_key(service)) unless selector_present?(selector)

          candidate = desired_endpoints(service, endpoints, subsets_for(service, selected_pods(service, pods, selector)))
          operations = []
          if endpoints.nil?
            operations << operation_create(candidate, owner: service, descriptor: ENDPOINTS, reason: "service selector update")
          elsif Support.owner_reference_matches?(service, endpoints)
            update = operation_update(endpoints, candidate, descriptor: ENDPOINTS, reason: "service selector update")
            operations << update if update
          end
          # Same self-heal as the EndpointSlice controller: a Pod readiness
          # event that raced the Service into the cache is re-planned 15 s on.
          ReconcileResult.new(operations: operations, status: {}, controller: name, key: reconcile_key(service), requeue_after: 15.0)
        end

        alias reconcile_service plan

        def delete(service, endpoints: nil, store: nil)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          endpoints ||= adapter&.find(ENDPOINTS, name: Support.name(service), namespace: Support.namespace(service))
          operations = endpoints ? [operation_delete(endpoints, descriptor: ENDPOINTS, reason: "service deletion")] : []
          ReconcileResult.new(operations: operations, controller: name)
        end

        private

        def reconcile_key(object)
          [Support.namespace(object), Support.name(object)].compact.join("/")
        end

        # "Delete the corresponding endpoints, as the service has been
        # deleted" (pkg/controller/endpoint/endpoints_controller.go:370).
        # Returning an empty plan left the Endpoints object behind for
        # ever, which is what "[sig-network] EndpointsController should
        # create and delete Endpoints for a Service" checks after it
        # deletes the Service.
        def orphaned_endpoints_deletion(endpoints)
          ReconcileResult.new(operations: [operation_delete(endpoints, descriptor: ENDPOINTS, reason: "service deleted")],
                              status: {}, controller: name, key: reconcile_key(endpoints))
        end

        def selector_present?(selector)
          selector.is_a?(Hash) ? !selector.empty? : !selector.nil? && !selector.to_s.empty?
        end

        def selected_pods(service, pods, selector)
          Array(pods).select do |pod|
            namespace_matches?(service, pod) &&
              !Support.metadata(pod).key?("deletionTimestamp") &&
              Support.selector_matches?(selector, pod)
          end
        end

        # One subset per distinct port list, ordered by port number, each with
        # its ready and not-ready addresses.
        def subsets_for(service, selected)
          groups = {}
          selected.each do |pod|
            address = address_for(pod, service)
            next if address.nil?

            ports = endpoint_ports(service, pod)
            group = (groups[ports] ||= {"ports" => ports, "addresses" => [], "notReadyAddresses" => []})
            (Support.ready?(pod) ? group["addresses"] : group["notReadyAddresses"]) << address
          end
          groups.values.sort_by { |group| group["ports"].map { |entry| entry["port"].to_i } }.map do |group|
            subset = {"ports" => group["ports"]}
            subset["addresses"] = group["addresses"] unless group["addresses"].empty?
            subset["notReadyAddresses"] = group["notReadyAddresses"] unless group["notReadyAddresses"].empty?
            subset
          end
        end

        # v1.EndpointPort carries the port *on the Pod*, not the Service
        # port: a subset describes where traffic actually lands.  Copying
        # the ServicePort verbatim published the Service port (and its
        # nodePort), which is not a field EndpointPort even has.
        # A named targetPort resolves per Pod (podutil.FindPort), so Pods
        # whose container ports differ land in different subsets, exactly as
        # upstream's endpoints controller groups them.
        def endpoint_ports(service, pod)
          container_ports = Array(Support.value(Support.spec(pod), "containers", [])).flat_map do |container|
            Array(Support.value(container, "ports", []))
          end
          Array(Support.value(Support.spec(service), "ports", [])).map do |port|
            target = Support.value(port, "targetPort", nil)
            target = Support.value(port, "port", nil) if target.nil? || target.to_s.empty?
            protocol = Support.value(port, "protocol", "TCP").to_s
            unless target.to_s.match?(/\A\d+\z/)
              match = container_ports.find do |candidate|
                Support.value(candidate, "name", "").to_s == target.to_s &&
                  Support.value(candidate, "protocol", "TCP").to_s == protocol
              end
              target = match ? Support.value(match, "containerPort", nil) : Support.value(port, "port", nil)
            end
            entry = {"port" => Support.integer(target, Support.integer(Support.value(port, "port", 0), 0)),
                     "protocol" => protocol}
            name = Support.value(port, "name", nil).to_s
            entry["name"] = name unless name.empty?
            app_protocol = Support.value(port, "appProtocol", nil)
            entry["appProtocol"] = app_protocol.to_s unless app_protocol.nil? || app_protocol.to_s.empty?
            entry
          end
        end

        def desired_endpoints(service, endpoints, subsets)
          candidate = if endpoints
                        Support.deep_copy(endpoints)
                      else
                        {"apiVersion" => "v1", "kind" => "Endpoints",
                         "metadata" => {"name" => Support.name(service), "namespace" => Support.namespace(service)}}
                      end
          candidate["subsets"] = subsets
          candidate["metadata"] ||= {}
          candidate["metadata"]["labels"] ||= {}
          # pkg/controller/endpoint/endpoints_controller.go ControllerName.
          candidate["metadata"]["labels"]["endpoints.kubernetes.io/managed-by"] = "endpoint-controller"
          candidate
        end

        def namespace_matches?(service, pod)
          service_namespace = Support.namespace(service)
          pod_namespace = Support.namespace(pod)
          service_namespace.nil? || service_namespace == pod_namespace
        end

        # pkg/controller/endpoint/endpoints_controller.go addressAndPort: the
        # Pod IP of the Service's primary family (ipFamilies[0], else the
        # family of its clusterIP, else the Pod's own primary), so an IPv6
        # Service in a dual-stack cluster is not published at the Pod's IPv4.
        def address_for(pod, service = nil)
          status = Support.status(pod)
          ips = Array(Support.value(status, "podIPs", [])).filter_map { |entry| Support.value(entry, "ip", nil).to_s }.reject(&:empty?)
          primary = Support.value(status, "podIP", nil) || Support.value(status, "podIp", nil)
          ips = [primary.to_s] if ips.empty? && !primary.to_s.empty?
          family = Array(Support.value(Support.spec(service || {}), "ipFamilies", [])).first.to_s
          if family.empty?
            cluster_ip = Support.value(Support.spec(service || {}), "clusterIP", "").to_s
            family = if !cluster_ip.empty? && cluster_ip != "None" then cluster_ip.include?(":") ? "IPv6" : "IPv4"
                     else ips.first.to_s.include?(":") ? "IPv6" : "IPv4"
                     end
          end
          ip = ips.find { |candidate| (family == "IPv6") == candidate.include?(":") }
          return nil if ip.nil? || ip.to_s.empty?

          # v1.ObjectReference: a targetRef without its namespace does not
          # identify the Pod, and the EndpointSlice conformance spec checks
          # the field explicitly.
          target = {"kind" => "Pod", "namespace" => Support.namespace(pod).to_s,
                    "name" => Support.name(pod), "uid" => Support.uid(pod)}
          target.delete("namespace") if target["namespace"].empty?
          target.delete("uid") if target["uid"].to_s.empty?
          {"ip" => ip.to_s, "targetRef" => target}
        end
      end
    end
  end
end
