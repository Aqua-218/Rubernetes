# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class EndpointController < BaseController
        SERVICE = ResourceDescriptor.parse("Service")
        POD = ResourceDescriptor.parse("Pod")
        ENDPOINTS = ResourceDescriptor.parse("Endpoints")

        def plan(resource, store: nil, pods: nil, endpoints: nil, **_options)
          adapter = store || @adapter
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
          selector = Support.unwrap_match_labels(Support.value(Support.spec(service), "selector", {}))
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
          adapter = store || @adapter
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
          matches = Support.selector_predicate(selector)
          publish_not_ready = Support.value(Support.spec(service), "publishNotReadyAddresses") == true
          Array(pods).select do |pod|
            namespace_matches?(service, pod) &&
              matches.call(pod) &&
              Support.pod_in_endpoints?(pod, include_terminating: publish_not_ready)
          end
        end

        # One subset per distinct port list, ordered by port number, each with
        # its ready and not-ready addresses.
        def subsets_for(service, selected)
          groups = {}
          publish_not_ready = Support.value(Support.spec(service), "publishNotReadyAddresses") == true
          selected.each do |pod|
            address = address_for(pod, service)
            next if address.nil?

            ports = Support.service_endpoint_ports(service, pod, include_empty_name: false)
            if ports.empty?
              spec = Support.spec(service)
              next unless Array(Support.value(spec, "ports")).empty? && Support.value(spec, "clusterIP") == "None"
            end

            group = (groups[ports] ||= {"ports" => ports, "addresses" => [], "notReadyAddresses" => []})
            field = publish_not_ready || Support.ready?(pod) ? "addresses" : "notReadyAddresses"
            group[field] << address
          end
          groups.values.sort_by { |group| group["ports"].map { |entry| entry["port"].to_i } }.map do |group|
            subset = {"ports" => group["ports"]}
            subset["addresses"] = group["addresses"] unless group["addresses"].empty?
            subset["notReadyAddresses"] = group["notReadyAddresses"] unless group["notReadyAddresses"].empty?
            subset
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
          candidate["metadata"]["labels"] = Support.service_endpoint_labels(service)
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
          ips = Support.pod_endpoint_ips(pod)
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
          {"ip" => ip.to_s, "targetRef" => target, "nodeName" => Support.value(Support.spec(pod), "nodeName").to_s,
           "hostname" => Support.endpoint_hostname(pod, service)}.compact
        end
      end
    end
  end
end
