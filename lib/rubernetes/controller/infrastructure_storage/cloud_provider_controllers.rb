# frozen_string_literal: true

require_relative "routed_load_balancer"

module Rubernetes
  module Controller
    # Cloud provider Service controller. A service with loadBalancerClass is
    # owned by the matching external implementation and is ignored here.
    class ServiceLBController < BaseController
      include InfrastructureStorageSupport
      include RoutedLoadBalancer

      SERVICE = ResourceDescriptor.parse("Service")
      NODE = ResourceDescriptor.parse("Node")

      def initialize(cloud_provider: nil, provider: nil, cloud: nil, **)
        @cloud_provider = cloud_provider || provider || cloud
        super(**)
      end

      def plan(service, store: nil, nodes: nil, provider: nil, cloud_provider: nil, cloud: nil, load_balancer_pool: nil,
               default_routed_load_balancer: false, **_options)
        if load_balancer_pool && (routed_service?(service, default_routed_load_balancer) || routed_finalizer?(service))
          return plan_routed_load_balancer(service, adapter_for(store), load_balancer_pool, default_routed_load_balancer)
        end

        return empty_result(service) unless cloud_owned?(service)

        provider = provider_from(provider || cloud_provider || cloud)
        return empty_result(service) if load_balancer_pool && !provider

        adapter = adapter_for(store)
        nodes ||= list_storage_objects(adapter, NODE, namespace: :all)
        result = call_provider(provider, %i[ensure_load_balancer ensureLoadBalancer create_load_balancer],
                               positional: [service, Array(nodes)],
                               keywords: {service: service, nodes: Array(nodes)})
        candidate_status = Support.deep_copy(Support.status(service))
        ingress = provider_ingress(result)
        load_balancer = Support.deep_copy(Support.value(candidate_status, "loadBalancer", {}))
        load_balancer = {} unless load_balancer.is_a?(Hash)
        load_balancer["ingress"] = Support.deep_copy(ingress) unless ingress.empty?
        candidate_status["loadBalancer"] = load_balancer unless load_balancer.empty?
        update = operation_status(service, candidate_status, descriptor: SERVICE,
                                                             reason: ingress.empty? ? "ensuring load balancer" : "load balancer ensured")
        events = if update.nil?
                   []
                 elsif ingress.empty?
                   [{"type" => "Normal", "reason" => "EnsuringLoadBalancer",
                     "message" => "ensuring load balancer for service #{name_key(service)}"}]
                 else
                   [{"type" => "Normal", "reason" => "EnsuredLoadBalancer",
                     "message" => "load balancer ensured for service #{name_key(service)}"}]
                 end
        ReconcileResult.new(operations: [update].compact, status: candidate_status, events: events,
                            controller: name, key: name_key(service))
      end

      def delete(service, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        call_provider(provider_from(provider || cloud_provider || cloud), %i[delete_load_balancer deleteLoadBalancer], positional: [service],
                                                                                                                       keywords: {service: service})
        ReconcileResult.new(operations: [], status: Support.status(service),
                            events: [{"type" => "Normal", "reason" => "DeletingLoadBalancer",
                                      "message" => "deleting load balancer for service #{name_key(service)}"}],
                            controller: name, key: name_key(service))
      end

      private

      def empty_result(service)
        ReconcileResult.new(operations: [], status: Support.status(service), controller: name,
                            key: name_key(service))
      end

      def cloud_owned?(service)
        Support.kind(service) == "Service" &&
          Support.value(Support.spec(service), "type", "ClusterIP").to_s == "LoadBalancer" &&
          Support.value(Support.spec(service), "loadBalancerClass", nil).to_s.empty?
      end
    end

    ServiceLbController = ServiceLBController
    ServiceLoadBalancerController = ServiceLBController

    # Synchronizes node PodCIDR routes through an injected cloud provider.
    # Route status entries carry a controller marker to fence ownership.
    class NodeRouteController < BaseController
      include InfrastructureStorageSupport

      NODE = ResourceDescriptor.parse("Node")
      MANAGED_BY = InfrastructureStorageSupport::MANAGED_ROUTE_CONTROLLER

      def initialize(cloud_provider: nil, provider: nil, cloud: nil, **)
        @cloud_provider = cloud_provider || provider || cloud
        super(**)
      end

      def plan(node, store: nil, routes: nil, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        cloud = provider_from(provider || cloud_provider || cloud)
        desired = desired_routes(node)
        existing = Array(routes || Support.value(Support.status(node), "routes", []))
        operations = []
        events = []
        desired.each do |route|
          call_provider(cloud, %i[ensure_route create_route], positional: [node, route],
                                                              keywords: {node: node, route: route, destination: route["destination"]})
          unless existing.any? { |candidate| route_identity(candidate) == route_identity(route) }
            events << {"type" => "Normal", "reason" => "RouteCreated",
                       "message" => "route #{route.fetch("destination")} assigned to node #{Support.name(node)}"}
          end
        end
        stale = existing.select do |candidate|
          managed_route?(candidate) &&
            desired.none? { |route| route_identity(route) == route_identity(candidate) }
        end
        stale.each do |route|
          call_provider(cloud, %i[delete_route remove_route], positional: [node, route],
                                                              keywords: {node: node, route: route, destination: Support.value(route, "destination", "")})
          events << {"type" => "Normal", "reason" => "RouteDeleted",
                     "message" => "route #{Support.value(route, "destination", "")} removed from node #{Support.name(node)}"}
        end
        candidate_status = Support.deep_copy(Support.status(node))
        candidate_status["routes"] = (existing.reject { |route| stale.include?(route) } + desired.reject do |route|
          existing.any? { |current| route_identity(current) == route_identity(route) }
        end).sort_by { |route| route_identity(route) }
        update = operation_status(node, candidate_status, descriptor: NODE, reason: "node route reconciliation")
        operations << update if update
        ReconcileResult.new(operations: operations, status: candidate_status, events: events,
                            controller: name, key: Support.name(node))
      end

      def delete(node, routes: nil, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        cloud = provider_from(provider || cloud_provider || cloud)
        Array(routes || Support.value(Support.status(node), "routes", [])).select { |route| managed_route?(route) }.each do |route|
          call_provider(cloud, %i[delete_route remove_route], positional: [node, route],
                                                              keywords: {node: node, route: route, destination: Support.value(route, "destination", "")})
        end
        ReconcileResult.new(operations: [], status: Support.status(node), controller: name,
                            key: Support.name(node))
      end

      private

      def desired_routes(node)
        spec = Support.spec(node)
        cidrs = Array(Support.value(spec, "podCIDRs", nil))
        cidrs = [Support.value(spec, "podCIDR", nil)] if cidrs.empty?
        provider_id = Support.value(spec, "providerID", nil).to_s
        cidrs.filter_map do |cidr|
          next if cidr.to_s.empty?

          {"destination" => cidr.to_s, "node" => Support.name(node),
           "providerID" => provider_id, "managedBy" => MANAGED_BY}
        end.sort_by { |route| route.fetch("destination") }
      end

      def route_identity(route)
        [Support.value(route, "destination", "").to_s, Support.value(route, "node", "").to_s]
      end

      def managed_route?(route)
        Support.value(route, "managedBy", nil).to_s == MANAGED_BY ||
          Support.value(route, "controller", nil).to_s == name.to_s
      end
    end

    # Removes nodes that the configured cloud provider no longer owns and
    # publishes a separate cloud readiness condition while present.
    class CloudNodeLifecycleController < BaseController
      include InfrastructureStorageSupport

      NODE = ResourceDescriptor.parse("Node")

      def initialize(cloud_provider: nil, provider: nil, cloud: nil, **)
        @cloud_provider = cloud_provider || provider || cloud
        super(**)
      end

      def plan(node, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        return empty_result(node) unless cloud_owned?(node)

        cloud = provider_from(provider || cloud_provider || cloud)
        provider_id = Support.value(Support.spec(node), "providerID", "").to_s
        result = if InfrastructureCapability.implements?(cloud, :instance_exists_by_provider_id)
                   call_provider(cloud, [:instance_exists_by_provider_id], positional: [provider_id],
                                                                           keywords: {node: node, provider_id: provider_id})
                 else
                   call_provider(cloud, %i[instance_exists? instance_exists node_exists? node_exists],
                                 positional: [node], keywords: {node: node, provider_id: provider_id})
                 end
        if result.nil?
          raise ProviderUnavailableError,
                "cloud provider for #{name} returned no instance-existence result"
        end
        return deletion_result(node) if result == false || Support.value(hash_value(result), "exists", true) == false

        candidate_status = Support.deep_copy(Support.status(node))
        candidate_status["conditions"] = upsert_condition(candidate_status["conditions"], "CloudNodeReady", "True", "CloudNodeExists")
        update = operation_status(node, candidate_status, descriptor: NODE, reason: "cloud node lifecycle")
        ReconcileResult.new(operations: [update].compact, status: candidate_status,
                            events: if update
                                      [{"type" => "Normal", "reason" => "CloudNodeReady",
                                        "message" => "cloud instance for node #{Support.name(node)} exists"}]
                                    else
                                      []
                                    end,
                            controller: name, key: Support.name(node))
      end

      private

      def cloud_owned?(node)
        Support.kind(node) == "Node" && !Support.value(Support.spec(node), "providerID", nil).to_s.empty?
      end

      def empty_result(node)
        ReconcileResult.new(operations: [], status: Support.status(node), controller: name,
                            key: Support.name(node))
      end

      def deletion_result(node)
        ReconcileResult.new(operations: [operation_delete(node, descriptor: NODE, reason: "cloud instance no longer exists")],
                            status: Support.status(node),
                            events: [{"type" => "Warning", "reason" => "CloudNodeNotReady",
                                      "message" => "cloud instance for node #{Support.name(node)} no longer exists"}],
                            controller: name, key: Support.name(node))
      end
    end
  end
end
