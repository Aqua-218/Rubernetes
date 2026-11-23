# frozen_string_literal: true

require_relative "network_policy"
require_relative "service_spec"
require_relative "../../support/service_traffic"

module Rubernetes
  module Schema
    # Service, Endpoints, EndpointSlice, Ingress, IngressClass, and ServiceCIDR.
    module KubernetesValidator
      module_function

      def service_load_balancer_errors(root, old, operation)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        old_spec = fetch(old, "spec") if operation == :update
        load_balancer = fetch(spec, "type") == "LoadBalancer"
        old_load_balancer = fetch(old_spec, "type") == "LoadBalancer"
        class_name = fetch(spec, "loadBalancerClass")
        old_class_name = fetch(old_spec, "loadBalancerClass")
        allocate = fetch(spec, "allocateLoadBalancerNodePorts")
        # The allocation strategy will drop unchanged fields when leaving LoadBalancer.
        if old_load_balancer && !load_balancer
          class_name = nil if class_name == old_class_name
          allocate = nil if allocate == fetch(old_spec, "allocateLoadBalancerNodePorts")
        end

        path = %w[spec loadBalancerClass]
        class_issues = service_load_balancer_class_errors(path, class_name, load_balancer)
        issues = []
        issues << valued_issue(path, class_name, "may not change once set") if old_load_balancer && load_balancer && class_name != old_class_name
        # ValidateServiceUpdate checks the class before running the base Service validator.
        issues.concat(class_issues) if old_spec
        if !load_balancer && !allocate.nil?
          issues << issue(%w[spec allocateLoadBalancerNodePorts], :forbidden, "may only be used when `type` is 'LoadBalancer'")
        end
        issues.concat(class_issues)
      end

      def service_traffic_errors(root, old)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        previous = fetch(old, "spec") || {}
        traffic = Rubernetes::Support::ServiceTraffic
        issues = []
        if traffic.type(spec) == "ClusterIP" && !traffic.drop_node_ports?(previous, spec)
          Array(spec["ports"]).each_with_index do |port, index|
            next unless port.is_a?(Hash) && port["nodePort"].is_a?(Integer) && !port["nodePort"].zero?

            issues << issue(["spec", "ports", index.to_s, "nodePort"], :forbidden, "may not be used when `type` is 'ClusterIP'")
          end
        end
        external = spec["externalTrafficPolicy"]
        if external.is_a?(String) && !external.empty? && !traffic.drop_external_policy?(previous, spec)
          if !traffic.external?(spec)
            issues << valued_issue(%w[spec externalTrafficPolicy], external, "may only be set for externally-accessible services")
          elsif !%w[Cluster Local].include?(external)
            issues << issue(%w[spec externalTrafficPolicy], :unsupported, unsupported_detail(%w[Cluster Local]))
          end
        end

        health = spec["healthCheckNodePort"]
        if health.is_a?(Integer) && !health.zero?
          if !traffic.health_check?(spec) && !traffic.drop_health_port?(previous, spec)
            issues << valued_issue(%w[spec healthCheckNodePort], health,
                                   "may only be set when `type` is 'LoadBalancer' and `externalTrafficPolicy` is 'Local'")
          elsif traffic.health_check?(previous) && traffic.health_check?(spec) && health != previous["healthCheckNodePort"]
            issues << issue(%w[spec healthCheckNodePort], :forbidden, "field is immutable")
          end
        end
        internal = spec["internalTrafficPolicy"]
        if internal.is_a?(String) && !%w[Cluster Local].include?(internal)
          issues << issue(%w[spec internalTrafficPolicy], :unsupported, unsupported_detail(%w[Cluster Local]))
        end
        issues
      end

      def service_load_balancer_class_errors(path, class_name, load_balancer)
        return [] if class_name.nil?
        return [issue(path, :forbidden, "may only be used when `type` is 'LoadBalancer'")] unless load_balancer

        qualified_name_messages(class_name, label_key: true).map { |message| valued_issue(path, class_name, message) }
      end

      # validateUpgradeDowngradeClusterIPs (pkg/apis/core/validation): a
      # Service's clusterIP may not change once set, and the primary may not be
      # unset.  Nothing enforced it, so an update could move a live Service to
      # a different address while every client kept using the old one.
      def service_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        old_spec = fetch(old, "spec")
        new_spec = fetch(root, "spec")
        return [] unless old_spec.is_a?(Hash) && new_spec.is_a?(Hash)
        # A Service moving to or from ExternalName legitimately gains or loses
        # its address; that transition is handled by the registry.
        return [] if external_name_service?(old_spec) || external_name_service?(new_spec)

        old_ips = Array(fetch(old_spec, "clusterIPs") || [fetch(old_spec, "clusterIP")].compact)
        new_ips = Array(fetch(new_spec, "clusterIPs") || [fetch(new_spec, "clusterIP")].compact)
        return [] if old_ips.empty?
        # An update that simply omits the field keeps what was allocated.
        return [] if new_ips.empty?

        return [] if new_ips.first.to_s == old_ips.first.to_s

        [issue(%w[spec clusterIPs 0], :invalid, "may not change once set")]
      end

      def endpoints_errors(root, operation = :create)
        return [] unless operation == :create

        subsets = fetch(root, "subsets")
        return [] unless subsets.is_a?(Array)

        subsets.each_with_index.flat_map do |subset, index|
          next [] unless subset.is_a?(Hash)

          issues = []
          addresses = fetch(subset, "addresses")
          not_ready = fetch(subset, "notReadyAddresses")
          if (!addresses.is_a?(Array) || addresses.empty?) &&
             (!not_ready.is_a?(Array) || not_ready.empty?)
            issues << issue(["subsets", index.to_s], :required,
                            "must specify `addresses` or `notReadyAddresses`")
          end
          %w[addresses notReadyAddresses].each do |field|
            entries = fetch(subset, field)
            next unless entries.is_a?(Array)

            entries.each_with_index do |address, address_index|
              next unless address.is_a?(Hash)

              ip = fetch(address, "ip")
              ip_path = ["subsets", index.to_s, field, address_index.to_s, "ip"]
              messages = legacy_ip_messages(ip)
              next if messages.empty?

              if messages == [INVALID_IP]
                # validateEpAddress: IsValidIPForLegacyField, then
                # ValidateEndpointIP's own parse failure.
                issues << issue(ip_path, :invalid, "must be a valid IP address")
                issues << issue(ip_path, :invalid, INVALID_IP)
              else
                issues.concat(invalid_messages(ip_path, messages))
              end
            end
          end
          issues
        end
      end

      def endpoint_slice_errors(root, operation = :create, old = nil)
        issues = []
        address_type = fetch(root, "addressType")
        if blank?(address_type)
          issues << issue(%w[addressType], :required, "")
        elsif !%w[FQDN IPv4 IPv6].include?(address_type.to_s)
          issues << issue(%w[addressType], :unsupported, "supported values: \"FQDN\", \"IPv4\", \"IPv6\"")
        end
        endpoints = fetch(root, "endpoints")
        if endpoints.is_a?(Array) && !(operation == :update && endpoints == fetch(old, "endpoints"))
          endpoints.each_with_index do |endpoint, index|
            next unless endpoint.is_a?(Hash)

            addresses = fetch(endpoint, "addresses")
            path = ["endpoints", index.to_s, "addresses"]
            if !addresses.is_a?(Array) || addresses.empty?
              issues << issue(path, :required, "must contain at least 1 address")
            elsif addresses.length > 100
              issues << ValidationIssue.new(path: path, code: :too_many, message: "must have at most 100 items",
                                            value: addresses.length, kubernetes_type: "Too many")
            end
          end
        end
        issues << issue(%w[addressType], :invalid, "field is immutable") if operation == :update && old && address_type.to_s != fetch(old, "addressType").to_s
        issues
      end

      def service_cidr_errors(root, operation)
        return [] unless operation == :create

        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        cidrs = fetch(spec, "cidrs")
        return [] if cidrs.is_a?(Array) && !cidrs.empty?

        [issue(%w[spec cidrs], :required, "at least one CIDR required")]
      end

      def ingress_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        default_backend = fetch(spec, "defaultBackend")
        rules = fetch(spec, "rules")
        issues = []
        if default_backend.nil? && (!rules.is_a?(Array) || rules.empty?)
          issues << issue(%w[spec], :invalid, "either `defaultBackend` or `rules` must be specified")
        end
        issues.concat(ingress_backend_errors(default_backend, %w[spec defaultBackend])) if default_backend.is_a?(Hash)
        return issues unless rules.is_a?(Array)

        rules.each_with_index do |rule, rule_index|
          next unless rule.is_a?(Hash)

          http = fetch(rule, "http")
          next unless http.is_a?(Hash)

          paths = fetch(http, "paths")
          if !paths.is_a?(Array) || paths.empty?
            issues << issue(["spec", "rules", rule_index.to_s, "http", "paths"], :required, "")
            next
          end
          paths.each_with_index do |path, path_index|
            next unless path.is_a?(Hash)

            path_base = ["spec", "rules", rule_index.to_s, "http", "paths", path_index.to_s]
            path_type = fetch(path, "pathType")
            if blank?(path_type)
              issues << issue(path_base + ["pathType"], :required, "pathType must be specified")
            elsif !%w[Exact ImplementationSpecific Prefix].include?(path_type.to_s)
              issues << issue(path_base + ["pathType"], :unsupported,
                              "supported values: \"Exact\", \"ImplementationSpecific\", \"Prefix\"")
            end
            backend = fetch(path, "backend")
            issues.concat(ingress_backend_errors(backend, path_base + ["backend"]))
          end
        end
        issues
      end

      def ingress_backend_errors(backend, path)
        backend = {} unless backend.is_a?(Hash)
        resource = fetch(backend, "resource")
        service = fetch(backend, "service")
        return [issue(path, :invalid, "cannot set both resource and service backends")] if resource.is_a?(Hash) && service.is_a?(Hash)
        return [issue(path, :invalid, "resource or service backend is required")] unless resource.is_a?(Hash) || service.is_a?(Hash)

        issues = []
        if service.is_a?(Hash)
          name = fetch(service, "name")
          if blank?(name)
            issues << issue(path + %w[service name], :required, "")
          else
            # RelaxedServiceNameValidation: the backend Service name is a
            # DNS label, the same rule as the Service's own name.
            issues.concat(invalid_messages(path + %w[service name], dns1123_label_messages(name)))
          end
          port = fetch(service, "port")
          port = {} unless port.is_a?(Hash)
          port_name = fetch(port, "name")
          port_number = fetch(port, "number")
          has_name = provided?(port_name) && !port_name.to_s.empty?
          has_number = provided?(port_number) && port_number != 0
          if has_name && has_number
            issues << issue(path, :invalid, "cannot set both port name & port number")
          elsif has_name
            issues.concat(invalid_messages(path + %w[service port name], port_name_messages(port_name.to_s)))
          elsif has_number
            unless port_number.is_a?(Integer) && port_number.between?(1, 65_535)
              issues << issue(path + %w[service port number], :invalid, "must be between 1 and 65535, inclusive")
            end
          else
            issues << issue(path, :required, "port name or number is required")
          end
        end
        issues
      end

      def ingress_class_errors(root, old = nil, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        required(spec, "controller", %w[spec], issues)
        parameters = fetch(spec, "parameters")
        %w[kind name].each { |field| required(parameters, field, %w[spec parameters], issues) } if parameters.is_a?(Hash)
        if operation == :update && old && fetch(spec, "controller") != value_at_path(old, %w[spec controller])
          issues << issue(%w[spec controller], :invalid, "field is immutable")
        end
        issues
      end

      def ip_address_errors(root, old, operation)
        path = %w[spec parentRef]
        parent = value_at_path(root, path)
        issues = []
        if parent.is_a?(Hash)
          group = fetch(parent, "group").to_s
          issues.concat(invalid_messages(path + ["group"], dns1123_subdomain_messages(group))) unless group.empty?
          %w[resource name namespace].each do |field|
            value = fetch(parent, field).to_s
            if value.empty?
              issues << issue(path + [field], :required, "") unless field == "namespace"
            else
              issues.concat(invalid_messages(path + [field], path_segment_name_messages(value)))
            end
          end
        else
          issues << issue(path, :required, "")
        end
        issues << issue(path, :invalid, "field is immutable") if operation == :update && old && parent != value_at_path(old, path)
        issues
      end
    end
  end
end
