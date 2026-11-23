# frozen_string_literal: true

require_relative "../schema/kubernetes_validator/formats"

module Rubernetes
  module Manifest
    module Expose
      SERVICE_TYPES = {cluster_ip: "ClusterIP", node_port: "NodePort", load_balancer: "LoadBalancer"}.freeze
      TRAFFIC_DISTRIBUTIONS = {same_zone: "PreferSameZone", same_node: "PreferSameNode"}.freeze

      # A standard Service connected to a workload object returned by the DSL.
      # Named targetPorts keep working when the container's port number changes.
      def expose(workload, ports:, name: nil, type: "ClusterIP", prefer: nil, load_balancer_class: nil, allocate_node_ports: nil)
        raise Error, "expose expects a workload declared in this manifest" unless result.any? { |resource| resource.equal?(workload) }

        kind = workload.fetch("kind")
        pod, selector = service_target(workload)
        namespace, workload_name = workload.fetch("metadata").values_at("namespace", "name")
        raise Error, "#{kind}/#{workload_name} needs Pod labels for a Service selector" if selector.to_h.empty?
        unless selector.all? { |key, value| pod.dig("metadata", "labels", key) == value }
          raise Error, "#{kind}/#{workload_name} selector does not match its Pod labels"
        end

        type = SERVICE_TYPES.fetch(type, type)
        raise Error, "Service type must be ClusterIP, NodePort or LoadBalancer" unless SERVICE_TYPES.value?(type)
        raise Error, "expose needs a map of named container ports to Service ports" unless ports.is_a?(Hash) && !ports.empty?

        ports_spec = exposed_ports(pod.fetch("spec", {}), ports, "#{kind}/#{workload_name}")
        service_spec = {selector: selector, ports: ports_spec, type: type}
        service_spec.merge!(load_balancer_options(type, load_balancer_class, allocate_node_ports))
        unless prefer.nil?
          service_spec[:traffic_distribution] = TRAFFIC_DISTRIBUTIONS.fetch(prefer) do
            raise Error, "expose prefer: must be :same_zone or :same_node (got #{prefer.inspect})"
          end
        end
        resource(api_version: "v1", kind: "Service", name: name || workload_name, namespace: namespace) do
          spec service_spec
        end
      end

      private

      def load_balancer_options(type, class_name, allocate_node_ports)
        return {} if class_name.nil? && allocate_node_ports.nil?
        raise Error, "load_balancer_class: and allocate_node_ports: require a LoadBalancer Service" unless type == "LoadBalancer"

        if !class_name.nil? && !(class_name.is_a?(String) && Rubernetes::Schema::KubernetesValidator.qualified_name_messages(class_name).empty?)
          raise Error, "load_balancer_class: must be a Kubernetes qualified name"
        end
        raise Error, "allocate_node_ports: must be true or false" unless [nil, true, false].include?(allocate_node_ports)

        {load_balancer_class: class_name, allocate_load_balancer_node_ports: allocate_node_ports}.compact
      end

      def service_target(workload)
        case workload.values_at("apiVersion", "kind")
        in ["v1", "Pod"]
          [workload, workload.dig("metadata", "labels")]
        in ["v1", "ReplicationController"]
          template = workload.dig("spec", "template") || {}
          selector = workload.dig("spec", "selector")
          [template, selector.to_h.empty? ? template.dig("metadata", "labels") : selector]
        in ["apps/v1", "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet"]
          selector = workload.dig("spec", "selector") || {}
          [workload.dig("spec", "template") || {}, service_selector(selector, workload.fetch("kind"))]
        else
          raise Error, "expose expects a Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet or ReplicationController"
        end
      end

      def service_selector(selector, kind)
        labels = selector["matchLabels"].to_h.dup
        expressions = Array(selector["matchExpressions"])
        if labels.value?(nil) || expressions.any? { |term| !term.is_a?(Hash) || Array(term["values"]).include?(nil) }
          raise Error, "#{kind} selector cannot contain null label values or expressions"
        end

        issue = Rubernetes::Schema::KubernetesValidator.label_selector_errors(selector, %w[spec selector]).first
        raise Error, "#{kind} has an invalid selector: #{issue.message}" if issue

        expressions.group_by { |term| term.fetch("key") }.each do |key, terms|
          values = service_label_values(labels[key], terms)
          raise Error, "Service selectors cannot express #{kind} matchExpressions for #{key.inspect} as a single label value" unless values&.one?

          labels[key] = values.first
        end
        labels
      end

      # A Service requires equality on each key. An In requirement or a
      # matchLabel supplies finite candidates; other terms can narrow them.
      def service_label_values(label, terms)
        allowed = [label] unless label.nil?
        excluded = []
        terms.each do |term|
          case term.fetch("operator")
          when "In"
            values = term.fetch("values")
            allowed = allowed ? allowed & values : values.uniq
          when "NotIn" then excluded.concat(term.fetch("values"))
          when "DoesNotExist" then return []
          end
        end
        allowed - excluded if allowed
      end

      def exposed_ports(pod_spec, mappings, target)
        declared = Workload.running_containers(pod_spec).flat_map { |container| Array(container["ports"]) }
        named = declared.reject { |port| port["name"].to_s.empty? }.group_by { |port| port["name"].to_s }
        ports = mappings.map do |key, number|
          name = key.to_s
          matches = named.fetch(name, [])
          if matches.empty?
            list = named.empty? ? "(none)" : named.keys.sort.join(", ")
            raise Error, "#{target} has no port named #{name.inspect}. Declared ports: #{list}"
          end
          raise Error, "#{target} declares port #{name.inspect} more than once" unless matches.one?
          raise Error, "Service port for #{name.inspect} must be an integer from 1 to 65535" unless number.is_a?(Integer) && number.between?(1, 65_535)

          errors = Rubernetes::Schema::KubernetesValidator.port_name_messages(name)
          raise Error, "#{target} port name #{name.inspect} #{errors.join(", ")}" unless errors.empty?

          protocol = matches.first.fetch("protocol", "TCP").to_s
          raise Error, "#{target} port #{name.inspect} has unsupported protocol #{protocol.inspect}" unless %w[TCP UDP SCTP].include?(protocol)

          {"name" => name, "port" => number, "targetPort" => name, "protocol" => protocol}
        end
        if ports.uniq { |port| port["name"] }.size != ports.size || ports.uniq { |port| port.values_at("port", "protocol") }.size != ports.size
          raise Error, "#{target} needs unique Service port names and port/protocol pairs"
        end

        ports
      end
    end
  end
end
