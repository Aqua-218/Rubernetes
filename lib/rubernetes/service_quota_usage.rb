# frozen_string_literal: true

module Rubernetes
  # Kubernetes' Service quota evaluator counts requested allocations before
  # the registry has assigned NodePorts.
  module ServiceQuotaUsage
    module_function

    def usage(spec)
      type = field(spec, "type").to_s
      ports = Array(field(spec, "ports"))
      node_ports = case type
                   when "NodePort"
                     ports.length
                   when "LoadBalancer"
                     if field(spec, "allocateLoadBalancerNodePorts") == false
                       ports.count { |port| !field(port, "nodePort").to_i.zero? }
                     else
                       ports.length
                     end
                   else
                     0
                   end
      {"services.nodeports" => node_ports, "services.loadbalancers" => type == "LoadBalancer" ? 1 : 0}
    end

    def field(object, name) = object.fetch(name) { object[name.to_sym] }
    private_class_method :field
  end
end
