# frozen_string_literal: true

module Rubernetes
  module Support
    module ServiceTraffic
      module_function

      def type(spec) = spec["type"].to_s.empty? ? "ClusterIP" : spec["type"]
      def uses_node_ports?(spec) = %w[NodePort LoadBalancer].include?(type(spec))
      def health_check?(spec) = type(spec) == "LoadBalancer" && spec["externalTrafficPolicy"] == "Local"
      def external?(spec) = uses_node_ports?(spec) || (type(spec) == "ClusterIP" && !Array(spec["externalIPs"]).empty?)

      # Service strategy drops carried values on a type switch. Ports can
      # move, change protocol or disappear as long as no new number was added.
      def drop_node_ports?(old, spec)
        uses_node_ports?(old) && !uses_node_ports?(spec) && node_ports(spec).subset?(node_ports(old))
      end

      def drop_health_port?(old, spec)
        health_check?(old) && !health_check?(spec) && spec["healthCheckNodePort"] == old["healthCheckNodePort"]
      end

      def drop_external_policy?(old, spec)
        external?(old) && !external?(spec) && spec["externalTrafficPolicy"] == old["externalTrafficPolicy"]
      end

      def node_ports(spec)
        Array(spec["ports"]).filter_map do |entry|
          port = entry["nodePort"] if entry.is_a?(Hash)
          port if port.is_a?(Integer) && !port.zero?
        end.to_set
      end
    end
  end
end
