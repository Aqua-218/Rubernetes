# frozen_string_literal: true

require_relative "../support/service_traffic"

module Rubernetes
  module Schema
    # Core v1 defaults applied before Service validation and allocation.
    module ServiceFields
      DEFAULT_AFFINITY_TIMEOUT = 10_800
      MAX_AFFINITY_TIMEOUT = 86_400

      module_function

      def default_spec(spec)
        spec["type"] = "ClusterIP" if spec["type"].to_s.empty?
        spec["sessionAffinity"] = "None" if spec["sessionAffinity"].to_s.empty?
        spec.delete("externalName") if spec["externalName"] == ""
        spec.delete("ports") if spec["ports"] == []
        case spec["sessionAffinity"]
        when "None"
          spec.delete("sessionAffinityConfig")
        when "ClientIP"
          config = spec["sessionAffinityConfig"]
          client = config.is_a?(Hash) ? config["clientIP"] : nil
          if (config.nil? || config.is_a?(Hash)) && (client.nil? || client.is_a?(Hash)) && client&.fetch("timeoutSeconds", nil).nil?
            spec["sessionAffinityConfig"] = {"clientIP" => {"timeoutSeconds" => DEFAULT_AFFINITY_TIMEOUT}}
          end
        end
      end

      def default_port(port)
        port["port"] = 0 if port["port"].nil?
        port["protocol"] = "TCP" if port["protocol"].to_s.empty?
        port["targetPort"] = port["port"] if default_target?(port["targetPort"])
        port.delete("name") if port["name"] == ""
      end

      def default_target?(target) = target.nil? || target == 0 || target == ""

      def default_traffic(spec)
        if spec["type"] == "ExternalName"
          spec.delete("internalTrafficPolicy")
        else
          spec["internalTrafficPolicy"] ||= "Cluster"
        end
        spec.delete("externalTrafficPolicy") if spec["externalTrafficPolicy"].to_s.empty?
        spec["externalTrafficPolicy"] ||= "Cluster" if Support::ServiceTraffic.external?(spec)
        spec["allocateLoadBalancerNodePorts"] = true if spec["type"] == "LoadBalancer" && spec["allocateLoadBalancerNodePorts"].nil?
      end
    end
  end
end
