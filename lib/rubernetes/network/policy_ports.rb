# frozen_string_literal: true

module Rubernetes
  module Network
    # NetworkPolicy ports match the destination. In particular, named egress
    # ports must stay paired with the Pod whose declaration resolved the name.
    module PolicyPorts
      private

      def normalize_port(port)
        hash = policy_port_object(port)
        raise PolicyError, "network policy port must be an object" unless hash.is_a?(Hash)

        protocol = normalize_protocol(Support.fetch(hash, "protocol", default: nil) || "TCP")
        value = Support.fetch(hash, "port", default: nil)
        end_port = Support.fetch(hash, "endPort", "end_port", default: nil)
        raise PolicyError, "endPort requires a numeric port" if end_port && !numeric_port?(value)

        if numeric_port?(value)
          value = Support.integer(value, "network policy port", min: 1, max: 65_535)
        elsif !value.nil?
          value = Support.string(value, "named network policy port")
        end
        finish = end_port.nil? ? nil : Support.integer(end_port, "network policy endPort", min: 1, max: 65_535)
        raise PolicyError, "endPort must be greater than or equal to port" if finish && finish < value

        {"protocol" => protocol, "port" => value, "end_port" => finish}.freeze
      end

      def normalize_pod_ports(value)
        entries = value.is_a?(Array) ? value : pod_port_entries(policy_port_object(value) || {})
        entries.each_with_object({}) do |entry, result|
          hash = policy_port_object(entry) || {}
          name = Support.fetch(hash, "name", default: nil)
          number = Support.fetch(hash, "port", "containerPort", "targetPort", default: nil)
          next if name.to_s.empty? || number.nil?

          protocol = normalize_protocol(Support.fetch(hash, "protocol", default: nil) || "TCP")
          (result[protocol] ||= {})[String(name)] = Support.integer(number, "pod port", min: 1, max: 65_535)
        end
      rescue ArgumentError, TypeError
        {}
      end

      def pod_port_entries(ports)
        ports.flat_map do |key, value|
          if value.is_a?(Hash)
            value.map { |name, number| {"name" => name, "port" => number, "protocol" => key} }
          else
            [{"name" => key, "port" => value}]
          end
        end
      end

      def port_match?(ports, destination, protocol, port)
        return true if ports.empty?

        destination_ports = normalize_pod_ports(destination.fetch("ports", {})).fetch(protocol, {})
        actual_port = numeric_port?(port) ? Integer(port) : destination_ports[port.to_s]
        ports.any? do |rule|
          next false unless rule.fetch("protocol") == protocol

          required = rule.fetch("port")
          next true if required.nil?
          next false if actual_port.nil?

          if required.is_a?(Integer)
            actual_port.between?(required, rule.fetch("end_port") || required)
          else
            destination_ports[required] == actual_port
          end
        end
      end

      def compile_peer_ports(ports, direction:, target:, peers:, pods:, family:)
        return peers.map { |peer| [peer, {"protocol" => nil, "port" => nil, "end_port" => nil}] } if ports.empty?

        named_peers = nil
        ports.flat_map do |port|
          name = port.fetch("port")
          protocol = port.fetch("protocol")
          if name.nil? || name.is_a?(Integer)
            peers.map { |peer| [peer, port] }
          elsif direction == "ingress"
            number = target.fetch("ports").dig(protocol, name)
            number ? peers.map { |peer| [peer, port.merge("port" => number)] } : []
          else
            named_peers ||= named_egress_peers(peers, pods, family)
            named_peers.filter_map do |peer|
              number = peer.fetch("ports").dig(protocol, name)
              [peer, port.merge("port" => number)] if number
            end
          end
        end
      end

      def named_egress_peers(peers, pods, family)
        pod_peers = peers.select { |peer| peer.fetch("kind") == "pod" }
        networks = peers.filter_map { |peer| IPAddr.new(peer.fetch("cidr")) if peer.fetch("kind") == "cidr" }
        all = peers.any? { |peer| peer.fetch("kind") == "all" }
        return pod_peers unless all || networks.any?

        pod_peers + pods.flat_map do |pod|
          parse_pod_peers(pod).select do |peer|
            peer.fetch("family") == family && (all || networks.any? { |network| network.include?(peer.fetch("ip")) })
          end
        end
      end
    end
  end
end
