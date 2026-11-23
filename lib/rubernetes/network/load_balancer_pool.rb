# frozen_string_literal: true

require "ipaddr"
require "socket"

module Rubernetes
  module Network
    # CIDRs routed to the cluster's Service proxy, in allocation order.
    class LoadBalancerPool
      CLASS_NAME = "rubernetes.io/routed"
      ADDRESS_FAMILIES = {Socket::AF_INET => "IPv4", Socket::AF_INET6 => "IPv6"}.freeze
      NON_UNICAST = %w[0.0.0.0/8 127.0.0.0/8 169.254.0.0/16 224.0.0.0/3 ::/127 ::ffff:0:0/96 fe80::/10 ff00::/8].map do |prefix|
        IPAddr.new(prefix)
      end.freeze

      attr_reader :cidrs

      def initialize(cidrs)
        unless cidrs.is_a?(Array) && !cidrs.empty? && cidrs.all? { |cidr| cidr.is_a?(String) && cidr.match?(%r{/\d+\z}) }
          raise ArgumentError, "load_balancer_pool must contain at least one CIDR"
        end

        @networks = cidrs.map do |cidr|
          network = IPAddr.new(cidr)
          if IPAddr.new(cidr.split("/", 2).first) != network || NON_UNICAST.any? { |reserved| overlap?(network, reserved) }
            raise ArgumentError, "load_balancer_pool CIDR #{cidr} must be a canonical unicast network"
          end

          network.freeze
        end.freeze
        raise ArgumentError, "load_balancer_pool CIDRs must be disjoint" if @networks.combination(2).any? { |left, right| overlap?(left, right) }

        @cidrs = @networks.map { |network| "#{network}/#{network.prefix}" }.freeze
      rescue IPAddr::Error => error
        raise ArgumentError, "invalid load_balancer_pool CIDR: #{error.message}"
      end

      def families = @networks.map { |network| ADDRESS_FAMILIES.fetch(network.family) }.uniq

      def conflicts_with?(cidr)
        other = IPAddr.new(cidr)
        @networks.any? { |network| overlap?(network, other) }
      end

      def usable?(ip)
        @networks.any? do |network|
          network.family == ip.family && usable_range(network).cover?(ip.to_i)
        end
      end

      def next_address(family, used)
        address_family = ADDRESS_FAMILIES.key(family)
        return unless address_family

        taken = used.select { |ip| ip.family == address_family }.to_set(&:to_i)
        @networks.each do |network|
          next unless network.family == address_family

          available = usable_range(network).find { |value| !taken.include?(value) }
          return IPAddr.new(available, address_family) if available
        end
        nil
      end

      private

      def overlap?(left, right)
        left.family == right.family && (left.include?(right) || right.include?(left))
      end

      def usable_range(network)
        range = network.to_range
        first = range.begin.to_i
        last = range.end.to_i
        return (first + 1)..(last - 1) if network.ipv4? && network.prefix < 31

        first..last
      end
    end
  end
end
