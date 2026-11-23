# frozen_string_literal: true

require "ipaddr"
require_relative "../network/ipam"

module Rubernetes
  module Bootstrap
    # kube-controller-manager NodeIPAM is opt-in. A local provisioner already
    # owns the nodes' bridge subnets and may supply those exact assignments.
    class NodeIPAMSettings
      KEYS = %w[allocate_node_cidrs cluster_cidrs node_cidr_mask_sizes assignments].freeze

      attr_reader :enabled, :controller_options

      def initialize(section)
        raise ArgumentError, "must be a mapping" unless section.is_a?(Hash)

        unknown = section.keys - KEYS
        raise ArgumentError, "unknown settings: #{unknown.join(", ")}" unless unknown.empty?

        @enabled = section.fetch("allocate_node_cidrs", false)
        raise ArgumentError, "allocate_node_cidrs must be true or false" unless [true, false].include?(@enabled)

        @controller_options = @enabled ? enabled_options(section) : {}
      end

      private

      def enabled_options(section)
        if section.key?("assignments")
          if section.key?("cluster_cidrs") || section.key?("node_cidr_mask_sizes")
            raise ArgumentError, "assignments and cluster CIDR allocation are mutually exclusive"
          end

          @assignments = validate_assignments(section["assignments"])
          return {cidr_allocator: method(:allocate_assigned_cidrs)}
        end

        pools = networks(section["cluster_cidrs"], "cluster_cidrs")
        masks = section.fetch("node_cidr_mask_sizes") do
          pools.map { |pool| Network::IPAM::DEFAULT_NODE_PREFIX.fetch(pool.ipv4? ? "ipv4" : "ipv6") }
        end
        unless masks.is_a?(Array) && masks.length == pools.length &&
               pools.zip(masks).all? { |pool, mask| mask.is_a?(Integer) && mask.between?(pool.prefix, pool.ipv4? ? 32 : 128) }
          raise ArgumentError, "node_cidr_mask_sizes must contain one valid prefix in cluster_cidrs order"
        end

        {cluster_cidrs: pools.map { |pool| cidr(pool) }, node_cidr_mask_sizes: masks.dup}
      end

      def validate_assignments(assignments)
        unless assignments.is_a?(Hash) && !assignments.empty? &&
               assignments.keys.all? { |name| name.is_a?(String) && !name.empty? }
          raise ArgumentError, "assignments must map node names to Pod CIDRs"
        end

        ranges = assignments.transform_values { |values| networks(values, "node assignment") }
        by_family = ranges.values.flatten.group_by(&:family)
        if by_family.any? { |_family, networks| networks.sort_by(&:to_i).each_cons(2).any? { |left, right| overlap?(left, right) } }
          raise ArgumentError, "node assignments overlap"
        end

        ranges
      end

      def networks(values, field)
        raise ArgumentError, "#{field} must contain one or two CIDRs" unless values.is_a?(Array) && values.size.between?(1, 2)

        ranges = values.map do |value|
          raise ArgumentError, "#{field} requires CIDR prefixes" unless value.is_a?(String) && %r{\A[^/]+/[0-9]+\z}.match?(value)

          network = IPAddr.new(value)
          raise ArgumentError, "#{field} contains host bits in #{value}" unless IPAddr.new(value.split("/", 2).first) == network

          network
        end
        raise ArgumentError, "#{field} must contain distinct address families" if ranges.map(&:family).uniq.size != ranges.size

        ranges
      end

      def allocate_assigned_cidrs(node, nodes)
        name = Controller::Support.name(node)
        ranges = @assignments[name]
        return [] unless ranges

        occupied = nodes.reject { |entry| Controller::Support.name(entry) == name }.flat_map do |entry|
          spec = Controller::Support.spec(entry)
          values = Array(Controller::Support.value(spec, "podCIDRs", nil))
          values = Array(Controller::Support.value(spec, "podCIDR", nil)) if values.empty?
          values.filter_map { |value| IPAddr.new(value) unless value.to_s.empty? }
        end
        return [] if ranges.product(occupied).any? { |left, right| overlap?(left, right) }

        ranges.map { |range| cidr(range) }
      end

      def overlap?(left, right)
        left.family == right.family && (left.include?(right) || right.include?(left))
      end

      def cidr(network) = "#{network}/#{network.prefix}"
    end
  end
end
