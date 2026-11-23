# frozen_string_literal: true

require_relative "../schema/quantity"
require_relative "support"

module Rubernetes
  module Controller
    # Kubernetes v1.36.2 trafficdist and topologycache calculate hints for the
    # desired EndpointSlices of one Service and one address family at a time.
    class EndpointSliceHints
      DISTRIBUTIONS = %w[PreferClose PreferSameZone PreferSameNode].freeze
      ZONE = "topology.kubernetes.io/zone"
      EXCLUDED_NODE_LABELS = %w[node-role.kubernetes.io/control-plane node-role.kubernetes.io/master].freeze
      OVERLOAD_THRESHOLD = 0.2
      Allocation = Data.define(:desired, :maximum)

      def initialize(auto:, distribution:, nodes:)
        @auto = auto
        @distribution = distribution if DISTRIBUTIONS.include?(distribution)
        @cpu_ratios = zone_cpu_ratios(nodes) if auto
      end

      def assign(pairs)
        if @auto
          assign_auto(pairs)
        elsif @distribution
          assign_explicit(pairs)
        end
      end

      private

      def assign_explicit(pairs)
        pairs.each do |candidate, existing|
          previous = matching_endpoints(candidate, existing)
          candidate.fetch("endpoints").each_with_index do |endpoint, index|
            hints = if ready?(endpoint)
                      local_hints(endpoint)
                    else
                      Support.value(previous&.[](index), "hints", nil)
                    end
            endpoint["hints"] = Support.deep_copy(hints) if hints
          end
        end
      end

      def local_hints(endpoint)
        hints = {}
        hints["forZones"] = [{"name" => endpoint["zone"]}] if endpoint["zone"]
        hints["forNodes"] = [{"name" => endpoint["nodeName"]}] if @distribution == "PreferSameNode" && endpoint["nodeName"]
        hints unless hints.empty?
      end

      def assign_auto(pairs)
        ready_endpoints = pairs.flat_map { |candidate, _| candidate.fetch("endpoints").select { |endpoint| ready?(endpoint) } }
        return if ready_endpoints.any? { |endpoint| endpoint["zone"].to_s.empty? }

        allocations = zone_allocations(ready_endpoints.length)
        return unless allocations

        counts = Hash.new(0)
        assignable = pairs.flat_map do |candidate, existing|
          previous = matching_endpoints(candidate, existing)
          existing_counts = retained_auto_counts(previous, counts, allocations)
          if existing_counts
            preserve_hints(candidate.fetch("endpoints"), previous)
            existing_counts.each { |zone, count| counts[zone] += count }
            []
          else
            candidate.fetch("endpoints").select { |endpoint| ready?(endpoint) }
          end
        end
        assignable.each do |endpoint|
          zone = endpoint.fetch("zone")
          counts[zone] += 1
          set_zone_hint(endpoint, zone)
        end
        redistribute(assignable, allocations, counts)
      end

      def ready?(endpoint)
        Support.value(Support.value(endpoint, "conditions", {}), "ready", nil) == true
      end

      def matching_endpoints(candidate, existing)
        return unless existing && Support.labels(existing) == Support.labels(candidate)
        return unless Array(Support.value(existing, "ports", [])) == candidate.fetch("ports")

        endpoints = Array(Support.value(existing, "endpoints", []))
        without_hints = endpoints.map { |endpoint| endpoint.reject { |key, _| key.to_s == "hints" } }
        endpoints if without_hints == candidate.fetch("endpoints")
      end

      def preserve_hints(endpoints, previous)
        endpoints.zip(previous).each do |endpoint, old_endpoint|
          hints = Support.value(old_endpoint, "hints", nil)
          endpoint["hints"] = Support.deep_copy(hints) if hints
        end
      end

      def retained_auto_counts(endpoints, allocated, allocations)
        return nil unless endpoints

        counts = Hash.new(0)
        endpoints.each do |endpoint|
          next unless ready?(endpoint)

          hints = Support.value(endpoint, "hints", {})
          zones = Array(Support.value(hints, "forZones", []))
          return nil if zones.empty?

          zones.each do |hint|
            zone = Support.value(hint, "name", nil)
            allocation = allocations[zone]
            return nil unless allocation

            counts[zone] += 1
            return nil if counts[zone] + allocated[zone] > allocation.maximum
          end
        end
        counts
      end

      def zone_cpu_ratios(nodes)
        capacity = Hash.new(0)
        Array(nodes).each do |node|
          labels = Support.labels(node)
          next if EXCLUDED_NODE_LABELS.any? { |label| labels.key?(label) }
          next unless Support.value(Support.condition(node, "Ready"), "status", "") == "True"

          zone = labels[ZONE]
          cpu = node_cpu(node)
          return nil if zone.to_s.empty? || !cpu.positive?

          capacity[zone] += cpu
        end
        return if capacity.length < 2

        total_millicores = (capacity.values.sum * 1000).ceil
        capacity.transform_values { |cpu| (cpu * 1000).ceil.fdiv(total_millicores) }
      end

      def node_cpu(node)
        allocatable = Support.value(Support.status(node), "allocatable", {})
        Schema::Quantity.from_json(Support.value(allocatable, "cpu", "0")).value
      rescue Schema::Quantity::ParseError
        0
      end

      def zone_allocations(count)
        return unless @cpu_ratios && count >= @cpu_ratios.length

        targets = @cpu_ratios.transform_values { |ratio| ratio * count }
        minimum = targets.transform_values { |target| (target * (1.0 / (1.0 + OVERLOAD_THRESHOLD))).ceil }
        remaining = count - minimum.values.sum
        return if remaining.negative?

        targets.to_h do |zone, desired|
          floor = minimum.fetch(zone)
          [zone, Allocation.new(desired: [desired, floor].max, maximum: floor + remaining)]
        end
      end

      def redistribute(endpoints, allocations, counts)
        surplus = allocations.to_h { |zone, allocation| [zone, counts[zone] - allocation.desired] }
        deficit = allocations.to_h { |zone, allocation| [zone, allocation.desired - counts[zone]] }
        giving, receiving = whole_endpoint_transfers(surplus, deficit)
        receiving_zones = receiving.keys.sort
        endpoints.each do |endpoint|
          zone = endpoint.fetch("zone")
          next if giving[zone].zero?

          destination = receiving_zones.first
          break unless destination

          set_zone_hint(endpoint, destination)
          giving[zone] -= 1
          receiving[destination] -= 1
          receiving_zones.shift if receiving[destination].zero?
        end
      end

      def whole_endpoint_transfers(surplus, deficit)
        giving = Hash.new(0)
        receiving = Hash.new(0)
        loop do
          from, donate = surplus.max_by { |zone, amount| [amount, zone] }
          to, accept = deficit.max_by { |zone, amount| [amount, zone] }
          break if donate < 0.5 || accept < 0.5 || (donate < 1.0 && accept < 1.0)

          giving[from] += 1
          receiving[to] += 1
          surplus[from] -= 1
          deficit[to] -= 1
        end
        [giving, receiving]
      end

      def set_zone_hint(endpoint, zone)
        endpoint["hints"] = {"forZones" => [{"name" => zone}]}
      end
    end
  end
end
