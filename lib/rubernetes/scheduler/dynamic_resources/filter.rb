# frozen_string_literal: true

module Rubernetes
  module Scheduler
    class DynamicResources
      def filter(pod, node, state, context)
        node_extended, mappings, rejection = filter_extended(state, pod, node)
        return rejection if rejection
        return true if node_extended.nil? && state.num_user.zero?

        unavailable = []
        state.claims.each_with_index do |claim, index|
          selector = state.informations[index].available_on_nodes
          if selector && !Allocator::NodeSelector.match?(selector, node.to_h)
            unavailable << index
            next
          end
          next unless allocated?(claim)
          next unless @features.device_binding_and_status

          begin
            ready = claim_ready_for_binding?(claim)
            unavailable << index if !ready && claim_timeout?(claim)
          rescue ClaimError
            unavailable << index
          end
        end

        allocations, by_claim = allocate_for_node(state, node, node_extended)

        statuses = if @node_allocatable
                     results = state.claims.map { |claim| by_claim[ref(claim)] || claim.dig("status", "allocation") }
                     NodeAllocatable.claim_statuses(pod, state.claims, results, state.allocator&.dig(:slices) || data(context, "resourceSlices"))
                   end
        if statuses && !statuses.empty?
          rejection = NodeAllocatable.rejection(pod, node, statuses)
          return rejection if rejection
        end

        state.mutex.synchronize do
          unless unavailable.empty?
            state.unavailable.merge(unavailable)
            return Filters::Helpers.reject("resourceclaim not available on the node", code: "UnschedulableAndUnresolvable")
          end
          if state.allocator || (statuses && !statuses.empty?)
            state.node_allocations[node.name] = NodeAllocation.new(results: allocations, extended_claim: node_extended,
                                                                   mappings: mappings, node_allocatable_status: statuses)
          end
        end
        true
      rescue Allocator::FailedOnNode => error
        Filters::Helpers.reject(error.message, code: "UnschedulableAndUnresolvable")
      rescue Allocator::Error, ClaimError, Schema::Quantity::ParseError => error
        raise FilterError.new("running #{NAME.inspect} filter plugin: #{error.message}", plugin: NAME, phase: :filter)
      end

      private

      def allocate_for_node(state, node, node_extended)
        return [nil, {}] unless state.allocator

        claims_to_allocate = []
        pending = []
        by_claim = {}
        state.claims.each_with_index do |claim, index|
          next if allocated?(claim)

          if extended_index?(state, index)
            # Nodes advertising the scalar resource need no extended claim.
            next if node_extended.nil?

            claim = node_extended
          end
          if (allocation = state.informations[index].allocation)
            pending << allocation
            by_claim[ref(claim)] = allocation if @node_allocatable
          else
            claims_to_allocate << claim
          end
        end
        result = Allocator.allocate(node: node.to_h, claims: claims_to_allocate, slices: state.allocator[:slices],
                                    classes: state.allocator[:classes], allocated_state: state.allocator[:allocated_state],
                                    features: @features, cel: @cel)
        raise Allocator::FailedOnNode, "cannot allocate all claims" if result.nil? || result.length != claims_to_allocate.length

        claims_to_allocate.zip(result).each { |claim, allocation| by_claim[ref(claim)] = allocation } if @node_allocatable
        [result + pending, by_claim]
      end
    end
  end
end
