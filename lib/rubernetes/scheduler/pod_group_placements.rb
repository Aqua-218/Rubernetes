# frozen_string_literal: true

module Rubernetes
  module Scheduler
    module PodGroupPlacements
      Cycle = Data.define(:nodes, :pods, :namespace_labels, :volume_data, :workload_selectors, :pod_groups)
      Assignment = Data.define(:pod, :node, :context)

      private

      def topology_key(group)
        return unless @feature_gates["TopologyAwareWorkloadScheduling"] == true

        Array(group.dig("spec", "schedulingConstraints", "topology")).first&.fetch("key", nil)
      end

      def placement_nodes(group, cycle, scheduled)
        key = topology_key(group)
        return [cycle.nodes] unless key

        by_name = cycle.nodes.to_h { |node| [node.name, node] }
        domains = scheduled.map { |pod| by_name[pod.node_name]&.labels&.fetch(key, nil) }.uniq
        return [] if domains.include?(nil) || domains.length > 1

        labeled = cycle.nodes.select { |node| node.labels.key?(key) }
        placements = labeled.group_by { |node| node.labels.fetch(key) }
        domains.empty? ? placements.values : [placements.fetch(domains.first, [])]
      end

      def pod_group_plan(group, cycle, members, scheduled)
        min_count = group.dig("spec", "schedulingPolicy", "gang", "minCount").to_i
        plans = placement_nodes(group, cycle, scheduled).filter_map do |nodes|
          plan = simulate_placement(cycle, members, nodes)
          [nodes, plan] if !plan.empty? && plan.length + scheduled.length >= min_count
        end
        return if plans.empty?
        return plans.first.last if plans.one?

        best_topology_plan(cycle, plans, members, scheduled.length)
      end

      def best_topology_plan(cycle, plans, members, scheduled_count)
        # v1.36.2 combines the normalized PodGroupPodsCount score with the
        # NodeResourcesFit MostAllocated placement score, both weight 1.
        most_placed = plans.map { |_, plan| plan.length + scheduled_count }.max
        context = build_context(cycle.nodes, cycle.pods, cycle.namespace_labels, cycle.volume_data, cycle.workload_selectors, cycle.pod_groups)
        by_name = context.nodes.to_h { |node| [node.name, node] }
        ranked = plans.group_by do |nodes, plan|
          count_score = Scores::MAX_NODE_SCORE * (scheduled_count + plan.length) / most_placed
          requested = members.filter_map do |member|
            Support.non_zero_requests_for(member, skip_pod_level: true) if plan.key?(pod_lock_key(member))
          end
          count_score + placement_resource_score(nodes.map { |node| by_name.fetch(node.name) }, requested)
        end
        ranked.fetch(ranked.keys.max).sample(random: @random).last
      end

      def placement_resource_score(nodes, proposed_requests)
        capacity = Support.sum_maps(nodes.map(&:allocatable))
        used = Support.sum_maps(nodes.map(&:non_zero_requested) + proposed_requests)
        scores = Scores::LeastAllocated::DEFAULT_RESOURCES.filter_map do |resource|
          allocatable = capacity.fetch(resource, 0)
          next if allocatable.zero?

          (Scores::MAX_NODE_SCORE * [used.fetch(resource, 0), allocatable].min / allocatable).floor
        end
        scores.empty? ? 0 : scores.sum.div(scores.length)
      end

      def simulate_placement(cycle, members, nodes)
        available_names = nodes.to_set(&:name)
        placed = []
        members.each do |member|
          existing = cycle.pods.reject { |pod| placed.any? { |assignment| same_pod?(assignment.pod, pod) } }
          existing.concat(placed.map(&:pod))
          context = build_context(cycle.nodes, existing, cycle.namespace_labels, cycle.volume_data, cycle.workload_selectors, cycle.pod_groups)
          assignment = simulate_group_member(member, context, available_names)
          placed << assignment if assignment
        end
        placed.to_h { |assignment| [pod_lock_key(assignment.pod), assignment.node.name] }
      ensure
        placed&.reverse_each do |assignment|
          @dynamic_resources.discard_assumption(assignment.pod, assignment.node, assignment.context)
          @volume_binding.unreserve(assignment.pod, assignment.node, assignment.context)
        end
      end

      def simulate_group_member(pod, context, available_names)
        return unless run_pre_enqueue(pod, context, Trace.new) == true

        candidates = context.nodes.select { |node| available_names.include?(node.name) }
        feasible, = filter_nodes(pod, candidates, context, trace: nil, nominated: nominated_pods_index(context))
        return if feasible.empty?

        node = score_nodes(pod, feasible, context, nil).max_by(&:total).node
        unless @volume_binding.reserve(pod, node, context) == true
          @volume_binding.unreserve(pod, node, context)
          return
        end
        begin
          @dynamic_resources.reserve(pod, node, context)
          pod = @dynamic_resources.pod_with_node_allocatable_status(pod, node, context)
          placed = pod.with("spec" => pod.spec.merge("nodeName" => node.name))
          Assignment.new(pod: placed, node: node, context: context)
        rescue StandardError
          @dynamic_resources.discard_assumption(pod, node, context)
          @volume_binding.unreserve(pod, node, context)
          raise
        end
      end
    end
  end
end
