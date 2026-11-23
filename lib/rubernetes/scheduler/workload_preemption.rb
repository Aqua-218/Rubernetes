# frozen_string_literal: true

module Rubernetes
  module Scheduler
    module WorkloadPreemption
      Victim = Data.define(:pods, :priority, :atomic)

      private

      def preempt_pod_group(pod, group, cycle, members, scheduled)
        return unless @preemption && @feature_gates["WorkloadAwarePreemption"] == true
        return if members.any? { |member| member.preemption_policy == "Never" }

        if members.any? { |member| preempting?(member) }
          park_group_preemption(pod, members, "waiting for the preemption for this pod group to be finished", gated: true)
        else
          select_group_victims(group, cycle, members, scheduled)&.then do |victims, plan|
            priority = group.dig("spec", "priority").to_i
            lower = group_lower_nominations(cycle, plan, members, priority)
            waiting = park_group_preemption(pod, members, "pod group is waiting for preemption to complete", victims: victims)
            evict_preempted_pods!(victims, lower, members)
            waiting
          end
        end
      end

      def select_group_victims(group, cycle, members, scheduled)
        candidates = group_victim_units(cycle, group, scheduled)
        return if candidates.empty?

        evicted = candidates.dup
        plan = plan_with_victims_removed(group, cycle, members, scheduled, evicted)
        return unless plan

        budgets = Array(cycle.workload_selectors&.fetch("podDisruptionBudgets", nil))
        limits = budgets.map { |budget| budget.dig("status", "disruptionsAllowed").to_i }
        ordered = candidates.sort_by { |unit| group_victim_importance(unit) }
        violating, allowed = ordered.partition { |unit| budget_violated?(unit, budgets, limits) }
        (violating + allowed).each do |unit|
          remaining = evicted - [unit]
          trial = plan_with_victims_removed(group, cycle, members, scheduled, remaining)
          next unless trial

          evicted = remaining
          plan = trial
        end
        return if evicted.empty?

        [evicted.sort_by { |unit| group_victim_importance(unit) }.flat_map(&:pods), plan]
      end

      def group_victim_units(cycle, group, scheduled)
        priority = group.dig("spec", "priority").to_i
        active_nodes = cycle.nodes.to_set(&:name)
        units = cycle.pods.select do |pod|
          active_nodes.include?(pod.node_name) && scheduled.none? { |peer| same_pod?(peer, pod) }
        end.group_by do |pod|
          pod_group = pod.scheduling_group && cycle.pod_groups["#{pod.namespace}/#{pod.scheduling_group}"]
          pod_group&.dig("spec", "disruptionMode") == "PodGroup" ? [pod.namespace, pod.scheduling_group] : pod
        end
        units.filter_map do |key, pods|
          atomic = key.is_a?(Array)
          victim_priority = atomic ? cycle.pod_groups.fetch(key.join("/")).dig("spec", "priority").to_i : key.priority
          Victim.new(pods: pods, priority: victim_priority, atomic: atomic) if victim_priority < priority
        end
      end

      def plan_with_victims_removed(group, cycle, members, scheduled, units)
        victims = units.flat_map(&:pods).to_set { |pod| pod_lock_key(pod) }
        remaining = cycle.pods.reject { |pod| victims.include?(pod_lock_key(pod)) }
        pod_group_plan(group, cycle.with(pods: remaining), members, scheduled)
      end

      def group_victim_importance(unit)
        oldest = unit.pods.filter_map { |pod| pod.status["startTime"] || pod.metadata["creationTimestamp"] }.min
        [-unit.priority, unit.atomic ? 0 : 1, -unit.pods.length, oldest || "", unit.pods.first.name]
      end

      def budget_violated?(unit, budgets, limits)
        unit.pods.any? do |pod|
          budgets.each_with_index.any? do |budget, index|
            selector = budget.dig("spec", "selector")
            next false if pod.namespace != budget.dig("metadata", "namespace") || selector.nil? || selector.empty?
            next false if budget.dig("status", "disruptedPods", pod.name) || !Filters::Helpers.selector_matches?(pod.labels, selector)

            limits[index] -= 1
            limits[index].negative?
          end
        end
      end

      def group_lower_nominations(cycle, plan, members, priority)
        nodes = plan.values.to_set
        cycle.pods.select do |candidate|
          candidate.node_name.empty? && nodes.include?(nominated_node_for(candidate)) && candidate.priority < priority &&
            members.none? { |member| same_pod?(candidate, member) }
        end
      end

      def park_group_preemption(pod, members, reason, victims: [], gated: false)
        members.each do |member|
          queue.enqueue_unschedulable(member, reason: reason, gated: gated, plugins: ["DefaultPreemption"])
        end
        ScheduleResult.new(status: :unschedulable, pod: pod, trace: Trace.new, reason: reason, victims: victims, gated: gated)
      end
    end
  end
end
