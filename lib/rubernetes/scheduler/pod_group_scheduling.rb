# frozen_string_literal: true

require_relative "pod_group_placements"
require_relative "workload_preemption"

module Rubernetes
  module Scheduler
    module PodGroupScheduling
      include PodGroupPlacements
      include WorkloadPreemption

      def gang_scheduled?(pod, pod_groups)
        group_name = pod.scheduling_group
        return false if group_name.nil? || pod_groups.nil?

        group = pod_groups["#{pod.namespace}/#{group_name}"]
        return false unless group

        topology_key(group) || @feature_gates["WorkloadAwarePreemption"] == true ||
          (@feature_gates["GangScheduling"] == true && !group.dig("spec", "schedulingPolicy", "gang").nil?)
      end

      # scheduleOnePodGroup: the Pod's whole gang is scheduled in one cycle.
      # Every member is reserved in turn against the nodes as the earlier
      # members filled them; all bind when all fit, none otherwise
      # (scheduler_podgroup_schedule_attempts_total{profile,result}).
      def schedule_pod_group(pod, nodes:, pods: nil, namespace_labels: nil, volume_data: nil, workload_selectors: nil, pod_groups: nil)
        started = monotonic
        group_name = pod.scheduling_group
        profile = pod.scheduler_name
        nodes = normalize_nodes(nodes)
        existing = normalize_pods(pods, nodes)
        cycle = Cycle.new(nodes: nodes, pods: existing, namespace_labels: namespace_labels, volume_data: volume_data,
                          workload_selectors: workload_selectors, pod_groups: pod_groups)
        group = pod_groups.fetch("#{pod.namespace}/#{group_name}")
        members, scheduled = group_members(pod, existing)
        algorithm_started = monotonic
        assumed, failure, already_parked = evaluate_pod_group(pod, group, cycle, members, scheduled)
        @metrics.pod_group_algorithm(monotonic - algorithm_started)
        outcome = if failure.nil? then "scheduled"
                  elsif failure.error then "error"
                  else "unschedulable"
                  end
        topology_node_count = nodes.length if topology_key(group)
        result = already_parked ? failure : finish_pod_group(members, existing, assumed, failure, topology_node_count: topology_node_count)
        @metrics.pod_group_attempt(profile, outcome, monotonic - started)
        note_pod_group_condition(pod.namespace, group_name, outcome, failure)
        result
      rescue StandardError => error
        members&.each { |member| requeue_after_failure(member, error) }
        raise
      ensure
        members&.each { |member| queue.done(member) }
      end

      private

      def group_members(pod, existing)
        peers = existing.select { |candidate| candidate.namespace == pod.namespace && candidate.scheduling_group == pod.scheduling_group }
        pending, scheduled = peers.partition { |candidate| candidate.node_name.empty? }
        members = [pod] + pending.select { |candidate| !same_pod?(candidate, pod) && queue.pop_specific(candidate) }
        members.sort_by! { |member| [-member.priority, -(queue.seconds_since_first_attempt(member) || 0.0)] }
        [members, scheduled]
      end

      def evaluate_pod_group(pod, group, cycle, members, scheduled)
        plan = nil
        if topology_key(group) || @feature_gates["WorkloadAwarePreemption"] == true
          plan = pod_group_plan(group, cycle, members, scheduled)
          unless plan
            preemption = preempt_pod_group(pod, group, cycle, members, scheduled)
            return [[], preemption, true] if preemption

            context = build_context(cycle.nodes, cycle.pods, cycle.namespace_labels, cycle.volume_data, cycle.workload_selectors, cycle.pod_groups)
            @dynamic_resources.unreserve_idle_group_claim(pod, context)
            reason = "no feasible placement for pod group"
            return [[], ScheduleResult.new(status: :unschedulable, pod: pod, trace: Trace.new, reason: reason)]
          end
        end
        assume_pod_group(cycle, members, plan)
      end

      def assume_pod_group(cycle, members, plan)
        assumed = []
        members.each do |member|
          destination = plan&.[](pod_lock_key(member))
          next if plan && destination.nil?

          placed = group_placements(assumed)
          existing = cycle.pods.reject { |candidate| placed.any? { |item| same_pod?(item, candidate) } } + placed
          result = schedule(member, cycle.nodes, pods: existing, namespace_labels: cycle.namespace_labels,
                                                 volume_data: cycle.volume_data, workload_selectors: cycle.workload_selectors,
                                                 pod_groups: cycle.pod_groups, assume_only: true, planned_node: destination)
          return [assumed, result] unless result.assumed?

          assumed << result
        end
        [assumed, nil]
      rescue StandardError => error
        assumed.reverse_each { |result| rollback_assumed(result, error) }
        raise
      end

      def group_placements(assumed)
        assumed.map { |result| result.pod.with("spec" => result.pod.spec.merge("nodeName" => result.node.name)) }
      end

      def finish_pod_group(members, existing, assumed, failure, topology_node_count:)
        if failure
          assumed.reverse_each { |result| rollback_assumed(result, PodGroupUnschedulable.new("pod group is unschedulable")) }
          members.each do |member|
            next if failure.gated? && same_pod?(member, failure.pod)

            report_peer = !failure.gated? && !same_pod?(member, failure.pod)
            report_nodes = topology_node_count if report_peer
            park_group_member(member, failure.reason, report_nodes: report_nodes)
          end
          return failure
        end

        placements = group_placements(assumed)
        preexisting = existing.reject { |candidate| placements.any? { |member| same_pod?(candidate, member) } }
        member_keys = placements.to_set { |pod| pod_lock_key(pod) }
        members.reject { |member| member_keys.include?(pod_lock_key(member)) }.each do |member|
          park_group_member(member, "no feasible node in the pod group's placement", report_nodes: topology_node_count)
        end
        assumed.map do |result|
          original = members.find { |member| same_pod?(member, result.pod) }
          permit_pods = preexisting + placements.reject { |candidate| same_pod?(candidate, result.pod) }
          bind_assumed(result, original: original, permit_pods: permit_pods)
        end.first
      end

      def park_group_member(member, reason, report_nodes: nil)
        queue.delete(member)
        queue.enqueue_unschedulable(member, reason: reason || "pod group is unschedulable", plugins: ["GangScheduling"])
        return unless report_nodes && @pod_group_unschedulable_handler

        result = ScheduleResult.new(status: :unschedulable, pod: member, trace: Trace.new, reason: reason)
        @pod_group_unschedulable_handler.call(result, report_nodes)
      end

      def bind_assumed(result, original:, permit_pods:)
        typed_pod = result.pod
        node = result.node
        context = result.reservation.context
        begin
          run_permit(typed_pod, node, context.with(pods: permit_pods), result.trace)
          bound_pod = bind!(original, typed_pod, node, context: context, trace: result.trace)
          commit_reservation!(result.reservation)
          forget_nomination(typed_pod)
          record_pod_scheduled(typed_pod)
          queue.delete(typed_pod)
          queue.forget(typed_pod)
          ScheduleResult.new(status: :scheduled, pod: bound_pod, node: node, filtered: result.filtered, scores: result.scores,
                             victims: result.victims, trace: result.trace, reservation: result.reservation)
        rescue StandardError => error
          rollback!(result.reservation, typed_pod, node, error, context: context, trace: result.trace)
          status = requeue_after_failure(typed_pod, error)
          ScheduleResult.new(status: status, pod: typed_pod, node: node, filtered: result.filtered, scores: result.scores,
                             victims: result.victims, trace: result.trace, error: error, reason: "bind or reserve failed")
        end
      end

      def rollback_assumed(result, error)
        context = result.reservation.context
        rollback!(result.reservation, result.pod, result.node, error, context: context, trace: result.trace)
      end

      class PodGroupUnschedulable < StandardError; end

      # The PodGroupScheduled condition (updatePodGroupCondition).
      def note_pod_group_condition(namespace, name, outcome, failure)
        return unless @pod_group_status_handler

        condition = case outcome
                    when "scheduled" then {"type" => "PodGroupScheduled", "status" => "True", "reason" => "Scheduled", "message" => ""}
                    when "unschedulable" then {"type" => "PodGroupScheduled", "status" => "False", "reason" => "Unschedulable",
                                               "message" => failure&.reason.to_s}
                    else {"type" => "PodGroupScheduled", "status" => "False", "reason" => "SchedulerError",
                          "message" => failure&.error&.message.to_s}
                    end
        @pod_group_status_handler.call(namespace, name, condition)
      end
    end
  end
end
