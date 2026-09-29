# frozen_string_literal: true

require "time"

module Rubernetes
  module Controller
    # Which Pods a ReplicaSet (or ReplicationController) scales down first:
    # replica_set.go getPodsToDelete with controller_utils.go
    # ActivePodsWithRanks.Less (PodDeletionCost and LogarithmicScaleDown on,
    # as they are by default):
    #
    #   1. unassigned < assigned
    #   2. Pending < Unknown < Running
    #   3. not ready < ready
    #   4. lower controller.kubernetes.io/pod-deletion-cost < higher
    #   5. more active related Pods on the same node < fewer (doubled up)
    #   6. both ready: ready more recently < longer, by log2 buckets of the
    #      time since (a tie goes to the lower UID)
    #   7. more container restarts < fewer (then sidecar restarts)
    #   8. created more recently < earlier, by log2 buckets (UID tie-break)
    #
    # +related+ are the active Pods of every ReplicaSet with the same
    # controller (getIndirectlyRelatedPods), which the doubled-up rank counts.
    module PodDeletionRanking
      DELETION_COST_ANNOTATION = "controller.kubernetes.io/pod-deletion-cost"
      PHASE_ORDINAL = {"Pending" => 0, "Unknown" => 1, "Running" => 2}.freeze
      INT32 = (-(2**31))..((2**31) - 1)

      module_function

      def pods_to_delete(pods, count, related: nil, now: Time.now)
        pods = Array(pods)
        count = Integer(count)
        # No need to sort when every Pod goes.
        return pods.first(count) if count >= pods.length

        on_node = Hash.new(0)
        Array(related || pods).each { |pod| on_node[node_name(pod)] += 1 if active?(pod) }
        chosen = ranked_order(pods, pods.map { |pod| on_node[node_name(pod)] }, now).first(count)
        report_sorting_deletion_age_ratio(pods, chosen)
        chosen
      end

      # reportSortingDeletionAgeRatioMetric: each ready Pod chosen, its age
      # over the youngest ready Pod's, in whole milliseconds and integer
      # division as upstream divides them.
      def report_sorting_deletion_age_ratio(pods, chosen)
        return unless Controller.metrics

        now = Time.now
        youngest = pods.filter_map { |pod| ready?(pod) ? time(dig(pod, "metadata", "creationTimestamp")) : nil }.max || Time.at(0)
        youngest_age = ((now - youngest) * 1000).to_i
        chosen.each do |pod|
          next unless ready?(pod)
          next if youngest_age.zero?

          created = time(dig(pod, "metadata", "creationTimestamp")) || Time.at(0)
          ControllerMetrics.observe("replicaset_controller_sorting_deletion_age_ratio", (((now - created) * 1000).to_i / youngest_age).to_f)
        end
      rescue StandardError
        nil
      end

      # The Pods sorted by Less, given each one's doubled-up rank.
      def ranked_order(pods, ranks, now)
        entries = pods.each_with_index.map { |pod, index| Entry.new(pod, ranks[index].to_i, index, facts(pod)) }
        entries.sort { |left, right| compare(left, right, now) }.map(&:pod)
      end

      Entry = Struct.new(:pod, :rank, :index, :facts)
      Facts = Struct.new(:node, :phase, :ready, :ready_time, :cost, :restarts, :sidecar_restarts, :created, :uid)

      def facts(pod)
        ready = ready?(pod)
        restarts, sidecar_restarts = max_container_restarts(pod)
        Facts.new(node_name(pod), PHASE_ORDINAL.fetch(dig(pod, "status", "phase").to_s, 0), ready,
                  ready ? ready_time(pod) : nil, deletion_cost(pod), restarts, sidecar_restarts,
                  time(dig(pod, "metadata", "creationTimestamp")), dig(pod, "metadata", "uid").to_s)
      end

      # sort.Sort's order from Less, the original order for Pods Less
      # cannot tell apart.
      def compare(left, right, now)
        return -1 if less?(left, right, now)
        return 1 if less?(right, left, now)

        left.index <=> right.index
      end

      def less?(left, right, now)
        a = left.facts
        b = right.facts
        return a.node.empty? if a.node != b.node && (a.node.empty? || b.node.empty?)
        return a.phase < b.phase if a.phase != b.phase
        return !a.ready if a.ready != b.ready
        return a.cost < b.cost if a.cost != b.cost
        return left.rank > right.rank if left.rank != right.rank

        if a.ready && b.ready && a.ready_time != b.ready_time
          return logarithmic_less(a.ready_time, b.ready_time, a.uid, b.uid, now)
        end
        return a.restarts > b.restarts if a.restarts != b.restarts
        return a.sidecar_restarts > b.sidecar_restarts if a.sidecar_restarts != b.sidecar_restarts
        return logarithmic_less(a.created, b.created, a.uid, b.uid, now) if a.created != b.created

        false
      end

      # afterOrZero unless both times and now are set; then logarithmicRankDiff.
      def logarithmic_less(first, second, first_uid, second_uid, now)
        return after_or_zero?(first, second) if now.nil? || first.nil? || second.nil?

        diff = log_rank(first, now) - log_rank(second, now)
        diff.zero? ? first_uid < second_uid : diff.negative?
      end

      def after_or_zero?(first, second)
        return first.nil? if first.nil? || second.nil?

        first > second
      end

      # int64(math.Log2(float64(now - t))) over nanoseconds; -1 when not after.
      def log_rank(time, now)
        nanoseconds = ((now.to_r - time.to_r) * 1_000_000_000).to_i
        nanoseconds.positive? ? Math.log2(nanoseconds.to_f).to_i : -1
      end

      def ready?(pod)
        Array(dig(pod, "status", "conditions")).any? { |condition| condition["type"] == "Ready" && condition["status"] == "True" }
      end

      def ready_time(pod)
        condition = Array(dig(pod, "status", "conditions")).find { |entry| entry["type"] == "Ready" && entry["status"] == "True" }
        time(condition && condition["lastTransitionTime"])
      end

      # GetDeletionCostFromPodAnnotations: an int32 without a sign or leading
      # zeros ("-5", "0", "12"); anything else counts as 0.
      def deletion_cost(pod)
        value = dig(pod, "metadata", "annotations", DELETION_COST_ANNOTATION)
        return 0 unless value.is_a?(String) && value.match?(/\A(-?[0-9]+)\z/)
        return 0 unless value.start_with?("-") || value == "0" || value.match?(/\A[1-9]/)

        cost = Integer(value, 10)
        INT32.cover?(cost) ? cost : 0
      rescue ArgumentError
        0
      end

      def max_container_restarts(pod)
        regular = Array(dig(pod, "status", "containerStatuses")).map { |status| status["restartCount"].to_i }.max || 0
        sidecars = Array(dig(pod, "spec", "initContainers")).select { |container| container["restartPolicy"] == "Always" }.map { |c| c["name"] }
        sidecar = Array(dig(pod, "status", "initContainerStatuses")).select { |status| sidecars.include?(status["name"]) }
                                                                    .map { |status| status["restartCount"].to_i }.max || 0
        [[regular, 0].max, [sidecar, 0].max]
      end

      # controller.IsPodActive.
      def active?(pod)
        !%w[Succeeded Failed].include?(dig(pod, "status", "phase").to_s) && dig(pod, "metadata", "deletionTimestamp").nil?
      end

      def node_name(pod) = dig(pod, "spec", "nodeName").to_s

      def time(value)
        return value if value.is_a?(Time)
        return nil if value.nil? || value.to_s.empty?

        Time.iso8601(value.to_s)
      rescue ArgumentError
        nil
      end

      def dig(object, *path)
        path.reduce(object) { |current, key| current.is_a?(Hash) ? (current[key] || current[key.to_sym]) : nil }
      end
    end
  end
end
