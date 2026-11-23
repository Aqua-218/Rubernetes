# frozen_string_literal: true

module Rubernetes
  module Node
    # Pod manager inventory and Pod worker states as exposed by
    # kubelet HandlePodCleanups.
    module KubeletPodMetrics
      attr_writer :pod_inventory

      private

      WORKER_TERMINATING_STATES = %w[Stopping RollingBack CleanupPending].freeze
      WORKER_TERMINATED_STATES = %w[Stopped Removed Failed Succeeded].freeze
      TERMINAL_POD_PHASES = %w[Failed Succeeded].freeze
      WORKING_POD_LABELS = [["desired", "true"], ["desired", ""], ["orphan", "true"], ["orphan", ""], ["runtime_only", "unknown"]].freeze

      def pod_gauges(registry, records)
        workers = records.to_h { |record| [record[:uid] || record["uid"], record] }
        desired, mirrors = pod_inventory_snapshot(workers)
        active = desired.select { |uid, pod| active_configured_pod?(pod, workers[uid]) }
        set_pod_count(registry, "kubelet_desired_pods", desired.values)
        set_pod_count(registry, "kubelet_active_pods", active.values)
        registry.set("kubelet_mirror_pods", mirrors)
        working_pods(registry, workers, desired)
      end

      def pod_inventory_snapshot(workers)
        if @pod_inventory
          pods, mirrors = @pod_inventory.call
          return [pods.to_h { |pod| [pod.dig("metadata", "uid"), pod] }, mirrors]
        end

        desired = workers.reject { |_uid, record| config_removed?(record) || worker_state(record) == "Removed" }
        [desired.transform_values { |record| record[:pod] || record["pod"] }, 0]
      end

      def set_pod_count(registry, metric, pods)
        static = pods.count { |pod| pod_static_label(pod) == "true" }
        registry.set(metric, static, {"static" => "true"})
        registry.set(metric, pods.length - static, {"static" => ""})
      end

      def active_configured_pod?(pod, record)
        state = worker_state(record)
        return false if WORKER_TERMINATED_STATES.include?(state)
        return true if WORKER_TERMINATING_STATES.include?(state)

        phase = record&.fetch(:phase, nil) || record&.fetch("phase", nil) || pod.dig("status", "phase")
        !TERMINAL_POD_PHASES.include?(phase)
      end

      def working_pods(registry, workers, desired)
        counts = Hash.new(0)
        workers.each do |uid, record|
          state = worker_state(record)
          config = desired.key?(uid) && !config_removed?(record) ? "desired" : "orphan"
          next if config == "orphan" && state == "Removed"

          counts[[worker_lifecycle(state), config, pod_static_label(record[:pod] || record["pod"])]] += 1
        end
        WORKING_POD_LABELS.each do |config, static|
          %w[sync terminating terminated].each do |lifecycle|
            registry.set("kubelet_working_pods", counts[[lifecycle, config, static]],
                         {"lifecycle" => lifecycle, "config" => config, "static" => static})
          end
        end
      end

      def worker_lifecycle(state)
        return "terminated" if WORKER_TERMINATED_STATES.include?(state)
        return "terminating" if WORKER_TERMINATING_STATES.include?(state)

        "sync"
      end

      def worker_state(record)
        (record&.fetch(:state, nil) || record&.fetch("state", nil)).to_s
      end

      def config_removed?(record)
        record[:config_removed] || record["config_removed"] || record[:source_gone] || record["source_gone"]
      end

      def pod_static_label(pod)
        source = pod.dig("metadata", "annotations", "kubernetes.io/config.source").to_s
        source.empty? || source == "api" ? "" : "true"
      end
    end
  end
end
