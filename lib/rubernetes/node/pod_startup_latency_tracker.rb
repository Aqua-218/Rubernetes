# frozen_string_literal: true

require "time"

module Rubernetes
  module Node
    # pkg/kubelet/util/pod_startup_latency_tracker.go (v1.36.2): the Pod
    # startup latency SLI.  A Pod is tracked from the first time the kubelet
    # sees it on the watch without a status.startTime (never one that is
    # unschedulable); the status manager marks when a status with every
    # container running was first written, and the next watch observation of
    # the Pod after that records
    #
    #   kubelet_pod_start_total_duration_seconds: watch time - creationTimestamp
    #   kubelet_pod_start_sli_duration_seconds:   the same, less the time spent
    #     pulling images (overlapping pulls counted once) and running init
    #     containers -- stateless Pods only
    #   kubelet_first_network_pod_start_sli_duration_seconds: the SLI of the
    #     first Pod not on the host network
    #
    # Times are wall-clock Time values (creationTimestamp is one).
    class PodStartupLatencyTracker
      State = Struct.new(:pull_sessions, :pull_starts, :init_runtime, :init_start, :observed_running, :recorded)
      STATELESS_VOLUMES = %w[secret configMap downwardAPI emptyDir projected].freeze

      def initialize(registry:, clock: -> { Time.now.utc })
        @registry = registry
        @clock = clock
        @pods = {}
        @excluded = {}
        @first_network_pod_seen = false
        @mutex = Mutex.new
      end

      def tracked?(uid) = @mutex.synchronize { @pods.key?(uid.to_s) }

      # config.go: every Pod the watch delivers.
      def observed_pod_on_watch(pod, now = @clock.call)
        uid = uid_of(pod)
        return if uid.empty?

        observation = nil
        @mutex.synchronize do
          status = pod["status"].is_a?(Hash) ? pod["status"] : {}
          if %w[Failed Succeeded].include?(status["phase"].to_s)
            @pods.delete(uid)
            next
          end
          state = @pods[uid]
          if state.nil?
            next if @excluded[uid]
            next unless status["startTime"].to_s.empty?

            if unschedulable?(pod)
              @excluded[uid] = true
            else
              @pods[uid] = State.new([], [], 0.0, nil, nil, false)
            end
            next
          end
          if unschedulable?(pod)
            @pods.delete(uid)
            @excluded[uid] = true
            next
          end
          next if state.observed_running.nil? || state.recorded
          next unless started_slo?(pod)

          state.recorded = true
          observation = [state, now]
        end
        record(pod, *observation) if observation
      end

      # imageManager: a pull of the Pod's began or ended.
      def image_started_pulling(uid, at = @clock.call)
        with_state(uid) { |state| state.pull_starts << at }
      end

      def image_finished_pulling(uid, at = @clock.call)
        with_state(uid) do |state|
          start = state.pull_starts.shift
          state.pull_sessions << [start, at] if start
        end
      end

      def init_container_started(uid, at)
        with_state(uid) { |state| state.init_start = at }
      end

      def init_container_finished(uid, at)
        with_state(uid) do |state|
          next unless state.init_start

          seconds = at - state.init_start
          state.init_runtime += seconds if seconds.positive?
          state.init_start = nil
        end
      end

      # statusManager.syncPod: a status the API server accepted (changed).
      def status_updated(pod)
        with_state(uid_of(pod)) do |state|
          next if state.recorded || state.observed_running

          state.observed_running = @clock.call if started_slo?(pod)
        end
      end

      def delete(uid)
        @mutex.synchronize do
          @pods.delete(uid.to_s)
          @excluded.delete(uid.to_s)
        end
      end

      # calculateImagePullingTime: sessions in the order they ended, an
      # overlap with the previous one counted once.
      def self.image_pulling_time(sessions)
        total = 0.0
        current_end = nil
        sessions.each_with_index do |(start, finish), index|
          next if finish.nil?

          if index.zero? || current_end.nil? || start > current_end
            total += finish - start
            current_end = finish
          elsif finish > current_end
            total += finish - current_end
            current_end = finish
          end
        end
        total
      end

      private

      def record(pod, state, now)
        created = creation_time(pod)
        return unless created

        total = now - created
        sli = total
        pulling = self.class.image_pulling_time(state.pull_sessions)
        sli -= pulling if pulling.positive?
        sli -= state.init_runtime if state.init_runtime.positive?
        @registry.observe("kubelet_pod_start_total_duration_seconds", total)
        return if stateful?(pod)

        @registry.observe("kubelet_pod_start_sli_duration_seconds", sli)
        first = @mutex.synchronize do
          next false if host_network?(pod) || @first_network_pod_seen

          @first_network_pod_seen = true
        end
        @registry.set("kubelet_first_network_pod_start_sli_duration_seconds", sli) if first
      end

      def with_state(uid)
        @mutex.synchronize do
          state = @pods[uid.to_s]
          yield state if state
        end
      end

      def uid_of(pod)
        pod.is_a?(Hash) ? pod.dig("metadata", "uid").to_s : ""
      end

      def creation_time(pod)
        value = pod.dig("metadata", "creationTimestamp")
        value.is_a?(Time) ? value : Time.parse(value.to_s)
      rescue ArgumentError, TypeError
        nil
      end

      # hasPodStartedSLO: every container status is running with a start time.
      def started_slo?(pod)
        statuses = pod.dig("status", "containerStatuses")
        Array(statuses).all? do |status|
          running = status.is_a?(Hash) ? status.dig("state", "running") : nil
          running.is_a?(Hash) && !running["startedAt"].to_s.empty?
        end
      end

      def stateful?(pod)
        Array(pod.dig("spec", "volumes")).any? do |volume|
          volume.is_a?(Hash) && STATELESS_VOLUMES.none? { |source| !volume[source].nil? }
        end
      end

      def host_network?(pod) = pod.dig("spec", "hostNetwork") == true

      def unschedulable?(pod)
        Array(pod.dig("status", "conditions")).any? do |condition|
          condition.is_a?(Hash) && condition["type"] == "PodScheduled" && condition["status"] == "False"
        end
      end
    end
  end
end
