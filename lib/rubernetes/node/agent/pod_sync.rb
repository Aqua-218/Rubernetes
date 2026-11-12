# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # What the agent does around the lifecycle on each sync of a Pod, and
      # the views of the lifecycle's Pods it hands to others.
      module PodSync
        private

        # The sync loop's reconcile: the lifecycle, with the kubelet's
        # bookkeeping around it.
        def reconcile_pod(pod, **options)
          # The kubelet never runs a mirror Pod: it is the API's view of a
          # static Pod, which StaticPods runs from its manifest.
          return nil if mirror_pod?(pod)

          check_declared_features_update(pod)
          @kubelet_metrics.pod_seen(pod)
          began = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = @lifecycle.reconcile(pod, **options)
          @kubelet_metrics.pod_worker_synced(pod, options[:action], Process.clock_gettime(Process::CLOCK_MONOTONIC) - began)
          @qos_cgroup_manager&.pods_changed
          result
        end

        def mirror_pod?(pod)
          annotations = pod.is_a?(Hash) ? (pod.dig("metadata", "annotations") || pod.dig(:metadata, :annotations) || {}) : {}
          annotations.key?(StaticPods::CONFIG_MIRROR) || annotations.key?(StaticPods::CONFIG_MIRROR.to_sym)
        end

        # kubelet HandlePodUpdates: an update of a Pod on this node that needs
        # a feature the node does not declare is reported (Warning
        # FailedNodeDeclaredFeaturesCheck); the API server's
        # NodeDeclaredFeatureValidator is what refuses it.
        def check_declared_features_update(pod)
          return if @declared_features.nil? || !pod.is_a?(Hash)

          metadata = pod["metadata"] || {}
          previous = @lifecycle.record(metadata["uid"].to_s)
          old_pod = previous.is_a?(Hash) ? previous[:pod] : nil
          return if old_pod.nil?

          missing = @admission.missing_update_features(old_pod, pod)
          return if missing.empty? || @event_recorder.nil?

          @event_recorder.record(
            involved_object: {"apiVersion" => "v1", "kind" => "Pod", "namespace" => metadata["namespace"],
                              "name" => metadata["name"], "uid" => metadata["uid"]},
            reason: "FailedNodeDeclaredFeaturesCheck", type: "Warning", namespace: metadata["namespace"],
            message: "Pod requires node features that are not available: #{missing.join(", ")}"
          )
        rescue StandardError => error
          @error_handler&.call(error)
        end

        # The Pods whose containers run here (podresources lists active Pods).
        def running_pods_for_pod_resources
          @lifecycle.records.values.filter_map do |record|
            next unless record.is_a?(Hash) && record[:state] == "Running"

            pod = record[:pod]
            pod.is_a?(Hash) ? Helpers.string_keys(pod) : nil
          end
        end
      end
    end
  end
end
