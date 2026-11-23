# frozen_string_literal: true

require "pathname"

module Rubernetes
  module Controller
    class PersistentVolumeBinderController < BaseController
      RECYCLER_NAMESPACE = "default"
      RECYCLER_CLAIM_UID = "pv.kubernetes.io/recycler-claim-uid"

      private

      # RecycleVolumeByWatchingPodUntilCompletion, one step per sync. An
      # API-backed controller rechecks ownership before either starting a scrub
      # or releasing the PV based on the result of a previously started one.
      def recycle_volume(volume, context)
        current = current_recycling_volume(volume, context)
        return unless current && volume_released?(current, context, fresh: true)

        context[:requeue] = RECHECK_SECONDS
        return unless %w[Released Failed].include?(Support.status(current)["phase"])
        return if recycling_blocked_by_users?(current, context)

        source, minimum = recycler_source(current)
        unless source
          update_volume_phase_with_event(current, "Failed", context, "Warning", "VolumeFailedRecycle",
                                         "No recycler plugin found for the volume!")
          return
        end

        name = "recycler-for-#{Support.name(current)}"
        pod = find_recycler_pod(context[:adapter], name)
        if pod
          observe_recycler_pod(current, pod, source, context)
        else
          context[:operations] << operation_create(recycler_pod(name, current, source, minimum), descriptor: POD,
                                                                                                 reason: "start the volume recycler")
        end
      end

      def current_recycling_volume(volume, context)
        uid = Support.uid(volume).to_s
        return if uid.empty?

        adapter = context[:adapter]
        current = if InfrastructureCapability.live_reads?(adapter)
                    adapter.find_live(PV, name: Support.name(volume))
                  else
                    volume
                  end
        return unless current && Support.uid(current) == uid && claim_ref(current) == claim_ref(volume)
        return if volume_deleting?(current) || reclaim_policy(current) != "Recycle"
        return unless Support.annotations(current)[ANN_MIGRATED_TO].to_s.empty?

        current
      end

      def recycling_blocked_by_users?(volume, context)
        namespace, name, uid = claim_ref(volume).values_at("namespace", "name", "uid")
        users = pods_by_claim(context, namespace, name, fresh: true).reject { |pod| pod_terminated?(pod) }
        return false if users.empty?

        cached = find_claim(context, namespace, name)
        if cached
          target = Support.value(Support.spec(cached), "volumeName", "").to_s
          return false if Support.uid(cached) != uid || (!target.empty? && target != Support.name(volume))
        end

        names = users.map { |pod| "#{Support.namespace(pod)}/#{Support.name(pod)}" }.sort
        event(context, "Normal", "VolumeFailedRecycle", "Volume is used by pods: #{names.join(",")}")
        true
      end

      def find_recycler_pod(adapter, name)
        if InfrastructureCapability.live_reads?(adapter)
          adapter.find_live(POD, name: name, namespace: RECYCLER_NAMESPACE)
        else
          adapter&.find(POD, name: name, namespace: RECYCLER_NAMESPACE)
        end
      end

      def observe_recycler_pod(volume, pod, source, context)
        unless owned_recycler_pod?(volume, pod, source)
          event(context, "Warning", "VolumeFailedRecycle", "Recycler Pod does not match the released volume and claim")
          return
        end

        case Support.status(pod)["phase"]
        when "Succeeded"
          delete_recycler_pod(pod, context)
          event(context, "Normal", "VolumeRecycled", "Volume recycled")
          unbind_volume(volume, context)
        when "Failed"
          delete_recycler_pod(pod, context)
          message = Support.status(pod)["message"].to_s
          message = "pod failed, pod.Status.Message unknown" if message.empty?
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedRecycle",
                                         "Recycle failed: failed to recycle volume: #{message}")
        end
      end

      def owned_recycler_pod?(volume, pod, source)
        return false if Support.uid(pod).to_s.empty? || !Support.owner_reference_matches?(volume, pod, controller: true)
        return false unless Support.annotations(pod)[RECYCLER_CLAIM_UID] == claim_ref(volume)["uid"]

        scrub = Array(Support.spec(pod)["volumes"]).find { |entry| entry["name"] == "vol" }
        source.all? do |kind, expected|
          actual = scrub&.[](kind)
          actual && actual["readOnly"] != true && actual.slice(*expected.keys) == expected
        end
      end

      def delete_recycler_pod(pod, context)
        options = {"preconditions" => {"uid" => Support.uid(pod)}}
        context[:operations] << operation_delete(pod, descriptor: POD, reason: "remove the finished recycler", options: options)
      end

      def recycler_source(volume)
        return [] unless volume_mode(volume) == "Filesystem"

        spec = Support.spec(volume)
        if (host = spec["hostPath"])
          path = host["path"].to_s
          return [] if path.empty? || path.include?("\0") || Pathname.new(path).cleanpath.root?

          [{"hostPath" => {"path" => path}}, 60]
        elsif (nfs = spec["nfs"])
          [{"nfs" => nfs.slice("server", "path")}, 300]
        else
          []
        end
      end

      # Upstream defaults: 30 s per whole GiB with a plugin-specific minimum.
      def recycler_pod(name, volume, source, minimum)
        timeout = [minimum, 30 * storage(volume_capacity(volume)).ceil.div(1024**3)].max
        reference = Support.owner_reference(volume, block_owner_deletion: false)
        {"apiVersion" => "v1", "kind" => "Pod",
         "metadata" => {"name" => name, "namespace" => RECYCLER_NAMESPACE, "ownerReferences" => [reference],
                        "annotations" => {RECYCLER_CLAIM_UID => claim_ref(volume)["uid"]}},
         "spec" => {"activeDeadlineSeconds" => timeout, "restartPolicy" => "Never",
                    "volumes" => [{"name" => "vol"}.merge(source)],
                    "containers" => [{"name" => "pv-recycler", "image" => RECYCLER_IMAGE, "command" => ["/bin/sh"],
                                      "args" => ["-c", RECYCLER_SCRIPT], "volumeMounts" => [{"name" => "vol", "mountPath" => "/scrub"}]}]}}
      end
    end
  end
end
