# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # A Pod's volumes: the attachable volumes reported in use, preparing the
      # volume set before the sandbox, and the periodic volume sync.
      module VolumeSetup
        # node.status.volumesInUse (volumeManager.GetVolumesInUse): the
        # attachable volumes of the desired state -- every admitted Pod's,
        # from admission until the Pod's containers are gone -- and of the
        # actual state -- every volume still mounted -- sorted and unique; the
        # attach/detach controller does not detach one while it is listed.
        def volumes_in_use
          @mutex.synchronize do
            @records.values.flat_map do |record|
              next [] if record[:state].to_s == "Removed"

              desired = INACTIVE_STATES.include?(record[:state].to_s) ? [] : Array(record[:attachable_volumes])
              mounted = if record[:volume].is_a?(Hash) && !(record[:cleanup_completed] || {})["volume"]
                          Array((record[:volume]["mounts"] || {}).values).filter_map { |mount| mount.is_a?(Hash) ? mount["uniqueName"] : nil }
                        else
                          []
                        end
              desired + mounted
            end.map(&:to_s).uniq.sort
          end
        end

        # Called with no arguments whenever the desired set of attachable
        # volumes changes (a node status sync is due).
        attr_accessor :volumes_in_use_observer

        # MarkVolumesAsReportedInUse: the list the Node's status now carries.
        def mark_volumes_reported_in_use(names)
          @mutex.synchronize do
            @reported_in_use = Array(names).map(&:to_s).to_h { |name| [name, true] }
            @reported_in_use_changed.broadcast
          end
          true
        end

        def volumes_reported_in_use = @mutex.synchronize { @reported_in_use.keys.sort }

        # How long a Pod start waits for its attachable volumes to be reported
        # in use (podAttachAndMountTimeout).
        VOLUME_REPORTED_IN_USE_TIMEOUT_SECONDS = 120
        attr_writer :volumes_reported_in_use_timeout

        private

        def release_stale_volumes(existing)
          return unless @pod_volumes

          handle = existing[:volume]
          return unless handle.is_a?(Hash)
          return if existing[:cleanup_completed] && existing[:cleanup_completed]["volume"]

          event(existing, "volume.release_stale")
          @pod_volumes.release(existing[:pod], handle, token: "release-stale-#{existing[:uid]}")
          existing[:cleanup_completed]["volume"] = true if existing[:cleanup_completed]
        rescue StandardError => error
          # The next prepare will fail loudly if the stage really is still
          # there; losing the reason for that here would hide it.
          event(existing, "volume.release_stale_failed", "error" => Helpers.failure_message(error))
        end

        # desiredStateOfWorldPopulator.processPodVolumes for this Pod: the
        # attachable volumes it names, kept on the record (durably) so the node
        # status reports them from now until the Pod is gone.
        def note_attachable_volumes(pod, record)
          return unless @pod_volumes

          names = @pod_volumes.attachable_volume_names(pod)
          return if names.empty?

          record[:attachable_volumes] = names
          event(record, "volume.desired", volumes: names)
          @volumes_in_use_observer&.call
        rescue StandardError => error
          event(record, "volume.desired_failed", error: Helpers.failure_message(error))
        end

        # reconciler.waitForVolumeAttach: an attachable volume is mounted only
        # after the node status reported it in use (so the attach/detach
        # controller knows the node holds it).  Without a status publisher
        # (no observer) there is nobody to wait for.
        def wait_for_volumes_reported_in_use(pod, record)
          names = Array(record[:attachable_volumes])
          return if names.empty? || @volumes_in_use_observer.nil?

          timeout = @volumes_reported_in_use_timeout || VOLUME_REPORTED_IN_USE_TIMEOUT_SECONDS
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          # The Pod's claim-backed volume names, for the kubelet's message.
          volume_names = Array(Helpers.key(Helpers.key(pod, "spec", {}), "volumes", [])).filter_map do |volume|
            name = Helpers.key(volume, "name", "").to_s
            name if Helpers.key(volume, "persistentVolumeClaim", nil) || Helpers.key(volume, "ephemeral", nil)
          end
          @mutex.synchronize do
            loop do
              missing = names.reject { |name| @reported_in_use.key?(name) }
              return if missing.empty?

              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              if remaining <= 0
                record[:reason] = "FailedMount"
                raise LifecycleError,
                      "Unable to attach or mount volumes: unmounted volumes=#{volume_names}, " + "unattached volumes=#{volume_names}, failed to process " \
                                                                                                 "volumes=[]: timed out waiting for the condition"
              end
              @volumes_in_use_observer&.call
              @reported_in_use_changed.wait(@mutex, [remaining, 1.0].min)
            end
          end
        end

        def prepare_volume(pod, record)
          event(record, "volume.prepare")
          if @pod_volumes
            begin
              handle = @pod_volumes.prepare(pod, token: "prepare-#{record[:uid]}", host_ip: @host_ip,
                                                 images: record[:volume_images] || {})
            rescue PodVolumes::MissingDependency, PodVolumes::Unsupported, PodVolumes::SELinuxConflict => error
              record[:reason] = "FailedMount"
              raise LifecycleError, "MountVolume.SetUp failed: #{error.message}"
            end
            record[:resources] << {"kind" => "volume", "id" => Array(handle["ids"]).join(",")} unless Array(handle["ids"]).empty?
            return handle
          end

          handle = @volume&.prepare(pod)
          record[:resources] << {"kind" => "volume", "id" => handle.to_s} unless handle.nil?
          handle
        end

        # kubelet's periodic sync also revisits the Pod's volumes: projected
        # ServiceAccount tokens are rotated before they expire (a token that
        # ran out took every in-cluster client with it) and ConfigMap / Secret
        # / downward API content is re-projected when it changed.
        # Projected volume contents follow the Pod's labels and annotations, which
        # only a periodic sync can notice -- but rebuilding every projected file
        # on every housekeeping tick is most of what the node spends its CPU on.
        # kubelet refreshes them on its own sync frequency (~60s); this keeps the
        # refresh well inside what clients wait for without paying for it every
        # few seconds.
        VOLUME_SYNC_INTERVAL_SECONDS = 15.0

        def projected_metadata(pod)
          metadata = Helpers.key(pod || {}, "metadata", {})
          [Helpers.key(metadata, "labels", nil), Helpers.key(metadata, "annotations", nil)]
        end

        def volume_sync_due?(record)
          now = monotonic_clock.call
          last = record[:last_volume_sync]
          return true if last.nil? || (now - last) >= VOLUME_SYNC_INTERVAL_SECONDS

          false
        end

        def sync_volumes(record, pod)
          record[:last_volume_sync] = monotonic_clock.call
          return unless @pod_volumes && record[:volume].is_a?(Hash)

          ips = pod_ips(record)
          rotated = @pod_volumes.rotate_tokens(pod, record[:volume], pod_ips: ips, host_ip: @host_ip)
          event(record, "volume.tokens_rotated", volumes: rotated) unless rotated.empty?
          @pod_volumes.expand_in_use(pod, record[:volume]).each do |name, outcome, message|
            event(record, outcome == :resized ? "volume.fs_resized" : "volume.fs_resize_failed", volume: name, message: message)
          end
          republished = @pod_volumes.republish_csi(pod, record[:volume])
          event(record, "volume.republished", volumes: republished) unless republished.empty?
          refreshed = @pod_volumes.refresh_contents(pod, record[:volume], pod_ips: ips, host_ip: @host_ip)
          event(record, "volume.contents_refreshed", volumes: refreshed) unless refreshed.empty?
        rescue StandardError => error
          event(record, "volume.sync_failed", error: error.message)
        end
      end
    end
  end
end
