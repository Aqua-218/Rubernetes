# frozen_string_literal: true

require_relative "../../image/errors"
require_relative "../../image/digest"
require_relative "../../image/reference"

module Rubernetes
  module Node
    class Lifecycle
      # Publishes a record as Pod status: per-container observations and the
      # aggregate the status manager reports.
      module StatusReporting
        private

        def update_status(pod, record)
          mark_dirty(record)
          record[:published_status_signature] = status_signature(record)
          image_volume_refs = mounted_image_refs(pod, record) if @image_volume_with_digest
          # An ephemeral container is reported in its own status list upstream
          # (status.ephemeralContainerStatuses); folding it in with the init
          # containers left the debug container invisible to every client that
          # waits for it.
          state = {
            "containers" => record[:containers].select { |entry| entry[:category] == "app" }.to_h do |entry|
              [entry[:name], container_observation(entry, record, image_volume_refs)]
            end,
            "initContainers" => record[:containers].select { |entry| %w[init sidecar].include?(entry[:category].to_s) }.to_h do |entry|
              [entry[:name], container_observation(entry, record, image_volume_refs)]
            end,
            "ephemeralContainers" => record[:containers].select { |entry| entry[:category] == "ephemeral" }.to_h do |entry|
              [entry[:name], container_observation(entry, record, image_volume_refs)]
            end
          }
          state["ephemeralContainers"].merge!(record.fetch(:rejected_ephemeral_containers, {}))
          apply_image_pull_failure(pod, record, state)
          ips = pod_ips(record)
          previous = retained_termination_status(pod, record)
          disruption = record[:disruption_condition] unless previous
          snapshot = @status.aggregate(
            pod: pod,
            state: state,
            phase: previous ? previous.fetch("phase", record[:phase]) : record[:phase],
            reason: previous ? previous["reason"] : status_reason(record),
            message: previous ? previous["message"] : status_message(record),
            preserve_phase: !previous.nil?,
            start_time: record[:started_at],
            observed_generation: observed_generation(pod, record),
            pod_ip: ips.first,
            pod_ips: ips,
            host_ip: @host_ip, host_ips: @host_ips,
            all_containers_restarting: record[:restarting_all] == true,
            # Kubelet-owned conditions beyond the standard ones: the resize
            # conditions and an eviction's DisruptionTarget.
            resize_conditions: [record[:resize_pending], record[:resize_in_progress], disruption].compact,
            pod_resources: pod_status_resources(record),
            allocated_resources: record[:pod] ? PodResize.allocated_resources(record[:pod]) : nil
          )
          # A fresh copy nobody mutates afterwards: frozen, json_safe converts
          # it once per status change instead of on every persist of the record.
          record[:status] = Helpers.deep_freeze(snapshot.to_h)
          snapshot
        end

        # mergePodStatus holds the old phase, reason, and message while the
        # kubelet is still stopping a Pod with a forced terminal outcome.
        def retained_termination_status(pod, record)
          return unless record[:pending_terminal_phase]

          current = Helpers.key(pod, "status", nil)
          return Helpers.string_keys(current) if current.is_a?(Hash) && !Helpers.key(current, "phase").to_s.empty?

          record[:status] || {}
        end

        def status_message(record)
          return if terminal_init_exit?(record) || container_image_pull_failure(record)
          return "Pod was rejected: #{record[:admission_message]}" if record[:admission_message]

          record[:error] || record[:termination_message]
        end

        def status_reason(record)
          return if terminal_init_exit?(record) || container_image_pull_failure(record)

          record[:admission_reason] || record[:reason] || (record[:error] && "StartFailed")
        end

        def terminal_init_exit?(record)
          record[:forced_terminal] && record[:reason] == ContainerStart::INIT_EXIT_REASON
        end

        def container_image_pull_failure(record)
          record[:image_pull_failure] if ImagePinning::IMAGE_PULL_REASONS.include?(record[:reason])
        end

        def apply_image_pull_failure(pod, record, state)
          failure = container_image_pull_failure(record)
          return unless failure

          %w[initContainers containers].each do |section|
            container = Array(pod.dig("spec", section)).find do |definition|
              definition["name"] == failure[:name] && definition["image"] == failure[:reference]
            end
            next unless container

            message = failure[:message]
            message = "Back-off pulling image #{failure[:reference].inspect}: #{message}" if record[:reason] == "ImagePullBackOff"
            state.fetch(section)[failure[:name]] ||= {"waiting" => {"reason" => record[:reason], "message" => message}}
          end
        end

        def observed_generation(pod, record)
          reported = record.dig(:status, "observedGeneration")
          current = [pod_generation(pod), pod_generation(record[:pod]), reported].compact.max
          latest = @desired_pod_lookup&.call(record[:uid])
          queued = pod_generation(latest)
          return current unless queued && queued > current.to_i
          # A metadata-only update or an ordinary init image change does not
          # depend on a preceding image replacement finishing or retrying.
          return current unless config_digest(latest) == config_digest(pod)

          queued
        end

        def pod_generation(pod)
          value = Helpers.key(Helpers.key(pod, "metadata", {}), "generation", nil)
          Integer(value) unless value.nil?
        end

        # kubelet reports *why* a container is waiting: a Pod that cannot be
        # configured shows CreateContainerConfigError on the container, not only
        # on the Pod.  Clients wait on that reason -- the subPath expansion
        # conformance spec waits for exactly it -- so a reasonless `waiting`
        # leaves them waiting forever.
        def container_observation(entry, record, image_volume_refs = nil)
          observation = entry[:status].merge("containerID" => entry[:id])
          prefix = container_id_prefix(record)
          format_container_ids(observation, prefix) if prefix
          observation["resources"] = entry.dig(:spec, "resources") || {}
          # The ordinary deletion path reports runtime readiness during its grace period.
          observation["ready"] = false if record[:state] == "Stopping" && record[:reason] != Termination::POD_TERMINATING_REASON
          observation["image"] ||= entry.dig(:spec, "image") if entry.dig(:spec, "image")
          if (observation["imageID"] || observation["image_id"]).to_s.empty?
            image_id = resolved_container_image_id(entry, observation)
            observation["imageID"] = image_id if image_id
          end
          observation["stopSignal"] = entry[:stop_signal] if @container_stop_signals && entry[:stop_signal]
          observation["imageVolumeRefs"] = image_volume_refs unless image_volume_refs.nil? || image_volume_refs.empty?
          recursive_mounts = observed_recursive_mounts(entry, record)
          observation["recursiveReadOnlyMounts"] = recursive_mounts if recursive_mounts
          user = container_user(entry)
          observation = observation.merge("user" => user) if user
          # ResourceHealthStatus: the health of each device the container holds.
          health = resource_health(record, entry)
          observation = observation.merge("allocatedResourcesStatus" => health) unless health.empty?
          reason = record[:reason].to_s
          return observation unless observation["state"].to_s == "waiting" && !reason.empty?

          waiting = observation["waiting"]
          waiting = waiting.is_a?(Hash) ? waiting.dup : {}
          return observation unless waiting["reason"].to_s.empty?

          waiting["reason"] = reason
          message = record[:error].to_s
          waiting["message"] = message unless message.empty?
          observation.merge("waiting" => waiting)
        end

        def observed_recursive_mounts(entry, record)
          return unless %w[running terminated exited].include?(entry.dig(:status, "state").to_s)
          return unless Array(entry.dig(:spec, "mounts")).any? { |mount| %w[IfPossible Enabled].include?(mount["recursive_readonly"]) }
          return unless cri_runtime_for_pod?(record[:pod])

          readback = entry.dig(:status, "recursiveReadOnlyMounts")
          return readback unless readback.nil?

          container_id = entry[:id]
          cached = entry[:recursive_mount_readback]
          return cached.last if cached && cached.first == container_id

          readback = best_effort { invoke(@runtime, :container_status, container_id).fetch("recursiveReadOnlyMounts") }
          entry[:recursive_mount_readback] = [container_id, readback] if readback
          readback || {}
        end

        def native_pod_log_backend?(record)
          return false unless defined?(Runtime::Native::PodLogFiles::RuntimeHooks)

          runtime = @runtime
          return true if runtime.is_a?(Runtime::Native::PodLogFiles::RuntimeHooks)
          return false unless defined?(Runtime::Multiplexer) && runtime.is_a?(Runtime::Multiplexer)

          native = runtime.backends[Runtime::Multiplexer::DEFAULT_HANDLER]
          return false unless native.is_a?(Runtime::Native::PodLogFiles::RuntimeHooks) && record[:sandbox_id]

          !native.sandbox(record[:sandbox_id]).nil?
        rescue Runtime::Native::Error
          false
        end

        def container_id_prefix(record)
          sandbox = record[:sandbox_id]
          if sandbox && runtime_supports?(:sandbox_container_id_prefix)
            prefix = @runtime.sandbox_container_id_prefix(sandbox)
            return prefix if prefix
          end

          "rubernetes" if native_pod_log_backend?(record)
        end

        def format_container_ids(observation, prefix)
          observation["containerID"] = api_container_id(observation["containerID"], prefix)
          if (terminated = observation["terminated"]) && terminated["containerID"]
            observation["terminated"] = terminated.merge("containerID" => api_container_id(terminated["containerID"], prefix))
          end
          if (previous = observation.dig("lastState", "terminated")) && previous["containerID"]
            observation["lastState"] = observation["lastState"].merge("terminated" => previous.merge(
              "containerID" => api_container_id(previous["containerID"], prefix)
            ))
          end
        end

        def api_container_id(id, prefix)
          return id if id.to_s.empty? || id.to_s.include?("://")

          "#{prefix}://#{id}"
        end

        def resolved_container_image_id(entry, observation)
          runtime_image = observation["imageRef"]
          return runtime_image unless runtime_image.to_s.empty?

          image = entry.dig(:spec, "resolved_image")
          return unless image && image["reference"] && image["digest"]

          Image::Reference.parse(image.fetch("reference")).with_digest(image.fetch("digest")).to_s
        rescue Image::ReferenceError, Image::DigestError
          nil
        end

        def mounted_image_refs(pod, record)
          mounts = Helpers.key(record[:volume] || {}, "mounts", {})
          images = record[:volume_images] || {}
          spec = Helpers.key(pod, "spec", {})
          Array(Helpers.key(spec, "volumes", [])).each_with_object({}) do |volume, refs|
            name = Helpers.key(volume, "name", "").to_s
            image = Helpers.key(volume, "image", {}) || {}
            reference = Helpers.key(image, "reference", "").to_s
            digest = images.dig(reference, "digest")
            refs[name] = digest if digest && mounts.key?(name)
          end
        end

        # ContainerStatus.user (SupplementalGroupsPolicy): the identity the
        # container runs with once it exists -- uid, gid and every group, in
        # the runtime's order (the gid, the image's memberships, the Pod's
        # supplementalGroups, fsGroup).
        def container_user(entry)
          return nil if entry[:id].nil? || !entry[:spec].is_a?(Hash)
          return nil unless %w[running terminated exited].include?(entry[:status].is_a?(Hash) ? entry[:status]["state"].to_s : "")

          context = Helpers.string_keys(Helpers.key(entry[:spec], "security_context", {}) || {})
          uid = Integer(context["runAsUser"] || 0)
          gid = Integer(context["runAsGroup"] || 0)
          image = Array(context["imageSupplementalGroups"]).map { |group| Integer(group) }
          pod = Array(context["supplementalGroups"]).map { |group| Integer(group) } - image
          groups = ([gid] + image + pod + [context["fsGroup"]].compact.map { |group| Integer(group) }).uniq
          {"linux" => {"uid" => uid, "gid" => gid, "supplementalGroups" => groups}}
        rescue ArgumentError, TypeError
          nil
        end

        # status.resources: the allocated pod-level resources, and once Running
        # what the Pod cgroup actually holds (read when the Pod starts running
        # and after each resize).
        def pod_status_resources(record)
          allocated = record[:pod]
          return nil if allocated.nil?

          running = record[:phase].to_s == "Running"
          record[:pod_cgroup] ||= runtime_pod_cgroup(record) if running
          previous = record[:status].is_a?(Hash) ? record[:status]["resources"] : nil
          previous_phase = record[:status].is_a?(Hash) ? record[:status]["phase"] : nil
          PodResize.status_resources(allocated, phase: record[:phase], cgroup: running ? record[:pod_cgroup] : nil,
                                                previous: previous, previous_phase: previous_phase)
        end
      end
    end
  end
end
