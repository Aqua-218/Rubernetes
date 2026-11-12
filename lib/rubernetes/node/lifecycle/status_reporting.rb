# frozen_string_literal: true

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
          # An ephemeral container is reported in its own status list upstream
          # (status.ephemeralContainerStatuses); folding it in with the init
          # containers left the debug container invisible to every client that
          # waits for it.
          state = {
            "containers" => record[:containers].select { |entry| entry[:category] == "app" }.to_h do |entry|
              [entry[:name], container_observation(entry, record)]
            end,
            "initContainers" => record[:containers].select { |entry| %w[init sidecar].include?(entry[:category].to_s) }.to_h do |entry|
              [entry[:name], container_observation(entry, record)]
            end,
            "ephemeralContainers" => record[:containers].select { |entry| entry[:category] == "ephemeral" }.to_h do |entry|
              [entry[:name], container_observation(entry, record)]
            end
          }
          ips = pod_ips(record)
          host_network = Helpers.key(Helpers.key(pod, "spec", {}), "hostNetwork", false) == true
          ips = [@host_ip].compact if host_network && ips.empty? && @host_ip
          snapshot = @status.aggregate(
            pod: pod,
            state: state,
            phase: record[:phase],
            reason: record[:reason] || (record[:error] && "StartFailed"),
            message: record[:error] || record[:termination_message],
            start_time: record[:started_at],
            # The newest generation this node has seen for the Pod: a status
            # published by the old record's termination must not roll
            # observedGeneration back below the one the restarted record saw.
            observed_generation: [pod, record[:pod]].compact.filter_map do |candidate|
              value = Helpers.key(Helpers.key(candidate, "metadata", {}), "generation", nil)
              value.nil? ? nil : Integer(value)
            end.max,
            pod_ip: ips.first,
            pod_ips: ips,
            host_ip: @host_ip,
            all_containers_restarting: record[:restarting_all] == true,
            # Kubelet-owned conditions beyond the standard ones: the resize
            # conditions and an eviction's DisruptionTarget.
            resize_conditions: [record[:resize_pending], record[:resize_in_progress], record[:disruption_condition]].compact,
            pod_resources: pod_status_resources(record),
            allocated_resources: record[:pod] ? PodResize.allocated_resources(record[:pod]) : nil
          )
          # A fresh copy nobody mutates afterwards: frozen, json_safe converts
          # it once per status change instead of on every persist of the record.
          record[:status] = Helpers.deep_freeze(snapshot.to_h)
          snapshot
        end

        # kubelet reports *why* a container is waiting: a Pod that cannot be
        # configured shows CreateContainerConfigError on the container, not only
        # on the Pod.  Clients wait on that reason -- the subPath expansion
        # conformance spec waits for exactly it -- so a reasonless `waiting`
        # leaves them waiting forever.
        def container_observation(entry, record)
          observation = entry[:status].merge("containerID" => entry[:id])
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
