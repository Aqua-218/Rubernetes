# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Cgroup limits and accounting: derives Pod and container limits from
      # the spec, withholds the ceilings that would starve the bootstrap until
      # the workload runs, attributes OOM kills, resizes in place, and reads
      # limits and usage back from the kernel.
      module ResourceLimits
        # The bootstrap that sets up a container's security is an interpreter
        # process living in the container's own cgroup, and it allocates while
        # it works.  A small memory ceiling -- 32Mi and 64Mi are ordinary in
        # conformance Pods -- therefore killed the bootstrap before it could
        # exec anything, and the Pod never started.  The ceiling is applied the
        # moment the workload has replaced it, which the gate observes exactly.
        # The CPU ceiling is deferred for the same reason: under a 10m limit the
        # bootstrap got 1 ms of CPU per 100 ms period and building a rootfs
        # took ten seconds or more, where runc's Go init needs a few ms.
        DEFERRED_LIMIT_FILES = %w[memory.max memory.high memory.swap.max cpu.max].freeze

        # The Pod cgroup's cpu/memory settings and memory usage as the kernel
        # reports them (kubelet GetPodCgroupConfig / PodCPUAndMemoryStats), for
        # status.resources and the memory-limit-below-usage resize check.
        POD_CGROUP_FILES = %w[cpu.weight cpu.max memory.max memory.current].freeze

        # Kernel-observed limits for a container cgroup, for status/evidence.
        def container_cgroup_readback(value)
          _sandbox, container = find_container(value)
          return {} unless container.cgroup

          @cgroup.limits_readback(container.cgroup)
        end

        def stats(value)
          _sandbox, container = find_container(value)
          raise InvalidState, "stats require a started container" unless container.process

          @process_supervisor.stats(container.process)
        end

        # The CPU manager's reconcile (UpdateContainerResources with only
        # CpusetCpus): re-pin a running container as the shared pool changes.
        def update_container_cpuset(value, cpus)
          sandbox, container = find_container(value)
          return false unless container.cgroup

          @cgroup.configure(container.cgroup, {"cpuset.cpus" => cpus.to_s})
          spec = normalize_hash(container.spec)
          spec["limits"] = normalize_hash(spec["limits"] || {}).merge("cpuset.cpus" => cpus.to_s)
          sandbox.update_container(container, spec: immutable(spec))
          record(:container_cpuset_updated, sandbox_id: sandbox.id, container_id: container.id, cpus: cpus.to_s)
          true
        end

        # InPlacePodVerticalScaling: apply new requests/limits to a running
        # container's cgroup (and the Pod cgroup) without recreating it.
        def update_container_resources(value, resources:, pod_spec: nil)
          sandbox, container = find_container(value)
          spec = normalize_hash(container.spec).merge("resources" => normalize_hash(resources))
          spec.delete("limits")
          spec.delete(:limits)
          qos = normalize_qos(sandbox.config)
          limits = container_cgroup_limits(spec, qos: qos, pod: pod_spec ? {"spec" => normalize_hash(pod_spec)} : sandbox.config)
          @cgroup.configure(container.cgroup, limits) if container.cgroup
          @mutex.synchronize { @deferred_memory_limits.delete(container_resource_id(sandbox, container)) }
          sandbox.update_container(container, spec: immutable(spec))
          if pod_spec && sandbox.cgroup
            pod_limits = pod_cgroup_limits(normalize_hash(sandbox.config).merge("spec" => normalize_hash(pod_spec), "pod_limits" => nil))
            @cgroup.configure_pod(sandbox.cgroup, pod_limits) unless pod_limits.nil? || pod_limits.empty?
          end
          record(:container_resized, sandbox_id: sandbox.id, container_id: container.id, limits: limits)
          limits
        end

        def pod_cgroup_readback(sandbox_id)
          sandbox = @mutex.synchronize { @sandboxes[String(sandbox_id)] }
          return nil unless sandbox && sandbox.cgroup

          @cgroup.pod_limits_readback(sandbox.cgroup, files: POD_CGROUP_FILES)
        rescue Platform::Linux::CgroupV2::Error, SystemCallError
          nil
        end

        # Raw usage for the kubelet stats provider: the Pod cgroup and each
        # running container's cgroup (cpu.stat / memory.stat / memory.current),
        # the container's start time and workspace (writable layer) path.
        def pod_usage(sandbox_id)
          sandbox = @mutex.synchronize { @sandboxes[String(sandbox_id)] }
          return nil unless sandbox && sandbox.cgroup && cgroup_reports_usage?

          containers = sandbox.containers.filter_map { |entry| container_usage(sandbox, entry) }
          netns_pid = netns_holder_pid(sandbox)
          {"pod" => @cgroup.usage(sandbox.cgroup, pod: true), "containers" => containers, "netns_pid" => netns_pid}
        rescue Platform::Linux::CgroupV2::Error, SystemCallError
          nil
        end

        # InPlacePodLevelResourcesVerticalScaling: the Pod cgroup follows new
        # pod-level requests/limits (cm.ResourceConfigForPod), and every
        # container that takes its CPU or memory limit from the Pod's follows too.
        def update_pod_resources(sandbox_id, pod_spec:)
          sandbox = @mutex.synchronize { @sandboxes[String(sandbox_id)] }
          raise Error, "unknown sandbox #{sandbox_id}" unless sandbox

          spec = normalize_hash(pod_spec)
          config = normalize_hash(sandbox.config).merge("spec" => spec, "pod_limits" => nil)
          pod_limits = pod_cgroup_limits(config)
          @cgroup.configure_pod(sandbox.cgroup, pod_limits) if sandbox.cgroup && !pod_limits.empty?
          qos = normalize_qos(sandbox.config)
          sandbox.containers.each do |entry|
            container = sandbox.container(entry["id"] || entry[:id])
            next unless container.cgroup

            limits = container_cgroup_limits(normalize_hash(container.spec), qos: qos, pod: {"spec" => spec})
            @cgroup.configure(container.cgroup, limits.slice("cpu.max", "memory.max"))
          end
          sandbox.update_config(immutable(config))
          record(:pod_resized, sandbox_id: sandbox.id, limits: pod_limits)
          pod_limits
        end

        private

        # One running container's entry of #pod_usage; a container that is
        # not running, or whose cgroup vanished under the read, has none.
        def container_usage(sandbox, entry)
          container = sandbox.container(entry["id"] || entry[:id])
          return nil unless container.state == :running && container.cgroup

          spec = normalize_hash(container.spec)
          process = container.process.to_h
          {"id" => container.id, "name" => (spec["name"] || spec[:name]).to_s, "usage" => @cgroup.usage(container.cgroup),
           "image" => (spec["image"] || spec[:image]).to_s,
           # The writable layer (overlay upper) and the log directory: what
           # the container's rootfs/logs ephemeral storage is measured on.
           "rootfs" => entry["workspace"].is_a?(Hash) ? (entry["workspace"]["upper"] || entry["workspace"][:upper]) : nil,
           "logs" => config.log_root ? File.join(config.log_root, "process-#{sandbox.id}-#{container.id}") : nil,
           "pid" => process["workload_pid"] || process["pid"]}
        rescue Platform::Linux::CgroupV2::Error, Sandbox::Error
          nil
        end

        # The network namespace holder, or nil while the sandbox has no
        # verifiable network namespace (Sandbox#network_sandbox_context).
        def netns_holder_pid(sandbox)
          sandbox.network_sandbox_context.dig("netns", "pid")
        rescue Sandbox::Error
          nil
        end

        def pod_cgroup_limits(input)
          explicit = input["pod_limits"] || input[:pod_limits]
          return normalize_hash(explicit) if mapping?(explicit) && !explicit.to_h.empty?
          return {} unless (input["spec"] || input[:spec]).is_a?(Hash)

          Resources.pod_cgroup_limits(input, qos: normalize_qos(input), memory_qos: config.memory_qos, pids_limit: config.pod_pids_limit)
        end

        # Explicit `limits` win; otherwise the v1.36.2 container formulas are
        # applied to `resources`, including the BestEffort defaults
        # (cpu.weight=1, cpu.max=max) when nothing was requested.
        def container_cgroup_limits(input, qos:, pod: nil)
          pod_spec = pod && (pod["spec"] || pod[:spec])
          derived = Resources.container_cgroup_limits(input, qos: qos, memory_qos: config.memory_qos,
                                                             pids_limit: input["pids_limit"] || input[:pids_limit] || config.pod_pids_limit,
                                                             pod: pod_spec.is_a?(Hash) ? pod_spec : nil)
          explicit = input["limits"] || input[:limits] || {}
          derived.merge(normalize_hash(explicit))
        end

        # Splits +limits+ into what is written when the cgroup is created and
        # what waits for the workload (see DEFERRED_LIMIT_FILES), remembering
        # the latter under +key+ for #apply_deferred_memory_limits.  Returns
        # the limits to apply now.
        def defer_bootstrap_limits(key, limits)
          deferred = limits.select { |name, _| DEFERRED_LIMIT_FILES.include?(name.to_s) }
          @mutex.synchronize { @deferred_memory_limits[key] = deferred } unless deferred.empty?
          limits.reject { |name, _| DEFERRED_LIMIT_FILES.include?(name.to_s) }
        end

        def apply_deferred_memory_limits(sandbox, container)
          return unless container.cgroup

          key = container_resource_id(sandbox, container)
          pod_key = "pod:#{sandbox.id}"
          deferred, pod_deferred = @mutex.synchronize do
            [@deferred_memory_limits.delete(key), @deferred_memory_limits.delete(pod_key)]
          end
          @cgroup.configure_pod(sandbox.cgroup, pod_deferred) if pod_deferred && !pod_deferred.empty? && sandbox.cgroup
          return if deferred.nil? || deferred.empty?

          @cgroup.configure(container.cgroup, deferred)
        rescue Platform::Linux::CgroupV2::Error => error
          record(:cgroup_memory_limit_failed, container_id: container.id, error: error.message)
          raise
        end

        def record_oom_baseline(sandbox, container)
          return unless container.cgroup

          key = container_resource_id(sandbox, container)
          count = @cgroup.oom_kill_count(container.cgroup)
          @mutex.synchronize do
            @oom_baselines[key] = count
            @oom_reported.delete(key)
          end
        rescue Platform::Linux::CgroupV2::Error => error
          record(:oom_baseline_unavailable, sandbox_id: sandbox.id, container_id: container.id, error: error.message)
        end

        # memory.events oom_kill is cumulative; the reason is attributed to the
        # first exit observed after the counter moved and never repeated
        # (§5.8.8: "exit reason と Pod status へ一度だけ反映する").
        def detect_oom(sandbox, container)
          return nil unless container.cgroup

          key = container_resource_id(sandbox, container)
          baseline = @mutex.synchronize { @oom_baselines[key] }
          return nil if baseline.nil?

          current = @cgroup.oom_kill_count(container.cgroup)
          return nil unless current > baseline

          already = @mutex.synchronize do
            reported = @oom_reported.key?(key)
            @oom_reported[key] = current
            @oom_baselines[key] = current
            reported
          end
          return nil if already

          record(:container_oom_killed, sandbox_id: sandbox.id, container_id: container.id, oom_kill: current - baseline)
          "OOMKilled"
        rescue Platform::Linux::CgroupV2::Error => error
          record(:oom_events_unavailable, sandbox_id: sandbox.id, container_id: container.id, error: error.message)
          nil
        end

        def normalize_qos(input)
          value = input["qos"] || input[:qos] || input["qos_class"] || input[:qos_class]
          value ||= (input["spec"] || input[:spec]).is_a?(Hash) ? Resources.qos_class(input) : "besteffort"
          normalized = String(value).downcase
          normalized = {"Guaranteed" => "guaranteed", "Burstable" => "burstable", "BestEffort" => "besteffort"}.fetch(String(value), normalized)
          raise ConfigurationError, "qos must be Guaranteed, Burstable, or BestEffort" unless %w[guaranteed burstable besteffort].include?(normalized)

          normalized
        end
      end
    end
  end
end
