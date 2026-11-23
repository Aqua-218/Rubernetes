# frozen_string_literal: true

require_relative "../cpu_quota"

module Rubernetes
  module Runtime
    module CRI
      module ResourceLimits
        attr_writer :cpu_quota_exemptions

        def update_container_resources(container, legacy_resources = nil, resources: legacy_resources, pod_spec: nil, **_options)
          id = key(container)
          entry, name = @mutex.synchronize { [@sandboxes[@containers.dig(id, :sandbox)], @containers.dig(id, :name)] }
          pod = entry && entry[:pod]
          pod = (pod || {}).merge("spec" => stringify(pod_spec)) if pod_spec
          apply_container_resources(id, {"name" => name, "resources" => stringify(resources || {})}, pod)
          update_pod_cgroup(entry, pod) if entry && pod_spec
          true
        end

        def update_container_cpuset(container, cpus)
          @client.runtime("UpdateContainerResources", {"container_id" => key(container), "linux" => {"cpuset_cpus" => cpus.to_s}})
          true
        end

        def update_pod_resources(sandbox, pod_spec:)
          id = key(sandbox)
          entry = @mutex.synchronize { @sandboxes[id] } or raise Backend::Error, "unknown sandbox #{id}"
          pod = entry.fetch(:pod).merge("spec" => stringify(pod_spec))
          update_pod_cgroup(entry, pod)
          update_inherited_cpu_limits(id, pod) if @cpu_cfs_quota
          true
        end

        def pod_cgroup_readback(sandbox)
          cgroup = @mutex.synchronize { @sandboxes.dig(key(sandbox), :cgroup) }
          return unless cgroup

          %w[cpu.max cpu.weight memory.max memory.current].to_h do |file|
            path = File.join(@cgroup_root, cgroup, file)
            [file, File.exist?(path) ? File.read(path).strip : nil]
          end.compact
        rescue Errno::ENOENT
          nil
        end

        private

        def apply_container_resources(id, spec, pod)
          @client.runtime("UpdateContainerResources", {"container_id" => id, "linux" => linux_resources(spec, pod: pod)})
        end

        def update_inherited_cpu_limits(sandbox, pod)
          return if milli(pod.dig("spec", "resources", "limits", "cpu")).to_i.zero?

          init = ResourceHelpers.containers(pod, "initContainers").select { |container| container["restartPolicy"] == "Always" }
          applications = ResourceHelpers.containers(pod, "containers")
          inheriting = (init + applications).select { |container| milli(container.dig("resources", "limits", "cpu")).to_i.zero? }
            .to_h { |container| [container.fetch("name"), container] }
          return if inheriting.empty?

          containers = @mutex.synchronize { @containers.select { |_id, value| value[:sandbox] == sandbox } }
          containers.each do |id, container|
            spec = inheriting[container[:name]]
            next unless spec

            status = @client.runtime("ContainerStatus", {"container_id" => id})["status"]
            apply_container_resources(id, spec, pod) if status && status["state"] == "CONTAINER_RUNNING"
          end
        end

        # kubelet's pod container manager + ResourceConfigForPod: the Pod's
        # cgroup with its requests as CPU weight and, when every container
        # declares them (or the Pod does), its CPU quota and memory limit.
        def create_pod_cgroup(pod)
          return nil if @cgroup_parent.nil?

          relative = pod_cgroup_path(pod.dig("metadata", "uid"))
          raise Backend::Error, "a Pod without a valid uid has no cgroup" unless relative

          enable_controllers(relative)
          write_pod_cgroup(relative, pod)
          relative
        end

        def pod_cgroup_path(uid)
          return unless @cgroup_parent && uid.to_s.match?(/\A[A-Za-z0-9_.-]+\z/)

          File.join(@cgroup_parent, "pod#{uid}")
        end

        def update_pod_cgroup(entry, pod)
          write_pod_cgroup(entry[:cgroup], pod) if entry[:cgroup]
          @mutex.synchronize { entry[:pod] = pod }
        end

        def write_pod_cgroup(relative, pod)
          pod_cgroup_settings(pod).each do |file, value|
            path = File.join(@cgroup_root, relative, file)
            File.write(path, value) if File.exist?(path)
          end
        end

        def pod_cgroup_settings(pod)
          qos = ResourceHelpers.qos_class(pod)
          return {"cpu.weight" => "1"} if qos == "BestEffort"

          requests = ResourceHelpers.pod_requests(pod)
          limits = ResourceHelpers.pod_limits(pod)
          cpu_request = requests["cpu"]&.milli_value.to_i
          shares = cpu_request.zero? ? 2 : [[(cpu_request * 1024) / 1000, 2].max, 262_144].min
          settings = {"cpu.weight" => (1 + (((shares - 2) * 9999) / 262_142)).to_s}
          if qos == "Guaranteed" || declared_for_all?(pod, "cpu")
            cpu_limit = limits["cpu"]&.milli_value.to_i
            enforce_cpu_quota = @cpu_cfs_quota && !@cpu_quota_exemptions&.pod_cpu_quota_exempt?(pod)
            settings["cpu.max"] = CPUQuota.cgroup_limit(cpu_limit, period: @cpu_period, enabled: enforce_cpu_quota)
          end
          settings["memory.max"] = limits["memory"].value.ceil.to_s if (qos == "Guaranteed" || declared_for_all?(pod, "memory")) && limits["memory"]
          if @memory_qos && requests["memory"]
            settings.merge!(MemoryQoS.reservation(requests["memory"].value.ceil, qos: qos, policy: @memory_reservation_policy))
          end
          settings
        end

        def declared_for_all?(pod, resource)
          return true if pod.dig("spec", "resources", "limits", resource)

          containers = ResourceHelpers.containers(pod, "containers") + ResourceHelpers.containers(pod, "initContainers")
          !containers.empty? && containers.all? { |container| container.dig("resources", "limits", resource) }
        end

        # kuberuntime's CPU shares/quota and memory limit.
        def linux_resources(spec, pod: nil)
          resources = spec["resources"] || {}
          requests = resources["requests"] || {}
          limits = resources["limits"] || {}
          result = {}
          cpu_limit = milli(limits["cpu"])
          cpu_limit = milli(pod&.dig("spec", "resources", "limits", "cpu")) if cpu_limit.to_i.zero?
          cpu_request = milli(requests["cpu"]) || cpu_limit
          result["cpu_shares"] = cpu_request.nil? ? 2 : [[(cpu_request * 1024) / 1000, 2].max, 262_144].min
          if @cpu_cfs_quota
            result["cpu_period"] = @cpu_period
            exempt = @cpu_quota_exemptions&.container_cpu_quota_exempt?(pod, spec)
            result["cpu_quota"] = exempt ? -1 : CPUQuota.from_milli_cpu(cpu_limit.to_i, @cpu_period)
          end
          %w[cpus mems].each do |suffix|
            affinity = spec.dig("limits", "cpuset.#{suffix}")
            result["cpuset_#{suffix}"] = affinity if affinity
          end
          if (memory = bytes(limits["memory"]))
            result["memory_limit_in_bytes"] = memory
          end
          if @memory_qos
            qos = ResourceHelpers.qos_class(pod || {})
            result["unified"] = MemoryQoS.container(request: bytes(requests["memory"]).to_i, limit: memory.to_i, qos: qos,
                                                    policy: @memory_reservation_policy, factor: @memory_throttling_factor,
                                                    allocatable: @memory_qos_allocatable)
          end
          (result["unified"] ||= {})["memory.oom.group"] = "1" if @group_oom_kill
          (result["unified"] ||= {})[Platform::Linux::SwapController::LIMIT] = "0" if @swap_controller
          result
        end

        def milli(value)
          return nil if value.nil?

          (Schema::Quantity.from_json(value.to_s).value * 1000).ceil
        end

        def bytes(value)
          return nil if value.nil?

          Schema::Quantity.from_json(value.to_s).value.ceil
        end
      end
    end
  end
end
