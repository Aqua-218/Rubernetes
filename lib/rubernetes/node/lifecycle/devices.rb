# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Devices a container is given: device plugin allocations, DRA claims
      # with their CDI devices, and the CPU/memory managers' affinity.
      module Devices
        # allocatedResourcesStatus: device plugin resources, then DRA claims.
        def resource_health(record, entry)
          # Health is informational: a failing lookup never blocks status.
          best_effort([]) { device_health(record, entry) }
        end

        private

        def device_health(record, entry)
          health = []
          health.concat(@device_plugins.allocated_resources_status(record[:uid], entry[:name])) if @device_plugins
          if @dra_manager
            claims = Helpers.key(Helpers.key(entry[:spec] || {}, "resources", {}) || {}, "claims", nil)
            if claims.is_a?(Array) && !claims.empty?
              health.concat(@dra_manager.allocated_resources_status(Helpers.string_keys(record[:pod]), Helpers.string_keys(entry[:spec])))
            end
          end
          health
        end

        # The container's device plugin allocation: environment, device nodes
        # and mounts from Allocate, and its CDI devices.
        def apply_device_plugin_allocation(record, spec, definition)
          return spec if @device_plugins.nil?

          allocation = @device_plugins.container_allocation(record[:uid], Helpers.key(definition, "name", ""))
          return spec if allocation.nil?

          env = Array(spec["env"]).map(&:dup)
          allocation["envs"].each do |name, value|
            env.reject! { |entry| entry["name"] == name }
            env << {"name" => name.to_s, "value" => value.to_s}
          end
          spec["env"] = env
          mounts = Array(spec["mounts"]).dup
          allocation["mounts"].each_with_index do |mount, index|
            mounts << {"name" => "device-plugin-mount-#{index}", "source" => mount["host_path"].to_s, "destination" => mount["container_path"].to_s,
                       "readonly" => mount["read_only"] == true, "propagation" => "None"}
          end
          allocation["devices"].each_with_index do |device, index|
            host = device["host_path"].to_s
            raise LifecycleError, "device plugin device #{host} does not exist on the node" unless File.exist?(host)

            mount = {"name" => "device-plugin-device-#{index}", "source" => host,
                     "destination" => (device["container_path"].to_s.empty? ? host : device["container_path"].to_s),
                     "readonly" => false, "propagation" => "None", "device" => true}
            # DeviceSpec.permissions ("rwm" subset) become the cgroup rule.
            mount["permissions"] = device["permissions"].to_s unless device["permissions"].to_s.empty?
            mounts << mount
          end
          spec["mounts"] = mounts
          ids = allocation["cdi_devices"].map { |device| device["name"].to_s }.reject(&:empty?)
          spec = CDI.apply(spec, CDI.resolve(ids, spec_dirs: @cdi_spec_dirs)) unless ids.empty?
          spec
        rescue CDI::Error => error
          record[:reason] = "CreateContainerError"
          raise LifecycleError,
                "container #{Helpers.key(definition, "name", "").inspect}: device plugin CDI injection failed: #{error.message}"
        end

        def dynamic_resources?(pod)
          return false if @dra_manager.nil?

          !Array(Helpers.key(Helpers.key(pod, "spec", {}), "resourceClaims", [])).empty? ||
            !Helpers.key(Helpers.key(pod, "status", {}), "extendedResourceClaimStatus", nil).nil?
        end

        # kuberuntime SyncPod: PrepareDynamicResources before the sandbox.
        def prepare_dynamic_resources(pod, record)
          return unless dynamic_resources?(pod)

          timed(record, "dra.prepared") { @dra_manager.prepare_resources(Helpers.string_keys(pod)) }
          record[:dra_prepared] = true
        rescue StandardError => error
          detail = error.is_a?(DRAManager::Error) ? error.message : Helpers.failure_message(error)
          message = "Failed to prepare dynamic resources: #{detail}"
          event(record, "pod.dra_prepare_failed", message: message)
          record[:reason] = "ContainerCreating"
          raise DynamicResourcesError, message
        end

        # GetResources: the container's CDI devices, applied through CDI edits
        # (containerd's "CDI device injection").
        def apply_cdi_devices(record, spec, definition)
          return spec unless dynamic_resources?(record[:pod])
          if Array(Helpers.key(Helpers.key(definition, "resources", {}), "claims", [])).empty? &&
             Helpers.key(Helpers.key(record[:pod], "status", {}), "extendedResourceClaimStatus", nil).nil?
            return spec
          end

          ids = @dra_manager.container_cdi_devices(Helpers.string_keys(record[:pod]), Helpers.string_keys(definition))
          return spec if ids.empty?

          CDI.apply(spec, CDI.resolve(ids, spec_dirs: @cdi_spec_dirs))
        rescue CDI::Error, DRAManager::Error => error
          record[:reason] = "CreateContainerError"
          raise LifecycleError, "container #{Helpers.key(definition, "name", "").inspect}: CDI device injection failed: #{error.message}"
        end

        # PreCreateContainer: the container's cpuset.cpus (its exclusive CPUs,
        # or the shared pool) and cpuset.mems (its NUMA nodes), as explicit
        # cgroup settings.
        def apply_resource_affinity(record, spec, definition)
          return spec unless @container_manager && spec.is_a?(Hash)

          limits = @container_manager.container_limits(Helpers.string_keys(record[:pod]), Helpers.string_keys(definition))
          return spec if limits.empty?

          spec["limits"] = Helpers.string_keys(spec["limits"] || {}).merge(limits)
          spec
        end

        # PreStartContainer.
        def pre_start_container(record, entry)
          return unless @container_manager

          @container_manager.pre_start(Helpers.string_keys(record[:pod]), Helpers.string_keys(entry[:spec] || {}), entry[:id])
        end
      end
    end
  end
end
