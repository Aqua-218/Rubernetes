# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # CgroupV2 already contains path and value validation.  This wrapper
        # adds the host-profile capability contract and keeps the production
        # adapter distinguishable from FakeCgroup/RecordingAdapter.
        class CgroupAdapter
          include CapabilityContract

          def initialize(root:, adapter: CgroupV2::FileAdapter.new)
            @root = File.expand_path(String(root))
            @delegate = CgroupV2.new(root: root, adapter: adapter)
          end

          def native_capabilities
            {cgroup_v2: cgroup_mount_available?}.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:cgroup_v2), "cgroup v2 is unavailable")
            true
          end

          def available?
            @delegate.available?
          end

          def create(**arguments) = @delegate.create(**arguments)
          def configure(handle, limits) = @delegate.configure(handle, limits)
          def configure_pod(handle, limits) = @delegate.configure_pod(handle, limits)
          def limits_readback(handle, **) = @delegate.limits_readback(handle, **)
          def pod_limits_readback(handle, **) = @delegate.pod_limits_readback(handle, **)
          def oom_kill_count(handle) = @delegate.oom_kill_count(handle)
          def attach(handle, pid:) = @delegate.attach(handle, pid: pid)
          def open_procs(handle) = @delegate.open_procs(handle)
          def kill(handle) = @delegate.kill(handle)
          def remove(handle, force: false) = @delegate.remove(handle, force: force)
          def stats(handle) = @delegate.stats(handle)
          # cpu.stat / memory.stat / memory.current / pids.current of a
          # container cgroup, or of the Pod cgroup above it (pod: true).
          # Runtime::Native#pod_usage feeds /stats/summary, /metrics/resource
          # and metrics.k8s.io from this; without it every Pod's CPU and
          # memory were simply absent from all three.
          def usage(handle, pod: false) = @delegate.usage(handle, pod: pod)
          def events(handle) = @delegate.events(handle)
          def resources = @delegate.resources
          def lookup(value) = @delegate.lookup(value)

          private

          def cgroup_mount_available?
            return true if @delegate.probe.available?

            mount_root = @root
            mount_root = File.dirname(mount_root) until File.directory?(mount_root) || mount_root == File.dirname(mount_root)
            controllers_path = File.join(mount_root, "cgroup.controllers")
            return false unless File.file?(controllers_path)

            controllers = File.read(controllers_path).split
            %w[cpu memory pids].all? { |name| controllers.include?(name) }
          rescue SystemCallError
            false
          end
        end
      end
    end
  end
end
