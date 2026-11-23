# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # kubelet /metrics: one KubeletMetrics, told about by every manager the
      # agent built, and the admission handlers the managers contribute.
      module Instrumentation
        private

        def initialize_metrics(image_resolver)
          @kubelet_metrics = KubeletMetrics.new(node_name: @node_name)
          @kubelet_metrics.plugin_manager = @plugin_manager if @plugin_manager
          @kubelet_metrics.pull_records = image_resolver.pull_records if image_resolver&.pull_records
          metrics = @kubelet_metrics
          @csi_plugins&.metrics_observer = lambda { |driver, method_name, code, seconds|
            metrics.csi_operation(driver, method_name, code, seconds)
          }
          return unless @container_manager

          @container_manager.metrics = metrics.registry
          start_container_manager
        end

        # The observers that need the lifecycle and the managers built after
        # it (the registry exists from the container manager's start).
        def attach_observers
          metrics = @kubelet_metrics
          lifecycle = @lifecycle
          @dra_manager.active_pods = -> { lifecycle.admitted_pods } if @dra_manager
          @stats_provider.metrics_observer = ->(source, seconds) { metrics.volume_metric_collection(source, seconds) } if @stats_provider
          @lifecycle.metrics_observer = metrics
          metrics.pod_inventory = method(:pod_metrics_inventory)
          attach_selinux_tracker
          attach_pod_certificate_manager
          @status.sync_observer = ->(pod, status, seconds) { metrics.pod_status_synced(pod, status, seconds) }
          [@image_gc_manager, *@cri_image_gc_managers].compact.each do |manager|
            manager.on_collected = ->(reason) { metrics.image_garbage_collected(reason) }
          end
          return unless @eviction_manager

          @eviction_manager.on_eviction = ->(signal) { metrics.eviction(signal) }
          @eviction_manager.on_stats_age = ->(signal, seconds) { metrics.eviction_stats_age(signal, seconds) }
        end

        def pod_metrics_inventory
          mirrors, api_pods = @sync_loop.pods.partition { |pod| mirror_pod?(pod) }
          [api_pods + Array(@static_pods&.pods), mirrors.length]
        end

        # canAdmitPod: the eviction manager (node under pressure), the
        # resource managers (no CPUs/NUMA fit) and the shutdown manager each
        # get a say.
        def attach_admit_handlers
          @admission.eviction_admit_handler = @eviction_manager.method(:admit) if @eviction_manager
          @admission.allocation_admit_handler = @container_manager.method(:admit) if @container_manager
          @admission.shutdown_admit_handler = @shutdown_manager.method(:admit) if @shutdown_manager
        end

        def attach_metrics_registry
          registry = @kubelet_metrics.registry
          [@pod_resources, @device_plugins, @dra_manager, @credential_providers].compact.each { |manager| manager.metrics = registry }
          if @qos_cgroup_manager
            metrics = @kubelet_metrics
            @qos_cgroup_manager.cgroup_observer = ->(operation, seconds) { metrics.cgroup_operation(operation, seconds) }
          end
          attach_memory_qos_metrics(registry) if @feature_gates["MemoryQoS"] == true
          @shutdown_manager.gauge_sink = ->(name, value) { registry.set(name, value) } if @shutdown_manager
        end

        def attach_runtime_handlers(shutdown_manager, shutdown, feature_gates)
          attach_observers
          initialize_shutdown(shutdown_manager, shutdown, feature_gates)
          attach_metrics_registry
          attach_admit_handlers
        end

        def attach_memory_qos_metrics(registry)
          min = "kubelet_memory_qos_node_memory_min_bytes"
          low = "kubelet_memory_qos_node_memory_low_bytes"
          registry.register(min, type: :gauge, help: "Total cgroup v2 memory.min in bytes for Guaranteed pods.")
          registry.register(low, type: :gauge, help: "Total cgroup v2 memory.low in bytes for Burstable pods.")
          [min, low].each { |name| registry.set(name, 0) }
          return unless @qos_cgroup_manager.is_a?(QOSCgroupManager)

          @qos_cgroup_manager.memory_qos_gauge = lambda do |guaranteed, burstable|
            registry.set(min, guaranteed)
            registry.set(low, burstable)
          end
        end
      end
    end
  end
end
