# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # The kubelet's managers the agent builds for a real node: resources
      # (CPU, memory, topology, QoS cgroups), eviction, image garbage
      # collection, graceful shutdown and critical-Pod preemption.  Each is
      # skipped when its configuration or its inputs are absent.
      module Managers
        private

        # GetNodeAllocatableReservation.  reservedSystemCPUs replaces the CPU
        # of both reservations with its own size (kubelet server.go).
        def node_allocatable_reservation(system_reserved, kube_reserved, reserved_system_cpus, eviction, host:)
          system, kube = reserved_resources(system_reserved, kube_reserved, reserved_system_cpus)
          config = Helpers.string_keys(eviction || {})
          hard = []
          if host && config.fetch("enabled", true) != false
            hard = EvictionManager.parse_threshold_config(hard: config.fetch("hard", EvictionManager::DEFAULT_EVICTION_HARD),
                                                          allocatable_config: [])
          end
          return {} if system.empty? && kube.empty? && hard.empty?

          NodeAllocatable.reservation(capacity: @capacity, system_reserved: system, kube_reserved: kube, hard_thresholds: hard)
        end

        # [system-reserved, kube-reserved] with reservedSystemCPUs applied.
        def reserved_resources(system_reserved, kube_reserved, reserved_system_cpus)
          system = Helpers.string_keys(system_reserved || {})
          kube = Helpers.string_keys(kube_reserved || {})
          unless reserved_system_cpus.nil? || reserved_system_cpus.to_s.empty?
            system["cpu"] = CPUManager::CPUSet.parse(reserved_system_cpus.to_s).size.to_s
            kube.delete("cpu")
          end
          [system, kube]
        end

        def build_container_manager(kubelet_root, host, cpu, memory, topology, reserved_system_cpus, error_handler)
          configured = [cpu, memory, topology].any? { |config| !Helpers.string_keys(config || {}).empty? }
          return nil unless kubelet_root && (host || configured)

          # PodLevelResourceManagers (alpha, off) needs PodLevelResources (on).
          pod_level = @feature_gates["PodLevelResourceManagers"] == true && @feature_gates.fetch("PodLevelResources", true) != false
          ContainerManager.new(state_directory: kubelet_root, reservation: @reservation, cpu: cpu, memory: memory, topology: topology,
                               reserved_system_cpus: reserved_system_cpus, pod_level_resource_managers: pod_level,
                               feature_gates: @feature_gates)
        rescue ContainerManager::Error, CPUManager::Topology::Error, SystemCallError => error
          # A configured policy that cannot run is fatal, as for the kubelet;
          # the default (none) policies must not keep the node from starting.
          raise if configured

          error_handler&.call(error, :container_manager)
          nil
        end

        def start_container_manager
          lifecycle = @lifecycle
          @container_manager.start(
            active_pods: -> { lifecycle.admitted_pods(include_allocating: true) },
            container_statuses: ->(pod) { lifecycle.container_states(Helpers.key(Helpers.key(pod, "metadata", {}), "uid", "")) },
            update_cpuset: ->(container_id, cpus) { @runtime.update_container_cpuset(container_id, cpus) if runtime_moves_cpusets? },
            sources_ready: -> { @recovered }
          )
        end

        # enforceNodeAllocatable ("pods" by default) over capacity less
        # system-reserved and kube-reserved; reservedSystemCPUs replaces both
        # reservations' CPU, as for the allocatable reported.
        def build_qos_cgroup_manager(config, system_reserved, kube_reserved, reserved_system_cpus, error_handler, host)
          config = Helpers.string_keys(config || {})
          return nil if !host || config.empty? || config["enabled"] == false

          system, kube = reserved_resources(system_reserved, kube_reserved, reserved_system_cpus)
          reference = node_reference
          QOSCgroupManager.new(
            root: config.fetch("root"), hierarchy: config.fetch("hierarchy", "rubernetes"), capacity: @capacity, node_name: @node_name,
            system_reserved: system, kube_reserved: kube,
            enforce_node_allocatable: config.fetch("enforce_node_allocatable", ["pods"]),
            system_reserved_cgroup: config["system_reserved_cgroup"], kube_reserved_cgroup: config["kube_reserved_cgroup"],
            reserved_memory_percent: (QOSCgroupManager.parse_reserved_memory(config.fetch("qos_reserved", {})) if @feature_gates["QOSReserved"] == true),
            memory_qos_policy: (config.fetch("memory_reservation_policy", "None") if @feature_gates["MemoryQoS"] == true),
            active_pods: -> { @lifecycle.admitted_pods },
            event: lambda { |type, reason, message|
              @event_recorder&.record(involved_object: reference, reason: reason, type: type, namespace: "default", message: message)
            },
            error_handler: error_handler
          )
        end

        # Image garbage collection over the resolver's unpacked images.
        def build_image_gc_manager(image_resolver, image_gc, error_handler)
          return nil unless image_resolver && @stats_provider && image_gc.fetch("enabled", true) != false
          return nil if @default_cri_client && (!@stats_provider.is_a?(StatsProvider) || native_container_root.nil?)

          lifecycle = @lifecycle
          reclaim = image_resolver.method(:reclaim_unused_stages) if defined?(Image::Resolver) && image_resolver.is_a?(Image::Resolver)
          stats = -> { @default_cri_client ? @stats_provider.native_image_fs_stats : @stats_provider.image_fs_stats }
          ImageGCManager.new(resolver: image_resolver, fs_stats: stats, pods: -> { lifecycle.pods_on_node },
                             used_roots: -> { lifecycle.image_roots_in_use + runtime_image_roots }, reclaim_stages: reclaim,
                             **image_gc_options(image_gc, error_handler))
        end

        def runtime_image_roots
          return [] unless defined?(Runtime::Native) && defined?(Image::StagingLease)

          (runtime_backends&.values || [@runtime]).grep(Runtime::Native).flat_map { |runtime| Image::StagingLease.runtime_roots(runtime.ledger) }
        end

        # The kubelet's image GC over each CRI runtime the node uses (one per
        # runtime connection, however many handlers share it), with the same
        # thresholds as the node's own images.
        def build_cri_image_gc_managers(image_gc, _node_reference, error_handler)
          return [] if image_gc.fetch("enabled", true) == false

          lifecycle = @lifecycle
          pods = -> { lifecycle.records.values.filter_map { |record| record[:pod] unless record[:state].to_s == "Removed" } }
          cri_clients.map do |client|
            source = Runtime::CRI::ImageGCSource.new(client: client, in_use: -> { images_in_use(pods.call) },
                                                     runtime_class_in_image_api: @feature_gates["RuntimeClassInImageCriApi"] == true)
            manager = ImageGCManager.new(resolver: source, fs_stats: -> { source.fs_stats }, pods: pods, **image_gc_options(image_gc, error_handler))
            @default_cri_image_gc_manager = manager if client.equal?(@default_cri_client)
            manager
          end
        end

        def image_gc_options(image_gc, error_handler)
          {
            high_threshold_percent: image_gc.fetch("high_threshold_percent", ImageGCManager::DEFAULT_HIGH_THRESHOLD_PERCENT),
            low_threshold_percent: image_gc.fetch("low_threshold_percent", ImageGCManager::DEFAULT_LOW_THRESHOLD_PERCENT),
            min_age: EvictionManager.parse_duration(image_gc.fetch("minimum_age", "2m")),
            max_age: EvictionManager.parse_duration(image_gc.fetch("maximum_age", "0s")),
            recorder: @event_recorder, node_ref: node_reference, error_handler: error_handler
          }
        end

        # The normalized references of every image the Pods name.
        def images_in_use(pods)
          images = Array(pods).flat_map do |pod|
            %w[initContainers containers ephemeralContainers].flat_map do |field|
              Array(pod.dig("spec", field)).map { |container| container["image"] }
            end
          end
          images.compact.to_set do |image|
            Image::Reference.parse(image.to_s).to_s
          rescue StandardError
            image.to_s
          end
        end

        def build_eviction_manager(config)
          thresholds = EvictionManager.parse_threshold_config(
            hard: config.fetch("hard", EvictionManager::DEFAULT_EVICTION_HARD),
            soft: config.fetch("soft", {}), soft_grace_period: config.fetch("soft_grace_period", {}),
            minimum_reclaim: config.fetch("minimum_reclaim", {})
          )
          lifecycle = @lifecycle
          stats = @stats_provider if @stats_provider.is_a?(StatsProvider) && !@default_cri_client
          image_fs = stats&.dedicated_image_fs?
          split_fs = stats&.split_container_fs? || false
          disk_summary = @stats_provider.method(:summary_with_filesystems) if @default_cri_client && @stats_provider.is_a?(StatsProvider)
          reclaim = if @default_cri_client
                      method(:cri_disk_reclaim_functions)
                    else
                      disk_reclaim_functions(image_fs: image_fs, split_fs: split_fs, manager: @image_gc_manager)
                    end
          EvictionManager.new(
            summary_provider: @stats_provider, thresholds: thresholds,
            active_pods: -> { lifecycle.admitted_pods },
            kill_pod: method(:evict_pod),
            pressure_transition_period: EvictionManager.parse_duration(config.fetch("pressure_transition_period", "5m")),
            max_pod_grace_period_seconds: config.fetch("max_pod_grace_period_seconds", 0),
            dedicated_image_fs: image_fs.nil? ? -> { @stats_provider.dedicated_image_fs? } : image_fs,
            split_container_fs: split_fs,
            node_reclaim: reclaim, disk_summary: disk_summary,
            recorder: @event_recorder,
            node_ref: node_reference,
            pod_cleaned_up: lambda { |pod|
              record = lifecycle.record(pod.dig("metadata", "uid").to_s)
              record.nil? || %w[Removed].include?(record[:state].to_s)
            },
            error_handler: @error_handler,
            on_conditions_changed: ->(_conditions) { persist_pressure_conditions }
          )
        end

        # buildSignalToNodeReclaimFuncs: disk signals first try deleting unused
        # images (dead containers are already removed when replaced).
        def cri_disk_reclaim_functions(layout)
          return {} unless layout

          image_fs, split_fs = layout
          disk_reclaim_functions(image_fs: image_fs, split_fs: split_fs, manager: @default_cri_image_gc_manager)
        end

        def disk_reclaim_functions(image_fs:, split_fs:, manager:)
          return {} unless manager

          delete_images = -> { manager.delete_unused_images }
          signals = [EvictionManager::IMAGEFS_AVAILABLE, EvictionManager::IMAGEFS_INODES_FREE]
          signals += [EvictionManager::NODEFS_AVAILABLE, EvictionManager::NODEFS_INODES_FREE] unless image_fs
          signals += [EvictionManager::CONTAINERFS_AVAILABLE, EvictionManager::CONTAINERFS_INODES_FREE] unless split_fs
          signals.to_h { |signal| [signal, [delete_images]] }
        end

        # killPodFunc: the Pod's own worker carries the eviction out.
        def evict_pod(pod, grace_period_seconds:, message:, condition:, reason: Lifecycle::EVICTED_REASON)
          uid = pod.dig("metadata", "uid").to_s
          @lifecycle.request_eviction(uid, message: message, grace_period_seconds: grace_period_seconds, condition: condition,
                                           reason: reason)
          @sync_loop.enqueue_pod(@sync_loop.cache[uid] || pod, action: "MODIFIED")
        end

        # nodeshutdown.NewManager with the kubelet's shutdownGracePeriod*
        # settings; nil (managerStub) without a grace period.
        def build_shutdown_manager(config, feature_gates, kubelet_root, error_handler)
          config = Helpers.string_keys(config || {})
          gates = Helpers.string_keys(feature_gates || {})
          lifecycle = @lifecycle
          ShutdownManager.build(
            gate: gates.fetch("GracefulNodeShutdown", true) != false,
            based_on_priority: gates.fetch("GracefulNodeShutdownBasedOnPodPriority", true) != false,
            grace_period: EvictionManager.parse_duration(config.fetch("grace_period", "0s")),
            critical_grace_period: EvictionManager.parse_duration(config.fetch("grace_period_critical_pods", "0s")),
            by_priority: Array(config["grace_period_by_pod_priority"]),
            active_pods: -> { lifecycle.admitted_pods },
            kill_pod: lambda { |pod, grace, message:, reason:, condition:|
              evict_pod(Helpers.string_keys(pod), grace_period_seconds: grace, message: message, condition: condition, reason: reason)
            },
            pod_terminated: lambda { |pod|
              record = lifecycle.record(Helpers.key(Helpers.key(pod, "metadata", {}), "uid", ""))
              record.nil? || Lifecycle::INACTIVE_STATES.include?(record[:state].to_s)
            },
            sync_node_status: -> { persist_node(build_node(ready: ready?)) if registered? },
            state_directory: kubelet_root, recorder: @event_recorder, node_ref: node_reference, error_handler: error_handler
          )
        end

        # preemption.NewCriticalPodAdmissionHandler(getAllocatedPods, killPodNow,
        # recorder): the admitted Pods and the eviction path are the
        # lifecycle's, looked up when a critical Pod is refused.
        def build_preemption
          Preemption.new(
            active_pods: -> { @lifecycle.admitted_pods },
            kill_pod: lambda { |pod, message:, condition:, reason:|
              evict_pod(Helpers.string_keys(pod), grace_period_seconds: nil, message: message, condition: condition, reason: reason)
            },
            recorder: @event_recorder,
            metrics: -> { @kubelet_metrics }
          )
        end

        def quantity_bytes(value)
          return nil if value.nil?

          Schema::Quantity.from_json(value).value.to_i
        end
      end
    end
  end
end
