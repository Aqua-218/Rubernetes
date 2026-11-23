# frozen_string_literal: true

require_relative "../system_oom_watcher"

module Rubernetes
  module Node
    class Agent
      # The constructor's steps, in the order #initialize runs them: what the
      # node is (name, resources, labels), then the collaborators that were
      # not injected, each built from the ones before it.
      module Wiring
        private

        def initialize_schedule(node_status_update_frequency, node_status_report_frequency, relist_period)
          @node_status_update_frequency = Float(node_status_update_frequency)
          @node_status_report_frequency = Float(node_status_report_frequency)
          @relist_period = Float(relist_period)
          @last_reported_status = nil
          @last_status_report_at = nil
          @node_status_condition = ConditionVariable.new
          @node_status_requested = false
        end

        def initialize_ports(node_name, api, runtime, clock:, sleeper:, error_handler:)
          raise ArgumentError, "node_name must not be empty" if node_name.to_s.empty?
          raise ArgumentError, "api is required" unless api

          initialize_state
          @node_name = node_name.to_s.freeze
          @api = api
          @runtime = runtime
          @clock = clock
          @sleeper = sleeper
          @error_handler = error_handler
        end

        def initialize_lease(node_namespace, lease_duration_seconds, lease_renew_fraction)
          @node_namespace = node_namespace.to_s.freeze
          @lease_duration_seconds = Integer(lease_duration_seconds)
          @lease_renew_fraction = Float(lease_renew_fraction)
          raise ArgumentError, "lease_duration_seconds must be positive" unless @lease_duration_seconds.positive?
          raise ArgumentError, "lease_renew_fraction must be between 0 and 1" unless @lease_renew_fraction.positive? && @lease_renew_fraction <= 1

          @lease_renew_interval = @lease_duration_seconds * @lease_renew_fraction
        end

        # +host+: a real node reports what the host has (kubelet: cAdvisor
        # machine info); injected capacity wins so tests and reservations stay
        # exact.  Node Allocatable is capacity less system-reserved,
        # kube-reserved and the hard eviction thresholds (a real node, or
        # reservations given).
        def initialize_node_resources(capacity, allocatable, reserved, eviction, host:, pod_root:, max_pods:, pods_per_core:)
          @host_node = host
          @kubelet_root = pod_root && File.dirname(File.expand_path(pod_root.to_s))
          detected = host ? HostResources.capacity(pod_root: pod_root, max_pods: max_pods, pods_per_core: pods_per_core) : {}
          @capacity = detected.merge(Helpers.string_keys(capacity)).freeze
          @reservation = node_allocatable_reservation(*reserved, eviction, host: host)
          @allocatable = if allocatable
                           Helpers.string_keys(allocatable).freeze
                         elsif @reservation.empty?
                           @capacity
                         else
                           NodeAllocatable.allocatable(@capacity, @reservation).freeze
                         end
          @host_info = host ? HostResources.node_info : {}
        end

        def initialize_node_identity(labels, annotations, addresses, architecture, operating_system, runtime_version, streaming_port,
                                     provider_id:, external_cloud_provider:, register_node:, register_with_taints:)
          @register_node = register_node
          # enableControllerAttachDetach (default true): the kubelet leaves
          # attach/detach to the controller manager and says so on the Node.
          @node_annotations = {"volumes.kubernetes.io/controller-managed-attach-detach" => "true"}
            .merge(Helpers.string_keys(annotations)).freeze
          @streaming_port = streaming_port
          @addresses = Helpers.string_keys(addresses).freeze
          # Kubernetes uses Go's GOARCH spelling ("amd64"), not uname's
          # ("x86_64"); node labels, image selection and nodeAffinity all match on
          # the Go form.
          @architecture = Registration.normalize_architecture(architecture).to_s.freeze
          # Kubernetes spells the OS the Go way ("linux"); RbConfig may say
          # "linux-gnu".
          @operating_system = (operating_system.to_s.start_with?("linux") ? "linux" : operating_system.to_s).freeze
          @node_labels = well_known_node_labels.merge(Helpers.string_keys(labels)).freeze
          @runtime_version = runtime_version.to_s.freeze
          @node_registration_spec = {}
          @node_registration_spec["providerID"] = provider_id if provider_id
          taints = Helpers.string_keys(register_with_taints).map { |taint| taint.slice("key", "value", "effect").compact }
          taints << {"key" => "node.cloudprovider.kubernetes.io/uninitialized", "value" => "true", "effect" => "NoSchedule"} if external_cloud_provider
          @node_registration_spec["taints"] = taints unless taints.empty?
        end

        # The kubelet always applies the well-known topology labels; anything
        # with a nodeSelector (conformance included) cannot land on a node
        # without them.  Configured labels win over the defaults.
        def well_known_node_labels
          {
            "kubernetes.io/hostname" => @node_name,
            "kubernetes.io/os" => @operating_system,
            "kubernetes.io/arch" => @architecture,
            "beta.kubernetes.io/os" => @operating_system,
            "beta.kubernetes.io/arch" => @architecture
          }.reject { |_key, value| value.to_s.empty? }
        end

        # Both static sources share the mirror and status lifecycle.
        def initialize_status(status, reporter, endpoint_manager, static_sources, feature_gates:)
          @static_pods = if static_sources[:path] || !static_sources[:url].to_s.empty?
                           StaticPods.new(node_name: @node_name, lifecycle: nil, api: @api, sleeper: @sleeper,
                                          logger: error_handler_logger(@error_handler), **static_sources)
                         end
          if @static_pods && reporter
            reporter = StaticPods::Reporter.new(reporter, @static_pods)
            report_target = reporter.method(:status_report_target)
          end
          @status = status || Status.new(endpoint_manager: endpoint_manager, reporter: reporter, report_target: report_target,
                                         clock: @clock, feature_gates: feature_gates)
          @static_pods.status_publisher = @status.method(:republish) if @static_pods && @status.is_a?(Status)
          reporter
        end

        def build_probe_manager(connectors, runtime)
          connectors ||= {}
          return nil if connectors.empty?

          ProbeManager.new(runtime: runtime, clock: @clock, sleeper: @sleeper,
                           http_client: connectors[:http] || connectors["http"],
                           tcp_client: connectors[:tcp] || connectors["tcp"],
                           grpc_client: connectors[:grpc] || connectors["grpc"])
        end

        # NodeDeclaredFeatures: what this node declares in status.declaredFeatures
        # (nil with the gate off), fixed for the life of the agent as upstream.
        #
        # kubelet admission on the node: sysctl allowlist, node selector/
        # affinity, OS/arch, resources, declared features.  Injected admission
        # (tests) wins.
        def initialize_admission(admission, feature_gates, runtime_features, allowed_unsafe_sysctls)
          @feature_gates = Helpers.string_keys(feature_gates || {}).freeze
          if @feature_gates["UserNamespacesHostNetworkSupport"] == true
            runtime_features = (runtime_features || {}).merge(DeclaredFeatures.discover_runtime_features(@runtime))
          end
          @declared_features = DeclaredFeatures.discover(feature_gates: feature_gates, runtime_features: runtime_features)&.freeze
          @admission = admission || Admission.new(node_name: @node_name, capacity: @capacity, allocatable: @allocatable,
                                                  node_labels: @node_labels, operating_system: @operating_system,
                                                  architecture: @architecture, runtime_classes: nil,
                                                  allowed_unsafe_sysctls: allowed_unsafe_sysctls,
                                                  declared_features: @declared_features, features: feature_gates,
                                                  node_labels_provider: live_node_labels_provider(@api), node_taints: -> { @observed_node_taints },
                                                  node_taints_provider: method(:refresh_node_taints))
        end

        # Events about Pods on this node (Pulling, Created, Started, Killing,
        # Failed, ...) with source kubelet/<node>, as the conformance suite
        # lists them.  Returns the lifecycle's event sink, if any.
        def initialize_events(event_recorder, publish_events, lifecycle_logger)
          @event_recorder = event_recorder
          client = node_adapter?(@api, :event_client) ? @api.event_client : api_client
          if @event_recorder.nil? && publish_events && client
            @event_recorder = EventRecorder.new(client: EventSink.new(client: client), reporting_component: "kubelet",
                                                reporting_instance: @node_name, event_time: false,
                                                source: {"component" => "kubelet", "host" => @node_name}, clock: @clock)
          end
          if @host_node && @event_recorder
            @oom_watcher = SystemOOMWatcher.new(node: node_reference, recorder: @event_recorder, allow_user_namespace: @feature_gates[SystemOOMWatcher::GATE],
                                                error_handler: @error_handler)
          end
          @event_recorder && KubeletEventPublisher.new(recorder: @event_recorder, node_name: @node_name, logger: lifecycle_logger)
        end

        # The CPU, memory and topology managers (state in <root>, as
        # /var/lib/kubelet/cpu_manager_state).
        def initialize_container_manager(container_manager, cpu, memory, topology, reserved_system_cpus)
          @container_manager = container_manager ||
                               build_container_manager(@kubelet_root, @host_node, cpu, memory, topology, reserved_system_cpus, @error_handler)
        end

        # +pod_ports+ are the lifecycle's own ports and paths, passed through.
        def initialize_lifecycle(lifecycle, pod_ports, publisher:, device_plugin_dir:, crash_loop_back_off_max:, image_credential_provider:)
          @lifecycle = lifecycle
          # devicemanager: device plugins registering on
          # <device_plugin_dir>/kubelet.sock advertise their devices here.
          @device_plugins = (DevicePlugins::Manager.new(directory: device_plugin_dir, on_change: -> { device_plugins_changed }) if device_plugin_dir)
          restart_manager = build_restart_manager(crash_loop_back_off_max)
          # --image-credential-provider-config / -bin-dir.
          @credential_providers = build_credential_providers(image_credential_provider, @api)
          @lifecycle ||= Lifecycle.new(
            credential_providers: @credential_providers, restart_manager: restart_manager, device_plugins: @device_plugins,
            admission: @admission, event_sink: publisher, status: @status, clock: @clock, sleeper: @sleeper,
            node_name: @node_name, node_allocatable: @allocatable, pod_deleter: pod_deleter_for(@api),
            dra_manager: @dra_manager, container_manager: @container_manager, preemption: build_preemption,
            feature_gates: @feature_gates,
            container_stop_signals: @feature_gates[ContainerStopSignals::GATE] == true,
            image_volume_with_digest: @feature_gates["ImageVolumeWithDigest"] == true, **pod_ports
          )
          publisher.lifecycle = @lifecycle if publisher
          # A new attachable volume in the desired state: report it in use now,
          # the mount waits for the report.
          @lifecycle.volumes_in_use_observer = -> { request_node_status_sync }
        end

        # Kubernetes v1.36.2 applies the reduced defaults before the kubelet
        # config's maxContainerRestartPeriod, which defaults to 300 seconds.
        def build_restart_manager(crash_loop_back_off_max)
          reduced = @feature_gates["ReduceDefaultCrashLoopBackOffDecay"] == true
          base = reduced ? RestartManager::REDUCED_BASE_DELAY_SECONDS : RestartManager::BASE_DELAY_SECONDS
          maximum = reduced ? RestartManager::REDUCED_MAX_DELAY_SECONDS : RestartManager::MAX_DELAY_SECONDS
          maximum = crash_loop_back_off_max || RestartManager::MAX_DELAY_SECONDS if @feature_gates["KubeletCrashLoopBackOffMax"] != false

          maximum = Float(maximum)
          RestartManager.new(clock: monotonic_clock, sleeper: @sleeper, max_delay: maximum, base_delay: [base, maximum].min)
        end

        # Node allocatable and QoS cgroup weights (kubelet cm), for a node
        # that runs Pods in the host's cgroups; the static Pods and the pod
        # resources API (<pod_resources_dir>/kubelet.sock) beside them.
        def initialize_pod_sources(qos_cgroup_manager, qos_cgroups, reserved, pod_resources_dir)
          @qos_cgroup_manager = qos_cgroup_manager || build_qos_cgroup_manager(qos_cgroups, *reserved, @error_handler, @host_node)
          @qos_cgroup_manager&.start
          @lifecycle.pod_cgroup_manager = @qos_cgroup_manager if @lifecycle.is_a?(Lifecycle) && @qos_cgroup_manager.is_a?(QOSCgroupManager)
          @static_pods&.lifecycle = @lifecycle
          return unless pod_resources_dir

          @pod_resources = PodResources.new(directory: pod_resources_dir, pods: -> { running_pods_for_pod_resources },
                                            device_plugins: @device_plugins, container_manager: @container_manager,
                                            dra_manager: @dra_manager)
        end

        def initialize_sync_loop(sync_loop, source, sync_period, watch_timeout, pods_api_directory)
          @sync_loop = sync_loop || SyncLoop.new(
            source: source || @api,
            reconcile: ->(pod, **options) { reconcile_pod(pod, **options) },
            node_name: @node_name,
            resync_period: sync_period,
            watch_timeout: watch_timeout,
            clock: monotonic_clock,
            sleeper: @sleeper,
            error_handler: @error_handler,
            removed: ->(uid) { @lifecycle.pod_removed(uid) },
            resynced: (method(:resync_cri_pod_logs) unless cri_log_backends.empty?)
          )
          @static_pods.enqueue_pod = @sync_loop.method(:enqueue_pod) if @static_pods && sync_loop.nil?
          @lifecycle.desired_pod_lookup = @sync_loop.method(:cached_pod) if @lifecycle.is_a?(Lifecycle) && @sync_loop.is_a?(SyncLoop)
          @wakeups = WakeupTimer.new do |uid|
            current = @sync_loop.cache[uid]
            @sync_loop.enqueue_pod(current, action: "MODIFIED") if current
          end
          @lifecycle.wakeup = ->(uid, delay) { @wakeups.schedule(uid, delay + BACKOFF_WAKEUP_SLACK) }
          initialize_pods_api(pods_api_directory) if @feature_gates["PodsAPI"] == true
        end

        # The Summary API (/stats/summary, /metrics/resource): on a real node,
        # or when injected.  Image garbage collection and node.status.images /
        # runtimeHandlers / features read from it (a real node only).
        def initialize_stats(stats_provider, image_resolver, volume, pod_root, image_gc, system_cgroups:, node_status_max_images:, volume_stats_agg_period:)
          backend = default_node_runtime
          @default_cri_client = backend.client if cri_backend?(backend)
          @stats_provider = stats_provider
          if @stats_provider.nil? && @host_node
            volume_health = @feature_gates["CSIVolumeHealth"] == true
            volume_stats = ->(id, path) { volume.csi_volume_stats(id, path, health: volume_health) } if volume_manager?(volume)
            if @feature_gates["LocalStorageCapacityIsolationFSQuotaMonitoring"] == true && volume.is_a?(Volume::Manager)
              project_quota_usage = volume.method(:project_quota_usage)
            end
            cri_backends = if @feature_gates["PodAndContainerStatsFromCRI"] == true
                             cri_runtime_backends
                           else
                             []
                           end
            @stats_provider = StatsProvider.new(node_name: @node_name, lifecycle: @lifecycle, runtime: @runtime, pod_root: pod_root,
                                                image_root: image_resolver && (image_resolver.staging_root || Dir.tmpdir),
                                                container_root: native_container_root, cri_image_client: @default_cri_client,
                                                allocatable_memory: quantity_bytes(@allocatable["memory"]),
                                                cri_clients: cri_backends.empty? ? [] : cri_clients,
                                                cri_log_roots: cri_backends.to_h { |backend| [backend.client, backend.log_root] },
                                                volume_stats: volume_stats, volume_health: volume_health, event_recorder: @event_recorder,
                                                volume_stats_agg_period: volume_stats_agg_period,
                                                project_quota_usage: project_quota_usage, system_cgroups: system_cgroups)
          end
          image_gc = Helpers.string_keys(image_gc || {})
          @image_gc_manager = build_image_gc_manager(image_resolver, image_gc, @error_handler)
          @cri_image_gc_managers = build_cri_image_gc_managers(image_gc, node_reference, @error_handler)
          return unless @host_node

          @status_images = StatusImages.new(resolver: image_resolver, cri_clients: cri_clients, max_images: node_status_max_images)
          @runtime_handlers = node_runtime_handlers
        end

        def native_container_root
          runtime = runtime_backends&.fetch("rubernetes-native", nil) || @runtime
          runtime.config.sandbox_root if runtime.is_a?(Runtime::Native)
        end

        def default_node_runtime
          return @runtime unless defined?(Runtime::Multiplexer) && @runtime.is_a?(Runtime::Multiplexer)

          @runtime.backend_for(@runtime.handler_for({}))
        end

        def cri_runtime_backends
          (runtime_backends&.values || [@runtime]).select { |backend| cri_backend?(backend) }
        end

        # The eviction manager reads the Summary API; without stats there is
        # nothing to evict on.
        def initialize_eviction(eviction_manager, eviction)
          eviction = Helpers.string_keys(eviction || {})
          @eviction_manager = eviction_manager
          @eviction_manager ||= build_eviction_manager(eviction) if @stats_provider && eviction.fetch("enabled", true) != false
        end

        # GracefulNodeShutdown: a manager only with a shutdown grace period.
        def initialize_shutdown(shutdown_manager, shutdown, feature_gates)
          @shutdown_manager = shutdown_manager || build_shutdown_manager(shutdown, feature_gates, @kubelet_root, @error_handler)
        end

        # What changes while the agent runs; everything else is fixed at construction.
        def initialize_state
          @pressure_conditions = {}
          @pressure_mutex = Mutex.new
          @mutex = Mutex.new
          @lease_condition = ConditionVariable.new
          @registered = false
          @running = false
          @ready = false
          @lease = nil
          @last_lease_renewal = nil
          @lease_thread = nil
          @relist_thread = nil
          @stop_requested = false
          @startup_error = nil
          @recovery_report = nil
          @recovered = false
        end
      end
    end
  end
end
