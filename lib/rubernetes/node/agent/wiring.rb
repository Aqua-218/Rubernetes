# frozen_string_literal: true

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
        def initialize_node_resources(capacity, allocatable, reserved, eviction, host:, pod_root:, max_pods:)
          @host_node = host
          @kubelet_root = pod_root && File.dirname(File.expand_path(pod_root.to_s))
          detected = host ? HostResources.capacity(pod_root: pod_root, max_pods: max_pods) : {}
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

        def initialize_node_identity(labels, annotations, addresses, architecture, operating_system, runtime_version, streaming_port)
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

        # kubelet staticPodPath: the manifests' Pods run here, mirrored in the
        # API; their status goes to the mirror Pod.  Returns the reporter the
        # lifecycle is to use.
        def initialize_status(status, static_pod_path, reporter, endpoint_manager)
          @static_pods = if static_pod_path
                           StaticPods.new(path: static_pod_path, node_name: @node_name, lifecycle: nil, api: @api, sleeper: @sleeper,
                                          logger: error_handler_logger(@error_handler))
                         end
          reporter = StaticPods::Reporter.new(reporter, @static_pods) if @static_pods && reporter
          @status = status || Status.new(endpoint_manager: endpoint_manager, reporter: reporter, clock: @clock)
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
          @declared_features = DeclaredFeatures.discover(feature_gates: feature_gates, runtime_features: runtime_features)&.freeze
          @admission = admission || Admission.new(node_name: @node_name, capacity: @capacity, allocatable: @allocatable,
                                                  node_labels: @node_labels, operating_system: @operating_system,
                                                  architecture: @architecture, runtime_classes: nil,
                                                  allowed_unsafe_sysctls: allowed_unsafe_sysctls,
                                                  declared_features: @declared_features, features: feature_gates,
                                                  node_labels_provider: live_node_labels_provider(@api))
        end

        # Events about Pods on this node (Pulling, Created, Started, Killing,
        # Failed, ...) with source kubelet/<node>, as the conformance suite
        # lists them.  Returns the lifecycle's event sink, if any.
        def initialize_events(event_recorder, publish_events, lifecycle_logger)
          @event_recorder = event_recorder
          client = api_client
          if @event_recorder.nil? && publish_events && client
            @event_recorder = EventRecorder.new(client: EventSink.new(client: client), reporting_component: "kubelet",
                                                reporting_instance: @node_name, event_time: false,
                                                source: {"component" => "kubelet", "host" => @node_name}, clock: @clock)
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
            dra_manager: @dra_manager, container_manager: @container_manager, preemption: build_preemption, **pod_ports
          )
          publisher.lifecycle = @lifecycle if publisher
          # A new attachable volume in the desired state: report it in use now,
          # the mount waits for the report.
          @lifecycle.volumes_in_use_observer = -> { request_node_status_sync }
        end

        # newCrashLoopBackOff: the configured maxContainerRestartPeriod caps
        # the backoff, and the initial delay never exceeds it.
        def build_restart_manager(crash_loop_back_off_max)
          return nil unless crash_loop_back_off_max

          maximum = Float(crash_loop_back_off_max)
          RestartManager.new(sleeper: @sleeper, max_delay: maximum, base_delay: [RestartManager::BASE_DELAY_SECONDS, maximum].min)
        end

        # Node allocatable and QoS cgroup weights (kubelet cm), for a node
        # that runs Pods in the host's cgroups; the static Pods and the pod
        # resources API (<pod_resources_dir>/kubelet.sock) beside them.
        def initialize_pod_sources(qos_cgroup_manager, qos_cgroups, reserved, pod_resources_dir)
          @qos_cgroup_manager = qos_cgroup_manager || build_qos_cgroup_manager(qos_cgroups, *reserved, @error_handler, @host_node)
          @qos_cgroup_manager&.start
          @static_pods&.lifecycle = @lifecycle
          return unless pod_resources_dir

          @pod_resources = PodResources.new(directory: pod_resources_dir, pods: -> { running_pods_for_pod_resources },
                                            device_plugins: @device_plugins, container_manager: @container_manager,
                                            dra_manager: @dra_manager)
        end

        def initialize_sync_loop(sync_loop, source, sync_period, watch_timeout)
          @sync_loop = sync_loop || SyncLoop.new(
            source: source || @api,
            reconcile: ->(pod, **options) { reconcile_pod(pod, **options) },
            node_name: @node_name,
            resync_period: sync_period,
            watch_timeout: watch_timeout,
            clock: monotonic_clock,
            sleeper: @sleeper,
            error_handler: @error_handler,
            removed: ->(uid) { @lifecycle.pod_removed(uid) }
          )
          @wakeups = WakeupTimer.new do |uid|
            current = @sync_loop.cache[uid]
            @sync_loop.enqueue_pod(current, action: "MODIFIED") if current
          end
          @lifecycle.wakeup = ->(uid, delay) { @wakeups.schedule(uid, delay + BACKOFF_WAKEUP_SLACK) }
        end

        # The Summary API (/stats/summary, /metrics/resource): on a real node,
        # or when injected.  Image garbage collection and node.status.images /
        # runtimeHandlers / features read from it (a real node only).
        def initialize_stats(stats_provider, image_resolver, volume, pod_root, image_gc)
          @stats_provider = stats_provider
          if @stats_provider.nil? && @host_node
            @stats_provider = StatsProvider.new(node_name: @node_name, lifecycle: @lifecycle, runtime: @runtime, pod_root: pod_root,
                                                image_root: image_resolver && (image_resolver.staging_root || Dir.tmpdir),
                                                allocatable_memory: quantity_bytes(@allocatable["memory"]),
                                                volume_stats: volume_manager?(volume) ? volume.method(:csi_volume_stats) : nil)
          end
          image_gc = Helpers.string_keys(image_gc || {})
          @image_gc_manager = build_image_gc_manager(image_resolver, image_gc, @error_handler)
          @cri_image_gc_managers = build_cri_image_gc_managers(image_gc, node_reference, @error_handler)
          return unless @host_node

          @status_images = StatusImages.new(resolver: image_resolver, cri_clients: cri_clients)
          @runtime_handlers = node_runtime_handlers
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
