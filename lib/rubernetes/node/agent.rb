# frozen_string_literal: true

require "digest"
require "rbconfig"
require "time"
require "tmpdir"

require_relative "../version"
require_relative "../runtime/common/errors"
require_relative "status"
require_relative "static_pods"
require_relative "preemption"
require_relative "device_plugins/manager"
require_relative "pod_resources"
require_relative "lifecycle"
require_relative "sync_loop"
require_relative "wakeup_timer"
require_relative "declared_features"
require_relative "stats_provider"
require_relative "eviction_manager"
require_relative "image_gc_manager"
require_relative "dra_manager"
require_relative "container_manager"
require_relative "shutdown_manager"
require_relative "node_allocatable"
require_relative "qos_cgroup_manager"
require_relative "status_images"
require_relative "plugins/manager"
require_relative "csi_plugins"
require_relative "kubelet_metrics"

module Rubernetes
  module Node
    # Node Agent entry point.  It owns registration and lease renewal, while
    # SyncLoop and Lifecycle own Pod work.  API, runtime, storage, and network
    # effects are all injected ports.
    class Agent
      DEFAULT_LEASE_DURATION_SECONDS = 40
      DEFAULT_LEASE_RENEW_FRACTION = 0.25
      NODE_LEASE_NAMESPACE = "kube-node-lease"
      DEFAULT_SLEEPER = ->(seconds) { sleep(seconds) }.freeze
      # kubelet PLEG relist period.
      DEFAULT_RELIST_PERIOD_SECONDS = 1.0
      # kubelet nodeStatusUpdateFrequency / nodeStatusReportFrequency: the
      # status is computed every 10 s and patched when it changed, and at
      # least every 5 min.
      NODE_STATUS_UPDATE_FREQUENCY_SECONDS = 10.0
      NODE_STATUS_REPORT_FREQUENCY_SECONDS = 300.0
      # A backoff wake-up lands just after the backoff ends, never on its edge.
      BACKOFF_WAKEUP_SLACK = 0.05

      Lease = Data.define(:node_name, :namespace, :duration_seconds, :renew_time, :transitions) do
        def to_h
          {
            "apiVersion" => "coordination.k8s.io/v1",
            "kind" => "Lease",
            "metadata" => {"name" => node_name, "namespace" => namespace},
            "spec" => {
              "holderIdentity" => node_name,
              "leaseDurationSeconds" => duration_seconds,
              "renewTime" => renew_time,
              "leaseTransitions" => transitions
            }
          }
        end
      end

      def initialize(node_name:, api:, runtime: nil, volume: nil, network: nil,
                     source: nil, lifecycle: nil, sync_loop: nil, admission: nil,
                     status: nil, endpoint_manager: nil, reporter: nil,
                     node_namespace: NODE_LEASE_NAMESPACE,
                     lease_duration_seconds: DEFAULT_LEASE_DURATION_SECONDS,
                     lease_renew_fraction: DEFAULT_LEASE_RENEW_FRACTION,
                     sync_period: SyncLoop::DEFAULT_RESYNC_PERIOD_SECONDS,
                     watch_timeout: 30, node_labels: {}, node_annotations: {},
                     capacity: {}, allocatable: nil, addresses: [],
                     architecture: RbConfig::CONFIG["host_cpu"],
                     operating_system: RbConfig::CONFIG["host_os"],
                     runtime_version: RUBY_VERSION,
                     state_store: nil, runtime_class_resolver: nil,
                     streaming_port: nil,
                     clock: -> { Time.now.utc }, sleeper: DEFAULT_SLEEPER,
                     error_handler: nil,
                     pod_root: nil, resource_reader: nil, host_ip: nil, cluster_domain: "cluster.local",
                     probe_connectors: nil, relist_period: DEFAULT_RELIST_PERIOD_SECONDS, pod_files: nil,
                     detect_host_resources: false, max_pods: HostResources::DEFAULT_MAX_PODS, crash_loop_back_off_max: nil,
                     static_pod_path: nil, device_plugin_dir: nil, pod_resources_dir: nil, image_credential_provider: nil,
                     allowed_unsafe_sysctls: [], event_recorder: nil, publish_events: true, lifecycle_logger: nil,
                     feature_gates: {}, runtime_features: {}, stats_provider: nil, eviction_manager: nil, eviction: {},
                     image_resolver: nil, image_gc: {}, dra: {}, dra_manager: nil, plugin_manager: nil, csi_plugins: nil,
                     system_reserved: {}, kube_reserved: {}, reserved_system_cpus: nil, cpu_manager: {}, memory_manager: {},
                     topology_manager: {}, container_manager: nil, shutdown: {}, shutdown_manager: nil,
                     qos_cgroups: nil, qos_cgroup_manager: nil,
                     node_status_update_frequency: NODE_STATUS_UPDATE_FREQUENCY_SECONDS,
                     node_status_report_frequency: NODE_STATUS_REPORT_FREQUENCY_SECONDS)
        raise ArgumentError, "node_name must not be empty" if node_name.to_s.empty?

        @node_status_update_frequency = Float(node_status_update_frequency)
        @node_status_report_frequency = Float(node_status_report_frequency)
        @last_reported_status = nil
        @last_status_report_at = nil
        @node_status_condition = ConditionVariable.new
        @node_status_requested = false
        raise ArgumentError, "api is required" unless api

        @node_name = node_name.to_s.freeze
        @api = api
        @runtime = runtime || (lifecycle.respond_to?(:runtime) ? lifecycle.runtime : nil)
        @clock = clock
        @sleeper = sleeper
        @error_handler = error_handler
        @node_namespace = node_namespace.to_s.freeze
        @lease_duration_seconds = Integer(lease_duration_seconds)
        @lease_renew_fraction = Float(lease_renew_fraction)
        raise ArgumentError, "lease_duration_seconds must be positive" unless @lease_duration_seconds.positive?
        unless @lease_renew_fraction.positive? && @lease_renew_fraction <= 1
          raise ArgumentError,
                "lease_renew_fraction must be between 0 and 1"
        end

        @lease_renew_interval = @lease_duration_seconds * @lease_renew_fraction
        # enableControllerAttachDetach (default true): the kubelet leaves
        # attach/detach to the controller manager and says so on the Node.
        @node_annotations = {"volumes.kubernetes.io/controller-managed-attach-detach" => "true"}
          .merge(Helpers.string_keys(node_annotations)).freeze
        @streaming_port = streaming_port
        detected = {}
        # A real node reports what the host has (kubelet: cAdvisor machine
        # info); injected capacity wins so tests and reservations stay exact.
        detected = HostResources.capacity(pod_root: pod_root, max_pods: max_pods) if detect_host_resources
        @capacity = detected.merge(Helpers.string_keys(capacity)).freeze
        # Node Allocatable: capacity less system-reserved, kube-reserved and
        # the hard eviction thresholds (a real node, or reservations given).
        @reservation = node_allocatable_reservation(system_reserved, kube_reserved, reserved_system_cpus, eviction,
                                                    host: detect_host_resources)
        @allocatable = if allocatable
                         Helpers.string_keys(allocatable).freeze
                       elsif @reservation.empty?
                         @capacity
                       else
                         NodeAllocatable.allocatable(@capacity, @reservation).freeze
                       end
        @host_info = detect_host_resources ? HostResources.node_info : {}
        @addresses = Helpers.string_keys(addresses).freeze
        # Kubernetes uses Go's GOARCH spelling ("amd64"), not uname's
        # ("x86_64"); node labels, image selection and nodeAffinity all match on
        # the Go form.
        @architecture = Registration.normalize_architecture(architecture).to_s.freeze
        # Kubernetes spells the OS the Go way ("linux"); RbConfig may say
        # "linux-gnu".
        @operating_system = (operating_system.to_s.start_with?("linux") ? "linux" : operating_system.to_s).freeze
        # The kubelet always applies the well-known topology labels; anything
        # with a nodeSelector (conformance included) cannot land on a node
        # without them.  Configured labels win over the defaults.
        @node_labels = {
          "kubernetes.io/hostname" => @node_name,
          "kubernetes.io/os" => @operating_system,
          "kubernetes.io/arch" => @architecture,
          "beta.kubernetes.io/os" => @operating_system,
          "beta.kubernetes.io/arch" => @architecture
        }.reject { |_key, value| value.to_s.empty? }
          .merge(Helpers.string_keys(node_labels)).freeze
        @runtime_version = runtime_version.to_s.freeze
        # kubelet staticPodPath: the manifests' Pods run here, mirrored in the
        # API; their status goes to the mirror Pod.
        @static_pods = if static_pod_path
                         StaticPods.new(path: static_pod_path, node_name: @node_name, lifecycle: nil, api: api, sleeper: sleeper,
                                        logger: error_handler_logger(error_handler))
                       end
        reporter = StaticPods::Reporter.new(reporter, @static_pods) if @static_pods && reporter
        @status = status || Status.new(endpoint_manager: endpoint_manager, reporter: reporter, clock: clock)
        @relist_period = Float(relist_period)
        @relist_thread = nil
        @host_ip = host_ip
        connectors = probe_connectors || {}
        probe_manager = if connectors.empty?
                          nil
                        else
                          ProbeManager.new(runtime: runtime, clock: clock, sleeper: sleeper,
                                           http_client: connectors[:http] || connectors["http"],
                                           tcp_client: connectors[:tcp] || connectors["tcp"],
                                           grpc_client: connectors[:grpc] || connectors["grpc"])
                        end
        # NodeDeclaredFeatures: what this node declares in status.declaredFeatures
        # (nil with the gate off), fixed for the life of the agent as upstream.
        @feature_gates = Helpers.string_keys(feature_gates || {}).freeze
        @declared_features = DeclaredFeatures.discover(feature_gates: feature_gates, runtime_features: runtime_features)&.freeze
        # kubelet admission on the node: sysctl allowlist, node selector/
        # affinity, OS/arch, resources, declared features.  Injected admission
        # (tests) wins.
        admission ||= Admission.new(node_name: @node_name, capacity: @capacity, allocatable: @allocatable,
                                    node_labels: @node_labels, operating_system: @operating_system,
                                    architecture: @architecture, runtime_classes: nil,
                                    allowed_unsafe_sysctls: allowed_unsafe_sysctls,
                                    declared_features: @declared_features, features: feature_gates,
                                    node_labels_provider: live_node_labels_provider(api))
        @admission = admission
        # Events about Pods on this node (Pulling, Created, Started, Killing,
        # Failed, ...) with source kubelet/<node>, as the conformance suite
        # lists them.
        @event_recorder = event_recorder
        if @event_recorder.nil? && publish_events && api.respond_to?(:client) && api.client
          @event_recorder = EventRecorder.new(client: EventSink.new(client: api.client), reporting_component: "kubelet",
                                              reporting_instance: @node_name, event_time: false,
                                              source: {"component" => "kubelet", "host" => @node_name}, clock: clock)
        end
        publisher = @event_recorder && KubeletEventPublisher.new(recorder: @event_recorder, node_name: @node_name,
                                                                 logger: lifecycle_logger)
        # Dynamic Resource Allocation on a real node: the kubelet plugin
        # registry (<root>/plugins_registry) and the DRA manager, whose claim
        # checkpoint lives in <root>/dra.  <root> is the parent of the Pod
        # directory, as /var/lib/kubelet is of /var/lib/kubelet/pods.
        dra = Helpers.string_keys(dra || {})
        @dra_manager = dra_manager
        @plugin_manager = plugin_manager
        kubelet_root = pod_root && File.dirname(File.expand_path(pod_root.to_s))
        if @dra_manager.nil? && kubelet_root && dra.fetch("enabled", true) != false && api.respond_to?(:client) && api.client
          @dra_manager = DRAManager.new(client: api.client, node_name: @node_name,
                                        state_directory: dra.fetch("state_dir", File.join(kubelet_root, "dra")),
                                        error_handler: error_handler,
                                        # ResourceHealthStatus (Beta, on): follow each driver's health stream.
                                        resource_health: @feature_gates.fetch("ResourceHealthStatus", true) != false)
        end
        # CSI node plugins register through the same registry (type
        # CSIPlugin); the volume manager then resolves a volume's driver to
        # the registered plugin when no single CSI socket is configured.
        @csi_plugins = csi_plugins
        if @csi_plugins.nil? && kubelet_root && dra.fetch("csi_plugins", true) != false && api.respond_to?(:client) && api.client
          @csi_plugins = CSIPlugins.new(client: api.client, node_name: @node_name, error_handler: error_handler)
        end
        volume.csi_registry = @csi_plugins if @csi_plugins && volume.respond_to?(:csi_registry=)
        handlers = {"DRAPlugin" => @dra_manager, CSIPlugins::TYPE => @csi_plugins}.compact
        if @plugin_manager.nil? && !handlers.empty? && kubelet_root
          @plugin_manager = Plugins::Manager.new(directory: dra.fetch("plugins_registry", File.join(kubelet_root, "plugins_registry")),
                                                 handlers: handlers, error_handler: error_handler)
        end
        cdi_spec_dirs = Array(dra.fetch("cdi_spec_dirs", CDI::DEFAULT_SPEC_DIRS))
        # The CPU, memory and topology managers (state in <root>, as
        # /var/lib/kubelet/cpu_manager_state).
        @container_manager = container_manager ||
                             build_container_manager(kubelet_root, detect_host_resources, cpu_manager, memory_manager, topology_manager,
                                                     reserved_system_cpus, error_handler)
        @lifecycle = lifecycle
        # devicemanager: device plugins registering on
        # <device_plugin_dir>/kubelet.sock advertise their devices here.
        @device_plugins = if device_plugin_dir
                            DevicePlugins::Manager.new(directory: device_plugin_dir, on_change: -> { device_plugins_changed })
                          end
        # newCrashLoopBackOff: the configured maxContainerRestartPeriod caps
        # the backoff, and the initial delay never exceeds it.
        restart_manager = if crash_loop_back_off_max
                            maximum = Float(crash_loop_back_off_max)
                            RestartManager.new(sleeper: sleeper, max_delay: maximum,
                                               base_delay: [RestartManager::BASE_DELAY_SECONDS, maximum].min)
                          end
        # --image-credential-provider-config / -bin-dir.
        @credential_providers = build_credential_providers(image_credential_provider, api)
        @lifecycle ||= Lifecycle.new(
          credential_providers: @credential_providers,
          restart_manager: restart_manager,
          device_plugins: @device_plugins,
          runtime: runtime,
          volume: volume,
          network: network,
          admission: admission,
          event_sink: publisher,
          status: @status,
          clock: clock,
          sleeper: sleeper,
          reporter: reporter,
          endpoint_manager: endpoint_manager,
          state_store: state_store,
          runtime_class_resolver: runtime_class_resolver,
          probe_manager: probe_manager,
          pod_root: pod_root,
          resource_reader: resource_reader,
          node_name: @node_name,
          host_ip: host_ip,
          node_allocatable: @allocatable,
          cluster_domain: cluster_domain,
          pod_files: pod_files,
          pod_deleter: pod_deleter_for(api),
          dra_manager: @dra_manager,
          cdi_spec_dirs: cdi_spec_dirs,
          container_manager: @container_manager,
          preemption: build_preemption
        )
        publisher.lifecycle = @lifecycle if publisher
        # A new attachable volume in the desired state: report it in use now,
        # the mount waits for the report.
        if @lifecycle.respond_to?(:volumes_in_use_observer=) && !@lifecycle.frozen?
          @lifecycle.volumes_in_use_observer = -> { request_node_status_sync }
        end
        if @dra_manager.respond_to?(:active_pods=) && @lifecycle.respond_to?(:admitted_pods)
          lifecycle_for_dra = @lifecycle
          @dra_manager.active_pods = -> { lifecycle_for_dra.admitted_pods }
        end
        @kubelet_metrics = KubeletMetrics.new(node_name: @node_name)
        @kubelet_metrics.plugin_manager = @plugin_manager if @plugin_manager
        if image_resolver.respond_to?(:pull_records) && image_resolver.pull_records && @kubelet_metrics.respond_to?(:pull_records=)
          @kubelet_metrics.pull_records = image_resolver.pull_records
        end
        if @csi_plugins.respond_to?(:metrics_observer=)
          kubelet_metrics = @kubelet_metrics
          @csi_plugins.metrics_observer = lambda { |driver, method_name, code, seconds|
            kubelet_metrics.csi_operation(driver, method_name, code, seconds)
          }
        end
        @container_manager.metrics = @kubelet_metrics.registry if @container_manager.respond_to?(:metrics=) && !@container_manager.frozen?
        start_container_manager if @container_manager
        # Node allocatable and QoS cgroup weights (kubelet cm), for a node
        # that runs Pods in the host's cgroups.
        @qos_cgroup_manager = qos_cgroup_manager ||
                              build_qos_cgroup_manager(qos_cgroups, system_reserved, kube_reserved, reserved_system_cpus,
                                                       error_handler, detect_host_resources)
        @qos_cgroup_manager&.start
        @static_pods&.lifecycle = @lifecycle
        # kubelet pod resources API on <pod_resources_dir>/kubelet.sock.
        @pod_resources = if pod_resources_dir
                           PodResources.new(directory: pod_resources_dir, pods: -> { running_pods_for_pod_resources },
                                            device_plugins: @device_plugins, container_manager: @container_manager,
                                            dra_manager: @dra_manager)
                         end
        @sync_loop = sync_loop || SyncLoop.new(
          source: source || api,
          reconcile: lambda { |pod, **options|
            # The kubelet never runs a mirror Pod: it is the API's view of a
            # static Pod, which StaticPods runs from its manifest.
            next nil if mirror_pod?(pod)

            check_declared_features_update(pod)
            @kubelet_metrics&.pod_seen(pod)
            began = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            result = @lifecycle.reconcile(pod, **options)
            @kubelet_metrics&.pod_worker_synced(pod, options[:action], Process.clock_gettime(Process::CLOCK_MONOTONIC) - began)
            @qos_cgroup_manager&.pods_changed
            result
          },
          node_name: @node_name,
          resync_period: sync_period,
          watch_timeout: watch_timeout,
          clock: monotonic_clock,
          sleeper: sleeper,
          error_handler: error_handler,
          removed: ->(uid) { @lifecycle.pod_removed(uid) if @lifecycle.respond_to?(:pod_removed) }
        )
        if @lifecycle.respond_to?(:wakeup=) && @sync_loop.respond_to?(:enqueue_pod)
          @wakeups = WakeupTimer.new do |uid|
            current = if @sync_loop.respond_to?(:cache)
                        begin
                          @sync_loop.cache[uid]
                        rescue StandardError
                          nil
                        end
                      end
            @sync_loop.enqueue_pod(current, action: "MODIFIED") if current
          end
          @lifecycle.wakeup = ->(uid, delay) { @wakeups.schedule(uid, delay + BACKOFF_WAKEUP_SLACK) }
        end
        # The Summary API (/stats/summary, /metrics/resource) and the eviction
        # manager reading it: on a real node, or when injected.
        @stats_provider = stats_provider
        image_root = (image_resolver.staging_root || Dir.tmpdir if image_resolver.respond_to?(:staging_root))
        if @stats_provider.nil? && detect_host_resources
          @stats_provider = StatsProvider.new(node_name: @node_name, lifecycle: @lifecycle, runtime: @runtime, pod_root: pod_root,
                                              image_root: image_root, allocatable_memory: quantity_bytes(@allocatable["memory"]),
                                              volume_stats: volume.respond_to?(:csi_volume_stats) ? volume.method(:csi_volume_stats) : nil)
        end
        if @stats_provider.respond_to?(:metrics_observer=) && @kubelet_metrics
          kubelet_metrics = @kubelet_metrics
          @stats_provider.metrics_observer = ->(source, seconds) { kubelet_metrics.volume_metric_collection(source, seconds) }
        end
        # Image garbage collection over the resolver's unpacked images.
        image_gc = Helpers.string_keys(image_gc || {})
        @image_gc_manager = nil
        if image_resolver.respond_to?(:cached_images) && @stats_provider.respond_to?(:image_fs_stats) &&
           image_gc.fetch("enabled", true) != false
          lifecycle_ref = @lifecycle
          @image_gc_manager = ImageGCManager.new(
            resolver: image_resolver, fs_stats: -> { @stats_provider.image_fs_stats },
            pods: lambda {
              if lifecycle_ref.respond_to?(:pods_on_node)
                lifecycle_ref.pods_on_node
              else
                records = lifecycle_ref.respond_to?(:records) ? lifecycle_ref.records.values : []
                records.filter_map { |record| record[:pod] unless record[:state].to_s == "Removed" }
              end
            },
            high_threshold_percent: image_gc.fetch("high_threshold_percent", ImageGCManager::DEFAULT_HIGH_THRESHOLD_PERCENT),
            low_threshold_percent: image_gc.fetch("low_threshold_percent", ImageGCManager::DEFAULT_LOW_THRESHOLD_PERCENT),
            min_age: EvictionManager.parse_duration(image_gc.fetch("minimum_age", "2m")),
            max_age: EvictionManager.parse_duration(image_gc.fetch("maximum_age", "0s")),
            recorder: @event_recorder, node_ref: node_reference, error_handler: error_handler
          )
        end
        @cri_image_gc_managers = build_cri_image_gc_managers(image_gc, node_reference, error_handler)
        # node.status.images / runtimeHandlers / features (a real node only).
        if detect_host_resources
          @status_images = StatusImages.new(resolver: image_resolver, cri_clients: cri_clients)
          @runtime_handlers = node_runtime_handlers
        end
        @eviction_manager = eviction_manager
        eviction = Helpers.string_keys(eviction || {})
        if @eviction_manager.nil? && @stats_provider && eviction.fetch("enabled", true) != false
          @eviction_manager = build_eviction_manager(eviction)
        end
        # kubelet /metrics (the registry exists from the container manager's start).
        @lifecycle.metrics_observer = @kubelet_metrics if @lifecycle.respond_to?(:metrics_observer=)
        attach_selinux_tracker
        attach_pod_certificate_manager
        kubelet_metrics = @kubelet_metrics
        if @status.respond_to?(:sync_observer=) && !@status.frozen?
          @status.sync_observer = ->(pod, status, seconds) { kubelet_metrics.pod_status_synced(pod, status, seconds) }
        end
        [@image_gc_manager, *Array(@cri_image_gc_managers)].each do |manager|
          next unless manager.respond_to?(:on_collected=) && !manager.frozen?

          manager.on_collected = ->(reason) { kubelet_metrics.image_garbage_collected(reason) }
        end
        if @eviction_manager.respond_to?(:on_eviction=)
          metrics = @kubelet_metrics
          @eviction_manager.on_eviction = ->(signal) { metrics.eviction(signal) }
          if @eviction_manager.respond_to?(:on_stats_age=)
            @eviction_manager.on_stats_age = ->(signal, seconds) { metrics.eviction_stats_age(signal, seconds) }
          end
        end
        if @eviction_manager && @admission.respond_to?(:eviction_admit_handler=)
          @admission.eviction_admit_handler = @eviction_manager.method(:admit)
        end
        if @container_manager && @admission.respond_to?(:allocation_admit_handler=)
          @admission.allocation_admit_handler = @container_manager.method(:admit)
        end
        # GracefulNodeShutdown: a manager only with a shutdown grace period.
        @shutdown_manager = shutdown_manager || build_shutdown_manager(shutdown, feature_gates, kubelet_root, error_handler)
        @pod_resources.metrics = @kubelet_metrics.registry if @pod_resources.respond_to?(:metrics=) && !@pod_resources.frozen?
        @device_plugins.metrics = @kubelet_metrics.registry if @device_plugins.respond_to?(:metrics=) && !@device_plugins.frozen?
        @dra_manager.metrics = @kubelet_metrics.registry if @dra_manager.respond_to?(:metrics=) && !@dra_manager.frozen?
        if @credential_providers.respond_to?(:metrics=) && !@credential_providers.frozen?
          @credential_providers.metrics = @kubelet_metrics.registry
        end
        if @qos_cgroup_manager.respond_to?(:cgroup_observer=) && !@qos_cgroup_manager.frozen?
          cgroup_metrics = @kubelet_metrics
          @qos_cgroup_manager.cgroup_observer = ->(operation, seconds) { cgroup_metrics.cgroup_operation(operation, seconds) }
        end
        if @shutdown_manager.respond_to?(:gauge_sink=) && !@shutdown_manager.frozen?
          shutdown_gauges = @kubelet_metrics.registry
          @shutdown_manager.gauge_sink = ->(name, value) { shutdown_gauges.set(name, value) }
        end
        if @shutdown_manager && @admission.respond_to?(:shutdown_admit_handler=)
          @admission.shutdown_admit_handler = @shutdown_manager.method(:admit)
        end
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
        @stop_requested = false
        @startup_error = nil
        @recovery_report = nil
        @recovered = false
      end
      attr_reader :declared_features, :stats_provider, :eviction_manager, :image_gc_manager, :dra_manager, :plugin_manager, :csi_plugins,
                  :kubelet_metrics, :container_manager, :shutdown_manager, :capacity, :allocatable, :node_name, :api, :runtime, :lifecycle, :sync_loop, :status, :lease_duration_seconds, :node_namespace, :startup_error, :recovery_report

      def registered?
        @mutex.synchronize { @registered }
      end

      def running?
        @mutex.synchronize { @running }
      end

      def ready?
        @mutex.synchronize { @ready }
      end

      def node
        build_node(ready: ready?)
      end

      alias registration node

      def lease
        @mutex.synchronize { @lease&.to_h }
      end

      def register(force: false)
        ensure_recovered!
        @mutex.synchronize do
          return node if @registered && !force
        end
        object = build_node(ready: true)
        @kubelet_metrics&.node_registration_attempted
        persist_node(object)
        @mutex.synchronize do
          @registered = true
          @ready = true
          @startup_error = nil
        end
        renew_lease(force: true)
        object
      rescue StandardError => error
        set_ready(false, reason: "RegistrationFailed", message: error.message, persist: false)
        raise
      end

      alias register_node register

      def renew_lease(force: false, now: nil)
        timestamp = time_value(now)
        @mutex.synchronize do
          return @lease&.to_h if !force && @last_lease_renewal && timestamp.to_f - @last_lease_renewal.to_f < @lease_renew_interval
        end
        previous = @mutex.synchronize { @lease }
        transitions = previous ? previous.transitions : 0
        current = Lease.new(
          node_name: @node_name,
          namespace: @node_namespace,
          duration_seconds: @lease_duration_seconds,
          renew_time: iso8601(timestamp),
          transitions: transitions
        ).freeze
        persist_lease(current.to_h, existing: !previous.nil?)
        @mutex.synchronize do
          @lease = current
          @last_lease_renewal = timestamp
          @ready = true
        end
        current.to_h
      rescue StandardError => error
        set_ready(false, reason: "LeaseRenewalFailed", message: error.message)
        raise
      end

      alias heartbeat renew_lease

      def start(lease_thread: false)
        perform_recovery!
        unless registered?
          begin
            register
          rescue StandardError => error
            @mutex.synchronize { @startup_error = error }
            # Registration is a readiness boundary. The sync loop must not
            # accept Pods while the node is absent from the API server; the
            # lease thread retries registration without opening the worker.
            raise unless @error_handler
          end
        end
        unless registered?
          @mutex.synchronize do
            @running = false
            @ready = false
          end
          start_lease_thread if lease_thread
          return self
        end
        start_sync_loop
        start_lease_thread if lease_thread
        self
      end

      def run
        start(lease_thread: true)
        @lease_thread&.join
        self
      end

      def stop(reason: "shutdown")
        @mutex.synchronize do
          @running = false
          @stop_requested = true
          @lease_condition.broadcast
        end
        @mutex.synchronize { @node_status_condition.broadcast }
        @sync_loop.stop if @sync_loop.respond_to?(:stop)
        @wakeups&.stop
        @static_pods&.stop
        @device_plugins&.stop
        @pod_resources&.stop
        @eviction_manager.stop if @eviction_manager.respond_to?(:stop)
        @image_gc_manager&.stop
        Array(@cri_image_gc_managers).each(&:stop)
        @container_manager&.stop
        @qos_cgroup_manager&.stop
        @shutdown_manager&.stop
        @plugin_manager&.stop
        @dra_manager&.stop
        @evented_pleg&.stop
        @pod_certificate_manager&.stop
        @relist_thread&.join if @relist_thread && @relist_thread != Thread.current
        @node_status_thread&.join if @node_status_thread && @node_status_thread != Thread.current
        @lease_thread&.join if @lease_thread && @lease_thread != Thread.current
        set_ready(false, reason: "NodeStopping", message: reason.to_s, persist: false)
        self
      end

      alias close stop

      # Deterministic single iteration: renew the lease if due and let the
      # SyncLoop process watch/resync input.
      def run_once(events: nil, now: nil, resync: true)
        perform_recovery!
        register unless registered?
        renew_lease(now: now)
        @sync_loop.run_once(events: events, now: monotonic_value(now), resync: resync) if @sync_loop.respond_to?(:run_once)
        self
      rescue StandardError => error
        set_ready(false, reason: "AgentLoopFailed", message: error.message)
        @error_handler&.call(error)
        raise
      end

      alias tick run_once

      def recover(observer: nil, cleaner: nil, force: false)
        report = if @lifecycle.respond_to?(:recover)
                   callable = @lifecycle.method(:recover)
                   options = {observer: observer, cleaner: cleaner, force: force}
                   if callable.parameters.any? { |kind, _| kind == :keyrest }
                     callable.call(**options.compact)
                   else
                     accepted = callable.parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
                     callable.call(**options.select { |key, _| accepted.include?(key) })
                   end
                 elsif @runtime.respond_to?(:recover)
                   callable = @runtime.method(:recover)
                   options = {observer: observer, cleaner: cleaner}
                   if callable.parameters.any? { |kind, _| kind == :keyrest }
                     callable.call(**options.compact)
                   else
                     accepted = callable.parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
                     callable.call(**options.select { |key, _| accepted.include?(key) })
                   end
                 else
                   {"ready" => true, "errors" => [], "blocked" => []}
                 end
        report = report.to_h if report.respond_to?(:to_h)
        report = if report.is_a?(Hash)
                   Helpers.string_keys(report)
                 elsif report == true
                   {"ready" => true, "errors" => [], "blocked" => []}
                 elsif report == false || report.nil?
                   {"ready" => false, "errors" => ["recovery returned #{report.nil? ? "no report" : "false"}"], "blocked" => []}
                 else
                   {"ready" => false, "errors" => ["recovery returned an invalid report"], "blocked" => []}
                 end
        errors = Array(report["errors"]).map(&:to_s)
        errors.concat(Array(report["identity_mismatch"]).map do |entry|
          "resource identity mismatch: #{recovery_resource_key(entry)}"
        end)
        cleaned_orphans = Array(report["cleaned_orphans"]).map(&:to_s)
        unresolved_orphans = Array(report["orphans"]).filter_map do |entry|
          key = recovery_resource_key(entry)
          key unless cleaned_orphans.include?(key)
        end
        # HandlePodCleanups: runtime Pods no worker knew of (orphaned).
        orphaned = Array(report["orphans"]).length
        @kubelet_metrics&.orphaned_runtime_pod(orphaned) if orphaned.positive?
        errors.concat(unresolved_orphans.map { |key| "unresolved orphan resource: #{key}" })
        blocked = Array(report["blocked"]).map(&:to_s)
        pod_errors = report["pod_errors"].is_a?(Hash) ? report["pod_errors"] : {}
        unless errors.empty? && report.fetch("ready", true) == true
          reason = (errors + blocked.map { |uid| "Pod #{uid} recovery is pending" }).join("; ")
          set_ready(false, reason: "RecoveryRequired", message: reason, persist: false)
          raise Runtime::RecoveryRequired, reason
        end
        # A Pod whose cleanup is still pending is reported and retried by the
        # lifecycle (retry_pending_cleanups); it does not keep the node down.
        blocked.each do |uid|
          detail = Array(pod_errors[uid]).join("; ")
          @error_handler&.call(Runtime::RecoveryRequired.new("Pod #{uid} recovery is pending#{": #{detail}" unless detail.empty?}"),
                               :pod_recovery_pending, uid)
        end
        @mutex.synchronize do
          @recovery_report = Helpers.deep_copy(report).freeze
          @recovered = true
          @ready = false
        end
        Helpers.deep_copy(report)
      rescue StandardError => error
        @mutex.synchronize do
          @recovered = false
          @recovery_report = {"ready" => false, "errors" => [error.message], "blocked" => []}.freeze
          @ready = false
        end
        raise
      end

      def set_ready(value, reason: nil, message: nil, persist: true)
        @mutex.synchronize { @ready = !!value }
        return unless persist

        persist_node(build_node(ready: value, reason: reason, message: message))
      end

      private

      # The final delete of a gracefully deleted Pod: the API server set its
      # deletionTimestamp and waits for the kubelet to confirm the containers
      # are gone (upstream's status manager does this).  Nil when the injected
      # API has no delete at all, so unit fixtures keep working.
      def pod_deleter_for(api)
        if api.respond_to?(:delete_pod)
          return lambda { |namespace:, name:, uid: nil|
            api.delete_pod(namespace: namespace, name: name, uid: uid)
          }
        end
        return nil unless api.respond_to?(:delete)

        lambda do |namespace:, name:, uid: nil|
          # gracePeriodSeconds=0 is what makes this DELETE remove the object
          # rather than restart the grace period: upstream's status manager
          # sends exactly this once the containers are gone
          # (pkg/kubelet/status/status_manager.go: "deleteOptions :=
          # metav1.DeleteOptions{GracePeriodSeconds: new(int64), Preconditions:
          # metav1.NewUIDPreconditions(string(pod.UID))}").  Without it the
          # second DELETE only re-set the deletionTimestamp, and the Pod stayed
          # Terminating for ever even though its containers had stopped.
          #
          # The UID precondition is the other half: the name may already have
          # been reused by a replacement Pod, and deleting that one instead
          # would kill a healthy workload.
          options = {"gracePeriodSeconds" => 0}
          options["preconditions"] = {"uid" => uid.to_s} unless uid.nil? || uid.to_s.empty?
          begin
            api.delete("pods", name, namespace: namespace, api_version: "v1", options: options)
          rescue ArgumentError
            # An injected API without DeleteOptions support still gets the
            # grace period, which is the half that removes the object.
            api.delete("pods", name, namespace: namespace, api_version: "v1",
                                     query: {"gracePeriodSeconds" => "0"})
          end
        end
      end

      def ensure_recovered!
        return if @mutex.synchronize { @recovered }

        perform_recovery!
      end

      def perform_recovery!
        return @recovery_report if @mutex.synchronize { @recovered }

        recover
      end

      def recovery_resource_key(entry)
        return entry.to_s unless entry.is_a?(Hash)

        kind = entry["kind"] || entry[:kind]
        id = entry["id"] || entry[:id]
        return entry.to_s if kind.nil? || id.nil?

        "#{kind}:#{id}"
      end

      def start_lease_thread
        @mutex.synchronize do
          return if @lease_thread&.alive?

          @lease_thread = Thread.new { lease_loop }
        end
      end

      def lease_loop
        until @mutex.synchronize { @stop_requested }
          begin
            if registered?
              renew_lease
              sync_extended_resources
            else
              register
              start_sync_loop unless @mutex.synchronize { @stop_requested }
            end
          rescue StandardError => error
            @error_handler&.call(error)
          end
          wait_for_lease_interval
        end
      end

      # kubelet nodestatus MachineInfo: every resource in the Node's capacity is
      # carried into allocatable on each status sync, including extended
      # resources this agent does not manage itself, and extended resources
      # gone from capacity leave allocatable.  The agent never did this, so a
      # resource a client wrote into capacity never became allocatable, the
      # scheduler could place nothing that requested it, and the agent's own
      # admission rejected it anyway -- "[sig-scheduling] SchedulerPreemption
      # PreemptionExecutionPath runs ReplicaSets to verify preemption running
      # path" adds "example.com/fakecpu" and its ReplicaSets never ran.
      def sync_extended_resources
        return unless @api.respond_to?(:read_object) && @api.respond_to?(:patch_node_status)

        node = @api.read_object("nodes", @node_name)
        status = node.is_a?(Hash) ? (node["status"] || {}) : {}
        capacity = status["capacity"].is_a?(Hash) ? status["capacity"] : {}
        allocatable = status["allocatable"].is_a?(Hash) ? status["allocatable"] : {}
        # Device plugin resources are this agent's own (allocatable = the
        # healthy devices); only the others are carried over from capacity.
        managed = @device_plugins ? @device_plugins.resource_names : []
        extended = capacity.select do |name, _|
          ResourceManager.extended_resource?(name) && !@capacity.key?(name.to_s) && !managed.include?(name.to_s)
        end
        patch = extended.reject { |name, value| allocatable[name] == value }
        allocatable.each_key do |name|
          next if managed.include?(name.to_s)

          patch[name] = nil if ResourceManager.extended_resource?(name) && !@capacity.key?(name.to_s) && !capacity.key?(name)
        end
        @api.patch_node_status(@node_name, {"allocatable" => patch}) unless patch.empty?
        manager = @admission.respond_to?(:resource_manager) ? @admission.resource_manager : nil
        manager.replace_extended(extended.merge(device_capacity.last)) if manager.respond_to?(:replace_extended)
      rescue StandardError => error
        @error_handler&.call(error)
      end

      # The Node's labels as the API server holds them now, for admission.
      def live_node_labels_provider(api)
        return nil unless api.respond_to?(:read_object)

        lambda do
          node = api.read_object("nodes", @node_name)
          labels = node.is_a?(Hash) ? node.dig("metadata", "labels") : nil
          labels.is_a?(Hash) ? @node_labels.merge(labels) : nil
        end
      end

      # kubelet HandlePodUpdates: an update of a Pod on this node that needs
      # a feature the node does not declare is reported (Warning
      # FailedNodeDeclaredFeaturesCheck); the API server's
      # NodeDeclaredFeatureValidator is what refuses it.
      def check_declared_features_update(pod)
        return if @declared_features.nil? || !@admission.respond_to?(:missing_update_features) || !pod.is_a?(Hash)

        metadata = pod["metadata"] || {}
        previous = @lifecycle.respond_to?(:record) ? @lifecycle.record(metadata["uid"].to_s) : nil
        old_pod = previous.is_a?(Hash) ? previous[:pod] : nil
        return if old_pod.nil?

        missing = @admission.missing_update_features(old_pod, pod)
        return if missing.empty? || @event_recorder.nil?

        @event_recorder.record(
          involved_object: {"apiVersion" => "v1", "kind" => "Pod", "namespace" => metadata["namespace"],
                            "name" => metadata["name"], "uid" => metadata["uid"]},
          reason: "FailedNodeDeclaredFeaturesCheck", type: "Warning", namespace: metadata["namespace"],
          message: "Pod requires node features that are not available: #{missing.join(", ")}"
        )
      rescue StandardError => error
        @error_handler&.call(error)
      end

      def wait_for_lease_interval
        if @sleeper.equal?(DEFAULT_SLEEPER)
          @mutex.synchronize do
            @lease_condition.wait(@mutex, @lease_renew_interval) unless @stop_requested
          end
        else
          @sleeper.call(@lease_renew_interval)
        end
      end

      # PLEG-style relist: notice containers that exited on their own between
      # syncs so restart policy and Pod phase follow the process, not the
      # resync timer.
      def start_relist_thread
        return unless @lifecycle.respond_to?(:observe_exits) && @lifecycle.respond_to?(:running_pod_uids)
        return unless @sleeper.equal?(DEFAULT_SLEEPER)

        @mutex.synchronize do
          return if @relist_thread&.alive?

          @relist_thread = Thread.new { relist_loop }
        end
      end

      # EventedPLEG (feature gate, off by default): with a CRI runtime that
      # streams container events, the generic relist slows to 300 s and the
      # events drive the lifecycle; if the stream keeps failing the relist
      # period is restored.
      def start_evented_pleg
        return unless @feature_gates.fetch("EventedPLEG", false) == true
        return unless @runtime.respond_to?(:client) && @runtime.client.respond_to?(:stream)
        return unless @lifecycle.respond_to?(:observe_exits)
        return if @evented_pleg&.in_use?

        default_period = @relist_period
        @evented_pleg = EventedPLEG.new(
          client: @runtime.client, metrics: @kubelet_metrics, logger: @logger,
          on_event: lambda do |uid, _type, _container_id|
            @lifecycle.observe_exits(uid)
          rescue StandardError => error
            @error_handler&.call(error, :evented_pleg, uid)
          end,
          relist: -> { relist_once },
          on_fallback: lambda do
            @relist_period = default_period
            @error_handler&.call(RuntimeError.new("evented PLEG gave up after #{EventedPLEG::MAX_STREAM_RETRIES} stream failures; generic relist at #{default_period}s"), :evented_pleg)
          end
        )
        @relist_period = EventedPLEG::GENERIC_RELIST_SECONDS_WITH_EVENTS
        @evented_pleg.start
      end

      # RuntimeConfig support of the CRI runtimes (kubelet_cri_losing_support).
      def check_cri_runtime_support
        return if @runtime.nil?

        Thread.new do
          Thread.current.name = "cri-support-check"
          CRISupportCheck.run(runtime: @runtime, metrics: @kubelet_metrics, logger: @logger)
        rescue StandardError => error
          @error_handler&.call(error, :cri_support_check)
        end
      end

      def relist_loop
        until @mutex.synchronize { @stop_requested }
          begin
            relist_once
          rescue StandardError => error
            @error_handler&.call(error, :relist)
          end
          sleep(@relist_period)
        end
      end

      def relist_once
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        relist_pods
      ensure
        @kubelet_metrics&.pleg_relist(started, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) if started
      end

      def relist_pods
        @lifecycle.running_pod_uids.each do |uid|
          @lifecycle.observe_exits(uid)
        rescue StandardError => error
          # GenericPLEG: a Pod whose runtime state could not be inspected
          # this relist is skipped (its events discarded) and tried again.
          @kubelet_metrics&.pleg_discard_event
          @error_handler&.call(error, :relist, uid)
        end
        return unless @lifecycle.respond_to?(:retry_pending_cleanups)

        begin
          @lifecycle.retry_pending_cleanups
        rescue StandardError => error
          @error_handler&.call(error, :relist)
        end
      end

      attr_reader :static_pods, :device_plugins, :pod_resources

      # The Pods whose containers run here (podresources lists active Pods).
      def running_pods_for_pod_resources
        records = @lifecycle.respond_to?(:records) ? @lifecycle.records.values : []
        records.filter_map do |record|
          next unless record.is_a?(Hash) && record[:state] == "Running"

          pod = record[:pod]
          pod.is_a?(Hash) ? Helpers.string_keys(pod) : nil
        end
      end

      # [capacity, allocatable] of the device plugin resources, as quantities.
      def device_capacity
        return [{}, {}] unless @device_plugins

        capacity, allocatable = @device_plugins.capacity
        [capacity.transform_values(&:to_s), allocatable.transform_values(&:to_s)]
      rescue StandardError
        [{}, {}]
      end

      # A plugin registered, its devices changed or it went away: the Node
      # status and the admission view follow at once (kubelet updates the
      # node status on the device manager's callback).
      # The credential provider plugins, with the Pod-bound ServiceAccount
      # tokens they may ask for (TokenRequest with a Pod boundObjectRef).
      def build_credential_providers(section, api)
        section = Helpers.string_keys(section || {})
        return nil if section["config"].to_s.empty?

        client = api.respond_to?(:client) ? api.client : nil
        token_requester = lambda do |namespace, name, audience:, service_account_uid:, pod_name:, pod_uid:|
          raise "no API client for ServiceAccount tokens" unless client

          request = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest",
                     "metadata" => {"uid" => service_account_uid},
                     "spec" => {"audiences" => [audience],
                                "boundObjectRef" => {"apiVersion" => "v1", "kind" => "Pod", "name" => pod_name, "uid" => pod_uid}}}
          response = client.raw("POST", "/api/v1/namespaces/#{namespace}/serviceaccounts/#{name}/token", body: JSON.generate(request),
                                                                                                         headers: {"Content-Type" => "application/json"})
          JSON.parse(response.body.to_s).dig("status", "token").to_s
        end
        reader = lambda do |namespace, name|
          client&.get("serviceaccounts", name, namespace: namespace)
        rescue StandardError
          nil
        end
        gates = Helpers.string_keys(@feature_gates || {})
        CredentialProviders.load(config_path: section["config"], bin_dir: section["bin_dir"].to_s, token_requester: token_requester,
                                 service_account_reader: reader,
                                 sa_tokens: gates.fetch("KubeletServiceAccountTokenForCredentialProviders", true) != false)
      end

      def device_plugins_changed
        return unless registered?

        manager = @admission.respond_to?(:resource_manager) ? @admission.resource_manager : nil
        if manager.respond_to?(:replace_extended)
          current = manager.allocatable_values.select { |name, _| ResourceManager.extended_resource?(name) }
          managed = @device_plugins.resource_names
          current = current.reject { |name, _| managed.include?(name.to_s) }.transform_values(&:to_s)
          manager.replace_extended(current.merge(device_capacity.last))
        end
        # Status is a subresource: an apply of the Node object does not carry
        # it, so the device counts go out as a merge patch of /status, and a
        # resource whose plugin is gone is removed from both maps.
        capacity, allocatable = device_capacity
        gone = (@published_device_resources || []) - capacity.keys
        patch = {"capacity" => capacity.merge(gone.to_h { |name| [name, nil] }),
                 "allocatable" => allocatable.merge(gone.to_h { |name| [name, nil] })}
        if @api.respond_to?(:patch_node_status)
          @api.patch_node_status(@node_name, patch)
        else
          persist_node(build_node(ready: ready?))
        end
        @published_device_resources = capacity.keys
      rescue StandardError => error
        @error_handler&.call(error)
      end

      def mirror_pod?(pod)
        annotations = pod.is_a?(Hash) ? (pod.dig("metadata", "annotations") || pod.dig(:metadata, :annotations) || {}) : {}
        annotations.key?(StaticPods::CONFIG_MIRROR) || annotations.key?(StaticPods::CONFIG_MIRROR.to_sym)
      end

      def error_handler_logger(error_handler)
        return nil unless error_handler.respond_to?(:call)

        handler = error_handler
        Object.new.tap do |logger|
          logger.define_singleton_method(:warn) do |event, **fields|
            handler.call(RuntimeError.new("#{event} #{fields}"))
          rescue StandardError
            nil
          end
        end
      end

      def start_sync_loop
        return if @mutex.synchronize { @running || @stop_requested }

        @sync_loop.start if @sync_loop.respond_to?(:start)
        @static_pods&.start
        begin
          @pod_resources&.start
        rescue StandardError => error
          @error_handler&.call(error)
        end
        begin
          @device_plugins&.start
        rescue StandardError => error
          @error_handler&.call(error)
        end
        start_relist_thread
        start_evented_pleg
        check_cri_runtime_support
        start_node_status_thread
        # kubelet: evictionManager.Start(..., evictionMonitoringPeriod).
        @eviction_manager.start if @eviction_manager.respond_to?(:start) && @sleeper.equal?(DEFAULT_SLEEPER)
        # kubelet StartGarbageCollection: image GC every ImageGCPeriod.
        @image_gc_manager.start if @image_gc_manager && @sleeper.equal?(DEFAULT_SLEEPER)
        Array(@cri_image_gc_managers).each(&:start) if @sleeper.equal?(DEFAULT_SLEEPER)
        # The shutdown manager's logind watch (inhibitor lock + PrepareForShutdown).
        @shutdown_manager.start if @shutdown_manager && @sleeper.equal?(DEFAULT_SLEEPER)
        # cpuManager reconcileState every cpuManagerReconcilePeriod.
        @container_manager.start_reconcile if @container_manager && @sleeper.equal?(DEFAULT_SLEEPER)
        # DRA: registration reconciler (1 s) and the manager's own loop.
        if @sleeper.equal?(DEFAULT_SLEEPER)
          @dra_manager&.start
          begin
            # InitializeCSINodeWithAnnotation, before any plugin registers.
            @csi_plugins&.initialize_csi_node
          rescue StandardError => error
            @error_handler&.call(error, :csi_node_init)
          end
          @plugin_manager&.start
        end
        @mutex.synchronize do
          @running = true
          @stop_requested = false
        end
        true
      end

      def build_node(ready:, reason: nil, message: nil)
        timestamp = iso8601(time_value(nil))
        # ReadyCondition: the shutdown manager's error makes the node NotReady.
        if ready && (shutdown = @shutdown_manager&.shutdown_status)
          ready = false
          reason = "KubeletNotReady"
          message = shutdown
        end
        message = "kubelet is posting ready status" if ready && message.nil?
        status = ready ? "True" : "False"
        # setNodeReadyCondition: the transition time moves only when the
        # status does; the heartbeat on every build.
        transition = @pressure_mutex.synchronize do
          previous = @ready_condition
          moment = previous && previous[0] == status ? previous[1] : timestamp
          @ready_condition = [status, moment]
          moment
        end
        conditions = [
          {
            "type" => "Ready",
            "status" => status,
            "reason" => reason || (ready ? "KubeletReady" : "KubeletNotReady"),
            "message" => message.to_s,
            "lastHeartbeatTime" => timestamp,
            "lastTransitionTime" => transition
          },
          *pressure_conditions(timestamp)
        ]
        Helpers.immutable(
          "apiVersion" => "v1",
          "kind" => "Node",
          "metadata" => {
            "name" => @node_name,
            "labels" => @node_labels,
            "annotations" => @node_annotations
          },
          "spec" => {},
          "status" => {
            "capacity" => @capacity.merge(device_capacity.first),
            "allocatable" => @allocatable.merge(device_capacity.last),
            "addresses" => @addresses,
            "conditions" => conditions,
            # The API server proxies logs/exec/attach/port-forward to this port;
            # a Node without it cannot serve any streaming subresource.
            # v1.DaemonEndpoint's JSON field is "Port" with a capital P
            # (types.go: `json:"Port"`), unlike every neighbouring field.
            # Writing "port" made the API server drop it and default the
            # endpoint to 0, so every logs/exec/attach/port-forward request
            # was proxied to the standard kubelet port instead of this node's.
            "daemonEndpoints" => @streaming_port ? {"kubeletEndpoint" => {"Port" => @streaming_port}} : nil,
            # kubelet_node_status.go: set on every status update while the gate is on.
            "declaredFeatures" => @declared_features,
            "images" => @status_images&.images,
            "volumesInUse" => volumes_in_use,
            "runtimeHandlers" => @runtime_handlers,
            # SupplementalGroupsPolicy: Merge and Strict both honoured.
            "features" => @runtime_handlers ? {"supplementalGroupsPolicy" => true} : nil,
            "nodeInfo" => @host_info.merge(
              "architecture" => @architecture,
              "operatingSystem" => @operating_system,
              "containerRuntimeVersion" => "rubernetes://#{Rubernetes::VERSION}",
              "kubeletVersion" => Rubernetes::KUBERNETES_GIT_VERSION,
              # DisableNodeKubeProxyVersion is locked on in v1.36: the field
              # is left empty.
              "kubeProxyVersion" => "",
              "osImage" => @host_info["osImage"].to_s.empty? ? @operating_system : @host_info["osImage"]
            )
          }.compact
        )
      end

      # nodestatus MemoryPressureCondition / DiskPressureCondition /
      # PIDPressureCondition: from the eviction manager's node conditions,
      # lastTransitionTime moving only when the status does.
      PRESSURE_CONDITIONS = {
        "MemoryPressure" => [["KubeletHasInsufficientMemory", "kubelet has insufficient memory available"],
                             ["KubeletHasSufficientMemory", "kubelet has sufficient memory available"]],
        "DiskPressure" => [["KubeletHasDiskPressure", "kubelet has disk pressure"],
                           ["KubeletHasNoDiskPressure", "kubelet has no disk pressure"]],
        "PIDPressure" => [["KubeletHasInsufficientPID", "kubelet has insufficient PID available"],
                          ["KubeletHasSufficientPID", "kubelet has sufficient PID available"]]
      }.freeze

      def pressure_conditions(timestamp)
        active = @eviction_manager.respond_to?(:node_conditions) ? @eviction_manager.node_conditions : []
        @pressure_mutex.synchronize do
          PRESSURE_CONDITIONS.map do |type, (pressured, clear)|
            on = active.include?(type)
            reason, message = on ? pressured : clear
            status = on ? "True" : "False"
            previous = @pressure_conditions[type]
            transition = previous && previous[0] == status ? previous[1] : timestamp
            @pressure_conditions[type] = [status, transition]
            {"type" => type, "status" => status, "reason" => reason, "message" => message,
             "lastHeartbeatTime" => timestamp, "lastTransitionTime" => transition}
          end
        end
      end

      # GetNodeAllocatableReservation.  reservedSystemCPUs replaces the CPU
      # of both reservations with its own size (kubelet server.go).
      def node_allocatable_reservation(system_reserved, kube_reserved, reserved_system_cpus, eviction, host:)
        system = Helpers.string_keys(system_reserved || {})
        kube = Helpers.string_keys(kube_reserved || {})
        unless reserved_system_cpus.nil? || reserved_system_cpus.to_s.empty?
          system["cpu"] = CPUManager::CPUSet.parse(reserved_system_cpus.to_s).size.to_s
          kube.delete("cpu")
        end
        config = Helpers.string_keys(eviction || {})
        hard = []
        if host && config.fetch("enabled", true) != false
          hard = EvictionManager.parse_threshold_config(hard: config.fetch("hard", EvictionManager::DEFAULT_EVICTION_HARD),
                                                        allocatable_config: [])
        end
        return {} if system.empty? && kube.empty? && hard.empty?

        NodeAllocatable.reservation(capacity: @capacity, system_reserved: system, kube_reserved: kube, hard_thresholds: hard)
      end

      def volumes_in_use
        return nil unless @lifecycle.respond_to?(:volumes_in_use)

        names = @lifecycle.volumes_in_use
        names.empty? ? nil : names
      rescue StandardError
        nil
      end

      def cri_clients
        return [] unless @runtime.respond_to?(:backends)

        @runtime.backends.values.select { |backend| backend.respond_to?(:image_gc_source) }.map(&:client).uniq
      end

      # nodestatus.RuntimeHandlers: the default handler ("") and every handler
      # the node serves, with the features each really has: the native
      # runtime applies recursive read-only mounts where mount_setattr(2)
      # exists (5.12) and user namespaces; a microVM neither; a CRI runtime
      # what its Status reports.
      def node_runtime_handlers
        kernel = HostResources.uname_release.to_s[/\A(\d+)\.(\d+)/] ? [Regexp.last_match(1).to_i, Regexp.last_match(2).to_i] : [0, 0]
        native = {"recursiveReadOnlyMounts" => (kernel <=> [5, 12]) >= 0, "userNamespaces" => true}
        handlers = [{"name" => "", "features" => native}]
        backends = @runtime.respond_to?(:backends) ? @runtime.backends : {"rubernetes-native" => @runtime}
        cri_features = {}
        backends.each do |name, backend|
          features = if backend.respond_to?(:image_gc_source)
                       cri_features[backend.client] ||= cri_handler_features(backend.client)
                       cri_features[backend.client].fetch(backend.handler, cri_features[backend.client].fetch("", {}))
                     elsif name.to_s.start_with?("rubernetes-firecracker")
                       {"recursiveReadOnlyMounts" => false, "userNamespaces" => false}
                     else
                       native
                     end
          handlers << {"name" => name.to_s, "features" => features}
        end
        handlers
      rescue StandardError
        nil
      end

      def cri_handler_features(client)
        Array(client.runtime("Status", {"verbose" => false})["runtime_handlers"]).to_h do |handler|
          [handler["name"].to_s, {"recursiveReadOnlyMounts" => handler.dig("features", "recursive_read_only_mounts") == true,
                                  "userNamespaces" => handler.dig("features", "user_namespaces") == true}]
        end
      rescue StandardError
        {}
      end

      # The kubelet's image GC over each CRI runtime the node uses (one per
      # runtime connection, however many handlers share it), with the same
      # thresholds as the node's own images.
      def build_cri_image_gc_managers(image_gc, node_reference, error_handler)
        return [] unless @runtime.respond_to?(:backends) && image_gc.fetch("enabled", true) != false

        clients = @runtime.backends.values.select { |backend| backend.respond_to?(:image_gc_source) }.map(&:client).uniq
        lifecycle_ref = @lifecycle
        pods = lambda do
          records = lifecycle_ref.respond_to?(:records) ? lifecycle_ref.records.values : []
          records.filter_map { |record| record[:pod] unless record[:state].to_s == "Removed" }
        end
        clients.map do |client|
          source = Runtime::CRI::ImageGCSource.new(client: client, in_use: lambda {
            Array(pods.call).flat_map do |pod|
              %w[initContainers containers ephemeralContainers].flat_map do |field|
                Array(pod.dig("spec", field)).map do |container|
                  container["image"]
                end
              end
            end.compact.map do |image|
              Image::Reference.parse(image.to_s).to_s
            rescue StandardError
              image.to_s
            end.to_set
          })
          ImageGCManager.new(
            resolver: source, fs_stats: -> { source.fs_stats }, pods: pods,
            high_threshold_percent: image_gc.fetch("high_threshold_percent", ImageGCManager::DEFAULT_HIGH_THRESHOLD_PERCENT),
            low_threshold_percent: image_gc.fetch("low_threshold_percent", ImageGCManager::DEFAULT_LOW_THRESHOLD_PERCENT),
            min_age: EvictionManager.parse_duration(image_gc.fetch("minimum_age", "2m")),
            max_age: EvictionManager.parse_duration(image_gc.fetch("maximum_age", "0s")),
            recorder: @event_recorder, node_ref: node_reference, error_handler: error_handler
          )
        end
      end

      # enforceNodeAllocatable ("pods" by default) over capacity less
      # system-reserved and kube-reserved; reservedSystemCPUs replaces both
      # reservations' CPU, as for the allocatable reported.
      def build_qos_cgroup_manager(config, system_reserved, kube_reserved, reserved_system_cpus, error_handler, host)
        config = Helpers.string_keys(config || {})
        return nil if !host || config.empty? || config["enabled"] == false

        system = Helpers.string_keys(system_reserved || {})
        kube = Helpers.string_keys(kube_reserved || {})
        unless reserved_system_cpus.nil? || reserved_system_cpus.to_s.empty?
          system["cpu"] = CPUManager::CPUSet.parse(reserved_system_cpus.to_s).size.to_s
          kube.delete("cpu")
        end
        node_reference = {"apiVersion" => "v1", "kind" => "Node", "name" => @node_name, "uid" => @node_name}
        QOSCgroupManager.new(
          root: config.fetch("root"), hierarchy: config.fetch("hierarchy", "rubernetes"), capacity: @capacity, node_name: @node_name,
          system_reserved: system, kube_reserved: kube,
          enforce_node_allocatable: config.fetch("enforce_node_allocatable", ["pods"]),
          system_reserved_cgroup: config["system_reserved_cgroup"], kube_reserved_cgroup: config["kube_reserved_cgroup"],
          active_pods: -> { @lifecycle.respond_to?(:admitted_pods) ? @lifecycle.admitted_pods : [] },
          event: lambda { |type, reason, message|
            @event_recorder&.record(involved_object: node_reference, reason: reason, type: type, namespace: "default", message: message)
          },
          error_handler: error_handler
        )
      end

      def build_container_manager(kubelet_root, host, cpu, memory, topology, reserved_system_cpus, error_handler)
        configured = [cpu, memory, topology].any? { |config| !Helpers.string_keys(config || {}).empty? }
        return nil unless kubelet_root && (host || configured)

        gates = Helpers.string_keys(@feature_gates || {})
        # PodLevelResourceManagers (alpha, off) needs PodLevelResources (on).
        pod_level = gates["PodLevelResourceManagers"] == true && gates.fetch("PodLevelResources", true) != false
        ContainerManager.new(state_directory: kubelet_root, reservation: @reservation, cpu: cpu, memory: memory, topology: topology,
                             reserved_system_cpus: reserved_system_cpus, pod_level_resource_managers: pod_level)
      rescue ContainerManager::Error, CPUManager::Topology::Error, SystemCallError => error
        # A configured policy that cannot run is fatal, as for the kubelet;
        # the default (none) policies must not keep the node from starting.
        raise if configured

        error_handler&.call(error, :container_manager)
        nil
      end

      def start_container_manager
        lifecycle = @lifecycle
        runtime = @runtime
        @container_manager.start(
          active_pods: -> { lifecycle.respond_to?(:admitted_pods) ? lifecycle.admitted_pods : [] },
          container_statuses: lambda { |pod|
            if lifecycle.respond_to?(:container_states)
              lifecycle.container_states(Helpers.key(Helpers.key(pod, "metadata", {}), "uid",
                                                     ""))
            else
              []
            end
          },
          update_cpuset: lambda { |container_id, cpus|
            runtime.update_container_cpuset(container_id, cpus) if runtime.respond_to?(:update_container_cpuset)
          },
          sources_ready: -> { @recovered }
        )
      end

      def build_eviction_manager(config)
        thresholds = EvictionManager.parse_threshold_config(
          hard: config.fetch("hard", EvictionManager::DEFAULT_EVICTION_HARD),
          soft: config.fetch("soft", {}), soft_grace_period: config.fetch("soft_grace_period", {}),
          minimum_reclaim: config.fetch("minimum_reclaim", {})
        )
        lifecycle = @lifecycle
        # buildSignalToNodeReclaimFuncs: disk signals first try deleting unused
        # images (dead containers are already removed when replaced).
        reclaim = if @image_gc_manager
                    delete_images = -> { @image_gc_manager.delete_unused_images }
                    [EvictionManager::NODEFS_AVAILABLE, EvictionManager::NODEFS_INODES_FREE, EvictionManager::IMAGEFS_AVAILABLE,
                     EvictionManager::IMAGEFS_INODES_FREE, EvictionManager::CONTAINERFS_AVAILABLE,
                     EvictionManager::CONTAINERFS_INODES_FREE].to_h { |signal| [signal, [delete_images]] }
                  else
                    {}
                  end
        EvictionManager.new(
          summary_provider: @stats_provider, thresholds: thresholds,
          active_pods: -> { lifecycle.respond_to?(:admitted_pods) ? lifecycle.admitted_pods : [] },
          kill_pod: method(:evict_pod),
          pressure_transition_period: EvictionManager.parse_duration(config.fetch("pressure_transition_period", "5m")),
          max_pod_grace_period_seconds: config.fetch("max_pod_grace_period_seconds", 0),
          dedicated_image_fs: -> { @stats_provider.respond_to?(:dedicated_image_fs?) && @stats_provider.dedicated_image_fs? },
          node_reclaim: reclaim,
          recorder: @event_recorder,
          node_ref: node_reference,
          pod_cleaned_up: lambda { |pod|
            record = lifecycle.respond_to?(:record) ? lifecycle.record(pod.dig("metadata", "uid").to_s) : nil
            record.nil? || %w[Removed].include?(record[:state].to_s)
          },
          error_handler: @error_handler,
          on_conditions_changed: ->(_conditions) { persist_pressure_conditions }
        )
      end

      # killPodFunc: the Pod's own worker carries the eviction out.
      def evict_pod(pod, grace_period_seconds:, message:, condition:, reason: Lifecycle::EVICTED_REASON)
        uid = pod.dig("metadata", "uid").to_s
        if @lifecycle.respond_to?(:request_eviction) && @sync_loop.respond_to?(:enqueue_pod)
          @lifecycle.request_eviction(uid, message: message, grace_period_seconds: grace_period_seconds, condition: condition,
                                           reason: reason)
          current = if @sync_loop.respond_to?(:cache)
                      begin
                        @sync_loop.cache[uid]
                      rescue StandardError
                        nil
                      end
                    end
          @sync_loop.enqueue_pod(current || pod, action: "MODIFIED")
        elsif @lifecycle.respond_to?(:evict)
          @lifecycle.evict(pod, message: message, grace_period_seconds: grace_period_seconds, condition: condition, reason: reason)
        end
      end

      # nodeshutdown.NewManager with the kubelet's shutdownGracePeriod*
      # settings; nil (managerStub) without a grace period.
      # The volume manager's SELinux desired-state checks (KEP-1710) on the
      # Pod volumes; CSIDriver.spec.seLinuxMount read through the node's reader.
      def attach_selinux_tracker
        pod_volumes = @lifecycle.respond_to?(:pod_volumes) ? @lifecycle.pod_volumes : nil
        return unless pod_volumes.respond_to?(:selinux_tracker=) && pod_volumes.selinux_tracker.nil?

        reader = @lifecycle.respond_to?(:resource_reader) ? @lifecycle.resource_reader : nil
        csi_driver_reader = lambda do |driver|
          reader.respond_to?(:get) ? reader.get("csidrivers", driver, namespace: nil) : nil
        rescue StandardError
          nil
        end
        pod_volumes.selinux_tracker = Volume::SELinux::Tracker.new(metrics: @kubelet_metrics, feature_gates: @feature_gates,
                                                                   csi_driver_reader: csi_driver_reader, logger: @logger)
      end

      # PodCertificateRequest (feature gate, off by default): projected
      # podCertificate sources are served by the PodCertificateManager.
      def attach_pod_certificate_manager
        return unless @feature_gates.fetch("PodCertificateRequest", false) == true

        pod_volumes = @lifecycle.respond_to?(:pod_volumes) ? @lifecycle.pod_volumes : nil
        client = @api.respond_to?(:client) ? @api.client : nil
        return unless pod_volumes.respond_to?(:pod_certificates=) && client

        recorder = @event_recorder
        manager = PodCertificateManager.new(
          client: client, node_name: @node_name, logger: @logger,
          node_uid: lambda do
            node = client.get("nodes", @node_name, api_version: "v1")
            node.is_a?(Hash) ? node.dig("metadata", "uid").to_s : ""
          rescue StandardError
            ""
          end,
          events: lambda do |pod, type, reason, message|
            recorder&.record(involved_object: pod, reason: reason, message: message, type: type)
          end
        )
        pod_volumes.pod_certificates = manager
        @kubelet_metrics.pod_certificates = manager if @kubelet_metrics.respond_to?(:pod_certificates=)
        @pod_certificate_manager = manager.start
      end

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
          active_pods: -> { lifecycle.respond_to?(:admitted_pods) ? lifecycle.admitted_pods : [] },
          kill_pod: lambda { |pod, grace, message:, reason:, condition:|
            evict_pod(Helpers.string_keys(pod), grace_period_seconds: grace, message: message, condition: condition, reason: reason)
          },
          pod_terminated: lambda { |pod|
            record = lifecycle.respond_to?(:record) ? lifecycle.record(Helpers.key(Helpers.key(pod, "metadata", {}), "uid", "")) : nil
            record.nil? || Lifecycle::INACTIVE_STATES.include?(record[:state].to_s)
          },
          sync_node_status: -> { persist_node(build_node(ready: ready?)) if registered? },
          state_directory: kubelet_root, recorder: @event_recorder, node_ref: node_reference, error_handler: error_handler
        )
      end

      def node_reference
        {"apiVersion" => "v1", "kind" => "Node", "name" => @node_name, "uid" => @node_name}
      end

      # preemption.NewCriticalPodAdmissionHandler(getAllocatedPods, killPodNow,
      # recorder): the admitted Pods and the eviction path are the
      # lifecycle's, looked up when a critical Pod is refused.
      def build_preemption
        Preemption.new(
          active_pods: -> { @lifecycle.respond_to?(:admitted_pods) ? @lifecycle.admitted_pods : [] },
          kill_pod: lambda { |pod, message:, condition:, reason:|
            evict_pod(Helpers.string_keys(pod), grace_period_seconds: nil, message: message, condition: condition, reason: reason)
          },
          recorder: @event_recorder,
          metrics: -> { @kubelet_metrics }
        )
      end

      def persist_pressure_conditions
        return unless registered?

        persist_node(build_node(ready: ready?))
      end

      def quantity_bytes(value)
        return nil if value.nil?

        Schema::Quantity.from_json(value).value.to_i
      rescue StandardError
        nil
      end

      # updateNodeStatus: a status the API server took with Ready=True
      # (RecordNodeReady).
      def node_status_persisted(response)
        conditions = response.is_a?(Hash) ? Array(response.dig("status", "conditions")) : []
        ready = conditions.any? { |condition| condition.is_a?(Hash) && condition["type"] == "Ready" && condition["status"] == "True" }
        @kubelet_metrics&.node_ready if ready
      rescue StandardError
        nil
      end

      def persist_node(object)
        status = object.is_a?(Hash) ? object["status"] : nil
        persisted = write_node(with_status_tombstones(object, status))
        @kubelet_metrics&.node_registered if @api.respond_to?(:node_created?) && @api.node_created?
        node_status_persisted(persisted)
        @mutex.synchronize do
          @last_reported_status = status
          @last_status_report_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
        mark_volumes_from_status(status)
        persisted
      end

      # nodeutil.PatchNodeStatus sends the difference between the last Node
      # and this one, so a status field that went away (the last volume in
      # use, a condition) arrives as null and is removed.  The built status
      # is compacted; the keys the last report had and this one lacks are
      # sent as null (a merge patch deletes them).
      def with_status_tombstones(object, status)
        previous = @mutex.synchronize { @last_reported_status }
        return object unless object.is_a?(Hash) && previous.is_a?(Hash) && status.is_a?(Hash)

        gone = previous.keys.map(&:to_s) - status.keys.map(&:to_s)
        return object if gone.empty?

        object.merge("status" => status.merge(gone.to_h { |key| [key, nil] }))
      end

      # kubelet syncNodeStatus / tryUpdateNodeStatus: the status is rebuilt
      # and patched when it differs from the last one reported (heartbeat
      # times aside) or when the report frequency has elapsed; either way
      # the volumes the Node carries are marked reported in use.  Public for
      # a deterministic tick.
      def sync_node_status(force: false)
        return false unless registered?

        node = build_node(ready: ready?)
        last, last_at = @mutex.synchronize { [@last_reported_status, @last_status_report_at] }
        due = last_at.nil? || Process.clock_gettime(Process::CLOCK_MONOTONIC) - last_at >= @node_status_report_frequency
        if force || due || self.class.node_status_changed?(last, node["status"])
          persist_node(node)
          true
        else
          mark_volumes_from_status(last)
          false
        end
      end

      # A pending desired-state change: the status thread wakes at once.
      def request_node_status_sync
        @mutex.synchronize do
          @node_status_requested = true
          @node_status_condition.broadcast
        end
        true
      end
      public :sync_node_status, :request_node_status_sync

      # nodeStatusHasChanged: conditions compared without their heartbeat
      # time (and by type), everything else as it is.
      def self.node_status_changed?(previous, current)
        return previous.nil? != current.nil? if previous.nil? || current.nil?

        strip = lambda do |status|
          copy = JSON.parse(JSON.generate(status))
          conditions = Array(copy.delete("conditions")).map do |condition|
            condition.is_a?(Hash) ? condition.except("lastHeartbeatTime") : condition
          end
          [copy, conditions.sort_by { |condition| condition.is_a?(Hash) ? condition["type"].to_s : "" }]
        end
        strip.call(previous) != strip.call(current)
      end

      def mark_volumes_from_status(status)
        return unless @lifecycle.respond_to?(:mark_volumes_reported_in_use)

        names = status.is_a?(Hash) ? Array(status["volumesInUse"]) : []
        @lifecycle.mark_volumes_reported_in_use(names)
      rescue StandardError => error
        @error_handler&.call(error)
      end

      def start_node_status_thread
        return unless @sleeper.equal?(DEFAULT_SLEEPER)

        @mutex.synchronize do
          return if @node_status_thread&.alive?

          @node_status_thread = Thread.new { node_status_loop }
        end
      end

      def node_status_loop
        until @mutex.synchronize { @stop_requested }
          begin
            sync_node_status
          rescue StandardError => error
            @error_handler&.call(error)
          end
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @node_status_update_frequency
          @mutex.synchronize do
            until @stop_requested || @node_status_requested
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              break if remaining <= 0

              @node_status_condition.wait(@mutex, remaining)
            end
            @node_status_requested = false
          end
        end
      end

      def write_node(object)
        if @api.respond_to?(:register_node)
          invoke_api(:register_node, object)
        elsif @api.respond_to?(:upsert_node)
          invoke_api(:upsert_node, object)
        elsif @api.respond_to?(:create_node)
          begin
            invoke_api(:create_node, object)
          rescue StandardError => error
            raise unless existing_error?(error)

            if @api.respond_to?(:update_node)
              invoke_api(:update_node, object)
            elsif @api.respond_to?(:update_node_status)
              invoke_api(:update_node_status, object)
            else
              raise
            end
          end
        elsif @api.respond_to?(:apply_node)
          invoke_api(:apply_node, object)
        elsif @api.respond_to?(:apply)
          invoke_api(:apply, object)
        else
          raise ArgumentError, "api does not implement node registration"
        end
      end

      def persist_lease(object, existing:)
        if @api.respond_to?(:renew_lease)
          invoke_api(:renew_lease, object)
        elsif existing && @api.respond_to?(:update_lease)
          invoke_api(:update_lease, object)
        elsif !existing && @api.respond_to?(:create_lease)
          begin
            invoke_api(:create_lease, object)
          rescue StandardError => error
            raise unless existing_error?(error)

            invoke_api(:update_lease, object) if @api.respond_to?(:update_lease)
          end
        elsif @api.respond_to?(:upsert_lease)
          invoke_api(:upsert_lease, object)
        elsif @api.respond_to?(:lease)
          invoke_api(:lease, object)
        else
          raise ArgumentError, "api does not implement lease registration or renewal"
        end
      end

      def invoke_api(method_name, object)
        method = @api.method(method_name)
        begin
          method.call(object)
        rescue ArgumentError => error
          raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

          begin
            method.call(@node_name, object)
          rescue ArgumentError => positional_error
            raise unless positional_error.message.include?("wrong number") || positional_error.message.include?("unknown keyword")

            if method_name.to_s.include?("lease")
              begin
                method.call(node_name: @node_name, lease: object)
              rescue ArgumentError => keyword_error
                raise unless keyword_error.message.include?("wrong number") || keyword_error.message.include?("unknown keyword")

                method.call(lease: object)
              end
            else
              method.call(node: object)
            end
          end
        end
      end

      def existing_error?(error)
        return true if defined?(Rubernetes::API::MemoryStore::AlreadyExists) && error.is_a?(Rubernetes::API::MemoryStore::AlreadyExists)

        error.message.to_s.match?(/already exists|already registered|conflict/i)
      end

      def set_ready_without_persist(value)
        @mutex.synchronize { @ready = !!value }
      end

      def monotonic_clock
        -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      end

      def monotonic_value(value)
        return value.to_f if value.is_a?(Numeric)
        return Process.clock_gettime(Process::CLOCK_MONOTONIC) if value.nil?

        value.to_f
      end

      def time_value(value)
        return value if value.is_a?(Numeric) || value.is_a?(Time)

        sampled = @clock.call
        sampled.respond_to?(:utc) ? sampled.utc : sampled.to_f
      end

      def iso8601(value)
        value.respond_to?(:utc) ? value.utc.iso8601(6) : Time.at(value.to_f).utc.iso8601(6)
      end
    end
  end
end
