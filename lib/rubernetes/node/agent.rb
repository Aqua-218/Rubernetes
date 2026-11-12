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

require_relative "agent/api_port"
require_relative "agent/wiring"
require_relative "agent/extensions"
require_relative "agent/managers"
require_relative "agent/instrumentation"
require_relative "agent/recovery"
require_relative "agent/registration"
require_relative "agent/run_loop"
require_relative "agent/pod_sync"
require_relative "agent/node_object"
require_relative "agent/status_reporting"

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

      include APIPort           # what the injected API offers; the Node and Lease writes
      include Wiring            # the constructor's steps
      include Extensions        # plugin registry, credential providers, volume-side trackers
      include Managers          # resource, eviction, image GC, shutdown and preemption managers
      include Instrumentation   # kubelet metrics and admit handlers
      include Recovery          # #recover: the startup barrier
      include NodeRegistration  # #register, #renew_lease, the lease thread
      include RunLoop           # #start, #run, #stop, #run_once, the PLEG relist
      include PodSync           # the reconcile around the lifecycle
      include NodeObject        # #node: the Node object and its conditions
      include StatusReporting   # #set_ready, #sync_node_status, the status thread

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

        initialize_schedule(node_status_update_frequency, node_status_report_frequency, relist_period)
        raise ArgumentError, "api is required" unless api

        initialize_ports(node_name, api, runtime || lifecycle&.runtime, clock: clock, sleeper: sleeper, error_handler: error_handler)
        initialize_lease(node_namespace, lease_duration_seconds, lease_renew_fraction)
        reserved = [system_reserved, kube_reserved, reserved_system_cpus]
        initialize_node_resources(capacity, allocatable, reserved, eviction, host: detect_host_resources, pod_root: pod_root, max_pods: max_pods)
        initialize_node_identity(node_labels, node_annotations, addresses, architecture, operating_system, runtime_version, streaming_port)
        reporter = initialize_status(status, static_pod_path, reporter, endpoint_manager)
        initialize_admission(admission, feature_gates, runtime_features, allowed_unsafe_sysctls)
        publisher = initialize_events(event_recorder, publish_events, lifecycle_logger)
        dra = Helpers.string_keys(dra || {})
        initialize_plugin_registry(dra, @kubelet_root, volume, dra_manager: dra_manager, plugin_manager: plugin_manager, csi_plugins: csi_plugins)
        initialize_container_manager(container_manager, cpu_manager, memory_manager, topology_manager, reserved_system_cpus)
        pod_ports = {runtime: runtime, volume: volume, network: network, reporter: reporter, endpoint_manager: endpoint_manager,
                     state_store: state_store, runtime_class_resolver: runtime_class_resolver, pod_root: pod_root, pod_files: pod_files,
                     probe_manager: build_probe_manager(probe_connectors, runtime), resource_reader: resource_reader, host_ip: host_ip,
                     cluster_domain: cluster_domain, cdi_spec_dirs: Array(dra.fetch("cdi_spec_dirs", CDI::DEFAULT_SPEC_DIRS))}
        initialize_lifecycle(lifecycle, pod_ports, publisher: publisher, device_plugin_dir: device_plugin_dir,
                                                   crash_loop_back_off_max: crash_loop_back_off_max, image_credential_provider: image_credential_provider)
        initialize_metrics(image_resolver)
        initialize_pod_sources(qos_cgroup_manager, qos_cgroups, reserved, pod_resources_dir)
        initialize_sync_loop(sync_loop, source, sync_period, watch_timeout)
        initialize_stats(stats_provider, image_resolver, volume, pod_root, image_gc)
        initialize_eviction(eviction_manager, eviction)
        attach_observers
        initialize_shutdown(shutdown_manager, shutdown, feature_gates)
        attach_metrics_registry
        attach_admit_handlers
      end
      attr_reader :declared_features, :stats_provider, :eviction_manager, :image_gc_manager, :dra_manager, :plugin_manager, :csi_plugins,
                  :kubelet_metrics, :container_manager, :shutdown_manager, :capacity, :allocatable, :node_name, :api, :runtime, :lifecycle, :sync_loop,
                  :status, :lease_duration_seconds, :node_namespace, :startup_error, :recovery_report

      def registered?
        @mutex.synchronize { @registered }
      end

      def running?
        @mutex.synchronize { @running }
      end

      def ready?
        @mutex.synchronize { @ready }
      end

      def lease
        @mutex.synchronize { @lease&.to_h }
      end

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

      private

      attr_reader :static_pods, :device_plugins, :pod_resources

      # --- What the injected ports are.  The agent calls its collaborators
      # without asking what they respond to; these predicates are the only
      # places that tell real implementations of a port apart.

      # The node's own API adapter (APIClientAdapter: a Kubernetes client,
      # object reads, status patches, Pod deletes), as opposed to a port that
      # only registers the Node and renews its Lease.
      def node_adapter?(api = @api)
        api.respond_to?(:client)
      end

      # The node's volume manager (CSI registry, per-volume stats), as
      # opposed to a bare volume port handed to the lifecycle.
      def volume_manager?(volume)
        volume.respond_to?(:csi_registry=)
      end

      # A multiplexing runtime serves several handlers; anything else is the
      # node's one runtime.
      def runtime_backends
        @runtime.respond_to?(:backends) ? @runtime.backends : nil
      end

      # A handler served by a CRI runtime (containerd, CRI-O) rather than by
      # this process.
      def cri_backend?(backend)
        backend.respond_to?(:image_gc_source)
      end

      # A CRI runtime whose client streams container events (EventedPLEG).
      def runtime_event_stream?
        @runtime.respond_to?(:client) && @runtime.client.respond_to?(:stream)
      end

      # Only the runtimes that run containers in the host's cgroups (the
      # native one and the multiplexer in front of it) can move a running
      # container to other CPUs.
      def runtime_moves_cpusets?
        @runtime.respond_to?(:update_container_cpuset)
      end

      # --- Lookups whose failure has a defined answer: the API or the CRI
      # runtime may be unreachable, and the caller goes on without the object.

      # A ServiceAccount that cannot be read is one the credential provider
      # gets no annotations for.
      def service_account_reader(client)
        lambda do |namespace, name|
          client&.get("serviceaccounts", name, namespace: namespace)
        rescue StandardError
          nil
        end
      end

      # A CSIDriver that cannot be read has no seLinuxMount opinion.
      def csi_driver_reader(reader)
        lambda do |driver|
          reader&.get("csidrivers", driver, namespace: nil)
        rescue StandardError
          nil
        end
      end

      # A runtime that does not answer Status advertises no handler features.
      def cri_handler_features(client)
        Array(client.runtime("Status", {"verbose" => false})["runtime_handlers"]).to_h do |handler|
          [handler["name"].to_s, {"recursiveReadOnlyMounts" => handler.dig("features", "recursive_read_only_mounts") == true,
                                  "userNamespaces" => handler.dig("features", "user_namespaces") == true}]
        end
      rescue StandardError
        {}
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

      # The injected clock may tell the time as a Time or as epoch seconds.
      def time_value(value)
        return value if value.is_a?(Numeric) || value.is_a?(Time)

        sampled = @clock.call
        sampled.is_a?(Time) ? sampled.utc : sampled.to_f
      end

      def iso8601(value)
        value.is_a?(Time) ? value.utc.iso8601(6) : Time.at(value.to_f).utc.iso8601(6)
      end
    end
  end
end
