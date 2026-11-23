# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "time"

require_relative "../network/host_port"
require_relative "../volume/deferred_fsync"
require_relative "status"
require_relative "probe_manager"
require_relative "image_credentials"
require_relative "restart_manager"
require_relative "pod_resize"
require_relative "container_spec"
require_relative "pod_files"
require_relative "pod_volumes"
require_relative "cdi"
require_relative "device_plugins/manager"
require_relative "dra_manager"
require_relative "preemption"
require_relative "../runtime/common/strict_json"
require_relative "../runtime/common/errors"
require_relative "../container_stop_signals"

require_relative "lifecycle/errors"
require_relative "lifecycle/state_store"
require_relative "lifecycle/result"
require_relative "lifecycle/conversion_cache"
require_relative "lifecycle/records"
require_relative "lifecycle/durable_state"
require_relative "lifecycle/recovery"
require_relative "lifecycle/reconciliation"
require_relative "lifecycle/startup"
require_relative "lifecycle/pod_admission"
require_relative "lifecycle/image_pinning"
require_relative "lifecycle/volume_setup"
require_relative "lifecycle/sandbox_setup"
require_relative "lifecycle/devices"
require_relative "lifecycle/container_start"
require_relative "lifecycle/hooks"
require_relative "lifecycle/probing"
require_relative "lifecycle/container_exits"
require_relative "lifecycle/container_restarts"
require_relative "lifecycle/resize"
require_relative "lifecycle/termination"
require_relative "lifecycle/container_stop"
require_relative "lifecycle/cleanup"
require_relative "lifecycle/status_reporting"
require_relative "lifecycle/instrumentation"

module Rubernetes
  module Node
    # Coordinates the Pod-level lifecycle.  Runtime, Volume, and Network are
    # deliberately ports: M2 owns ordering and rollback, while M4 supplies
    # the concrete data-plane implementations.
    #
    # This file is the entry point: the constructor, the injected ports and
    # what is asked of them.  The behaviour lives in the modules included
    # below, one responsibility each (lib/rubernetes/node/lifecycle/).
    #
    # The public interface, and where each part of it is:
    #   reconcile (sync), acknowledge_generation            Reconciliation
    #   start (create, start_pod)                           Startup
    #   terminate (stop, delete, stop_pod, delete_pod),
    #     request_eviction, evict                           Termination
    #   probe (probe_containers), wakeup=, schedule_wakeup  Probing
    #   observe_exits, handle_container_exit
    #     (container_exited, on_container_exit)             ContainerExits
    #   restart_container, resume_backoff_restarts          ContainerRestarts
    #   retry_pending_cleanups                              Cleanup
    #   recover                                             Recovery
    #   record, records, state, stats_records,
    #     container_states, pods_on_node, running_pod_uids  Records
    #   admitted_pods, pod_removed                          PodAdmission
    #   volumes_in_use, mark_volumes_reported_in_use        VolumeSetup
    #   metrics_observer=                                   Instrumentation
    class Lifecycle
      RUNTIME_STATES = %w[
        New Validated ImagePinned WorkspaceAllocated IsolationCreated
        ResourcesAttached WorkloadStopped Running Stopping Stopped Removed
        RollingBack CleanupPending StateUnknown
      ].freeze
      POD_PHASES = %w[Pending Running Succeeded Failed Unknown].freeze

      # The record states of a Pod the node has finished with: admission
      # (PodAdmission#admitted_pods) and node.status.volumesInUse
      # (VolumeSetup#volumes_in_use) no longer count it.
      INACTIVE_STATES = %w[Stopped Removed CleanupPending RollingBack].freeze

      # kubelet keeps retrying a Pod whose start failed before its workload
      # ran (a missing ConfigMap, an unbound claim, a sandbox that could not
      # be created): the Pod stays Pending with the reason in its status and
      # the next sync tries again after a backoff.  Only an admission
      # rejection is terminal.
      TERMINAL_START_REASONS = %w[PodAdmissionFailed].freeze

      # State the node keeps per Pod.
      include Records         # record lookup, the event trail, state transitions
      include DurableState    # restore and persist across agent restarts
      include Recovery        # #recover: startup reconciliation with the runtime

      # One sync of a Pod, and the start it leads to, in the normative order
      # admission -> Volume -> sandbox -> network -> init -> sidecar -> app.
      include Reconciliation  # #reconcile: terminate, start, resize or upkeep
      include Startup         # #start, and the rollback of a failed start
      include PodAdmission    # host ports, admission handler, preemption, devices
      include ImagePinning    # resolve and pin images, pull events
      include VolumeSetup     # volumesInUse, prepare, periodic volume sync
      include SandboxSetup    # sandbox, network, host ports, sysctls, Pod files
      include Devices         # device plugins, DRA/CDI, CPU and memory affinity
      include ContainerStart  # init, sidecar, app and ephemeral containers
      include Hooks           # postStart / preStop handlers

      # A running Pod.
      include Probing            # #probe, readiness and endpoints, probe wakeups
      include ContainerExits     # #observe_exits, #handle_container_exit
      include ContainerRestarts  # restart policy, CrashLoopBackOff, RestartAllContainers
      include Resize             # in-place resize

      # The end of a Pod.
      include Termination     # #terminate, #evict, the final API delete
      include ContainerStop   # TERM, grace period, KILL, confirmation
      include Cleanup         # reverse-order release, #retry_pending_cleanups

      # Reporting.
      include StatusReporting  # Pod status from the record
      include Instrumentation  # metrics observer, instrumented port calls

      def initialize(runtime_value = nil, runtime: nil, volume: nil, network: nil, admission: nil,
                     status: nil, probe_manager: nil, restart_manager: nil,
                     endpoint_manager: nil, reporter: nil,
                     clock: -> { Time.now.utc }, sleeper: ->(seconds) { sleep(seconds) },
                     event_sink: nil, runtime_class_resolver: nil, image_resolver: nil,
                     state_store: nil, recovery_observer: nil, recovery_cleaner: nil,
                     container_spec: nil, pod_volumes: nil, pod_files: nil, pod_root: nil, host_ports: nil,
                     pod_deleter: nil, node_image_config: nil,
                     resource_reader: nil, node_name: nil, host_ip: nil, host_ips: nil, node_allocatable: nil,
                     cluster_domain: "cluster.local", dra_manager: nil, cdi_spec_dirs: CDI::DEFAULT_SPEC_DIRS,
                     container_manager: nil, device_plugins: nil, credential_providers: nil, preemption: nil,
                     container_stop_signals: false, image_volume_with_digest: false, feature_gates: {})
        runtime ||= runtime_value
        raise ArgumentError, "runtime is required" unless runtime

        @runtime = runtime
        @container_stop_signals = container_stop_signals
        @image_volume_with_digest = image_volume_with_digest
        @resize_feature_gates = Helpers.string_keys(feature_gates || {}).freeze
        @volume = volume
        @cluster_trust_bundle_projection = Helpers.key(feature_gates, "ClusterTrustBundleProjection", false) == true
        @network = network
        @admission = admission
        @node_image_config = node_image_config
        assign_resource_managers(preemption: preemption, credential_providers: credential_providers, device_plugins: device_plugins,
                                 container_manager: container_manager, dra_manager: dra_manager, cdi_spec_dirs: cdi_spec_dirs)
        # Programs containerPort.hostPort on the node.  Nil in unit fixtures
        # that have no network at all.
        @host_ports = host_ports || (network ? Network::HostPort.new : nil)
        @pod_deleter = pod_deleter
        @node_name = node_name.to_s
        @host_ips = Array(host_ips || host_ip).map(&:to_s).reject(&:empty?).uniq.freeze
        @host_ip = @host_ips.first
        @pod_root = pod_root && File.expand_path(String(pod_root))
        @resource_reader = resource_reader
        @clock = clock
        @sleeper = sleeper
        @event_sink = event_sink
        @runtime_class_resolver = runtime_class_resolver
        @recovery_observer = recovery_observer
        @recovery_cleaner = recovery_cleaner
        build_pod_translation(pod_volumes: pod_volumes, container_spec: container_spec, pod_files: pod_files,
                              node_allocatable: node_allocatable, cluster_domain: cluster_domain)
        @image_resolver = image_resolver || (runtime_supports?(:image_resolver) ? runtime.image_resolver : nil)
        @state_store = state_store.is_a?(String) ? StateStore.new(state_store) : state_store
        @status = status || Status.new(endpoint_manager: endpoint_manager, reporter: reporter, clock: clock, feature_gates: feature_gates)
        @probes = probe_manager || ProbeManager.new(runtime: runtime, clock: clock, sleeper: sleeper)
        @restarts = restart_manager || RestartManager.new(clock: monotonic_clock, sleeper: sleeper)
        initialize_bookkeeping
        restore_state!
      end

      attr_reader :runtime, :volume, :network, :status, :probes, :restarts, :recovery_report,
                  :pod_volumes, :container_spec, :pod_root
      # The kubelet-side Pod volume translation and the node's API reader
      # (the agent attaches the SELinux tracker to them).
      attr_reader :resource_reader

      private

      def assign_resource_managers(preemption:, credential_providers:, device_plugins:, container_manager:, dra_manager:, cdi_spec_dirs:)
        # CriticalPodAdmissionHandler: evicts lower-priority Pods when a
        # critical Pod is refused for lack of resources.
        @preemption = preemption
        # Image credential provider plugins (--image-credential-provider-*).
        @credential_providers = credential_providers
        # Device plugins (devicemanager): devices allocated at admission,
        # applied to each container's spec.
        @device_plugins = device_plugins
        # The CPU/memory/topology managers' internal container lifecycle:
        # cpuset pinning at create, registration at start, release at removal.
        @container_manager = container_manager
        wire_cpu_quota_exemptions(container_manager)
        # Dynamic Resource Allocation: claims prepared by their drivers before
        # the sandbox exists, CDI devices applied to the containers that name
        # them, claims unprepared once the containers are gone.
        @dra_manager = dra_manager
        @cdi_spec_dirs = Array(cdi_spec_dirs)
      end

      def wire_cpu_quota_exemptions(manager)
        return unless manager.is_a?(ContainerManager)

        runtime = @runtime
        backends = defined?(Runtime::Multiplexer) && runtime.is_a?(Runtime::Multiplexer) ? runtime.backends.values : [runtime]
        backends.each do |backend|
          native = defined?(Runtime::Native) && backend.is_a?(Runtime::Native)
          cri = defined?(Runtime::CRI::Backend) && backend.is_a?(Runtime::CRI::Backend)
          backend.cpu_quota_exemptions = manager if native || cri
        end
      end

      # The kubelet-side translation: Pod volumes to host paths, Pod files
      # (/etc/hosts, resolv.conf) and the per-container runtime spec.  They
      # are only built when the node knows where Pod files live; the pure
      # lifecycle tests hand the Pod straight to a fake runtime.
      def build_pod_translation(pod_volumes:, container_spec:, pod_files:, node_allocatable:, cluster_domain:)
        @pod_volumes = pod_volumes
        if @volume && @pod_root
          @volume.pin_configured_volume_roots!(@pod_root) if defined?(Volume::Manager) && @volume.is_a?(Volume::Manager)
          @pod_volumes ||= PodVolumes.new(volume: @volume, reader: @resource_reader, node_name: @node_name,
                                          root: File.join(@pod_root, "volumes"), kubelet_pod_root: @pod_root, clock: @clock,
                                          node_allocatable: node_allocatable, cluster_trust_bundle_projection: @cluster_trust_bundle_projection)
        end
        @pod_files = pod_files || (PodFiles.new(cluster_domain: cluster_domain) if @pod_root)
        @container_spec = container_spec
        return unless @pod_root

        @container_spec ||= ContainerSpec.new(reader: @resource_reader, node_name: @node_name, node_allocatable: node_allocatable,
                                              cluster_domain: cluster_domain, pod_volumes: @pod_volumes)
      end

      def initialize_bookkeeping
        @mutex = Mutex.new
        @allocation_mutex = Mutex.new
        @persist_mutex = Mutex.new
        @persist_counter_mutex = Mutex.new
        @persist_requested = 0
        @persist_completed = 0
        @records = {}
        @pending_removals = {}
        # Pods that ran to completion, by uid.  The API status cannot carry
        # this decision on its own: the node writes that status itself, so one
        # spurious restart makes the Pod look Running again and the node keeps
        # re-creating it forever.  A local tombstone is the durable answer.
        @finished = {}
        # Evictions the eviction manager asked for, carried out by the Pod's
        # own worker on its next sync (the kubelet sends the kill through the
        # pod worker too), so they never race a reconcile of the same Pod.
        @eviction_requests = {}
        # volumeManager: the attachable volumes node.status.volumesInUse has
        # reported (MarkVolumesAsReportedInUse); an attachable volume is
        # mounted only once it is in the list.  The observer is told when the
        # desired set changes so the node status goes out at once.
        @reported_in_use = {}
        @reported_in_use_changed = ConditionVariable.new
        @volumes_in_use_observer = nil
        # The Pods a terminate is running for right now: a second terminate
        # (a cleanup retry, a DELETED event) waits for the first instead of
        # running the same cleanup concurrently.  Two concurrent cleanups of
        # one Pod raced the runtime's removal and left a stale cleanup error
        # that made the record CleanupPending for ever.
        @terminating = {}
        @terminating_done = ConditionVariable.new
        @recovery_report = nil
        @recovery_done = false
      end

      # -- What the injected ports can do ------------------------------------
      #
      # Every collaborator is handed in.  What all of its implementations
      # provide is simply called (run_sandbox, create/start/stop/remove
      # container, remove_sandbox; network add/delete; volume prepare/release;
      # the probe and restart managers, Pod volumes, the image resolver).
      # What only some provide is asked about here, and nowhere else: the
      # modules call these predicates instead of probing an object themselves.

      # Optional runtime operations.  Native has them all; the CRI and microVM
      # backends lack some (apply_sysctls, sandbox, sandbox_removed?,
      # resource_inventory, image_resolver, update_pod_resources,
      # pod_cgroup_readback, update_container_resources, wait_container,
      # http_get, tcp_socket), and the multiplexer answers for its default
      # backend.  container_status, network_sandbox_context and recover are
      # on every backend but not on the narrow runtime doubles of the
      # milestone probes (tools/milestones), which also are the only ones
      # that take signal / kill_container.
      def runtime_supports?(operation) = @runtime.respond_to?(operation)

      # Admission is the node's Admission (#admit) or any callable.
      def admission_supports?(operation) = @admission.respond_to?(operation)

      # StateStore#save_body takes the document as text (the fast path); a
      # store with only #save is handed the snapshot.
      def state_store_supports?(operation) = @state_store.respond_to?(operation)

      # The endpoint manager is Status's port and keeps Status's three
      # spellings of "ready": set_ready, add, mark_ready.
      def endpoint_supports?(operation) = @status.endpoint_manager.respond_to?(operation)

      # -- The shapes of what the ports answer with ---------------------------
      #
      # A runtime answers with its own value objects (a container, a status,
      # an exec session) where a simpler one answers with a Hash, a String or
      # true; admission answers with a Decision, a Hash or a boolean.

      # A value object that converts itself to a Hash.
      def hash_convertible?(value) = value.respond_to?(:to_h)

      # A value that carries +attribute+ (an id, an exit status, a stream).
      def value_reports?(value, attribute) = value.respond_to?(attribute)

      # -- Failures the lifecycle does not act on -----------------------------
      #
      # For steps whose failure must not change what happens to the Pod:
      # observers and callbacks, informational lookups, and stops that are
      # followed by a removal either way.  The caller says why at the call,
      # and what stands in for the result.
      def best_effort(fallback = nil)
        yield
      rescue StandardError
        fallback
      end
    end
  end
end
