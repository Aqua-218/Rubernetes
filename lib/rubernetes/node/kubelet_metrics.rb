# frozen_string_literal: true

require "set"
require_relative "../observability/metrics"
require_relative "pod_startup_latency_tracker"
require_relative "../schema/quantity"

module Rubernetes
  module Node
    # kubelet's /metrics (pkg/kubelet/metrics/metrics.go, v1.36.2) for what
    # this node can observe: counters fed by the lifecycle's trace entries
    # (pods and containers started, failed starts, terminations, pod start
    # latency, evictions, restarted static Pods) and gauges computed from the
    # records at scrape time (node name, running Pods and containers by
    # state, desired / active / mirror Pods, the cgroup version).
    class KubeletMetrics
      POD_START_BUCKETS = [0.5, 1, 2, 3, 4, 5, 6, 8, 10, 20, 30, 45, 60, 120, 180, 240, 300, 360, 480, 600, 900, 1200, 1800,
                           2700, 3600].freeze
      # prometheus.DefBuckets.
      DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10].freeze
      # metrics.ExponentialBuckets(.005, 2.5, 14).
      RUNTIME_BUCKETS = Array.new(14) { |index| (0.005 * (2.5**index)).round(9) }.freeze
      # metrics.go imagePullDurationBuckets and imageSizeBuckets.
      IMAGE_PULL_BUCKETS = [1, 5, 10, 20, 30, 60, 120, 180, 240, 300, 360, 480, 600, 900, 1200, 1800, 2700, 3600].freeze
      IMAGE_SIZE_BUCKETS = [[0, "0-10MB"], [10 << 20, "10MB-100MB"], [100 << 20, "100MB-500MB"], [500 << 20, "500MB-1GB"],
                            [1 << 30, "1GB-5GB"], [5 << 30, "5GB-10GB"], [10 << 30, "10GB-20GB"], [20 << 30, "20GB-30GB"],
                            [30 << 30, "30GB-40GB"], [40 << 30, "40GB-60GB"], [60 << 30, "60GB-100GB"], [100 << 30, "GT100GB"]].freeze
      CONTAINER_TYPES = {"init" => "init_container", "sidecar" => "init_container", "ephemeral" => "ephemeral_container"}.freeze
      TERMINAL_STATES = %w[Removed Stopped Failed Succeeded].freeze
      # PodWorkerState of a lifecycle record (kubelet_working_pods lifecycle).
      TERMINATING_STATES = %w[Stopping RollingBack CleanupPending].freeze
      TERMINATED_STATES = %w[Stopped Removed Failed].freeze
      # kubelet.go admissionRejectionReasons.
      ADMISSION_REJECTION_REASONS = ["AppArmor", "PodOSSelectorNodeLabelDoesNotMatch", "PodOSNotSupported", "InvalidNodeInfo",
                                     "InitContainerRestartPolicyForbidden", "SupplementalGroupsPolicyNotSupported",
                                     "UnexpectedAdmissionError", "UnknownReason", "UnexpectedPredicateFailureType", "OutOfcpu",
                                     "OutOfmemory", "OutOfephemeral-storage", "OutOfpods", "PodLevelResourcesNotSupported",
                                     "PodFeatureUnsupported", "node(s) had taints that the pod didn't tolerate", "Evicted",
                                     "SysctlForbidden", "TopologyAffinityError", "NodeShutdown", "VolumeAttachmentLimitExceeded"].freeze

      def initialize(node_name:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, cgroup_root: "/sys/fs/cgroup",
                     wall_clock: -> { Time.now.utc })
        @node_name = node_name.to_s
        @clock = clock
        @wall_clock = wall_clock
        @cgroup_root = cgroup_root
        @registry = Observability::Metrics.new(apiserver: false, component: "kubelet")
        register_counters
        # Registered by the certificate managers and the credential provider
        # plugins, and only when they run (serving certificates are never
        # rotated here).
        %w[kubelet_certificate_manager_client_expiration_renew_errors kubelet_certificate_manager_client_ttl_seconds
           kubelet_certificate_manager_server_ttl_seconds kubelet_certificate_manager_server_rotation_seconds
           kubelet_server_expiration_renew_errors
           kubelet_credential_provider_plugin_errors_total kubelet_credential_provider_plugin_duration].each { |name| @registry.unregister(name) }
        @startup = PodStartupLatencyTracker.new(registry: @registry, clock: wall_clock)
        # kubelet_metrics_provider: the container metrics come from the
        # embedded cAdvisor-equivalent, never from the CRI stats.
        @registry.set("kubelet_metrics_provider", 1, {"provider" => "cadvisor"})
        @plugin_manager = nil
        @registry.add_collector { |registry| collect_plugin_manager(registry) }
        @node_startup = {kubelet: wall_clock.call.to_f}
        @worker_started = {}
        @worker_synced = Set.new
        @userns_pending = {}
        @first_seen = {}
        @started = {}
        @mutex = Mutex.new
      end

      attr_reader :registry, :startup
      # The Plugins::Manager whose registry directory plugin_manager_total_plugins reports.
      attr_accessor :plugin_manager

      def collect_plugin_manager(registry)
        manager = @plugin_manager
        return unless manager.respond_to?(:plugin_states)

        # A Custom collector upstream: not in the registry until declared here.
        registry.register("plugin_manager_total_plugins", type: :gauge) unless registry.registered?("plugin_manager_total_plugins")
        registry.reset("plugin_manager_total_plugins")
        manager.plugin_states.each do |socket, state|
          registry.set("plugin_manager_total_plugins", 1, {"socket_path" => socket.to_s, "state" => state})
        end
      rescue StandardError
        nil
      end

      # util/node_startup_latency_tracker.go: boot -> kubelet start -> first
      # registration attempt -> Node created -> first Ready status.  Times
      # are wall-clock seconds.
      def node_registration_attempted
        @mutex.synchronize { @node_startup[:attempt] ||= @wall_clock.call.to_f }
      end

      def node_registered
        times = @mutex.synchronize do
          next nil if @node_startup[:attempt].nil? || @node_startup[:registered]

          @node_startup[:registered] = @wall_clock.call.to_f
          @node_startup.dup
        end
        return unless times

        boot = self.class.boot_time
        @registry.set("kubelet_node_startup_pre_kubelet_duration_seconds", times[:kubelet] - boot) if boot
        @registry.set("kubelet_node_startup_pre_registration_duration_seconds", times[:attempt] - times[:kubelet])
        @registry.set("kubelet_node_startup_registration_duration_seconds", times[:registered] - times[:attempt])
      end

      def node_ready
        times = @mutex.synchronize do
          next nil if @node_startup[:registered].nil? || @node_startup[:ready]

          @node_startup[:ready] = @wall_clock.call.to_f
          @node_startup.dup
        end
        return unless times

        @registry.set("kubelet_node_startup_post_registration_duration_seconds", times[:ready] - times[:registered])
        boot = self.class.boot_time
        @registry.set("kubelet_node_startup_duration_seconds", times[:ready] - boot) if boot
      end

      # GetBootTime: /proc/stat btime.
      def self.boot_time(path = "/proc/stat")
        line = File.foreach(path).find { |text| text.start_with?("btime ") }
        line ? Float(line.split[1]) : nil
      rescue StandardError
        nil
      end

      # rotateCertificates: the client certificate manager's gauge and
      # renewal-error counter exist only with it (kubelet_certificate_manager_client_*).
      def client_certificate_source=(source)
        @registry.register("kubelet_certificate_manager_client_expiration_renew_errors", type: :counter)
        @registry.register("kubelet_certificate_manager_client_ttl_seconds", type: :gauge)
        clock = @wall_clock
        @registry.add_collector do |registry|
          certificate = begin
            source.call
          rescue StandardError
            nil
          end
          ttl = certificate.respond_to?(:not_after) ? (certificate.not_after - clock.call).truncate.to_f : Float::INFINITY
          registry.set("kubelet_certificate_manager_client_ttl_seconds", ttl)
        end
      end

      def client_certificate_renew_failed
        @registry.increment("kubelet_certificate_manager_client_expiration_renew_errors")
      end

      # The sync loop saw the Pod (kubelet's first-seen time).
      def pod_seen(pod)
        uid = pod.is_a?(Hash) ? pod.dig("metadata", "uid").to_s : ""
        return if uid.empty?

        @mutex.synchronize { @first_seen[uid] ||= @clock.call }
        @startup.observed_pod_on_watch(pod, @wall_clock.call)
      rescue StandardError
        nil
      end

      # podWorkers: one sync of a Pod, by its UpdateType -- "create" for the
      # first, "update" for a change, "sync" for a resync, "kill" for a
      # removal.
      def pod_worker_synced(pod, action, seconds)
        uid = pod.is_a?(Hash) ? pod.dig("metadata", "uid").to_s : ""
        return if uid.empty?

        created = @mutex.synchronize { @worker_synced.add?(uid) }
        type = case action.to_s
               when "DELETED" then "kill"
               when "SYNC" then created ? "create" : "sync"
               else created ? "create" : "update"
               end
        @registry.observe("kubelet_pod_worker_duration_seconds", seconds, {"operation_type" => type})
      rescue StandardError
        nil
      end

      # statusManager: the API server took a changed status.
      def pod_status_synced(pod, status, seconds)
        @registry.observe("kubelet_pod_status_sync_duration_seconds", (seconds.to_f * 1000).floor / 1000.0) if seconds
        @startup.status_updated(pod.merge("status" => status)) if pod.is_a?(Hash) && status.is_a?(Hash)
      rescue StandardError
        nil
      end

      # imageGCManager.freeImage: "age" or "space".
      def image_garbage_collected(reason)
        @registry.increment("kubelet_image_garbage_collected_total", {"reason" => reason.to_s})
      end

      # The lifecycle's trace entry for a Pod record.
      def observe(record, entry)
        uid = (record[:uid] || record["uid"]).to_s
        type = entry["type"].to_s
        @mutex.synchronize { @first_seen[uid] ||= @clock.call } unless uid.empty?
        case type
        when "sandbox.create"
          @registry.increment("kubelet_started_pods_total")
          user_namespaced_start(uid, record)
        when "container.create"
          image_volume_mounts(record, entry["name"])
        when "hook.http_fallback"
          @registry.increment("kubelet_lifecycle_handler_http_fallbacks_total")
        when "hook.sleep_terminated"
          @registry.increment("kubelet_sleep_action_terminated_early_total")
        when "image.resolve"
          @startup.image_started_pulling(uid, entry_time(entry))
        when "pod.admission_failed"
          admission_rejection(record[:admission_reason] || record["admission_reason"] || entry["reason"])
        when "container.started"
          @registry.increment("kubelet_started_containers_total", {"container_type" => container_type(record, entry["name"])})
          @startup.init_container_started(uid, entry_time(entry)) if init_container?(record, entry["name"])
        when "container.restart_failed"
          @registry.increment("kubelet_started_containers_errors_total",
                              {"container_type" => container_type(record, entry["name"]), "code" => "Unknown"})
          user_namespaced_failed(uid)
        when "sandbox.failed"
          @registry.increment("kubelet_started_pods_errors_total")
          user_namespaced_failed(uid)
        when "pod.failed", "volume.failed"
          user_namespaced_failed(uid)
        when "image.pulled"
          @startup.image_finished_pulling(uid, entry["finished_at"] ? Time.parse(entry["finished_at"].to_s) : entry_time(entry))
          @registry.observe("kubelet_image_pull_duration_seconds", (entry["seconds"].to_f * 1000).floor / 1000.0,
                            {"image_size_in_bytes" => self.class.image_size_bucket(entry["size"].to_i)})
          ensure_image_request(entry["policy"], entry["present"], true)
        when "image.present"
          @startup.image_finished_pulling(uid, entry_time(entry))
          ensure_image_request(entry["policy"], true, false)
        when "image.pull_failed"
          ensure_image_request(entry["policy"], entry["present"], true)
        when "image.never_pull"
          ensure_image_request(entry["policy"], entry["present"], entry["required"])
        when "container.exited"
          @startup.init_container_finished(uid, entry_time(entry)) if init_container?(record, entry["name"])
          @registry.increment("kubelet_terminated_containers_total",
                              {"container_type" => container_type(record, entry["name"]), "exit_code" => entry["exit_code"].to_s,
                               "reason" => entry["reason"].to_s})
        when "state"
          if entry["to"].to_s == "Running"
            observe_pod_start(uid)
            @mutex.synchronize { @userns_pending.delete(uid) }
          end
          observe_worker_start(uid, record) if entry["to"].to_s == "New"
        end
      rescue StandardError
        nil
      end

      # metrics.GetImageSizeBucket.
      def self.image_size_bucket(size)
        return "N/A" if size.zero?

        IMAGE_SIZE_BUCKETS.reverse_each { |bound, label| return label if size > bound }
        ""
      end

      # images/metrics.go recordEnsureImageRequest.
      def ensure_image_request(policy, present, required)
        text = ->(value) { value.nil? ? "unknown" : value.to_s }
        @registry.increment("kubelet_image_manager_ensure_image_requests_total",
                            {"pull_policy" => policy.to_s.downcase, "present_locally" => text.call(present),
                             "pull_required" => text.call(required)})
      end
      private :ensure_image_request

      # instrumentedRuntimeService.recordOperation / recordError, and
      # RunPodSandbox's own duration and errors by RuntimeClass handler.
      def runtime_operation(operation, seconds, failed: false, runtime_handler: nil)
        if operation.to_s == "run_podsandbox"
          handler = {"runtime_handler" => runtime_handler.to_s}
          @registry.observe("kubelet_run_podsandbox_duration_seconds", seconds, handler)
          @registry.increment("kubelet_run_podsandbox_errors_total", handler) if failed
        end
        # SetPodCgroupConfig beside UpdatePodSandboxResources.
        cgroup_operation("update", seconds) if operation.to_s == "update_podsandbox_resources"
        labels = {"operation_type" => operation.to_s}
        @registry.increment("kubelet_runtime_operations_total", labels)
        @registry.observe("kubelet_runtime_operations_duration_seconds", seconds, labels)
        @registry.increment("kubelet_runtime_operations_errors_total", labels) if failed
      end

      # GenericPLEG.Relist: its duration, the interval since the previous
      # relist began, and when it was last seen.
      def pleg_relist(started, seconds)
        previous = @mutex.synchronize do
          value = @last_relist
          @last_relist = started
          value
        end
        @registry.observe("kubelet_pleg_relist_interval_seconds", started - previous) if previous
        @registry.observe("kubelet_pleg_relist_duration_seconds", seconds)
        @registry.set("kubelet_pleg_last_seen_seconds", Time.now.to_f)
      end

      # evictionManager.evictPod: one per evicted Pod and signal.
      def eviction(signal)
        @registry.increment("kubelet_evictions", {"eviction_signal" => signal.to_s})
      end

      # preemption.evictPodsToFreeRequests: one per Pod evicted for a critical
      # Pod, by the first insufficient resource ("" without one).
      def preemption(resource)
        @registry.increment("kubelet_preemptions", {"preemption_signal" => resource.to_s})
      end

      # GenericPLEG.Relist: an event for a Pod the relist could not inspect.
      def pleg_discard_event
        @registry.increment("kubelet_pleg_discard_events")
      end

      # HandlePodCleanups: a runtime Pod no worker knows (orphaned).
      def orphaned_runtime_pod(count = 1)
        @registry.increment("kubelet_orphaned_runtime_pods_total", by: count)
      end

      # recordContainerResizeOperations: add, remove, increase or decrease of
      # each container's cpu / memory requests and limits (pod-level
      # resources have no metric upstream yet).
      def resize_requested(old_pod, new_pod)
        spec = ->(pod) { (pod["spec"] || {}) }
        new_containers = %w[containers initContainers].flat_map { |field| Array(spec.call(new_pod)[field]) }.to_h { |item| [item["name"], item] }
        %w[containers initContainers].flat_map { |field| Array(spec.call(old_pod)[field]) }.each do |old|
          current = new_containers[old["name"]]
          next unless current

          resize_operations(old["resources"] || {}, current["resources"] || {}, "kubelet_container_requested_resizes_total")
        end
      rescue StandardError
        nil
      end

      def pod_resize_duration(seconds, success)
        @registry.observe("kubelet_pod_resize_duration_milliseconds", (seconds * 1000).floor, {"success" => success ? "true" : "false"})
      end

      def pod_infeasible_resize(detail)
        @registry.increment("kubelet_pod_infeasible_resizes_total", {"reason_detail" => detail.to_s})
      end

      def deferred_resize_accepted(trigger)
        @registry.increment("kubelet_pod_deferred_accepted_resizes_total", {"retry_trigger" => trigger.to_s})
      end

      # resizeOperationForResources.
      def self.resize_operation(new_value, old_value)
        new_value = new_value.to_r
        old_value = old_value.to_r
        return "remove" if new_value.zero? && !old_value.zero?
        return "add" if old_value.zero? && !new_value.zero?
        return "decrease" if new_value < old_value
        return "increase" if new_value > old_value

        nil
      end

      # cgroupManager Create / Update / Destroy.
      def cgroup_operation(operation, seconds)
        @registry.observe("kubelet_cgroup_manager_duration_seconds", seconds, {"operation_type" => operation.to_s})
      end

      # evictionManager.synchronize: the age of the stats behind a threshold
      # used to pick a Pod to evict.
      def eviction_stats_age(signal, seconds)
        @registry.observe("kubelet_eviction_stats_age_seconds", seconds, {"eviction_signal" => signal.to_s})
      end

      # A static Pod deleted and recreated with the same UID.
      def pod_restarted(static:)
        @registry.increment("kubelet_restarted_pods_total", {"static" => static ? "true" : "false"})
      end

      def forget(uid)
        @mutex.synchronize do
          @first_seen.delete(uid.to_s)
          @started.delete(uid.to_s)
          @worker_started.delete(uid.to_s)
          @worker_synced.delete(uid.to_s)
          @userns_pending.delete(uid.to_s)
        end
        @startup.delete(uid)
      end

      # Gauges from the records, then the registry.
      def render(records)
        registry = @registry
        registry.set("kubelet_node_name", 1, {"node" => @node_name})
        pods = records.select { |record| record.is_a?(Hash) && (record[:pod] || record["pod"]).is_a?(Hash) }
        live = pods.reject { |record| TERMINAL_STATES.include?((record[:state] || record["state"]).to_s) }
        registry.set("kubelet_running_pods", live.count { |record| record[:sandbox_id] || record["sandbox_id"] })
        states = Hash.new(0)
        pods.each do |record|
          Array(record[:containers] || record["containers"]).each do |container|
            states[container_state(container)] += 1
          end
        end
        %w[created running exited unknown].each { |state| registry.set("kubelet_running_containers", states[state], {"container_state" => state}) }
        static = live.count { |record| static?(record) }
        %w[false true].each do |flag|
          count = flag == "true" ? static : live.length - static
          registry.set("kubelet_desired_pods", count, {"static" => flag})
          registry.set("kubelet_active_pods", count, {"static" => flag})
        end
        registry.set("kubelet_mirror_pods", static)
        working_pods(registry, pods)
        resize_gauges(registry, pods)
        registry.set("kubelet_managed_ephemeral_containers", pods.sum do |record|
          Array((record[:pod] || record["pod"]).dig("spec", "ephemeralContainers")).length
        end)
        version = cgroup_version
        registry.set("kubelet_cgroup_version", version) if version
        total_volumes(registry, pods)
        yield registry if block_given?
        registry.render
      end

      private

      def register_counters
        {"kubelet_node_name" => [:gauge, "The node's name. The count is always 1."],
         "kubelet_running_pods" => [:gauge, "Number of pods that have a running pod sandbox"],
         "kubelet_running_containers" => [:gauge, "Number of containers currently running"],
         "kubelet_desired_pods" => [:gauge, "The number of pods the kubelet is being instructed to run. static is true if the pod is not from the apiserver."],
         "kubelet_active_pods" => [:gauge, "The number of pods the kubelet considers active and which are being considered when admitting new pods. static is true if the pod is not from the apiserver."],
         "kubelet_mirror_pods" => [:gauge, "The number of mirror pods the kubelet will try to create (one per admitted static pod)"],
         "kubelet_cgroup_version" => [:gauge, "cgroup version on the hosts."],
         "kubelet_started_pods_total" => [:counter, "Cumulative number of pods started"],
         "kubelet_started_pods_errors_total" => [:counter, "Cumulative number of errors when starting pods"],
         "kubelet_started_containers_total" => [:counter, "Cumulative number of containers started"],
         "kubelet_started_containers_errors_total" => [:counter, "Cumulative number of errors when starting containers"],
         "kubelet_terminated_containers_total" => [:counter, "Cumulative number of container terminations."],
         "kubelet_restarted_pods_total" => [:counter, "Number of pods that have been restarted because they were deleted and recreated with the same UID while the kubelet was watching them (common for static pods, extremely uncommon for API pods)"],
         "kubelet_evictions" => [:counter, "Cumulative number of pod evictions by eviction signal"],
         "kubelet_preemptions" => [:counter, "Cumulative number of pod preemptions by preemption resource"],
         "kubelet_pleg_discard_events" => [:counter, "The number of discard events in PLEG."],
         "kubelet_orphaned_runtime_pods_total" => [:counter, "Number of pods that have been detected in the container runtime without being already known to the pod worker. This typically indicates the kubelet was restarted while a pod was force deleted in the API or in the local configuration, which is unusual."]}.each do |name, (type, help)|
          @registry.register(name, type: type, help: help)
        end
        @registry.register("kubelet_image_pull_duration_seconds", type: :histogram, buckets: IMAGE_PULL_BUCKETS,
                                                                  help: "Duration in seconds to pull an image.")
        @registry.register("kubelet_image_manager_ensure_image_requests_total", type: :counter,
                                                                                help: "Number of ensure-image requests processed by the kubelet.")
        @registry.register("kubelet_pleg_relist_duration_seconds", type: :histogram, buckets: DEFAULT_BUCKETS,
                                                                   help: "Duration in seconds for relisting pods in PLEG.")
        @registry.register("kubelet_pleg_relist_interval_seconds", type: :histogram, buckets: DEFAULT_BUCKETS,
                                                                   help: "Interval in seconds between relisting in PLEG.")
        @registry.register("kubelet_pleg_last_seen_seconds", type: :gauge, help: "Timestamp in seconds when PLEG was last seen active.")
        @registry.register("kubelet_runtime_operations_total", type: :counter,
                                                               help: "Cumulative number of runtime operations by operation type.")
        @registry.register("kubelet_runtime_operations_errors_total", type: :counter,
                                                                      help: "Cumulative number of runtime operation errors by operation type.")
        @registry.register("kubelet_runtime_operations_duration_seconds", type: :histogram, buckets: RUNTIME_BUCKETS,
                                                                          help: "Duration in seconds of runtime operations. Broken down by operation type.")
        @registry.register("kubelet_first_network_pod_start_sli_duration_seconds", type: :gauge,
                           help: "[INTERNAL] Duration in seconds to start the first network pod, excluding time to pull images and run " \
                                 "init containers, measured from pod creation timestamp to when all its containers are reported as " \
                                 "started and observed via watch")
        @registry.register("kubelet_pod_start_duration_seconds", type: :histogram, buckets: POD_START_BUCKETS,
                                                                 help: "Duration in seconds from kubelet seeing a pod for the first time to the pod starting to run")
        # volume/util/metrics.go and volumemanager/metrics.
        @registry.register("storage_operation_duration_seconds", type: :histogram, buckets: STORAGE_BUCKETS,
                                                                 help: "Storage operation duration")
        @registry.register("volume_manager_total_volumes", type: :gauge, help: "Number of volumes in Volume Manager")
      end

      STORAGE_BUCKETS = [0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 25, 50, 120, 300, 600].freeze
      # The volume plugins' names (pkg/volume/*), by the Pod volume source.
      VOLUME_PLUGIN_NAMES = {
        "emptyDir" => "kubernetes.io/empty-dir", "hostPath" => "kubernetes.io/host-path", "configMap" => "kubernetes.io/configmap",
        "secret" => "kubernetes.io/secret", "downwardAPI" => "kubernetes.io/downward-api", "projected" => "kubernetes.io/projected",
        "csi" => "kubernetes.io/csi", "local" => "kubernetes.io/local-volume", "image" => "kubernetes.io/image"
      }.freeze

      # OperationCompleteHook: one storage operation (volume_mount,
      # volume_unmount, ...) of a plugin, with its outcome.
      def storage_operation(plugin, operation, status, seconds, migrated: false)
        @registry.observe("storage_operation_duration_seconds", seconds,
                          {"migrated" => migrated ? "true" : "false", "operation_name" => operation.to_s, "status" => status.to_s,
                           "volume_plugin" => plugin.to_s})
        # volume_operation_total_seconds: the operation end to end (the
        # nested operation executor's whole run, which here is the same span).
        @registry.observe("volume_operation_total_seconds", seconds, {"operation_name" => operation.to_s, "plugin_name" => plugin.to_s})
      end

      # csi_operations_seconds{driver_name, grpc_status_code, method_name, migrated}:
      # one CSI RPC, with the gRPC status it ended in ("OK" on success).
      def csi_operation(driver_name, method_name, grpc_status_code, seconds, migrated: false)
        @registry.observe("csi_operations_seconds", seconds,
                          {"driver_name" => driver_name.to_s, "grpc_status_code" => grpc_status_code.to_s,
                           "method_name" => method_name.to_s, "migrated" => migrated ? "true" : "false"})
      end

      # kubelet_volume_metric_collection_duration_seconds{metric_source}: one
      # volume's stats ("csi" from NodeGetVolumeStats, "fs" from the filesystem).
      def volume_metric_collection(source, seconds)
        @registry.observe("kubelet_volume_metric_collection_duration_seconds", seconds, {"metric_source" => source.to_s})
      end

      # reconstruct_volume_operations_total / _errors_total: the volumes the
      # manager rebuilt from its durable state at startup, and the ones whose
      # backend could not be rebuilt (StateUnknown).
      def volume_reconstruction(attempted, errors, force_cleaned: 0, force_clean_errors: 0)
        @registry.increment("reconstruct_volume_operations_total", by: attempted.to_i) if attempted.to_i.positive?
        @registry.increment("reconstruct_volume_operations_errors_total", by: errors.to_i) if errors.to_i.positive?
        @registry.increment("force_cleaned_failed_volume_operations_total", by: force_cleaned.to_i) if force_cleaned.to_i.positive?
        @registry.increment("force_cleaned_failed_volume_operation_errors_total", by: force_clean_errors.to_i) if force_clean_errors.to_i.positive?
      end

      # kubelet_orphan_pod_cleaned_volumes / _errors: the last recovery sweep
      # over Pods that were gone from the API (their volumes torn down).
      def orphan_pod_volumes(cleaned, errors)
        @registry.set("kubelet_orphan_pod_cleaned_volumes", cleaned.to_i)
        @registry.set("kubelet_orphan_pod_cleaned_volumes_errors", errors.to_i)
      end

      def image_volume_mount_failed(count = 1)
        @registry.increment("kubelet_image_volume_mounted_errors_total", by: count)
      end
      public :csi_operation, :volume_metric_collection, :volume_reconstruction, :orphan_pod_volumes, :image_volume_mount_failed

      # totalVolumesCollector: the volumes per plugin in the desired state
      # (every live Pod's) and the actual state (every mounted one).
      def total_volumes(registry, records)
        registry.reset("volume_manager_total_volumes")
        desired = Hash.new(0)
        actual = Hash.new(0)
        records.each do |record|
          pod = record[:pod] || record["pod"]
          state = (record[:state] || record["state"]).to_s
          mounts = (record[:volume] || record["volume"]).is_a?(Hash) ? ((record[:volume] || record["volume"])["mounts"] || {}) : {}
          cleaned = (record[:cleanup_completed] || record["cleanup_completed"] || {})["volume"]
          unless cleaned
            mounts.each_value do |mount|
              plugin = mount_plugin(mount)
              actual[plugin] += 1 if plugin
            end
          end
          next if TERMINAL_STATES.include?(state) || state == "Removed"

          attachable = Array(record[:attachable_volumes] || record["attachable_volumes"])
          Array(pod.dig("spec", "volumes")).each do |volume|
            plugin = if (mount = mounts[volume["name"].to_s])
                       mount_plugin(mount)
                     elsif volume.key?("persistentVolumeClaim") || volume.key?("ephemeral")
                       "kubernetes.io/csi" unless attachable.empty?
                     else
                       VOLUME_PLUGIN_NAMES[(volume.keys - ["name"]).first.to_s]
                     end
            desired[plugin] += 1 if plugin
          end
        end
        desired.each { |plugin, count| registry.set("volume_manager_total_volumes", count, {"plugin_name" => plugin, "state" => "desired_state_of_world"}) }
        actual.each { |plugin, count| registry.set("volume_manager_total_volumes", count, {"plugin_name" => plugin, "state" => "actual_state_of_world"}) }
      end

      # The plugin behind a recorded mount: the PV's backend for a claim, the
      # Pod source otherwise.
      def self.mount_plugin(mount)
        return nil unless mount.is_a?(Hash)

        source = (mount["source"] || mount[:source]).to_s
        backend = (mount["backend"] || mount[:backend]).to_s
        if %w[persistentVolumeClaim ephemeral].include?(source)
          return "kubernetes.io/csi" if !(mount["uniqueName"] || mount[:uniqueName]).to_s.empty? || backend.empty? || backend == "csi"

          VOLUME_PLUGIN_NAMES[backend]
        else
          VOLUME_PLUGIN_NAMES[source] || VOLUME_PLUGIN_NAMES[backend]
        end
      end

      def mount_plugin(mount) = self.class.mount_plugin(mount)
      public :storage_operation

      def resize_operations(old_resources, new_resources, name)
        quantity = lambda do |resources, kind, resource|
          value = (resources[kind] || {})[resource]
          value.nil? ? 0 : Schema::Quantity.parse(value.to_s).value
        end
        [%w[memory requests], %w[memory limits], %w[cpu requests], %w[cpu limits]].each do |resource, kind|
          operation = self.class.resize_operation(quantity.call(new_resources, kind, resource), quantity.call(old_resources, kind, resource))
          @registry.increment(name, {"resource" => resource, "requirement" => kind, "operation" => operation}) if operation
        end
      end

      # status_manager recordPendingResizeCount / recordInProgressResizeCount.
      def resize_gauges(registry, pods)
        pending = Hash.new(0)
        in_progress = 0
        pods.each do |record|
          condition = record[:resize_pending] || record["resize_pending"]
          pending[condition["reason"].to_s.downcase] += 1 if condition.is_a?(Hash)
          in_progress += 1 if record[:resize_in_progress] || record["resize_in_progress"]
        end
        registry.reset("kubelet_pod_pending_resizes")
        pending.each { |reason, count| registry.set("kubelet_pod_pending_resizes", count, {"reason" => reason}) }
        registry.set("kubelet_pod_in_progress_resizes", in_progress)
      end

      # kubelet_pods.go HandlePodCleanups: every valid PodWorkerSync
      # combination, zero included.
      def working_pods(registry, pods)
        counts = Hash.new(0)
        pods.each do |record|
          state = (record[:state] || record["state"]).to_s
          lifecycle = if TERMINATED_STATES.include?(state) then "terminated"
                      elsif TERMINATING_STATES.include?(state) then "terminating"
                      else "sync"
                      end
          counts[[lifecycle, "desired", static?(record) ? "true" : "false"]] += 1
        end
        [%w[desired true], %w[desired false], %w[orphan true], %w[orphan false], %w[runtime_only unknown]].each do |config, static|
          %w[sync terminating terminated].each do |lifecycle|
            registry.set("kubelet_working_pods", counts[[lifecycle, config, static]],
                         {"lifecycle" => lifecycle, "config" => config, "static" => static})
          end
        end
      end

      # recordAdmissionRejection: known reasons, OutOf<extended resource>,
      # or Other.
      def admission_rejection(reason)
        reason = reason.to_s
        label = if ADMISSION_REJECTION_REASONS.include?(reason) then reason
                elsif reason.start_with?("OutOf") then "OutOfExtendedResources"
                else "Other"
                end
        @registry.increment("kubelet_admission_rejections_total", {"reason" => label})
      end

      # The pod worker's first sync of a Pod: kubelet_pod_worker_start_duration_seconds
      # since the Pod was first seen, and its container count.
      def observe_worker_start(uid, record)
        seen = @mutex.synchronize do
          next nil if uid.empty? || @worker_started[uid]

          @worker_started[uid] = true
          @first_seen[uid]
        end
        return unless seen

        @registry.observe("kubelet_pod_worker_start_duration_seconds", @clock.call - seen)
        pod = record[:pod] || record["pod"]
        @registry.observe("kubelet_containers_per_pod_count", Array(pod.dig("spec", "containers")).length) if pod.is_a?(Hash)
      end

      # SyncPod with UserNamespacesSupport: a sandbox for a Pod with
      # hostUsers: false, and an error anywhere in that sync.
      def user_namespaced_start(uid, record)
        pod = record[:pod] || record["pod"]
        return unless pod.is_a?(Hash) && pod.dig("spec", "hostUsers") == false

        @registry.increment("kubelet_started_user_namespaced_pods_total")
        @mutex.synchronize { @userns_pending[uid] = true }
      end

      def user_namespaced_failed(uid)
        pending = @mutex.synchronize { @userns_pending.delete(uid) }
        @registry.increment("kubelet_started_user_namespaced_pods_errors_total") if pending
      end

      # incrementImageVolumeMetrics: at each container start, every image
      # volume of the Pod is requested, and each of the container's mounts
      # of one is mounted.
      def image_volume_mounts(record, name)
        pod = record[:pod] || record["pod"]
        return unless pod.is_a?(Hash)

        image_volumes = Array(pod.dig("spec", "volumes")).filter_map do |volume|
          volume["name"].to_s if volume.is_a?(Hash) && volume["image"].is_a?(Hash)
        end
        return if image_volumes.empty?

        @registry.increment("kubelet_image_volume_requested_total", by: image_volumes.length)
        entry = Array(record[:containers] || record["containers"]).find { |candidate| (candidate[:name] || candidate["name"]).to_s == name.to_s }
        spec = entry && (entry[:spec] || entry["spec"])
        mounts = spec.is_a?(Hash) ? Array(spec["volumeMounts"]) : []
        mounts.each do |mount|
          @registry.increment("kubelet_image_volume_mounted_succeed_total") if mount.is_a?(Hash) && image_volumes.include?(mount["name"].to_s)
        end
      end

      def entry_time(entry)
        Time.parse(entry["at"].to_s)
      rescue ArgumentError, TypeError
        @wall_clock.call
      end

      def init_container?(record, name)
        %w[init_container].include?(container_type(record, name)) &&
          Array(record[:containers] || record["containers"]).any? do |candidate|
            (candidate[:name] || candidate["name"]).to_s == name.to_s && (candidate[:category] || candidate["category"]).to_s == "init"
          end
      end

      def observe_pod_start(uid)
        seen = @mutex.synchronize do
          next nil if uid.empty? || @started[uid]

          @started[uid] = true
          @first_seen[uid]
        end
        return unless seen

        @registry.observe("kubelet_pod_start_duration_seconds", @clock.call - seen)
      end

      def container_type(record, name)
        entry = Array(record[:containers] || record["containers"]).find { |candidate| (candidate[:name] || candidate["name"]).to_s == name.to_s }
        category = entry && (entry[:category] || entry["category"]).to_s
        CONTAINER_TYPES.fetch(category.to_s, "container")
      end

      def container_state(container)
        exited = container[:exited] || container["exited"]
        started = container[:started] || container["started"]
        return "exited" if exited
        return "running" if started
        return "created" if container[:id] || container["id"]

        "unknown"
      end

      def static?(record)
        pod = record[:pod] || record["pod"]
        annotations = pod.dig("metadata", "annotations") || {}
        annotations["kubernetes.io/config.source"].to_s.then { |source| !source.empty? && source != "api" } ||
          annotations.key?("kubernetes.io/config.mirror")
      end

      def cgroup_version
        File.exist?(File.join(@cgroup_root.to_s, "cgroup.controllers")) ? 2 : 1
      rescue StandardError
        nil
      end
    end
  end
end
