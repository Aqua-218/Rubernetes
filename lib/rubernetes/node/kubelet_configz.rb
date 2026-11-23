# frozen_string_literal: true

require_relative "kubelet_healthz"
require_relative "kubelet_api_rates"
require_relative "../image/pull_limiter"
require_relative "../runtime/cpu_quota"

module Rubernetes
  module Node
    # /configz: {"kubeletconfig": <KubeletConfiguration>} as kubelet
    # registers it (cmd/kubelet/app/server.go setConfigz, the internal
    # configuration converted to kubelet.config.k8s.io/v1beta1).  Every field
    # starts at the v1beta1 default (apis/config/v1beta1/defaults.go) and is
    # replaced by what this agent is actually configured with, so clients
    # reading it (the e2e framework's getCurrentKubeletConfig) see the node's
    # real settings rather than invented ones.
    module KubeletConfigz
      DEFAULT_VOLUME_STATS_AGG_PERIOD_SECONDS = 60
      DEFAULT_EVICTION_HARD = {"memory.available" => "100Mi", "nodefs.available" => "10%", "nodefs.inodesFree" => "5%",
                               "imagefs.available" => "15%", "imagefs.inodesFree" => "5%"}.freeze

      module_function

      def defaults
        {
          "apiVersion" => "kubelet.config.k8s.io/v1beta1", "kind" => "KubeletConfiguration",
          "enableServer" => true, "syncFrequency" => "1m0s", "fileCheckFrequency" => "20s", "httpCheckFrequency" => "20s",
          "address" => "0.0.0.0", "port" => 10_250, "readOnlyPort" => 0,
          "authentication" => {"x509" => {}, "webhook" => {"enabled" => true, "cacheTTL" => "2m0s"}, "anonymous" => {"enabled" => false}},
          "authorization" => {"mode" => "Webhook", "webhook" => {"cacheAuthorizedTTL" => "5m0s", "cacheUnauthorizedTTL" => "30s"}},
          "registryPullQPS" => 5, "registryBurst" => 10, "eventRecordQPS" => 50, "eventBurst" => 100,
          "enableDebuggingHandlers" => true, "healthzPort" => KubeletHealthz::DEFAULT_PORT, "healthzBindAddress" => KubeletHealthz::DEFAULT_HOST,
          "oomScoreAdj" => -999, "streamingConnectionIdleTimeout" => "4h0m0s", "nodeStatusUpdateFrequency" => "10s",
          "nodeStatusReportFrequency" => "5m0s", "nodeLeaseDurationSeconds" => 40, "imageMinimumGCAge" => "2m0s",
          "imageMaximumGCAge" => "0s", "imageGCHighThresholdPercent" => 85, "imageGCLowThresholdPercent" => 80,
          "volumeStatsAggPeriod" => duration(DEFAULT_VOLUME_STATS_AGG_PERIOD_SECONDS), "cgroupsPerQOS" => true, "cgroupDriver" => "cgroupfs",
          "cpuManagerPolicy" => "none", "cpuManagerReconcilePeriod" => "10s", "memoryManagerPolicy" => "None",
          "topologyManagerPolicy" => "none", "topologyManagerScope" => "container", "runtimeRequestTimeout" => "2m0s",
          "hairpinMode" => "promiscuous-bridge", "maxPods" => 110, "podPidsLimit" => -1, "resolvConf" => "/etc/resolv.conf",
          "cpuCFSQuota" => true, "cpuCFSQuotaPeriod" => "100ms", "nodeStatusMaxImages" => 50, "maxOpenFiles" => 1_000_000,
          "contentType" => "application/vnd.kubernetes.protobuf",
          "kubeAPIQPS" => KubeletAPIRates::DEFAULT_QPS, "kubeAPIBurst" => KubeletAPIRates::DEFAULT_BURST,
          "serializeImagePulls" => true, "evictionHard" => DEFAULT_EVICTION_HARD.dup, "evictionPressureTransitionPeriod" => "5m0s",
          "mergeDefaultEvictionSettings" => false, "enableControllerAttachDetach" => true, "makeIPTablesUtilChains" => true,
          "iptablesMasqueradeBit" => 14, "iptablesDropBit" => 15, "failSwapOn" => true, "memorySwap" => {},
          "containerLogMaxSize" => "10Mi", "containerLogMaxFiles" => 5, "containerLogMaxWorkers" => 1,
          "containerLogMonitorInterval" => "10s", "configMapAndSecretChangeDetectionStrategy" => "Watch",
          "enforceNodeAllocatable" => ["pods"], "volumePluginDir" => "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
          "logging" => {"format" => "text", "flushFrequency" => "5s", "verbosity" => 0, "options" => {"json" => {"infoBufferSize" => "0"}}},
          "enableSystemLogHandler" => true, "enableSystemLogQuery" => false, "shutdownGracePeriod" => "0s",
          "shutdownGracePeriodCriticalPods" => "0s", "enableProfilingHandler" => true, "enableDebugFlagsHandler" => true,
          "seccompDefault" => false, "memoryThrottlingFactor" => 0.9, "memoryReservationPolicy" => "None", "registerNode" => true,
          "localStorageCapacityIsolation" => true, "containerRuntimeEndpoint" => "unix:///run/containerd/containerd.sock",
          "failCgroupV1" => true, "crashLoopBackOff" => {"maxContainerRestartPeriod" => "5m0s"},
          "imagePullCredentialsVerificationPolicy" => "NeverVerifyPreloadedImages"
        }
      end

      # +config+: the agent's process configuration; +cluster_dns+ and
      # +cluster_domain+ the resolver the node gives its Pods.
      def build(config, cluster_dns: [], cluster_domain: nil, streaming_port: nil)
        config = config.to_h
        result = defaults
        streaming = (config["streaming"] || {}).to_h
        result["enableServer"] = streaming["enabled"] != false
        result["address"] = streaming.fetch("host", "127.0.0.1").to_s
        listener_port = streaming_port || streaming["port"]
        result["port"] = Integer(listener_port) if listener_port
        result["readOnlyPort"] = config["read_only_port"] if config.key?("read_only_port")
        result["healthzPort"] = config["healthz_port"] if config.key?("healthz_port")
        result["healthzBindAddress"] = config["healthz_bind_address"] if config.key?("healthz_bind_address")
        apply_security(result, streaming)
        result["enableSystemLogHandler"] = streaming.fetch("enable_system_log_handler", true) != false
        result["enableSystemLogQuery"] = streaming["enable_system_log_query"] == true

        apply_sync_intervals(result, config)
        lease = (config["lease"] || {}).to_h
        result["nodeLeaseDurationSeconds"] = Integer(lease["duration_seconds"]) if lease["duration_seconds"]
        apply_static_sources(result, config)
        apply_node_limits(result, config)
        result["registerNode"] = config.fetch("register_node", true)
        taints = Array(config["register_with_taints"])
        result["registerWithTaints"] = taints.map { |taint| taint.except("timeAdded").compact } unless taints.empty?
        result["clusterDomain"] = (cluster_domain || config["cluster_domain"]).to_s if cluster_domain || config["cluster_domain"]
        result["clusterDNS"] = Array(cluster_dns).map(&:to_s) unless Array(cluster_dns).empty?
        resolv_conf = config.dig("dns", "resolv_conf") || config["resolv_conf"]
        result["resolvConf"] = resolv_conf.to_s if resolv_conf
        result["cgroupRoot"] = config["cgroup_root"].to_s if config["cgroup_root"]
        result["kubeletCgroups"] = config["kubelet_cgroups"] if config["kubelet_cgroups"]
        result["systemCgroups"] = config["system_cgroups"] if config["system_cgroups"]
        result["cgroupsPerQOS"] = config["cgroups_per_qos"] != false if config.key?("cgroups_per_qos")
        result["enforceNodeAllocatable"] = Array(config["enforce_node_allocatable"]).map(&:to_s) if config.key?("enforce_node_allocatable")
        result["systemReservedCgroup"] = config["system_reserved_cgroup"].to_s if config["system_reserved_cgroup"]
        result["kubeReservedCgroup"] = config["kube_reserved_cgroup"].to_s if config["kube_reserved_cgroup"]
        result["systemReserved"] = stringify(config["system_reserved"]) if config["system_reserved"]
        result["kubeReserved"] = stringify(config["kube_reserved"]) if config["kube_reserved"]
        result["reservedSystemCPUs"] = config["reserved_system_cpus"].to_s if config["reserved_system_cpus"]
        result["allowedUnsafeSysctls"] = Array(config["allowed_unsafe_sysctls"]).map(&:to_s) if config["allowed_unsafe_sysctls"]
        result["featureGates"] = config["feature_gates"].to_h.transform_keys(&:to_s) unless config["feature_gates"].to_h.empty?
        result["providerID"] = config["provider_id"] if config["provider_id"]
        result["rotateCertificates"] = config["rotate_certificates"] == true
        apply_client_rates(result, config)
        apply_managers(result, config)
        apply_eviction(result, (config["eviction"] || {}).to_h)
        apply_image_gc(result, (config["image_gc"] || {}).to_h)
        result["serializeImagePulls"] = Image::PullLimiter.serialized?(config)
        maximum_pulls = config["max_parallel_image_pulls"]
        result["maxParallelImagePulls"] = maximum_pulls if maximum_pulls
        apply_shutdown(result, (config["shutdown"] || {}).to_h)
        backoff = (config["crash_loop_back_off"] || {}).to_h["max_container_restart_period_seconds"]
        if result.dig("featureGates", "KubeletCrashLoopBackOffMax") == false
          result["crashLoopBackOff"] = {}
        elsif backoff
          result["crashLoopBackOff"]["maxContainerRestartPeriod"] = duration(backoff)
        end
        apply_runtime(result, config)
        {"kubeletconfig" => result}
      end

      def apply_runtime(result, config)
        result["cpuCFSQuota"] = config["cpu_cfs_quota"] != false
        result["cpuCFSQuotaPeriod"] = duration(config["cpu_cfs_quota_period_seconds"] || Runtime::CPUQuota::DEFAULT_SECONDS)
        result["singleProcessOOMKill"] = config["single_process_oom_kill"] unless config["single_process_oom_kill"].nil?
        cri = (config["cri"] || {}).to_h
        logs = cri["enabled"] == true ? cri : {}
        logs = logs.merge(config.slice("container_log_max_size", "container_log_max_files"))
        result["containerLogMaxSize"] = logs["container_log_max_size"].to_s if logs.key?("container_log_max_size")
        result["containerLogMaxFiles"] = logs["container_log_max_files"] if logs.key?("container_log_max_files")
        result["podLogsDir"] = config["pod_logs_dir"] if config["pod_logs_dir"]
        result["podPidsLimit"] = config["pod_pids_limit"] if config.key?("pod_pids_limit")
        if cri["enabled"] == true
          result["runtimeRequestTimeout"] = duration(cri.fetch("timeout_seconds", 60))
          result["containerLogMaxWorkers"] = cri["container_log_max_workers"] if cri.key?("container_log_max_workers")
          result["containerLogMonitorInterval"] = duration(cri["container_log_monitor_interval_seconds"]) if cri.key?("container_log_monitor_interval_seconds")
        end
        result["containerRuntimeEndpoint"] = cri["enabled"] == true ? cri["endpoint"].to_s : ""
      end

      def apply_sync_intervals(result, config)
        sync = (config["sync"] || {}).to_h
        result["syncFrequency"] = duration(sync["period_seconds"]) if sync["period_seconds"]
        result["volumeStatsAggPeriod"] = duration(config["volume_stats_agg_period_seconds"]) if config.key?("volume_stats_agg_period_seconds")
        {"nodeStatusUpdateFrequency" => "node_status_update_frequency_seconds",
         "nodeStatusReportFrequency" => "node_status_report_frequency_seconds"}.each do |field, native|
          result[field] = duration(sync[native]) if sync[native]
        end
      end

      def apply_client_rates(result, config)
        result["kubeAPIQPS"], result["kubeAPIBurst"] = KubeletAPIRates.configured(config)
      end

      # What the endpoint really does: without authentication configured the
      # loopback-only endpoint admits everyone (anonymous, AlwaysAllow).
      def apply_security(result, streaming)
        authentication = (streaming["authentication"] || {}).to_h
        authorization = (streaming["authorization"] || {}).to_h
        tls = (streaming["tls"] || {}).to_h
        if authentication.empty? && authorization.empty?
          result["authentication"] = {"x509" => {}, "webhook" => {"enabled" => false, "cacheTTL" => "2m0s"},
                                      "anonymous" => {"enabled" => true}}
          result["authorization"] = {"mode" => "AlwaysAllow", "webhook" => result.dig("authorization", "webhook")}
        else
          result["authentication"]["anonymous"]["enabled"] = authentication["anonymous"] == true
          result["authentication"]["webhook"]["enabled"] = authentication.fetch("webhook", true) != false
          result["authorization"]["mode"] = authorization.fetch("mode", "Webhook").to_s
        end
        result["authentication"]["x509"]["clientCAFile"] = tls["client_ca_file"].to_s if tls["client_ca_file"]
        result["tlsCertFile"] = tls["cert_file"].to_s if tls["cert_file"]
        result["tlsPrivateKeyFile"] = tls["key_file"].to_s if tls["key_file"]
      end

      def apply_managers(result, config)
        result["qosReserved"] = stringify(config["qos_reserved"]) if config["qos_reserved"]
        result["memoryThrottlingFactor"] = config["memory_throttling_factor"] if config["memory_throttling_factor"]
        result["memoryReservationPolicy"] = config["memory_reservation_policy"] if config["memory_reservation_policy"]
        result["protectKernelDefaults"] = config["protect_kernel_defaults"] if config.key?("protect_kernel_defaults")
        cpu = (config["cpu_manager"] || {}).to_h
        result["cpuManagerPolicy"] = cpu["policy"].to_s if cpu["policy"]
        result["cpuManagerPolicyOptions"] = stringify(cpu["options"]) if cpu["options"]
        result["cpuManagerReconcilePeriod"] = duration(cpu["reconcile_period_seconds"]) if cpu["reconcile_period_seconds"]
        memory = (config["memory_manager"] || {}).to_h
        result["memoryManagerPolicy"] = memory["policy"].to_s if memory["policy"]
        if memory["policy"] == "Static" && memory.key?("reserved_memory")
          result["reservedMemory"] = memory["reserved_memory"].map do |entry|
            {"numaNode" => entry.fetch("numa_node"), "limits" => stringify(entry.fetch("limits", {}))}
          end
        end
        topology = (config["topology_manager"] || {}).to_h
        result["topologyManagerPolicy"] = topology["policy"].to_s if topology["policy"]
        result["topologyManagerScope"] = topology["scope"].to_s if topology["scope"]
        result["topologyManagerPolicyOptions"] = stringify(topology["options"]) if topology["options"]
      end

      def apply_eviction(result, eviction)
        result["evictionHard"] = stringify(eviction["hard"]) if eviction["hard"]
        result["evictionSoft"] = stringify(eviction["soft"]) if eviction["soft"]
        if eviction["soft_grace_period"]
          result["evictionSoftGracePeriod"] = eviction["soft_grace_period"].transform_values { |grace_period| duration(grace_period) }
        end
        result["evictionMinimumReclaim"] = stringify(eviction["minimum_reclaim"]) if eviction["minimum_reclaim"]
        if eviction["pressure_transition_period"]
          result["evictionPressureTransitionPeriod"] =
            duration(eviction["pressure_transition_period"])
        end
        result["evictionMaxPodGracePeriod"] = Integer(eviction["max_pod_grace_period_seconds"]) if eviction["max_pod_grace_period_seconds"]
      end

      def apply_image_gc(result, image_gc)
        result["imageGCHighThresholdPercent"] = Integer(image_gc["high_threshold_percent"]) if image_gc["high_threshold_percent"]
        result["imageGCLowThresholdPercent"] = Integer(image_gc["low_threshold_percent"]) if image_gc["low_threshold_percent"]
        result["imageMinimumGCAge"] = duration(image_gc["minimum_age"]) if image_gc["minimum_age"]
        result["imageMaximumGCAge"] = duration(image_gc["maximum_age"]) if image_gc["maximum_age"]
      end

      def apply_shutdown(result, shutdown)
        result["shutdownGracePeriod"] = duration(shutdown["grace_period"]) if shutdown["grace_period"]
        if shutdown["grace_period_critical_pods"]
          result["shutdownGracePeriodCriticalPods"] =
            duration(shutdown["grace_period_critical_pods"])
        end
        return unless shutdown["grace_period_by_pod_priority"]

        result["shutdownGracePeriodByPodPriority"] = Array(shutdown["grace_period_by_pod_priority"]).map do |entry|
          entry = entry.to_h
          {"priority" => Integer(entry["priority"] || 0),
           "shutdownGracePeriodSeconds" => Integer(entry["shutdown_grace_period_seconds"] || entry["shutdownGracePeriodSeconds"] || 0)}
        end
      end

      def stringify(value)
        if value.respond_to?(:to_h)
          value.to_h.to_h { |key, child| [key.to_s, child.is_a?(Numeric) ? child.to_s : child] }
        else
          value
        end
      end

      def apply_static_sources(result, config)
        result["fileCheckFrequency"] = duration(config["file_check_frequency_seconds"]) if config["file_check_frequency_seconds"]
        result["staticPodPath"] = config["static_pod_path"].to_s if config["static_pod_path"]
        result["httpCheckFrequency"] = duration(config["http_check_frequency_seconds"]) if config["http_check_frequency_seconds"]
        result["staticPodURL"] = config["static_pod_url"] unless config["static_pod_url"].to_s.empty?
        headers = config["static_pod_url_header"]
        result["staticPodURLHeader"] = stringify(headers) if headers && !headers.empty?
      end

      def apply_node_limits(result, config)
        result["maxPods"] = Integer(config["max_pods"]) if config["max_pods"]
        pods_per_core = config.fetch("pods_per_core", 0)
        result["podsPerCore"] = pods_per_core if pods_per_core != 0
        result["nodeStatusMaxImages"] = config["node_status_max_images"] if config.key?("node_status_max_images")
      end

      # metav1.Duration uses Go's duration string format, including fractional units.
      def duration(value)
        seconds = if value.is_a?(String) && value.match?(/[a-z]/)
                    parse_duration(value)
                  else
                    value.is_a?(Numeric) ? value : Float(value)
                  end
        nanos = (seconds * 1_000_000_000).round
        return "-#{positive_duration(nanos.abs)}" if nanos.negative?

        positive_duration(nanos)
      end

      def positive_duration(nanos)
        return "0s" if nanos.zero?
        return "#{nanos}ns" if nanos < 1_000
        return scaled_duration(nanos, 3, "µs") if nanos < 1_000_000
        return scaled_duration(nanos, 6, "ms") if nanos < 1_000_000_000

        hours, rest = nanos.divmod(3_600_000_000_000)
        minutes, remainder = rest.divmod(60_000_000_000)
        elapsed = scaled_duration(remainder, 9, "s")
        return "#{hours}h#{minutes}m#{elapsed}" if hours.positive?
        return "#{minutes}m#{elapsed}" if minutes.positive?

        elapsed
      end

      def scaled_duration(nanos, precision, unit)
        whole, fraction = nanos.divmod(10**precision)
        return "#{whole}#{unit}" if fraction.zero?

        decimals = fraction.to_s.rjust(precision, "0").sub(/0+\z/, "")
        "#{whole}.#{decimals}#{unit}"
      end

      def parse_duration(text)
        text.scan(/(\d+(?:\.\d+)?)(ms|h|m|s)/).sum do |number, unit|
          Float(number) * {"h" => 3600, "m" => 60, "s" => 1, "ms" => 0.001}.fetch(unit)
        end
      end
    end
  end
end
