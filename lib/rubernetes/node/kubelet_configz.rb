# frozen_string_literal: true

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
      DEFAULT_EVICTION_HARD = {"memory.available" => "100Mi", "nodefs.available" => "10%", "nodefs.inodesFree" => "5%",
                               "imagefs.available" => "15%", "imagefs.inodesFree" => "5%"}.freeze

      module_function

      def defaults
        {
          "enableServer" => true, "syncFrequency" => "1m0s", "fileCheckFrequency" => "20s", "httpCheckFrequency" => "20s",
          "address" => "0.0.0.0", "port" => 10_250,
          "authentication" => {"x509" => {}, "webhook" => {"enabled" => true, "cacheTTL" => "2m0s"}, "anonymous" => {"enabled" => false}},
          "authorization" => {"mode" => "Webhook", "webhook" => {"cacheAuthorizedTTL" => "5m0s", "cacheUnauthorizedTTL" => "30s"}},
          "registryPullQPS" => 5, "registryBurst" => 10, "eventRecordQPS" => 50, "eventBurst" => 100,
          "enableDebuggingHandlers" => true, "healthzPort" => 10_248, "healthzBindAddress" => "127.0.0.1",
          "oomScoreAdj" => -999, "streamingConnectionIdleTimeout" => "4h0m0s", "nodeStatusUpdateFrequency" => "10s",
          "nodeStatusReportFrequency" => "5m0s", "nodeLeaseDurationSeconds" => 40, "imageMinimumGCAge" => "2m0s",
          "imageMaximumGCAge" => "0s", "imageGCHighThresholdPercent" => 85, "imageGCLowThresholdPercent" => 80,
          "volumeStatsAggPeriod" => "1m0s", "cgroupsPerQOS" => true, "cgroupDriver" => "cgroupfs",
          "cpuManagerPolicy" => "none", "cpuManagerReconcilePeriod" => "10s", "memoryManagerPolicy" => "None",
          "topologyManagerPolicy" => "none", "topologyManagerScope" => "container", "runtimeRequestTimeout" => "2m0s",
          "hairpinMode" => "promiscuous-bridge", "maxPods" => 110, "podPidsLimit" => -1, "resolvConf" => "/etc/resolv.conf",
          "cpuCFSQuota" => true, "cpuCFSQuotaPeriod" => "100ms", "nodeStatusMaxImages" => 50, "maxOpenFiles" => 1_000_000,
          "contentType" => "application/vnd.kubernetes.protobuf", "kubeAPIQPS" => 50, "kubeAPIBurst" => 100,
          "serializeImagePulls" => true, "evictionHard" => DEFAULT_EVICTION_HARD.dup, "evictionPressureTransitionPeriod" => "5m0s",
          "mergeDefaultEvictionSettings" => false, "enableControllerAttachDetach" => true, "makeIPTablesUtilChains" => true,
          "iptablesMasqueradeBit" => 14, "iptablesDropBit" => 15, "failSwapOn" => true, "memorySwap" => {},
          "containerLogMaxSize" => "10Mi", "containerLogMaxFiles" => 5, "containerLogMaxWorkers" => 1,
          "containerLogMonitorInterval" => "10s", "configMapAndSecretChangeDetectionStrategy" => "Watch",
          "enforceNodeAllocatable" => ["pods"], "volumePluginDir" => "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
          "logging" => {"format" => "text", "flushFrequency" => "5s", "verbosity" => 0, "options" => {"json" => {"infoBufferSize" => "0"}}},
          "enableSystemLogHandler" => true, "enableSystemLogQuery" => false, "shutdownGracePeriod" => "0s",
          "shutdownGracePeriodCriticalPods" => "0s", "enableProfilingHandler" => true, "enableDebugFlagsHandler" => true,
          "seccompDefault" => false, "memoryThrottlingFactor" => 0.9, "registerNode" => true,
          "localStorageCapacityIsolation" => true, "containerRuntimeEndpoint" => "unix:///run/containerd/containerd.sock",
          "failCgroupV1" => true, "crashLoopBackOff" => {"maxContainerRestartPeriod" => "5m0s"},
          "imagePullCredentialsVerificationPolicy" => "NeverVerifyPreloadedImages"
        }
      end

      # +config+: the agent's process configuration; +cluster_dns+ and
      # +cluster_domain+ the resolver the node gives its Pods.
      def build(config, cluster_dns: [], cluster_domain: nil)
        config = config.to_h
        result = defaults
        streaming = (config["streaming"] || {}).to_h
        result["address"] = streaming["host"].to_s if streaming["host"]
        result["port"] = Integer(streaming["port"]) if streaming["port"]
        apply_security(result, streaming)
        result["enableSystemLogHandler"] = streaming.fetch("enable_system_log_handler", true) != false
        result["enableSystemLogQuery"] = streaming["enable_system_log_query"] == true

        sync = (config["sync"] || {}).to_h
        result["syncFrequency"] = duration(sync["period_seconds"]) if sync["period_seconds"]
        lease = (config["lease"] || {}).to_h
        result["nodeLeaseDurationSeconds"] = Integer(lease["duration_seconds"]) if lease["duration_seconds"]
        result["staticPodPath"] = config["static_pod_path"].to_s if config["static_pod_path"]
        result["maxPods"] = Integer(config["max_pods"]) if config["max_pods"]
        result["clusterDomain"] = (cluster_domain || config["cluster_domain"]).to_s if cluster_domain || config["cluster_domain"]
        result["clusterDNS"] = Array(cluster_dns).map(&:to_s) unless Array(cluster_dns).empty?
        result["resolvConf"] = config["resolv_conf"].to_s if config["resolv_conf"]
        result["cgroupRoot"] = config["cgroup_root"].to_s if config["cgroup_root"]
        result["cgroupsPerQOS"] = config["cgroups_per_qos"] != false if config.key?("cgroups_per_qos")
        result["enforceNodeAllocatable"] = Array(config["enforce_node_allocatable"]).map(&:to_s) if config.key?("enforce_node_allocatable")
        result["systemReservedCgroup"] = config["system_reserved_cgroup"].to_s if config["system_reserved_cgroup"]
        result["kubeReservedCgroup"] = config["kube_reserved_cgroup"].to_s if config["kube_reserved_cgroup"]
        result["systemReserved"] = stringify(config["system_reserved"]) if config["system_reserved"]
        result["kubeReserved"] = stringify(config["kube_reserved"]) if config["kube_reserved"]
        result["reservedSystemCPUs"] = config["reserved_system_cpus"].to_s if config["reserved_system_cpus"]
        result["allowedUnsafeSysctls"] = Array(config["allowed_unsafe_sysctls"]).map(&:to_s) if config["allowed_unsafe_sysctls"]
        result["featureGates"] = config["feature_gates"].to_h.transform_keys(&:to_s) unless config["feature_gates"].to_h.empty?
        result["rotateCertificates"] = config["rotate_certificates"] == true
        apply_managers(result, config)
        apply_eviction(result, (config["eviction"] || {}).to_h)
        apply_image_gc(result, (config["image_gc"] || {}).to_h)
        apply_shutdown(result, (config["shutdown"] || {}).to_h)
        backoff = (config["crash_loop_back_off"] || {}).to_h["max_container_restart_period_seconds"]
        result["crashLoopBackOff"] = {"maxContainerRestartPeriod" => duration(backoff)} if backoff
        cri = (config["cri"] || {}).to_h
        result["containerRuntimeEndpoint"] = cri["enabled"] == false || cri["endpoint"].nil? ? "" : cri["endpoint"].to_s
        {"kubeletconfig" => result}
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
        cpu = (config["cpu_manager"] || {}).to_h
        result["cpuManagerPolicy"] = cpu["policy"].to_s if cpu["policy"]
        result["cpuManagerPolicyOptions"] = stringify(cpu["options"]) if cpu["options"]
        result["cpuManagerReconcilePeriod"] = duration(cpu["reconcile_period_seconds"]) if cpu["reconcile_period_seconds"]
        memory = (config["memory_manager"] || {}).to_h
        result["memoryManagerPolicy"] = memory["policy"].to_s if memory["policy"]
        topology = (config["topology_manager"] || {}).to_h
        result["topologyManagerPolicy"] = topology["policy"].to_s if topology["policy"]
        result["topologyManagerScope"] = topology["scope"].to_s if topology["scope"]
        result["topologyManagerPolicyOptions"] = stringify(topology["options"]) if topology["options"]
      end

      def apply_eviction(result, eviction)
        result["evictionHard"] = stringify(eviction["hard"]) if eviction["hard"]
        result["evictionSoft"] = stringify(eviction["soft"]) if eviction["soft"]
        result["evictionSoftGracePeriod"] = stringify(eviction["soft_grace_period"]) if eviction["soft_grace_period"]
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
          {"priority" => Integer(entry["priority"] || 0), "shutdownGracePeriodSeconds" => Integer(entry["shutdown_grace_period_seconds"] || entry["shutdownGracePeriodSeconds"] || 0)}
        end
      end

      def stringify(value)
        if value.respond_to?(:to_h)
          value.to_h.to_h { |key, child| [key.to_s, child.is_a?(Numeric) ? child.to_s : child] }
        else
          value
        end
      end

      # metav1.Duration's String form (time.Duration.String): 1m0s, 30s, 1h0m0s.
      def duration(value)
        seconds = value.is_a?(String) && value.match?(/[a-z]/) ? parse_duration(value) : Float(value)
        whole = seconds.to_i
        return "0s" if seconds.zero?
        return "#{(seconds * 1000).round}ms" if seconds < 1

        hours, rest = whole.divmod(3600)
        minutes, secs = rest.divmod(60)
        fraction = seconds - whole
        secs_text = fraction.zero? ? secs.to_s : format("%g", secs + fraction)
        return "#{hours}h#{minutes}m#{secs_text}s" if hours.positive?
        return "#{minutes}m#{secs_text}s" if minutes.positive?

        "#{secs_text}s"
      end

      def parse_duration(text)
        text.scan(/(\d+(?:\.\d+)?)(ms|h|m|s)/).sum do |number, unit|
          Float(number) * {"h" => 3600, "m" => 60, "s" => 1, "ms" => 0.001}.fetch(unit)
        end
      end
    end
  end
end
