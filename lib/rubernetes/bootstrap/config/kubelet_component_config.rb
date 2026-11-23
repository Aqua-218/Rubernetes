# frozen_string_literal: true

require "ipaddr"
require_relative "../../node/kubelet_configz"

module Rubernetes
  module Bootstrap
    class Config
      # The agent's supported subset of the v1beta1 component configuration.
      # Translate into the same immutable process config used for ordinary
      # startup; /configz is always rebuilt from that process config.
      module KubeletComponentConfig
        API_VERSION = "kubelet.config.k8s.io/v1beta1"
        KIND = "KubeletConfiguration"
        TYPE_FIELDS = %w[apiVersion kind].freeze
        INT32_MAX = (2**31) - 1

        SETTINGS = {
          "enableServer" => "streaming.enabled",
          "address" => "streaming.host",
          "port" => "streaming.port",
          "staticPodPath" => "static_pod_path",
          "staticPodURL" => "static_pod_url",
          "staticPodURLHeader" => "static_pod_url_header",
          "healthzPort" => "healthz_port",
          "healthzBindAddress" => "healthz_bind_address",
          "readOnlyPort" => "read_only_port",
          "tlsCertFile" => "streaming.tls.cert_file",
          "tlsPrivateKeyFile" => "streaming.tls.key_file",
          "maxPods" => "max_pods",
          "podsPerCore" => "pods_per_core",
          "nodeStatusMaxImages" => "node_status_max_images",
          "podPidsLimit" => "pod_pids_limit",
          "podLogsDir" => "pod_logs_dir",
          "nodeLeaseDurationSeconds" => "lease.duration_seconds",
          "registerNode" => "register_node",
          "registerWithTaints" => "register_with_taints",
          "clusterDomain" => "cluster_domain",
          "clusterDNS" => "dns.cluster_dns",
          "resolvConf" => "dns.resolv_conf",
          "cgroupsPerQOS" => "cgroups_per_qos",
          "qosReserved" => "qos_reserved",
          "protectKernelDefaults" => "protect_kernel_defaults",
          "enforceNodeAllocatable" => "enforce_node_allocatable",
          "systemReserved" => "system_reserved",
          "kubeReserved" => "kube_reserved",
          "reservedSystemCPUs" => "reserved_system_cpus",
          "systemReservedCgroup" => "system_reserved_cgroup",
          "kubeReservedCgroup" => "kube_reserved_cgroup",
          "cpuManagerPolicy" => "cpu_manager.policy",
          "cpuCFSQuota" => "cpu_cfs_quota",
          "cpuManagerPolicyOptions" => "cpu_manager.options",
          "memoryManagerPolicy" => "memory_manager.policy",
          "singleProcessOOMKill" => "single_process_oom_kill",
          "memoryThrottlingFactor" => "memory_throttling_factor",
          "memoryReservationPolicy" => "memory_reservation_policy",
          "topologyManagerPolicy" => "topology_manager.policy",
          "topologyManagerScope" => "topology_manager.scope",
          "topologyManagerPolicyOptions" => "topology_manager.options",
          "imageGCHighThresholdPercent" => "image_gc.high_threshold_percent",
          "imageGCLowThresholdPercent" => "image_gc.low_threshold_percent",
          "serializeImagePulls" => "serialize_image_pulls",
          "maxParallelImagePulls" => "max_parallel_image_pulls",
          "containerLogMaxSize" => "container_log_max_size",
          "containerLogMaxFiles" => "container_log_max_files",
          "containerLogMaxWorkers" => "cri.container_log_max_workers",
          "kubeAPIQPS" => "kube_api_qps",
          "kubeAPIBurst" => "kube_api_burst",
          "providerID" => "provider_id",
          "evictionHard" => "eviction.hard",
          "evictionSoft" => "eviction.soft",
          "evictionMinimumReclaim" => "eviction.minimum_reclaim",
          "evictionMaxPodGracePeriod" => "eviction.max_pod_grace_period_seconds"
        }.freeze

        DURATIONS = {
          "fileCheckFrequency" => "file_check_frequency_seconds",
          "httpCheckFrequency" => "http_check_frequency_seconds",
          "syncFrequency" => "sync.period_seconds",
          "volumeStatsAggPeriod" => "volume_stats_agg_period_seconds",
          "nodeStatusUpdateFrequency" => "sync.node_status_update_frequency_seconds",
          "nodeStatusReportFrequency" => "sync.node_status_report_frequency_seconds",
          "runtimeRequestTimeout" => "cri.timeout_seconds",
          "containerLogMonitorInterval" => "cri.container_log_monitor_interval_seconds",
          "cpuManagerReconcilePeriod" => "cpu_manager.reconcile_period_seconds",
          "cpuCFSQuotaPeriod" => "cpu_cfs_quota_period_seconds",
          "imageMinimumGCAge" => "image_gc.minimum_age",
          "imageMaximumGCAge" => "image_gc.maximum_age",
          "evictionPressureTransitionPeriod" => "eviction.pressure_transition_period",
          "shutdownGracePeriod" => "shutdown.grace_period",
          "shutdownGracePeriodCriticalPods" => "shutdown.grace_period_critical_pods"
        }.freeze

        # These gates have explicit consumers in the agent, its runtime, or
        # its bootstrap wiring. Other gates may be echoed from native YAML.
        FEATURE_GATES = %w[
          CPUManagerPolicyAlphaOptions CPUManagerPolicyBetaOptions CRIListStreaming CSIVolumeHealth ContainerStopSignals CustomCPUCFSQuotaPeriod
          DRAWorkloadResourceClaims DisableCPUQuotaWithExclusiveCPUs EventedPLEG GracefulNodeShutdown GracefulNodeShutdownBasedOnPodPriority
          ImageVolumeWithDigest InPlacePodVerticalScalingExclusiveCPUs InPlacePodVerticalScalingExclusiveMemory
          InPlacePodVerticalScalingInitContainers KubeletCrashLoopBackOffMax LocalStorageCapacityIsolationFSQuotaMonitoring
          MemoryQoS NodeDeclaredFeatures PodAndContainerStatsFromCRI PodLevelResourceManagers PodLevelResources
          PodLogsQuerySplitStreams PodReadyToStartContainersCondition
          PodsAPI QOSReserved ReduceDefaultCrashLoopBackOffDecay ReloadKubeletClientCAFile
          ReloadKubeletServerCertificateFile ResourceHealthStatus RotateKubeletServerCertificate RuntimeClassInImageCriApi
        ].freeze
        CRI_SETTINGS = %w[runtimeRequestTimeout containerLogMaxWorkers containerLogMonitorInterval].freeze
        CONTAINER_LOG_LIMITS = %w[containerLogMaxSize containerLogMaxFiles].freeze
        MEMORY_QOS_SETTINGS = %w[memoryThrottlingFactor memoryReservationPolicy].freeze
        LIST_SETTINGS = {
          "reservedMemory" => ["memory_manager.reserved_memory", {"numaNode" => "numa_node", "limits" => "limits"}],
          "shutdownGracePeriodByPodPriority" => ["shutdown.grace_period_by_pod_priority",
                                                 {"priority" => "priority", "shutdownGracePeriodSeconds" => "shutdown_grace_period_seconds"}]
        }.freeze

        DURATION_PART = /(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/
        DURATION_UNITS = {"ns" => 1, "us" => 1_000, "µs" => 1_000, "μs" => 1_000, "ms" => 1_000_000,
                          "s" => 1_000_000_000, "m" => 60_000_000_000, "h" => 3_600_000_000_000}.freeze

        Result = Data.define(:process, :read_only_fields)

        module_function

        def typed_document?(document)
          document["kind"] == KIND || document["apiVersion"].to_s.start_with?("kubelet.config.k8s.io/")
        end

        def translate(document, process:, path:)
          raise Error, "#{path} must declare apiVersion #{API_VERSION} and kind #{KIND}" unless document.values_at(*TYPE_FIELDS) == [API_VERSION, KIND]

          effective = Node::KubeletConfigz.build(process).fetch("kubeletconfig")
          # The v1beta1 Go encoder materializes zero-valued struct fields.
          effective.fetch("logging").fetch("options")["text"] = {"infoBufferSize" => "0"}
          read_only = []
          converted = feature_gate_settings(process, document["featureGates"], read_only)
          unsupported = []
          document.except(*TYPE_FIELDS, "featureGates").each do |field, value|
            route, setting = mapped_setting(field, value, path)
            route, setting = client_ca_setting(value, effective[field], path) if field == "authentication"
            if readback_of_cri_log_limit?(field, route, value, process, effective)
              read_only << field
            elsif route && (setting.nil? || setting_available?(field, converted, document))
              apply_empty = %w[crashLoopBackOff serializeImagePulls maxParallelImagePulls cpuCFSQuota cpuCFSQuotaPeriod].include?(field)
              apply_empty ||= field == "singleProcessOOMKill" || (field == "staticPodPath" && value == "")
              converted = set_setting(converted, route.split("."), setting) if !setting.nil? || apply_empty
            elsif effective.key?(field) && unchanged_setting?(value, effective[field])
              read_only << field
            else
              unsupported << field
            end
          end
          raise Error, "#{path} contains unsupported KubeletConfiguration settings: #{unsupported.sort.join(", ")}" unless unsupported.empty?

          converted = apply_component_defaults(converted, document)
          validate_tls_settings!(converted, document)
          validate_listener!(converted, document, original: process)
          validate_shutdown_gates!(converted, document)
          Result.new(process: converted, read_only_fields: read_only.sort)
        end

        def setting_available?(field, process, document)
          return process.dig("cri", "enabled") == true if CRI_SETTINGS.include?(field)
          return host_native_runtime?(process) if %w[podPidsLimit protectKernelDefaults].include?(field)
          return host_native_runtime?(process) || process.dig("cri", "enabled") == true if field == "podLogsDir"
          return memory_setting_available?(field, process, document) if MEMORY_QOS_SETTINGS.include?(field) || %w[qosReserved reservedMemory].include?(field)

          true
        end

        def host_native_runtime?(process)
          %w[host_integration kernel_isolation l3].include?(process.fetch("runtime_profile", "pure").downcase.tr("-", "_"))
        end

        def memory_setting_available?(field, process, document)
          host = host_native_runtime?(process)
          case field
          when "reservedMemory"
            host && (document["memoryManagerPolicy"] || process.dig("memory_manager", "policy")) == "Static"
          when "qosReserved"
            cgroups = document["cgroupsPerQOS"].nil? ? process.fetch("cgroups_per_qos", true) : document["cgroupsPerQOS"]
            host && cgroups == true && process.dig("feature_gates", "QOSReserved") == true
          else
            (host || process.dig("cri", "enabled") == true) && process.dig("feature_gates", "MemoryQoS") == true
          end
        end

        def readback_of_cri_log_limit?(field, route, value, process, effective)
          CONTAINER_LOG_LIMITS.include?(field) && process.dig("cri", "enabled") == true &&
            process.fetch("cri").key?(route) && !process.key?(route) && effective[field] == value
        end

        def feature_gate_settings(process, requested, read_only)
          return process if requested.nil?
          raise Error, "KubeletConfiguration.featureGates must map gate names to booleans" unless requested.is_a?(Hash)

          native = process.fetch("feature_gates", {})
          unsupported = requested.except(*FEATURE_GATES)
          changed = unsupported.reject { |gate, value| native.key?(gate) && native[gate] == value }
          raise Error, "unsupported KubeletConfiguration feature gates: #{changed.keys.sort.join(", ")}" unless changed.empty?

          read_only << "featureGates" unless unsupported.empty?
          process.merge("feature_gates" => native.merge(requested))
        end

        def apply_component_defaults(process, document)
          process = apply_client_rate_defaults(process, document)
          if document["volumeStatsAggPeriod"] && process["volume_stats_agg_period_seconds"] == 0
            process = process.merge("volume_stats_agg_period_seconds" => Node::KubeletConfigz::DEFAULT_VOLUME_STATS_AGG_PERIOD_SECONDS)
          end
          if document["nodeStatusUpdateFrequency"] && !process.dig("sync", "node_status_report_frequency_seconds")
            seconds = process.dig("sync", "node_status_update_frequency_seconds")
            process = set_setting(process, %w[sync node_status_report_frequency_seconds], seconds)
          end
          process
        end

        def apply_client_rate_defaults(process, document)
          qps, burst = document.values_at("kubeAPIQPS", "kubeAPIBurst")
          return process if qps.nil? && burst.nil?

          {"kubeAPIQPS" => qps, "kubeAPIBurst" => burst}.each do |field, value|
            next if value.nil? || (value.is_a?(Integer) && value.between?(0, INT32_MAX))

            raise Error, "KubeletConfiguration.#{field} must be a non-negative int32"
          end
          effective_burst = process.fetch("kube_api_burst", Node::KubeletAPIRates::DEFAULT_BURST)
          process.merge("kube_api_burst" => (effective_burst == 0 ? Node::KubeletAPIRates::DEFAULT_BURST : effective_burst))
        end

        def validate_listener!(process, document, original:)
          return unless %w[enableServer address port readOnlyPort].any? { |field| !document[field].nil? }

          validate_listener_values!(document, original.dig("streaming", "port"))
          streaming = process.fetch("streaming", {})
          hosts = [streaming.fetch("host", "127.0.0.1"), *streaming.fetch("additional_hosts", [])]
          return if hosts.all? { |host| %w[127.0.0.1 ::1 localhost].include?(host) }

          read_only_port = process.fetch("read_only_port", 0)
          bind_changed = hosts.first != original.dig("streaming", "host") || read_only_port != original.fetch("read_only_port", 0)
          if bind_changed && read_only_port.is_a?(Integer) && read_only_port.positive?
            raise Error, "KubeletConfiguration requires loopback addresses with readOnlyPort enabled"
          end
          return if streaming["enabled"] == false || streaming.values_at("authentication", "authorization").any? { |value| value.is_a?(Hash) && !value.empty? }

          raise Error, "KubeletConfiguration.address requires native streaming authentication and authorization on non-loopback addresses"
        end

        def validate_listener_values!(document, original_port)
          enabled = document["enableServer"]
          raise Error, "KubeletConfiguration.enableServer must be a boolean" unless enabled.nil? || [true, false].include?(enabled)

          port = document["port"]
          native_ephemeral = port.eql?(0) && original_port.eql?(0)
          unless port.nil? || native_ephemeral || (port.is_a?(Integer) && port.between?(1, 65_535))
            raise Error, "KubeletConfiguration.port must be between 1 and 65535"
          end

          address = document["address"]
          return if address.nil? || address == "localhost"

          raise IPAddr::InvalidAddressError unless address.is_a?(String) && !address.include?("/")

          IPAddr.new(address)
        rescue IPAddr::InvalidAddressError
          raise Error, "KubeletConfiguration.address must be an IP address or localhost"
        end

        def validate_shutdown_gates!(process, document)
          entries = document["shutdownGracePeriodByPodPriority"]
          grace_fields = %w[shutdownGracePeriod shutdownGracePeriodCriticalPods].select do |field|
            document[field] && duration(document[field], field).positive?
          end
          grace_fields << "shutdownGracePeriodByPodPriority" if entries && !entries.empty?
          if !grace_fields.empty? && process.dig("feature_gates", "GracefulNodeShutdown") == false
            raise Error, "KubeletConfiguration.#{grace_fields.first} requires GracefulNodeShutdown"
          end
          return if entries.nil? || entries.empty? || process.dig("feature_gates", "GracefulNodeShutdownBasedOnPodPriority") != false

          raise Error, "KubeletConfiguration.shutdownGracePeriodByPodPriority requires GracefulNodeShutdownBasedOnPodPriority"
        end

        def mapped_setting(field, value, path)
          if SETTINGS.key?(field)
            NodeRegistration.validate_flag!(value, "KubeletConfiguration.#{field}") if field == "registerNode" && !value.nil?
            NodeRegistration.validate_taints!(value, "KubeletConfiguration.#{field}") if field == "registerWithTaints" && !value.nil?
            value = certificate_path(field, value, path) if %w[tlsCertFile tlsPrivateKeyFile].include?(field)
            if %w[staticPodPath resolvConf].include?(field) && value.is_a?(String) && !value.empty?
              raise Error, "KubeletConfiguration.#{field} must be a valid path" if value.include?("\0")

              value = File.absolute_path(value, File.dirname(path))
            end
            value = nil if field == "staticPodPath" && value == ""
            return [SETTINGS.fetch(field), value]
          end
          return [DURATIONS.fetch(field), duration(value, field, allow_negative: field == "volumeStatsAggPeriod")] if DURATIONS.key?(field)
          return list_setting(field, value) if LIST_SETTINGS.key?(field)

          if field == "evictionSoftGracePeriod"
            return ["eviction.soft_grace_period", nil] if value.nil?

            raise Error, "KubeletConfiguration.#{field} must map eviction signals to durations" unless value.is_a?(Hash)

            return ["eviction.soft_grace_period", value.transform_values { |entry| duration(entry, field) }]
          end
          return [nil, nil] unless field == "crashLoopBackOff"

          restart_period(value)
        end

        def client_ca_setting(value, effective, path)
          return [nil, nil] unless value.is_a?(Hash) && value["x509"].is_a?(Hash) && value["x509"].key?("clientCAFile")

          unchanged = value.merge("x509" => value.fetch("x509").except("clientCAFile"))
          return [nil, nil] unless unchanged_setting?(unchanged, effective)

          ["streaming.tls.client_ca_file", certificate_path("authentication.x509.clientCAFile", value.dig("x509", "clientCAFile"), path)]
        end

        def certificate_path(field, value, path)
          return nil if value.nil?
          raise Error, "KubeletConfiguration.#{field} must name a certificate file" unless value.is_a?(String) && !value.empty? && !value.include?("\0")

          File.absolute_path(value, File.dirname(path))
        end

        def validate_tls_settings!(process, document)
          if document.key?("tlsCertFile") || document.key?("tlsPrivateKeyFile") || document.dig("authentication", "x509", "clientCAFile")
            tls = process.dig("streaming", "tls")
            raise Error, "KubeletConfiguration requires both tlsCertFile and tlsPrivateKeyFile" unless tls && tls.values_at("cert_file", "key_file").all?
          end
          return unless process["server_tls_bootstrap"] == true && process.dig("feature_gates", "RotateKubeletServerCertificate") == false

          raise Error, "KubeletConfiguration.serverTLSBootstrap requires RotateKubeletServerCertificate"
        end

        def list_setting(field, value)
          route, keys = LIST_SETTINGS.fetch(field)
          return [route, nil] if value.nil?
          raise Error, "KubeletConfiguration.#{field} must be a list" unless value.is_a?(Array)

          entries = value.each_with_index.map do |entry, index|
            context = "KubeletConfiguration.#{field}[#{index}]"
            raise Error, "#{context} must contain only #{keys.keys.join(", ")}" unless entry.is_a?(Hash) && (entry.keys - keys.keys).empty?

            validate_list_numbers!(entry, context)
            entry.transform_keys { |key| keys.fetch(key) }
          end
          [route, entries]
        end

        def validate_list_numbers!(entry, context)
          {"numaNode" => (0..INT32_MAX), "priority" => (-(2**31)..INT32_MAX),
           "shutdownGracePeriodSeconds" => (0..((2**63) - 1))}.each do |key, range|
            next unless entry.key?(key)

            number = entry.fetch(key)
            raise Error, "#{context}.#{key} must be an integer between #{range.begin} and #{range.end}" unless number.is_a?(Integer) && range.cover?(number)
          end
        end

        def restart_period(value)
          field = "crashLoopBackOff.maxContainerRestartPeriod"
          route = "crash_loop_back_off.max_container_restart_period_seconds"
          return [route, nil] if value.nil?

          unless value.is_a?(Hash) && (value.keys - ["maxContainerRestartPeriod"]).empty?
            raise Error, "KubeletConfiguration.crashLoopBackOff only supports maxContainerRestartPeriod"
          end

          [route, duration(value["maxContainerRestartPeriod"], field)]
        end

        def duration(value, field, allow_negative: false)
          return nil if value.nil?
          return 0 if %w[0 +0 -0].include?(value)

          if value.is_a?(String)
            prefix = value.start_with?("+", "-") ? value[0] : ""
            text = value.delete_prefix(prefix)
            parts = text.scan(DURATION_PART)
            if parts.any? && parts.map(&:join).join == text && (allow_negative || prefix != "-")
              nanos = parts.sum { |number, unit| (Rational(number) * DURATION_UNITS.fetch(unit)).to_i }
              nanos = -nanos if prefix == "-"
              if nanos.between?(allow_negative ? -(2**63) : 0, (2**63) - 1)
                seconds = Rational(nanos, DURATION_UNITS.fetch("s"))
                return allow_negative ? seconds : seconds.to_f
              end
            end
          end
          unit = allow_negative ? "a Go duration" : "a non-negative Go duration"
          raise Error, "KubeletConfiguration.#{field} must be #{unit}"
        end

        def set_setting(settings, route, value)
          key, *remaining = route
          return settings.merge(key => value) if remaining.empty?

          settings.merge(key => set_setting(settings.fetch(key, {}), remaining, value))
        end

        def unchanged_setting?(requested, effective)
          return requested == effective unless requested.is_a?(Hash) && effective.is_a?(Hash)

          requested.all? { |key, value| effective.key?(key) && unchanged_setting?(value, effective[key]) }
        end
      end

      def self.load(process_name:, path: nil, kubelet_config_path: nil)
        validate_process_name!(process_name)
        defaults = read_yaml(DEFAULT_PATH)
        overrides = path ? read_yaml(File.expand_path(path)) : {}
        component = overrides if KubeletComponentConfig.typed_document?(overrides)
        base = component ? defaults : deep_merge(defaults, overrides)
        return new(process_name: process_name, data: base) unless component || kubelet_config_path

        raise Error, "use just one KubeletConfiguration file" if component && kubelet_config_path

        with_kubelet_component_config(process_name: process_name, path: File.expand_path(kubelet_config_path || path),
                                      base: base, document: component)
      end

      def self.with_kubelet_component_config(process_name:, path:, base:, document:)
        raise Error, "KubeletConfiguration can only configure rubernetes-agent" unless process_name == "rubernetes-agent"

        native_config = new(process_name: process_name, data: base)
        component = document || read_yaml(path)
        result = KubeletComponentConfig.translate(component, process: native_config.process, path: path)
        processes = base.fetch("processes").merge(process_name => result.process)
        new(process_name: process_name, data: base.merge("processes" => processes), kubelet_read_only_fields: result.read_only_fields)
      end
      private_class_method :with_kubelet_component_config
    end
  end
end
