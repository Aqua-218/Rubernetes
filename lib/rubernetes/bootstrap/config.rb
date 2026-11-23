# frozen_string_literal: true

require_relative "../support/object_tree"

require "psych"
require "uri"
require "ipaddr"

require_relative "config/value_checks"
require_relative "config/security_validation"
require_relative "config/static_pod_source"
require_relative "config/proxy_validation"
require_relative "config/cri_validation"
require_relative "config/kubelet_component_config"
require_relative "config/node_registration"
require_relative "node_ipam_settings"
require_relative "../network/load_balancer_pool"
require_relative "../network/nat64_prefix"
require_relative "../runtime/memory_qos"
require_relative "../node/kubelet_healthz"
require_relative "../storage/memory_store"

module Rubernetes
  module Bootstrap
    class Config
      class Error < StandardError; end

      LEVELS = %w[debug info warn error fatal].freeze
      PROCESS_NAMES = %w[
        rubectl
        rubernetes-apiserver
        rubernetes-controller-manager
        rubernetes-scheduler
        rubernetes-agent
        rubernetes-proxy
      ].freeze
      DEFAULT_PATH = File.expand_path("../../../config/defaults/m1.yml", __dir__).freeze
      TOP_LEVEL_KEYS = %w[version logging processes console].freeze
      # A Ruby prompt inside the running process (Console::Server), for the
      # owner of this socket only.  Absent, the process does not listen.
      CONSOLE_KEYS = %w[socket].freeze
      LOGGING_KEYS = %w[level].freeze
      MAX_BYTES = 1_048_576
      APISERVER_KEYS = %w[bind_address port max_body_bytes watch_history_limit datastore tls security runtime_config
                          service_cluster_ip_range node_port_range advertise_address proxy_client kubelet_client
                          peer_ca_file peer_advertise_ip peer_advertise_port
                          encryption_config_file encryption_config_reload_interval_seconds egress_selector_config_file
                          extensions].freeze
      TLS_KEYS = %w[cert_file key_file].freeze
      SECURITY_KEYS = %w[authentication authorization admission audit flow_control feature_gates].freeze
      AUTHENTICATION_KEYS = %w[client_ca_file token_file service_account bootstrap_tokens request_header jwt webhook anonymous
                               config_file].freeze
      SERVICE_ACCOUNT_KEYS = %w[issuer signing_key_file key_files api_audiences max_expiration_seconds signing_endpoint
                                allow_signing_with_non_oidc_keys extend_expiration].freeze
      REQUEST_HEADER_KEYS = %w[ca_file allowed_names username_headers group_headers extra_header_prefixes uid_headers].freeze
      AUTHENTICATION_WEBHOOK_KEYS = %w[url ca_file client_cert_file client_key_file cache_authenticated_ttl
                                       cache_unauthenticated_ttl].freeze
      AUTHORIZATION_KEYS = %w[modes abac_policy_file webhook config_file].freeze
      AUTHORIZATION_WEBHOOK_KEYS = %w[url ca_file client_cert_file client_key_file cache_authorized_ttl cache_unauthorized_ttl
                                      failure_policy].freeze
      ADMISSION_KEYS = %w[enable disable config].freeze
      AUDIT_KEYS = %w[policy_file log_path max_queue webhook].freeze
      AUDIT_WEBHOOK_KEYS = %w[url mode ca_file token token_file timeout_seconds batch_max_size batch_max_wait_seconds].freeze
      FLOW_CONTROL_KEYS = %w[enabled read_seats mutating_seats].freeze
      DATASTORE_KEYS = %w[type node_id cluster_id data_dir pki_dir listen_address listen_port voters peers timing
                          compaction_interval_seconds history_retention_policy join].freeze
      DATASTORE_TYPES = %w[memory raft].freeze
      DATASTORE_TIMING_KEYS = %w[
        election_timeout_min election_timeout_max heartbeat_interval batch_max_entries batch_max_bytes
        batch_flush_timeout snapshot_entries snapshot_wal_bytes snapshot_min_interval max_inflight_appends snapshot_chunk_bytes
        max_command_bytes
      ].freeze
      CONTROL_PLANE_KEYS = %w[api_server kubeconfig context identity sync lease resource_kinds controllers root_ca_file metrics_server serving cluster_signing
                              use_service_account_credentials service_account_private_key_file extensions
                              enable_hostpath_provisioner hostpath_provisioner_root load_balancer_pool default_routed_load_balancer
                              cloud_controller_manager kube_api_qps
                              kube_api_burst feature_gates terminated_pod_gc_threshold node_ipam].freeze
      CLUSTER_SIGNING_KEYS = %w[cert_file key_file duration_seconds signers].freeze
      CLUSTER_SIGNING_SIGNERS = %w[kubelet_serving kubelet_client kube_apiserver_client legacy_unknown].freeze
      # ComponentServer: the scheduler's / controller-manager's endpoints.
      SERVING_KEYS = %w[enabled bind_address port].freeze
      METRICS_SERVER_KEYS = %w[
        enabled port bind_address advertise_address metric_resolution_seconds scrape_timeout_seconds kubelet_scheme kubelet_port
        kubelet_insecure_tls address_type_priority node_selector register tls jitter
      ].freeze
      SCHEDULER_KEYS = %w[api_server kubeconfig context identity sync lease resource_kinds serving feature_gates extensions kube_api_qps kube_api_burst].freeze
      # Extension objects (rubernetes.io/v1alpha1) are Ruby source evaluated
      # inside the component: off unless the configuration turns them on.
      EXTENSIONS_KEYS = %w[enabled].freeze
      PROXY_KEYS = %w[api_server kubeconfig context node_name node_addresses backend attach sync serving kube_api_qps kube_api_burst].freeze
      AGENT_KEYS = %w[
        node_name api_server kubeconfig context runtime_profile cloud_provider provider_id register_node register_with_taints
        sandbox_root cgroup_root log_root journal_path runtime_paths runtime kubelet_cgroups runtime_cgroups system_cgroups
        static_pod_path file_check_frequency_seconds static_pod_url static_pod_url_header http_check_frequency_seconds
        sync lease privileged l3 network volume microvm runtime_classes
        streaming addresses dns pod_root cluster_domain seccomp_root resolv_conf max_pods healthz_port healthz_bind_address read_only_port
        pods_per_core node_status_max_images volume_stats_agg_period_seconds cpu_cfs_quota cpu_cfs_quota_period_seconds
        allowed_unsafe_sysctls feature_gates eviction image image_gc serialize_image_pulls max_parallel_image_pulls dra
        system_reserved kube_reserved reserved_system_cpus cpu_manager memory_manager topology_manager shutdown
        memory_throttling_factor memory_reservation_policy single_process_oom_kill protect_kernel_defaults
        cgroups_per_qos enforce_node_allocatable system_reserved_cgroup kube_reserved_cgroup qos_reserved cri crash_loop_back_off
        device_plugins pod_resources pods_api_directory pod_logs_dir pod_pids_limit image_pull_credentials image_credential_provider
        container_log_max_size container_log_max_files
        bootstrap_kubeconfig rotate_certificates server_tls_bootstrap cert_dir kube_api_qps kube_api_burst
      ].freeze
      # A CRI runtime (containerd, CRI-O) serving RuntimeClass handlers:
      # handlers maps the node's handler name to the CRI runtime handler.
      AGENT_CRI_KEYS = %w[enabled endpoint handlers default_handler log_root cgroup_parent timeout_seconds
                          container_log_max_size container_log_max_files container_log_max_workers container_log_monitor_interval_seconds].freeze
      # kubelet shutdownGracePeriod / shutdownGracePeriodCriticalPods /
      # shutdownGracePeriodByPodPriority.
      AGENT_SHUTDOWN_KEYS = %w[grace_period grace_period_critical_pods grace_period_by_pod_priority].freeze
      AGENT_CPU_MANAGER_KEYS = %w[policy options reconcile_period_seconds].freeze
      AGENT_MEMORY_MANAGER_KEYS = %w[policy reserved_memory].freeze
      AGENT_TOPOLOGY_MANAGER_KEYS = %w[policy scope options].freeze
      # Dynamic Resource Allocation on the node: the kubelet plugin registry
      # directory, the DRA manager's state directory and the CDI spec dirs.
      AGENT_DRA_KEYS = %w[enabled plugins_registry state_dir cdi_spec_dirs].freeze
      # kubelet imageGCHighThresholdPercent / imageGCLowThresholdPercent /
      # imageMinimumGCAge / imageMaximumGCAge.
      AGENT_IMAGE_GC_KEYS = %w[enabled high_threshold_percent low_threshold_percent minimum_age maximum_age].freeze
      # kubelet evictionHard / evictionSoft / evictionSoftGracePeriod /
      # evictionMinimumReclaim / evictionPressureTransitionPeriod /
      # evictionMaxPodGracePeriod.
      AGENT_EVICTION_KEYS = %w[enabled hard soft soft_grace_period minimum_reclaim pressure_transition_period
                               max_pod_grace_period_seconds].freeze
      AGENT_DNS_KEYS = %w[enabled port bind_addresses cluster_dns upstreams cluster_domain resolv_conf positive_ttl negative_ttl kubeconfig hosts
                          nat64_prefix].freeze
      AGENT_MICROVM_KEYS = %w[enabled data_dir chroot_base netns_root run_root parent_cgroup vcpu_count mem_size_mib use_base_snapshot
                              artifacts_lock workspace_mib].freeze
      AGENT_RUNTIME_PATH_KEYS = %w[sandbox_root cgroup_root log_root journal_path userns_allocation_path].freeze
      AGENT_SYNC_KEYS = %w[period_seconds watch_timeout_seconds resync_period watch_timeout
                           node_status_update_frequency_seconds node_status_report_frequency_seconds].freeze
      AGENT_LEASE_KEYS = %w[namespace duration_seconds renew_fraction].freeze
      CONTROL_PLANE_SYNC_KEYS = %w[period_seconds interval_seconds].freeze
      CONTROL_PLANE_LEASE_KEYS = %w[namespace name lease_duration_seconds renew_deadline_seconds retry_period_seconds].freeze
      NETWORK_KEYS = %w[cluster_cidr ipv4_cidr ipv6_cidr node_subnet_prefix ipv4_node_prefix ipv6_node_prefix state_path bridge_name mtu
                        fsync policy_backend policy_table policy_kubeconfig plugin cni].freeze
      # network.plugin: the built-in bridge, or CNI plugins run by the agent.
      NETWORK_PLUGINS = %w[bridge cni].freeze
      NETWORK_CNI_KEYS = %w[conf_dir bin_dirs].freeze
      NETWORK_POLICY_BACKENDS = %w[ebpf nftables disabled].freeze
      VOLUME_KEYS = %w[data_dir root fsync profile csi].freeze
      VOLUME_CSI_KEYS = %w[
        socket timeout identity probe socket_uid socket_gid socket_mode peer_uid peer_gid
      ].freeze
      VOLUME_CSI_IDENTITY_KEYS = %w[name vendor_version vendorVersion].freeze
      VOLUME_PROFILES = %w[native test fake_io].freeze
      GATE_DEPENDENCIES = {
        "ClusterTrustBundleProjection" => {"ClusterTrustBundle" => false},
        "DRAResourcePoolStatus" => {"DynamicResourceAllocation" => true},
        "DRAWorkloadResourceClaims" => {"DynamicResourceAllocation" => true, "GenericWorkload" => false},
        "PodCertificateRequest" => {"AuthorizeNodeWithSelectors" => true},
        "WorkloadWithJob" => {"GenericWorkload" => false}
      }.freeze

      attr_reader :process_name, :kubelet_read_only_fields

      def self.validate_process_name!(process_name)
        return if PROCESS_NAMES.include?(process_name)

        raise Error, "unknown process #{process_name.inspect}"
      end

      def self.read_yaml(path)
        content = File.binread(path, MAX_BYTES + 1)
        raise Error, "configuration exceeds #{MAX_BYTES} bytes: #{path}" if content.bytesize > MAX_BYTES

        document = Psych.safe_load(
          content,
          filename: path,
          permitted_classes: [],
          permitted_symbols: [],
          aliases: false
        )
        document ||= {}
        raise Error, "configuration root must be a mapping: #{path}" unless document.is_a?(Hash)

        stringify_keys(document)
      rescue Errno::ENOENT, Errno::EACCES, Psych::Exception => error
        raise Error.new("cannot load configuration #{path}: #{error.message}"), cause: error
      end
      private_class_method :read_yaml

      def self.stringify_keys(value)
        case value
        when Hash
          value.to_h { |key, child| [String(key), stringify_keys(child)] }
        when Array
          value.map { |child| stringify_keys(child) }
        else
          value
        end
      end
      private_class_method :stringify_keys

      def self.deep_merge(base, override)
        base.merge(override) do |_key, left, right|
          left.is_a?(Hash) && right.is_a?(Hash) ? deep_merge(left, right) : right
        end
      end
      private_class_method :deep_merge

      def initialize(process_name:, data:, kubelet_read_only_fields: [])
        @process_name = process_name.dup.freeze
        @kubelet_read_only_fields = deep_freeze(kubelet_read_only_fields)
        validate!(data)
        @data = deep_freeze(data)
        freeze
      end

      def logging_level
        @data.fetch("logging").fetch("level")
      end

      def process
        @data.fetch("processes").fetch(process_name)
      end

      def console_socket
        @data.dig("console", "socket")
      end

      def to_h
        @data
      end

      include SecurityValidation
      include StaticPodSource
      include ProxyValidation
      include CRIValidation
      include ValueChecks

      private

      def validate!(data)
        reject_unknown_keys!(data, TOP_LEVEL_KEYS, "configuration")
        raise Error, "configuration version must be 1" unless data["version"] == 1

        logging = data["logging"]
        raise Error, "logging must be a mapping" unless logging.is_a?(Hash)

        reject_unknown_keys!(logging, LOGGING_KEYS, "logging")
        validate_console!(data["console"]) if data.key?("console")
        raise Error, "logging.level must be one of #{LEVELS.join(", ")}" unless LEVELS.include?(logging["level"])

        processes = data["processes"]
        raise Error, "processes must be a mapping" unless processes.is_a?(Hash)

        unknown_processes = processes.keys - PROCESS_NAMES
        raise Error, "unknown process configuration: #{unknown_processes.sort.join(", ")}" unless unknown_processes.empty?
        raise Error, "missing process configuration: #{process_name}" unless processes[process_name].is_a?(Hash)

        processes.each do |name, process_config|
          raise Error, "process configuration must be a mapping: #{name}" unless process_config.is_a?(Hash)

          if name == "rubernetes-apiserver"
            validate_apiserver!(process_config)
          elsif name == "rubernetes-agent"
            validate_agent!(process_config)
          elsif name == "rubernetes-controller-manager"
            validate_control_plane!(process_config, CONTROL_PLANE_KEYS, name, lease: true)
            validate_metrics_server!(process_config["metrics_server"]) if process_config.key?("metrics_server")
            validate_cluster_signing!(process_config["cluster_signing"]) if process_config.key?("cluster_signing")
            validate_load_balancer!(process_config)
            validate_node_ipam!(process_config["node_ipam"]) if process_config.key?("node_ipam")
            threshold = process_config.fetch("terminated_pod_gc_threshold", 0)
            unless threshold.is_a?(Integer) && threshold.between?(-(2**31), (2**31) - 1)
              raise Error, "rubernetes-controller-manager.terminated_pod_gc_threshold must be a signed 32-bit integer"
            end

            if process_config.key?("service_account_private_key_file")
              validate_absolute_path!(process_config["service_account_private_key_file"],
                                      "rubernetes-controller-manager.service_account_private_key_file")
            end
            validate_hostpath_provisioner!(process_config)
            if process_config.key?("use_service_account_credentials") && ![true,
                                                                           false].include?(process_config["use_service_account_credentials"])
              raise Error, "rubernetes-controller-manager.use_service_account_credentials must be true or false"
            end
          elsif name == "rubernetes-scheduler"
            validate_control_plane!(process_config, SCHEDULER_KEYS, name, lease: true)
          elsif name == "rubernetes-proxy"
            validate_proxy!(process_config)
          else
            raise Error, "M0 process configuration must be empty: #{name}" unless process_config.empty?
          end
        end
      end

      def validate_metrics_server!(options)
        validate_mapping!(options, "rubernetes-controller-manager.metrics_server")
        reject_unknown_keys!(options, METRICS_SERVER_KEYS, "rubernetes-controller-manager.metrics_server")
        %w[enabled kubelet_insecure_tls register jitter].each do |key|
          next unless options.key?(key)

          raise Error, "rubernetes-controller-manager.metrics_server.#{key} must be a boolean" unless [true, false].include?(options[key])
        end
        %w[port kubelet_port].each do |key|
          next unless options.key?(key)

          value = options[key]
          raise Error, "rubernetes-controller-manager.metrics_server.#{key} must be a port" unless value.is_a?(Integer) && value.between?(
            0, 65_535
          )
        end
        %w[metric_resolution_seconds scrape_timeout_seconds].each do |key|
          next unless options.key?(key)

          unless options[key].is_a?(Numeric) && options[key].positive?
            raise Error,
                  "rubernetes-controller-manager.metrics_server.#{key} must be positive"
          end
        end
        if options.key?("kubelet_scheme") && !%w[http https].include?(options["kubelet_scheme"])
          raise Error, "rubernetes-controller-manager.metrics_server.kubelet_scheme must be http or https"
        end
        if options["register"] == true && options["advertise_address"].to_s.empty?
          raise Error, "rubernetes-controller-manager.metrics_server.register requires advertise_address"
        end
        return unless options.key?("tls")

        validate_mapping!(options["tls"], "rubernetes-controller-manager.metrics_server.tls")
        reject_unknown_keys!(options["tls"], TLS_KEYS, "rubernetes-controller-manager.metrics_server.tls")
      end

      def validate_agent!(process_config)
        begin
          reject_unknown_keys!(process_config, AGENT_KEYS, "rubernetes-agent configuration")
          validate_agent_api_rate!(process_config)
        rescue Error => error
          # Keep the M0 diagnostic wording stable for callers that validate all
          # daemon profiles with the original empty-process contract.
          raise Error, "M0 process configuration must be empty for unknown fields: #{error.message}"
        end
        validate_non_empty_string!(process_config.fetch("node_name"), "rubernetes-agent.node_name")
        NodeRegistration.validate_flag!(process_config["register_node"], "rubernetes-agent.register_node") if process_config.key?("register_node")
        if process_config.key?("register_with_taints")
          NodeRegistration.validate_taints!(process_config["register_with_taints"], "rubernetes-agent.register_with_taints")
        end
        if process_config.key?("cloud_provider") && process_config["cloud_provider"] != "external"
          raise Error, "rubernetes-agent.cloud_provider must be external"
        end

        validate_non_empty_string!(process_config["provider_id"], "rubernetes-agent.provider_id") if process_config.key?("provider_id")
        validate_absolute_path!(process_config["pods_api_directory"], "rubernetes-agent.pods_api_directory") if process_config.key?("pods_api_directory")
        validate_api_server!(process_config.fetch("api_server")) if process_config.key?("api_server")
        %w[kubeconfig context].each do |key|
          if process_config.key?(key) && !process_config[key].nil?
            validate_non_empty_string!(process_config[key],
                                       "rubernetes-agent.#{key}")
          end
        end
        validate_agent_certificates!(process_config)
        validate_agent_listener_ports!(process_config)

        # kubelet --feature-gates: overrides of the pinned v1.36.2 defaults.
        if process_config.key?("feature_gates")
          gates = process_config["feature_gates"]
          validate_mapping!(gates, "rubernetes-agent.feature_gates")
          gates.each do |gate, enabled|
            raise Error, "rubernetes-agent.feature_gates.#{gate} must be a boolean" unless [true, false].include?(enabled)
          end
          validate_feature_gate_dependencies!(gates, "rubernetes-agent.feature_gates")
        end
        validate_eviction!(process_config["eviction"]) if process_config.key?("eviction")
        validate_image_staging!(process_config["image"]) if process_config.key?("image")
        validate_image_gc!(process_config["image_gc"]) if process_config.key?("image_gc")
        validate_dra!(process_config["dra"]) if process_config.key?("dra")
        %w[system_reserved kube_reserved].each do |key|
          validate_reservation!(process_config[key], key) if process_config.key?(key)
        end
        validate_cpu_set!(process_config["reserved_system_cpus"], "reserved_system_cpus") if process_config.key?("reserved_system_cpus")
        validate_node_allocatable_enforcement!(process_config)
        validate_qos_reserved!(process_config["qos_reserved"]) if process_config.key?("qos_reserved")
        validate_memory_qos!(process_config)
        if process_config.key?("protect_kernel_defaults") && ![true, false].include?(process_config["protect_kernel_defaults"])
          raise Error, "rubernetes-agent.protect_kernel_defaults must be a boolean"
        end

        validate_cpu_manager!(process_config["cpu_manager"]) if process_config.key?("cpu_manager")
        validate_memory_manager!(process_config["memory_manager"]) if process_config.key?("memory_manager")
        validate_topology_manager!(process_config["topology_manager"]) if process_config.key?("topology_manager")
        validate_shutdown!(process_config["shutdown"]) if process_config.key?("shutdown")
        validate_microvm!(process_config["microvm"]) if process_config.key?("microvm")
        validate_runtime_classes!(process_config["runtime_classes"]) if process_config.key?("runtime_classes")
        validate_agent_runtime_limits!(process_config)
        validate_crash_loop_back_off!(process_config) if process_config.key?("crash_loop_back_off")
        validate_image_pull_credentials!(process_config) if process_config.key?("image_pull_credentials")
        if process_config.key?("image_credential_provider")
          section = process_config["image_credential_provider"]
          context = "rubernetes-agent.image_credential_provider"
          raise Error, "#{context} must be a mapping" unless section.is_a?(Hash)

          reject_unknown_keys!(section, %w[config bin_dir], context)
          validate_absolute_path!(section["config"], "#{context}.config")
          validate_absolute_path!(section["bin_dir"], "#{context}.bin_dir")
        end
        if process_config.key?("pod_resources")
          section = process_config["pod_resources"]
          raise Error, "rubernetes-agent.pod_resources must be a mapping" unless section.is_a?(Hash)

          reject_unknown_keys!(section, %w[directory], "rubernetes-agent.pod_resources")
          validate_absolute_path!(section["directory"], "rubernetes-agent.pod_resources.directory") unless section["directory"].nil?
        end
        if process_config.key?("device_plugins")
          section = process_config["device_plugins"]
          raise Error, "rubernetes-agent.device_plugins must be a mapping" unless section.is_a?(Hash)

          reject_unknown_keys!(section, %w[directory], "rubernetes-agent.device_plugins")
          validate_absolute_path!(section["directory"], "rubernetes-agent.device_plugins.directory") unless section["directory"].nil?
        end
        profile = process_config.fetch("runtime_profile", "pure")
        unless profile.is_a?(String) && %w[pure fake_io host_integration kernel_isolation l3].include?(profile.downcase.tr("-", "_"))
          raise Error, "rubernetes-agent.runtime_profile must be one of pure, fake_io, host_integration, kernel_isolation, l3"
        end

        %w[sandbox_root cgroup_root log_root journal_path kubelet_cgroups runtime_cgroups system_cgroups].each do |key|
          validate_absolute_path!(process_config[key], "rubernetes-agent.#{key}") if process_config.key?(key)
        end
        %w[runtime_paths runtime].each do |container_key|
          next unless process_config.key?(container_key)

          paths = process_config.fetch(container_key)
          validate_mapping!(paths, "rubernetes-agent.#{container_key}")
          reject_unknown_keys!(paths, AGENT_RUNTIME_PATH_KEYS, "rubernetes-agent.#{container_key}")
          AGENT_RUNTIME_PATH_KEYS.each do |key|
            validate_absolute_path!(paths[key], "rubernetes-agent.#{container_key}.#{key}") if paths.key?(key)
          end
        end
        validate_static_pod_source!(process_config)

        sync = process_config.fetch("sync", {})
        validate_mapping!(sync, "rubernetes-agent.sync")
        reject_unknown_keys!(sync, AGENT_SYNC_KEYS, "rubernetes-agent.sync")
        sync.each { |key, value| validate_positive_number!(value, "rubernetes-agent.sync.#{key}") }

        lease = process_config.fetch("lease", {})
        validate_mapping!(lease, "rubernetes-agent.lease")
        reject_unknown_keys!(lease, AGENT_LEASE_KEYS, "rubernetes-agent.lease")
        validate_non_empty_string!(lease["namespace"], "rubernetes-agent.lease.namespace") if lease.key?("namespace")
        validate_positive_integer!(lease["duration_seconds"], "rubernetes-agent.lease.duration_seconds") if lease.key?("duration_seconds")
        if lease.key?("renew_fraction")
          value = lease["renew_fraction"]
          raise Error, "rubernetes-agent.lease.renew_fraction must be between 0 and 1" unless value.is_a?(Numeric) && value.positive? && value <= 1
        end
        %w[privileged l3].each do |key|
          next unless process_config.key?(key)
          raise Error, "rubernetes-agent.#{key} must be true or false" unless [true, false].include?(process_config[key])
        end
        normalized_profile = profile.downcase.tr("-", "_")
        if process_config["l3"] == true && !%w[kernel_isolation l3].include?(normalized_profile)
          raise Error, "rubernetes-agent.l3 requires kernel_isolation or l3 runtime_profile"
        end
        raise Error, "rubernetes-agent.l3 must be true for the l3 runtime_profile" if normalized_profile == "l3" && process_config["l3"] != true

        validate_network!(process_config["network"], "rubernetes-agent.network") if process_config.key?("network")
        validate_volume!(process_config["volume"], "rubernetes-agent.volume") if process_config.key?("volume")
        %w[pod_root seccomp_root].each do |key|
          validate_absolute_path!(process_config[key], "rubernetes-agent.#{key}") if process_config.key?(key) && !process_config[key].nil?
        end
        validate_agent_resolver!(process_config, "rubernetes-agent")
        validate_agent_node_limits!(process_config)
        if process_config.key?("volume_stats_agg_period_seconds")
          seconds = process_config["volume_stats_agg_period_seconds"]
          unless seconds.is_a?(Numeric) && seconds.finite? && seconds.real?
            raise Error, "rubernetes-agent.volume_stats_agg_period_seconds must be a finite number"
          end
        end
        validate_agent_dns!(process_config["dns"], profile: normalized_profile) if process_config.key?("dns")
      end

      def validate_agent_listener_ports!(config)
        %w[healthz_port read_only_port].each do |field|
          next unless config.key?(field)

          port = config.fetch(field)
          raise Error, "rubernetes-agent.#{field} must be between 0 and 65535" unless port.is_a?(Integer) && port.between?(0, 65_535)
        end
        return unless config.key?("healthz_bind_address") && !Node::KubeletHealthz.loopback_address?(config["healthz_bind_address"])

        raise Error, "rubernetes-agent.healthz_bind_address must be a loopback IP address"
      end

      def validate_agent_certificates!(process_config)
        %w[bootstrap_kubeconfig cert_dir].each do |key|
          validate_absolute_path!(process_config[key], "rubernetes-agent.#{key}") if process_config.key?(key)
        end
        if process_config.key?("bootstrap_kubeconfig") && !process_config.key?("kubeconfig")
          raise Error, "rubernetes-agent.bootstrap_kubeconfig requires kubeconfig (the file the bootstrap writes)"
        end

        %w[server_tls_bootstrap rotate_certificates].each do |key|
          next unless process_config.key?(key) && ![true, false].include?(process_config[key])

          raise Error, "rubernetes-agent.#{key} must be true or false"
        end
      end

      def validate_agent_dns!(section, profile:)
        validate_mapping!(section, "rubernetes-agent.dns")
        reject_unknown_keys!(section, AGENT_DNS_KEYS, "rubernetes-agent.dns")
        raise Error, "rubernetes-agent.dns.enabled must be true or false" if section.key?("enabled") && ![true, false].include?(section["enabled"])

        validate_positive_integer!(section["port"], "rubernetes-agent.dns.port") if section.key?("port")
        %w[bind_addresses cluster_dns upstreams].each do |key|
          next unless section.key?(key)
          next if section[key].is_a?(Array) && section[key].all? do |value|
            value.is_a?(String) && !value.empty?
          end

          raise Error,
                "rubernetes-agent.dns.#{key} must be a list of addresses"
        end
        validate_agent_resolver!(section, "rubernetes-agent.dns")
        if section.key?("hosts")
          hosts = section["hosts"]
          valid = hosts.is_a?(Hash) && hosts.all? do |name, addresses|
            name.is_a?(String) && !name.empty? &&
              Array(addresses).all? { |value| value.is_a?(String) && !value.empty? } && !Array(addresses).empty?
          end
          raise Error, "rubernetes-agent.dns.hosts must map names (or *.suffix) to one or more addresses" unless valid
        end
        validate_absolute_path!(section["kubeconfig"], "rubernetes-agent.dns.kubeconfig") if section.key?("kubeconfig")
        %w[positive_ttl negative_ttl].each do |key|
          validate_positive_integer!(section[key], "rubernetes-agent.dns.#{key}") if section.key?(key) && section[key] != 0
        end
        return unless section.key?("nat64_prefix")

        validate_nat64_prefix!(section["nat64_prefix"])
        return unless section["enabled"] == false || !%w[host_integration kernel_isolation l3].include?(profile)

        raise Error, "rubernetes-agent.dns.nat64_prefix requires enabled DNS and a native runtime profile"
      end

      def validate_dra!(value)
        validate_mapping!(value, "rubernetes-agent.dra")
        unknown = value.keys.map(&:to_s) - AGENT_DRA_KEYS
        raise Error, "rubernetes-agent.dra has unknown fields: #{unknown.sort.join(", ")}" unless unknown.empty?
        raise Error, "rubernetes-agent.dra.enabled must be a boolean" if value.key?("enabled") && ![true, false].include?(value["enabled"])

        %w[plugins_registry state_dir].each do |key|
          next unless value.key?(key)
          next if value[key].is_a?(String) && value[key].start_with?("/")

          raise Error, "rubernetes-agent.dra.#{key} must be an absolute path"
        end
        return unless value.key?("cdi_spec_dirs")

        dirs = value["cdi_spec_dirs"]
        return if dirs.is_a?(Array) && dirs.all? { |dir| dir.is_a?(String) && dir.start_with?("/") }

        raise Error, "rubernetes-agent.dra.cdi_spec_dirs must be a list of absolute paths"
      end

      # kubelet cgroupsPerQOS, enforceNodeAllocatable, systemReservedCgroup
      # and kubeReservedCgroup (ValidateKubeletConfiguration's rules).
      def validate_node_allocatable_enforcement!(process_config)
        if process_config.key?("cgroups_per_qos") && ![true, false].include?(process_config["cgroups_per_qos"])
          raise Error, "rubernetes-agent.cgroups_per_qos must be a boolean"
        end

        %w[system_reserved_cgroup kube_reserved_cgroup].each do |key|
          next unless process_config.key?(key)
          next if process_config[key].is_a?(String) && process_config[key].start_with?("/")

          raise Error, "rubernetes-agent.#{key} must be an absolute cgroup path"
        end
        return unless process_config.key?("enforce_node_allocatable")

        values = process_config["enforce_node_allocatable"]
        allowed = %w[pods system-reserved kube-reserved system-reserved-compressible kube-reserved-compressible none]
        unless values.is_a?(Array) && values.all? { |value| allowed.include?(value) }
          raise Error, "rubernetes-agent.enforce_node_allocatable must be a list of pods, system-reserved, kube-reserved, " \
                       "system-reserved-compressible, kube-reserved-compressible or none"
        end
        if values.include?("none") && values.length > 1
          raise Error,
                "rubernetes-agent.enforce_node_allocatable: none cannot be combined with other values"
        end
        if values.include?("pods") && process_config["cgroups_per_qos"] == false
          raise Error, "rubernetes-agent.enforce_node_allocatable: pods requires cgroups_per_qos"
        end

        # ValidateKubeletConfiguration: a reservation cgroup is required for
        # either enforcement of it, and the two cannot both be asked for.
        {"system-reserved" => "system_reserved_cgroup", "kube-reserved" => "kube_reserved_cgroup",
         "system-reserved-compressible" => "system_reserved_cgroup", "kube-reserved-compressible" => "kube_reserved_cgroup"}.each do |value, key|
          next unless values.include?(value) && !process_config.key?(key)

          raise Error, "rubernetes-agent.#{key} is required when enforce_node_allocatable has #{value}"
        end
        %w[system-reserved kube-reserved].each do |value|
          next unless values.include?(value) && values.include?("#{value}-compressible")

          raise Error, "rubernetes-agent.enforce_node_allocatable: #{value} and #{value}-compressible cannot both be set"
        end
      end

      # kubelet systemReserved / kubeReserved: resource => quantity.
      def validate_reservation!(value, name)
        require_relative "../resource_helpers"
        validate_mapping!(value, "rubernetes-agent.#{name}")
        value.each do |resource, quantity|
          Rubernetes::ResourceHelpers::Quantity.from_json(quantity)
        rescue StandardError
          raise Error, "rubernetes-agent.#{name}.#{resource} must be a quantity"
        end
      end

      def validate_cpu_set!(value, name)
        require_relative "../node/cpu_manager/cpu_set"
        Rubernetes::Node::CPUManager::CPUSet.parse(value.to_s) if value.is_a?(String)
        raise Error, "rubernetes-agent.#{name} must be a CPU list (\"0-3,8\")" unless value.is_a?(String)
      rescue Rubernetes::Node::CPUManager::CPUSet::ParseError
        raise Error, "rubernetes-agent.#{name} must be a CPU list (\"0-3,8\")"
      end

      def validate_string_map!(value, name)
        validate_mapping!(value, name)
        value.each { |key, entry| raise Error, "#{name}.#{key} must be a string" unless entry.is_a?(String) }
      end

      def validate_qos_reserved!(value)
        require_relative "../node/qos_cgroup_manager"
        validate_mapping!(value, "rubernetes-agent.qos_reserved")
        Node::QOSCgroupManager.parse_reserved_memory(value)
      rescue Node::QOSCgroupManager::Error => error
        raise Error, "rubernetes-agent.qos_reserved #{error.message}"
      end

      def validate_memory_qos!(process)
        if process.key?("memory_throttling_factor")
          factor = process["memory_throttling_factor"]
          unless factor.is_a?(Numeric) && factor.positive? && factor <= 1
            raise Error, "rubernetes-agent.memory_throttling_factor must be greater than zero and at most one"
          end
        end
        policy = process.fetch("memory_reservation_policy", "None")
        unless Runtime::MemoryQoS::RESERVATION_POLICIES.include?(policy)
          raise Error, "rubernetes-agent.memory_reservation_policy must be None or TieredReservation"
        end
        return unless policy == Runtime::MemoryQoS::TIERED_RESERVATION && process.dig("feature_gates", "MemoryQoS") != true

        raise Error, "rubernetes-agent.memory_reservation_policy TieredReservation requires MemoryQoS"
      end

      # kubelet cpuManagerPolicy / cpuManagerPolicyOptions / cpuManagerReconcilePeriod.
      def validate_cpu_manager!(value)
        name = "rubernetes-agent.cpu_manager"
        validate_mapping!(value, name)
        unknown = value.keys.map(&:to_s) - AGENT_CPU_MANAGER_KEYS
        raise Error, "#{name} has unknown fields: #{unknown.sort.join(", ")}" unless unknown.empty?
        raise Error, "#{name}.policy must be none or static" if value.key?("policy") && !%w[none static].include?(value["policy"])

        validate_string_map!(value["options"], "#{name}.options") if value.key?("options")
        return unless value.key?("reconcile_period_seconds")
        return if value["reconcile_period_seconds"].is_a?(Numeric) && value["reconcile_period_seconds"].positive?

        raise Error, "#{name}.reconcile_period_seconds must be a positive number"
      end

      # kubelet memoryManagerPolicy / reservedMemory.
      def validate_memory_manager!(value)
        name = "rubernetes-agent.memory_manager"
        validate_mapping!(value, name)
        unknown = value.keys.map(&:to_s) - AGENT_MEMORY_MANAGER_KEYS
        raise Error, "#{name} has unknown fields: #{unknown.sort.join(", ")}" unless unknown.empty?
        raise Error, "#{name}.policy must be None or Static" if value.key?("policy") && !%w[None Static].include?(value["policy"])
        return unless value.key?("reserved_memory")

        entries = value["reserved_memory"]
        raise Error, "#{name}.reserved_memory must be a list" unless entries.is_a?(Array)

        entries.each_with_index do |entry, index|
          path = "#{name}.reserved_memory[#{index}]"
          validate_mapping!(entry, path)
          unless entry["numa_node"].is_a?(Integer) && !entry["numa_node"].negative?
            raise Error,
                  "#{path}.numa_node must be a non-negative integer"
          end

          validate_reservation!(entry.fetch("limits", {}), "memory_manager.reserved_memory[#{index}].limits")
        end
      end

      def validate_shutdown!(value)
        name = "rubernetes-agent.shutdown"
        validate_mapping!(value, name)
        unknown = value.keys.map(&:to_s) - AGENT_SHUTDOWN_KEYS
        raise Error, "#{name} has unknown fields: #{unknown.sort.join(", ")}" unless unknown.empty?

        require_relative "../node/eviction_manager"
        durations = %w[grace_period grace_period_critical_pods].select { |key| value.key?(key) }.to_h do |key|
          [key, Rubernetes::Node::EvictionManager.parse_duration(value[key])]
        rescue StandardError
          raise Error, "#{name}.#{key} must be a duration"
        end
        durations.each do |key, seconds|
          raise Error, "#{name}.#{key} must be either zero or otherwise >= 1 sec" if seconds.positive? && seconds < 1
        end
        if durations.fetch("grace_period_critical_pods", 0) > durations.fetch("grace_period", 0)
          raise Error, "#{name}.grace_period_critical_pods must not be greater than grace_period"
        end
        return unless value.key?("grace_period_by_pod_priority")

        entries = value["grace_period_by_pod_priority"]
        raise Error, "#{name}.grace_period_by_pod_priority must be a list" unless entries.is_a?(Array)
        if !entries.empty? && durations.any? { |_, seconds| seconds.positive? }
          raise Error, "#{name}: grace_period_by_pod_priority cannot be combined with grace_period"
        end

        entries.each_with_index do |entry, index|
          path = "#{name}.grace_period_by_pod_priority[#{index}]"
          validate_mapping!(entry, path)
          raise Error, "#{path}.priority must be an integer" unless entry["priority"].is_a?(Integer)
          next if entry["shutdown_grace_period_seconds"].is_a?(Integer) && !entry["shutdown_grace_period_seconds"].negative?

          raise Error, "#{path}.shutdown_grace_period_seconds must be a non-negative integer"
        end
      end

      # kubelet topologyManagerPolicy / topologyManagerScope / topologyManagerPolicyOptions.
      def validate_topology_manager!(value)
        name = "rubernetes-agent.topology_manager"
        validate_mapping!(value, name)
        unknown = value.keys.map(&:to_s) - AGENT_TOPOLOGY_MANAGER_KEYS
        raise Error, "#{name} has unknown fields: #{unknown.sort.join(", ")}" unless unknown.empty?
        if value.key?("policy") && !%w[none best-effort restricted single-numa-node].include?(value["policy"])
          raise Error, "#{name}.policy must be none, best-effort, restricted or single-numa-node"
        end
        raise Error, "#{name}.scope must be container or pod" if value.key?("scope") && !%w[container pod].include?(value["scope"])

        validate_string_map!(value["options"], "#{name}.options") if value.key?("options")
      end

      def validate_image_staging!(section)
        context = "rubernetes-agent.image"
        validate_mapping!(section, context)
        reject_unknown_keys!(section, %w[staging_root public_blob_source], context)
        section.each { |key, value| validate_absolute_path!(value, "#{context}.#{key}") }
      end

      def validate_image_gc!(value)
        validate_mapping!(value, "rubernetes-agent.image_gc")

        unknown = value.keys.map(&:to_s) - AGENT_IMAGE_GC_KEYS

        raise Error, "rubernetes-agent.image_gc has unknown fields: #{unknown.sort.join(", ")}" unless unknown.empty?

        raise Error, "rubernetes-agent.image_gc.enabled must be a boolean" if value.key?("enabled") && ![true, false].include?(value["enabled"])

        high = value.fetch("high_threshold_percent", 85)

        low = value.fetch("low_threshold_percent", 80)

        [["high_threshold_percent", high], ["low_threshold_percent", low]].each do |key, percent|
          next if percent.is_a?(Integer) && (0..100).cover?(percent)

          raise Error, "rubernetes-agent.image_gc.#{key} must be an integer in range [0-100]"
        end

        raise Error, "rubernetes-agent.image_gc.low_threshold_percent can not be higher than high_threshold_percent" if low > high

        require_relative "../node/eviction_manager"

        %w[minimum_age maximum_age].each do |key|
          Node::EvictionManager.parse_duration(value[key]) if value.key?(key)
        end
      rescue Node::EvictionManager::ConfigError => error
        raise Error, "rubernetes-agent.image_gc: #{error.message}"
      end

      def validate_eviction!(value)
        validate_mapping!(value, "rubernetes-agent.eviction")
        unknown = value.keys.map(&:to_s) - AGENT_EVICTION_KEYS
        raise Error, "rubernetes-agent.eviction has unknown fields: #{unknown.sort.join(", ")}" unless unknown.empty?
        raise Error, "rubernetes-agent.eviction.enabled must be a boolean" if value.key?("enabled") && ![true, false].include?(value["enabled"])

        %w[hard soft soft_grace_period minimum_reclaim].each do |key|
          validate_mapping!(value[key], "rubernetes-agent.eviction.#{key}") if value.key?(key)
        end
        require_relative "../node/eviction_manager"
        Node::EvictionManager.parse_threshold_config(
          hard: value.fetch("hard", Node::EvictionManager::DEFAULT_EVICTION_HARD), soft: value.fetch("soft", {}),
          soft_grace_period: value.fetch("soft_grace_period", {}), minimum_reclaim: value.fetch("minimum_reclaim", {})
        )
        Node::EvictionManager.parse_duration(value["pressure_transition_period"]) if value.key?("pressure_transition_period")
        if value.key?("max_pod_grace_period_seconds") && !value["max_pod_grace_period_seconds"].is_a?(Integer)
          raise Error, "rubernetes-agent.eviction.max_pod_grace_period_seconds must be an integer"
        end
      rescue Node::EvictionManager::ConfigError, Schema::Quantity::ParseError => error
        raise Error, "rubernetes-agent.eviction: #{error.message}"
      end

      # MicroVM backend section (spec/node/runtime.md 5.8.11).
      def validate_microvm!(section)
        raise Error, "rubernetes-agent.microvm must be an object" unless section.is_a?(Hash)

        unknown = section.keys.map(&:to_s) - AGENT_MICROVM_KEYS
        raise Error, "rubernetes-agent.microvm has unknown fields: #{unknown.join(", ")}" unless unknown.empty?
        raise Error, "rubernetes-agent.microvm.enabled must be true or false" if section.key?("enabled") && ![true,
                                                                                                              false].include?(section["enabled"])

        %w[data_dir chroot_base netns_root run_root artifacts_lock].each do |key|
          next unless section.key?(key)

          value = section[key]
          raise Error, "rubernetes-agent.microvm.#{key} must be an absolute path" unless value.is_a?(String) && value.start_with?("/")
        end
        %w[vcpu_count mem_size_mib workspace_mib].each do |key|
          next unless section.key?(key)
          unless section[key].is_a?(Integer) && section[key].positive?
            raise Error,
                  "rubernetes-agent.microvm.#{key} must be a positive integer"
          end
        end
        if section.key?("parent_cgroup") &&
           !(section["parent_cgroup"].is_a?(String) && section["parent_cgroup"].match?(%r{\A[a-zA-Z0-9_./-]+\z}) && !section["parent_cgroup"].start_with?("/"))
          raise Error,
                "rubernetes-agent.microvm.parent_cgroup must be a relative cgroup path"
        end
        return unless section.key?("use_base_snapshot") && ![true, false].include?(section["use_base_snapshot"])

        raise Error, "rubernetes-agent.microvm.use_base_snapshot must be true or false"
      end

      # kubelet imagePullCredentialsVerificationPolicy and
      # preloadedImagesVerificationAllowlist (KubeletEnsureSecretPulledImages).
      def validate_image_pull_credentials!(process_config)
        context = "rubernetes-agent.image_pull_credentials"
        section = process_config["image_pull_credentials"]
        raise Error, "#{context} must be a mapping" unless section.is_a?(Hash)

        reject_unknown_keys!(section, %w[verification_policy preloaded_images_verification_allowlist state_dir], context)
        validate_absolute_path!(section["state_dir"], "#{context}.state_dir") if section.key?("state_dir")
        gates = process_config["feature_gates"].is_a?(Hash) ? process_config["feature_gates"] : {}
        if gates["KubeletEnsureSecretPulledImages"] == false
          raise Error, "#{context} must not be set if KubeletEnsureSecretPulledImages feature gate is not enabled"
        end

        require_relative "../image/pull_records"
        policy = section.fetch("verification_policy", Image::PullRecords::NEVER_VERIFY_PRELOADED).to_s
        unless Image::PullRecords::POLICIES.include?(policy)
          raise Error, "#{context}.verification_policy must be one of #{Image::PullRecords::POLICIES.join(", ")}"
        end

        allowlist = section.fetch("preloaded_images_verification_allowlist", [])
        unless allowlist.is_a?(Array) && allowlist.all?(String)
          raise Error,
                "#{context}.preloaded_images_verification_allowlist must be a list of strings"
        end
        if !allowlist.empty? && policy != Image::PullRecords::NEVER_VERIFY_ALLOWLISTED
          raise Error,
                "#{context}: can't set preloaded_images_verification_allowlist unless verification_policy is NeverVerifyAllowlistedImages"
        end

        Image::PullRecords.parse_allowlist(allowlist)
      rescue Image::PullRecords::InvalidPolicy => error
        raise Error, "#{context}: invalid image pattern in preloaded_images_verification_allowlist: #{error.message}"
      end

      # kubelet validates maxContainerRestartPeriod after truncating to
      # whole milliseconds, from 1000 through 300000 inclusive.
      def validate_crash_loop_back_off!(process)
        section = process["crash_loop_back_off"]
        raise Error, "rubernetes-agent.crash_loop_back_off must be a mapping" unless section.is_a?(Hash)

        reject_unknown_keys!(section, %w[max_container_restart_period_seconds], "rubernetes-agent.crash_loop_back_off")
        value = section["max_container_restart_period_seconds"]
        return if value.nil?

        if process.dig("feature_gates", "KubeletCrashLoopBackOffMax") == false
          raise Error, "rubernetes-agent.crash_loop_back_off.max_container_restart_period_seconds requires KubeletCrashLoopBackOffMax"
        end
        return if value.is_a?(Numeric) && value >= 1 && value < 300.001

        raise Error, "rubernetes-agent.crash_loop_back_off.max_container_restart_period_seconds must be between 1 and 300"
      end

      def validate_runtime_classes!(section)
        unless section.is_a?(Hash) && section.all? do |name, handler|
          name.is_a?(String) && handler.is_a?(String) && !name.empty? && !handler.empty?
        end
          raise Error,
                "rubernetes-agent.runtime_classes must be an object of name => handler"
        end
      end

      def validate_control_plane!(process_config, allowed_keys, process_name, lease: false)
        reject_unknown_keys!(process_config, allowed_keys, "#{process_name} configuration")
        if process_config.key?("feature_gates")
          gates = process_config["feature_gates"]
          validate_mapping!(gates, "#{process_name}.feature_gates")
          gates.each do |gate, enabled|
            raise Error, "#{process_name}.feature_gates.#{gate} must be true or false" unless [true, false].include?(enabled)
          end
          validate_feature_gate_dependencies!(gates, "#{process_name}.feature_gates")
        end
        validate_api_rate!(process_config, process_name)
        validate_api_server!(process_config["api_server"], context: "#{process_name}.api_server") if process_config.key?("api_server")
        %w[kubeconfig context identity].each do |key|
          next unless process_config.key?(key) && !process_config[key].nil?

          validate_non_empty_string!(process_config[key], "#{process_name}.#{key}")
        end
        validate_sync!(process_config["sync"], process_name) if process_config.key?("sync")
        validate_lease!(process_config["lease"], process_name) if lease && process_config.key?("lease")
        validate_resource_kinds!(process_config["resource_kinds"], process_name) if process_config.key?("resource_kinds")
        validate_controllers!(process_config["controllers"], process_name) if process_config.key?("controllers")
        validate_serving!(process_config["serving"], process_name) if process_config.key?("serving")
        validate_extensions!(process_config["extensions"], process_name) if process_config.key?("extensions")
      end

      def validate_hostpath_provisioner!(process_config)
        context = "rubernetes-controller-manager"
        if process_config.key?("enable_hostpath_provisioner") && ![true, false].include?(process_config["enable_hostpath_provisioner"])
          raise Error, "#{context}.enable_hostpath_provisioner must be true or false"
        end
        return unless process_config.key?("hostpath_provisioner_root")

        path = process_config["hostpath_provisioner_root"]
        validate_absolute_path!(path, "#{context}.hostpath_provisioner_root")
        raise Error, "#{context}.hostpath_provisioner_root must be a dedicated directory" if File.expand_path(path) == "/"
      end

      def validate_node_ipam!(section)
        NodeIPAMSettings.new(section)
      rescue ArgumentError => error
        raise Error, "rubernetes-controller-manager.node_ipam #{error.message}"
      end

      def validate_feature_gate_dependencies!(gates, context)
        GATE_DEPENDENCIES.each do |gate, dependencies|
          next unless gates[gate] == true

          dependencies.each do |dependency, default_enabled|
            next if gates.fetch(dependency, default_enabled) == true

            raise Error, "#{context}.#{gate} requires #{dependency}"
          end
        end
      end

      def validate_load_balancer!(process_config)
        context = "rubernetes-controller-manager"
        cloud_manager = process_config["cloud_controller_manager"]
        raise Error, "#{context}.cloud_controller_manager must be external" if process_config.key?("cloud_controller_manager") && cloud_manager != "external"

        default_routed = process_config.fetch("default_routed_load_balancer", false)
        raise Error, "#{context}.default_routed_load_balancer must be true or false" unless [true, false].include?(default_routed)
        raise Error, "#{context}.default_routed_load_balancer requires load_balancer_pool" if default_routed && !process_config.key?("load_balancer_pool")

        if default_routed && cloud_manager == "external"
          raise Error, "#{context}.default_routed_load_balancer conflicts with cloud_controller_manager: external"
        end
        return unless process_config.key?("load_balancer_pool")

        Network::LoadBalancerPool.new(process_config["load_balancer_pool"])
        controllers = Array(process_config["controllers"])
        if !controllers.empty? && !controllers.include?("service-lb-controller")
          raise Error, "rubernetes-controller-manager.load_balancer_pool requires service-lb-controller"
        end
      rescue ArgumentError => error
        raise Error, "rubernetes-controller-manager: #{error.message}"
      end

      def validate_cluster_signing!(section)
        context = "rubernetes-controller-manager.cluster_signing"
        raise Error, "#{context} must be a mapping" unless section.is_a?(Hash)

        reject_unknown_keys!(section, CLUSTER_SIGNING_KEYS, context)
        validate_signing_pair!(section, context) if section.key?("cert_file") || section.key?("key_file")
        if section.key?("duration_seconds") && !(section["duration_seconds"].is_a?(Integer) && section["duration_seconds"].positive?)
          raise Error, "#{context}.duration_seconds must be a positive integer"
        end
        return unless section.key?("signers")

        signers = section["signers"]
        raise Error, "#{context}.signers must be a mapping" unless signers.is_a?(Hash)

        reject_unknown_keys!(signers, CLUSTER_SIGNING_SIGNERS, "#{context}.signers")
        signers.each do |name, files|
          raise Error, "#{context}.signers.#{name} must be a mapping" unless files.is_a?(Hash)

          reject_unknown_keys!(files, %w[cert_file key_file], "#{context}.signers.#{name}")
          validate_signing_pair!(files, "#{context}.signers.#{name}")
        end
        # Upstream refuses the default pair together with per-signer files.
        return unless section.key?("cert_file") && !signers.empty?

        raise Error, "#{context}: cert_file/key_file cannot be combined with signers"
      end

      def validate_signing_pair!(section, context)
        %w[cert_file key_file].each do |key|
          raise Error, "#{context}.#{key} is required with the other signing file" unless section.key?(key)

          validate_absolute_path!(section[key], "#{context}.#{key}")
        end
      end

      def validate_serving!(section, process_name, keys: SERVING_KEYS)
        raise Error, "#{process_name}.serving must be a mapping" unless section.is_a?(Hash)

        reject_unknown_keys!(section, keys, "#{process_name}.serving")
        raise Error, "#{process_name}.serving.enabled must be true or false" if section.key?("enabled") && ![true, false].include?(section["enabled"])

        validate_non_empty_string!(section["bind_address"], "#{process_name}.serving.bind_address") if section.key?("bind_address")
        port = section["port"]
        return unless section["enabled"] == true && !(port.is_a?(Integer) && port.between?(1, 65_535))

        raise Error, "#{process_name}.serving.port must be an integer between 1 and 65535"
      end

      def validate_sync!(value, process_name)
        validate_mapping!(value, "#{process_name}.sync")
        reject_unknown_keys!(value, CONTROL_PLANE_SYNC_KEYS, "#{process_name}.sync")
        CONTROL_PLANE_SYNC_KEYS.each do |key|
          validate_positive_number!(value[key], "#{process_name}.sync.#{key}") if value.key?(key)
        end
      end

      def validate_lease!(value, process_name)
        validate_mapping!(value, "#{process_name}.lease")
        reject_unknown_keys!(value, CONTROL_PLANE_LEASE_KEYS, "#{process_name}.lease")
        %w[namespace name].each do |key|
          validate_non_empty_string!(value[key], "#{process_name}.lease.#{key}") if value.key?(key)
        end
        %w[lease_duration_seconds renew_deadline_seconds retry_period_seconds].each do |key|
          validate_positive_number!(value[key], "#{process_name}.lease.#{key}") if value.key?(key)
        end
      end

      def validate_resource_kinds!(value, process_name)
        return if value.is_a?(Array) && value.all? { |kind| kind.is_a?(String) && !kind.empty? }

        raise Error, "#{process_name}.resource_kinds must be an array of non-empty strings"
      end

      def validate_controllers!(value, process_name)
        unless value.is_a?(Array) && !value.empty? && value.all? { |name| name.is_a?(String) && !name.empty? }
          raise Error, "#{process_name}.controllers must be a non-empty array of controller names"
        end
        raise Error, "#{process_name}.controllers must not contain duplicates" unless value.uniq.length == value.length
      end

      def validate_network!(value, context)
        validate_mapping!(value, context)
        reject_unknown_keys!(value, NETWORK_KEYS, context)
        value.slice("state_path", "policy_kubeconfig").each { |name, path| validate_absolute_path!(path, "#{context}.#{name}") }
        validate_positive_integer!(value["mtu"], "#{context}.mtu") if value.key?("mtu")
        raise Error, "#{context}.fsync must be true or false" if value.key?("fsync") && ![true, false].include?(value["fsync"])
        if value.key?("policy_backend") && !NETWORK_POLICY_BACKENDS.include?(value["policy_backend"].to_s.downcase)
          raise Error, "#{context}.policy_backend must be one of #{NETWORK_POLICY_BACKENDS.join(", ")}"
        end

        validate_non_empty_string!(value["policy_table"], "#{context}.policy_table") if value.key?("policy_table")
        raise Error, "#{context}.plugin must be one of #{NETWORK_PLUGINS.join(", ")}" if value.key?("plugin") && !NETWORK_PLUGINS.include?(value["plugin"])
        return unless value.key?("cni")

        validate_mapping!(value["cni"], "#{context}.cni")
        reject_unknown_keys!(value["cni"], NETWORK_CNI_KEYS, "#{context}.cni")
        validate_absolute_path!(value["cni"]["conf_dir"], "#{context}.cni.conf_dir") if value["cni"].key?("conf_dir")
        Array(value["cni"]["bin_dirs"]).each { |directory| validate_absolute_path!(directory, "#{context}.cni.bin_dirs") }
      end

      def validate_volume!(value, context)
        validate_mapping!(value, context)
        reject_unknown_keys!(value, VOLUME_KEYS, context)
        %w[data_dir root].each do |key|
          validate_absolute_path!(value[key], "#{context}.#{key}") if value.key?(key)
        end
        raise Error, "#{context}.fsync must be true or false" if value.key?("fsync") && ![true, false].include?(value["fsync"])
        raise Error, "#{context}.profile must be one of #{VOLUME_PROFILES.join(", ")}" if value.key?("profile") && !value["profile"].is_a?(String)
        if value.key?("profile") && !VOLUME_PROFILES.include?(value["profile"].downcase.tr("-", "_"))
          raise Error, "#{context}.profile must be one of #{VOLUME_PROFILES.join(", ")}"
        end

        validate_volume_csi!(value["csi"], "#{context}.csi") if value.key?("csi")
      end

      def validate_volume_csi!(value, context)
        validate_mapping!(value, context)
        reject_unknown_keys!(value, VOLUME_CSI_KEYS, context)
        socket = value.fetch("socket") { raise Error, "#{context}.socket is required" }
        normalized_socket = socket.to_s.delete_prefix("unix://")
        validate_absolute_path!(normalized_socket, "#{context}.socket")
        raise Error, "#{context}.socket exceeds the Unix socket limit" if normalized_socket.bytesize >= 108

        validate_positive_number!(value["timeout"], "#{context}.timeout") if value.key?("timeout")
        %w[socket_uid socket_gid peer_uid peer_gid].each do |key|
          validate_linux_identity!(value[key], "#{context}.#{key}") if value.key?(key)
        end
        validate_file_mode!(value["socket_mode"], "#{context}.socket_mode") if value.key?("socket_mode")
        raise Error, "#{context}.probe must be true or false" if value.key?("probe") && ![true, false].include?(value["probe"])
        return unless value.key?("identity")

        identity = value["identity"]
        validate_mapping!(identity, "#{context}.identity")
        reject_unknown_keys!(identity, VOLUME_CSI_IDENTITY_KEYS, "#{context}.identity")
        raise Error, "#{context}.identity.name is required" unless identity.key?("name")

        validate_non_empty_string!(identity["name"], "#{context}.identity.name")
        %w[vendor_version vendorVersion].each do |key|
          validate_non_empty_string!(identity[key], "#{context}.identity.#{key}") if identity.key?(key)
        end
      end

      def validate_api_server!(value, context: "rubernetes-agent.api_server")
        validate_non_empty_string!(value, context)
        uri = URI.parse(value)
        unless %w[http https].include?(uri.scheme) && uri.host && uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
          raise Error, "#{context} must be an http(s) URL without credentials or query"
        end
      rescue URI::InvalidURIError => error
        raise Error.new("#{context} is not a valid URL: #{error.message}"), cause: error
      end

      def validate_console!(section)
        validate_mapping!(section, "console")
        reject_unknown_keys!(section, CONSOLE_KEYS, "console")
        validate_absolute_path!(section["socket"], "console.socket")
      end

      def validate_extensions!(section, process_name)
        validate_mapping!(section, "#{process_name}.extensions")
        reject_unknown_keys!(section, EXTENSIONS_KEYS, "#{process_name}.extensions")
        return if !section.key?("enabled") || [true, false].include?(section["enabled"])

        raise Error, "#{process_name}.extensions.enabled must be true or false"
      end

      def validate_apiserver!(process_config)
        reject_unknown_keys!(process_config, APISERVER_KEYS, "rubernetes-apiserver configuration")
        validate_extensions!(process_config["extensions"], "rubernetes-apiserver") if process_config.key?("extensions")
        if process_config.key?("encryption_config_file")
          validate_absolute_path!(process_config["encryption_config_file"],
                                  "rubernetes-apiserver.encryption_config_file")
        end
        if process_config.key?("egress_selector_config_file")
          validate_absolute_path!(process_config["egress_selector_config_file"],
                                  "rubernetes-apiserver.egress_selector_config_file")
        end
        if process_config.key?("encryption_config_reload_interval_seconds")
          validate_positive_integer!(process_config["encryption_config_reload_interval_seconds"],
                                     "rubernetes-apiserver.encryption_config_reload_interval_seconds")
        end
        address = process_config["bind_address"]
        raise Error, "rubernetes-apiserver.bind_address must be a non-empty String" unless address.is_a?(String) && !address.empty?

        port = process_config["port"]
        raise Error, "rubernetes-apiserver.port must be between 0 and 65535" unless port.is_a?(Integer) && port.between?(0, 65_535)

        if process_config.key?("service_cluster_ip_range")
          ranges = process_config["service_cluster_ip_range"]
          ranges = [ranges] if ranges.is_a?(String)
          unless ranges.is_a?(Array) && !ranges.empty? && ranges.all? { |cidr| cidr.is_a?(String) && cidr.include?("/") }
            raise Error, "rubernetes-apiserver.service_cluster_ip_range must be a CIDR or a list of CIDRs"
          end
        end
        if process_config.key?("node_port_range")
          value = process_config["node_port_range"]
          unless value.is_a?(String) && value.match?(/\A\d+-\d+\z/) && value.split("-").map(&:to_i).then do |lo, hi|
            lo.between?(1, 65_535) && hi.between?(lo, 65_535)
          end
            raise Error, "rubernetes-apiserver.node_port_range must be like 30000-32767"
          end
        end
        if process_config.key?("advertise_address")
          validate_non_empty_string!(process_config["advertise_address"],
                                     "rubernetes-apiserver.advertise_address")
        end
        max_body_bytes = process_config["max_body_bytes"]
        unless max_body_bytes.is_a?(Integer) && max_body_bytes.between?(1, 16 * 1024 * 1024)
          raise Error, "rubernetes-apiserver.max_body_bytes must be between 1 and 16777216"
        end

        validate_datastore!(process_config["datastore"]) if process_config.key?("datastore")
        history_limit = process_config["watch_history_limit"]
        policy = process_config.fetch("datastore", {}).fetch("history_retention_policy", Storage::MemoryStore::DEFAULT_HISTORY_POLICY)
        if policy == Storage::MemoryStore::LONGER_HISTORY_POLICY
          unless history_limit.nil? || (history_limit.is_a?(Integer) && history_limit.between?(0, 1_000_000))
            raise Error, "rubernetes-apiserver.watch_history_limit must be null or between 0 and 1000000"
          end
        elsif !history_limit.is_a?(Integer) || !history_limit.between?(1, 1_000_000)
          raise Error, "rubernetes-apiserver.watch_history_limit must be between 1 and 1000000"
        end

        validate_tls!(process_config["tls"]) if process_config.key?("tls")
        validate_tls!(process_config["proxy_client"], "rubernetes-apiserver.proxy_client") if process_config.key?("proxy_client")
        validate_kubelet_client!(process_config["kubelet_client"]) if process_config.key?("kubelet_client")
        validate_security!(process_config["security"]) if process_config.key?("security")
        validate_peer_proxy!(process_config)
        return unless process_config.key?("runtime_config")

        validate_mapping!(process_config["runtime_config"], "rubernetes-apiserver.runtime_config")
        process_config["runtime_config"].each do |key, value|
          raise Error, "rubernetes-apiserver.runtime_config.#{key} must be a boolean" unless [true, false].include?(value)
          unless key == "api/all" || key.match?(%r{\A[a-z0-9.-]*/?v\d+[a-z0-9]*\z})
            raise Error,
                  "rubernetes-apiserver.runtime_config key #{key.inspect} must be api/all or group/version"
          end
        end
      end

      def validate_peer_proxy!(config)
        gates = config.dig("security", "feature_gates") || {}
        enabled = gates.fetch("UnknownVersionInteroperabilityProxy", true)
        raise Error, "UnknownVersionInteroperabilityProxy requires APIServerIdentity" if enabled && gates["APIServerIdentity"] == false

        flags = %w[peer_ca_file peer_advertise_ip peer_advertise_port]
        return if flags.none? { |flag| config.key?(flag) }
        raise Error, "peer proxy configuration requires UnknownVersionInteroperabilityProxy" unless enabled

        if config.key?("peer_advertise_ip")
          address = config["peer_advertise_ip"]
          unless address.is_a?(String) && !address.include?("/") && IPAddr.new(address).to_i.positive?
            raise Error, "rubernetes-apiserver.peer_advertise_ip must be an IP address"
          end
        end
        if config.key?("peer_advertise_port")
          port = config["peer_advertise_port"]
          raise Error, "rubernetes-apiserver.peer_advertise_port must be between 1 and 65535" unless port.is_a?(Integer) && port.between?(1, 65_535)
        end
        return unless config.key?("peer_ca_file")

        validate_absolute_path!(config["peer_ca_file"], "rubernetes-apiserver.peer_ca_file")
        unless config["tls"] && config["proxy_client"] && config.dig("security", "authentication", "request_header")
          raise Error, "rubernetes-apiserver.peer_ca_file requires serving TLS, proxy_client, and request_header authentication"
        end
      rescue IPAddr::InvalidAddressError
        raise Error, "rubernetes-apiserver.peer_advertise_ip must be an IP address"
      end

      # --kubelet-client-certificate / --kubelet-client-key and
      # --kubelet-certificate-authority.
      def validate_kubelet_client!(value)
        context = "rubernetes-apiserver.kubelet_client"
        validate_mapping!(value, context)
        reject_unknown_keys!(value, %w[cert_file key_file ca_file], context)
        %w[cert_file key_file].each { |key| validate_absolute_path!(value[key], "#{context}.#{key}") }
        validate_absolute_path!(value["ca_file"], "#{context}.ca_file") if value.key?("ca_file")
      end

      def validate_tls!(value, context = "rubernetes-apiserver.tls")
        validate_mapping!(value, context)
        reject_unknown_keys!(value, TLS_KEYS, context)
        %w[cert_file key_file].each { |key| validate_absolute_path!(value[key], "#{context}.#{key}") }
      end

      # security: authentication / authorization / admission / audit /
      # flow_control / feature_gates.  Every file is an absolute path; modes
      # must be in the v1.36.2 authorization-mode corpus.
      # datastore: {type: memory} (default) or {type: raft, node_id:, cluster_id:,
      # data_dir:, pki_dir:, listen_address:, listen_port:, voters: [...],
      # peers: {id => "host:port"}}.  Raft parameters are fixed by the
      # specification; `timing` may only be given to scale them uniformly in
      # tests and is validated by Consensus::Node::Timing.
      def validate_datastore!(value)
        context = "rubernetes-apiserver.datastore"
        validate_mapping!(value, context)
        reject_unknown_keys!(value, DATASTORE_KEYS, context)
        validate_datastore_retention!(value, context)
        type = value["type"] || "memory"
        raise Error, "#{context}.type must be one of #{DATASTORE_TYPES.join(", ")}" unless DATASTORE_TYPES.include?(type)
        return if type == "memory"

        %w[node_id cluster_id].each do |key|
          identifier = value[key]
          unless identifier.is_a?(String) && identifier.match?(/\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/)
            raise Error,
                  "#{context}.#{key} must match [A-Za-z0-9][A-Za-z0-9._-]*"
          end
        end
        %w[data_dir pki_dir].each { |key| validate_absolute_path!(value[key], "#{context}.#{key}") }
        validate_non_empty_string!(value["listen_address"], "#{context}.listen_address")
        port = value["listen_port"]
        raise Error, "#{context}.listen_port must be between 0 and 65535" unless port.is_a?(Integer) && port.between?(0, 65_535)

        voters = value["voters"]
        unless voters.is_a?(Array) && !voters.empty? && voters.all? do |id|
          id.is_a?(String) && !id.empty?
        end
          raise Error,
                "#{context}.voters must be a non-empty list of node ids"
        end
        # A node joining a running cluster starts as nobody's voter: it
        # names the cluster's voters and waits to be taken in.
        raise Error, "#{context}.join must be true or false" if value.key?("join") && ![true, false].include?(value["join"])

        member = voters.include?(value["node_id"]) || value["join"] == true
        raise Error, "#{context}.voters must include node_id #{value["node_id"]}" unless member
        raise Error, "#{context}.voters must be unique" unless voters.uniq.length == voters.length

        peers = value["peers"] || {}
        validate_mapping!(peers, "#{context}.peers")
        peers.each do |id, address|
          unless id.is_a?(String) && address.is_a?(String) && address.match?(/\A.+:\d{1,5}\z/)
            raise Error,
                  "#{context}.peers[#{id}] must be host:port"
          end
          raise Error, "#{context}.peers must not include node_id" if id == value["node_id"]
        end
        (voters - [value["node_id"]]).each do |id|
          raise Error, "#{context}.peers must include an address for voter #{id}" unless peers.key?(id)
        end
        timing = value["timing"]
        return if timing.nil?

        validate_mapping!(timing, "#{context}.timing")
        reject_unknown_keys!(timing, DATASTORE_TIMING_KEYS, "#{context}.timing")
        timing.each { |key, number| validate_positive_number!(number, "#{context}.timing.#{key}") }
      end

      def validate_datastore_retention!(datastore, context)
        policy = datastore.fetch("history_retention_policy", Storage::MemoryStore::DEFAULT_HISTORY_POLICY)
        policies = Storage::MemoryStore::DEFAULT_HISTORY_SECONDS_BY_POLICY.keys
        raise Error, "#{context}.history_retention_policy must be one of #{policies.join(", ")}" unless policies.include?(policy)
        return unless policy == Storage::MemoryStore::LONGER_HISTORY_POLICY

        seconds = datastore["compaction_interval_seconds"]
        return if seconds.nil?

        duration = Float(seconds, exception: false)
        return if duration&.finite? && !duration.negative?

        raise Error, "#{context}.compaction_interval_seconds must be null or a finite non-negative number"
      end

      def reject_unknown_keys!(mapping, allowed, context)
        unknown = mapping.keys - allowed
        raise Error, "unknown #{context} keys: #{unknown.sort.join(", ")}" unless unknown.empty?
      end

      def deep_freeze(value) = ObjectTree.deep_freeze(value, nested_keys: false)
    end
  end
end
