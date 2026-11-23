# frozen_string_literal: true

require "stringio"
require "tmpdir"
require "yaml"
require_relative "../test_helper"
require "rubernetes/bootstrap/cli"

class KubeletComponentConfigTest < Minitest::Test
  Config = Rubernetes::Bootstrap::Config
  CLI = Rubernetes::Bootstrap::CLI
  AGENT = "rubernetes-agent"

  def setup
    @directory = Dir.mktmpdir("kubelet-config")
    @native = File.join(@directory, "agent.yml")
    @component = File.join(@directory, "kubelet-config")
    File.write(@native, YAML.dump({"processes" => {AGENT => {
                                    "file_check_frequency_seconds" => 17,
                                    "static_pod_path" => "/var/lib/native/manifests",
                                    "node_name" => "native-worker",
                                    "sync" => {"watch_timeout_seconds" => 12},
                                    "streaming" => {"authorization" => {"mode" => "Webhook"}}
                                  }}}))
  end

  def teardown = FileUtils.remove_entry(@directory)

  def test_direct_kubelet_configuration_uses_the_same_config_entrypoint
    write_component("fileCheckFrequency" => "1m2.5s", "staticPodPath" => "manifests", "healthzPort" => 0)
    config = Config.load(process_name: AGENT, path: @component)

    assert_in_delta(62.5, config.process["file_check_frequency_seconds"])
    assert_equal File.join(@directory, "manifests"), config.process["static_pod_path"]
    assert_equal 0, config.process["healthz_port"]
    assert_predicate config.process, :frozen?
    assert_empty config.kubelet_read_only_fields
  end

  def test_overlay_only_overrides_mapped_settings_and_leaves_rubernetes_wiring
    write_component("fileCheckFrequency" => "30s", "staticPodPath" => "", "cgroupsPerQOS" => false,
                    "syncFrequency" => "1m30s", "cgroupDriver" => "cgroupfs", "clusterDNS" => ["192.0.2.11"])
    config = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)

    assert_equal "native-worker", config.process["node_name"]
    assert_equal 30, config.process["file_check_frequency_seconds"]
    assert_nil config.process["static_pod_path"]
    assert_equal false, config.process["cgroups_per_qos"]
    assert_equal({"period_seconds" => 90, "watch_timeout_seconds" => 12}, config.process["sync"])
    assert_equal ["192.0.2.11"], config.process.dig("dns", "cluster_dns")
    assert_equal "Webhook", config.process.dig("streaming", "authorization", "mode")
    assert_equal ["cgroupDriver"], config.kubelet_read_only_fields
    assert_equal 17, Config.load(process_name: AGENT, path: @native).process["file_check_frequency_seconds"]
  end

  def test_empty_resolver_path_and_cluster_domain_round_trip
    write_component("resolvConf" => "", "clusterDomain" => "")
    config = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)

    assert_equal "", config.process.dig("dns", "resolv_conf")
    assert_equal "", config.process.fetch("cluster_domain")
    assert_equal ["", ""], configz(config.process).values_at("resolvConf", "clusterDomain")
  end

  def test_restart_period_accepts_fractional_upper_boundary_and_preserves_its_precision
    write_component("crashLoopBackOff" => {"maxContainerRestartPeriod" => "300s999999ns"})
    config = Config.load(process_name: AGENT, path: @component)

    assert_in_delta 300.000999999, config.process.dig("crash_loop_back_off", "max_container_restart_period_seconds"), 1e-10
    assert_equal "5m0.000999999s", configz(config.process).dig("crashLoopBackOff", "maxContainerRestartPeriod")

    %w[999ms999999ns 300s1ms].each do |invalid|
      write_component("crashLoopBackOff" => {"maxContainerRestartPeriod" => invalid})
      error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

      assert_match(/max_container_restart_period_seconds must be between 1 and 300/, error.message)
    end
  end

  def test_declared_empty_restart_period_uses_the_feature_gate_default_over_a_native_override
    File.write(@native, YAML.dump({"processes" => {AGENT => {
                                    "crash_loop_back_off" => {"max_container_restart_period_seconds" => 9}
                                  }}}))

    write_component("clusterDomain" => "cluster.local")
    config = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)

    assert_equal({"maxContainerRestartPeriod" => "9s"}, configz(config.process).fetch("crashLoopBackOff"))

    {true => {"maxContainerRestartPeriod" => "5m0s"}, false => {}}.each do |enabled, expected|
      write_component("crashLoopBackOff" => {}, "featureGates" => {"KubeletCrashLoopBackOffMax" => enabled})
      config = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)

      assert_nil config.process.dig("crash_loop_back_off", "max_container_restart_period_seconds")
      assert_equal expected, configz(config.process).fetch("crashLoopBackOff")
    end
  end

  def test_image_pull_concurrency_defaults_and_round_trips
    cases = [[{}, true, nil], [{"maxParallelImagePulls" => 1}, true, 1], [{"maxParallelImagePulls" => 2}, false, 2],
             [{"serializeImagePulls" => false}, false, nil],
             [{"serializeImagePulls" => true, "maxParallelImagePulls" => 1}, true, 1],
             [{"serializeImagePulls" => false, "maxParallelImagePulls" => 1}, false, 1],
             [{"serializeImagePulls" => false, "maxParallelImagePulls" => 2_147_483_647}, false, 2_147_483_647]]
    cases.each do |fields, serial, maximum|
      write_component(fields)
      process = Config.load(process_name: AGENT, path: @component).process
      expected = {"serializeImagePulls" => serial, "maxParallelImagePulls" => maximum}.compact

      assert_equal expected, configz(process).slice("serializeImagePulls", "maxParallelImagePulls")
    end
  end

  def test_image_pull_concurrency_invalid_settings_are_rejected
    [{"maxParallelImagePulls" => 0}, {"maxParallelImagePulls" => -1}, {"maxParallelImagePulls" => 2_147_483_648},
     {"maxParallelImagePulls" => "2"}, {"serializeImagePulls" => "false"},
     {"serializeImagePulls" => true, "maxParallelImagePulls" => 2}].each do |fields|
      write_component(fields)

      assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }
    end
  end

  def test_image_pull_concurrency_overlay_can_reset_both_settings
    File.write(@native, YAML.dump({"processes" => {AGENT => {"serialize_image_pulls" => false, "max_parallel_image_pulls" => 3}}}))
    write_component("serializeImagePulls" => nil, "maxParallelImagePulls" => nil)
    process = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component).process

    assert_equal({"serializeImagePulls" => true}, configz(process).slice("serializeImagePulls", "maxParallelImagePulls"))
  end

  def test_cpu_quota_config_default_and_custom_period_keep_wire_precision
    cases = [[{}, true, "100ms"], [{"cpuCFSQuota" => false, "cpuCFSQuotaPeriod" => "17ms123456ns"}, false, "17.123456ms"],
             [{"cpuCFSQuotaPeriod" => "1ms"}, true, "1ms"], [{"cpuCFSQuotaPeriod" => "1s"}, true, "1s"],
             [{"cpuCFSQuotaPeriod" => "100ms", "featureGates" => {"CustomCPUCFSQuotaPeriod" => false}}, true, "100ms"]]
    cases.each do |fields, enabled, period|
      write_component(fields)
      process = Config.load(process_name: AGENT, path: @component).process

      assert_equal [enabled, period], configz(process).values_at("cpuCFSQuota", "cpuCFSQuotaPeriod")
    end
  end

  def test_cpu_quota_config_rejects_invalid_values_and_period_with_disabled_gate
    %w[999999ns 1s1ns 0].each do |period|
      write_component("cpuCFSQuotaPeriod" => period)
      error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

      assert_match(/between 1ms and 1s/, error.message)
    end

    write_component("cpuCFSQuotaPeriod" => "10ms", "featureGates" => {"CustomCPUCFSQuotaPeriod" => false})
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/requires feature gate CustomCPUCFSQuotaPeriod/, error.message)

    write_component("cpuCFSQuota" => "false")
    assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }
  end

  def test_single_process_oom_kill_is_nullable_and_round_trips
    skip "cgroup v2 required" unless File.file?("/sys/fs/cgroup/cgroup.controllers")

    [{}, {"singleProcessOOMKill" => nil}, {"singleProcessOOMKill" => true}, {"singleProcessOOMKill" => false}].each do |fields|
      write_component(fields)
      process = Config.load(process_name: AGENT, path: @component).process

      assert_equal fields.compact, configz(process).slice("singleProcessOOMKill")
    end
    native = YAML.safe_load_file(@native)
    native.fetch("processes").fetch(AGENT)["single_process_oom_kill"] = true
    File.write(@native, YAML.dump(native))
    write_component("singleProcessOOMKill" => nil)
    process = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component).process

    refute configz(process).key?("singleProcessOOMKill")
  end

  def test_single_process_oom_kill_rejects_non_boolean_values
    write_component("singleProcessOOMKill" => "false")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/single_process_oom_kill must be a boolean or null/, error.message)
  end

  def test_node_limits_round_trip_as_v1beta1_integers
    defaults = configz(Config.load(process_name: AGENT, path: @native).process)

    assert_equal 50, defaults.fetch("nodeStatusMaxImages")
    refute defaults.key?("podsPerCore")

    [[1, 2], [-1, 2_147_483_647], [0, 0]].each do |images, per_core|
      write_component("nodeStatusMaxImages" => images, "podsPerCore" => per_core)
      config = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)
      reported = configz(config.process)

      assert_equal [images, per_core], config.process.values_at("node_status_max_images", "pods_per_core")
      assert_equal images, reported.fetch("nodeStatusMaxImages")
      assert_equal per_core, reported.fetch("podsPerCore", 0)
      refute reported.key?("podsPerCore") if per_core.zero?
    end
  end

  def test_node_limits_reject_out_of_range_and_non_integer_values
    {"nodeStatusMaxImages" => ["node_status_max_images", -2], "podsPerCore" => ["pods_per_core", -1]}.each do |field, (native, invalid)|
      [invalid, 2_147_483_648, "1", 1.0, false].each do |value|
        write_component(field => value)
        error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

        assert_match(/^rubernetes-agent\.#{native} must be an integer/, error.message)
      end
    end
  end

  def test_unknown_or_changed_readback_only_values_are_rejected
    write_component("experimentalAccidentalKey" => false, "cgroupDriver" => "systemd")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component) }

    assert_match(/unsupported KubeletConfiguration settings: cgroupDriver, experimentalAccidentalKey/, error.message)

    write_component("authorization" => {"mode" => "AlwaysAllow"})
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component) }

    assert_match(/unsupported KubeletConfiguration settings: authorization/, error.message)
  end

  def test_certificate_files_and_rotation_gates_round_trip
    gates = {"ReloadKubeletClientCAFile" => true, "ReloadKubeletServerCertificateFile" => false,
             "RotateKubeletServerCertificate" => false}
    write_component("tlsCertFile" => "serving.crt", "tlsPrivateKeyFile" => "serving.key",
                    "authentication" => {"x509" => {"clientCAFile" => "ca.crt"}}, "featureGates" => gates)
    config = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)
    reported = configz(config.process)

    assert_equal [File.join(@directory, "serving.crt"), File.join(@directory, "serving.key")],
                 reported.values_at("tlsCertFile", "tlsPrivateKeyFile")
    assert_equal File.join(@directory, "ca.crt"), reported.dig("authentication", "x509", "clientCAFile")
    assert_equal gates, reported["featureGates"]
    assert_equal "Webhook", reported.dig("authorization", "mode")
  end

  def test_certificate_settings_require_a_serving_pair_and_preserve_authentication
    write_component("tlsCertFile" => "serving.crt")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component) }
    assert_match(/requires both tlsCertFile and tlsPrivateKeyFile/, error.message)

    write_component("tlsCertFile" => "serving.crt", "tlsPrivateKeyFile" => "serving.key",
                    "authentication" => {"x509" => {"clientCAFile" => "ca.crt"}, "anonymous" => {"enabled" => true}})
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component) }

    assert_match(/unsupported KubeletConfiguration settings: authentication/, error.message)
  end

  def test_rejects_invalid_durations_and_uses_normal_agent_validation
    write_component("fileCheckFrequency" => "1malformed30s")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/fileCheckFrequency must be a non-negative Go duration/, error.message)

    write_component("fileCheckFrequency" => "0s")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/file_check_frequency_seconds must be a positive number/, error.message)

    write_component("healthzBindAddress" => "192.0.2.18")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/healthz_bind_address must be a loopback IP address/, error.message)
  end

  def test_readback_emits_valid_duration_strings_for_loaded_settings
    write_component("fileCheckFrequency" => "750us", "httpCheckFrequency" => "1.000001234s",
                    "evictionSoft" => {"nodefs.available" => "15%"},
                    "evictionSoftGracePeriod" => {"nodefs.available" => "1m2.5s"})
    config = Config.load(process_name: AGENT, path: @component)
    reported = Rubernetes::Node::KubeletConfigz.build(config.process).fetch("kubeletconfig")

    assert_equal "750µs", reported["fileCheckFrequency"]
    assert_equal "1.000001234s", reported["httpCheckFrequency"]
    assert_equal({"nodefs.available" => "1m2.5s"}, reported["evictionSoftGracePeriod"])
  end

  def test_volume_stats_aggregation_accepts_signed_go_durations_and_defaults_typed_zero
    ["0s", "5.25s", "-1s", "-2562047h47m16.854775808s"].zip(["1m0s", "5.25s", "-1s", "-2562047h47m16.854775808s"]).each do |input, expected|
      write_component("volumeStatsAggPeriod" => input)
      config = Config.load(process_name: AGENT, path: @component)

      assert_equal expected, configz(config.process).fetch("volumeStatsAggPeriod")
      assert_empty config.kubelet_read_only_fields
    end

    write_component("volumeStatsAggPeriod" => "2562047h47m16.854775808s")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/volumeStatsAggPeriod must be a Go duration/, error.message)
  end

  def test_node_schedule_and_network_client_rates_use_the_existing_agent_components
    write_component("nodeStatusUpdateFrequency" => "17s", "kubeAPIBurst" => 11, "providerID" => "test://worker")
    assembly = Rubernetes::Bootstrap::Assembler.new(process_name: AGENT, config_path: @native, kubelet_config_path: @component,
                                                    log_io: StringIO.new).build
    node = assembly.service.node_agent
    config = assembly.config.process
    kubelet = configz(config)

    assert_in_delta(17.0, node.instance_variable_get(:@node_status_update_frequency))
    assert_in_delta(17.0, node.instance_variable_get(:@node_status_report_frequency))
    assert_equal ["17s", "17s", 50, 11, "test://worker"], kubelet.values_at("nodeStatusUpdateFrequency", "nodeStatusReportFrequency",
                                                                            "kubeAPIQPS", "kubeAPIBurst", "providerID")
    limiter = assembly.service.api_adapter.client.rest_client.instance_variable_get(:@rate_limiter)

    assert_equal [50, 11], [limiter.qps, limiter.burst]
    write_component("nodeStatusUpdateFrequency" => "10s", "nodeStatusReportFrequency" => "1m30s", "kubeAPIQPS" => 3)
    other = configz(Config.load(process_name: AGENT, path: @component).process)

    assert_equal ["10s", "1m30s", 3, 100], other.values_at("nodeStatusUpdateFrequency", "nodeStatusReportFrequency", "kubeAPIQPS", "kubeAPIBurst")
  end

  def test_node_client_rate_defaults_keep_explicit_zero_qps_in_configz
    write_component({})
    default_assembly = Rubernetes::Bootstrap::Assembler.new(process_name: AGENT, config_path: @native, kubelet_config_path: @component,
                                                            log_io: StringIO.new).build
    default_limiter = default_assembly.service.api_adapter.client.rest_client.instance_variable_get(:@rate_limiter)

    assert_equal [50, 100], configz(default_assembly.config.process).values_at("kubeAPIQPS", "kubeAPIBurst")
    assert_equal [50, 100], [default_limiter.qps, default_limiter.burst]

    write_component("kubeAPIQPS" => 0, "kubeAPIBurst" => 0)
    assembly = Rubernetes::Bootstrap::Assembler.new(process_name: AGENT, config_path: @native, kubelet_config_path: @component,
                                                    log_io: StringIO.new).build

    assert_equal [0, 100], configz(assembly.config.process).values_at("kubeAPIQPS", "kubeAPIBurst")

    limiter = assembly.service.api_adapter.client.rest_client.instance_variable_get(:@rate_limiter)

    assert_instance_of Rubernetes::Client::RateLimiter::ByAPIVersion, limiter
  end

  def test_priority_shutdown_and_memory_settings_round_trip_after_loading
    File.write(@native, YAML.dump({"processes" => {AGENT => {"runtime_profile" => "host_integration"}}}))
    priority = [{"priority" => 100_000, "shutdownGracePeriodSeconds" => 5}, {"priority" => -1, "shutdownGracePeriodSeconds" => 2}]
    reservations = [{"numaNode" => 0, "limits" => {"memory" => "512Mi"}}]
    options = {"shutdownGracePeriodByPodPriority" => priority, "reservedMemory" => reservations, "memoryManagerPolicy" => "Static",
               "memoryThrottlingFactor" => 0.8, "memoryReservationPolicy" => "TieredReservation", "qosReserved" => {"memory" => "50%"},
               "protectKernelDefaults" => true, "featureGates" => {"MemoryQoS" => true, "QOSReserved" => true}}
    write_component(options)
    process = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component).process
    periods = Rubernetes::Node::ShutdownManager.periods(grace_period: 0, by_priority: process.dig("shutdown", "grace_period_by_pod_priority"))

    assert_equal([[-1, 2], [100_000, 5]], periods.map { |period| [period.priority, period.seconds] })
    assert_equal options, configz(process).slice(*options.keys)
    write_component(configz(process))
    reloaded = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)

    assert_equal options, configz(reloaded.process).slice(*options.keys)
    assert_includes reloaded.kubelet_read_only_fields, "cgroupDriver"
    assert_equal [50, 100], configz(reloaded.process).values_at("kubeAPIQPS", "kubeAPIBurst")
  end

  def test_cri_runtime_settings_apply_only_to_a_configured_cri_backend
    native = {"cri" => {"enabled" => true, "endpoint" => "unix://#{@directory}/cri.sock", "handlers" => {"cri" => ""}}}
    File.write(@native, YAML.dump({"processes" => {AGENT => native}}))
    options = {"runtimeRequestTimeout" => "1m15s", "containerLogMaxSize" => "512Ki", "containerLogMaxFiles" => 3,
               "containerLogMaxWorkers" => 3, "containerLogMonitorInterval" => "2.5s", "podLogsDir" => File.join(@directory, "pod-logs")}
    write_component(options)
    assembly = Rubernetes::Bootstrap::Assembler.new(process_name: AGENT, config_path: @native, kubelet_config_path: @component, log_io: StringIO.new).build
    process = assembly.config.process
    backend = assembly.service.runtime.backend_for("cri")
    native_runtime = assembly.service.runtime.backend_for("rubernetes-native")
    logs = backend.log_manager

    assert_equal 3, logs.max_workers

    assert_in_delta(75, backend.client.instance_variable_get(:@timeout))
    assert_in_delta(2.5, logs.instance_variable_get(:@interval))
    assert_equal [512 * 1024, 3], [logs.instance_variable_get(:@max_size), logs.instance_variable_get(:@max_files)]
    assert_equal [512 * 1024, 3], [native_runtime.config.max_log_bytes, native_runtime.config.max_log_files]
    assert_equal options["podLogsDir"], backend.log_root
    assert_equal options, configz(process).slice(*options.keys)
    write_component(options.slice("containerLogMonitorInterval", "runtimeRequestTimeout"))
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/unsupported KubeletConfiguration settings: containerLogMonitorInterval, runtimeRequestTimeout/, error.message)
  end

  def test_log_worker_count_validates_int32_and_remains_readback_only_without_cri
    native = {"cri" => {"enabled" => true, "endpoint" => "unix://#{@directory}/cri.sock"}}
    File.write(@native, YAML.dump({"processes" => {AGENT => native}}))
    [0, -1, 2**31, 1.2, "2"].each do |workers|
      write_component("containerLogMaxWorkers" => workers)
      error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component) }

      assert_match(/container_log_max_workers must be an int32 greater than or equal to 1/, error.message)
    end

    write_component("containerLogMaxWorkers" => 2)
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(/unsupported KubeletConfiguration settings: containerLogMaxWorkers/, error.message)
    write_component("containerLogMaxWorkers" => 1)
    native_only = Config.load(process_name: AGENT, path: @component)

    assert_equal ["containerLogMaxWorkers"], native_only.kubelet_read_only_fields
    assert_nil native_only.process["cri"]
  end

  def test_native_pod_limits_and_log_root_are_used_by_the_host_runtime
    native = {"runtime_profile" => "host_integration", "sandbox_root" => File.join(@directory, "sandbox"),
              "log_root" => File.join(@directory, "spool"), "journal_path" => File.join(@directory, "runtime.jsonl")}
    File.write(@native, YAML.dump({"processes" => {AGENT => native}}))
    pod_logs = File.join(@directory, "pod-logs")
    write_component("podPidsLimit" => 64, "podLogsDir" => pod_logs)
    process = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component).process
    runtime = Rubernetes::Bootstrap::Assembler.new(process_name: AGENT).send(:build_runtime, process)
    settings = runtime.send(:pod_cgroup_limits, {"spec" => {"containers" => [{"name" => "app"}]}})

    assert_equal "64", settings.fetch("pids.max")
    assert_equal pod_logs, runtime.instance_variable_get(:@pod_log_files).instance_variable_get(:@pod_root)
    assert_equal [64, pod_logs], configz(process).values_at("podPidsLimit", "podLogsDir")
    write_component("podLogsDir" => "relative")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component) }

    assert_match(/pod_logs_dir must be an absolute path/, error.message)
  end

  def test_rejects_unsupported_gate_changes_and_ineffective_options
    examples = [
      [{"featureGates" => {"KubeletUnknownNewSetting" => true}}, /unsupported KubeletConfiguration feature gates/],
      [{"featureGates" => {"MemoryQoS" => "true"}}, /MemoryQoS must be a boolean/],
      [{"memoryThrottlingFactor" => 0.6}, /unsupported KubeletConfiguration settings: memoryThrottlingFactor/],
      [{"shutdownGracePeriodByPodPriority" => [{"priority" => 1, "shutdownGracePeriodSeconds" => 5}],
        "featureGates" => {"GracefulNodeShutdownBasedOnPodPriority" => false}}, /requires GracefulNodeShutdownBasedOnPodPriority/],
      [{"nodeStatusReportFrequency" => "0s"}, /node_status_report_frequency_seconds must be a positive number/],
      [{"kubeAPIBurst" => 2**31}, /kubeAPIBurst must be a non-negative int32/],
      [{"kubeAPIBurst" => -1}, /kubeAPIBurst must be a non-negative int32/],
      [{"kubeAPIQPS" => 3.5}, /kubeAPIQPS must be a non-negative int32/],
      [{"kubeAPIQPS" => -1}, /kubeAPIQPS must be a non-negative int32/],
      [{"kubeAPIQPS" => 2**31}, /kubeAPIQPS must be a non-negative int32/]
    ]
    examples.each do |options, message|
      write_component(options)
      error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

      assert_match message, error.message
    end
  end

  def test_streaming_bind_validation_preserves_native_authorization
    write_component("address" => "192.0.2.120", "port" => 20_250)
    config = Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component)

    assert_equal [true, "192.0.2.120", 20_250], configz(config.process).values_at("enableServer", "address", "port")
    assert_equal "Webhook", config.process.dig("streaming", "authorization", "mode")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }
    assert_match(/requires native streaming authentication and authorization/, error.message)

    write_component("address" => "192.0.2.120", "readOnlyPort" => 10_255)
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @native, kubelet_config_path: @component) }
    assert_match(/requires loopback addresses with readOnlyPort enabled/, error.message)
  end

  def test_rejects_wrong_type_conflicting_files_and_non_agent_use
    write_component("apiVersion" => "kubelet.config.k8s.io/v1beta2")
    error = assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component) }

    assert_match(%r{kubelet.config.k8s.io/v1beta1}, error.message)

    write_component("fileCheckFrequency" => "30s")
    assert_raises(Config::Error) { Config.load(process_name: AGENT, path: @component, kubelet_config_path: @component) }
    assert_raises(Config::Error) { Config.load(process_name: "rubernetes-scheduler", path: @component) }
  end

  def test_check_config_rereads_the_operand_and_reports_unchanged_fields
    write_component("fileCheckFrequency" => "30s", "cgroupDriver" => "cgroupfs")
    arguments = ["--config", @native, "--kubelet-config", @component, "--check-config"]
    out = StringIO.new
    err = StringIO.new

    assert_equal 0, CLI.run(process_name: AGENT, argv: arguments, stdout: out, stderr: err)
    result = JSON.parse(out.string)

    assert_equal 30, result.dig("config", "processes", AGENT, "file_check_frequency_seconds")
    assert_match(/unchanged readback-only KubeletConfiguration fields: cgroupDriver/, err.string)

    write_component("fileCheckFrequency" => "45s")
    out = StringIO.new

    assert_equal 0, CLI.run(process_name: AGENT, argv: arguments, stdout: out, stderr: StringIO.new)
    assert_equal 45, JSON.parse(out.string).dig("config", "processes", AGENT, "file_check_frequency_seconds")
  end

  private

  def configz(process)
    Rubernetes::Node::KubeletConfigz.build(process).fetch("kubeletconfig")
  end

  def write_component(values)
    document = {"apiVersion" => "kubelet.config.k8s.io/v1beta1", "kind" => "KubeletConfiguration"}.merge(values)
    File.write(@component, YAML.dump(document))
  end
end
