# frozen_string_literal: true

require_relative "../../platform/linux/kubelet_cgroup_layout"

module Rubernetes
  module Bootstrap
    class Assembler
      # The container runtime: the native one, and the microVM and CRI handlers
      # behind a multiplexer when they are enabled; RuntimeClass resolution.
      module RuntimeBuilder
        private

        def build_runtime(process, adapters: {}, image_resolver: nil, pull_limiter: Image::PullLimiter.from_config(process))
          profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
          privileged = process.fetch("privileged", false) == true
          if privileged && %i[pure fake_io].include?(profile)
            raise Runtime::Native::CapabilityError, "privileged agent runtime requires an explicit host-capable profile"
          end

          paths = process.fetch("runtime_paths", process.fetch("runtime", {})) || {}
          sandbox_root = process.fetch("sandbox_root", paths.fetch("sandbox_root", Runtime::Native::Configuration::DEFAULT_SANDBOX_ROOT))
          cgroup_root = process.fetch("cgroup_root", paths.fetch("cgroup_root", Runtime::Native::Configuration::DEFAULT_CGROUP_ROOT))
          runtime_adapters = adapters.to_h
          if %i[host_integration kernel_isolation l3].include?(profile)
            runtime_adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
              profile: profile,
              sandbox_root: sandbox_root,
              cgroup_root: cgroup_root,
              kubelet_layout: Platform::Linux::KubeletCgroupLayout.new(cgroup_root, enabled: process.fetch("cgroups_per_qos", true)),
              architecture: process["architecture"]
            ).merge(runtime_adapters)
          end
          runtime = Runtime::Native.new(
            adapters: runtime_adapters,
            image_resolver: image_resolver,
            profile: profile,
            sandbox_root: sandbox_root,
            cgroup_root: cgroup_root,
            log_root: process.fetch("log_root", paths.fetch("log_root", Runtime::Native::Configuration::DEFAULT_LOG_ROOT)),
            journal_path: process.fetch("journal_path", paths.fetch("journal_path", Runtime::Native::Configuration::DEFAULT_JOURNAL_PATH)),
            userns_allocation_path: paths["userns_allocation_path"],
            l3: process.fetch("l3", false),
            **memory_options(process),
            **cpu_quota_options(process),
            **native_limits(process),
            security_context: {"privileged" => privileged},
            # kubelet: Localhost seccomp profiles live under <root-dir>/seccomp.
            seccomp_root: process.fetch("seccomp_root",
                                        File.join(File.dirname(process.fetch("journal_path",
                                                                             paths.fetch("journal_path", Runtime::Native::Configuration::DEFAULT_JOURNAL_PATH))),
                                                  "seccomp"))
          )
          if privileged && !privileged_capabilities_available?(runtime)
            raise Runtime::Native::CapabilityError, "privileged agent runtime capabilities are unavailable"
          end

          if runtime.config.host_profile?
            require_relative "../../runtime/native/pod_log_files"
            Runtime::Native::PodLogFiles.install(runtime, **{pod_root: process["pod_logs_dir"]}.compact)
          end

          wrap_microvm_backends(runtime, process, pull_limiter: pull_limiter)
        end

        def native_limits(process)
          size = process["container_log_max_size"]
          pids = process["pod_pids_limit"]
          {max_log_bytes: (Schema::Quantity.parse_int64(size.to_s) if size),
           max_log_files: process["container_log_max_files"], pod_pids_limit: (pids if pids && pids.positive?)}.compact
        end

        # The multiplexer routes each Pod by RuntimeClass and remembers the
        # owner of every sandbox. Pods without a RuntimeClass use the node's
        # configured default handler.
        def wrap_microvm_backends(native, process, pull_limiter:)
          section = process["microvm"]
          backends = {"rubernetes-native" => native}
          backends.merge!(microvm_backends(section)) if section.is_a?(Hash) && section["enabled"] == true
          if process["cri"].is_a?(Hash) && process["cri"]["enabled"] == true
            require "rubernetes/runtime/cri"
            allocations = Runtime::CRI::UserNamespaces::Allocations.new(-> { cri_userns_allocator(native) })
            section = process["cri"].merge(process.slice("container_log_max_size", "container_log_max_files"))
            section["log_root"] = process["pod_logs_dir"] if process["pod_logs_dir"]
            backends.merge!(cri_backends(section, feature_gates: process.fetch("feature_gates", {}),
                                                  resource_options: memory_options(process).merge(cpu_quota_options(process)),
                                                  user_namespace_allocations: allocations,
                                                  pull_limiter: pull_limiter))
          end
          return native if backends.length == 1

          require "rubernetes/runtime/multiplexer"
          default = process.dig("cri", "default_handler") || Runtime::Multiplexer::DEFAULT_HANDLER
          Runtime::Multiplexer.new(backends: backends, default: default)
        end

        def cri_userns_allocator(native)
          return native.userns_allocator unless native.config.pure_profile?

          # CRI effects are durable even when the native engine is a test double.
          Platform::Linux::UserNamespace::Allocator.new(path: native.config.userns_allocation_path)
        end

        # One CRI backend per handler, sharing the runtime connection.
        def cri_backends(section, feature_gates:, resource_options:, user_namespace_allocations:, pull_limiter:)
          client = Runtime::CRI::Client.new(endpoint: section.fetch("endpoint"), timeout: section.fetch("timeout_seconds", 60),
                                            stream_lists: feature_gates["CRIListStreaming"] == true)
          # kubelet containerLogMaxSize (10Mi) / containerLogMaxFiles (5).
          log_manager = Runtime::CRI::LogManager.new(
            client: client, max_files: section.fetch("container_log_max_files", 5),
            max_size: section.fetch("container_log_max_size", Runtime::CRI::LogManager::DEFAULT_MAX_SIZE),
            max_workers: section.fetch("container_log_max_workers", Runtime::CRI::LogManager::DEFAULT_WORKERS),
            interval: section.fetch("container_log_monitor_interval_seconds", 10)
          )
          handlers = section.fetch("handlers", {"cri" => ""})
          handlers.to_h do |name, handler|
            [name.to_s, Runtime::CRI::Backend.new(client: client, handler: handler.to_s, log_manager: log_manager, pull_limiter: pull_limiter,
                                                  runtime_class_in_image_api: feature_gates["RuntimeClassInImageCriApi"] == true,
                                                  user_namespace_allocations: user_namespace_allocations,
                                                  user_namespaces_host_network: feature_gates["UserNamespacesHostNetworkSupport"] == true,
                                                  **resource_options,
                                                  log_root: section.fetch("log_root", "/var/log/pods"),
                                                  # Beside the native hierarchy, never in it: the
                                                  # native runtime's cgroup scan must not meet CRI Pods.
                                                  cgroup_parent: section.fetch("cgroup_parent", "/rubernetes-cri"))]
          end
        end

        def memory_options(process)
          {single_process_oom_kill: process["single_process_oom_kill"], memory_qos: process.dig("feature_gates", "MemoryQoS") == true,
           memory_throttling_factor: process.fetch("memory_throttling_factor", Runtime::MemoryQoS::DEFAULT_THROTTLING_FACTOR),
           memory_reservation_policy: process.fetch("memory_reservation_policy", "None")}
        end

        def cpu_quota_options(process)
          seconds = process["cpu_cfs_quota_period_seconds"] || Runtime::CPUQuota::DEFAULT_SECONDS
          {cpu_cfs_quota: process["cpu_cfs_quota"] != false, cpu_period: Runtime::CPUQuota.period_microseconds(seconds)}
        end

        def microvm_backends(section)
          require "rubernetes/runtime/microvm"
          options = {
            data_dir: section.fetch("data_dir", "/var/lib/rubernetes/microvm"),
            chroot_base: section.fetch("chroot_base", Runtime::MicroVM::DEFAULT_CHROOT_BASE),
            netns_root: section.fetch("netns_root", Runtime::MicroVM::DEFAULT_NETNS_ROOT),
            run_root: section.fetch("run_root", Runtime::MicroVM::DEFAULT_RUN_ROOT),
            parent_cgroup: section.fetch("parent_cgroup", Runtime::MicroVM::DEFAULT_PARENT_CGROUP),
            machine: {"vcpu_count" => section.fetch("vcpu_count", 1), "mem_size_mib" => section.fetch("mem_size_mib", 512)},
            use_base_snapshot: section.fetch("use_base_snapshot", true),
            artifacts_lock: section["artifacts_lock"]
          }.compact
          {
            "rubernetes-firecracker" => Runtime::MicroVM.new(**options, data_dir: File.join(options[:data_dir], "firecracker")),
            "rubernetes-firecracker-restricted" => Runtime::MicroVMRestricted.new(**options, data_dir: File.join(options[:data_dir],
                                                                                                                 "restricted"))
          }
        end

        # kubelet's runtimeclass manager: a Pod's RuntimeClass object names its
        # handler (read through the node's cached reader); the node's own table
        # (native, microVM, CRI handlers, configured runtime_classes) serves
        # the names the API does not know.
        def runtime_class_resolver(process, reader: nil)
          require "rubernetes/runtime/microvm/runtime_classes"
          # A CRI handler is served under its own name as a RuntimeClass too.
          cri = process["cri"].is_a?(Hash) && process["cri"]["enabled"] == true ? process["cri"].fetch("handlers", {"cri" => ""}) : {}
          table = Runtime::MicroVMRuntimeClasses.handler_table(cri.keys.to_h { |name| [name, name] }.merge(process["runtime_classes"] || {}))
          lambda do |pod|
            name = pod.dig("spec", "runtimeClassName") || pod.dig(:spec, :runtimeClassName)
            next nil if name.nil? || name.to_s.empty?

            handler = runtime_class_handler(reader, name.to_s)
            next handler if handler

            table.fetch(name.to_s) { raise Node::Lifecycle::LifecycleError, "runtime class #{name.inspect} is not provided by this node" }
          end
        end

        def privileged_capabilities_available?(runtime)
          probe = runtime.security.probe
          %w[SYS_ADMIN SYS_CHROOT SETUID SETGID].all? { |name| probe.capability?(name) }
        rescue NoMethodError
          false
        end
      end
    end
  end
end
