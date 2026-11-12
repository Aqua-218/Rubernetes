# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Assembler
      # The container runtime: the native one, and the microVM and CRI handlers
      # behind a multiplexer when they are enabled; RuntimeClass resolution.
      module RuntimeBuilder
        private

        def build_runtime(process, adapters: {}, image_resolver: nil)
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
            l3: process.fetch("l3", false),
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

          wrap_microvm_backends(runtime, process)
        end

        # When the microvm section is enabled the node serves three runtime
        # handlers; the multiplexer routes each Pod to the backend of its
        # RuntimeClass handler and remembers the owner of every sandbox.
        def wrap_microvm_backends(native, process)
          section = process["microvm"]
          backends = {"rubernetes-native" => native}
          backends.merge!(microvm_backends(section)) if section.is_a?(Hash) && section["enabled"] == true
          backends.merge!(cri_backends(process["cri"])) if process["cri"].is_a?(Hash) && process["cri"]["enabled"] == true
          return native if backends.length == 1

          Runtime::Multiplexer.new(backends: backends)
        end

        # One CRI backend per handler, sharing the runtime connection.
        def cri_backends(section)
          require "rubernetes/runtime/cri"
          client = Runtime::CRI::Client.new(endpoint: section.fetch("endpoint"), timeout: section.fetch("timeout_seconds", 60))
          # kubelet containerLogMaxSize (10Mi) / containerLogMaxFiles (5).
          log_manager = Runtime::CRI::LogManager.new(
            client: client, max_files: section.fetch("container_log_max_files", 5),
            max_size: Schema::Quantity.from_json(section.fetch("container_log_max_size", "10Mi").to_s).value.to_i
          )
          handlers = section.fetch("handlers", {"cri" => ""})
          handlers.to_h do |name, handler|
            [name.to_s, Runtime::CRI::Backend.new(client: client, handler: handler.to_s, log_manager: log_manager,
                                                  log_root: section.fetch("log_root", "/var/log/pods"),
                                                  # Beside the native hierarchy, never in it: the
                                                  # native runtime's cgroup scan must not meet CRI Pods.
                                                  cgroup_parent: section.fetch("cgroup_parent", "/rubernetes-cri"))]
          end
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
