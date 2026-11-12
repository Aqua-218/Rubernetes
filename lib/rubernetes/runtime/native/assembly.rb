# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Constructor wiring: gathers the injected adapters under their
      # canonical names and builds the collaborators the runtime works
      # through (journal, namespace, filesystem, cgroup, security, process
      # supervisor), failing closed when a host profile cannot be proven.
      module Assembly
        # Adapters may arrive under their constructor-keyword name inside the
        # `adapters:` hash; each is filed under the short name the runtime
        # reads, without displacing an entry already filed there.
        ADAPTER_ALIASES = {
          namespace_adapter: :namespace,
          filesystem_adapter: :filesystem,
          cgroup_adapter: :cgroup,
          security_adapter: :security_adapter,
          process_adapter: :process_adapter,
          pidfd_adapter: :pidfd,
          exec_adapter: :exec,
          attach_adapter: :attach,
          port_forward_adapter: :port_forward,
          http_probe_adapter: :http_probe,
          tcp_probe_adapter: :tcp_probe,
          sysctl_adapter: :sysctl,
          device_filter_adapter: :device_filter,
          image_resolver: :image_resolver
        }.freeze

        private

        # +explicit+ holds the constructor's own keyword adapters; one that
        # was given wins over the same entry of the `adapters:` hash.
        def collect_adapters(adapters, explicit)
          collected = adapters.to_h.transform_keys(&:to_sym)
          ADAPTER_ALIASES.each do |source, target|
            collected[target] ||= collected[source] if collected.key?(source)
          end
          explicit.each { |key, value| collected[key] = value if value }
          collected
        end

        def default_journal
          return MemoryJournal.new(clock: @clock) if config.pure_profile?

          RollbackJournal.new(config.journal_path, clock: @clock)
        rescue SystemCallError => error
          raise CapabilityError, "Native durable journal cannot be opened: #{error.message}"
        end

        def validate_host_adapters!
          HostCapabilityContract.validate!(
            profile: config.profile,
            adapters: {
              namespace: @adapters[:namespace],
              filesystem: @adapters[:filesystem],
              cgroup: @adapters[:cgroup],
              security: @adapters[:security] || @adapters[:security_adapter],
              security_probe: @adapters[:security_probe],
              process: @adapters[:process_supervisor] || @adapters[:process_adapter],
              pidfd: @adapters[:pidfd],
              exec: @adapters[:exec],
              port_forward: @adapters[:port_forward]
            }
          )
        rescue HostCapabilityContract::Error => error
          raise CapabilityError, "Native host profile is unavailable: #{error.message}"
        end

        def build_namespace
          return @adapters[:namespace] if @adapters[:namespace].is_a?(Namespace)

          adapter = @adapters[:namespace] || Namespace::RecordingAdapter.new
          Namespace.new(adapter: adapter, profile: config.profile)
        end

        def build_filesystem
          Filesystem.new(adapter: @adapters[:filesystem], root: config.sandbox_root)
        end

        def build_cgroup
          return @adapters[:cgroup] if @adapters[:cgroup]
          return FakeCgroup.new if config.pure_profile?

          Platform::Linux::CgroupV2.new(root: config.cgroup_root, adapter: @adapters[:cgroup_io] || Platform::Linux::CgroupV2::FileAdapter.new)
        end

        def build_security
          if @adapters[:security].is_a?(Platform::Linux::Security)
            @security_probe = @adapters[:security_probe]&.call || Platform::Linux::Security::CapabilityProbe.new.call
            return @adapters[:security]
          end
          @security_probe = if config.pure_profile?
                              FakeCapabilityProbe.new(architecture: config.architecture).call
                            elsif @adapters[:security_probe]
                              run_security_probe(@adapters[:security_probe])
                            else
                              Platform::Linux::Security::CapabilityProbe.new(architecture: config.architecture).call
                            end
          security = Platform::Linux::Security.new(
            capability_probe: @adapters[:security_probe] || -> { @security_probe },
            adapter: @adapters[:security_adapter] || Platform::Linux::Security::RecordingAdapter.new,
            seccomp_compiler: @adapters[:seccomp_compiler],
            seccomp_root: config.seccomp_root
          )
          share_security_with_process_adapter(security)
          security
        end

        def build_process_supervisor
          return @adapters[:process_supervisor] if @adapters[:process_supervisor]

          Platform::Linux::ProcessSupervisor.new(
            process_adapter: @adapters[:process_adapter] || default_process_adapter,
            pidfd_adapter: @adapters[:pidfd].nil? ? default_pidfd_adapter : @adapters[:pidfd],
            cgroup: @cgroup,
            log_directory: config.log_root,
            max_log_bytes: config.max_log_bytes,
            max_log_files: config.max_log_files,
            clock: @clock
          )
        end

        def default_process_adapter
          config.pure_profile? ? FakeProcessAdapter.new : Platform::Linux::ProcessSupervisor::ForkAdapter.new
        end

        # Without a pidfd every signal is addressed by pid, and a recycled pid
        # makes "stop this container" land on an unrelated process -- including
        # the node agent itself.  Host profiles therefore default to the real
        # pidfd adapter instead of silently degrading; only a host whose
        # syscall ABI manifest cannot be loaded goes without one.
        def default_pidfd_adapter
          return nil if config.pure_profile?

          Platform::Linux::NativeAdapters::PidfdAdapter.new
        rescue Platform::Linux::ABIManifest::Error, SystemCallError
          nil
        end

        def validate_profile_capabilities!
          probe = @security_probe
          # NoNewPrivs reports the state of the probing process, not whether the
          # kernel can set it in the gated workload child.  L3 preflight must
          # require support; SecurityAdapter applies and verifies the state in
          # the child before reporting exec readiness.
          required = {
            seccomp: probe.available?(:seccomp),
            no_new_privs: probe.available?(:no_new_privs),
            landlock: probe.available?(:landlock)
          }
          missing = required.reject { |_name, available| available }.keys
          missing << :cgroup_v2 unless @cgroup.available?
          raise CapabilityError, "L3 kernel isolation profile is unavailable: #{missing.join(", ")}" unless missing.empty?
        end
      end
    end
  end
end
