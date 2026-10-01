# frozen_string_literal: true

# Small adapter defaults for the standalone Native backend.  Recording adapters
# are intentionally boring: they make pure/fake profiles useful without
# pretending that a host kernel boundary was established.

module Rubernetes
  module Runtime
    class Native
      class RecordingAdapter
        attr_reader :name, :calls

        def initialize(name = :adapter, values: {})
          @name = name.to_sym
          @values = values.dup
          @calls = []
          @counter = 0
        end

        def call(operation = :call, **arguments)
          @counter += 1
          @calls << {"operation" => operation.to_sym, "arguments" => immutable(arguments), "sequence" => @counter}.freeze
          @values.fetch(operation.to_sym, true)
        end

        def probe
          @values.fetch(:probe, true)
        end

        private

        def immutable(value)
          copied = case value
                   when Hash then value.to_h { |key, child| [String(key), immutable(child)] }
                   when Array then value.map { |child| immutable(child) }
                   else value
                   end
          copied.freeze
        end
      end

      # Host profiles are allowed to use only adapters that can prove the
      # kernel effects they implement.  A capability hash by itself is not a
      # proof: validation must execute a read-only/preflight check before the
      # runtime can become ready.  Pure and fake_io profiles intentionally do
      # not enter this contract and remain deterministic.
      class HostCapabilityContract
        REQUIREMENTS = {
          namespace: {
            capability: :namespace,
            methods: %i[create destroy]
          },
          filesystem: {
            capability: :filesystem,
            methods: %i[prepare cleanup]
          },
          cgroup: {
            capability: :cgroup_v2,
            methods: %i[available? create configure attach kill remove stats events]
          },
          security: {
            capability: :security_application,
            methods: [:apply]
          },
          process: {
            capability: :process_gate,
            methods: %i[spawn release_gate wait signal]
          },
          pidfd: {
            capability: :pidfd,
            methods: %i[open send_signal wait close]
          },
          exec: {
            capability: :namespace_exec_streams,
            methods: [:exec]
          },
          port_forward: {
            capability: :namespace_port_forward,
            methods: [:port_forward]
          }
        }.freeze

        class Error < Native::CapabilityError; end

        def self.validate!(profile:, adapters:)
          if adapters[:security_probe] && testing_adapter?(adapters[:security_probe])
            raise Error, "security probe #{adapters[:security_probe].class} is a fake adapter and cannot be used by a host profile"
          end

          requirements = Requirements.dup
          requirements.delete(:pidfd) unless %i[kernel_isolation l3].include?(profile.to_sym)
          requirements.each do |name, requirement|
            adapter = adapters[name]
            raise Error, "#{profile} profile requires an explicit #{name} adapter" unless adapter

            validate_adapter!(name, adapter, requirement)
          end
          true
        end

        def self.validate_adapter!(name, adapter, requirement)
          if testing_adapter?(adapter)
            raise Error, "#{name} adapter #{adapter.class} is a recording/fake adapter and cannot be used by a host profile"
          end

          missing_methods = requirement.fetch(:methods).reject { |method| adapter.respond_to?(method) }
          unless missing_methods.empty?
            raise Error, "#{name} adapter #{adapter.class} is missing required effects: #{missing_methods.join(", ")}"
          end

          declaration = adapter.respond_to?(:native_capabilities) ? adapter.native_capabilities : nil
          unless declaration.respond_to?(:to_h)
            raise Error, "#{name} adapter #{adapter.class} must declare native_capabilities and validate them"
          end

          capabilities = declaration.to_h
          capability = requirement.fetch(:capability)
          declared = capabilities[capability] || capabilities[capability.to_s]
          raise Error, "#{name} adapter #{adapter.class} does not prove #{capability}" unless declared == true
          unless adapter.respond_to?(:validate_native_capabilities!)
            raise Error, "#{name} adapter #{adapter.class} must implement validate_native_capabilities!"
          end

          result = adapter.validate_native_capabilities!
          raise Error, "#{name} adapter #{adapter.class} failed native capability validation" unless result == true

          true
        rescue NoMethodError => error
          raise Error, "#{name} adapter #{adapter.class} returned an invalid native capability contract: #{error.message}"
        rescue StandardError => error
          raise Error, "#{name} adapter #{adapter.class} failed native capability validation: #{error.message}"
        end

        def self.testing_adapter?(adapter)
          name = adapter.class.name.to_s
          return true if name.match?(/(?:^|::)RecordingAdapter\z/)
          return true if name.match?(/(?:^|::)Fake(?:Cgroup|ProcessAdapter|PidfdAdapter|CapabilityProbe)\z/)

          false
        end

        private_class_method :testing_adapter?
      end

      class FakeCgroup
        Handle = Data.define(:path, :qos, :pod_id, :container_id, :identity) do
          def to_h
            {"path" => path, "qos" => qos, "pod_id" => pod_id, "container_id" => container_id, "identity" => identity}
          end
        end

        attr_reader :calls

        def initialize
          @calls = []
          @handles = {}
        end

        def create(qos:, pod_id:, container_id:, identity: nil, limits: nil, pod_limits: nil)
          handle = Handle.new(path: "fake/#{qos}/#{pod_id}/#{container_id}", qos: qos, pod_id: pod_id, container_id: container_id,
                              identity: identity || "cgroup:#{pod_id}:#{container_id}")
          @handles[handle.path] = handle
          @calls << [:create, handle]
          @limits ||= {}
          @limits[handle.path] = (limits || {}).to_h.transform_keys(&:to_s)
          @calls << [:configure, handle, limits] if limits && !limits.empty?
          @calls << [:configure_pod, handle, pod_limits] if pod_limits && !pod_limits.empty?
          handle
        end

        def configure_pod(handle, limits)
          @calls << [:configure_pod, handle, limits]
          true
        end

        # The fake echoes the configured values so pure-profile tests can
        # assert on the formulas without a kernel.
        def limits_readback(handle, **_options)
          (@limits || {}).fetch(handle.path, {})
        end

        def pod_limits_readback(_handle, **_options)
          {}
        end

        def oom_kill_count(_handle)
          0
        end

        alias create_cgroup create

        def configure(handle, limits)
          @calls << [:configure, handle, limits]
          true
        end

        alias apply_limits configure

        def attach(handle, pid:)
          @calls << [:attach, handle, pid]
          true
        end

        alias add_process attach

        def stats(_handle)
          {"cpu" => {}, "memory" => {}, "io" => {}, "pids" => 0, "pressure" => {}, "events" => {}}
        end

        def events(_handle)
          {}
        end

        def kill(handle)
          @calls << [:kill, handle]
          true
        end

        def remove(handle, force: false)
          @calls << [:remove, handle, force]
          @handles.delete(handle.path)
          true
        end

        alias remove_cgroup remove

        # The fake backend still exposes the resources it created so a pure
        # runtime can reconcile real adapter state instead of echoing ledger
        # entries.  Callers must compare identity before invoking remove.
        def resources
          @handles.values.map(&:to_h).freeze
        end

        def lookup(value)
          path = value.respond_to?(:path) ? value.path : String(value)
          @handles.fetch(path) { raise KeyError, "unknown fake cgroup #{path}" }
        end
      end

      class FakeProcessAdapter
        ProcessResult = Data.define(:pid, :pidfd, :gate, :stdout, :stderr, :cgroup)
        Wait = Data.define(:exit_status, :term_signal, :code)

        attr_reader :calls

        def initialize
          @calls = []
          @next_pid = 10_000
          @running = {}
        end

        def spawn(command:, env: {}, cwd: nil, gate: true, cgroup: nil, **_options)
          @next_pid += 1
          value = ProcessResult.new(pid: @next_pid, pidfd: @next_pid, gate: gate ? Object.new : nil, stdout: nil, stderr: nil,
                                    cgroup: cgroup)
          @running[value.pidfd] = true
          @calls << [:spawn, command, env, cwd, gate, cgroup]
          value
        end

        def release_gate(gate)
          @calls << [:release_gate, gate]
          true
        end

        # A non-blocking wait on a process that has not exited reports nothing,
        # exactly as waitpid(WNOHANG) does.  A fake that always reports an exit
        # makes a running workload look finished to every caller that polls.
        def wait(pid:, timeout: nil)
          @calls << [:wait, pid, timeout]
          return nil if timeout && Float(timeout).zero? && @running[pid]

          @running.delete(pid)
          Wait.new(exit_status: 0, term_signal: nil, code: 0)
        end

        def signal(pid:, signal:)
          @calls << [:signal, pid, signal]
          @running.delete(pid)
          true
        end
      end

      class FakePidfdAdapter
        Wait = Data.define(:exit_status, :term_signal, :code)

        attr_reader :calls

        def initialize
          @calls = []
        end

        def open(pid:, resource_id:)
          @calls << [:open, pid, resource_id]
          Integer(pid)
        end

        def send_signal(pidfd:, signal:, resource_id:)
          @calls << [:send_signal, pidfd, signal, resource_id]
          true
        end

        def wait(pidfd:, timeout:, resource_id:)
          @calls << [:wait, pidfd, timeout, resource_id]
          Wait.new(exit_status: 0, term_signal: nil, code: 0)
        end

        def alive?(pidfd:)
          @calls << [:alive, pidfd]
          true
        end
      end

      class FakeCapabilityProbe
        def initialize(architecture: "x86_64")
          @probe = Platform::Linux::Security::Probe.new(
            architecture: architecture,
            capabilities: Platform::Linux::Security::CAPABILITIES.transform_values { true },
            no_new_privs: true,
            seccomp: true,
            landlock: true,
            details: {"profile" => "fake"}.freeze
          )
        end

        def call
          @probe
        end

        alias probe call
      end
    end
  end
end
