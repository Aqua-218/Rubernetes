# frozen_string_literal: true

# Ruby Native Runtime backend.  It owns validation, state ordering, resource
# ownership, and workload gates; Linux-specific effects are delegated to the
# typed adapters under Platform::Linux and are injectable for L0/L1 tests.

require "digest"
require "json"
require "securerandom"
require "time"

# The native ownership implementation predates the common Runtime contract and
# uses a few top-level constants with the same names.  Keep those primitives
# private to this backend when the common contract was loaded first: capture
# the common definitions, load the native implementation, and restore the
# common definitions after retaining the native classes under Native::Support.
# This also makes `require "rubernetes/runtime"` followed by
# `require "rubernetes/runtime/native"` safe and warning-free.
module Rubernetes
  module Runtime
    NATIVE_LOADER_CONSTANTS = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache) unless const_defined?(:NATIVE_LOADER_CONSTANTS, false)
    %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired
       RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      NATIVE_LOADER_CONSTANTS[name] = const_get(name, false) if const_defined?(name, false)
    end
    NATIVE_LOADER_CONSTANTS.each_key { |name| remove_const(name) }
    generic_runtime = const_get(:Runtime, false) if const_defined?(:Runtime, false)
    remove_const(:Native) if const_defined?(:Native, false) && generic_runtime && const_get(:Native, false).equal?(generic_runtime)
    remove_const(:Backend) if const_defined?(:Backend, false) && generic_runtime && const_get(:Backend, false).equal?(generic_runtime)
    class Native
      EFFECT_POINTS = %i[
        workspace_allocated isolation_created resources_attached workload_stopped
      ].freeze

      module Support
      end
    end
  end
end

require_relative "ownership"

module Rubernetes
  module Runtime
    %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired
       RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      Native::Support.const_set(name, const_get(name, false)) unless Native::Support.const_defined?(name, false)
    end
    NATIVE_LOADER_CONSTANTS.each do |name, value|
      remove_const(name) if const_defined?(name, false)
      const_set(name, value)
    end
    remove_const(:NATIVE_LOADER_CONSTANTS)
  end
end

require_relative "../platform/linux/cgroup_v2"
require_relative "../platform/linux/device_cgroup"
require_relative "../platform/linux/landlock"
require_relative "../platform/linux/openat2"
require_relative "../platform/linux/process_supervisor"
require_relative "../platform/linux/security"
require_relative "../platform/linux/native_adapters"
require_relative "native/errors"
require_relative "native/config"
require_relative "native/namespace"
require_relative "native/filesystem"
require_relative "native/sandbox"
require_relative "native/adapters"
require_relative "native/resources"
require_relative "native/kernel_observer"
require_relative "native/hooks"
require_relative "../platform/linux/userns"

module Rubernetes
  module Runtime
    class Native
      OwnershipLedger = Support::OwnershipLedger unless const_defined?(:OwnershipLedger, false)
      RollbackJournal = Support::RollbackJournal unless const_defined?(:RollbackJournal, false)
      JournalCorruption = Support::JournalCorruption unless const_defined?(:JournalCorruption, false)
      OwnershipConflict = Support::OwnershipConflict unless const_defined?(:OwnershipConflict, false)
      InvalidTransition = Support::InvalidTransition unless const_defined?(:InvalidTransition, false)
      # Native is part of the public Runtime contract.  Its own recovery
      # failures must be catchable through Runtime::RecoveryRequired even
      # though the legacy ownership helpers retain private Support errors.
      RecoveryRequired = Rubernetes::Runtime::RecoveryRequired unless const_defined?(:RecoveryRequired, false)

      class MemoryJournal
        Record = Data.define(:sequence, :operation_id, :event, :payload, :timestamp, :previous_digest, :digest)

        def initialize(clock: -> { Time.now.utc })
          @clock = clock
          @records = []
          @mutex = Mutex.new
        end

        def append(operation_id:, event:, payload: {}, timestamp: nil)
          @mutex.synchronize do
            sequence = @records.length + 1
            record = Record.new(
              sequence: sequence,
              operation_id: String(operation_id),
              event: String(event),
              payload: deep_copy(payload),
              timestamp: (timestamp || @clock.call).utc,
              previous_digest: @records.last&.digest || ("0" * 64),
              digest: Digest::SHA256.hexdigest([sequence, operation_id, event, JSON.generate(payload)].join("\0"))
            )
            @records << record
            record
          end
        end

        def each(&block)
          return enum_for(__method__) unless block

          @mutex.synchronize { @records.each(&block) }
          self
        end

        def records
          @mutex.synchronize { @records.map { |record| record }.freeze }
        end

        alias entries records

        def last
          @mutex.synchronize { @records.last }
        end

        private

        def deep_copy(value)
          case value
          when Hash then value.to_h { |key, child| [String(key), deep_copy(child)] }
          when Array then value.map { |child| deep_copy(child) }
          else value
          end
        end
      end

      # An attach client borrows the supervisor-owned stdio descriptors. Its
      # HTTP/WebSocket lifecycle must never close the sole read end and send
      # SIGPIPE to the container. Each request gets an independently closable
      # view while the underlying descriptor remains owned by the process
      # supervisor until container teardown.
      class BorrowedProcessStream
        def initialize(endpoint)
          @endpoint = endpoint
          @closed = false
          @mutex = Mutex.new
        end

        def read(length = nil)
          ensure_open!
          length.nil? ? @endpoint.read : @endpoint.read(length)
        end

        def readpartial(length)
          ensure_open!
          @endpoint.readpartial(length)
        end

        def read_nonblock(length, exception: true)
          ensure_open!
          @endpoint.read_nonblock(length, exception: exception)
        end

        def write(value)
          ensure_open!
          @endpoint.write(value)
        end

        def write_nonblock(value, exception: true)
          ensure_open!
          @endpoint.write_nonblock(value, exception: exception)
        end

        def flush
          ensure_open!
          @endpoint.flush if @endpoint.respond_to?(:flush)
          self
        end

        def close
          @mutex.synchronize { @closed = true }
          self
        end

        alias close_write close

        def closed?
          @mutex.synchronize { @closed }
        end

        private

        def ensure_open!
          raise IOError, "borrowed process stream is closed" if closed?
        end
      end

      def initialize(config: nil, profile: nil, adapters: {}, journal: nil, clock: -> { Time.now.utc },
                     namespace_adapter: nil, cgroup_adapter: nil, filesystem_adapter: nil,
                     security_adapter: nil, security_probe: nil, process_adapter: nil,
                     pidfd_adapter: nil, exec_adapter: nil, attach_adapter: nil,
                     port_forward_adapter: nil, http_probe_adapter: nil, tcp_probe_adapter: nil,
                     image_resolver: nil,
                     **config_options)
        @config = Configuration.from(config, profile: profile, **config_options)
        @clock = clock
        @adapters = adapters.to_h.transform_keys(&:to_sym)
        {
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
        }.each do |source, target|
          @adapters[target] ||= @adapters[source] if @adapters.key?(source)
        end
        {
          namespace: namespace_adapter,
          cgroup: cgroup_adapter,
          filesystem: filesystem_adapter,
          security_adapter: security_adapter,
          security_probe: security_probe,
          process_adapter: process_adapter,
          pidfd: pidfd_adapter,
          exec: exec_adapter,
          attach: attach_adapter,
          port_forward: port_forward_adapter,
          http_probe: http_probe_adapter,
          tcp_probe: tcp_probe_adapter,
          image_resolver: image_resolver
        }.each { |key, value| @adapters[key] = value if value }
        @image_resolver = @adapters[:image_resolver]
        @mutex = Mutex.new
        @events = []
        @sandboxes = {}
        @requests = {}
        @oom_baselines = {}
        @oom_reported = {}
        @deferred_memory_limits = {}
        @userns_allocator = nil
        validate_host_adapters! if @config.host_profile?
        @journal = journal || default_journal
        @ledger = OwnershipLedger.new(journal: @journal, clock: @clock)
        @namespace = build_namespace
        @filesystem = build_filesystem
        @cgroup = build_cgroup
        @device_filter = build_device_filter
        @security = build_security
        @security_plans = {}
        @security_plan_mutex = Mutex.new
        @process_supervisor = build_process_supervisor
        validate_profile_capabilities! if @config.l3
      rescue Platform::Linux::CgroupV2::Error, Platform::Linux::Landlock::Error => error
        raise CapabilityError, "Native profile capability probe failed closed: #{error.message}"
      end

      def profile
        config.profile
      end

      def runtime_class
        config.runtime_class
      end

      def host_integration?
        config.host_profile?
      end

      def l3?
        config.l3
      end

      attr_reader :capability_probe, :config, :ledger, :namespace, :filesystem, :security, :process_supervisor, :events, :image_resolver

      def validate_config!
        config.validate!
      end

      # Creates all sandbox resources while keeping the workload gate closed.
      # No process is started before the returned sandbox reaches
      # WorkloadStopped and a container explicitly calls start_container.
      def run_sandbox(sandbox_config = {}, runtime_class: nil, request_id: nil, id: nil, **options)
        runtime_class ||= config.runtime_class
        validate_runtime_class!(runtime_class)
        input = normalize_hash(sandbox_config)
        input.merge!(normalize_hash(options))
        request = String(request_id || input["request_id"] || input[:request_id] || id || "request-#{SecureRandom.hex(12)}")
        existing_id = @mutex.synchronize { @requests[request] }
        if existing_id
          existing = @mutex.synchronize { @sandboxes[existing_id] }
          if existing
            if %i[cleanup_pending state_unknown rolling_back stopping].include?(existing.state)
              raise RecoveryRequired, "request #{request} is waiting for durable recovery (#{existing.state})"
            end

            return existing_id
          end
        end

        input = resolve_images(input)
        # QoS is derived from the Pod spec exactly once (v1.36.2
        # ComputePodQOS) and pinned into the config so replays and the
        # container cgroup path agree on the class.
        input["qos"] = normalize_qos(input)
        validate_sandbox_input!(input)
        durable = if @ledger.respond_to?(:operation_for_request)
                    @ledger.operation_for_request(request)
                  else
                    @ledger.operations.find do |operation|
                      ledger_value(operation, :request_id).to_s == request
                    end
                  end
        if durable
          durable_config_digest = ledger_value(durable, :config_digest)
          raise OwnershipConflict, "request #{request} was replayed with different intent" unless durable_config_digest == digest(input)

          durable_result = ledger_value(durable, :result)
          durable_id = (durable_result["sandbox_id"] || durable_result[:sandbox_id] if durable_result.is_a?(Hash))
          durable_id ||= ledger_value(durable, :target_id)
          durable_id ||= ledger_value(durable, :id)
          durable_state = ledger_value(durable, :state)
          if %w[StateUnknown CleanupPending].include?(durable_state)
            raise RecoveryRequired, "request #{request} is waiting for durable recovery (#{durable_state})"
          end

          if durable_id && %w[WorkloadStopped Running Stopping Stopped Removed].include?(durable_state)
            @mutex.synchronize { @requests[request] = durable_id }
            return durable_id
          end
          raise RecoveryRequired, "request #{request} has a durable operation without a replayable result"
        end

        sandbox_id = String(id || input["id"] || input[:id] || generated_sandbox_id(input))
        identity = "sandbox:#{sandbox_id}:#{Digest::SHA256.hexdigest(sandbox_id)[0, 16]}"
        sandbox = Sandbox.new(id: sandbox_id, identity: identity, config: immutable(input), clock: @clock)
        @mutex.synchronize do
          raise Error, "sandbox #{sandbox_id} already exists" if @sandboxes.key?(sandbox_id)

          @sandboxes[sandbox_id] = sandbox
          @requests[request] = sandbox_id
        end
        operation = @ledger.begin_operation(operation_id: sandbox_id, owner: identity,
                                            config_digest: digest(input), request_id: request)

        advance(sandbox, operation, :validated)
        image_digest = pin_image(input)
        advance(sandbox, operation, :image_pinned)
        # The user-namespace range is allocated before the first filesystem
        # effect so the workspace can be owned by the Pod's mapped root.
        namespace_spec = namespace_spec_for(input, identity)
        workspace_owner = workspace_owner_for(namespace_spec)
        workspace = @filesystem.prepare(id: sandbox_id, image_digest: image_digest, lowerdirs: input["lowerdirs"] || input[:lowerdirs] || [],
                                        read_only: input["read_only_root_filesystem"] == true, owner: workspace_owner)
        claim(operation, kind: "workspace", id: sandbox_id, identity: workspace.identity,
                         metadata: workspace_metadata(workspace))
        sandbox.set_resources(workspace: workspace)
        advance(sandbox, operation, :workspace_allocated)

        namespace = @namespace.create(id: sandbox_id, spec: namespace_spec, identity: "namespace:#{sandbox_id}")
        claim(operation, kind: "namespace", id: sandbox_id, identity: namespace.identity, metadata: namespace.to_h)
        sandbox.set_resources(namespace: namespace)
        @filesystem.activate(workspace, namespace: namespace) if @filesystem.respond_to?(:activate)
        # Refresh the claim after activation.  A mount syscall return value is
        # not a stable ownership proof; the adapter must read back mount ID,
        # target, and filesystem from the holder namespace before we persist
        # the workspace as owned.
        claim(operation, kind: "workspace", id: sandbox_id, identity: workspace.identity,
                         metadata: workspace_metadata(workspace))
        security_plan, = security_plan_for(input["security_context"] || input[:security_context] || config.security_context)
        sandbox.set_resources(security_plan: security_plan)
        record(:isolation_created, sandbox_id: sandbox_id, namespace: namespace.to_h, security_steps: security_plan.step_names.map(&:to_s))
        advance(sandbox, operation, :isolation_created)

        limits = input["limits"] || input[:limits] || config.limits
        pod_limits = pod_cgroup_limits(input)
        # The Pod ceiling constrains the container cgroups nested under it, so
        # it is deferred for the same reason the container ceiling is: the
        # bootstrap that sets up the first container lives in that hierarchy
        # and allocates while it works.  See #apply_deferred_memory_limits.
        deferred_pod_memory = normalize_hash(pod_limits).select { |name, _| DEFERRED_LIMIT_FILES.include?(name.to_s) }
        initial_pod_limits = normalize_hash(pod_limits).reject { |name, _| DEFERRED_LIMIT_FILES.include?(name.to_s) }
        @mutex.synchronize { @deferred_memory_limits["pod:#{sandbox_id}"] = deferred_pod_memory } unless deferred_pod_memory.empty?
        # Creation, delegation, and limit application are one adapter call so
        # a rejected limit rolls the directory back before it can be claimed.
        cgroup = @cgroup.create(qos: normalize_qos(input), pod_id: sandbox_id, container_id: "sandbox",
                                identity: "cgroup:#{sandbox_id}",
                                limits: (limits.nil? || limits.empty? ? nil : limits),
                                pod_limits: (initial_pod_limits.empty? ? nil : initial_pod_limits))
        claim(operation, kind: "cgroup", id: sandbox_id, identity: cgroup.identity,
                         metadata: cgroup.to_h.merge("pod_limits" => pod_limits, "qos" => normalize_qos(input)))
        sandbox.set_resources(cgroup: cgroup)
        record(:resources_attached, sandbox_id: sandbox_id, cgroup: cgroup.to_h)
        advance(sandbox, operation, :resources_attached)

        advance(sandbox, operation, :workload_stopped)
        record(:workload_gate_closed, sandbox_id: sandbox_id)
        if @ledger.respond_to?(:set_result)
          @ledger.set_result(operation.id, {
                               "sandbox_id" => sandbox_id,
                               "identity" => identity,
                               "runtime_class" => runtime_class
                             })
        end
        sandbox_id
      rescue StandardError => error
        rollback_sandbox(sandbox, operation, original_error: error) if sandbox && operation
        raise
      end

      def stop_sandbox(value, timeout: 5.0)
        sandbox = sandbox(value)
        operation = @ledger.operation(sandbox.id) || raise(Error, "sandbox operation is missing")
        if sandbox.state == :cleanup_pending
          sandbox.transition(:rolling_back)
          @ledger.transition(operation_id: sandbox.id, to: "RollingBack") if operation.state == "CleanupPending"
          cleanup_sandbox_resources(sandbox, operation)
          sandbox.transition(:stopped)
          @ledger.transition(operation_id: sandbox.id, to: "Stopped") if @ledger.operation(sandbox.id)&.state == "RollingBack"
          record(:sandbox_stopped, sandbox_id: sandbox.id)
          return true
        end
        if sandbox.state == :workload_stopped
          sandbox.transition(:rolling_back)
          @ledger.transition(operation_id: sandbox.id, to: "RollingBack") if operation.state == "WorkloadStopped"
          cleanup_sandbox_resources(sandbox, operation)
          sandbox.transition(:stopped)
          @ledger.transition(operation_id: sandbox.id, to: "Stopped") if @ledger.operation(sandbox.id)&.state == "RollingBack"
          record(:sandbox_stopped, sandbox_id: sandbox.id)
          return true
        end
        sandbox.transition(:stopping) if sandbox.state == :running
        # RuntimeLifecycle.tla BeginStopping: Running -> Stopping records
        # liveProcess = FALSE with ownership unchanged.  The durable Stopping
        # transition is therefore written only after every workload process
        # has been confirmed dead (supervisor wait/pidfd), and the process
        # ledger claims stay owned until cleanup releases them in Stopped
        # (CleanupOne).  A crash between the kill and this record leaves the
        # ledger in Running with a dead process, which recovery resolves
        # through StateUnknown -> Stopping exactly as the model does.
        sandbox.containers.each do |container_hash|
          container_id = container_hash.fetch("id")
          container = sandbox.container(container_id)
          stop_container(container, timeout: timeout, release_process: false) if container.state == :running
        end
        current_operation = @ledger.operation(sandbox.id)
        @ledger.transition(operation_id: sandbox.id, to: "Stopping") if current_operation&.state == "Running"
        sandbox.transition(:stopped) if %i[stopping workload_stopped rolling_back].include?(sandbox.state)
        current_operation = @ledger.operation(sandbox.id)
        @ledger.transition(operation_id: sandbox.id, to: "Stopped") if current_operation && %w[Stopping RollingBack].include?(current_operation.state)
        record(:sandbox_stopped, sandbox_id: sandbox.id)
        true
      rescue Sandbox::Error => error
        raise InvalidState, error.message
      rescue StandardError => error
        mark_cleanup_pending(sandbox, operation, error)
        raise
      end

      def remove_sandbox(value)
        sandbox = begin
          sandbox(value)
        rescue Error => error
          # The sandbox is no longer known because an earlier removal finished
          # (the ledger records it Removed): removing it again is a no-op,
          # not a failure to retry for ever.
          return true if sandbox_removed?(value)

          raise error
        end
        stop_sandbox(sandbox) unless %i[stopped removed].include?(sandbox.state)
        return true if sandbox.state == :removed

        operation = @ledger.operation(sandbox.id) || raise(Error, "sandbox operation is missing")
        # Containers removed with their sandbox are deleted here: their
        # poststop hooks run now (remove_container already ran the others').
        sandbox.containers.each do |container_hash|
          run_poststop_hooks(sandbox, sandbox.container(container_hash.fetch("id")))
        rescue StandardError
          nil
        end
        cleanup_sandbox_resources(sandbox, operation) unless sandbox.resources_cleaned?
        sandbox.transition(:removed)
        @ledger.transition(operation_id: sandbox.id, to: "Removed") unless operation.state == "Removed"
        @mutex.synchronize { @sandboxes.delete(sandbox.id) }
        remove_sandbox_logs(sandbox)
        record(:sandbox_removed, sandbox_id: sandbox.id)
        true
      end

      # True when the ledger's operation for this sandbox reached Removed.
      def sandbox_removed?(value)
        id = value.respond_to?(:id) ? value.id : String(value)
        operation = @ledger.operation(String(id))
        !operation.nil? && operation.state.to_s == "Removed"
      rescue StandardError
        false
      end

      # kubelet removes /var/log/pods/<ns>_<name>_<uid> with the Pod; the
      # supervisor's per-container log directories (one per container id,
      # so a restarted container's predecessor keeps its own until here)
      # were kept for ever: 346 directories per worker after one round.
      # Every container of this sandbox is stopped and removed by now.
      def remove_sandbox_logs(sandbox)
        return unless config.log_root

        # Exact names, no glob: a glob over a log root holding hundreds of
        # directories was 4% of teardown CPU on its own.
        sandbox.container_ids_ever.each do |container_id|
          directory = File.join(config.log_root, "process-#{sandbox.id}-#{container_id}")
          FileUtils.rm_rf(directory) if File.directory?(directory)
        end
      rescue StandardError => error
        record(:sandbox_log_cleanup_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
      end

      def create_container(sandbox_value, spec, id: nil, request_id: nil)
        sandbox = sandbox(sandbox_value)
        raise InvalidState, "container creation requires a WorkloadStopped or Running sandbox" unless %i[workload_stopped running].include?(sandbox.state)

        input = resolve_container_spec(normalize_hash(spec), sandbox: sandbox)
        command = input["command"] || input[:command] || input["argv"] || input[:argv]
        validate_command!(command) if command
        input["mounts"] = normalize_mounts(input["mounts"] || input[:mounts]) if input["mounts"] || input[:mounts]
        # Container ids are node-unique (kubelet/CRI semantics): a bare
        # "container-1" repeated in every sandbox let a log or exec request
        # for one Pod reach another Pod's container.
        # Never derive the id from the LIVE COUNT: a restart removes the old
        # container first, so the count falls back and the new container takes
        # the removed one's id -- and with it the removed one's create-request
        # identity in the ledger, which answered the retry with a container
        # that no longer exists ("unknown container ...").  The sandbox's own
        # sequence only moves forward.
        container_id = String(id || input["id"] || input[:id] || sandbox.next_container_id)
        request = request_id || input["request_id"] || input[:request_id] || "create:#{sandbox.id}:#{container_id}"
        request_state = begin_native_request(request, operation: "container.create", input: {
                                               "sandbox_id" => sandbox.id, "container_id" => container_id, "spec" => input
                                             })
        if request_state&.state == "Completed"
          recorded_id = request_state.result.is_a?(Hash) ? (request_state.result["container_id"] || request_state.result[:container_id]) : nil
          return sandbox.container(recorded_id || container_id)
        end

        container = nil
        cgroup = nil
        begin
          container = sandbox.create_container(spec: input, id: container_id)
          qos = normalize_qos(sandbox.config)
          limits = container_cgroup_limits(input, qos: qos, pod: sandbox.config)
          # The memory ceiling is applied once the workload has replaced the
          # bootstrap; see #apply_deferred_memory_limits.
          deferred_memory = limits.select { |name, _| DEFERRED_LIMIT_FILES.include?(name.to_s) }
          initial_limits = limits.reject { |name, _| DEFERRED_LIMIT_FILES.include?(name.to_s) }
          unless deferred_memory.empty?
            @mutex.synchronize do
              @deferred_memory_limits[container_resource_id(sandbox, container)] = deferred_memory
            end
          end
          # The leaf drops the sandbox prefix the container id repeats: the
          # Pod directory above it already names the sandbox (and the Pod
          # UID), and a leaf that matched the same UID search made the Pod
          # cgroup ambiguous to anyone looking it up by UID.
          leaf = container.id.delete_prefix("#{sandbox.id}.")
          cgroup = @cgroup.create(qos: qos, pod_id: sandbox.id,
                                  container_id: leaf, identity: "cgroup:#{sandbox.id}:#{leaf}",
                                  limits: (initial_limits.empty? ? nil : initial_limits))
          plan, plan_digest = security_plan_for(container_security_context(input))
          attach_device_filter(sandbox, container, cgroup, input, plan)
          # Every container gets its own root filesystem from its own image.
          # The sandbox workspace overlays *all* of the Pod's images into one
          # tree, so a Pod mixing images (agnhost + a glibc image) ran each
          # container on a union where the busybox `sh` met the wrong
          # dynamic loader: "No such file or directory - execveat".
          workspace = prepare_container_workspace(sandbox, container, input)
          result = sandbox.update_container(container, cgroup: cgroup, security_plan: plan, workspace: workspace)
          record(:container_created, sandbox_id: sandbox.id, container_id: result.id, qos: qos, limits: limits)
          operation = @ledger.operation(sandbox.id)
          claim(operation, kind: "cgroup", id: container_resource_id(sandbox, result), identity: cgroup.identity,
                           # The spec is what startup reconstruction rebuilds the
                           # container from; the security plan is derived from it again
                           # there (reconstruct_one_sandbox!), so only its digest is
                           # recorded: the plan itself (the whole capability probe) was
                           # 22 KB per claim and most of the journal.
                           metadata: result.cgroup.to_h.merge(
                             "container_id" => result.id,
                             "limits" => limits,
                             "spec" => result.spec,
                             "security_context" => container_security_context(result.spec),
                             "security_plan_digest" => plan_digest
                           ))
          complete_native_request(request, state: "Completed", result: {"container_id" => result.id})
          result
        rescue StandardError => error
          begin
            detach_device_filter(sandbox, container_id, cgroup) if cgroup
            @cgroup.remove(cgroup, force: true) if cgroup
          rescue StandardError => cleanup_error
            record(:container_create_cleanup_error, sandbox_id: sandbox.id, container_id: container_id,
                                                    error: "#{cleanup_error.class}: #{cleanup_error.message}")
          end
          begin
            sandbox.remove_container(container) if container && container.state != :running
          rescue StandardError
            nil
          end
          begin
            operation = @ledger.operation(sandbox.id)
            resource = operation && ledger_resource_for(operation, "cgroup", container_resource_id(sandbox, container)) if container
            if resource && ledger_value(resource, :state).to_s != "Released"
              @ledger.release(operation_id: operation.id, kind: "cgroup", id: ledger_value(resource, :id),
                              identity: ledger_value(resource, :identity), force: true)
            end
          rescue StandardError => ledger_error
            record(:container_create_ledger_cleanup_error, sandbox_id: sandbox.id, container_id: container_id,
                                                           error: "#{ledger_error.class}: #{ledger_error.message}")
          end
          complete_native_request(request, state: "Failed", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
          raise
        end
      end

      def start_container(value, request_id: nil)
        sandbox, container = find_container(value)
        spec = container.spec
        request = request_id || spec["request_id"] || "start:#{sandbox.id}:#{container.id}"
        request_state = begin_native_request(request, operation: "container.start", input: {
                                               "sandbox_id" => sandbox.id, "container_id" => container.id, "spec" => spec
                                             })
        return sandbox.container(container.id) if request_state&.state == "Completed"

        unless container.state == :created
          error = InvalidState.new("container #{container.id} is not startable")
          complete_native_request(request, state: "Failed", error: error_payload(error))
          raise error
        end
        command = spec["command"] || spec["argv"]
        if command.nil?
          raise FailClosed, "container image config did not provide an executable command" if config.host_profile? || spec["image"] || spec["resolved_image"]

          command = ["/bin/true"]
        end
        process = nil
        gate_released = false
        begin
          resolved_rootfs = workload_rootfs(sandbox, spec, container: container)
          command = resolve_executable(command, rootfs: resolved_rootfs, env: spec["env"] || {})
          # CDI container edits may carry OCI hooks.  A supervisor that builds
          # the container in a child runs the in-container stages there and
          # calls back for the runtime-namespace ones once the namespaces
          # exist; otherwise (no container namespaces) every pre-start stage
          # runs here, before the gate.
          hooks = container_hooks(spec)
          hook_plan = hooks.empty? ? nil : prepare_hook_bundle(sandbox, container, spec, command, resolved_rootfs, hooks)
          hooks_in_child = hook_plan && @process_supervisor.respond_to?(:runs_container_hooks?) && @process_supervisor.runs_container_hooks?
          hook_options = {}
          if hooks_in_child
            hook_options[:container_hooks] = {
              "hooks" => hooks.slice(*Hooks::IN_CONTAINER), "state" => hook_plan[:state],
              "runtime" => ->(pid) { run_hooks(hooks, Hooks::RUNTIME_CREATE, hook_plan, pid: pid) }
            }
          end
          process = @process_supervisor.spawn(
            command: command,
            env: spec["env"] || {},
            cwd: spec["cwd"],
            rootfs: resolved_rootfs,
            mounts: resolved_rootfs ? Array(spec["mounts"]) : [],
            security_plan: container.security_plan,
            namespace: sandbox.namespace,
            resource_id: "process:#{sandbox.id}:#{container.id}",
            id: "process-#{sandbox.id}-#{container.id}",
            cgroup: container.cgroup,
            # v1.Container stdin: without it the process reads /dev/null.
            stdin: spec["stdin"] == true,
            **hook_options
          )
          # Attach the wrapper before releasing the gate.  The production
          # ProcessGateAdapter forks the final workload only after the gate;
          # cgroup inheritance therefore places the actual workload in this
          # exact cgroup before its first instruction executes.
          @cgroup.attach(container.cgroup, pid: process.pid) if process.respond_to?(:pid) && container.cgroup
          apply_oom_score_adj(process, spec)
          record_oom_baseline(sandbox, container)
          unless @process_supervisor.respond_to?(:security_applied_in_child?) && @process_supervisor.security_applied_in_child?
            @security.apply(container.security_plan,
                            probe: @security_probe)
          end
          if hook_plan && !hooks_in_child
            run_hooks(hooks, Hooks::RUNTIME_CREATE + Hooks::IN_CONTAINER, hook_plan, pid: process.respond_to?(:pid) ? process.pid : nil)
          end
          started = @process_supervisor.release_gate(process)
          gate_released = true
          # release_gate returns only once the bootstrap's close-on-exec status
          # pipe reached EOF, which happens exactly when execve succeeded: the
          # interpreter's pages are gone and what remains charged to this
          # cgroup is the workload itself.
          apply_deferred_memory_limits(sandbox, container)
          running = sandbox.update_container(container, process: started, state: :running)
          operation = @ledger.operation(sandbox.id)
          process_hash = started.respond_to?(:to_h) ? started.to_h : {}
          process_identity = process_identity_for(sandbox, container, process_hash)
          claim(operation, kind: "process", id: container_resource_id(sandbox, container), identity: process_identity,
                           metadata: process_hash.merge("managed_by" => "rubernetes-native", "live" => true))
          if sandbox.state == :workload_stopped
            sandbox.transition(:running)
            @ledger.transition(operation_id: sandbox.id, to: "Running") if operation&.state == "WorkloadStopped"
          end
          complete_native_request(request, state: "Completed", result: {
                                    "container_id" => running.id, "process_id" => process_identity
                                  })
          record(:container_started, sandbox_id: sandbox.id, container_id: running.id,
                                     pid: process_hash["workload_pid"] || process_hash["pid"],
                                     wrapper_pid: process_hash["pid"])
          if hook_plan
            run_post_hooks(sandbox, running, hooks, hook_plan, "poststart",
                           pid: process_hash["workload_pid"] || process_hash["pid"])
          end
          running
        rescue StandardError => error
          @process_supervisor.stop(process, timeout: 1.0) if process
          begin
            operation = @ledger.operation(sandbox.id)
            resource = operation && ledger_resource_for(operation, "process", container_resource_id(sandbox, container))
            if resource && ledger_value(resource, :state).to_s != "Released"
              @ledger.release(operation_id: operation.id, kind: "process", id: ledger_value(resource, :id),
                              identity: ledger_value(resource, :identity), force: true)
            end
          rescue StandardError => ledger_error
            record(:container_start_ledger_cleanup_error, sandbox_id: sandbox.id, container_id: container.id,
                                                          error: "#{ledger_error.class}: #{ledger_error.message}")
          end
          complete_native_request(request, state: "Failed", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
          raise FailClosed, "container start failed before workload gate release: #{error.message}"
        ensure
          # A forked workload waiting on its gate must never outlive a start
          # that did not release it.  The rescue above covers exceptions, but
          # a pod worker killed or timed out mid-start (Thread#kill, Timeout)
          # unwinds through ensure only -- and left a pre-exec child sleeping
          # on the gate for good: a full copy of the agent (2.7 GB RSS)
          # parked in select for 40 hours on worker-1.
          if process && !gate_released
            begin
              @process_supervisor.stop(process, timeout: 1.0)
            rescue StandardError
              nil
            end
          end
        end
      rescue StandardError => error
        raise error if error.is_a?(FailClosed) || error.is_a?(RecoveryRequired) || error.is_a?(OwnershipConflict)

        raise FailClosed, "container start failed before workload gate release: #{error.message}"
      end

      def stop_container(value, timeout: 5.0, request_id: nil, release_process: true)
        sandbox, container = find_container(value)
        request = request_id || "stop:#{sandbox.id}:#{container.id}"
        request_state = begin_native_request(request, operation: "container.stop", input: {
                                               "sandbox_id" => sandbox.id, "container_id" => container.id, "timeout" => timeout
                                             })
        return sandbox.container(container.id) if request_state&.state == "Completed"

        if container.state == :stopped
          complete_native_request(request, state: "Completed", result: {"container_id" => container.id, "state" => "stopped"})
          return container
        end
        unless container.process
          # A container that did start and then lost its process handle may
          # still be running: that stays fail-closed and goes to recovery.
          if container_started?(sandbox, container)
            error = InvalidState.new("container #{container.id} has not started")
            complete_native_request(request, state: "Failed", error: error_payload(error))
            raise error
          end

          # Nothing has ever run under this id, so there is nothing to stop
          # yet -- but a container created moments before its start may be
          # started right after this call.  Recording either a failure or a
          # success would settle the request forever and make every later stop
          # replay that verdict, so the pod could never reach a terminal
          # phase.  Leave it replayable, exactly as a pending cleanup is.
          complete_native_request(request, state: "CleanupPending")
          return container
        end

        begin
          @process_supervisor.stop(container.process, timeout: timeout, resource_id: "process:#{sandbox.id}:#{container.id}")
          oom_reason = detect_oom(sandbox, container)
          @cgroup.kill(container.cgroup) if container.cgroup && @cgroup.respond_to?(:kill)
          process_hash = container.process.respond_to?(:to_h) ? container.process.to_h : {}
          @process_supervisor.close(container.process)
          stopped = sandbox.update_container(container, state: :stopped)
          operation = @ledger.operation(sandbox.id)
          release_process_resource(operation, sandbox, stopped, process_hash) if release_process
          complete_native_request(request, state: "Completed",
                                           result: {"container_id" => stopped.id, "state" => "stopped", "reason" => oom_reason}.compact)
          record(:container_stopped, sandbox_id: sandbox.id, container_id: stopped.id, reason: oom_reason)
          stopped
        rescue StandardError => error
          complete_native_request(request, state: "Failed", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
          raise
        end
      end

      def remove_container(value, request_id: nil)
        begin
          sandbox, container = find_container(value)
        rescue Error
          # CRI RemoveContainer is idempotent: "This call is idempotent, and
          # must not return an error if the container has already been
          # removed" (cri-api runtime.proto).  Treating a container that is
          # already gone as a cleanup failure left the Pod in CleanupPending,
          # which stops the final delete: the Pod stayed Terminating in the API
          # for ever and every spec that waits for it to disappear timed out.
          return true
        end
        request = request_id || "remove:#{sandbox.id}:#{container.id}"
        request_state = begin_native_request(request, operation: "container.remove", input: {
                                               "sandbox_id" => sandbox.id, "container_id" => container.id
                                             })
        return true if request_state&.state == "Completed"

        begin
          stop_container(container, request_id: "#{request}:stop") if container.state == :running
          process_hash = container.process.respond_to?(:to_h) ? container.process.to_h : {}
          @process_supervisor.close(container.process) if container.process
          if container.cgroup
            detach_device_filter(sandbox, container.id, container.cgroup)
            removed = @cgroup.remove(container.cgroup, force: false)
            raise ResourceError, "container cgroup cleanup returned false" if removed == false
          end
          run_poststop_hooks(sandbox, container)
          if container.respond_to?(:workspace) && container.workspace
            cleaned = @filesystem.cleanup(container.workspace)
            raise ResourceError, "container workspace cleanup returned false" if cleaned == false
          end
          operation = @ledger.operation(sandbox.id)
          release_container_resource(operation, sandbox, container, process_hash)
          sandbox.remove_container(container)
          complete_native_request(request, state: "Completed", result: {"container_id" => container.id, "removed" => true})
          true
        rescue StandardError => error
          mark_container_cleanup_pending(sandbox, container, operation: @ledger.operation(sandbox.id), error: error)
          complete_native_request(request, state: "CleanupPending", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
          raise
        end
      end

      def container_status(value)
        sandbox, container = find_container(value)
        # A workload that exits on its own is still recorded as running until
        # someone reaps it.  Status is where that is noticed: without this the
        # runtime reports a finished container as running forever, so its Pod
        # never reaches a confirmed stop and the node re-creates it on every
        # sync.  A non-blocking wait is proof of exit, never a guess.
        reap_exited(sandbox, container)
        sandbox, container = find_container(value)
        status = container.to_h.merge("oom_killed" => @mutex.synchronize { @oom_reported.key?(container_resource_id(sandbox, container)) })
        if container.state == :stopped && container.process.respond_to?(:exit_status)
          exit_code = container.process.exit_status
          if exit_code.nil? && container.process.respond_to?(:term_signal) && container.process.term_signal
            exit_code = 128 + Integer(container.process.term_signal)
          end
          status["exitCode"] = exit_code
          status["terminated"] = {"exitCode" => exit_code, "signal" => container.process.respond_to?(:term_signal) ? container.process.term_signal : nil,
                                  "reason" => status["oom_killed"] ? "OOMKilled" : nil}.compact
        end
        status
      end

      def reap_exited(_sandbox, container)
        return unless container.state == :running && container.process

        wait_container(container.id, timeout: 0)
      rescue StandardError
        nil
      end

      # Kernel-observed limits for a container cgroup, for status/evidence.
      def container_cgroup_readback(value)
        _sandbox, container = find_container(value)
        return {} unless container.cgroup && @cgroup.respond_to?(:limits_readback)

        @cgroup.limits_readback(container.cgroup)
      end

      # Execute a new process only through an adapter that explicitly owns the
      # namespace/cgroup entry operation.  The Native backend cannot safely
      # infer that operation from a host PID, so an absent adapter is a hard
      # capability failure rather than a host-side fallback.
      def exec(value, command, tty: false, **options)
        sandbox, container = find_container(value)
        raise InvalidState, "exec requires a running container" unless container.state == :running

        command = validate_command!(command)
        adapter = @adapters[:exec]
        raise CapabilityError, "exec adapter is not configured" unless adapter

        result = invoke(adapter, :exec, sandbox: sandbox, container: container, command: command, tty: tty, **options)
        validate_duplex_result!(result, operation: :exec, options: options)
        result
      end

      # Attach exposes only the already-running process streams.  This default
      # is valid for a process supervisor that returned real streams; pure
      # fake processes have no stream and therefore fail closed.
      def attach(value, tty: false, **options)
        sandbox, container = find_container(value)
        raise InvalidState, "attach requires a running container" unless container.state == :running

        result = if (adapter = @adapters[:attach])
                   invoke(adapter, :attach, sandbox: sandbox, container: container, tty: tty, **options)
                 else
                   attach_process_streams(container, tty: tty, **options)
                 end
        validate_duplex_result!(result, operation: :attach, options: options)
        result
      end

      # Port-forward requires a connector because the runtime owns the target
      # network namespace.  It never falls back to a host socket.
      def port_forward(value, ports, timeout: 30.0, stream: nil, **)
        sandbox, container = find_container(value)
        raise InvalidState, "port-forward requires a running container" unless container.state == :running

        normalized_ports = normalize_ports(ports)
        timeout = normalize_timeout(timeout)
        adapter = @adapters[:port_forward]
        raise CapabilityError, "port-forward connector is not configured" unless adapter

        result = invoke(adapter, :port_forward, sandbox: sandbox, container: container,
                                                ports: normalized_ports, timeout: timeout, stream: stream, **)
        validate_duplex_result!(result, operation: :port_forward, options: {stdin: true, stdout: true})
        result
      end

      # spec.securityContext.sysctls: written inside the sandbox's network
      # and IPC namespaces by the connector, which owns namespace entry.
      def apply_sysctls(value, sysctls)
        sandbox = sandbox(value)
        entries = Array(sysctls).map { |entry| normalize_hash(entry) }.reject { |entry| entry["name"].to_s.empty? }
        return [] if entries.empty?

        adapter = @adapters[:sysctl] || @adapters[:http_probe]
        raise CapabilityError, "sysctl adapter is not configured" unless adapter && adapter.respond_to?(:apply_sysctls)

        invoke(adapter, :apply_sysctls, sandbox: sandbox, sysctls: entries)
      end

      # Probe effects are explicit runtime capabilities.  ProbeManager may use
      # these methods when no external client was injected, but an unavailable
      # connector remains an observable failure.
      def http_get(value, definition, timeout: 1.0, **)
        sandbox, container = find_container(value)
        raise InvalidState, "HTTP probe requires a running container" unless container.state == :running

        adapter = @adapters[:http_probe]
        raise CapabilityError, "HTTP probe connector is not configured" unless adapter

        invoke(adapter, :http_get, sandbox: sandbox, container: container,
                                   definition: normalize_hash(definition), timeout: normalize_timeout(timeout), **)
      end

      # gRPC health probes join the Pod's network namespace through the same
      # connector as HTTP probes; the agent's own namespace cannot reach a
      # Pod's loopback (or, on this host, its IP at all).
      def grpc_check(value, definition, timeout: 1.0, **)
        sandbox, container = find_container(value)
        raise InvalidState, "gRPC probe requires a running container" unless container.state == :running

        adapter = @adapters[:http_probe]
        raise CapabilityError, "gRPC probe connector is not configured" unless adapter.respond_to?(:grpc_check)

        invoke(adapter, :grpc_check, sandbox: sandbox, container: container,
                                     definition: normalize_hash(definition), timeout: normalize_timeout(timeout), **)
      end

      def tcp_socket(value, definition, timeout: 1.0, **)
        sandbox, container = find_container(value)
        raise InvalidState, "TCP probe requires a running container" unless container.state == :running

        adapter = @adapters[:tcp_probe]
        raise CapabilityError, "TCP probe connector is not configured" unless adapter

        invoke(adapter, :tcp_socket, sandbox: sandbox, container: container,
                                     definition: normalize_hash(definition), timeout: normalize_timeout(timeout), **)
      end

      def wait_container(value, timeout: nil)
        sandbox, container = find_container(value)
        raise InvalidState, "wait requires a running container" unless container.state == :running

        process = container.process
        raise InvalidState, "container #{container.id} has no process handle" unless process

        result = @process_supervisor.wait(process, timeout: timeout, resource_id: "process:#{sandbox.id}:#{container.id}")
        return {"state" => "running", "exitCode" => nil}.freeze unless result

        exit_code = if result.respond_to?(:exit_status) && !result.exit_status.nil?
                      Integer(result.exit_status)
                    elsif result.respond_to?(:term_signal) && !result.term_signal.nil?
                      128 + Integer(result.term_signal)
                    end
        oom_reason = detect_oom(sandbox, container)
        # The container keeps the handle that carries the exit: the
        # supervisor's own copy is closed below, and status readers (the node's
        # relist, stop confirmation) need the exit code afterwards.
        exited = if process.respond_to?(:with) && process.respond_to?(:exit_status)
                   process.with(state: :stopped, exit_status: result.respond_to?(:exit_status) ? result.exit_status : nil,
                                term_signal: result.respond_to?(:term_signal) ? result.term_signal : nil)
                 else
                   process
                 end
        stopped = sandbox.update_container(container, state: :stopped, process: exited)
        process_hash = process.respond_to?(:to_h) ? process.to_h : {}
        operation = @ledger.operation(sandbox.id)
        release_process_resource(operation, sandbox, stopped, process_hash)
        @process_supervisor.close(process)
        record(:container_waited, sandbox_id: sandbox.id, container_id: stopped.id, exit_code: exit_code, reason: oom_reason)
        {"state" => "terminated", "exitCode" => exit_code, "signal" => result.respond_to?(:term_signal) ? result.term_signal : nil,
         "reason" => oom_reason}.freeze
      end

      # A container's log is BOTH streams: the Pod log API has no way to ask
      # for only one, and kubelet returns whatever the container wrote to
      # either (the CRI tags each line with its stream and ReadLogs returns
      # them all).  Serving stdout alone hid every diagnostic a workload
      # writes to stderr.
      def logs(value, follow: false, since: nil, tail: nil, stream: :all, timestamps: false)
        sandbox, container = find_container(value)
        # A container that ran and exited (a restart being backed off, the
        # querier of the DNS specs whose loop has finished) keeps its log with
        # the supervisor under its process id even after the handle was
        # released; kubelet serves that log until the container is removed.
        handle = container.process || (container.state == :stopped ? "process-#{sandbox.id}-#{container.id}" : nil)
        raise InvalidState, "logs require a started container" unless handle

        @process_supervisor.logs(handle, follow: follow, since: since, tail: tail, stream: stream,
                                         timestamps: timestamps)
      end

      def stats(value)
        _sandbox, container = find_container(value)
        raise InvalidState, "stats require a started container" unless container.process

        @process_supervisor.stats(container.process)
      end

      # Returns the resources currently accounted for by the native adapters.
      # It deliberately never reads the ledger: the caller needs an honest
      # view of kernel-side state in order to detect a missing or duplicated
      # durable ownership record after a crash.
      def resource_inventory
        source = @adapters[:observer]
        return normalize_inventory(invoke_observer(source)) if source

        resources = []
        @mutex.synchronize do
          @sandboxes.values.each do |sandbox|
            owner = sandbox.identity
            live = sandbox.state != :removed
            add_inventory_resource(resources, "workspace", sandbox.workspace, owner: owner,
                                                                              live: live, parent: sandbox.id)
            add_inventory_resource(resources, "namespace", sandbox.namespace, owner: owner,
                                                                              live: live, parent: sandbox.id)
            add_inventory_resource(resources, "cgroup", sandbox.cgroup, owner: owner,
                                                                        live: live, parent: sandbox.id)
            sandbox.containers.each do |container_hash|
              if container_hash["workspace"]
                add_inventory_resource(resources, "workspace", container_hash["workspace"], owner: owner,
                                                                                            live: live, parent: sandbox.id)
              end
              container = sandbox.container(container_hash.fetch("id"))
              if container.cgroup
                add_inventory_resource(resources, "cgroup", container.cgroup, owner: owner,
                                                                              live: container.state == :running, parent: sandbox.id)
              end
              next unless container.process

              process = container.process.respond_to?(:to_h) ? container.process.to_h : container.process
              process_id = container_resource_id(sandbox, container)
              process_identity = process_identity_for(sandbox, container, process)
              resources << managed_inventory_resource(
                "process", process_id, process_identity, owner,
                metadata: {"parent" => sandbox.id, "container_id" => container.id,
                           "live" => container.state == :running, "managed_by" => "rubernetes-native",
                           "id" => process["id"] || process[:id],
                           "command" => process["command"] || process[:command],
                           "state" => process["state"] || process[:state],
                           "started_at" => process["started_at"] || process[:started_at],
                           "pid" => process["workload_pid"] || process[:workload_pid] || process["pid"] || process[:pid],
                           "wrapper_pid" => process["pid"] || process[:pid],
                           "start_time" => process["workload_start_time"] || process[:workload_start_time],
                           "executable_digest" => process["workload_executable_digest"] || process[:workload_executable_digest],
                           "pidfd" => process["workload_pidfd"] || process[:workload_pidfd] || process["pidfd"] || process[:pidfd],
                           "cgroup" => container.cgroup&.path}
              )
            end
          end
        end

        add_component_inventory(resources, @filesystem, "workspace")
        add_component_inventory(resources, @namespace, "namespace")
        add_component_inventory(resources, @cgroup, "cgroup")
        normalize_inventory(resources)
      end

      alias list_resources resource_inventory
      alias observe_resources resource_inventory

      # Removes one adapter-owned resource after the caller has established
      # that it is a dead, managed resource with a stable identity.  Unknown
      # or live resources fail closed and are never delegated to an adapter.
      def cleanup_resource(resource)
        value = normalize_inventory([resource]).fetch(0)
        metadata = value.fetch("metadata", {})
        raise RecoveryRequired, "cannot cleanup a live native resource #{resource_key(value)}" unless metadata["live"] == false
        unless metadata["managed_by"] == "rubernetes-native" || @adapters[:cleaner]
          raise CapabilityError, "native resource #{resource_key(value)} has no trusted cleanup owner"
        end

        if (cleaner = @adapters[:cleaner])
          return invoke_cleaner(cleaner, value)
        end

        kind = value.fetch("kind")
        case kind
        when "workspace"
          handle = @filesystem.workspaces.find do |entry|
            entry["id"].to_s == value.fetch("id") && entry["identity"] == value.fetch("identity")
          end
          workspace = if handle
                        @filesystem.workspaces.find { |entry| entry["id"].to_s == value.fetch("id") }
                      else
                        # A dead operation's workspace that this (restarted)
                        # runtime never adopted: the ledger's own record says
                        # where it is.
                        orphan_workspace(value, metadata)
                      end
          raise RecoveryRequired, "workspace #{resource_key(value)} is not present in this runtime" unless workspace

          @filesystem.cleanup(Native::Filesystem::Workspace.new(**workspace.transform_keys(&:to_sym)))
        when "namespace"
          handle = @namespace.lookup(value.fetch("id"))
          unless handle.identity == value.fetch("identity")
            raise Native::Namespace::Error,
                  "namespace #{resource_key(value)} identity changed"
          end

          @namespace.destroy(handle)
        when "cgroup"
          handle = begin
            @cgroup.lookup(metadata["path"] || value.fetch("id"))
          rescue Platform::Linux::CgroupV2::Error
            orphan_cgroup(value, metadata) || raise
          end
          unless handle.identity == value.fetch("identity")
            raise Platform::Linux::CgroupV2::Error,
                  "cgroup #{resource_key(value)} identity changed"
          end

          expected_inode = metadata["cgroup_inode"] || metadata["cgroup_id"]
          if expected_inode && handle.respond_to?(:path)
            actual_inode = File.stat(handle.path).ino
            unless actual_inode == Integer(expected_inode)
              raise Platform::Linux::CgroupV2::Error,
                    "cgroup #{resource_key(value)} kernel identity changed"
            end
          end

          @cgroup.remove(handle, force: true)
        when "process"
          expected = value.fetch("identity")
          metadata_pid = metadata["pid"] || metadata["workload_pid"]
          metadata_start = metadata["start_time"] || metadata["workload_start_time"]
          handle = @process_supervisor.handles.values.find do |entry|
            next true if entry.id.to_s == value.fetch("id")

            observed = entry.respond_to?(:to_h) ? entry.to_h : {}
            candidate_pid = observed["workload_pid"] || observed["pid"]
            candidate_start = observed["workload_start_time"]
            candidate_digest = observed["workload_executable_digest"] || observed["executable_digest"]
            candidate_identity = if candidate_pid
                                   "process:#{metadata["parent"]}:#{metadata["container_id"]}:#{candidate_pid}:#{candidate_start || "unknown"}:#{candidate_digest || "unknown"}"
                                 end
            candidate_identity == expected &&
              (metadata_pid.nil? || candidate_pid.to_i == metadata_pid.to_i) &&
              (metadata_start.nil? || candidate_start.to_i == metadata_start.to_i)
          end
          raise RecoveryRequired, "process #{resource_key(value)} is not present in this runtime" unless handle

          if handle.running? || handle.state == :created
            @process_supervisor.stop(handle, timeout: 1.0,
                                             resource_id: value.fetch("identity"))
          end
          @process_supervisor.close(handle)
        else
          raise CapabilityError, "native cleanup does not support resource kind #{kind.inspect}"
        end
        true
      end

      # The workspace a ledger record describes, when its identity is exactly
      # the record's: never adopted after a restart, so only the ledger knows it.
      def orphan_workspace(value, metadata)
        fields = %w[id root upper work identity image_digest]
        return nil unless fields.all? { |field| metadata.key?(field) } && metadata["identity"] == value.fetch("identity")

        metadata.slice(*fields)
      end

      # A cgroup under this runtime's hierarchy that a dead operation left
      # behind; the caller still checks its identity and inode.
      def orphan_cgroup(value, metadata)
        path = metadata["path"].to_s
        root = @cgroup.respond_to?(:root) ? @cgroup.root.to_s : ""
        return nil if path.empty? || root.empty? || !path.start_with?("#{root}/") || !File.directory?(path)

        Platform::Linux::CgroupV2::Handle.new(path: path, qos: metadata["qos"], pod_id: metadata["pod_id"],
                                              container_id: metadata["container_id"], identity: value.fetch("identity"))
      end

      def recover(observer: nil, cleaner: nil, orphan_predicate: nil)
        # A post-crash in-memory inventory is not evidence of kernel state.
        # Recovery may release durable ownership only when an external/native
        # observer was explicitly wired (or supplied for this invocation).
        observer ||= @adapters[:observer]
        raise RecoveryRequired, "native runtime recovery requires an explicit resource observer" unless observer
        if observer.respond_to?(:external_observer?) && !observer.external_observer?
          raise RecoveryRequired, "native runtime recovery requires an external resource observer"
        end

        cleaner ||= @adapters[:cleaner] || method(:cleanup_resource)
        observed_snapshot = normalize_inventory(invoke_observer(observer))
        mark_dead_operations_for_recovery!(observed_snapshot)
        observed_snapshot = quiesce_dead_operations!(observed_snapshot, observer)
        reconstruct_sandboxes_from_observed!(observed_snapshot)
        recovery = Support::Recovery.new(
          ledger: ledger,
          observer: -> { observed_snapshot },
          cleaner: ->(resource) { invoke_cleaner(cleaner, resource) },
          orphan_predicate: orphan_predicate
        )
        result = recovery.reconcile
        record(:recovery, result: result.to_h)
        result
      end

      private

      # A complete external inventory can prove that a durable operation lost
      # one of its exact kernel identities, or that the identity remains but
      # is dead.  Persist StateUnknown before cleanup so Recovery can release
      # only the resources from that operation.  Identity mismatches are not
      # downgraded to death: they remain fatal evidence of possible PID/path
      # reuse and are never cleaned automatically.
      def mark_dead_operations_for_recovery!(observed)
        observed_by_key = observed.to_h { |entry| [resource_key(entry), entry] }
        @ledger.operations.each do |operation_value|
          operation = operation_value.respond_to?(:to_h) ? operation_value.to_h : operation_value
          state = String(operation.fetch("state") { operation[:state] })
          next if %w[RollingBack CleanupPending StateUnknown Stopped Removed].include?(state)

          owner = String(operation.fetch("owner") { operation[:owner] })
          resources = normalize_inventory(@ledger.resources(owner: owner, include_released: false))
          # A key collision with a different durable identity/owner on a
          # path-like resource (inode, namespace link) is reuse evidence: the
          # operation is not downgraded to a cleanup candidate; Recovery
          # surfaces the mismatch and refuses deletion.  A *process* whose pid
          # now carries another start time or executable is proof that ours
          # exited (the kernel reused the pid): the operation is dead and the
          # claim is released without ever signalling the stranger.
          identity_mismatch = resources.any? do |resource|
            observed_resource = observed_by_key[resource_key(resource)]
            observed_resource && resource["kind"] != "process" &&
              (observed_resource["identity"] != resource["identity"] ||
               observed_resource["owner"] != resource["owner"])
          end
          next if identity_mismatch

          dead = resources.any? do |resource|
            observed_resource = observed_by_key[resource_key(resource)]
            observed_resource.nil? ||
              (resource["kind"] == "process" && observed_resource["identity"] != resource["identity"]) ||
              (observed_resource["identity"] == resource["identity"] &&
               observed_resource["owner"] == resource["owner"] &&
               observed_resource.dig("metadata", "live") == false)
          end
          @ledger.transition(operation_id: operation.fetch("id") { operation[:id] }, to: "StateUnknown") if dead
        end
        true
      end

      RECOVERY_CANDIDATE_STATES = %w[StateUnknown RollingBack CleanupPending].freeze
      RECOVERY_STOP_TIMEOUT_SECONDS = 10

      # A dead operation (its sandbox lost a namespace, a veth, a mount) may
      # still have live containers; kubelet kills the containers of a broken
      # sandbox and lets the Pod be recreated.  Stop every process Recovery
      # would otherwise refuse to touch ("live or liveness is unknown"), but
      # only after re-verifying it is ours (pid + start time + executable
      # digest through ProcessSupervisor#adopt), kill the populated cgroups
      # the same way, then observe again so the cleanup sees dead resources.
      # A pid whose identity no longer matches is never signalled.
      def quiesce_dead_operations!(observed, observer)
        observed_by_key = observed.to_h { |entry| [resource_key(entry), entry] }
        quiesced = []
        @ledger.operations.each do |operation_value|
          operation = operation_value.respond_to?(:to_h) ? operation_value.to_h : operation_value
          state = String(operation.fetch("state") { operation[:state] })
          next unless RECOVERY_CANDIDATE_STATES.include?(state)

          owner = String(operation.fetch("owner") { operation[:owner] })
          resources = normalize_inventory(@ledger.resources(owner: owner, include_released: false))
          resources.sort_by { |resource| resource["kind"] == "process" ? 0 : 1 }.each do |resource|
            observed_resource = observed_by_key[resource_key(resource)]
            next unless observed_resource
            next unless observed_resource["identity"] == resource["identity"] && observed_resource["owner"] == resource["owner"]
            next unless observed_resource.dig("metadata", "live") == true

            begin
              case resource["kind"]
              when "process" then stop_recovered_process(resource)
              when "cgroup" then kill_recovered_cgroup(resource)
              else next
              end
              quiesced << resource_key(resource)
            rescue StandardError => error
              record(:recovery_quiesce_failed, resource: resource_key(resource), error: error_payload(error))
            end
          end
        end
        return observed if quiesced.empty?

        record(:recovery_quiesced, resources: quiesced)
        normalize_inventory(invoke_observer(observer))
      end

      def stop_recovered_process(resource)
        metadata = resource.fetch("metadata", {}).merge("id" => resource.fetch("id"))
        handle = @process_supervisor.handles.values.find { |entry| entry.id.to_s == resource.fetch("id") } ||
                 @process_supervisor.adopt(metadata: metadata)
        @process_supervisor.stop(handle, timeout: RECOVERY_STOP_TIMEOUT_SECONDS, resource_id: "process:#{resource.fetch("id")}")
        @process_supervisor.close(handle)
      end

      def kill_recovered_cgroup(resource)
        return unless @cgroup.respond_to?(:kill)

        metadata = resource.fetch("metadata", {})
        handle = @cgroup.lookup(metadata["path"] || resource.fetch("id"))
        raise Platform::Linux::CgroupV2::Error, "cgroup #{resource_key(resource)} identity changed" unless handle.identity == resource.fetch("identity")

        @cgroup.kill(handle)
      end

      # hostUsers=false receives a durable, non-overlapping 65,536 ID range
      # bound to the sandbox identity before the holder is created (§5.8.6).
      def namespace_spec_for(input, identity)
        spec = input["namespace"] || input[:namespace] || input
        return spec unless @namespace.respond_to?(:user_namespace_required?) && @namespace.user_namespace_required?(spec)

        mapping = userns_allocator.allocate(identity)
        normalized = normalize_hash(spec)
        normalized["uid_base"] = mapping.uid_base
        normalized["gid_base"] = mapping.gid_base
        normalized
      end

      def workspace_owner_for(namespace_spec)
        return nil unless namespace_spec.is_a?(Hash) && namespace_spec.key?("uid_base")

        [Integer(namespace_spec.fetch("uid_base")), Integer(namespace_spec.fetch("gid_base"))]
      end

      def userns_allocator
        @userns_allocator ||= if config.pure_profile?
                                Platform::Linux::UserNamespace::Allocator.new(path: File.join(Dir.tmpdir,
                                                                                              "rubernetes-pure-userns-#{Process.pid}.json"))
                              else
                                Platform::Linux::UserNamespace::Allocator.new(path: config.userns_allocation_path)
                              end
      end

      def release_user_namespace_range(sandbox)
        plan = sandbox.namespace.respond_to?(:plan) ? sandbox.namespace.plan : nil
        return true unless plan.respond_to?(:user_mapping) && plan.user_mapping

        userns_allocator.release(sandbox.identity)
      rescue Platform::Linux::UserNamespace::Error => error
        raise ResourceError, "user namespace range release failed: #{error.message}"
      end

      def pod_cgroup_limits(input)
        explicit = input["pod_limits"] || input[:pod_limits]
        return normalize_hash(explicit) if explicit.respond_to?(:to_h) && !explicit.to_h.empty?
        return {} unless (input["spec"] || input[:spec]).is_a?(Hash)

        Resources.pod_cgroup_limits(input, qos: normalize_qos(input), memory_qos: config.memory_qos, pids_limit: config.pod_pids_limit)
      end

      # Explicit `limits` win; otherwise the v1.36.2 container formulas are
      # applied to `resources`, including the BestEffort defaults
      # (cpu.weight=1, cpu.max=max) when nothing was requested.
      # The bootstrap that sets up a container's security is an interpreter
      # process living in the container's own cgroup, and it allocates while
      # it works.  A small memory ceiling -- 32Mi and 64Mi are ordinary in
      # conformance Pods -- therefore killed the bootstrap before it could
      # exec anything, and the Pod never started.  The ceiling is applied the
      # moment the workload has replaced it, which the gate observes exactly.
      # The CPU ceiling is deferred for the same reason: under a 10m limit the
      # bootstrap got 1 ms of CPU per 100 ms period and building a rootfs
      # took ten seconds or more, where runc's Go init needs a few ms.
      DEFERRED_LIMIT_FILES = %w[memory.max memory.high memory.swap.max cpu.max].freeze

      def apply_deferred_memory_limits(sandbox, container)
        return unless container.cgroup && @cgroup.respond_to?(:configure)

        key = container_resource_id(sandbox, container)
        pod_key = "pod:#{sandbox.id}"
        deferred, pod_deferred = @mutex.synchronize do
          [@deferred_memory_limits.delete(key), @deferred_memory_limits.delete(pod_key)]
        end
        @cgroup.configure_pod(sandbox.cgroup, pod_deferred) if pod_deferred && !pod_deferred.empty? && sandbox.cgroup && @cgroup.respond_to?(:configure_pod)
        return if deferred.nil? || deferred.empty?

        @cgroup.configure(container.cgroup, deferred)
      rescue Platform::Linux::CgroupV2::Error => error
        record(:cgroup_memory_limit_failed, container_id: container.id, error: error.message)
        raise
      end

      def container_cgroup_limits(input, qos:, pod: nil)
        pod_spec = pod && (pod["spec"] || pod[:spec])
        derived = Resources.container_cgroup_limits(input, qos: qos, memory_qos: config.memory_qos,
                                                           pids_limit: input["pids_limit"] || input[:pids_limit] || config.pod_pids_limit,
                                                           pod: pod_spec.is_a?(Hash) ? pod_spec : nil)
        explicit = input["limits"] || input[:limits] || {}
        derived.merge(normalize_hash(explicit))
      end

      # runc's process.oomScoreAdj: set on the gated wrapper, which the
      # workload is forked from after the gate, so it inherits the value.
      def apply_oom_score_adj(process, spec)
        value = spec["oom_score_adj"] || spec[:oom_score_adj]
        return if value.nil? || !process.respond_to?(:pid) || process.pid.nil?

        path = "/proc/#{Integer(process.pid)}/oom_score_adj"
        return unless File.exist?(path)

        File.write(path, Integer(value).clamp(-1000, 1000).to_s)
      rescue SystemCallError, IOError => error
        record(:oom_score_adj_failed, pid: process.pid, error: "#{error.class}: #{error.message}")
      end

      def record_oom_baseline(sandbox, container)
        return unless container.cgroup && @cgroup.respond_to?(:oom_kill_count)

        key = container_resource_id(sandbox, container)
        count = @cgroup.oom_kill_count(container.cgroup)
        @mutex.synchronize do
          @oom_baselines[key] = count
          @oom_reported.delete(key)
        end
      rescue Platform::Linux::CgroupV2::Error => error
        record(:oom_baseline_unavailable, sandbox_id: sandbox.id, container_id: container.id, error: error.message)
      end

      # memory.events oom_kill is cumulative; the reason is attributed to the
      # first exit observed after the counter moved and never repeated
      # (§5.8.8: "exit reason と Pod status へ一度だけ反映する").
      def detect_oom(sandbox, container)
        return nil unless container.cgroup && @cgroup.respond_to?(:oom_kill_count)

        key = container_resource_id(sandbox, container)
        baseline = @mutex.synchronize { @oom_baselines[key] }
        return nil if baseline.nil?

        current = @cgroup.oom_kill_count(container.cgroup)
        return nil unless current > baseline

        already = @mutex.synchronize do
          reported = @oom_reported.key?(key)
          @oom_reported[key] = current
          @oom_baselines[key] = current
          reported
        end
        return nil if already

        record(:container_oom_killed, sandbox_id: sandbox.id, container_id: container.id, oom_kill: current - baseline)
        "OOMKilled"
      rescue Platform::Linux::CgroupV2::Error => error
        record(:oom_events_unavailable, sandbox_id: sandbox.id, container_id: container.id, error: error.message)
        nil
      end

      def prepare_container_workspace(sandbox, container, input)
        return nil unless config.host_profile?

        image_root = input["rootfs_path"] || input[:rootfs_path]
        return nil if image_root.to_s.empty? || sandbox.workspace.nil?

        resolved = input["resolved_image"] || input[:resolved_image]
        digest = if resolved.respond_to?(:[]) &&
                    (resolved["digest"] || resolved[:digest])
                   resolved["digest"] || resolved[:digest]
                 else
                   sandbox.workspace.image_digest
                 end
        identifier = "#{sandbox.id}.#{container.id}"
        namespace_spec = namespace_spec_for(sandbox.config, sandbox.identity)
        workspace = @filesystem.prepare(id: identifier, image_digest: digest, lowerdirs: [image_root],
                                        read_only: read_only_root_filesystem?(input),
                                        owner: workspace_owner_for(namespace_spec))
        operation = @ledger.operation(sandbox.id)
        claim(operation, kind: "workspace", id: identifier, identity: workspace.identity, metadata: workspace_metadata(workspace))
        @filesystem.activate(workspace, namespace: sandbox.namespace) if @filesystem.respond_to?(:activate) && sandbox.namespace
        workspace
      end

      # ------------------------------------------------------------ OCI hooks

      def container_hooks(spec)
        return {} if Array(spec["cdi_hooks"]).empty?

        Hooks.normalize(spec["cdi_hooks"])
      rescue Hooks::Error => error
        raise FailClosed, "container hooks are invalid: #{error.message}"
      end

      def hook_bundle_directory(sandbox, container)
        File.join(File.dirname(config.journal_path), "oci-bundles", "#{sandbox.id}.#{container.id}")
      end

      def prepare_hook_bundle(sandbox, container, spec, command, rootfs, hooks)
        directory = hook_bundle_directory(sandbox, container)
        annotations = spec["annotations"].is_a?(Hash) ? spec["annotations"].transform_values(&:to_s) : {}
        env = (spec["env"] || {}).to_h.compact.map { |name, value| "#{name}=#{value}" }
        Hooks.write_bundle(directory, root: rootfs || "/", process: {"args" => Array(command), "env" => env, "cwd" => spec["cwd"] || "/"},
                                      mounts: Array(spec["mounts"]), annotations: annotations, hooks: hooks)
        {directory: directory, id: container.id, annotations: annotations,
         state: Hooks.state(id: container.id, status: "creating", pid: nil, bundle: directory, annotations: annotations)}
      end

      # Runs the hooks of +stages+ in order, in this process's namespaces.
      def run_hooks(hooks, stages, plan, pid:)
        stages.each do |stage|
          Array(hooks[stage]).each_with_index do |hook, index|
            state = Hooks.state(id: plan[:id], status: Hooks::STATUS.fetch(stage), pid: pid, bundle: plan[:directory],
                                annotations: plan[:annotations])
            Hooks.run(hook, state, stage: stage, index: index)
          end
        end
        true
      end

      # poststart and poststop failures are warnings: the lifecycle goes on.
      def run_post_hooks(sandbox, container, hooks, plan, stage, pid:)
        run_hooks(hooks, [stage], plan, pid: pid)
      rescue Hooks::Error, SystemCallError => error
        record(:container_hook_warning, sandbox_id: sandbox.id, container_id: container.id, stage: stage, error: error.message)
        false
      end

      # The bundle marks a container whose poststop hooks are still owed; it
      # is removed once they ran, so a retried removal runs them only once.
      def run_poststop_hooks(sandbox, container)
        return if container.nil?

        hooks = container_hooks(container.spec || {})
        directory = hook_bundle_directory(sandbox, container)
        return if hooks.empty? || !File.directory?(directory)

        plan = {directory: directory, id: container.id,
                annotations: container.spec["annotations"].is_a?(Hash) ? container.spec["annotations"].transform_values(&:to_s) : {}}
        run_post_hooks(sandbox, container, hooks, plan, "poststop", pid: nil)
        FileUtils.rm_rf(directory)
      rescue FailClosed
        nil
      end

      def workload_rootfs(sandbox, spec, container: nil)
        return nil unless config.host_profile?
        return nil unless spec["rootfs_path"] || spec[:rootfs_path]

        root = (container.respond_to?(:workspace) && container.workspace&.root) || sandbox.workspace&.root
        raise FailClosed, "resolved image rootfs is unavailable at workload start" unless root && File.directory?(root) && !File.symlink?(root)

        root
      end

      # Adapter-owned metadata (mount ID, cgroup inode, and similar kernel
      # identities) is kept alongside the portable workspace descriptor.  A
      # restart must be able to verify those identities before reusing a path.
      def workspace_metadata(workspace)
        metadata = workspace.respond_to?(:to_h) ? workspace.to_h : {}
        extra = if @filesystem.respond_to?(:resource_metadata)
                  @filesystem.resource_metadata(workspace)
                else
                  {}
                end
        metadata.merge(extra || {})
      end

      # Rebuild only resources whose durable identity is present in the
      # external kernel inventory.  Missing or mismatched resources are left
      # to Recovery, which can release ledger ownership only after the same
      # identity checks; it never guesses a replacement PID, mount, or cgroup.
      def reconstruct_sandboxes_from_observed!(observed)
        return true unless @namespace.adapter.respond_to?(:adopt)

        observed_by_key = observed.to_h { |entry| [resource_key(entry), entry] }
        @ledger.operations.each do |operation_value|
          operation = operation_value.respond_to?(:to_h) ? operation_value.to_h : operation_value
          state = String(operation.fetch("state") { operation[:state] })
          next if state == "Removed"

          sandbox_id = String(operation.fetch("id") { operation[:id] })
          next if @mutex.synchronize { @sandboxes.key?(sandbox_id) }

          owner = String(operation.fetch("owner") { operation[:owner] })
          resources = @ledger.resources(owner: owner, include_released: false).map { |resource| normalize_hash(resource) }
          sandbox_resources = resources.select do |resource|
            metadata = resource["metadata"] || {}
            resource_id = resource["id"].to_s
            resource_id == sandbox_id || resource_id.start_with?("#{sandbox_id}:") || metadata["parent"].to_s == sandbox_id
          end
          next if sandbox_resources.empty?
          next unless sandbox_resources.all? do |resource|
            observed_resource = observed_by_key[resource_key(resource)]
            observed_resource && observed_resource["identity"] == resource["identity"] && observed_resource.dig("metadata", "live") != false
          end

          reconstruct_one_sandbox!(operation, sandbox_resources)
        end
        true
      rescue StandardError => error
        raise RecoveryRequired, "native startup reconstruction failed closed: #{error.message}"
      end

      def reconstruct_one_sandbox!(operation, resources)
        sandbox_id = String(operation.fetch("id") { operation[:id] })
        owner = String(operation.fetch("owner") { operation[:owner] })
        workspace_resource = resources.find { |resource| resource["kind"] == "workspace" && resource["id"] == sandbox_id }
        namespace_resource = resources.find { |resource| resource["kind"] == "namespace" && resource["id"] == sandbox_id }
        cgroup_resource = resources.find { |resource| resource["kind"] == "cgroup" && resource["id"] == sandbox_id }
        return unless workspace_resource && namespace_resource && cgroup_resource

        namespace_metadata = namespace_resource.fetch("metadata")
        plan_data = namespace_metadata.fetch("plan")
        plan = Namespace::Plan.new(
          namespaces: Array(plan_data.fetch("namespaces")).map(&:to_sym).freeze,
          shared: Array(plan_data.fetch("shared", [])).map(&:to_sym).freeze,
          host: Array(plan_data.fetch("host", [])).map(&:to_sym).freeze,
          user_mapping: plan_data["user_mapping"], hostname: plan_data["hostname"]
        )
        namespace = @namespace.adopt(id: sandbox_id, identity: namespace_resource.fetch("identity"),
                                     plan: plan, metadata: namespace_metadata)
        cgroup = adopt_cgroup(cgroup_resource)
        workspace_data = workspace_resource.fetch("metadata")
        workspace_fields = %w[id root upper work identity image_digest].to_h do |field|
          [field.to_sym, workspace_data.fetch(field)]
        end
        workspace = Filesystem::Workspace.new(**workspace_fields)
        @filesystem.adopt(workspace, namespace: namespace, metadata: workspace_resource.fetch("metadata", {}))
        sandbox = Sandbox.new(id: sandbox_id, identity: owner, config: {}, clock: @clock)
        sandbox.set_resources(namespace: namespace, workspace: workspace, cgroup: cgroup)

        container_cgroups = resources.select do |resource|
          resource["kind"] == "cgroup" && resource["id"].to_s.start_with?("#{sandbox_id}:")
        end
        process_resources = resources.select do |resource|
          resource["kind"] == "process" && resource["id"].to_s.start_with?("#{sandbox_id}:")
        end
        container_cgroups.each do |resource|
          container_id = resource.fetch("id").to_s.delete_prefix("#{sandbox_id}:")
          process_resource = process_resources.find { |candidate| candidate["id"] == resource["id"] }
          process_metadata = process_resource && process_resource.fetch("metadata")
          container_metadata = resource.fetch("metadata", {})
          persisted_spec = container_metadata["spec"]
          raise RecoveryRequired, "container #{sandbox_id}:#{container_id} has no durable spec" unless persisted_spec.respond_to?(:to_h)

          spec = persisted_spec.to_h.transform_keys(&:to_s).merge("id" => container_id)
          spec["command"] = Array(process_metadata["command"]) if process_metadata && process_metadata["command"]
          container = sandbox.create_container(spec: spec, id: container_id)
          container_cgroup = adopt_cgroup(resource)
          security_context = container_security_context(spec)
          security_plan, = security_plan_for(security_context)
          process = (@process_supervisor.adopt(metadata: process_metadata, cgroup: container_cgroup) if process_metadata)
          sandbox.update_container(container, cgroup: container_cgroup,
                                              process: process,
                                              security_plan: security_plan,
                                              state: process ? :running : :created)
        end
        restore_sandbox_state!(sandbox, String(operation.fetch("state") { operation[:state] }))
        @mutex.synchronize { @sandboxes[sandbox_id] = sandbox }
      end

      def adopt_cgroup(resource)
        metadata = resource.fetch("metadata")
        path = metadata.fetch("path")
        handle = @cgroup.lookup(path)
        unless handle.identity == resource.fetch("identity")
          raise RecoveryRequired,
                "cgroup #{resource_key(resource)} identity changed during adoption"
        end

        expected_inode = metadata["cgroup_inode"] || metadata["cgroup_id"]
        if expected_inode && handle.respond_to?(:path)
          actual_inode = File.stat(handle.path).ino
          unless actual_inode == Integer(expected_inode)
            raise RecoveryRequired,
                  "cgroup #{resource_key(resource)} kernel identity changed during adoption"
          end
        end

        handle
      end

      def restore_sandbox_state!(sandbox, state)
        target = state.to_s.downcase.to_sym
        return if target == :new

        if target == :state_unknown
          sandbox.transition(:state_unknown)
          return
        end
        if target == :cleanup_pending
          sandbox.transition(:state_unknown)
          sandbox.transition(:cleanup_pending)
          return
        end
        base_states = %i[validated image_pinned workspace_allocated isolation_created resources_attached workload_stopped]
        base_states.each do |step|
          sandbox.transition(step)
          break if step == target
        end
        return if sandbox.state == target

        case target
        when :running
          sandbox.transition(:running)
        when :stopping
          sandbox.transition(:running)
          sandbox.transition(:stopping)
        when :stopped
          sandbox.transition(:rolling_back)
          sandbox.transition(:stopped)
        when :rolling_back
          sandbox.transition(:rolling_back)
        else
          raise RecoveryRequired, "unsupported sandbox state #{state.inspect} during reconstruction"
        end
      end

      # Return nil for a newly-created request and a durable record for an
      # existing request.  Pending records are never replayed because the
      # original process may have lost its response after the kernel effect.
      # The ledger, not the in-memory handle, is the durable record of whether
      # a container ever had a process: after a restart the handle is gone
      # while the workload may not be.
      def container_started?(sandbox, container)
        return false unless @ledger.respond_to?(:request)

        started = @ledger.request("start:#{sandbox.id}:#{container.id}")
        return false if started.nil?

        ledger_value(started, :state).to_s == "Completed"
      rescue StandardError
        true
      end

      def begin_native_request(request_id, operation:, input:)
        request = String(request_id)
        raise ConfigurationError, "request id must not be empty" if request.empty? || request.include?("\0")
        return nil unless @ledger.respond_to?(:begin_request)

        config_digest = digest(input)
        existing = @ledger.request(request)
        if existing
          existing_digest = ledger_value(existing, :config_digest)
          existing_operation = ledger_value(existing, :operation)
          unless existing_digest == config_digest && existing_operation.to_s == operation.to_s
            raise OwnershipConflict, "request #{request} was replayed with different intent"
          end

          state = ledger_value(existing, :state).to_s
          return existing if state == "Completed"

          if state == "Failed"
            error = ledger_value(existing, :error)
            raise FailClosed,
                  "request #{request} previously failed: #{error.is_a?(Hash) ? error.fetch("message", "unknown failure") : error}"
          end
          # A cleanup request remains replayable after a transient cleanup
          # failure. The resource and its durable ownership record stay live
          # until a later attempt confirms cleanup, so retrying the same
          # request is safe and does not repeat an already-confirmed removal.
          return nil if state == "CleanupPending"

          raise RecoveryRequired, "request #{request} is pending durable reconciliation"
        end
        owner = input["sandbox_id"] || input[:sandbox_id]
        if owner && ledger_requests_take_owner?
          @ledger.begin_request(request_id: request, operation: operation, config_digest: config_digest, owner: String(owner))
        else
          @ledger.begin_request(request_id: request, operation: operation, config_digest: config_digest)
        end
        nil
      end

      def ledger_requests_take_owner?
        return @ledger_requests_take_owner unless @ledger_requests_take_owner.nil?

        @ledger_requests_take_owner = @ledger.method(:begin_request).parameters.any? do |kind, name|
          %i[key keyreq].include?(kind) && name == :owner
        end
      end

      def complete_native_request(request_id, state:, result: nil, error: nil)
        return true unless @ledger.respond_to?(:complete_request)

        @ledger.complete_request(request_id: String(request_id), state: state, result: result, error: error)
        true
      end

      def error_payload(error)
        {"class" => error.class.name.to_s, "message" => error.message.to_s}
      end

      def container_resource_id(sandbox, container)
        id = container.respond_to?(:id) ? container.id : container.to_s
        "#{sandbox.id}:#{id}"
      end

      def process_identity_for(sandbox, container, process)
        pid = process["workload_pid"] || process[:workload_pid] || process["pid"] || process[:pid]
        start_time = process["workload_start_time"] || process[:workload_start_time]
        executable_digest = process["workload_executable_digest"] || process[:workload_executable_digest] ||
                            process["executable_digest"] || process[:executable_digest]
        "process:#{sandbox.id}:#{container.id}:#{pid}:#{start_time || "unknown"}:#{executable_digest || "unknown"}"
      end

      def ledger_resource_for(operation, kind, id)
        @ledger.resources(owner: operation.owner, include_released: true).find do |resource|
          ledger_value(resource, :kind).to_s == kind.to_s && ledger_value(resource, :id).to_s == id.to_s
        end
      end

      def release_process_resource(operation, sandbox, container, _process)
        return unless operation

        id = container_resource_id(sandbox, container)
        resource = ledger_resource_for(operation, "process", id)
        return unless resource && ledger_value(resource, :state).to_s != "Released"

        @ledger.release(operation_id: operation.id, kind: "process", id: id,
                        identity: ledger_value(resource, :identity), force: true)
      end

      def release_container_resource(operation, sandbox, container, process)
        return unless operation

        id = container_resource_id(sandbox, container)
        [%w[process], %w[cgroup], ["workspace", "#{sandbox.id}.#{container.id}"]].each do |kind, resource_id|
          resource_id ||= id
          resource = ledger_resource_for(operation, kind, resource_id)
          next unless resource && ledger_value(resource, :state).to_s != "Released"

          @ledger.release(operation_id: operation.id, kind: kind, id: resource_id,
                          identity: ledger_value(resource, :identity), force: true)
        end
        process
      end

      # Native's historical ownership ledger exposes hash-shaped operation
      # snapshots with symbol keys, while the common ledger exposes immutable
      # operation values. Normalize both without accidentally calling
      # Object#id on a Hash during replay.
      def ledger_value(value, name)
        if value.respond_to?(:key?)
          return value[name] if value.key?(name)

          string = name.to_s
          return value[string] if value.key?(string)
          return value[string.to_sym] if value.key?(string.to_sym)
        end
        return value.public_send(name) if value.respond_to?(name)

        nil
      end

      # Attach joins a running container's streams the way the CRI shim does:
      # output is the container's log from the moment of attaching (the
      # supervisor's pipe is owned by the logger; a second reader on it would
      # steal bytes from `kubectl logs`), input is the process's stdin pipe.
      def attach_process_streams(container, tty:, stdin: false, stdout: true, stderr: false, **_options)
        process = container.process
        raise CapabilityError, "container process does not expose attach streams" unless process

        input = stream_requested?(stdin) ? borrow_process_stream(process_stream(process, :stdin)) : nil
        output = stream_requested?(stdout) ? follow_log_stream(process, :stdout) : nil
        error = !tty && stream_requested?(stderr) ? follow_log_stream(process, :stderr) : nil
        raise CapabilityError, "container process stdin stream is unavailable" if stream_requested?(stdin) && input.nil?
        raise CapabilityError, "container process stdout stream is unavailable" if stream_requested?(stdout) && output.nil?
        raise CapabilityError, "container process stderr stream is unavailable" if stream_requested?(stderr) && !tty && error.nil?

        {stdin: input, stdout: output, stderr: error}.freeze
      end

      def follow_log_stream(process, stream)
        return nil unless @process_supervisor.respond_to?(:logs)

        # Only new output: the log so far belongs to `logs`, not `attach`.
        existing = @process_supervisor.logs(process, follow: false, stream: stream)
        since = existing.is_a?(String) ? existing.bytesize : nil
        @process_supervisor.logs(process, follow: true, since: since, stream: stream)
      rescue StandardError
        nil
      end

      def borrow_process_stream(stream)
        stream && BorrowedProcessStream.new(stream)
      end

      def process_stream(process, name)
        return process.public_send(name) if process.respond_to?(name)
        return process.fetch(name) if process.respond_to?(:fetch) && process.key?(name)
        return process.fetch(name.to_s) if process.respond_to?(:fetch) && process.key?(name.to_s)

        nil
      end

      def validate_duplex_result!(result, operation:, options: {})
        stdin_required = stream_requested?(options[:stdin])
        stdout_required = stream_requested?(options.fetch(:stdout, true))
        stderr_required = stream_requested?(options[:stderr]) && !options[:tty]
        return result if result.respond_to?(:read) && result.respond_to?(:write)

        if result.is_a?(Hash) || result.respond_to?(:to_h)
          value = result.respond_to?(:to_h) ? result.to_h : result
          input = value[:stdin] || value["stdin"] || value[:input] || value["input"]
          output = value[:stdout] || value["stdout"] || value[:output] || value["output"]
          error = value[:stderr] || value["stderr"] || value[:error] || value["error"]
          raise CapabilityError, "#{operation} adapter returned no stdin stream" if stdin_required && input.nil?
          raise CapabilityError, "#{operation} adapter returned no stdout stream" if stdout_required && output.nil?
          raise CapabilityError, "#{operation} adapter returned no stderr stream" if stderr_required && error.nil?

          return result
        end

        return result if stdout_required && result.is_a?(String)
        return result if !stdin_required && !stdout_required && !stderr_required && !result.nil?

        raise CapabilityError, "#{operation} adapter returned no usable byte stream"
      end

      def stream_requested?(value)
        value == true || value.respond_to?(:read) || value.respond_to?(:write)
      end

      def normalize_ports(value)
        values = value.is_a?(Array) ? value : [value]
        raise ConfigurationError, "port-forward requires at least one port" if values.empty?
        raise ConfigurationError, "port-forward accepts at most 128 ports" if values.length > 128

        normalized = values.flat_map do |port|
          if port.is_a?(Range)
            first = normalize_port(port.begin)
            last = normalize_port(port.end) - (port.exclude_end? ? 1 : 0)
            raise ConfigurationError, "port-forward range must be ascending" if last < first
            raise ConfigurationError, "port-forward range is too large" if last - first + 1 > 128

            (first..last).to_a
          else
            [normalize_port(port)]
          end
        end
        raise ConfigurationError, "port-forward port list must not be empty" if normalized.empty?

        normalized.freeze
      end

      def normalize_port(value)
        value = value.to_s.split(":", 2).last if value.is_a?(String) && value.include?(":")
        port = Integer(value)
        raise ConfigurationError, "port-forward ports must be between 1 and 65535" unless port.between?(1, 65_535)

        port
      rescue ArgumentError, TypeError => error
        raise ConfigurationError, "port-forward port must be an integer: #{error.message}"
      end

      def normalize_timeout(value)
        timeout = Float(value)
        raise ConfigurationError, "timeout must be non-negative" if timeout.negative?

        timeout
      rescue ArgumentError, TypeError => error
        raise ConfigurationError, "timeout must be a non-negative number: #{error.message}"
      end

      public

      def sandbox(value)
        id = value.respond_to?(:id) ? value.id : String(value)
        @mutex.synchronize { @sandboxes.fetch(String(id)) { raise Error, "unknown sandbox #{id}" } }
      end

      def network_sandbox_context(value)
        sandbox(value).network_sandbox_context
      end

      def sandboxes
        @mutex.synchronize { @sandboxes.values.map(&:to_h).freeze }
      end

      def trace
        @mutex.synchronize { @events.map(&:dup).freeze }
      end

      private

      def normalize_inventory(value)
        normalized = Array(value).map do |resource|
          hash = resource.respond_to?(:to_h) ? resource.to_h : resource
          kind = String(hash.fetch("kind") { hash.fetch(:kind) })
          id = hash["id"] || hash[:id]
          if id.nil? && hash["pod_id"]
            id = hash["container_id"].to_s == "sandbox" ? hash["pod_id"] : "#{hash.fetch("pod_id")}:#{hash.fetch("container_id")}"
          end
          raise RecoveryRequired, "observed native resource #{kind.inspect} has no stable id" if id.nil?

          identity = hash["identity"] || hash[:identity] || hash["stable_identity"] || hash[:stable_identity]
          if identity.nil? || String(identity).empty?
            raise RecoveryRequired,
                  "observed native resource #{kind}:#{id} has no stable identity"
          end

          metadata = hash["metadata"] || hash[:metadata] || {}
          metadata = metadata.to_h.transform_keys(&:to_s)
          # Adapters may expose stable identity fields at the top level
          # (pid/start time, namespace links, mount ID, cgroup inode). Carry
          # them into the canonical metadata map so restart adoption sees the
          # same proof material as the durable ledger claim.
          %w[pid workload_pid wrapper_pid start_time workload_start_time
             pidfd workload_pidfd executable_digest workload_executable_digest
             namespace_links kernel_identity supervisor_pid mount_identity cgroup_inode cgroup_id
             command path plan].each do |field|
            metadata[field] ||= hash[field] if hash.key?(field)
            metadata[field] ||= hash[field.to_sym] if hash.key?(field.to_sym)
          end
          metadata["path"] ||= hash["path"] if hash.key?("path")
          metadata["path"] ||= hash[:path] if hash.key?(:path)
          metadata["managed_by"] ||= hash["managed_by"] || hash[:managed_by]
          metadata["live"] = hash["live"] if hash.key?("live")
          metadata["live"] = hash[:live] if hash.key?(:live)
          metadata.delete("path") if metadata["path"].nil?
          metadata.delete("managed_by") if metadata["managed_by"].nil?
          {
            "kind" => kind,
            "id" => String(id),
            "identity" => String(identity),
            "owner" => String(hash["owner"] || hash[:owner] || ""),
            "metadata" => metadata
          }
        end
        normalized.each_with_object({}) do |entry, result|
          key = resource_key(entry)
          existing = result[key]
          if existing.nil?
            result[key] = entry
          else
            unless existing["identity"] == entry["identity"] && existing["owner"] == entry["owner"]
              raise RecoveryRequired, "observed native resource #{key} has duplicate identities"
            end

            result[key] = existing.merge(
              "metadata" => existing.fetch("metadata", {}).merge(entry.fetch("metadata", {}))
            )
          end
        end.values
      end

      def add_inventory_resource(resources, kind, component, owner:, live:, parent: nil)
        return unless component

        hash = component.respond_to?(:to_h) ? component.to_h : component
        id = hash["id"] || hash[:id]
        if id.nil? && (pod_id = hash["pod_id"] || hash[:pod_id])
          container_id = hash["container_id"] || hash[:container_id]
          id = container_id.to_s == "sandbox" ? pod_id : "#{pod_id}:#{container_id}"
        end
        return if id.nil?

        identity = hash["identity"] || hash[:identity] || hash["stable_identity"] || hash[:stable_identity]
        return if identity.nil?

        metadata = {
          "managed_by" => "rubernetes-native",
          "live" => live
        }
        metadata.merge!(hash["metadata"].to_h.transform_keys(&:to_s)) if hash["metadata"].respond_to?(:to_h)
        identity_metadata_fields(hash).each { |key, value| metadata[key] ||= value }
        metadata["parent"] = parent if parent
        metadata["path"] = hash["path"] || hash[:path] if hash["path"] || hash[:path]
        resources << managed_inventory_resource(kind, id, identity, owner, metadata: metadata)
      end

      def add_component_inventory(resources, component, kind)
        return unless component.respond_to?(:resources)

        Array(component.resources).each do |entry|
          hash = entry.respond_to?(:to_h) ? entry.to_h : entry
          id = hash["id"] || hash[:id]
          if id.nil? && hash["pod_id"]
            id = hash["container_id"].to_s == "sandbox" ? hash["pod_id"] : "#{hash.fetch("pod_id")}:#{hash.fetch("container_id")}"
          end
          next if id.nil?

          identity = hash["identity"] || hash[:identity] || hash["stable_identity"] || hash[:stable_identity]
          next if identity.nil?

          owner = owner_for_resource(kind, id)
          metadata = {
            "managed_by" => "rubernetes-native",
            "live" => hash.key?("live") ? hash["live"] : hash[:live]
          }
          metadata.merge!(hash["metadata"].to_h.transform_keys(&:to_s)) if hash["metadata"].respond_to?(:to_h)
          identity_metadata_fields(hash).each { |key, value| metadata[key] ||= value }
          metadata["path"] = hash["path"] || hash[:path] if hash["path"] || hash[:path]
          metadata["parent"] = hash["pod_id"] || hash[:pod_id] if hash["pod_id"] || hash[:pod_id]
          resources << managed_inventory_resource(kind, id, identity, owner, metadata: metadata)
        end
      end

      def managed_inventory_resource(kind, id, identity, owner, metadata: {})
        {
          "kind" => String(kind),
          "id" => String(id),
          "identity" => String(identity),
          "owner" => String(owner),
          "metadata" => metadata.transform_keys(&:to_s)
        }
      end

      def identity_metadata_fields(hash)
        %w[pid workload_pid wrapper_pid start_time workload_start_time
           pidfd workload_pidfd executable_digest workload_executable_digest
           namespace_links kernel_identity supervisor_pid mount_identity cgroup_inode cgroup_id
           command path plan].each_with_object({}) do |field, result|
          value = hash[field] if hash.key?(field)
          value = hash[field.to_sym] if value.nil? && hash.key?(field.to_sym)
          result[field] = value unless value.nil?
        end
      end

      def owner_for_resource(kind, id)
        resource = @ledger.resources(include_released: false).find do |entry|
          hash = entry.respond_to?(:to_h) ? entry.to_h : entry
          (hash["kind"].to_s == String(kind) && hash["id"].to_s == String(id)) ||
            (hash[:kind].to_s == String(kind) && hash[:id].to_s == String(id))
        end
        owner = if resource
                  hash = resource.respond_to?(:to_h) ? resource.to_h : resource
                  hash["owner"] || hash[:owner]
                end
        owner.to_s
      end

      def invoke_observer(source)
        return source.call if source.is_a?(Proc) || source.is_a?(Method)
        return source.list_resources if source.respond_to?(:list_resources)
        return source.observe if source.respond_to?(:observe)
        return source.resources if source.respond_to?(:resources)
        return source.call(:call) if source.respond_to?(:call)

        raise CapabilityError, "native resource observer must expose a callable inventory"
      end

      def invoke_cleaner(source, resource)
        if source.is_a?(Proc) || source.is_a?(Method)
          parameters = source.parameters
          keyword_resource = parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :resource } ||
                             parameters.any? { |kind, _name| kind == :keyrest }
          return keyword_resource ? source.call(resource: resource) : source.call(resource)
        end
        return source.cleanup_resource(resource) if source.respond_to?(:cleanup_resource)
        return source.release_resource(resource) if source.respond_to?(:release_resource)
        return source.call(:cleanup_resource, resource: resource) if source.respond_to?(:call)

        raise CapabilityError, "native resource cleaner must expose a cleanup contract"
      end

      def resource_key(resource)
        kind = resource["kind"] || resource[:kind]
        id = resource["id"] || resource[:id]
        "#{kind}:#{id}"
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

      # The cgroup device controller (runc's eBPF allowlist) for every
      # container cgroup.  A host profile that cannot load the program does
      # not start: a container without it may mknod and read host block
      # devices.  The pure profile has no cgroups to attach to.
      def build_device_filter
        return @adapters[:device_filter] if @adapters.key?(:device_filter)
        return nil if config.pure_profile?

        filter = Platform::Linux::DeviceCgroup::Attacher.new
        filter.validate!
        filter
      rescue Platform::Linux::DeviceCgroup::Error => error
        raise CapabilityError, "cgroup device filter is unavailable for the #{config.profile} profile " \
                               "(BPF_PROG_TYPE_CGROUP_DEVICE needs a kernel with CONFIG_BPF_SYSCALL and CONFIG_CGROUP_BPF): #{error.message}"
      end

      # Attaches the container's device allowlist to its cgroup before any
      # process can join it: containerd's rules (deny all -- allow all when
      # privileged -- plus the container's own devices) and runc's default
      # devices.
      def attach_device_filter(sandbox, container, cgroup, input, plan)
        return unless @device_filter && cgroup.respond_to?(:path)

        privileged = plan.respond_to?(:context) && plan.context.respond_to?(:privileged?) && plan.context.privileged?
        devices = container_device_rules(input)
        rules = Platform::Linux::DeviceCgroup.rules_for(privileged: privileged, devices: devices)
        program_id = @device_filter.attach(cgroup.path, rules)
        device_rules = devices.map { |rule| rule.respond_to?(:to_h) ? rule.to_h : rule }
        record(:device_filter_attached, sandbox_id: sandbox.id, container_id: container.id, cgroup: cgroup.path,
                                        program_id: program_id, privileged: privileged, devices: devices.map do |rule|
                                                                                          rule.respond_to?(:to_h) ? rule.to_h : rule
                                                                                        end)
        program_id
      rescue Platform::Linux::DeviceCgroup::Error => error
        raise ResourceError, "container #{container.id}: #{error.message}"
      end

      # Detaches before the cgroup goes (the kernel would release the program
      # with the cgroup anyway); a failure here is recorded, not raised, so
      # the removal still reaches the cgroup.
      def detach_device_filter(sandbox, container_id, cgroup)
        return unless @device_filter && cgroup.respond_to?(:path)

        detached = @device_filter.detach(cgroup.path)
        record(:device_filter_detached, sandbox_id: sandbox.id, container_id: container_id, cgroup: cgroup.path, program_ids: detached)
        detached
      rescue Platform::Linux::DeviceCgroup::Error => error
        record(:device_filter_detach_error, sandbox_id: sandbox.id, container_id: container_id, cgroup: cgroup.path, error: error.message)
        nil
      end

      DEVICE_DIRECTORY_SKIPS = %w[pts shm fd mqueue .lxc .lxd-mounts .udev].freeze

      # The container's own device nodes as cgroup rules: every mount flagged
      # "device" (device plugin allocations, CDI deviceNodes) with the
      # permissions its source gave, resolved like containerd's
      # oci.DeviceFromPath -- a directory contributes every node beneath it
      # (HostDevices), CDI may name type/major/minor itself.
      def container_device_rules(input)
        Array(input["mounts"]).flat_map do |mount|
          next [] unless mount["device"] == true

          permissions = mount["permissions"].nil? ? "" : String(mount["permissions"])
          if mount["device_type"] && mount["major"]
            next [{"type" => String(mount["device_type"]), "major" => Integer(mount["major"]), "minor" => Integer(mount["minor"] || 0),
                   "access" => permissions, "allow" => true}]
          end

          device_nodes(mount.fetch("source")).map do |stat|
            {"type" => stat.chardev? ? "c" : "b", "major" => stat.rdev_major, "minor" => stat.rdev_minor,
             "access" => permissions, "allow" => true}
          end
        end
      end

      def device_nodes(path)
        stat = File.stat(path)
        return [stat] if stat.chardev? || stat.blockdev?
        raise ConfigurationError, "device mount source #{path} is not a device node" unless stat.directory?

        Dir.children(path).sort.flat_map do |name|
          child = File.join(path, name)
          if File.directory?(child) && !File.symlink?(child)
            DEVICE_DIRECTORY_SKIPS.include?(name) ? [] : device_nodes(child)
          else
            next [] if name == "console"

            begin
              child_stat = File.stat(child)
            rescue Errno::ENOENT, Errno::ELOOP
              next []
            end
            child_stat.chardev? || child_stat.blockdev? ? [child_stat] : []
          end
        end
      rescue Errno::ENOENT
        raise ConfigurationError, "device mount source #{path} does not exist"
      end

      def build_security
        if @adapters[:security].is_a?(Platform::Linux::Security)
          @security_probe = @adapters[:security_probe]&.call || Platform::Linux::Security::CapabilityProbe.new.call
          return @adapters[:security]
        end
        @security_probe = if config.pure_profile?
                            FakeCapabilityProbe.new(architecture: config.architecture).call
                          elsif @adapters[:security_probe]
                            probe = @adapters[:security_probe]
                            probe.respond_to?(:call) ? probe.call : probe.probe
                          else
                            Platform::Linux::Security::CapabilityProbe.new(architecture: config.architecture).call
                          end
        security = Platform::Linux::Security.new(
          capability_probe: @adapters[:security_probe] || -> { @security_probe },
          adapter: @adapters[:security_adapter] || Platform::Linux::Security::RecordingAdapter.new,
          seccomp_compiler: @adapters[:seccomp_compiler],
          seccomp_root: config.seccomp_root
        )
        process_adapter = @adapters[:process_adapter]
        process_adapter.security = security if process_adapter.respond_to?(:security=)
        security
      end

      def build_process_supervisor
        return @adapters[:process_supervisor] if @adapters[:process_supervisor]

        process_adapter = @adapters[:process_adapter] || (config.pure_profile? ? FakeProcessAdapter.new : Platform::Linux::ProcessSupervisor::ForkAdapter.new)
        # Without a pidfd every signal is addressed by pid, and a recycled pid
        # makes "stop this container" land on an unrelated process -- including
        # the node agent itself.  Host profiles therefore default to the real
        # pidfd adapter instead of silently degrading.
        pidfd_adapter = @adapters[:pidfd]
        if pidfd_adapter.nil? && !config.pure_profile?
          pidfd_adapter = begin
            Platform::Linux::NativeAdapters::PidfdAdapter.new
          rescue StandardError
            nil
          end
        end
        Platform::Linux::ProcessSupervisor.new(
          process_adapter: process_adapter,
          pidfd_adapter: pidfd_adapter,
          cgroup: @cgroup,
          log_directory: config.log_root,
          max_log_bytes: config.max_log_bytes,
          max_log_files: config.max_log_files,
          clock: @clock
        )
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
        missing << :cgroup_v2 unless @cgroup.respond_to?(:available?) && @cgroup.available?
        raise CapabilityError, "L3 kernel isolation profile is unavailable: #{missing.join(", ")}" unless missing.empty?
      end

      def validate_runtime_class!(value)
        return if String(value) == config.runtime_class

        raise ConfigurationError,
              "Native backend received unsupported runtime class #{value.inspect}"
      end

      def validate_sandbox_input!(input)
        validate_runtime_class!(input["runtime_class"] || input[:runtime_class]) if input["runtime_class"] || input[:runtime_class]
        digest = input["image_digest"] || input[:image_digest] || config.image["digest"]
        validate_rootfs_path!(input["rootfs_path"]) if input["rootfs_path"]
        Array(input["lowerdirs"] || input[:lowerdirs]).each { |path| validate_rootfs_path!(path) }
        if input["rootfs_entries"]
          input["rootfs_entries"].each do |entry|
            Filesystem.new.validate_entry!(entry.fetch("path") do
              entry.fetch(:path)
            end, type: entry["type"] || entry[:type] || :file, link_target: entry["link_target"] || entry[:link_target])
          end
        end
        raise Filesystem::DigestMismatch, "image digest must be sha256:<64 hex characters>" if digest && !String(digest).match?(/\Asha256:[0-9a-fA-F]{64}\z/)

        true
      end

      def validate_rootfs_path!(path)
        value = String(path)
        raise Filesystem::UnsafeEntry, "rootfs path contains NUL" if value.include?("\0")

        expanded = File.expand_path(value)
        unless File.directory?(expanded) && !File.symlink?(expanded)
          raise Filesystem::UnsafeEntry,
                "rootfs path must be a regular directory"
        end

        expanded
      end

      # Resolve direct runtime callers as well as the Node lifecycle path. The
      # latter supplies `resolved_images`; direct callers with an image must
      # inject the same resolver explicitly, otherwise the runtime fails before
      # it creates a sandbox record or touches a host adapter.
      def resolve_images(input)
        resolved = Array(input["resolved_images"] || input[:resolved_images])
        references = []
        references << input["image"] if input["image"] || input[:image]
        spec = input["spec"] || input[:spec]
        if spec.is_a?(Hash)
          Array(spec["initContainers"] || spec[:initContainers]).each { |container| references << normalize_hash(container)["image"] }
          Array(spec["containers"] || spec[:containers]).each { |container| references << normalize_hash(container)["image"] }
        end
        references = references.compact.reject { |value| value.to_s.empty? }
        if resolved.empty? && references.any?
          raise FailClosed, "image resolver is required for a sandbox with image references" unless @image_resolver

          resolved = references.map do |reference|
            value = if @image_resolver.respond_to?(:resolve)
                      @image_resolver.resolve(reference)
                    elsif @image_resolver.respond_to?(:call)
                      @image_resolver.call(reference)
                    else
                      raise CapabilityError, "image resolver must implement resolve or call"
                    end
            normalize_resolved_image(value, reference)
          end
        else
          resolved = resolved.map { |value| normalize_resolved_image(value) }
        end
        return input if resolved.empty?

        input["resolved_images"] = resolved
        input["image_digest"] ||= aggregate_image_digest(resolved)
        roots = resolved.filter_map { |image| image["rootfs"] }.uniq
        input["lowerdirs"] = (Array(input["lowerdirs"] || input[:lowerdirs]) + roots).compact.uniq
        input
      end

      def normalize_resolved_image(value, reference = nil)
        image = normalize_hash(value)
        digest = image["digest"]
        raise FailClosed, "image resolver returned an invalid pinned digest" unless digest.to_s.match?(/\Asha256:[0-9a-fA-F]{64}\z/)

        image["digest"] = digest.to_s.downcase
        unless reference.nil?
          image["reference"] ||= reference.to_s
          image["requested_reference"] ||= reference.to_s
        end
        image
      end

      def aggregate_image_digest(images)
        digests = images.map { |image| image.fetch("digest") }.uniq.sort
        "sha256:#{Digest::SHA256.hexdigest(JSON.generate(digests))}"
      end

      def resolve_container_spec(input, sandbox: nil)
        resolved = input["resolved_image"] || input[:resolved_image]
        if resolved.nil? && input["image"] && sandbox
          candidates = Array(sandbox.config["resolved_images"])
          resolved = candidates.find do |candidate|
            candidate["requested_reference"].to_s == input["image"].to_s || candidate["reference"].to_s == input["image"].to_s
          end
          resolved ||= candidates.fetch(0) if candidates.length == 1
        end
        raise FailClosed, "container image was not resolved before container creation" if input["image"] && resolved.nil?
        return input unless resolved

        resolved = normalize_resolved_image(resolved, input["image"])
        input["resolved_image"] = resolved
        input["image_digest"] = resolved["digest"]
        input["rootfs_path"] = resolved["rootfs"] if resolved["rootfs"]
        image_entrypoint = Array(resolved["entrypoint"])
        image_command = Array(resolved["cmd"])
        command = if input.key?("command") || input.key?("argv")
                    input["command"] || input["argv"]
                  elsif input.key?("args")
                    image_entrypoint + normalize_argv(input["args"], "container args")
                  else
                    resolved["command"] || (image_entrypoint + image_command)
                  end
        input["command"] = command unless command.nil?
        input["env"] = merge_environment(resolved["env"], input["env"])
        input["cwd"] = input["workingDir"] || resolved["working_dir"] if input["workingDir"] || resolved["working_dir"]
        input
      end

      # The container security context arrives either in the runtime's own
      # snake_case form or as the Pod container's `securityContext`; the Node
      # merges Pod- and container-level fields before handing it over.  An
      # absent context falls back to the runtime configuration default.
      # securityContext.readOnlyRootFilesystem is a CONTAINER-level field, and
      # the workspace mount is what enforces it.  Reading it only from the top
      # of the container spec meant a Pod that asked for a read-only root got a
      # writable one -- "[sig-node] Kubelet when scheduling a read only busybox
      # container should not write to root filesystem" writes a file and
      # expects the write to be refused.
      def read_only_root_filesystem?(input)
        return true if input.respond_to?(:[]) &&
                       (input["read_only_root_filesystem"] || input[:read_only_root_filesystem]) == true

        context = container_security_context(input)
        return false unless context.respond_to?(:[])

        %w[readOnlyRootFilesystem read_only_root_filesystem].any? do |field|
          (context[field] || context[field.to_sym]) == true
        end
      rescue StandardError
        false
      end

      # A plan is a pure function of the security context and the host probe
      # (Security#plan validates the context, compiles the seccomp program and
      # orders the steps), and every container of a burst carries the same
      # context, so the plan and its digest are computed once per distinct
      # context.  Plans are frozen Data values shared safely between
      # containers; an invalid context raises every time and is never cached.
      SECURITY_PLAN_CACHE_LIMIT = 256

      def security_plan_for(security_context)
        key = digest(security_context)
        cached = @security_plan_mutex.synchronize { @security_plans[key] }
        return cached if cached

        plan = @security.plan(security_context, probe: @security_probe)
        entry = [plan, digest(plan.respond_to?(:to_h) ? plan.to_h : plan)].freeze
        @security_plan_mutex.synchronize do
          @security_plans.clear if @security_plans.length >= SECURITY_PLAN_CACHE_LIMIT
          @security_plans[key] = entry
        end
        entry
      end

      def container_security_context(input)
        return config.security_context unless input.respond_to?(:key?)

        value = input["security_context"] || input[:security_context] || input["securityContext"] || input[:securityContext]
        value.nil? ? config.security_context : value
      end

      # Bind mounts the container receives beneath its rootfs (volumes,
      # projections, termination log, /etc files).  Only shape is checked
      # here; the host source must exist at start time and the destination is
      # resolved inside the rootfs by the adapter.
      def normalize_mounts(value)
        raise ConfigurationError, "container mounts must be an array" unless value.is_a?(Array)

        value.each_with_index.map do |entry, index|
          mount = normalize_hash(entry)
          source = mount["source"] || mount["host_path"] || mount["hostPath"]
          destination = mount["destination"] || mount["container_path"] || mount["containerPath"] || mount["mountPath"]
          raise ConfigurationError, "mount #{index} requires an absolute source path" unless source.is_a?(String) && source.start_with?("/")
          unless destination.is_a?(String) && destination.start_with?("/")
            raise ConfigurationError,
                  "mount #{index} requires an absolute destination path"
          end
          raise ConfigurationError, "mount #{index} path contains NUL" if source.include?("\0") || destination.include?("\0")

          propagation = (mount["propagation"] || mount["mount_propagation"] || mount["mountPropagation"] || "None").to_s
          unless %w[None HostToContainer Bidirectional].include?(propagation)
            raise ConfigurationError, "mount #{index} has unsupported propagation #{propagation.inspect}"
          end

          {
            "source" => source,
            "destination" => destination,
            "readonly" => mount["readonly"] == true || mount["read_only"] == true || mount["readOnly"] == true,
            "propagation" => propagation,
            "name" => mount["name"].nil? ? nil : String(mount["name"]),
            # Disabled / IfPossible / Enabled (the bootstrap applies it).
            "recursive_readonly" => mount["recursive_readonly"].nil? ? nil : String(mount["recursive_readonly"]),
            # A device node the container is granted (device plugin, CDI):
            # the device cgroup gets a rule with these permissions (CRI
            # Device.permissions verbatim, as containerd passes them; CDI
            # supplies "rwm" by default) for the node found at the source --
            # or the node CDI names explicitly.
            "device" => mount["device"] == true ? true : nil,
            "permissions" => mount["permissions"].nil? ? nil : String(mount["permissions"]),
            "device_type" => mount["device_type"].nil? ? nil : String(mount["device_type"]),
            "major" => mount["major"].nil? ? nil : Integer(mount["major"]),
            "minor" => mount["minor"].nil? ? nil : Integer(mount["minor"])
          }.compact
        end
      end

      def normalize_argv(value, label)
        values = Array(value)
        raise ConfigurationError, "#{label} must be an array" unless value.is_a?(Array)

        values.map do |argument|
          text = String(argument)
          raise ConfigurationError, "#{label} contains NUL" if text.include?("\0")

          text
        end
      rescue TypeError => error
        raise ConfigurationError, "#{label} contains a non-string value: #{error.message}"
      end

      def merge_environment(image_env, container_env)
        result = normalize_environment_hash(image_env)
        return result if container_env.nil?

        if container_env.is_a?(Hash)
          result.merge!(container_env.transform_keys(&:to_s).transform_values(&:to_s))
        elsif container_env.is_a?(Array)
          container_env.each do |entry|
            value = normalize_hash(entry)
            name = value["name"].to_s
            raise ConfigurationError, "container environment variable name is invalid" unless name.match?(/\A[[:print:]&&[^=]]+\z/)
            raise ConfigurationError, "valueFrom environment entries are unsupported by Native" if value["valueFrom"]

            result[name] = value.fetch("value", "").to_s
          end
        else
          raise ConfigurationError, "container env must be an object or array"
        end
        result
      end

      def normalize_environment_hash(value)
        return {} unless value
        raise ConfigurationError, "image env must be an object" unless value.is_a?(Hash)

        value.each_with_object({}) do |(name, content), result|
          key = name.to_s
          raise ConfigurationError, "image environment variable name is invalid" unless key.match?(/\A[^=\0]+\z/)

          result[key] = content.to_s
        end
      end

      def pin_image(input)
        digest = input["image_digest"] || input[:image_digest] || config.image["digest"]
        bytes = input["image_bytes"] || input[:image_bytes]
        verified = false
        image_adapter = @adapters[:image]
        image_adapter ||= default_image_verifier if config.host_profile? && bytes.nil? && Array(input["resolved_images"]).any?
        if image_adapter
          result = invoke(image_adapter, :verify, image: input, digest: digest, bytes: bytes)
          unless result == true || result == digest || result == digest&.downcase
            raise FailClosed,
                  "image adapter did not confirm digest verification"
          end

          verified = true
        end
        if bytes && digest
          Filesystem.new.verify_digest(bytes, digest)
          verified = true
        end
        raise FailClosed, "production Native runtime requires image bytes or an adapter-verified OCI identity" if config.host_profile? && !verified

        if digest
          String(digest).downcase
        elsif config.host_profile? || input["image"] || input["resolved_images"]
          raise FailClosed, "production Native runtime requires a verified OCI image identity"
        else
          # Pure/fake profiles intentionally support an image-less state
          # machine test.  This fixed test identity is never accepted by a
          # host profile and is not derived from mutable request input.
          "sha256:#{Digest::SHA256.hexdigest("rubernetes-pure-test-image-v1")}"
        end
      end

      # Host profiles verify pinned OCI manifests with the production image
      # verifier when the caller did not inject one; a resolver result is
      # never trusted on the strength of its digest string alone.
      def default_image_verifier
        require_relative "../image/verifier"
        @default_image_verifier ||= Rubernetes::Image::PinnedImageVerifier.new
      end

      # The pod cgroup directory is named after the sandbox, and kubelet names
      # it after the Pod UID (cgroupfs "pod<uid>", systemd "kubepods-pod<uid>
      # .slice"); tooling -- the in-place resize conformance suite among it --
      # finds a Pod's cgroup by searching for its UID.
      def generated_sandbox_id(input)
        metadata = input["metadata"] || input[:metadata]
        uid = metadata.is_a?(Hash) ? (metadata["uid"] || metadata[:uid]).to_s : ""
        return "pod#{uid}-#{SecureRandom.hex(6)}" if uid.match?(/\A[A-Za-z0-9-]{1,64}\z/)

        "sandbox-#{SecureRandom.hex(12)}"
      end

      def normalize_qos(input)
        value = input["qos"] || input[:qos] || input["qos_class"] || input[:qos_class]
        value ||= (input["spec"] || input[:spec]).is_a?(Hash) ? Resources.qos_class(input) : "besteffort"
        normalized = String(value).downcase
        normalized = {"Guaranteed" => "guaranteed", "Burstable" => "burstable", "BestEffort" => "besteffort"}.fetch(String(value),
                                                                                                                    normalized)
        raise ConfigurationError, "qos must be Guaranteed, Burstable, or BestEffort" unless %w[guaranteed burstable
                                                                                               besteffort].include?(normalized)

        normalized
      end

      DEFAULT_EXEC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

      def validate_command!(command)
        values = Array(command).map(&:to_s)
        raise ConfigurationError, "container command must not be empty" if values.empty?
        raise ConfigurationError, "container executable must not be empty" if values.first.empty?
        raise ConfigurationError, "container command must not contain NUL" if values.any? { |value| value.include?("\0") }

        values
      end

      # runc semantics: an executable containing no "/" is looked up on PATH
      # *inside the container's rootfs*; one that contains a slash is used as
      # given.  Requiring an absolute path instead rejects the overwhelmingly
      # common `command: ["sh", "-c", ...]`, which no image is obliged to
      # spell out.
      def resolve_executable(command, rootfs:, env: {})
        values = Array(command).map(&:to_s)
        program = values.first.to_s
        return values if program.start_with?("/") || program.include?("/")
        return values if rootfs.nil?

        # The image is mounted into the container's own mount namespace, so the
        # host view of the workspace root is empty at this point and cannot be
        # searched.  Resolve here only when the rootfs really is populated on
        # the host; otherwise hand the bare name to the child, which performs
        # the PATH lookup inside the container where the image is visible.
        search = environment_value(env, "PATH") || DEFAULT_EXEC_PATH
        resolved = search.split(":").filter_map do |directory|
          next if directory.empty?

          candidate = File.join(directory, program)
          host_path = File.join(rootfs.to_s, candidate)
          candidate if File.file?(host_path) && File.executable?(host_path)
        end.first
        return values unless resolved

        [resolved] + values[1..]
      end

      def environment_value(env, name)
        case env
        when Hash
          env[name] || env[name.to_sym]
        when Array
          entry = env.map(&:to_s).find { |value| value.start_with?("#{name}=") }
          entry&.split("=", 2)&.last
        end
      end

      def advance(sandbox, operation, target)
        state_name = target.to_s.split("_").map(&:capitalize).join
        sandbox.transition(target)
        @ledger.transition(operation_id: operation.id, to: state_name)
        record(target, sandbox_id: sandbox.id)
        invoke_effect_hook(target, sandbox, operation) if EFFECT_POINTS.include?(target.to_sym)
      end

      # Fault/crash probes observe only fully durable effect boundaries.  The
      # hook runs after both the in-memory state and the fsynced ownership WAL
      # transition agree, so a blocked or raised hook cannot fabricate a state
      # that recovery would not replay after process death.
      def invoke_effect_hook(effect_point, sandbox, operation)
        hook = @adapters[:effect_hook]
        return true unless hook

        transition = @ledger.journal.last
        hook.call(
          effect_point: effect_point.to_s,
          sandbox: sandbox,
          operation: @ledger.operation(operation.id),
          transition: transition.respond_to?(:to_h) ? transition.to_h : transition
        )
        true
      end

      def claim(operation, kind:, id:, identity:, metadata: {})
        @ledger.claim(operation_id: operation.id, kind: kind, id: id, identity: identity, metadata: metadata)
      end

      def rollback_sandbox(sandbox, operation, original_error:)
        primary_error = error_payload(original_error)
        record(:rollback_started, sandbox_id: sandbox.id, error: "#{original_error.class}: #{original_error.message}",
                                  primary_error: primary_error)
        cleanup_failed = false
        begin
          sandbox.transition(:rolling_back) unless %i[rolling_back stopped removed].include?(sandbox.state)
          @ledger.transition(operation_id: operation.id, to: "RollingBack") unless operation.state == "RollingBack"
        rescue StandardError => error
          record(:rollback_transition_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
        end
        begin
          cleanup_errors = cleanup_sandbox_resources(sandbox, operation, primary_error: original_error)
        rescue StandardError => error
          cleanup_failed = true
          cleanup_errors = if error.respond_to?(:cleanup_errors) && !error.cleanup_errors.empty?
                             error.cleanup_errors
                           else
                             []
                           end
          preserve_cleanup_errors(original_error, cleanup_errors)
          payload = {sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}",
                     primary_error: primary_error}
          payload[:cleanup_errors] = cleanup_errors unless cleanup_errors.empty?
          record(:rollback_cleanup_error, **payload)
        end
        if cleanup_failed
          begin
            sandbox.transition(:cleanup_pending) if sandbox.state == :rolling_back
            @ledger.transition(operation_id: operation.id, to: "CleanupPending") if @ledger.operation(operation.id)&.state == "RollingBack"
          rescue StandardError => error
            record(:rollback_pending_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
          end
          return
        end
        begin
          sandbox.transition(:stopped) if sandbox.state == :rolling_back
          @ledger.transition(operation_id: operation.id, to: "Stopped") if @ledger.operation(operation.id)&.state == "RollingBack"
          @mutex.synchronize do
            @sandboxes.delete(sandbox.id)
            @requests.delete_if { |_request, sandbox_id| sandbox_id == sandbox.id }
          end
        rescue StandardError => error
          record(:rollback_finalize_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
        end
      end

      def cleanup_sandbox_resources(sandbox, operation, primary_error: nil)
        cleanup_errors = []
        blocked_by = nil
        sandbox.containers.reverse_each do |container_hash|
          remove_container(container_hash.fetch("id"))
        rescue StandardError => error
          cleanup_errors << cleanup_error_entry(
            resource: "container:#{container_hash.fetch("id")}", error: error
          )
          blocked_by ||= "container:#{container_hash.fetch("id")}"
        end

        # Sandbox acquisition is workspace -> namespace -> cgroup.  Rollback
        # must release the exact reverse sequence.  A lower resource may depend
        # on the upper owner still holding a live kernel object, so cleanup
        # stops at the first failed release and records every dependent resource
        # as pending instead of destructively touching it.
        [[@cgroup, sandbox.cgroup, :remove, "cgroup"],
         [@namespace, sandbox.namespace, :destroy, "namespace"],
         [@filesystem, sandbox.workspace, :cleanup, "workspace"]].each do |component, resource, operation_name, resource_kind|
          next unless resource
          next if ledger_resource_released?(operation, resource_kind, sandbox.id)

          resource_key = "#{resource_kind}:#{sandbox.id}"
          if blocked_by
            cleanup_errors << cleanup_error_entry(
              resource: resource_key,
              error: "cleanup blocked by #{blocked_by}",
              blocked_by: blocked_by
            )
            mark_resource_cleanup_pending(
              operation, resource_kind, sandbox.id, blocked_by: blocked_by, cleanup_errors: cleanup_errors
            )
            next
          end

          begin
            result = if component.equal?(@cgroup)
                       component.public_send(operation_name, resource, force: true)
                     elsif component.equal?(@namespace)
                       component.public_send(operation_name, resource)
                     else
                       component.public_send(operation_name, resource)
                     end
            raise ResourceError, "#{resource_kind} cleanup returned false" if result == false

            release_user_namespace_range(sandbox) if resource_kind == "namespace"
            release_sandbox_resource(operation, resource_kind, sandbox.id)
          rescue StandardError => error
            cleanup_errors << cleanup_error_entry(resource: resource_key, error: error)
            mark_resource_cleanup_pending(
              operation, resource_kind, sandbox.id, blocked_by: nil, cleanup_errors: cleanup_errors
            )
            blocked_by = resource_key
          end
        end

        cleanup_payload = {sandbox_id: sandbox.id, errors: cleanup_errors.freeze}
        cleanup_payload[:primary_error] = error_payload(primary_error) if primary_error
        record(:cleanup, **cleanup_payload)
        unless cleanup_errors.empty?
          error_messages = cleanup_errors.map do |entry|
            "#{entry.fetch("resource")}: #{entry.fetch("error")}"
          end
          error = ResourceError.new(
            "sandbox cleanup failed: #{error_messages.join("; ")}",
            cleanup_errors: cleanup_error_details(cleanup_errors)
          )
          mark_cleanup_pending(sandbox, operation, error, primary_error: primary_error)
          raise error
        end
        sandbox.mark_resources_cleaned
        true
      end

      def release_sandbox_resource(operation, kind, id)
        resource = ledger_resource_for(operation, kind, id)
        return true unless resource && ledger_value(resource, :state).to_s != "Released"

        released = @ledger.release(operation_id: operation.id, kind: kind, id: id,
                                   identity: ledger_value(resource, :identity), force: true)
        raise ResourceError, "ledger #{kind} release returned false" if released == false

        true
      rescue StandardError => error
        raise ResourceError, "ledger #{kind} release failed: #{error.message}"
      end

      def cleanup_error_details(cleanup_errors)
        Array(cleanup_errors).map do |entry|
          if entry.respond_to?(:to_h)
            entry.to_h.transform_keys(&:to_s)
          else
            resource, message = String(entry).split(": ", 2)
            {"resource" => resource, "error" => message || String(entry)}
          end
        end.map { |entry| immutable(entry) }.freeze
      end

      # Keep the original operation exception as the raised value while making
      # durable cleanup failures available to callers that need to retry them.
      # Native callers historically receive the primary exception directly, so
      # wrapping it would obscure the actual effect-point failure.
      def preserve_cleanup_errors(error, cleanup_errors)
        existing = error.respond_to?(:cleanup_errors) ? Array(error.cleanup_errors) : []
        details = dedupe_cleanup_errors(existing + cleanup_error_details(cleanup_errors))
        return error if details.empty?

        if error.respond_to?(:cleanup_errors)
          error.instance_variable_set(:@cleanup_errors, details.freeze)
        else
          error.instance_variable_set(:@native_cleanup_errors, details.freeze)
          error.define_singleton_method(:cleanup_errors) { @native_cleanup_errors }
        end
        error
      rescue StandardError
        # Exception objects may be frozen or reject singleton methods. The
        # structured rollback event remains the durable source of truth.
        error
      end

      def dedupe_cleanup_errors(entries)
        seen = {}
        Array(entries).each_with_object([]) do |entry, result|
          key = cleanup_error_key(entry)
          next if seen[key]

          seen[key] = true
          result << entry
        end
      end

      def cleanup_error_key(entry)
        value = if entry.respond_to?(:to_h)
                  entry.to_h
                elsif entry.respond_to?(:message)
                  {"class" => entry.class.name.to_s, "message" => entry.message.to_s}
                else
                  entry
                end
        canonical_cleanup_value(value)
      end

      def canonical_cleanup_value(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.map do |key|
            child = if value.key?(key)
                      value[key]
                    elsif value.key?(key.to_sym)
                      value[key.to_sym]
                    end
            [key, canonical_cleanup_value(child)]
          end
        when Array
          value.map { |child| canonical_cleanup_value(child) }
        else
          [value.class.name.to_s, value]
        end
      end

      def mark_container_cleanup_pending(sandbox, container, operation:, error:)
        return unless operation

        cleanup_errors = []
        mark_resource_cleanup_pending(
          operation, "cgroup", container_resource_id(sandbox, container), blocked_by: nil,
                                                                          cleanup_errors: cleanup_errors
        )
        record(:container_cleanup_pending, sandbox_id: sandbox.id, container_id: container.id,
                                           error: "#{error.class}: #{error.message}", cleanup_errors: cleanup_errors.freeze)
      rescue StandardError => cleanup_error
        record(:container_cleanup_pending_error, sandbox_id: sandbox.id, container_id: container.id,
                                                 error: "#{cleanup_error.class}: #{cleanup_error.message}")
      end

      def cleanup_error_entry(resource:, error:, blocked_by: nil)
        entry = {
          "resource" => String(resource),
          "error" => error.respond_to?(:message) ? "#{error.class}: #{error.message}" : String(error),
          "state" => "cleanup_pending"
        }
        entry["blocked_by"] = String(blocked_by) if blocked_by
        entry
      end

      def mark_resource_cleanup_pending(operation, kind, id, blocked_by:, cleanup_errors:)
        resource = ledger_resource_for(operation, kind, id)
        return true unless resource && ledger_value(resource, :state).to_s != "Released"

        metadata = ledger_value(resource, :metadata)
        metadata = metadata.respond_to?(:to_h) ? metadata.to_h.transform_keys(&:to_s) : {}
        metadata["cleanup_pending"] = true
        if blocked_by
          metadata["blocked_by"] = String(blocked_by)
        else
          metadata.delete("blocked_by")
        end
        claimed = @ledger.claim(
          operation_id: operation.id,
          kind: kind,
          id: id,
          identity: ledger_value(resource, :identity),
          metadata: metadata
        )
        raise ResourceError, "ledger #{kind} cleanup_pending metadata update returned false" if claimed == false

        true
      rescue StandardError => error
        cleanup_errors << cleanup_error_entry(resource: "ledger:#{kind}:#{id}", error: error)
        false
      end

      def ledger_resource_released?(operation, kind, id)
        resource = if @ledger.respond_to?(:resource)
                     @ledger.resource(kind: kind, id: id)
                   else
                     @ledger.resources(owner: operation.owner, include_released: true).find do |value|
                       ledger_value(value, :kind).to_s == kind.to_s && ledger_value(value, :id).to_s == id.to_s
                     end
                   end
        ledger_value(resource, :state).to_s == "Released"
      rescue StandardError
        false
      end

      def mark_cleanup_pending(sandbox, operation, error, primary_error: nil)
        begin
          sandbox.transition(:rolling_back) if sandbox.state == :stopping
          sandbox.transition(:cleanup_pending) if %i[rolling_back stopped].include?(sandbox.state)
        rescue Sandbox::Error => transition_error
          record(:cleanup_pending_transition_error, sandbox_id: sandbox.id,
                                                    error: "#{transition_error.class}: #{transition_error.message}")
        end
        current = @ledger.operation(operation.id)
        begin
          if current&.state == "Running"
            # A stop that failed before the durable Stopping record leaves the
            # workload liveness unknown; the model permits only
            # Running -> StateUnknown here.
            @ledger.transition(operation_id: operation.id, to: "StateUnknown")
            current = @ledger.operation(operation.id)
          end
          if current&.state == "StateUnknown"
            @ledger.transition(operation_id: operation.id, to: "CleanupPending")
            current = @ledger.operation(operation.id)
          end
          if current&.state == "Stopping"
            @ledger.transition(operation_id: operation.id, to: "RollingBack")
            current = @ledger.operation(operation.id)
          end
          @ledger.transition(operation_id: operation.id, to: "CleanupPending") if current && %w[RollingBack Stopped].include?(current.state)
          cleanup_errors = if error.respond_to?(:cleanup_errors) && !error.cleanup_errors.empty?
                             error.cleanup_errors
                           else
                             [{"resource" => "sandbox:#{sandbox.id}", "error" => error.message}]
                           end
          pending_payload = {sandbox_id: sandbox.id, errors: cleanup_errors.freeze}
          pending_payload[:primary_error] = error_payload(primary_error) if primary_error
          record(:cleanup_pending, **pending_payload)
          if @ledger.respond_to?(:record_cleanup_error)
            cleanup_errors.each do |cleanup_error|
              @ledger.record_cleanup_error(
                operation_id: operation.id,
                resource_key: cleanup_error.fetch("resource", "sandbox:#{sandbox.id}"),
                error: ResourceError.new(cleanup_error.fetch("error", error.message))
              )
            end
          end
        rescue StandardError => ledger_error
          record(:cleanup_pending_ledger_error, sandbox_id: sandbox.id,
                                                error: "#{ledger_error.class}: #{ledger_error.message}")
        end
      end

      # The CPU manager's reconcile (UpdateContainerResources with only
      # CpusetCpus): re-pin a running container as the shared pool changes.
      public def update_container_cpuset(value, cpus)
        sandbox, container = find_container(value)
        return false unless container.cgroup && @cgroup.respond_to?(:configure)

        @cgroup.configure(container.cgroup, {"cpuset.cpus" => cpus.to_s})
        spec = normalize_hash(container.spec)
        spec["limits"] = normalize_hash(spec["limits"] || {}).merge("cpuset.cpus" => cpus.to_s)
        sandbox.update_container(container, spec: immutable(spec))
        record(:container_cpuset_updated, sandbox_id: sandbox.id, container_id: container.id, cpus: cpus.to_s)
        true
      end

      # InPlacePodVerticalScaling: apply new requests/limits to a running
      # container's cgroup (and the Pod cgroup) without recreating it.
      public def update_container_resources(value, resources:, pod_spec: nil)
        sandbox, container = find_container(value)
        spec = normalize_hash(container.spec).merge("resources" => normalize_hash(resources))
        spec.delete("limits")
        spec.delete(:limits)
        qos = normalize_qos(sandbox.config)
        limits = container_cgroup_limits(spec, qos: qos, pod: pod_spec ? {"spec" => normalize_hash(pod_spec)} : sandbox.config)
        @cgroup.configure(container.cgroup, limits) if container.cgroup && @cgroup.respond_to?(:configure)
        @mutex.synchronize { @deferred_memory_limits.delete(container_resource_id(sandbox, container)) }
        sandbox.update_container(container, spec: immutable(spec))
        if pod_spec && sandbox.respond_to?(:cgroup) && sandbox.cgroup && @cgroup.respond_to?(:configure_pod)
          pod_limits = pod_cgroup_limits(normalize_hash(sandbox.config).merge("spec" => normalize_hash(pod_spec), "pod_limits" => nil))
          @cgroup.configure_pod(sandbox.cgroup, pod_limits) unless pod_limits.nil? || pod_limits.empty?
        end
        record(:container_resized, sandbox_id: sandbox.id, container_id: container.id, limits: limits)
        limits
      end

      # The Pod cgroup's cpu/memory settings and memory usage as the kernel
      # reports them (kubelet GetPodCgroupConfig / PodCPUAndMemoryStats), for
      # status.resources and the memory-limit-below-usage resize check.
      POD_CGROUP_FILES = %w[cpu.weight cpu.max memory.max memory.current].freeze

      public def pod_cgroup_readback(sandbox_id)
        sandbox = @mutex.synchronize { @sandboxes[String(sandbox_id)] }
        return nil unless sandbox && sandbox.respond_to?(:cgroup) && sandbox.cgroup && @cgroup.respond_to?(:pod_limits_readback)

        @cgroup.pod_limits_readback(sandbox.cgroup, files: POD_CGROUP_FILES)
      rescue Platform::Linux::CgroupV2::Error, SystemCallError
        nil
      end

      # Raw usage for the kubelet stats provider: the Pod cgroup and each
      # running container's cgroup (cpu.stat / memory.stat / memory.current),
      # the container's start time and workspace (writable layer) path.
      public def pod_usage(sandbox_id)
        sandbox = @mutex.synchronize { @sandboxes[String(sandbox_id)] }
        return nil unless sandbox && sandbox.cgroup && @cgroup.respond_to?(:usage)

        containers = sandbox.containers.filter_map do |entry|
          container = sandbox.container(entry["id"] || entry[:id])
          next unless container.state == :running && container.cgroup

          spec = normalize_hash(container.spec)
          {"id" => container.id, "name" => (spec["name"] || spec[:name]).to_s, "usage" => @cgroup.usage(container.cgroup),
           "image" => (spec["image"] || spec[:image]).to_s,
           # The writable layer (overlay upper) and the log directory: what
           # the container's rootfs/logs ephemeral storage is measured on.
           "rootfs" => entry["workspace"].is_a?(Hash) ? (entry["workspace"]["upper"] || entry["workspace"][:upper]) : nil,
           "logs" => config.log_root ? File.join(config.log_root, "process-#{sandbox.id}-#{container.id}") : nil,
           "pid" => container.process.respond_to?(:to_h) ? (container.process.to_h["workload_pid"] || container.process.to_h["pid"]) : nil}
        rescue Platform::Linux::CgroupV2::Error, Sandbox::Error
          nil
        end
        netns_pid = begin
          sandbox.respond_to?(:network_sandbox_context) ? sandbox.network_sandbox_context.dig("netns", "pid") : nil
        rescue StandardError
          nil
        end
        {"pod" => @cgroup.usage(sandbox.cgroup, pod: true), "containers" => containers, "netns_pid" => netns_pid}
      rescue Platform::Linux::CgroupV2::Error, SystemCallError
        nil
      end

      # InPlacePodLevelResourcesVerticalScaling: the Pod cgroup follows new
      # pod-level requests/limits (cm.ResourceConfigForPod), and every
      # container that takes its CPU or memory limit from the Pod's follows too.
      public def update_pod_resources(sandbox_id, pod_spec:)
        sandbox = @mutex.synchronize { @sandboxes[String(sandbox_id)] }
        raise Error, "unknown sandbox #{sandbox_id}" unless sandbox

        spec = normalize_hash(pod_spec)
        config = normalize_hash(sandbox.config).merge("spec" => spec, "pod_limits" => nil)
        pod_limits = pod_cgroup_limits(config)
        if sandbox.respond_to?(:cgroup) && sandbox.cgroup && @cgroup.respond_to?(:configure_pod) && !pod_limits.empty?
          @cgroup.configure_pod(sandbox.cgroup, pod_limits)
        end
        qos = normalize_qos(sandbox.config)
        sandbox.containers.each do |entry|
          container = sandbox.container(entry["id"] || entry[:id])
          next unless container.cgroup && @cgroup.respond_to?(:configure)

          limits = container_cgroup_limits(normalize_hash(container.spec), qos: qos, pod: {"spec" => spec})
          @cgroup.configure(container.cgroup, limits.slice("cpu.max", "memory.max"))
        end
        sandbox.update_config(immutable(config))
        record(:pod_resized, sandbox_id: sandbox.id, limits: pod_limits)
        pod_limits
      end

      def find_container(value)
        # One lookup per sandbox, no exception per miss: with a node full of
        # Pods the old rescue-driven scan raised once per sandbox for every
        # status query.
        if value.respond_to?(:id) && value.class.name.to_s.end_with?("::Container")
          @sandboxes.each_value do |sandbox|
            found = sandbox.container_if_present(value.id)
            return [sandbox, found] if found
          end
        end
        id = value.respond_to?(:id) ? value.id : String(value)
        @mutex.synchronize do
          @sandboxes.each_value do |sandbox|
            found = sandbox.container_if_present(id)
            return [sandbox, found] if found
          end
        end
        raise Error, "unknown container #{id}"
      end

      def normalize_hash(value)
        hash = value.respond_to?(:to_h) ? value.to_h : {}
        hash.each_with_object({}) { |(key, child), normalized| normalized[String(key)] = child }
      end

      def digest(value)
        Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
            source = value.key?(key) ? key : value.keys.find { |candidate| candidate.to_s == key }
            result[key] = canonical(value.fetch(source))
          end
        when Array then value.map { |child| canonical(child) }
        else value
        end
      end

      def immutable(value)
        case value
        when Hash then value.to_h { |key, child| [String(key), immutable(child)] }.freeze
        when Array then value.map { |child| immutable(child) }.freeze
        else value
        end
      end

      def invoke(adapter, operation = :call, **arguments)
        if adapter.respond_to?(operation)
          adapter.public_send(operation, **arguments)
        elsif adapter.respond_to?(:call)
          adapter.call(operation, **arguments)
        else
          raise CapabilityError, "adapter cannot perform #{operation}"
        end
      end

      def record(event, **payload)
        entry = {"event" => event.to_s, "timestamp" => @clock.call.utc.iso8601(6), **immutable(payload)}.freeze
        @mutex.synchronize { @events << entry }
        entry
      end
    end

    # The support classes retain the native implementation's lexical error
    # constants after their legacy top-level names are hidden.  Hiding only
    # constants that still point at Support keeps common Runtime definitions
    # intact when common code was loaded before this file.
    support_errors = %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired]
    %i[RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      support_class = Native::Support.const_get(name, false)
      support_errors.each do |error_name|
        support_class.const_set(error_name, Native::Support.const_get(error_name, false)) unless support_class.const_defined?(error_name,
                                                                                                                              false)
      end
    end
    %i[Error JournalCorruption OwnershipConflict InvalidTransition RecoveryRequired
       RollbackJournal OwnershipLedger ResourceLedger Recovery StartupReconciler].each do |name|
      remove_const(name) if const_defined?(name,
                                           false) && Native::Support.const_defined?(name,
                                                                                    false) && const_get(name,
                                                                                                        false).equal?(Native::Support.const_get(
                                                                                                          name, false
                                                                                                        ))
    end

    NativeRuntime = Native unless const_defined?(:NativeRuntime, false)
    Backend = Native unless const_defined?(:Backend, false)
  end
end
