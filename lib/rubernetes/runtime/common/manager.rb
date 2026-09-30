# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"
require "stringio"
require "tmpdir"
require "timeout"

require_relative "canonical"
require_relative "errors"
require_relative "ownership"
require_relative "recovery"
require_relative "rollback"
require_relative "snapshot"
require_relative "state_machine"
require_relative "wal"

module Rubernetes
  module Runtime
    # Pure config checks are deliberately separate from backend calls.  A
    # rejected config therefore cannot allocate a filesystem, process, or
    # kernel object through this façade.
    module ConfigValidator
      RUNTIME_CLASSES = %w[
        rubernetes-native rubernetes-firecracker rubernetes-firecracker-restricted
      ].freeze
      DIGEST_PATTERN = /\Asha256:[0-9a-f]{64}\z/i

      module_function

      def validate(config, runtime_class: nil)
        raise ValidationError, "runtime config must be a hash-like object" unless config.respond_to?(:to_h)

        normalized = Canonical.copy(config.to_h)
        selected = runtime_class || normalized["runtime_class"] || normalized["runtimeClassName"] || "rubernetes-native"
        selected = String(selected)
        raise ValidationError, "unsupported runtime class #{selected.inspect}" unless RUNTIME_CLASSES.include?(selected)

        normalized["runtime_class"] = selected
        image_digest = normalized["image_digest"] || normalized["imageDigest"]
        if image_digest && !String(image_digest).match?(DIGEST_PATTERN)
          raise ValidationError, "image digest must be sha256:<64 lowercase hexadecimal characters>"
        end

        [Canonical.immutable(normalized), selected, Canonical.digest(normalized)]
      end
    end

    # Minimal backend keeps L0 tests deterministic.  Production Native and
    # MicroVM adapters implement the same effect/observation methods.
    class NullAdapter
      def list_resources
        []
      end
    end

    # Common lifecycle façade shared by Native and MicroVM backends.
    class Runtime
      NOT_FOUND = :not_found

      def initialize(data_dir: nil, journal_path: nil, snapshot_dir: nil, adapter: nil,
                     observer: nil, cleaner: nil, orphan_predicate: nil, audit: nil,
                     clock: -> { Time.now.utc }, fsync: true, wal: nil, ledger: nil,
                     snapshot_store: nil, owner: nil)
        @data_dir = File.expand_path(data_dir || File.join(Dir.tmpdir, "rubernetes-runtime-#{Process.pid}-#{SecureRandom.hex(8)}"))
        FileUtils.mkdir_p(@data_dir)
        @clock = clock
        @adapter = adapter || NullAdapter.new
        @observer_available = !observer.nil? || @adapter.respond_to?(:list_resources)
        @observer = observer || default_observer
        @cleaner = cleaner || default_cleaner
        @orphan_predicate = orphan_predicate
        @audit = audit
        @owner = String(owner || "runtime:#{Process.pid}:#{SecureRandom.hex(8)}")
        @wal = wal || DurableWAL.new(journal_path || File.join(@data_dir, "runtime.wal"), clock: clock, fsync: fsync)
        @ledger = ledger || ResourceLedger.new(wal: @wal, clock: clock)
        @snapshot_store = snapshot_store || AtomicSnapshotStore.new(snapshot_dir || File.join(@data_dir, "snapshots"), fsync: fsync)
        @mutex = Mutex.new
      end

      attr_reader :adapter, :ledger, :wal, :snapshot_store

      def run_sandbox(config, runtime_class: nil, request_id: nil)
        normalized, selected_class, config_digest = ConfigValidator.validate(config, runtime_class: runtime_class)
        request_id = request_id_for(request_id)
        sandbox_id = stable_id("sandbox", request_id)
        existing = @ledger.operation_for_request(request_id)
        if existing
          return replay_result(existing, "sandbox_id", action: "run_sandbox", config_digest: config_digest,
                                                       target_id: sandbox_id)
        end

        operation = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "run_sandbox",
          target_id: sandbox_id, owner: "sandbox:#{sandbox_id}", config_digest: config_digest,
          metadata: {"runtime_class" => selected_class}
        )
        @ledger.set_result(operation.id, {"sandbox_id" => sandbox_id, "runtime_class" => selected_class})
        @ledger.transition(operation_id: operation.id, to: "Validated")
        begin
          verify_image(normalized, selected_class)
          @ledger.transition(operation_id: operation.id, to: "ImagePinned")
          effect_step(operation, "WorkspaceAllocated", :workspace, normalized, sandbox_id: sandbox_id,
                                                                               runtime_class: selected_class)
          effect_step(operation, "IsolationCreated", :isolation, normalized, sandbox_id: sandbox_id,
                                                                             runtime_class: selected_class)
          effect_step(operation, "ResourcesAttached", :attached, normalized, sandbox_id: sandbox_id,
                                                                             runtime_class: selected_class)
          effect_step(operation, "WorkloadStopped", :stopped, normalized, sandbox_id: sandbox_id,
                                                                          runtime_class: selected_class)
          sandbox_id
        rescue AmbiguousResult, Timeout::Error => error
          raise mark_unknown(operation.id, error)
        rescue StandardError => error
          raise rollback_failure(operation.id, error)
        end
      end

      def stop_sandbox(id, timeout:, request_id: nil)
        operation = sandbox_operation!(id)
        request_id = request_id_for(request_id)
        existing = @ledger.operation_for_request(request_id)
        if existing
          return replay_result(existing, "sandbox_id", action: "stop_sandbox", config_digest: operation.config_digest,
                                                       target_id: operation.target_id)
        end
        reject_unknown!(operation)
        raise InvalidTransition, "sandbox #{id} is already Removed" if operation.state == "Removed"

        stop_operation = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "stop_sandbox",
          target_id: operation.target_id, owner: operation.owner, config_digest: operation.config_digest,
          metadata: {"sandbox_id" => operation.target_id}
        )
        @ledger.set_result(stop_operation.id, {"sandbox_id" => operation.target_id})
        begin
          stop_child_containers(operation.target_id, timeout: timeout)
          @ledger.transition(operation_id: stop_operation.id, to: "Validated")
          @ledger.transition(operation_id: stop_operation.id, to: "ImagePinned")
          @ledger.transition(operation_id: stop_operation.id, to: "WorkspaceAllocated")
          @ledger.transition(operation_id: stop_operation.id, to: "IsolationCreated")
          @ledger.transition(operation_id: stop_operation.id, to: "ResourcesAttached")
          @ledger.transition(operation_id: stop_operation.id, to: "WorkloadStopped")
          if operation.state == "WorkloadStopped"
            raise Error, "stop_sandbox backend effect returned false" if invoke_optional(:stop_sandbox, {id: id, timeout: timeout}) == false

            @ledger.transition(operation_id: stop_operation.id, to: "RollingBack")
          else
            @ledger.transition(operation_id: stop_operation.id, to: "Running")
            @ledger.transition(operation_id: stop_operation.id, to: "Stopping")
            raise Error, "stop_sandbox backend effect returned false" if invoke_optional(:stop_sandbox, {id: id, timeout: timeout}) == false
          end
          @ledger.transition(operation_id: stop_operation.id, to: "Stopped")
          @ledger.transition(operation_id: operation.id, to: "Stopping") if operation.state == "Running"
          @ledger.transition(operation_id: operation.id, to: "Stopped") if @ledger.operation(operation.id).state == "Stopping"
          if operation.state == "WorkloadStopped"
            @ledger.transition(operation_id: operation.id, to: "RollingBack")
            RollbackExecutor.new(ledger: @ledger, adapter: @adapter, observer: @observer).execute(
              operation_id: operation.id,
              operation_error: {"class" => "Stop", "message" => "sandbox stopped before gate release"},
              mark_failed: false
            )
          end
          operation.target_id
        rescue AmbiguousResult, Timeout::Error => error
          raise mark_unknown(stop_operation.id, error)
        rescue StandardError => error
          raise rollback_failure(stop_operation.id, error)
        end
      end

      def remove_sandbox(id, request_id: nil)
        operation = sandbox_operation!(id)
        request_id = request_id_for(request_id)
        existing = @ledger.operation_for_request(request_id)
        if existing
          return replay_result(existing, "sandbox_id", action: "remove_sandbox", config_digest: operation.config_digest,
                                                       target_id: operation.target_id)
        end
        reject_unknown!(operation)
        raise InvalidTransition, "sandbox #{id} must be Stopped before removal" unless operation.state == "Stopped"

        removal = nil
        removal = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "remove_sandbox",
          target_id: operation.target_id, owner: operation.owner, config_digest: operation.config_digest
        )
        @ledger.set_result(removal.id, {"sandbox_id" => operation.target_id})
        @ledger.transition(operation_id: removal.id, to: "Validated")
        @ledger.transition(operation_id: removal.id, to: "ImagePinned")
        @ledger.transition(operation_id: removal.id, to: "WorkspaceAllocated")
        @ledger.transition(operation_id: removal.id, to: "IsolationCreated")
        @ledger.transition(operation_id: removal.id, to: "ResourcesAttached")
        @ledger.transition(operation_id: removal.id, to: "WorkloadStopped")
        @ledger.transition(operation_id: removal.id, to: "RollingBack")
        remove_child_containers(operation.target_id)
        raise Error, "remove_sandbox backend effect returned false" if invoke_optional(:remove_sandbox, {id: id}) == false

        @ledger.transition(operation_id: removal.id, to: "Stopped")
        @ledger.transition(operation_id: removal.id, to: "Removed")
        @ledger.transition(operation_id: operation.id, to: "RollingBack")
        RollbackExecutor.new(ledger: @ledger, adapter: @adapter, observer: @observer).execute(
          operation_id: operation.id,
          operation_error: {"class" => "Remove", "message" => "sandbox removal cleanup"},
          mark_failed: false
        )
        @ledger.transition(operation_id: operation.id, to: "Removed")
        operation.target_id
      rescue AmbiguousResult, Timeout::Error => error
        raise mark_unknown(removal.id, error)
      rescue StandardError => error
        raise rollback_failure(removal.id, error)
      end

      def create_container(sandbox, spec, request_id: nil)
        sandbox_operation = sandbox_operation!(sandbox)
        reject_unknown!(sandbox_operation)
        raise InvalidTransition, "sandbox #{sandbox} is not accepting containers" if %w[Stopped Removed].include?(sandbox_operation.state)

        normalized, _runtime_class, config_digest = ConfigValidator.validate(spec, runtime_class: spec_runtime_class(spec))
        request_id = request_id_for(request_id)
        container_id = stable_id("container", request_id)
        existing = @ledger.operation_for_request(request_id)
        if existing
          return replay_result(existing, "container_id", action: "create_container", config_digest: config_digest,
                                                         target_id: container_id)
        end

        operation = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "create_container",
          target_id: container_id, owner: "container:#{container_id}", config_digest: config_digest,
          metadata: {"sandbox_id" => sandbox_operation.target_id}
        )
        @ledger.set_result(operation.id, {"container_id" => container_id, "sandbox_id" => sandbox_operation.target_id})
        begin
          @ledger.transition(operation_id: operation.id, to: "Validated")
          verify_image(normalized, normalized.fetch("runtime_class"))
          @ledger.transition(operation_id: operation.id, to: "ImagePinned")
          @ledger.transition(operation_id: operation.id, to: "WorkspaceAllocated")
          result = invoke_optional(:create_container, {id: container_id, sandbox_id: sandbox_operation.target_id,
                                                       spec: normalized, gate: :closed})
          raise Error, "create_container backend effect returned false" if result == false

          claim_backend_resources(operation, :container, result, parent: sandbox_operation.target_id,
                                                                 fallback_id: container_id)
          @ledger.transition(operation_id: operation.id, to: "IsolationCreated")
          @ledger.transition(operation_id: operation.id, to: "ResourcesAttached")
          @ledger.transition(operation_id: operation.id, to: "WorkloadStopped")
          container_id
        rescue AmbiguousResult, Timeout::Error => error
          raise mark_unknown(operation.id, error)
        rescue StandardError => error
          raise rollback_failure(operation.id, error)
        end
      end

      def start_container(id, request_id: nil)
        operation = container_operation!(id)
        reject_unknown!(operation)
        return true if operation.state == "Running"
        raise InvalidTransition, "container #{id} must be WorkloadStopped before start" unless operation.state == "WorkloadStopped"

        parent = sandbox_operation!(operation.metadata.fetch("sandbox_id"))
        reject_unknown!(parent)
        request_id = request_id_for(request_id)
        existing = @ledger.operation_for_request(request_id)
        if existing
          return replay_result(existing, "container_id", action: "start_container",
                                                         config_digest: operation.config_digest, target_id: operation.target_id)
        end
        start_operation = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "start_container",
          target_id: operation.target_id, owner: operation.owner, config_digest: operation.config_digest
        )
        @ledger.set_result(start_operation.id, {"container_id" => operation.target_id})
        begin
          @ledger.transition(operation_id: start_operation.id, to: "Validated")
          @ledger.transition(operation_id: start_operation.id, to: "ImagePinned")
          @ledger.transition(operation_id: start_operation.id, to: "WorkspaceAllocated")
          @ledger.transition(operation_id: start_operation.id, to: "IsolationCreated")
          @ledger.transition(operation_id: start_operation.id, to: "ResourcesAttached")
          @ledger.transition(operation_id: start_operation.id, to: "WorkloadStopped")
          raise Error, "start_container backend effect returned false" if invoke_optional(:start_container,
                                                                                          {id: id, gate: :closed}) == false

          @ledger.transition(operation_id: parent.id, to: "Running") if parent.state == "WorkloadStopped"
          @ledger.transition(operation_id: operation.id, to: "Running")
          @ledger.transition(operation_id: start_operation.id, to: "Running")
          invoke_optional(:release_workload_gate, {id: id, sandbox_id: parent.target_id})
          true
        rescue AmbiguousResult, Timeout::Error => error
          raise mark_unknown(operation.id, error)
        rescue StandardError => error
          raise rollback_failure(start_operation.id, error)
        end
      end

      def stop_container(id, timeout:, request_id: nil)
        operation = container_operation!(id)
        reject_unknown!(operation)
        request_id = request_id_for(request_id)
        existing = @ledger.operation_for_request(request_id)
        if existing
          return replay_result(existing, "container_id", action: "stop_container",
                                                         config_digest: operation.config_digest, target_id: operation.target_id)
        end
        return id if operation.state == "Stopped"
        raise InvalidTransition, "container #{id} is already Removed" if operation.state == "Removed"
        unless %w[Running WorkloadStopped].include?(operation.state)
          raise InvalidTransition, "container #{id} cannot be stopped from #{operation.state}"
        end

        stop_operation = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "stop_container",
          target_id: operation.target_id, owner: operation.owner, config_digest: operation.config_digest
        )
        @ledger.set_result(stop_operation.id, {"container_id" => id})
        begin
          states = if operation.state == "WorkloadStopped"
                     %w[Validated ImagePinned WorkspaceAllocated IsolationCreated ResourcesAttached WorkloadStopped RollingBack]
                   else
                     %w[Validated ImagePinned WorkspaceAllocated IsolationCreated ResourcesAttached WorkloadStopped Running Stopping]
                   end
          states.each do |state|
            @ledger.transition(operation_id: stop_operation.id, to: state)
          end
          @ledger.transition(operation_id: operation.id, to: "Stopping") if operation.state == "Running"
          raise Error, "stop_container backend effect returned false" if invoke_optional(:stop_container,
                                                                                         {id: id, timeout: timeout}) == false

          @ledger.transition(operation_id: stop_operation.id, to: "Stopped")
          @ledger.transition(operation_id: operation.id, to: "Stopped") if @ledger.operation(operation.id).state == "Stopping"
          if operation.state == "WorkloadStopped"
            @ledger.transition(operation_id: operation.id, to: "RollingBack")
            @ledger.transition(operation_id: operation.id, to: "Stopped")
          end
          id
        rescue AmbiguousResult, Timeout::Error => error
          raise mark_unknown(stop_operation.id, error)
        rescue StandardError => error
          raise rollback_failure(stop_operation.id, error)
        end
      end

      def remove_container(id, request_id: nil)
        operation = container_operation!(id)
        request_id = request_id_for(request_id)
        existing = @ledger.operation_for_request(request_id)
        if existing
          return replay_result(existing, "container_id", action: "remove_container",
                                                         config_digest: operation.config_digest, target_id: operation.target_id)
        end
        reject_unknown!(operation)
        raise InvalidTransition, "container #{id} must be Stopped before removal" unless operation.state == "Stopped"

        removal = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "remove_container",
          target_id: id, owner: operation.owner, config_digest: operation.config_digest
        )
        @ledger.set_result(removal.id, {"container_id" => id})
        begin
          %w[Validated ImagePinned WorkspaceAllocated IsolationCreated ResourcesAttached WorkloadStopped RollingBack Stopped
             Removed].each do |state|
            @ledger.transition(operation_id: removal.id, to: state)
          end
          raise Error, "remove_container backend effect returned false" if invoke_optional(:remove_container, {id: id}) == false

          @ledger.transition(operation_id: operation.id, to: "RollingBack")
          RollbackExecutor.new(ledger: @ledger, adapter: @adapter, observer: @observer).execute(
            operation_id: operation.id,
            operation_error: {"class" => "Remove", "message" => "container removal cleanup"},
            mark_failed: false
          )
          @ledger.transition(operation_id: operation.id, to: "Removed")
          id
        rescue AmbiguousResult, Timeout::Error => error
          raise mark_unknown(removal.id, error)
        rescue StandardError => error
          raise rollback_failure(removal.id, error)
        end
      end

      def container_status(id)
        operation = container_operation!(id)
        backend = invoke_optional(:container_status, {id: id})
        {"id" => id, "state" => operation.state, "backend" => backend}.freeze
      end

      def exec(id, cmd, tty:, request_id: nil)
        operation = container_operation!(id)
        reject_workload_action!(operation)
        invoke_optional(:exec, {id: id, cmd: Array(cmd), tty: tty, request_id: request_id}) || StringIO.new
      end

      def attach(id, tty:, request_id: nil)
        operation = container_operation!(id)
        reject_workload_action!(operation)
        invoke_optional(:attach, {id: id, tty: tty, request_id: request_id}) || StringIO.new
      end

      def logs(id, follow:, since:, tail:, request_id: nil)
        operation = container_operation!(id)
        raise StateUnknownError, "container #{id} is StateUnknown; logs are observe-only" if operation.state == "StateUnknown" && follow

        invoke_optional(:logs, {id: id, follow: follow, since: since, tail: tail, request_id: request_id}) || StringIO.new
      end

      def stats(id)
        operation = container_operation!(id)
        backend = invoke_optional(:stats, {id: id})
        {"id" => id, "state" => operation.state, "stats" => backend}.freeze
      end

      def checkpoint_base(runtime_class:, request_id: nil)
        selected = String(runtime_class)
        raise ValidationError, "unsupported runtime class #{selected.inspect}" unless ConfigValidator::RUNTIME_CLASSES.include?(selected)

        request_id = request_id_for(request_id)
        digest = Canonical.digest("runtime_class" => selected, "request_id" => request_id)
        existing = @ledger.operation_for_request(request_id)
        return replay_result(existing, "snapshot_id", action: "checkpoint_base", config_digest: digest) if existing

        operation = @ledger.begin_operation(
          request_id: request_id, operation_id: request_id, action: "checkpoint_base",
          target_id: nil, owner: "snapshot:#{request_id}", config_digest: digest,
          metadata: {"runtime_class" => selected}
        )
        snapshot_id = stable_id("snapshot", request_id)
        @ledger.set_result(operation.id, {"snapshot_id" => snapshot_id, "runtime_class" => selected})
        begin
          @ledger.transition(operation_id: operation.id, to: "Validated")
          @ledger.transition(operation_id: operation.id, to: "ImagePinned")
          @ledger.transition(operation_id: operation.id, to: "WorkspaceAllocated")
          @ledger.transition(operation_id: operation.id, to: "IsolationCreated")
          @ledger.transition(operation_id: operation.id, to: "ResourcesAttached")
          payload = invoke_optional(:checkpoint_base, {runtime_class: selected, state: "WorkloadStopped"}) || {}
          raise Error, "checkpoint_base backend effect returned false" if payload == false

          @snapshot_store.write(snapshot_id: snapshot_id, state: "WorkloadStopped", identity: "base:#{selected}:#{snapshot_id}",
                                payload: payload)
          @ledger.transition(operation_id: operation.id, to: "WorkloadStopped")
          snapshot_id
        rescue AmbiguousResult, Timeout::Error => error
          raise mark_unknown(operation.id, error)
        rescue StandardError => error
          raise rollback_failure(operation.id, error)
        end
      end

      def recover
        raise RecoveryRequired, "runtime recovery requires an injected resource observer" unless @observer_available

        pending = []
        RollbackExecutor.new(ledger: @ledger, adapter: @adapter, observer: @observer).then do |executor|
          @ledger.recovery_candidates.each do |operation|
            next if operation.state == "StateUnknown"

            pending << executor.execute(operation_id: operation.id,
                                        operation_error: operation.error || {"class" => "Recovery", "message" => "replayed cleanup"},
                                        mark_failed: false)
          end
        end
        report = StartupReconciler.new(ledger: @ledger, observer: @observer, cleaner: @cleaner,
                                       orphan_predicate: @orphan_predicate, audit: @audit).reconcile
        report.to_h.merge("pending_recovered" => pending).freeze
      end

      def operation_state(id)
        if (operation = @ledger.operation(id))
          operation.state
        elsif (operation = sandbox_operation(id))
          operation.state
        elsif (operation = container_operation(id))
          operation.state
        end
      end

      private

      def effect_step(operation, state, kind, config, sandbox_id:, runtime_class:)
        method_name = {
          workspace: :allocate_workspace,
          isolation: :create_isolation,
          attached: :attach_resources,
          stopped: :hold_workload
        }.fetch(kind)
        result = invoke_optional(method_name, {sandbox_id: sandbox_id, config: config,
                                               runtime_class: runtime_class, gate: :closed})
        raise Error, "#{method_name} backend effect returned false" if result == false

        claim_backend_resources(operation, kind, result, parent: sandbox_id,
                                                         fallback_id: "#{kind}-#{sandbox_id}")
        @ledger.transition(operation_id: operation.id, to: state)
      end

      def claim_backend_resources(operation, kind, result, parent:, fallback_id:)
        resources = extract_resources(result)
        resources = [{"kind" => kind.to_s, "id" => fallback_id, "identity" => "#{kind}:#{fallback_id}"}] if resources.empty?
        resources.each_with_index do |resource, index|
          hash = resource.respond_to?(:to_h) ? resource.to_h : {"id" => resource}
          resource_id = String(hash["id"] || hash[:id] || "#{fallback_id}-#{index}")
          resource_kind = String(hash["kind"] || hash[:kind] || kind)
          identity = hash["identity"] || hash[:identity] || hash["stable_identity"] || hash[:stable_identity] || "#{resource_kind}:#{resource_id}"
          metadata = hash["metadata"] || hash[:metadata] || {}
          metadata = metadata.merge("parent" => parent.to_s)
          @ledger.claim(operation_id: operation.id, kind: resource_kind, id: resource_id,
                        identity: identity, metadata: metadata)
        end
      end

      def extract_resources(result)
        return [] if result.nil?

        if result.is_a?(Hash)
          nested = result["resources"] || result[:resources]
          return Array(nested) if nested
          return [result] if result.key?("id") || result.key?(:id) || result.key?("kind") || result.key?(:kind)

          return []
        end
        if result.is_a?(Array)
          return result if result.all? { |entry| resource_entry?(entry) }

          return []
        end
        if result.is_a?(String)
          [result]
        elsif result.respond_to?(:to_h)
          hash = result.to_h
          hash.is_a?(Hash) && (hash.key?("id") || hash.key?(:id) || hash.key?("kind") || hash.key?(:kind)) ? [result] : []
        else
          []
        end
      end

      def resource_entry?(entry)
        return true if entry.is_a?(String)
        return false unless entry.respond_to?(:to_h)

        hash = entry.to_h
        hash.is_a?(Hash) && (hash.key?("id") || hash.key?(:id) || hash.key?("kind") || hash.key?(:kind))
      rescue TypeError
        false
      end

      def verify_image(config, runtime_class)
        return unless @adapter.respond_to?(:verify_image)

        response = invoke_optional(:verify_image, {config: config, runtime_class: runtime_class})
        raise ValidationError, "image digest verification failed" if response == false
      end

      def rollback_failure(operation_id, original_error)
        @ledger.fail(operation_id, error: original_error)
        report = RollbackExecutor.new(ledger: @ledger, adapter: @adapter, observer: @observer).execute(
          operation_id: operation_id, operation_error: original_error, mark_failed: false
        )
        OperationFailure.new("runtime operation #{operation_id} failed: #{original_error.message}",
                             operation_id: operation_id, cause_error: original_error,
                             cleanup_errors: report.fetch("cleanup_errors"))
      rescue StandardError => cleanup_error
        OperationFailure.new("runtime operation #{operation_id} failed: #{original_error.message}",
                             operation_id: operation_id, cause_error: original_error,
                             cleanup_errors: [{"resource" => "ledger", "error" => "#{cleanup_error.class}: #{cleanup_error.message}"}])
      end

      def mark_unknown(operation_id, error)
        begin
          @ledger.transition(operation_id: operation_id, to: "StateUnknown")
        rescue InvalidTransition
          # The operation may already have been durably marked unknown by a
          # concurrent recovery worker; the original ambiguity remains primary.
          nil
        end
        @ledger.fail(operation_id, error: error)
        OperationFailure.new("runtime operation #{operation_id} has an ambiguous result: #{error.message}",
                             operation_id: operation_id, cause_error: error)
      end

      def replay_result(operation, key, action: nil, config_digest: nil, target_id: nil)
        raise OwnershipConflict, "request #{operation.request_id} was replayed with incompatible operation" unless operation
        if (action && operation.action != action) ||
           (config_digest && operation.config_digest != config_digest) ||
           (!target_id.nil? && operation.target_id != target_id)
          raise OwnershipConflict, "request #{operation.request_id} was replayed with different intent"
        end
        if operation.state == "StateUnknown"
          raise StateUnknownError.new("operation #{operation.id} is StateUnknown; observe or cleanup only", operation_id: operation.id)
        end
        if operation.error && operation.state != "Removed"
          raise OperationFailure.new("request #{operation.request_id} previously failed: #{operation.error.fetch("message")}",
                                     operation_id: operation.id, cause_error: Error.new(operation.error.fetch("message")),
                                     cleanup_errors: operation.cleanup_errors)
        end
        unless %w[WorkloadStopped Running Stopping Stopped Removed].include?(operation.state)
          raise RecoveryRequired.new("request #{operation.request_id} is incomplete at #{operation.state}; recover before retry",
                                     operation_id: operation.id)
        end

        result = operation.result || {}
        result.fetch(key) { operation.target_id || true }
      end

      def sandbox_operation!(id)
        sandbox_operation(id) || raise(OwnershipConflict, "unknown sandbox #{id}")
      end

      def sandbox_operation(id)
        id = String(id)
        @ledger.operations.reverse_each do |operation|
          next unless %w[run_sandbox remove_sandbox].include?(operation.action)
          next unless operation.target_id == id || operation.result&.fetch("sandbox_id", nil) == id

          return operation
        end
        nil
      end

      def container_operation!(id)
        container_operation(id) || raise(OwnershipConflict, "unknown container #{id}")
      end

      def container_operation(id)
        id = String(id)
        @ledger.operations.reverse_each do |operation|
          next unless %w[create_container remove_container].include?(operation.action)
          next unless operation.target_id == id || operation.result&.fetch("container_id", nil) == id

          return operation
        end
        nil
      end

      def reject_unknown!(operation)
        return unless operation.state == "StateUnknown"

        raise StateUnknownError.new("operation #{operation.id} is StateUnknown; cleanup or observe only", operation_id: operation.id)
      end

      def reject_workload_action!(operation)
        reject_unknown!(operation)
        raise InvalidTransition, "container #{operation.target_id} is not Running" unless operation.state == "Running"
      end

      def stop_child_containers(sandbox_id, timeout:)
        @ledger.operations.select do |operation|
          operation.action == "create_container" && operation.metadata.fetch("sandbox_id", nil) == sandbox_id &&
            %w[Running WorkloadStopped].include?(operation.state)
        end.each do |container|
          _stop_container_without_request(container, timeout: timeout)
        end
      end

      def remove_child_containers(sandbox_id)
        @ledger.operations.select do |operation|
          operation.action == "create_container" && operation.metadata.fetch("sandbox_id", nil) == sandbox_id &&
            operation.state != "Removed"
        end.each do |container|
          unless container.state == "Stopped"
            raise InvalidTransition, "container #{container.target_id} must be Stopped before sandbox removal"
          end
          raise Error, "remove_container backend effect returned false" if invoke_optional(:remove_container,
                                                                                           {id: container.target_id}) == false

          @ledger.transition(operation_id: container.id, to: "RollingBack")
          RollbackExecutor.new(ledger: @ledger, adapter: @adapter, observer: @observer).execute(
            operation_id: container.id,
            operation_error: {"class" => "Remove", "message" => "sandbox removal cleanup"},
            mark_failed: false
          )
          @ledger.transition(operation_id: container.id, to: "Removed")
        end
      end

      def _stop_container_without_request(operation, timeout:)
        @ledger.transition(operation_id: operation.id, to: "Stopping") if operation.state == "Running"
        raise Error, "stop_container backend effect returned false" if invoke_optional(:stop_container,
                                                                                       {id: operation.target_id, timeout: timeout}) == false

        @ledger.transition(operation_id: operation.id, to: "Stopped") if @ledger.operation(operation.id).state == "Stopping"
        @ledger.transition(operation_id: operation.id, to: "Stopped") if @ledger.operation(operation.id).state == "WorkloadStopped"
      end

      def spec_runtime_class(spec)
        spec.respond_to?(:to_h) ? spec.to_h["runtime_class"] || spec.to_h["runtimeClassName"] : nil
      end

      def default_observer
        lambda do
          if @adapter.respond_to?(:list_resources)
            @adapter.list_resources
          else
            []
          end
        end
      end

      def default_cleaner
        return nil unless @adapter.respond_to?(:cleanup_resource)

        ->(resource) { @adapter.cleanup_resource(resource) }
      end

      def invoke_optional(name, payload)
        return nil unless @adapter.respond_to?(name)

        method = @adapter.method(name)
        parameters = method.parameters
        positional_parameters = parameters.select { |kind, _| %i[req opt].include?(kind) }
        keyword_parameters = parameters.select { |kind, _| %i[key keyreq keyrest].include?(kind) }
        if positional_parameters.any? && keyword_parameters.any?
          arguments = positional_parameters.each_with_index.map do |(_kind, parameter), index|
            parameter_value(parameter, payload, index)
          end
          keywords = if keyword_parameters.any? { |kind, _| kind == :keyrest }
                       payload
                     else
                       accepted = keyword_parameters.map(&:last)
                       payload.select { |key, _value| accepted.include?(key) }
                     end
          method.call(*arguments, **keywords)
        elsif keyword_parameters.any?
          method.call(**payload)
        elsif method.arity.zero?
          method.call
        elsif method.arity == 1
          parameter = parameters.first&.last
          if %i[config spec id sandbox_id container_id runtime_class].include?(parameter)
            method.call(parameter_value(parameter, payload, 0))
          else
            method.call(payload)
          end
        else
          first = payload[:id] || payload[:sandbox_id] || payload[:runtime_class]
          method.call(first, payload)
        end
      rescue ArgumentError => error
        raise error unless error.message.include?("keyword") || error.message.include?("wrong number")

        method.call(payload)
      end

      def parameter_value(parameter, payload, index)
        return payload[parameter] if payload.key?(parameter)

        case parameter.to_sym
        when :id, :sandbox_id, :container_id
          payload[:id] || payload[:sandbox_id] || payload[:container_id]
        when :sandbox
          payload[:sandbox_id]
        when :config, :spec
          payload[:config] || payload[:spec]
        when :runtime_class
          payload[:runtime_class]
        else
          payload.values[index]
        end
      end

      def request_id_for(request_id)
        value = request_id || SecureRandom.uuid
        string = String(value)
        raise ValidationError, "request_id must not be empty" if string.empty? || string.include?("\0")

        string
      end

      def stable_id(prefix, request_id)
        "#{prefix}-#{Digest::SHA256.hexdigest(String(request_id))[0, 24]}"
      end

      # R-3.4: one runtime instance serializes all public lifecycle calls.  A
      # retry that races its first invocation must observe the durable request
      # record rather than starting a second backend effect.
      PUBLIC_METHODS = %i[
        run_sandbox stop_sandbox remove_sandbox create_container start_container
        stop_container remove_container container_status exec attach logs stats
        checkpoint_base recover operation_state
      ].freeze

      PUBLIC_METHODS.each do |method_name|
        unlocked_name = :"__unlocked_#{method_name}"
        alias_method unlocked_name, method_name
        define_method(method_name) do |*arguments, **keywords, &block|
          @mutex.synchronize do
            public_send(unlocked_name, *arguments, **keywords, &block)
          end
        end
      end
      public(*PUBLIC_METHODS)
    end

    Native = Runtime unless const_defined?(:Native, false)

    class MicroVM < Runtime
      def initialize(**)
        super
      end
    end

    MicroVMRestricted = MicroVM unless const_defined?(:MicroVMRestricted, false)
    Manager = Runtime
    Lifecycle = Runtime
    Engine = Runtime
  end
end
