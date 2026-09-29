# frozen_string_literal: true

require "fileutils"

require_relative "../common/manager"
require_relative "adapter"
require_relative "artifacts"

module Rubernetes
  module Runtime
    # MicroVM backend (spec/node/runtime.md 5.8.11-5.8.14): the common
    # lifecycle façade over a Firecracker adapter.  One Pod is one jailed
    # Firecracker process with one guest kernel; the Ruby guest supervisor
    # runs the containers inside.
    class MicroVM < Runtime
      RUNTIME_CLASS = "rubernetes-firecracker"
      DEFAULT_CHROOT_BASE = "/srv/rubernetes/jailer"
      DEFAULT_NETNS_ROOT = "/run/rubernetes/netns"
      DEFAULT_RUN_ROOT = "/run/rubernetes/microvm"
      DEFAULT_PARENT_CGROUP = "rubernetes/microvm"
      POD_OVERHEAD = {"cpu" => "50m", "memory" => "128Mi"}.freeze

      def self.runtime_class = RUNTIME_CLASS

      def initialize(data_dir:, artifacts: nil, artifacts_lock: nil, project_root: nil, chroot_base: DEFAULT_CHROOT_BASE, netns_root: DEFAULT_NETNS_ROOT,
                     run_root: DEFAULT_RUN_ROOT, parent_cgroup: DEFAULT_PARENT_CGROUP, machine: nil, use_base_snapshot: true, logger: nil,
                     clock: -> { Time.now.utc }, broker: nil, adapter: nil, **options)
        project_root ||= File.expand_path("../../../..", __dir__)
        artifacts ||= Artifacts.load(lock_path: artifacts_lock || File.join(project_root, MicroVMArtifactDefaults::LOCK_PATH), root: project_root)
        @microvm_adapter = adapter || Adapter.new(runtime_class: self.class.runtime_class, data_dir: data_dir, artifacts: artifacts, chroot_base: chroot_base,
                                                  netns_root: netns_root, run_root: run_root, parent_cgroup: parent_cgroup, clock: clock, logger: logger,
                                                  machine: machine, use_base_snapshot: use_base_snapshot, network_device: self.class.network_device?, broker: broker)
        super(data_dir: data_dir, adapter: @microvm_adapter, clock: clock, **options)
      end

      def self.network_device? = true

      def runtime_class = self.class.runtime_class
      def profile = :l4
      def artifacts = @microvm_adapter.artifacts
      def identity_ledger = @microvm_adapter.identity_ledger
      def snapshot_pool = @microvm_adapter.pool
      def broker = @microvm_adapter.broker
      def session(sandbox_id) = @microvm_adapter.session(sandbox_id)
      def force_teardown(sandbox_id) = @microvm_adapter.force_teardown(sandbox_id)

      # The node lifecycle (like the Native backend) removes a sandbox
      # without a separate stop_sandbox call: stop it first when it is still
      # live so the common state machine can then remove it.
      def remove_sandbox(id, request_id: nil)
        state = operation_state(id)
        stop_sandbox(id, timeout: 10, request_id: request_id && "#{request_id}-stop") if %w[WorkloadStopped Running Stopping StateUnknown].include?(state)
        super(id, request_id: request_id)
      rescue Rubernetes::Runtime::InvalidTransition, Rubernetes::Runtime::RecoveryRequired
        # A hung/unknown VM cannot be gracefully stopped; reconcile host-side.
        errors = @microvm_adapter.force_teardown(id)
        raise Error, "sandbox #{id} force teardown errors: #{errors.inspect}" unless errors.empty?

        id
      end

      def network_sandbox_context(sandbox_id)
        @microvm_adapter.network_sandbox_context(sandbox_id)
      end

      # Prepares the cached base snapshot the fast path restores from.
      def prepare_base!(request_id: nil)
        checkpoint_base(runtime_class: runtime_class, request_id: request_id)
      end

      def pod_overhead = POD_OVERHEAD

      def runtime_class_document
        {"apiVersion" => "node.k8s.io/v1", "kind" => "RuntimeClass", "metadata" => {"name" => self.class.runtime_class_name},
         "handler" => runtime_class, "overhead" => {"podFixed" => POD_OVERHEAD}}
      end

      def self.runtime_class_name = "microvm"
    end

    # The restricted variant has no network device: the guest reaches the
    # outside only through the broker's closed operation set.
    remove_const(:MicroVMRestricted) if const_defined?(:MicroVMRestricted, false)
    class MicroVMRestricted < MicroVM
      RUNTIME_CLASS = "rubernetes-firecracker-restricted"

      def self.runtime_class = RUNTIME_CLASS
      def self.network_device? = false
      def self.runtime_class_name = "microvm-restricted"
    end
  end
end
