# frozen_string_literal: true

require "fileutils"
require "json"
require "monitor"
require "pathname"
require "securerandom"
require "tmpdir"

require_relative "../platform/linux/openat2"
require_relative "deferred_fsync"
require_relative "record_files"
require_relative "linux_storage_devices"

module Rubernetes
  module Volume
    # The one place the volume manager asks an injected collaborator what it
    # can do.  Mount adapters, CSI adapters, secret resolvers, token providers
    # and path resolvers are injected and genuinely differ (the in-memory
    # FilesystemAdapter has no find_mount, only a kubelet node plugin answers
    # pod_context?, a foreign error carries no details), so each question is
    # asked here once, by name, instead of inline at every call site.
    module Capability
      module_function

      # -- values that cross the adapter boundary ---------------------------

      def hash_like?(value) = value.respond_to?(:to_h)

      def list_like?(value) = value.respond_to?(:to_a)

      # -- mount and device adapters ----------------------------------------

      def finds_mounts?(adapter) = adapter.respond_to?(:find_mount)

      def lists_mounts?(adapter) = adapter.respond_to?(:list_mounts)

      def lists_devices?(adapter) = adapter.respond_to?(:list_devices)

      def unmounts?(adapter) = adapter.respond_to?(:unmount)

      def applies_fs_group?(adapter) = adapter.respond_to?(:apply_fs_group)

      def applies_selinux_label?(adapter) = adapter.respond_to?(:apply_selinux_label)

      def applies_mount_propagation?(adapter) = adapter.respond_to?(:apply_mount_propagation)

      # -- CSI adapters ------------------------------------------------------

      # A volume spec may carry its own adapter under "csi"; anything that
      # cannot create a volume is not one.
      def csi_adapter?(csi) = csi.respond_to?(:create_volume)

      # The kubelet plugin registry resolves a node plugin per driver name.
      def plugin_registry?(csi) = csi.respond_to?(:for_driver)

      # Only a kubelet node plugin receives the Pod in its publish context.
      def declares_pod_context?(csi) = csi.respond_to?(:pod_context?)

      def declares_republish?(csi) = csi.respond_to?(:requires_republish?)

      def decides_fs_group?(csi) = csi.respond_to?(:fs_group_mode)

      def reports_identity?(csi) = csi.respond_to?(:identity)

      def named?(identity) = identity.respond_to?(:name)

      def lists_volumes?(csi) = csi.respond_to?(:list_volumes)

      def lists_snapshots?(csi) = csi.respond_to?(:list_snapshots)

      # -- errors (a plugin or adapter may raise any class) -------------------

      def reports_ambiguity?(error) = error.respond_to?(:ambiguous?)

      def detailed?(error) = error.respond_to?(:details)

      def names_operation?(error) = error.respond_to?(:operation)

      def names_resource?(error) = error.respond_to?(:resource_id)

      # -- backends ----------------------------------------------------------

      def updatable?(backend) = backend.respond_to?(:update)

      def rotates_token?(backend) = backend.respond_to?(:rotate_token)

      # -- secret resolvers, token providers, subPath handles -----------------

      def resolver_object?(resolver) = resolver.respond_to?(:resolve)

      def callable?(resolver) = resolver.respond_to?(:call)

      def declares_parameters?(resolver) = resolver.respond_to?(:parameters)

      def per_pod_provider?(provider) = provider.respond_to?(:for_pod)

      def exposes_path?(handle) = handle.respond_to?(:path)

      def exposes_identity?(handle) = handle.respond_to?(:identity)
    end
  end
end

require_relative "manager/volume_store"
require_relative "manager/shared_csi_stages"
require_relative "manager/operation_support"
require_relative "manager/remote_backend"
require_relative "manager/controller"
require_relative "manager/node"
require_relative "manager/records"
require_relative "manager/redaction"
require_relative "manager/csi_secrets"
require_relative "manager/specs"
require_relative "manager/backend_factory"
require_relative "manager/content_operations"
require_relative "manager/csi_observation"
require_relative "manager/operation_resolution"
require_relative "manager/recovery"

module Rubernetes
  module Volume
    # The node's volume manager: owns the durable volume records, the
    # operation and mount ledgers and the backends, and exposes the CSI-shaped
    # controller and node lifecycle.  This file is the entry point --
    # construction and the public interface; each responsibility lives in a
    # module or collaborator under manager/.
    class Manager
      include Records
      include Redaction
      include CSISecrets
      include Specs
      include BackendFactory
      include ContentOperations
      include CSIObservation
      include OperationResolution
      include Recovery

      CSI_RECOVERY_PAGE_LIMIT = 10_000

      def initialize(data_dir: nil, root: nil, adapter: nil, mount_adapter: nil, path_security: nil,
                     resolver: nil, store: nil, operation_ledger: nil, mount_ledger: nil, csi: nil,
                     binder: nil, snapshot_store: nil, clock: -> { Time.now.utc }, fsync: false,
                     identity: nil, capabilities: nil, device_adapter: nil, require_real_readback: false,
                     secret_resolver: nil, token_provider: nil, storage_devices: nil, project_quota: nil)
        @data_dir = File.expand_path((data_dir || root || File.join(Dir.tmpdir, "rubernetes-volumes")).to_s)
        @root = File.expand_path((root || File.join(@data_dir, "volumes")).to_s)
        FileUtils.mkdir_p(@root)
        ensure_real_readback_adapter!(require_real_readback, mount_adapter, adapter)
        @token_provider = token_provider
        @project_quota = project_quota
        assign_adapters(adapter: adapter, mount_adapter: mount_adapter, device_adapter: device_adapter,
                        require_real_readback: require_real_readback, fsync: fsync)
        @storage_devices = storage_devices || (LinuxStorageDevices.new(data_dir: @data_dir, fsync: fsync) if @require_real_readback)
        @default_path_security = path_security.nil? && resolver.nil?
        @path_security = path_security || default_path_security(resolver, csi)
        pin_configured_volume_roots!(@data_dir, @root) if data_dir || root
        @volume_store = store || VolumeStore.new(path: File.join(@data_dir, "volumes.json"), fsync: fsync)
        @reconstruction_stats = reconstruct_from_store
        @operations = operation_ledger || OperationLedger.new(path: File.join(@data_dir, "operations.json"), fsync: fsync, clock: clock)
        @mount_ledger = mount_ledger || MountIdentityLedger.new(path: File.join(@data_dir, "mounts.json"), fsync: fsync)
        install_mount_live_check
        @backends = {}
        @volume_lock = Monitor.new
        @csi = csi
        @secret_resolver = secret_resolver
        @csi_secret_mutex = Mutex.new
        @volatile_csi_secrets = {}
        @secret_redactions = []
        @identity_value = identity || Identity.new(supports: %w[STAGE_UNSTAGE GET_VOLUME_STATS EXPAND_VOLUME SNAPSHOT CLONE])
        @capabilities_value = capabilities || default_capabilities
        @binder = binder || Binder.new
        # Snapshot metadata is lifecycle state, not a cache.  The default is
        # therefore an fsync'd catalog beside the volume store so a restart
        # can reconcile CSI ListSnapshots instead of silently forgetting IDs.
        @snapshot_store = snapshot_store || DurableSnapshotStore.new(path: File.join(@data_dir, "snapshots.json"), fsync: true)
        @clock = clock
        @snapshot_manager = build_snapshot_manager(csi, clock)
        @controller = Controller.new(self)
        @node = Node.new(self)
        recover_backends_from_store!
      rescue StandardError
        close
        raise
      end

      attr_reader :volume_store, :backends, :operations, :mount_ledger, :controller, :node, :binder, :snapshot_manager, :adapter,
                  :mount_adapter, :device_adapter, :path_security, :data_dir, :require_real_readback, :reconstruction_stats, :root,
                  :kubelet_csi_paths

      def close
        @path_security.close if @path_security && @path_security.is_a?(PathSecurity)
      end

      def pin_configured_volume_roots!(*paths)
        return unless defined?(NativeMountAdapter) && @mount_adapter.is_a?(NativeMountAdapter) && @path_security.is_a?(PathSecurity)

        paths.uniq.each do |path|
          FileUtils.mkdir_p(path)
          @path_security.pin_configured_root!(path) do
            NativeMountAdapter.parse_mountinfo(File.binread("/proc/self/mountinfo"))
          end
        end
      end

      def configure_kubelet_csi_paths(root)
        return unless @mount_adapter.is_a?(NativeMountAdapter)

        root = @path_security.validate_target!(File.expand_path(root))
        paths = SharedCSIStages::KubeletPaths.new(root)
        path = @path_security.validate_target!(paths.directory)
        FileUtils.mkdir_p(path)
        mount = Rubernetes::Platform::Linux::Mount.new
        @path_security.allow_mount_boundary!(root) if @path_security.root != root && mount.mountinfo_entry(root)
        # Give stages a shared mount under the CSI plugin's
        # HostPath. Leave the rest of the kubelet root untouched: rebinding
        # it would duplicate existing live mount IDs after an agent upgrade.
        mount.ensure_shared_self_bind(target: path, recursive_bind: true)
        @path_security.allow_mount_boundary!(path) unless @path_security.root == path
        @kubelet_csi_paths = paths
      end

      def legacy_csi_stage_path(key)
        File.join(@data_dir, "csi-staging", key)
      end

      def kubelet_csi_filesystem?(id)
        backend = @backends[id]
        @mount_adapter.is_a?(NativeMountAdapter) && backend.is_a?(RemoteBackend) && backend.kubelet_filesystem_publish?
      end

      def identity
        @identity_value.is_a?(Identity) ? @identity_value : Identity.new(**@identity_value.to_h.transform_keys(&:to_sym))
      end

      # One lock per volume, not one for the node.  Every volume operation
      # persists three ledgers with fsync, and behind a single node-wide lock a
      # 100-Pod ReplicationController's kube-api-access volumes queued for
      # minutes (volume.ready median 65 s late in a round).  The ledgers and
      # the volume store synchronize themselves; the lock only orders the
      # operations of ONE volume.
      def with_volume_lock(key, &)
        lock = @volume_lock.synchronize { (@volume_locks ||= {})[key.to_s] ||= Monitor.new }
        lock.synchronize(&)
      end

      # Mutating an object after an effect response was lost is unsafe: the
      # next request could attach or publish the same kernel resource twice.
      # Keep the durable record fenced until recover has observed the adapter.
      #
      # Teardown is the exception the state machine already names: "Cleanup" is
      # one of the actions an Unknown volume still permits.  Every CSI teardown
      # call is required to be idempotent and to succeed when the volume is
      # already gone (csi.proto: NodeUnpublishVolume, NodeUnstageVolume,
      # ControllerUnpublishVolume and DeleteVolume are all "idempotent"), and
      # fencing them instead is how a Pod becomes unremovable: an Unknown
      # volume refused unpublish, unstage, detach and delete alike, the node
      # left the Pod in CleanupPending, and the Pod stayed Terminating in the
      # API until the spec waiting for it to disappear timed out.
      def ensure_known!(record, action: "Mutate")
        StateMachine.ensure_action!(record.state, action)
      end

      def ensure_attach_policy!(record, node:, pod: nil)
        @controller.ensure_attach_policy(record, node: node, pod: pod)
      end

      def capabilities
        Types.deep_copy(@capabilities_value)
      end

      # -- controller lifecycle ------------------------------------------------

      def create_volume(spec, token:)
        controller.create_volume(spec, token: token)
      end

      def delete_volume(id, token:)
        controller.delete_volume(id, token: token)
      end

      def publish(id, node_name, token:)
        controller.publish(id, node_name, token: token)
      end

      def unpublish(id, node_name, token:)
        controller.unpublish(id, node_name, token: token)
      end

      def create_snapshot(id, token:, name: nil)
        controller.create_snapshot(id, token: token, name: name)
      end

      def delete_snapshot(id, token:)
        controller.delete_snapshot(id, token: token)
      end

      def expand(id, capacity, token:)
        controller.expand(id, capacity, token: token)
      end

      def attach(id, node_name, token:)
        controller.publish(id, node_name, token: token)
      end

      def detach(id, node_name, token:)
        controller.unpublish(id, node_name, token: token)
      end

      # -- node lifecycle ------------------------------------------------------

      def stage(id, path, token:, **)
        node.stage(id, path, token: token, **)
      end

      def node_publish(id, pod, container_path, readonly:, token:, **)
        node.publish(id, pod, container_path, readonly: readonly, token: token, **)
      end

      def direct_path(id, pod:, fs_group: nil)
        node.direct_path(id, pod: pod, fs_group: fs_group)
      end

      def node_unpublish(id, pod, container_path, token:)
        node.unpublish(id, pod, container_path, token: token)
      end

      # The summary API's stats for a kubelet CSI volume published at +path+
      # (see RemoteBackend#kubelet_volume_stats).
      def csi_volume_stats(id, path, health: false)
        backend = backends[id.to_s]
        return nil unless backend.is_a?(RemoteBackend)

        backend.kubelet_volume_stats(path, health: health)
      end

      # ExpandInUseVolume on the node: NodeExpandVolume on the Pod's
      # published target, recording the new capacity.  Returns the driver's
      # response, :unsupported, or nil when the volume is not a published
      # kubelet CSI volume.
      def node_expand_in_use(id, pod, container_path, capacity_bytes:, token:)
        node.expand_in_use(id, pod, container_path, capacity_bytes: capacity_bytes, token: token)
      end

      def node_republish(id, pod, container_path, token:)
        node.republish(id, pod, container_path, token: token)
      end

      def unstage(id, path, token:, **)
        node.unstage(id, path, token: token, **)
      end

      def stats(id, path: nil)
        node.stats(id, path: path)
      end

      def project_quota_usage(id, path)
        return unless @project_quota && id

        record = volume_store[id]
        return unless record&.backend == "emptyDir"

        project = record.spec.dig("backendResult", "projectQuotaId")
        @project_quota.usage(File.join(root, record.id), project, published_path: path) if project
      end

      # -- queries -------------------------------------------------------------

      def volume(id)
        fetch_record(id)
      end

      def list_volumes
        volume_store.values
      end

      def list_snapshots
        snapshot_manager.list
      end

      # -- Pod lifecycle hooks -------------------------------------------------

      # Compatibility with Node::Lifecycle's prepare/release hooks. A Pod's
      # volume specs are prepared as independent records; release reverses the
      # local references without bypassing the state machine.
      def prepare(pod, token: nil)
        token ||= "prepare-#{pod_identifier(pod)}"
        volumes = Types.key(Types.key(pod.to_h, "spec", {}), "volumes", [])
        ids = Array(volumes).map do |volume|
          spec = normalize_pod_volume(volume, pod)
          create_volume(spec, token: "#{token}-#{Types.key(volume, "name", SecureRandom.hex(4))}")
        end
        ids.length == 1 ? ids.first : ids
      end

      def release(handle, token: nil)
        ids = handle.is_a?(Array) ? handle : [handle]
        ids.each_with_index do |id, index|
          record = volume_store[id]
          next unless record

          token_value = token || "release-#{id}-#{index}"
          # Only delete records with no ownership; an active consumer is never
          # forcefully detached by the lifecycle compatibility hook.
          delete_volume(id, token: token_value) if record.attachments.empty? && record.publishes.empty? && record.stages.empty?
        end
        true
      end

      # -- binding, snapshots --------------------------------------------------

      def bind(pvc, **)
        binder.bind(pvc, **)
      end

      def register_pv(value)
        binder.register_pv(value)
      end

      def register_pvc(value)
        binder.register_pvc(value)
      end

      def register_storage_class(value)
        binder.register_storage_class(value)
      end

      def restore(snapshot_id, token:, spec: {})
        snapshot_manager.restore(snapshot_id, spec: spec, token: token)
      end

      def clone(id, token:, spec: {})
        snapshot_manager.clone(id, spec: spec, token: token)
      end

      private

      def ensure_real_readback_adapter!(require_real_readback, mount_adapter, adapter)
        return unless require_real_readback == true

        raise MountIdentityError, "real mount readback requires an explicitly injected mount adapter" if mount_adapter.nil? && adapter.nil?
        return unless [mount_adapter, adapter].compact.any?(FilesystemAdapter)

        raise MountIdentityError, "real mount readback cannot use the in-memory FilesystemAdapter"
      end

      def assign_adapters(adapter:, mount_adapter:, device_adapter:, require_real_readback:, fsync:)
        @mount_adapter = mount_adapter || adapter || FilesystemAdapter.new(root: @root, fsync: fsync)
        @adapter = adapter || @mount_adapter
        @device_adapter = device_adapter || @adapter
        native_mount_adapter = defined?(NativeMountAdapter) && @mount_adapter.is_a?(NativeMountAdapter)
        @require_real_readback = require_real_readback == true || native_mount_adapter
      end

      def default_path_security(resolver, csi)
        if resolver
          PathSecurity.new(root: @root, resolver: resolver)
        elsif csi || (defined?(NativeMountAdapter) && @mount_adapter.is_a?(NativeMountAdapter))
          # Native volume and CSI targets use descriptor-relative validation
          # for direct Manager callers as well as the production Assembler.
          descriptor_path_security
        else
          PathSecurity.new(root: "/", require_openat2: true)
        end
      end

      def descriptor_path_security
        openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
        PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
      end

      # What the durable state gave back at startup (kubelet's volume
      # reconstruction): records with mounts or attachments, and the ones
      # whose backend is unknown.
      def reconstruct_from_store
        restored = @volume_store.values
        stats = {
          attempted: restored.count { |record| !record.publishes.to_h.empty? || !record.attachments.to_h.empty? },
          errors: restored.count { |record| record.state.to_s == "Unknown" },
          force_cleaned: 0, force_clean_errors: 0
        }
        force_clean_unknown!(restored, stats)
        stats.freeze
      end

      # Best effort, and deliberately so: this runs inside the constructor,
      # and a node whose fallback cleanup failed must still come up.  Whatever
      # was not cleaned stays in its record (see Recovery).
      def force_clean_unknown!(records, stats)
        force_clean_unknown_publishes(records, stats)
      rescue StandardError
        nil
      end

      def install_mount_live_check
        return unless @mount_ledger.live_check.nil? && Capability.finds_mounts?(@mount_adapter)

        @mount_ledger.live_check = lambda do |mount|
          observed = @mount_adapter.find_mount(mount.target)
          !observed.nil? && observed.fetch("mountId").to_s == mount.mount_id.to_s
        end
      end

      def build_snapshot_manager(csi, clock)
        SnapshotManager.new(backend_lookup: method(:backend_for), record_lookup: method(:fetch_record),
                            create_volume: method(:create_volume), restore_volume: method(:restore_snapshot_volume),
                            clone_volume: method(:clone_volume), store: @snapshot_store, csi: csi, clock: clock,
                            error_sanitizer: method(:persistence_error))
      end

      def default_capabilities
        {"controller" => %w[CREATE_DELETE_VOLUME PUBLISH_UNPUBLISH_VOLUME CREATE_DELETE_SNAPSHOT EXPAND_VOLUME CLONE_VOLUME],
         "node" => %w[STAGE_UNSTAGE_VOLUME PUBLISH_UNPUBLISH_VOLUME GET_VOLUME_STATS EXPAND_VOLUME],
         "accessModes" => %w[ReadWriteOnce ReadOnlyMany ReadWriteMany ReadWriteOncePod]}
      end
    end
  end
end
