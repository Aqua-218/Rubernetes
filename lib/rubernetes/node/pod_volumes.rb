# frozen_string_literal: true

require "digest"
require "base64"
require "fileutils"
require "json"
require "securerandom"

require_relative "status"
require_relative "field_ref"
require_relative "../volume/kubernetes_csi"
require_relative "../volume/csi_migration"
require_relative "kubelet_metrics"
require_relative "pod_volumes/nested_mountpoints"
require_relative "pod_volumes/storage_sources"
require_relative "pod_volumes/trust_bundles"
require_relative "pod_volumes/kubelet_publish_paths"
require_relative "volume_groups"

module Rubernetes
  module Node
    # Turns `pod.spec.volumes` into mounted host paths the runtime can bind
    # into containers, the way kubelet's volume manager does:
    #
    #   1. each referenced volume source is resolved against the API (ConfigMap
    #      and Secret contents, the PersistentVolume behind a claim, downward
    #      API values from the live Pod) and translated to a Volume::Manager
    #      spec whose file map is already computed (`items`, key selection,
    #      `defaultMode`, per-item `mode` are applied here);
    #   2. the manager provisions, attaches, stages and publishes the volume;
    #      native CSI Filesystem and inline NFS targets use the kubelet's per-plugin layout;
    #   3. `subPath` mounts get their own publish under
    #      `<root>/pods/<uid>/volume-subpaths/<container>/<volume>/<index>`
    #      so the descriptor-validated sub-path is what the container sees.
    #
    # The result maps each volume name to its host path plus the metadata a
    # container mount needs.  Release walks the same steps backwards.
    class PodVolumes
      class Error < StandardError
        attr_accessor :volume_name
      end

      # A required ConfigMap, Secret, or claim that is absent. The kubelet
      # reports the dependency as FailedMount and retries.
      class MissingDependency < Error; end
      class Unsupported < Error; end

      include KubeletPublishPaths

      SUPPORTED_SOURCES = (%w[
        emptyDir hostPath configMap secret downwardAPI projected persistentVolumeClaim ephemeral image csi local nfs iscsi fc
      ] + Volume::CSIMigration::DRIVERS.keys).freeze
      DEFAULT_MODE = 0o644

      # +unique_name+: the attachable volume's plugin-qualified name in
      # node.status.volumesInUse.
      Mount = Struct.new(:name, :id, :path, :readonly, :source, :backend, :sub_paths, :direct, :unique_name, :volume_mode, keyword_init: true) do
        def to_h
          {"name" => name, "id" => id, "path" => path, "readonly" => readonly, "source" => source,
           "backend" => backend, "subPaths" => sub_paths, "direct" => direct == true, "uniqueName" => unique_name,
           "volumeMode" => volume_mode}.compact
        end
      end

      # The volume manager's startup reconstruction counts, for
      # reconstruct_volume_operations_total.
      def reconstruction_stats
        @volume.respond_to?(:reconstruction_stats) ? @volume.reconstruction_stats : nil
      end

      def initialize(volume:, reader: nil, node_name: nil, root: nil, kubelet_pod_root: nil, clock: -> { Time.now.utc },
                     node_allocatable: nil, cluster_trust_bundle_projection: false)
        raise ArgumentError, "volume manager is required" unless volume

        @volume = volume
        @reader = reader
        @node_name = node_name.to_s
        @root = File.expand_path(String(root || (volume.respond_to?(:root) ? File.join(volume.root, "pods") : "/var/lib/rubernetes/pods")))
        @kubelet_pod_root = File.expand_path(kubelet_pod_root) if kubelet_pod_root
        @clock = clock
        @node_allocatable = node_allocatable
        @cluster_trust_bundle_projection = cluster_trust_bundle_projection
        # kubelet setupDataDirs: the root directory is made a shared mount at
        # start-up, before any Pod (and before recovery touches the paths of
        # a previous run, which are already beneath the mount).
        ensure_propagating_root!
      end

      attr_reader :root

      # Whether the Pod root is a shared mount (see ensure_propagating_root!).
      def propagating_root?
        @propagating_root == true
      end

      # kubelet binds a container's subPaths when that container starts, and
      # containerd's shim sees them because the host's mount tree is shared
      # and the sandbox is its slave.  The Pod root is made a shared mount
      # here (only with real mounts, never in the in-memory adapter) so the
      # sandbox holder, a slave of it (NamespaceAdapter#make_mounts_slave),
      # sees every bind made under it after the sandbox exists.  Idempotent
      # and re-checked once per process; an existing bind from a previous
      # agent run is reused.
      def ensure_propagating_root!
        return false unless real_mounts? && Process.respond_to?(:uid) && Process.uid.zero?

        PROPAGATING_ROOT_LOCK.synchronize do
          require_relative "../platform/linux/mount"
          FileUtils.mkdir_p(@root)
          # Re-checked on every Pod start, not only once: a process that
          # made the host root recursively private (a test worker forgetting
          # to unshare, an operator's `mount --make-rprivate /`) strips the
          # peer group and every later subPath silently becomes invisible to
          # its sandbox.  The check is one read of /proc/self/mountinfo.
          Rubernetes::Platform::Linux::Mount.new.ensure_shared_self_bind(target: @root, resource_id: "pod-root:#{@root}")
          # Lookups from the path-security root ("/") must be allowed to
          # cross into this one mount.
          security = @volume.respond_to?(:path_security) ? @volume.path_security : nil
          security.allow_mount_boundary!(@root) if security.respond_to?(:allow_mount_boundary!)
          @propagating_root = true
        end
      rescue StandardError => error
        raise Error, "cannot make the Pod root #{@root} a shared mount: #{error.message}"
      end

      PROPAGATING_ROOT_LOCK = Mutex.new

      def real_mounts?
        adapter = @volume.respond_to?(:mount_adapter) ? @volume.mount_adapter : nil
        adapter && defined?(Rubernetes::Volume::NativeMountAdapter) && adapter.is_a?(Rubernetes::Volume::NativeMountAdapter)
      end
      # ->(plugin, operation, status, seconds): storage_operation_duration_seconds.
      attr_accessor :metrics_observer
      # Volume::SELinux::Tracker: the label each volume is mounted with and
      # the KEP-1710 mismatch checks; nil mounts without -o context.
      attr_accessor :selinux_tracker
      # Node::PodCertificateManager for projected podCertificate sources
      # (PodCertificateRequest feature gate); nil refuses such volumes.
      attr_reader :pod_certificates

      def pod_certificates=(manager)
        @pod_certificates = manager
        Volume::ProjectedBackend.pod_certificate_provider = manager if defined?(Volume::ProjectedBackend)
      end

      # A volume whose containers or Pods disagree on an SELinux label and
      # whose access mode makes that an error (MountVolume.SetUp fails).
      class SELinuxConflict < Error; end

      def pod_directory(pod)
        File.join(@root, pod_uid(pod))
      end

      # Prepare every referenced volume. Returns {"ids" => [...], "mounts" =>
      # {name => Mount#to_h}} which the lifecycle records durably.
      def prepare(pod, token: nil, pod_ip: nil, host_ip: nil, images: {}, existing_mounts: {})
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        uid = pod_uid(object)
        ensure_propagating_root!
        # Every attempt gets its own operation tokens: the manager's durable
        # operation ledger replays a token's recorded result, and a retried
        # start after a rolled-back attempt must not be handed the volume id
        # that rollback already deleted.
        token ||= "prepare-#{uid}"
        token = "#{token}-#{SecureRandom.hex(4)}"
        volumes = used_volume_definitions(object).reject { |volume| existing_mounts.key?(Helpers.key(volume, "name", "").to_s) }
        names = volumes.map { |volume| Helpers.key(volume, "name", "").to_s }
        duplicate = names.find { |name| names.count(name) > 1 }
        raise Error, "volume name #{duplicate.inspect} is used more than once" if duplicate

        mounts = {}
        publish_targets = existing_mounts.values.to_h { |entry| [Helpers.key(entry, "path"), true] }
        stage_paths = {}
        ids = []
        operation_started = nil
        current_plugin = name = target = nil
        selinux_contexts = nil
        selinux_volumes = {}
        begin
          volumes.each do |volume|
            entry = Helpers.string_keys(volume)
            name = Helpers.key(entry, "name", "").to_s
            raise Error, "volume without a name" if name.empty?

            spec, readonly, projection = translate(entry, object, pod_ip: pod_ip, host_ip: host_ip, images: images)
            validate_persistent_volume_mode!(object, name, spec)
            credentials = iscsi_credentials(spec)
            # Scope a volume's identity to this Pod and mount attempt.
            spec = volume_provision_spec(spec, object, name, projection: projection, uid: uid, token: token)
            operation_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            current_plugin = plugin_name(entry, spec)
            selinux_label = admit_selinux(object, uid, name, spec, selinux_contexts ||= Volume::SELinux.container_contexts(object))
            spec = spec.merge("selinuxMountLabel" => selinux_label) if selinux_label
            selinux_volumes[name] = @selinux_tracker.unique_name(uid, name, spec) if @selinux_tracker
            id = create(spec, token: "#{token}-#{name}")
            ids << id
            target = kubelet_publish_target(id, uid, name, spec, publish_targets) || File.join(pod_directory(object), "volumes", name)
            publish_targets[target] = true
            stage_path = File.join(pod_directory(object), "stages", name)
            # Recorded before the mount is attempted: a rollback has to release
            # a stage that a failed mount left behind.
            stage_paths[id] = stage_path
            mounts[name] = publish_prepared_volume(id, name, object, entry, spec, stage_path: stage_path, target: target,
                                                                                  readonly: readonly, token: "#{token}-#{name}", credentials: credentials)
            mounts[name]["selinuxVolume"] = selinux_volumes[name] if selinux_volumes[name]
            content_signatures[id] = projection_signature(projection) if projection
            observe_operation(current_plugin, "volume_mount", "success", operation_started)
          end
        rescue StandardError => error
          transient = [Volume::PodCertificateNotReadyError, Volume::MultiAttachError, Volume::LocalSourceNotFoundError]
          error = MissingDependency.new(error.message) if transient.any? { |type| error.is_a?(type) }
          error = Unsupported.new(error.message) if error.is_a?(Volume::LocalBlockDeviceError) || error.is_a?(Volume::CSIMigration::Invalid)
          error.volume_name ||= name if error.is_a?(Error)
          observe_operation(current_plugin, "volume_mount", "fail-unknown", operation_started) if operation_started
          selinux_volumes.each_value { |unique| @selinux_tracker&.forget(pod_uid: uid, volume_name: nil, unique_name: unique) }
          begin
            release(object, {"ids" => ids, "mounts" => mounts, "stage_paths" => stage_paths},
                    token: "#{token}-rollback", keep_certificates: true, keep_pod_directory: !existing_mounts.empty?)
            remove_empty_csi_target(uid, target)
            remove_empty_nfs_target(uid, target)
          rescue StandardError => cleanup_error
            raise error.exception("#{error.message} (rollback: #{cleanup_error.message})")
          end
          raise error
        end
        {"ids" => ids, "mounts" => mounts}
      end

      def prepare_newly_used(pod, handle, **context)
        current = handle.fetch("mounts")
        additional = prepare(pod, existing_mounts: current, **context)
        return handle if additional.fetch("ids").empty?

        {"ids" => handle.fetch("ids") + additional.fetch("ids"), "mounts" => current.merge(additional.fetch("mounts"))}
      end

      # Publish a `subPath` of an already prepared volume for one container
      # and return the host path to bind.
      def sub_path(pod, handle, volume_name:, sub_path:, container_name:, index:, readonly:, token: nil)
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        mounts = Helpers.key(handle, "mounts", {})
        mount = Helpers.key(mounts, volume_name, nil)
        raise Error, "volume #{volume_name.inspect} was not prepared for this Pod" if mount.nil?

        validate_sub_path!(sub_path)
        raise Error, "subPath is unsupported for block volume #{volume_name.inspect}" if mount["volumeMode"] == "Block"
        raise Error, "volume #{volume_name.inspect} was prepared without a publish; its subPath cannot be bound" if Helpers.key(mount,
                                                                                                                                "direct", false) == true

        target = File.join(pod_directory(object), "volume-subpaths", container_name.to_s, volume_name.to_s, index.to_s)
        # The publish creates the target itself under an openat2 resolution
        # that refuses to create intermediate components, so the per-container
        # and per-volume directories have to exist first -- exactly as #mount
        # prepares the parents of a stage and a volume target.
        FileUtils.mkdir_p(File.dirname(target))
        id = Helpers.key(mount, "id")
        token ||= "subpath-#{pod_uid(object)}-#{container_name}-#{volume_name}-#{index}"
        @volume.node_publish(id, object, target, readonly: readonly || Helpers.key(mount, "readonly", false) == true,
                                                 token: token, node: node_argument, sub_path: sub_path)
        (mount["subPaths"] ||= {})["#{container_name}:#{index}"] = {"target" => target, "subPath" => sub_path}
        target
      rescue Volume::PathSecurityError => error
        raise Error, "failed to prepare subPath #{sub_path.inspect} for volume #{volume_name.inspect}: #{error.message}"
      end

      # Re-project the sources that depend on the Pod's runtime state (downward
      # API status.podIP/hostIP) once the network is attached; kubelet does
      # the same through its periodic volume resync.
      def refresh(pod, handle, pod_ips: [], host_ip: nil)
        refresh_contents(pod, handle, pod_ips: pod_ips, host_ip: host_ip, status_only: true)
        true
      end

      # Periodic content sync (kubelet reprocesses ConfigMap / Secret /
      # downward API / projected volumes on every sync loop): re-resolve each
      # source and rewrite the projection only when its content changed.  A
      # projected serviceAccountToken is rotated separately (rotate_tokens), so
      # a content check never mints a token.  Returns the refreshed volume names.
      def refresh_contents(pod, handle, pod_ips: [], host_ip: nil, status_only: false)
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        namespace = Helpers.key(Helpers.key(object, "metadata", {}), "namespace", "default").to_s
        mounts = Helpers.key(handle || {}, "mounts", {})
        backends = @volume.respond_to?(:backends) ? @volume.backends : {}
        pod_ip = pod_ips.first
        refreshed = []
        Array(Helpers.key(Helpers.key(object, "spec", {}), "volumes", [])).each do |volume|
          entry = Helpers.string_keys(volume)
          name = Helpers.key(entry, "name", "").to_s
          mount = Helpers.key(mounts, name, nil)
          next if mount.nil?

          id = Helpers.key(mount, "id")
          backend = backends[id]
          next if backend.nil? || !backend.respond_to?(:update)

          kind = source_kind(entry)
          source = Helpers.key(entry, kind, {})
          next if status_only && !status_projection?(kind, source)

          payload = case kind
                    when "configMap" then {files: config_map_files(source, namespace, "configMap volume").first}
                    when "secret" then {files: secret_files(source, namespace, "secret volume").first}
                    when "downwardAPI" then {files: downward_api_files(source, object, pod_ip: pod_ip, host_ip: host_ip).first}
                    when "projected" then {sources: projected_sources(source, object, namespace, pod_ip: pod_ip, host_ip: host_ip, volume_name: name)}
                    end
          next if payload.nil?

          signature = projection_signature(payload)
          missing_generation = backend.respond_to?(:published_generation?) && !backend.published_generation?
          next if content_signatures[id] == signature && !missing_generation

          backend.update(**payload)
          next unless reapply_ownership(object, entry, mount, id)

          content_signatures[id] = signature
          refreshed << name
        rescue MissingDependency, Error => error
          raise if status_only

          refresh_errors[name] = error.message
        end
        refreshed
      end

      # PVC resize statuses (v1.ClaimResourceStatus) and conditions.
      NODE_RESIZE_PENDING = "NodeResizePending"
      NODE_RESIZE_IN_PROGRESS = "NodeResizeInProgress"
      RESIZE_CONDITIONS = %w[Resizing FileSystemResizePending ControllerResizeError NodeResizeError].freeze

      # The kubelet's in-use expansion (desired state populator
      # checkVolumeFSResize + NodeExpander): a CSI PersistentVolume whose
      # capacity outgrew the claim's status.capacity, with the claim marked
      # NodeResizePending by the resizer, gets NodeExpandVolume on the Pod's
      # target and the claim's new capacity recorded.  Returns
      # [[volume name, :resized | :failed, message], ...].
      def expand_in_use(pod, handle)
        return [] unless @volume.respond_to?(:node_expand_in_use) && @reader.respond_to?(:patch_status)

        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        namespace = Helpers.key(Helpers.key(object, "metadata", {}), "namespace", "default").to_s
        mounts = Helpers.key(handle || {}, "mounts", {})
        results = []
        Array(Helpers.key(Helpers.key(object, "spec", {}), "volumes", [])).each do |volume|
          entry = Helpers.string_keys(volume)
          name = Helpers.key(entry, "name", "").to_s
          mount = Helpers.key(mounts, name, nil)
          next if mount.nil? || Helpers.key(mount, "direct", false) == true

          claim_name = claim_name_for(entry, object)
          next if claim_name.nil?

          outcome = expand_claim(object, namespace, claim_name, mount)
          results << [name, *outcome] if outcome
        rescue StandardError => error
          refresh_errors[name] = "expand: #{error.message}"
        end
        results
      end

      # CSIDriver.spec.requiresRepublish: NodePublishVolume again for every
      # CSI volume of the Pod whose driver asks for it.  Returns the names.
      def republish_csi(pod, handle)
        return [] unless @volume.respond_to?(:node_republish)

        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        republished = []
        Helpers.key(handle || {}, "mounts", {}).each do |name, mount|
          # Node-written volumes are bound directly; only a published CSI
          # volume can need a remount (the manager answers false otherwise).
          next if Helpers.key(mount, "direct", false) == true

          begin
            if @volume.node_republish(Helpers.key(mount, "id"), object, Helpers.key(mount, "path"),
                                      token: "republish-#{pod_uid(object)}-#{name}")
              republished << name.to_s
            end
          rescue StandardError => error
            refresh_errors[name.to_s] = "republish: #{error.message}"
          end
        end
        republished
      end

      # Rotate every projected serviceAccountToken that is due.  A backend that
      # no longer holds its token (the agent restarted) is re-projected once so
      # the token on disk is one whose expiry this process tracks.
      def rotate_tokens(pod, handle, now: nil, pod_ips: [], host_ip: nil)
        now ||= @clock.call
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        namespace = Helpers.key(Helpers.key(object, "metadata", {}), "namespace", "default").to_s
        mounts = Helpers.key(handle || {}, "mounts", {})
        backends = @volume.respond_to?(:backends) ? @volume.backends : {}
        rotated = []
        Array(Helpers.key(Helpers.key(object, "spec", {}), "volumes", [])).each do |volume|
          entry = Helpers.string_keys(volume)
          name = Helpers.key(entry, "name", "").to_s
          mount = Helpers.key(mounts, name, nil)
          next if mount.nil?

          id = Helpers.key(mount, "id")
          backend = backends[id]
          certificate_due = backend.respond_to?(:pod_certificate_refresh_due?) && backend.pod_certificate_refresh_due?
          token_missing = backend.respond_to?(:token) && backend.token.nil? &&
                          backend.respond_to?(:service_account_token_source?) && backend.service_account_token_source?
          if certificate_due || token_missing
            sources = projected_sources(Helpers.key(entry, "projected", {}), object, namespace, pod_ip: pod_ips.first, host_ip: host_ip, volume_name: name)
            backend.update(sources: sources)
            content_signatures[id] = projection_signature(sources: sources)
          end

          token_due = backend.respond_to?(:token_rotation_due?) && backend.token_rotation_due?(now)
          if token_due
            result = @volume.rotate_token(id, now: now, token: "rotate-#{pod_uid(object)}-#{name}-#{now.to_f.to_i}")
            token_due = false if result.is_a?(Hash) && result["rotated"] == false
          end
          if certificate_due || token_missing || token_due
            reapply_ownership(object, entry, mount, id)
            rotated << name
          end
        end
        rotated
      end

      def reapply_ownership(pod, entry, mount, id)
        return true unless @volume.respond_to?(:reapply_fs_group)

        fs_group = fs_group_for(pod, {"backend" => source_kind(entry)})
        return true if fs_group.nil?

        stage_path = if Helpers.key(mount, "direct", false) == true
                       Helpers.key(mount, "path")
                     else
                       File.join(pod_directory(pod), "stages", Helpers.key(mount, "name"))
                     end
        @volume.reapply_fs_group(id, pod: pod, stage_path: stage_path, fs_group: fs_group, readonly: true)
        true
      rescue StandardError => error
        content_signatures.delete(id)
        refresh_errors[Helpers.key(entry, "name", "").to_s] = "fsGroup: #{error.message}"
        false
      end

      def content_signatures
        @content_signatures ||= {}
      end

      def projection_signature(payload)
        # File maps have no ordering. Hash raw bytes first so ConfigMap binaryData
        # and Secret values never pass through a text encoder. Projection source
        # arrays retain their order, which determines which overlapping file wins.
        files = payload[:files]
        payload = {files: files.transform_values { |bytes| Digest::SHA256.hexdigest(bytes) }} if files
        Volume::Types.digest(payload)
      end

      def refresh_errors
        @refresh_errors ||= {}
      end

      def status_projection?(kind, source)
        return status_dependent?(source) if kind == "downwardAPI"
        return false unless kind == "projected"

        Array(Helpers.key(source, "sources", [])).any? { |projection| status_dependent?(Helpers.key(projection, "downwardAPI", {})) }
      end

      def status_dependent?(source)
        Array(Helpers.key(source || {}, "items", [])).any? do |item|
          Helpers.key(Helpers.key(Helpers.string_keys(item), "fieldRef", {}) || {}, "fieldPath", "").to_s.start_with?("status.")
        end
      end

      # Tear the Pod's volumes down in reverse: sub-path publishes, the main
      # publish, the stage, the attachment, then the volume itself.  Every
      # failure is collected so the caller records all of them.
      # +keep_certificates+: a rollback of a failed setup keeps the Pod's
      # PodCertificateRequests in flight (the retry needs their answers).
      def release(pod, handle, token: nil, keep_certificates: false, keep_pod_directory: false)
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        uid = pod_uid(object)
        token ||= "release-#{uid}"
        errors = []
        mounts = Helpers.key(handle || {}, "mounts", {})
        mounts.values.reverse_each do |mount|
          id = Helpers.key(mount, "id")
          unmount_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          content_signatures.delete(id)
          errors_before = errors.length
          # The operation token is an identifier, not a path: a token carrying
          # the bind target's absolute path is rejected outright ("operation
          # token contains an unsafe path separator"), so this unpublish had
          # never once run.  Everything behind it -- unstage, detach, delete --
          # then refused with "still has published consumers", the Pod stayed
          # in CleanupPending, and every subPath Pod was undeletable.  The
          # subPaths key is "<container>:<index>", which names the same bind
          # the publish token did without the path.
          Helpers.key(mount, "subPaths", {}).each do |key, entry|
            container_name, _, index = key.to_s.rpartition(":")
            guard(errors, "unpublish subPath #{entry["target"]}") do
              @volume.node_unpublish(id, object, entry.fetch("target"),
                                     token: "#{token}-subpath-#{container_name}-#{index}")
            end
          end
          unless Helpers.key(mount, "direct", false) == true
            guard(errors, "unpublish #{id}") do
              unpublish_volume(id, object, uid, Helpers.key(mount, "path"), token)
            end
            guard(errors, "unstage #{id}") do
              @volume.unstage(id, File.join(pod_directory(object), "stages", Helpers.key(mount, "name")), token: "#{token}-unstage-#{id}",
                                                                                                          node: node_argument)
            end
            guard(errors, "detach #{id}") { @volume.unpublish(id, @node_name, token: "#{token}-detach-#{id}") } unless @node_name.empty?
          end
          guard(errors, "delete #{id}") { @volume.delete_volume(id, token: "#{token}-delete-#{id}") }
          guard(errors, "remove NFS publication #{id}") { remove_empty_nfs_target(uid, Helpers.key(mount, "path")) } if errors.length == errors_before
          if (unique = Helpers.key(mount, "selinuxVolume", nil))
            @selinux_tracker&.forget(pod_uid: uid, volume_name: Helpers.key(mount, "name"), unique_name: unique)
          end
          observe_operation(KubeletMetrics.mount_plugin(mount), "volume_unmount", errors.length == errors_before ? "success" : "fail-unknown",
                            unmount_started)
        end
        Array(Helpers.key(handle || {}, "ids", [])).each do |id|
          next if mounts.values.any? { |mount| Helpers.key(mount, "id") == id }

          # A volume whose mount did not finish is not in `mounts`, but it may
          # already be attached or staged: deleting it in that state raises a
          # ConflictError and the rollback reports that instead of the failure
          # that caused it.  Release what it holds first, ignoring the steps
          # that were never reached.
          stage_path = Helpers.key(handle || {}, "stage_paths", {})[id]
          if stage_path
            guard(errors, "unstage #{id}", ignore: true) do
              @volume.unstage(id, stage_path, token: "#{token}-unstage-#{id}", node: node_argument)
            end
          end
          unless @node_name.empty?
            guard(errors, "detach #{id}", ignore: true) do
              @volume.unpublish(id, @node_name, token: "#{token}-detach-#{id}")
            end
          end
          guard(errors, "delete #{id}") { @volume.delete_volume(id, token: "#{token}-delete-#{id}") }
        end
        @pod_certificates&.forget_pod(uid) unless keep_certificates
        guard(errors, "remove pod directory") do
          directory = pod_directory(object)
          FileUtils.rm_rf(directory) if !keep_pod_directory && File.directory?(directory) && !mounted_beneath?(directory)
        end
        raise Error, errors.join("; ") unless errors.empty?

        true
      end

      private

      def create(spec, token:)
        raise Unsupported, "volume manager does not implement create_volume" unless @volume.respond_to?(:create_volume)

        @volume.create_volume(spec, token: token)
      end

      # The node itself writes the contents of a Secret, ConfigMap,
      # downwardAPI or projected volume, so its staged copy has to be
      # writable: read-only is a property of the container's bind mount, and
      # staging it read-only makes the fsGroup ownership pass fail with EROFS.
      CONTENT_PROJECTED_BACKENDS = %w[secret configMap downwardAPI projected].freeze

      def publish_prepared_volume(id, name, object, entry, spec, stage_path:, target:, readonly:, token:, credentials:)
        fs_group = fs_group_for(object, spec)
        backend = Helpers.key(spec, "backend", nil).to_s
        block = spec["volumeMode"] == "Block"
        fs_group = nil if block || (readonly && %w[iscsi fc].include?(backend))
        direct = direct_volume?(backend, object, name)
        if direct
          target = @volume.direct_path(id, pod: object, fs_group: fs_group)
        else
          published = mount(id, object, stage_path: stage_path, target: target, readonly: readonly, fs_group: fs_group,
                                        backend: backend, token: token, credentials: credentials)
        end
        Mount.new(name: name, id: id, path: target, readonly: readonly,
                  source: source_kind(entry), backend: backend,
                  sub_paths: {}, direct: direct, unique_name: attachable_name(spec),
                  volume_mode: ("Block" if block)).to_h.tap do |handle|
          conflict = Helpers.key(published, "localFsGroupConflict", nil)
          handle["localFsGroupConflict"] = conflict if conflict
          handle["volumeGid"] = spec["volumeGid"] if !block && spec.key?("volumeGid")
        end
      end

      def mount(id, pod, stage_path:, target:, readonly:, fs_group:, token:, backend: nil, credentials: nil)
        FileUtils.mkdir_p(File.dirname(stage_path))
        # Every attempt mints a fresh volume id but the stage and publish
        # paths are fixed per Pod and volume name, so a mount left by an
        # attempt that died belongs to nothing and would make this one fail
        # with "already mounted".  kubelet keeps one idempotent volume set per
        # Pod; here the abandoned mounts are cleared first.
        reclaim_abandoned_mount(stage_path)
        prepare_publish_target!(target)
        FileUtils.mkdir_p(File.dirname(target))
        @volume.publish(id, @node_name, token: "#{token}-attach") unless @node_name.empty?
        stage_readonly = readonly && !CONTENT_PROJECTED_BACKENDS.include?(backend.to_s)
        # fsGroup travels with the stage for a CSI driver that applies it
        # itself (VOLUME_MOUNT_GROUP).
        context = {"fsGroup" => fs_group, "iscsiCredentials" => credentials}.compact
        stage_options = context.empty? ? {} : {context: context}
        @volume.stage(id, stage_path, token: "#{token}-stage", node: node_argument, readonly: stage_readonly, **stage_options)
        @volume.node_publish(id, pod, target, readonly: readonly, token: "#{token}-publish", node: node_argument,
                                              fs_group: fs_group)
      end

      def node_argument
        @node_name.empty? ? nil : @node_name
      end

      # A volume whose content this node writes (ConfigMap, Secret, downward
      # API, projected) is bound into its containers from the backend's own
      # directory, as kubelet binds its per-Pod volume directory: no stage
      # and publish bind mounts, readbacks or ledger records.  A volume some
      # container mounts with a subPath keeps the publish path, which is
      # where the subPath is validated and bound.
      def direct_volume?(backend, pod, name)
        return false unless @volume.respond_to?(:direct_path)
        return false unless CONTENT_PROJECTED_BACKENDS.include?(backend)

        spec = Helpers.key(pod, "spec", {}) || {}
        %w[initContainers containers ephemeralContainers].none? do |group|
          Array(Helpers.key(spec, group, [])).any? do |container|
            Array(Helpers.key(Helpers.string_keys(container), "volumeMounts", [])).any? do |mount|
              mount = Helpers.string_keys(mount)
              Helpers.key(mount, "name", "").to_s == name &&
                (!Helpers.key(mount, "subPath", "").to_s.empty? || !Helpers.key(mount, "subPathExpr", "").to_s.empty?)
            end
          end
        end
      end

      # `ignore: true` is for a best-effort step whose failure only means the
      # step was never reached; the caller still reports whatever failed after
      # it.
      # A teardown step whose subject is already gone has nothing left to do.
      # Every CSI teardown call is required to succeed in that case
      # (csi.proto: DeleteVolume "SHALL return... if the volume does not
      # exist"; NodeUnpublishVolume the same for its target), and treating it
      # as a failure is what kept a Pod in CleanupPending -- the node then
      # never issued its final delete and the Pod stayed Terminating in the API
      # until every spec waiting for it to disappear timed out.
      ALREADY_GONE_ERRORS = ["Rubernetes::Volume::NotFoundError"].freeze

      def guard(errors, label, ignore: false)
        yield
      rescue StandardError => error
        return if ALREADY_GONE_ERRORS.include?(error.class.name)

        errors << "#{label}: #{error.class}: #{error.message}" unless ignore
      end

      # Unmounts anything still mounted at `path` from an earlier attempt.
      # Failure is not fatal: the mount may have been cleaned already, and the
      # stage that follows reports the real problem if it was not.
      def reclaim_abandoned_mount(path)
        return unless mount_point?(path)

        system("umount", "-l", path.to_s, out: File::NULL, err: File::NULL)
        # The durable mount ledger still names the dead attempt's mount at
        # this path; leaving the record makes the next mount here fail as a
        # conflicting attachment even though nothing is mounted any more.
        @volume.forget_mount_target(path) if @volume.respond_to?(:forget_mount_target)
        nil
      end

      # A path that does not exist is not a mount point (a mounted directory
      # cannot be removed in this namespace), which settles every fresh Pod
      # without reading the node's whole mount table; otherwise only lines
      # that mention the path in its mountinfo encoding are decoded.
      def mount_point?(path)
        normalized = File.expand_path(path.to_s)
        return false unless File.exist?(normalized)
        return false unless File.file?("/proc/self/mountinfo")

        needle = " #{mountinfo_encode(normalized)} "
        File.binread("/proc/self/mountinfo").each_line.any? do |line|
          next false unless line.include?(needle)

          line.split[4].to_s.gsub(/\\([0-7]{3})/) { ::Regexp.last_match(1).to_i(8).chr } == normalized
        end
      rescue SystemCallError
        false
      end

      def mountinfo_encode(path)
        path.gsub(/[ \t\n\\]/) { |char| format("\\%03o", char.ord) }
      end

      def mounted_beneath?(directory)
        return false unless File.file?("/proc/self/mountinfo")

        prefix = "#{directory}/"
        File.foreach("/proc/self/mountinfo").any? do |line|
          mountpoint = line.split[4].to_s.gsub(/\\([0-7]{3})/) { ::Regexp.last_match(1).to_i(8).chr }
          mountpoint == directory || mountpoint.start_with?(prefix)
        end
      rescue SystemCallError
        false
      end

      # ---------------------------------------------------------------- translation

      # emptydir calculateEmptyDirMemorySize: a Memory emptyDir is a tmpfs no
      # larger than the node's allocatable memory, the Pod's memory limit
      # (cm.ResourceConfigForPod, pod-level resources included) and the
      # volume's sizeLimit, whichever is smallest and positive.  Only the
      # sizeLimit was used, so an unbounded tmpfs could hold half the node.
      def empty_dir_memory_size(pod, size_limit)
        resources = Rubernetes::Runtime::Native::Resources
        allocatable = Helpers.key(@node_allocatable || {}, "memory", nil)
        size = allocatable && resources.bytes(allocatable)
        pod_limit = resources.pod_cgroup_limits(Helpers.string_keys(pod))["memory.max"]
        pod_limit = Integer(pod_limit) if pod_limit
        size = pod_limit if pod_limit&.positive? && (size.nil? || pod_limit <= size)
        volume_limit = size_limit.nil? ? nil : resources.bytes(size_limit)
        size = volume_limit if volume_limit&.positive? && (size.nil? || volume_limit <= size)
        size.nil? ? size_limit : size.to_s
      rescue StandardError
        size_limit
      end

      def source_kind(entry)
        SUPPORTED_SOURCES.find { |kind| entry.key?(kind) } ||
          entry.keys.find { |key| key != "name" } || "emptyDir"
      end

      # Returns [manager spec, readonly].
      # +images+ maps an image volume's reference to the image the node pinned
      # for it (digest and unpacked rootfs).
      def translate(entry, pod, pod_ip:, host_ip:, images: {})
        name = Helpers.key(entry, "name").to_s
        kind = source_kind(entry)
        raise Unsupported, "volume #{name.inspect} uses unsupported source #{kind.inspect}" unless SUPPORTED_SOURCES.include?(kind)

        source = Helpers.key(entry, kind, {}) || {}
        namespace = Helpers.key(Helpers.key(pod, "metadata", {}), "namespace", "default").to_s
        case kind
        when "emptyDir"
          medium = Helpers.key(source, "medium", "")
          size_limit = Helpers.key(source, "sizeLimit", nil)
          size_limit = empty_dir_memory_size(pod, size_limit) if medium.to_s.casecmp?("Memory")
          quota_monitor = true if medium.to_s.empty? && Helpers.key(pod["spec"], "hostUsers") == false
          [{"name" => name, "backend" => "emptyDir", "medium" => medium, "sizeLimit" => size_limit, "quotaMonitor" => quota_monitor}.compact, false]
        when "hostPath"
          [{"name" => name, "backend" => "hostPath", "path" => Helpers.key(source, "path"),
            "type" => Helpers.key(source, "type", "")}, false]
        when "configMap"
          files, modes = config_map_files(source, namespace, "configMap volume #{name.inspect}")
          [{"name" => name, "backend" => "configMap", "modes" => modes,
            "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}.merge(split_binary_files(files)), true, {files: files}]
        when "secret"
          files, modes = secret_files(source, namespace, "secret volume #{name.inspect}")
          [{"name" => name, "backend" => "secret", "modes" => modes,
            "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}.merge(split_binary_files(files)), true, {files: files}]
        when "downwardAPI"
          files, modes = downward_api_files(source, pod, pod_ip: pod_ip, host_ip: host_ip)
          [{"name" => name, "backend" => "downwardAPI", "files" => files, "modes" => modes,
            "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}, true, {files: files}]
        when "projected"
          sources = projected_sources(source, pod, namespace, pod_ip: pod_ip, host_ip: host_ip, volume_name: name)
          spec = {"name" => name, "backend" => "projected", "sources" => sources,
                  "podUid" => pod_uid(pod), "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}
          # Resolved file sources already contain their payload. Only credentials
          # need the Pod for provider identity or credential file ownership.
          spec["pod"] = pod if sources.any? { |item| item.key?("serviceAccountToken") || item.key?("podCertificate") || item.key?("clusterTrustBundle") }
          spec["podCertificateProvider"] = @pod_certificates if sources.any? { |projection| projection.is_a?(Hash) && projection.key?("podCertificate") }
          if sources.any? { |projection| projection.is_a?(Hash) && projection.key?("serviceAccountToken") }
            rotator = @volume.respond_to?(:token_rotator_for) ? @volume.token_rotator_for(pod) : nil
            if rotator.nil?
              raise MissingDependency,
                    "projected serviceAccountToken volume #{name.inspect} needs the node's TokenRequest client"
            end

            spec["tokenRotator"] = rotator
          end
          [spec, true, {sources: sources}]
        when "image"
          # kubelet mounts the pulled image's filesystem read-only: the volume
          # is the unpacked rootfs the node pinned for this reference.
          reference = Helpers.key(source, "reference")
          resolved = Helpers.string_keys(Helpers.key(images || {}, reference.to_s, nil) || {})
          spec = {"name" => name, "backend" => "image", "image" => reference,
                  "pullPolicy" => Helpers.key(source, "pullPolicy", "IfNotPresent")}
          spec["digest"] = resolved["digest"] unless resolved["digest"].to_s.empty?
          spec["rootfs"] = resolved["rootfs"] unless resolved["rootfs"].to_s.empty?
          [spec, true]
        when "csi"
          ephemeral_csi_volume(name, source, pod, namespace)
        when *Volume::CSIMigration::DRIVERS.keys
          migrated_inline_volume(entry, namespace)
        when "local"
          [{"name" => name, "backend" => "local", "path" => Helpers.key(source, "path")}, false]
        when "nfs", "iscsi", "fc"
          static_storage_volume({"name" => name}, kind, source, namespace, readonly: false)
        when "persistentVolumeClaim"
          claim_volume(name, Helpers.key(source, "claimName").to_s, namespace, readonly: Helpers.key(source, "readOnly", false) == true)
        when "ephemeral"
          pod_name = Helpers.key(Helpers.key(pod, "metadata", {}), "name", "").to_s
          claim_volume(name, "#{pod_name}-#{name}", namespace, readonly: false)
        end
      end

      # NodeExpander.expandOnPlugin for one claim; nil when nothing is due.
      def expand_claim(pod, namespace, claim_name, mount)
        claim = read("persistentvolumeclaims", claim_name, namespace: namespace)
        return nil if claim.nil?

        pv_name = Helpers.key(Helpers.key(claim, "spec", {}), "volumeName", "").to_s
        return nil if pv_name.empty?

        pv = read("persistentvolumes", pv_name, namespace: nil)
        return nil unless pv && Volume::CSIMigration.persistent_spec(pv)["csi"]

        pv_quantity = pv.dig("spec", "capacity", "storage")
        return nil if pv_quantity.nil?

        pv_size = Volume::Types.parse_capacity(pv_quantity)
        status = Helpers.key(claim, "status", {}) || {}
        status_quantity = status.dig("capacity", "storage")
        status_size = status_quantity.nil? ? 0 : Volume::Types.parse_capacity(status_quantity)
        return nil if pv_size <= status_size

        # runPreCheck: the node may expand only once the resizer handed the
        # claim to it.
        resize_status = (status["allocatedResourceStatuses"] || {})["storage"].to_s
        return nil unless [NODE_RESIZE_PENDING, NODE_RESIZE_IN_PROGRESS].include?(resize_status)

        metadata = Helpers.key(claim, "metadata", {})
        if resize_status == NODE_RESIZE_PENDING
          # MarkNodeExpansionInProgress (resourceVersion-checked).
          @reader.patch_status("persistentvolumeclaims", claim_name,
                               {"metadata" => {"resourceVersion" => metadata["resourceVersion"]}.compact,
                                "status" => {"allocatedResourceStatuses" => {"storage" => NODE_RESIZE_IN_PROGRESS}}},
                               namespace: namespace)
        end
        message_volume = "MountVolume.NodeExpandVolume %s for volume #{pv_name.inspect} #{@node_name}".strip
        begin
          result = @volume.node_expand_in_use(Helpers.key(mount, "id"), pod, Helpers.key(mount, "path"),
                                              capacity_bytes: pv_size, token: "expand-#{pod_uid(pod)}-#{claim_name}")
        rescue Volume::CSIError => error
          unless error.ambiguous?
            # MarkNodeExpansionFailedCondition: a final error from the driver.
            conditions = Array(status["conditions"]).reject { |condition| condition["type"] == "NodeResizeError" }
            conditions << {"type" => "NodeResizeError", "status" => "True",
                           "lastTransitionTime" => @clock.call.utc.iso8601, "message" => "failed to expand pvc with #{error.message}"}
            @reader.patch_status("persistentvolumeclaims", claim_name, {"status" => {"conditions" => conditions}}, namespace: namespace)
          end
          return [:failed, format(message_volume, "failed") + ": #{error.message}"]
        end
        return nil if result.nil?
        return [:failed, format(message_volume, "failed") + ": NodeExpand is not supported by the CSI driver"] if result == :unsupported

        # MarkNodeExpansionFinishedWithRecovery.
        statuses = (status["allocatedResourceStatuses"] || {}).except("storage")
        conditions = Array(status["conditions"]).reject { |condition| RESIZE_CONDITIONS.include?(condition["type"]) }
        @reader.patch_status("persistentvolumeclaims", claim_name,
                             {"status" => {"capacity" => (status["capacity"] || {}).merge("storage" => pv_quantity),
                                           "allocatedResourceStatuses" => statuses.empty? ? nil : statuses,
                                           "conditions" => conditions.empty? ? nil : conditions}},
                             namespace: namespace)
        [:resized, format(message_volume, "succeeded")]
      end

      def claim_volume(name, claim_name, namespace, readonly:)
        raise Error, "persistentVolumeClaim volume #{name.inspect} has no claimName" if claim_name.empty?

        claim = read("persistentvolumeclaims", claim_name, namespace: namespace)
        raise MissingDependency, "persistentvolumeclaim \"#{claim_name}\" not found" if claim.nil?

        phase = claim.dig("status", "phase").to_s
        pv_name = claim.dig("spec", "volumeName").to_s
        raise MissingDependency, "persistentvolumeclaim \"#{claim_name}\" is not bound (phase #{phase.inspect})" if phase != "Bound" || pv_name.empty?

        pv = read("persistentvolumes", pv_name, namespace: nil)
        raise MissingDependency, "persistentvolume \"#{pv_name}\" bound to claim \"#{claim_name}\" not found" if pv.nil?

        pv_spec = Volume::CSIMigration.persistent_spec(pv)
        access_modes = Array(Helpers.key(pv_spec, "accessModes", []))
        base = {"name" => name, "accessModes" => access_modes, "capacity" => pv_spec.dig("capacity", "storage"),
                "volumeMode" => Helpers.key(pv_spec, "volumeMode", "Filesystem"),
                "persistentVolume" => pv_name, "claim" => "#{namespace}/#{claim_name}",
                "volumeGid" => VolumeGroups.for_claim(pv, claim)}.compact
        mount_options = Array(Helpers.key(pv_spec, "mountOptions", []))
        if (kind = STATIC_STORAGE_SOURCES.keys.find { |key| pv_spec[key].is_a?(Hash) })
          base["mountOptions"] = mount_options unless mount_options.empty?
          return static_storage_volume(base, kind, pv_spec.fetch(kind), namespace,
                                       readonly: readonly || access_modes.include?("ReadOnlyMany"))
        end

        spec = if (host = Helpers.key(pv_spec, "hostPath", nil))
                 base.merge("backend" => "hostPath", "path" => Helpers.key(host, "path"), "type" => Helpers.key(host, "type", ""))
               elsif (local = Helpers.key(pv_spec, "local", nil))
                 base.merge("backend" => "local", "path" => Helpers.key(local, "path"))
               elsif (csi = Helpers.key(pv_spec, "csi", nil))
                 # The PV's mountOptions reach NodeStage/NodePublish as mount flags.
                 base.merge("csi" => csi_spec(csi, namespace, pv: true)).merge(mount_options.empty? ? {} : {"mountOptions" => mount_options})
               else
                 sources = pv_spec.keys - %w[accessModes capacity volumeMode storageClassName persistentVolumeReclaimPolicy
                                             claimRef nodeAffinity mountOptions]
                 raise Unsupported, "persistentvolume \"#{pv_name}\" uses unsupported source #{sources.first.inspect}"
               end
        readonly ||= spec.dig("csi", "readOnly") || access_modes == ["ReadOnlyMany"]
        [spec, readonly]
      end

      # The attachable volumes a Pod's spec resolves to right now
      # (desiredStateOfWorldPopulator: what node.status.volumesInUse reports
      # from the moment the Pod is admitted, before anything is mounted).  A
      # claim that is not bound yet, or a source this node cannot read, is
      # simply not there yet -- the populator retries on its next pass, here
      # the mount does.  Sorted and unique.
      def attachable_volume_names(pod)
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        namespace = Helpers.key(Helpers.key(object, "metadata", {}), "namespace", "default").to_s
        used_volume_definitions(object).filter_map do |volume|
          entry = Helpers.string_keys(volume)
          claim_name = claim_name_for(entry, object)
          spec = if claim_name && !claim_name.empty?
                   claim_volume(Helpers.key(entry, "name", "").to_s, claim_name, namespace, readonly: false).first
                 elsif Volume::CSIMigration::DRIVERS.each_key.any? { |key| entry.key?(key) }
                   migrated_inline_volume(entry, namespace).first
                 elsif (kind = %w[iscsi fc].find { |key| entry[key].is_a?(Hash) })
                   static_storage_volume({}, kind, entry.fetch(kind), namespace, readonly: false).first
                 end
          next unless spec

          attachable_name(spec)
        rescue Error, StandardError
          nil
        end.uniq.sort
      end
      public :attachable_volume_names

      # The volume plugin of a Pod volume (its PV's for a claim).
      def plugin_name(entry, spec)
        kind = source_kind(entry)
        return "kubernetes.io/csi" if spec["csi"]

        if %w[persistentVolumeClaim ephemeral].include?(kind)

          KubeletMetrics::VOLUME_PLUGIN_NAMES[Helpers.key(spec, "backend", "").to_s]
        else
          KubeletMetrics::VOLUME_PLUGIN_NAMES[kind]
        end
      end

      # desiredStateOfWorld.AddPodToVolume's SELinux part: the label this
      # volume is mounted with for this Pod, or nil.
      def admit_selinux(pod, uid, name, spec, contexts)
        return nil unless @selinux_tracker

        tracker_spec = spec["pod"] ? spec : spec.merge("pod" => pod)
        @selinux_tracker.admit(pod_uid: uid, volume_name: name, spec: tracker_spec, contexts: contexts[name])
      rescue Volume::SELinux::Error => error
        raise SELinuxConflict, "volume #{name.inspect}: #{error.message}"
      end

      def observe_operation(plugin, operation, status, started)
        return if @metrics_observer.nil? || plugin.nil?

        @metrics_observer.call(plugin, operation, status, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
      rescue StandardError
        nil
      end

      # ConfigMap / Secret / downward API file maps -------------------------

      # The volume spec travels through the manager's JSON ledger, which can
      # carry only UTF-8 text: a ConfigMap binaryData entry (or a binary
      # Secret) goes as base64 under "binaryFiles" and the backend decodes it
      # ("[sig-storage] ConfigMap binary data should be reflected in volume"
      # failed with JSON::GeneratorError on the raw bytes).
      def split_binary_files(files)
        text = {}
        binary = {}
        files.each do |path, content|
          value = String(content)
          utf8 = value.dup.force_encoding(Encoding::UTF_8)
          if utf8.valid_encoding?
            text[path] = utf8
          else
            binary[path] = Base64.strict_encode64(value)
          end
        end
        result = {"files" => text}
        result["binaryFiles"] = binary unless binary.empty?
        result
      end

      def config_map_files(source, namespace, label)
        name = Helpers.key(source, "name").to_s
        optional = Helpers.key(source, "optional", false) == true
        object = read("configmaps", name, namespace: namespace)
        if object.nil?
          return [{}, {}] if optional

          raise MissingDependency, "configmap \"#{name}\" not found"
        end
        data = Helpers.key(object, "data", {}).to_h.transform_values { |value| String(value) }
        binary = Helpers.key(object, "binaryData", {}).to_h.transform_values { |value| Base64.strict_decode64(String(value)) }
        select_items(data.merge(binary), Helpers.key(source, "items", nil), optional: optional, label: label)
      rescue ArgumentError => error
        raise Error, "#{label}: #{error.message}"
      end

      def secret_files(source, namespace, label)
        name = Helpers.key(source, "secretName", Helpers.key(source, "name")).to_s
        optional = Helpers.key(source, "optional", false) == true
        object = read("secrets", name, namespace: namespace)
        if object.nil?
          return [{}, {}] if optional

          raise MissingDependency, "secret \"#{name}\" not found"
        end
        select_items(decode_secret_data(object), Helpers.key(source, "items", nil), optional: optional, label: label)
      end

      def decode_secret_data(secret)
        data = Helpers.key(secret, "data", {}).to_h.transform_values { |value| Base64.strict_decode64(String(value)) }
        string_data = Helpers.key(secret, "stringData", {}).to_h.transform_values { |value| String(value) }
        data.merge(string_data)
      rescue ArgumentError => error
        raise Error, "secret data is not valid base64: #{error.message}"
      end

      # `items` restricts and renames keys; an item for a key the object does
      # not carry is an error unless the source is optional (kubelet:
      # "references non-existent config key").
      def select_items(data, items, optional:, label:)
        if Array(items).empty?
          data.each_key { |key| validate_relative_path!(key, label) }
          return [data, {}]
        end

        files = {}
        modes = {}
        Array(items).each do |item|
          entry = Helpers.string_keys(item)
          key = Helpers.key(entry, "key").to_s
          path = Helpers.key(entry, "path", key).to_s
          validate_relative_path!(path, label)
          unless data.key?(key)
            next if optional

            raise MissingDependency, "#{label} references non-existent key #{key.inspect}"
          end
          files[path] = data.fetch(key)
          mode = Helpers.key(entry, "mode", nil)
          modes[path] = Integer(mode) unless mode.nil?
        end
        [files, modes]
      end

      def downward_api_files(source, pod, pod_ip:, host_ip:)
        files = {}
        modes = {}
        Array(Helpers.key(source, "items", [])).each do |item|
          entry = Helpers.string_keys(item)
          path = Helpers.key(entry, "path").to_s
          validate_relative_path!(path, "downwardAPI volume")
          files[path] = FieldRef.resolve_item(entry, pod, pod_ip: pod_ip, host_ip: host_ip, node_allocatable: @node_allocatable)
          mode = Helpers.key(entry, "mode", nil)
          modes[path] = Integer(mode) unless mode.nil?
        end
        [files, modes]
      end

      def projected_files(kind, files, modes = {})
        encoded = split_binary_files(files)
        payload = if kind == "secret"
                    {"stringData" => encoded.fetch("files"), "data" => encoded.fetch("binaryFiles", {})}
                  else
                    {"data" => encoded.fetch("files"), "binaryData" => encoded.fetch("binaryFiles", {})}
                  end
        payload["modes"] = modes
        {kind => payload}
      end

      def projected_sources(source, pod, namespace, pod_ip:, host_ip:, volume_name:)
        Array(Helpers.key(source, "sources", [])).map.with_index do |projection, index|
          entry = Helpers.string_keys(projection)
          next {} if entry.empty? # A disabled projection feature may leave an empty source.

          if (config_map = Helpers.key(entry, "configMap", nil))
            projected_files("configMap", *config_map_files(config_map, namespace, "projected configMap"))
          elsif (secret = Helpers.key(entry, "secret", nil))
            projected_files("secret", *secret_files(secret, namespace, "projected secret"))
          elsif (downward = Helpers.key(entry, "downwardAPI", nil))
            projected_files("configMap", *downward_api_files(downward, pod, pod_ip: pod_ip, host_ip: host_ip))
          elsif (token = Helpers.key(entry, "serviceAccountToken", nil))
            # The token itself is minted by the manager's rotator; only the
            # projection parameters travel.
            {"serviceAccountToken" => {"audience" => Helpers.key(token, "audience", nil),
                                       "expirationSeconds" => Helpers.key(token, "expirationSeconds", nil),
                                       "path" => Helpers.key(token, "path", "token")}.compact}
          elsif (bundle = Helpers.key(entry, "clusterTrustBundle", nil))
            {"clusterTrustBundle" => cluster_trust_bundle_files(bundle)}
          elsif (certificate = Helpers.key(entry, "podCertificate", nil))
            if @pod_certificates.nil?
              raise Unsupported,
                    "projected podCertificate needs the PodCertificateRequest feature gate and the node's API client"
            end

            %w[credentialBundlePath keyPath certificateChainPath].each do |field|
              path = Helpers.key(certificate, field, nil)
              validate_relative_path!(path.to_s, "projected podCertificate #{field}") unless path.nil?
            end
            {"podCertificate" => {"signerName" => Helpers.key(certificate, "signerName", nil), "keyType" => Helpers.key(certificate, "keyType", nil),
                                  "maxExpirationSeconds" => Helpers.key(certificate, "maxExpirationSeconds", nil),
                                  "credentialBundlePath" => Helpers.key(certificate, "credentialBundlePath", nil),
                                  "keyPath" => Helpers.key(certificate, "keyPath", nil), "certificateChainPath" => Helpers.key(certificate,
                                                                                                                               "certificateChainPath", nil),
                                  "userAnnotations" => Helpers.key(certificate, "userAnnotations", nil),
                                  "volumeName" => volume_name, "sourceIndex" => index}.compact}
          else
            raise Unsupported, "projected source #{entry.keys.inspect} is not supported"
          end
        end
      end

      def fs_group_for(pod, spec)
        context = Helpers.key(Helpers.key(pod, "spec", {}), "securityContext", {}) || {}
        value = Helpers.key(context, "fsGroup", nil)
        return nil if value.nil?
        return nil if %w[hostPath nfs].include?(Helpers.key(spec, "backend", "").to_s)

        Integer(value)
      end

      def validate_relative_path!(path, label)
        value = path.to_s
        raise Error, "#{label}: path must not be empty" if value.empty?
        raise Error, "#{label}: path must be relative" if value.start_with?("/")
        raise Error, "#{label}: path must not contain '..'" if value.split("/").include?("..")
        raise Error, "#{label}: path contains NUL" if value.include?("\0")

        value
      end

      def validate_sub_path!(value)
        text = value.to_s
        raise Error, "subPath must not be empty" if text.empty?
        raise Error, "subPath must be relative" if text.start_with?("/")
        raise Error, "subPath must not contain '..'" if text.split("/").include?("..")

        text
      end

      def read(resource, name, namespace:)
        raise MissingDependency, "node has no API reader to resolve #{resource} #{name.inspect}" unless @reader

        @reader.get(resource, name, namespace: namespace)
      end

      def list(resource, namespace:)
        raise MissingDependency, "node has no API reader to list #{resource}" unless @reader

        @reader.list(resource, namespace: namespace)
      end

      def pod_uid(pod)
        metadata = Helpers.key(pod, "metadata", {})
        Helpers.key(metadata, "uid", Helpers.key(metadata, "name", "pod")).to_s
      end
    end
  end
end
