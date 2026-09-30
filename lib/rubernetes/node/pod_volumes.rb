require "digest"
require "base64"
require "fileutils"
require "json"
require "securerandom"

require_relative "status"
require_relative "field_ref"
require_relative "../volume/kubernetes_csi"
require_relative "kubelet_metrics"

module Rubernetes
  module Node
    # Turns `pod.spec.volumes` into mounted host paths the runtime can bind
    # into containers, the way kubelet's volume manager does:
    #
    #   1. the Kubernetes volume source is resolved against the API (ConfigMap
    #      and Secret contents, the PersistentVolume behind a claim, downward
    #      API values from the live Pod) and translated to a Volume::Manager
    #      spec whose file map is already computed (`items`, key selection,
    #      `defaultMode`, per-item `mode` are applied here);
    #   2. the manager provisions, attaches, stages and publishes the volume
    #      under the per-Pod directory `<root>/pods/<uid>/volumes/<name>`;
    #   3. `subPath` mounts get their own publish under
    #      `<root>/pods/<uid>/volume-subpaths/<container>/<volume>/<index>`
    #      so the descriptor-validated sub-path is what the container sees.
    #
    # The result maps each volume name to its host path plus the metadata a
    # container mount needs.  Release walks the same steps backwards.
    class PodVolumes
      class Error < StandardError; end
      # Raised when a referenced object (ConfigMap, Secret, claim) is absent
      # and the source is not optional; kubelet reports this as
      # CreateContainerConfigError / FailedMount and retries.
      class MissingDependency < Error; end
      class Unsupported < Error; end

      SUPPORTED_SOURCES = %w[
        emptyDir hostPath configMap secret downwardAPI projected persistentVolumeClaim
        ephemeral image csi local
      ].freeze
      DEFAULT_MODE = 0o644

      # +unique_name+: the attachable volume's name in node.status.volumesInUse
      # (a PersistentVolume's CSI volume: kubernetes.io/csi/<driver>^<handle>).
      Mount = Struct.new(:name, :id, :path, :readonly, :source, :backend, :sub_paths, :direct, :unique_name, keyword_init: true) do
        def to_h
          {"name" => name, "id" => id, "path" => path, "readonly" => readonly, "source" => source,
           "backend" => backend, "subPaths" => sub_paths, "direct" => direct == true, "uniqueName" => unique_name}.compact
        end
      end

      # The volume manager's startup reconstruction counts, for
      # reconstruct_volume_operations_total.
      def reconstruction_stats
        @volume.respond_to?(:reconstruction_stats) ? @volume.reconstruction_stats : nil
      end

      def initialize(volume:, reader: nil, node_name: nil, root: nil, clock: -> { Time.now.utc },
                     node_allocatable: nil)
        raise ArgumentError, "volume manager is required" unless volume

        @volume = volume
        @reader = reader
        @node_name = node_name.to_s
        @root = File.expand_path(String(root || (volume.respond_to?(:root) ? File.join(volume.root, "pods") : "/var/lib/rubernetes/pods")))
        @clock = clock
        @node_allocatable = node_allocatable
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

      # Prepare every volume of the Pod.  Returns {"ids" => [...], "mounts" =>
      # {name => Mount#to_h}} which the lifecycle records durably.
      def prepare(pod, token: nil, pod_ip: nil, host_ip: nil, images: {})
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        uid = pod_uid(object)
        ensure_propagating_root!
        # Every attempt gets its own operation tokens: the manager's durable
        # operation ledger replays a token's recorded result, and a retried
        # start after a rolled-back attempt must not be handed the volume id
        # that rollback already deleted.
        token ||= "prepare-#{uid}"
        token = "#{token}-#{SecureRandom.hex(4)}"
        volumes = Array(Helpers.key(Helpers.key(object, "spec", {}), "volumes", []))
        names = volumes.map { |volume| Helpers.key(volume, "name", "").to_s }
        duplicate = names.find { |name| names.count(name) > 1 }
        raise Error, "volume name #{duplicate.inspect} is used more than once" if duplicate

        mounts = {}
        stage_paths = {}
        ids = []
        operation_started = nil
        current_plugin = nil
        selinux_contexts = nil
        selinux_volumes = {}
        begin
          volumes.each do |volume|
            entry = Helpers.string_keys(volume)
            name = Helpers.key(entry, "name", "").to_s
            raise Error, "volume without a name" if name.empty?

            spec, readonly = translate(entry, object, pod_ip: pod_ip, host_ip: host_ip, images: images)
            # A Pod volume belongs to this Pod and this attempt: the manager
            # derives the volume id (and the durable operation fingerprint)
            # from the spec, so two Pods declaring the same emptyDir, or a
            # retried attempt, must not collapse onto one volume record.
            spec = spec.merge("podUid" => uid, "attempt" => token)
            operation_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            current_plugin = plugin_name(entry, spec)
            selinux_label = admit_selinux(object, uid, name, spec, selinux_contexts ||= Volume::SELinux.container_contexts(object))
            spec = spec.merge("selinuxMountLabel" => selinux_label) if selinux_label
            selinux_volumes[name] = @selinux_tracker.unique_name(uid, name, spec) if @selinux_tracker
            id = create(spec, token: "#{token}-#{name}")
            ids << id
            target = File.join(pod_directory(object), "volumes", name)
            stage_path = File.join(pod_directory(object), "stages", name)
            # Recorded before the mount is attempted: a rollback has to release
            # a stage that a failed mount left behind.
            stage_paths[name] = stage_path
            fs_group = fs_group_for(object, spec)
            backend = Helpers.key(spec, "backend", nil).to_s
            direct = direct_volume?(backend, object, name)
            if direct
              target = @volume.direct_path(id, pod: object, fs_group: fs_group)
            else
              mount(id, object, stage_path: stage_path, target: target, readonly: readonly, fs_group: fs_group,
                    backend: backend, token: "#{token}-#{name}")
            end
            mounts[name] = Mount.new(name: name, id: id, path: target, readonly: readonly,
                                     source: source_kind(entry), backend: backend,
                                     sub_paths: {}, direct: direct, unique_name: attachable_name(spec)).to_h
            mounts[name]["selinuxVolume"] = selinux_volumes[name] if selinux_volumes[name]
            observe_operation(current_plugin, "volume_mount", "success", operation_started)
          end
        rescue StandardError => error
          error = MissingDependency.new(error.message) if error.is_a?(Volume::PodCertificateNotReadyError)
          observe_operation(current_plugin, "volume_mount", "fail-unknown", operation_started) if operation_started
          selinux_volumes.each_value { |unique| @selinux_tracker&.forget(pod_uid: uid, volume_name: nil, unique_name: unique) }
          begin
            release(object, {"ids" => ids, "mounts" => mounts, "stage_paths" => stage_paths},
                    token: "#{token}-rollback", keep_certificates: true)
          rescue StandardError => cleanup_error
            raise error.class, "#{error.message} (rollback: #{cleanup_error.message})", error.backtrace
          end
          raise
        end
        {"ids" => ids, "mounts" => mounts}
      end

      # Publish a `subPath` of an already prepared volume for one container
      # and return the host path to bind.
      def sub_path(pod, handle, volume_name:, sub_path:, container_name:, index:, readonly:, token: nil)
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        mounts = Helpers.key(handle, "mounts", {})
        mount = Helpers.key(mounts, volume_name, nil)
        raise Error, "volume #{volume_name.inspect} was not prepared for this Pod" if mount.nil?

        validate_sub_path!(sub_path)
        # prepare publishes (never uses directly) any volume a subPath names.
        raise Error, "volume #{volume_name.inspect} was prepared without a publish; its subPath cannot be bound" if Helpers.key(mount, "direct", false) == true

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
      end

      # Re-project the sources that depend on the Pod's runtime state (downward
      # API status.podIP/hostIP) once the network is attached; kubelet does
      # the same through its periodic volume resync.
      def refresh(pod, handle, pod_ips: [], host_ip: nil)
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        volumes = Array(Helpers.key(Helpers.key(object, "spec", {}), "volumes", []))
        mounts = Helpers.key(handle || {}, "mounts", {})
        backends = @volume.respond_to?(:backends) ? @volume.backends : {}
        volumes.each do |volume|
          entry = Helpers.string_keys(volume)
          name = Helpers.key(entry, "name", "").to_s
          mount = Helpers.key(mounts, name, nil)
          next if mount.nil?

          backend = backends[Helpers.key(mount, "id")]
          next if backend.nil?

          kind = source_kind(entry)
          pod_ip = pod_ips.first
          case kind
          when "downwardAPI"
            next unless status_dependent?(Helpers.key(entry, kind, {}))

            files, _modes = downward_api_files(Helpers.key(entry, kind, {}), object, pod_ip: pod_ip, host_ip: host_ip)
            backend.update(files: files) if backend.respond_to?(:update)
          when "projected"
            source = Helpers.key(entry, kind, {})
            next unless Array(Helpers.key(source, "sources", [])).any? { |projection| status_dependent?(Helpers.key(Helpers.string_keys(projection), "downwardAPI", {})) }

            namespace = Helpers.key(Helpers.key(object, "metadata", {}), "namespace", "default").to_s
            sources, _modes = projected_sources(source, object, namespace, pod_ip: pod_ip, host_ip: host_ip)
            backend.update(sources: sources) if backend.respond_to?(:update)
          end
        end
        true
      end

      # Periodic content sync (kubelet reprocesses ConfigMap / Secret /
      # downward API / projected volumes on every sync loop): re-resolve each
      # source and rewrite the projection only when its content changed.  A
      # projected serviceAccountToken is rotated separately (rotate_tokens), so
      # a content check never mints a token.  Returns the refreshed volume names.
      def refresh_contents(pod, handle, pod_ips: [], host_ip: nil)
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
          payload = case kind
                    when "configMap" then {files: config_map_files(source, namespace, "configMap volume").first}
                    when "secret" then {files: secret_files(source, namespace, "secret volume").first}
                    when "downwardAPI" then {files: downward_api_files(source, object, pod_ip: pod_ip, host_ip: host_ip).first}
                    when "projected" then {sources: projected_sources(source, object, namespace, pod_ip: pod_ip, host_ip: host_ip).first}
                    end
          next if payload.nil?
      
          signature = Digest::SHA256.hexdigest(Marshal.dump(payload))
          previous = content_signatures[id]
          content_signatures[id] = signature
          # The first pass after a start records what was projected; only a
          # later change is written.
          next if previous.nil? || previous == signature
      
          backend.update(**payload)
          reapply_ownership(object, entry, mount, id)
          refreshed << name
        rescue MissingDependency, Error => error
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
          next unless backend.respond_to?(:token_rotation_due?)
      
          if backend.token_rotation_due?(now)
            @volume.rotate_token(id, now: now, token: "rotate-#{pod_uid(object)}-#{name}-#{now.to_f.to_i}")
            reapply_ownership(object, entry, mount, id)
            rotated << name
          elsif backend.respond_to?(:token) && backend.token.nil? &&
                backend.respond_to?(:service_account_token_source?) && backend.service_account_token_source?
            sources, = projected_sources(Helpers.key(entry, "projected", {}), object, namespace, pod_ip: pod_ips.first, host_ip: host_ip)
            backend.update(sources: sources)
            reapply_ownership(object, entry, mount, id)
            content_signatures.delete(id)
            rotated << name
          end
        end
        rotated
      end
      
      def reapply_ownership(pod, entry, mount, id)
        return unless @volume.respond_to?(:reapply_fs_group)

        fs_group = fs_group_for(pod, {"backend" => source_kind(entry)})
        return if fs_group.nil?

        stage_path = if Helpers.key(mount, "direct", false) == true
                       Helpers.key(mount, "path")
                     else
                       File.join(pod_directory(pod), "stages", Helpers.key(mount, "name"))
                     end
        @volume.reapply_fs_group(id, pod: pod, stage_path: stage_path, fs_group: fs_group)
      rescue StandardError => error
        refresh_errors[Helpers.key(entry, "name", "").to_s] = "fsGroup: #{error.message}"
      end

      def content_signatures
        @content_signatures ||= {}
      end
      
      def refresh_errors
        @refresh_errors ||= {}
      end
      
      def status_dependent?(source)
        Array(Helpers.key(source || {}, "items", [])).any? do |item|
          Helpers.key(Helpers.key(Helpers.string_keys(item), "fieldRef", {}) || {}, "fieldPath", "").to_s.start_with?("status.")
        end
      end

      # Tear the Pod's volumes down in reverse: sub-path publishes, the main
      # publish, the stage, the attachment, then the volume itself.  Every
      # failure is collected so the caller records all of them.
      def release(pod, handle, token: nil)
        object = Helpers.string_keys(pod.respond_to?(:to_h) ? pod.to_h : pod)
        uid = pod_uid(object)
        token ||= "release-#{uid}"
        errors = []
        mounts = Helpers.key(handle || {}, "mounts", {})
        mounts.values.reverse_each do |mount|
          id = Helpers.key(mount, "id")
          unmount_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
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
            guard(errors, "unpublish #{id}") { @volume.node_unpublish(id, object, Helpers.key(mount, "path"), token: "#{token}-unpublish-#{id}") }
            guard(errors, "unstage #{id}") do
              @volume.unstage(id, File.join(pod_directory(object), "stages", Helpers.key(mount, "name")), token: "#{token}-unstage-#{id}", node: node_argument)
            end
            guard(errors, "detach #{id}") { @volume.unpublish(id, @node_name, token: "#{token}-detach-#{id}") } unless @node_name.empty?
          end
          guard(errors, "delete #{id}") { @volume.delete_volume(id, token: "#{token}-delete-#{id}") }
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
          Helpers.key(handle || {}, "stage_paths", {}).each do |_name, stage_path|
            guard(errors, "unstage #{id}", ignore: true) do
              @volume.unstage(id, stage_path, token: "#{token}-unstage-#{id}", node: node_argument)
            end
          end
          guard(errors, "detach #{id}", ignore: true) { @volume.unpublish(id, @node_name, token: "#{token}-detach-#{id}") } unless @node_name.empty?
          guard(errors, "delete #{id}") { @volume.delete_volume(id, token: "#{token}-delete-#{id}") }
        end
        guard(errors, "remove pod directory") do
          directory = pod_directory(object)
          FileUtils.rm_rf(directory) if File.directory?(directory) && !mounted_beneath?(directory)
        end
        raise Error, errors.join("; ") unless errors.empty?

        true
      end

      private

      def create(spec, token:)
        if @volume.respond_to?(:create_volume)
          @volume.create_volume(spec, token: token)
        else
          raise Unsupported, "volume manager does not implement create_volume"
        end
      end

      # The node itself writes the contents of a Secret, ConfigMap,
      # downwardAPI or projected volume, so its staged copy has to be
      # writable: read-only is a property of the container's bind mount, and
      # staging it read-only makes the fsGroup ownership pass fail with EROFS.
      CONTENT_PROJECTED_BACKENDS = %w[secret configMap downwardAPI projected].freeze

      def mount(id, pod, stage_path:, target:, readonly:, fs_group:, token:, backend: nil)
        FileUtils.mkdir_p(File.dirname(stage_path))
        FileUtils.mkdir_p(File.dirname(target))
        # Every attempt mints a fresh volume id but the stage and publish
        # paths are fixed per Pod and volume name, so a mount left by an
        # attempt that died belongs to nothing and would make this one fail
        # with "already mounted".  kubelet keeps one idempotent volume set per
        # Pod; here the abandoned mounts are cleared first.
        reclaim_abandoned_mount(stage_path)
        reclaim_abandoned_mount(target)
        @volume.publish(id, @node_name, token: "#{token}-attach") unless @node_name.empty?
        stage_readonly = readonly && !CONTENT_PROJECTED_BACKENDS.include?(backend.to_s)
        # fsGroup travels with the stage for a CSI driver that applies it
        # itself (VOLUME_MOUNT_GROUP).
        stage_options = fs_group.nil? ? {} : {context: {"fsGroup" => fs_group}}
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

          line.split(" ")[4].to_s.gsub(/\\([0-7]{3})/) { $1.to_i(8).chr } == normalized
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
          mountpoint = line.split(" ")[4].to_s.gsub(/\\([0-7]{3})/) { $1.to_i(8).chr }
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
          [{"name" => name, "backend" => "emptyDir", "medium" => medium, "sizeLimit" => size_limit}.compact, false]
        when "hostPath"
          [{"name" => name, "backend" => "hostPath", "path" => Helpers.key(source, "path"),
            "type" => Helpers.key(source, "type", "")}, false]
        when "configMap"
          files, modes = config_map_files(source, namespace, "configMap volume #{name.inspect}")
          [{"name" => name, "backend" => "configMap", "modes" => modes,
            "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}.merge(split_binary_files(files)), true]
        when "secret"
          files, modes = secret_files(source, namespace, "secret volume #{name.inspect}")
          [{"name" => name, "backend" => "secret", "modes" => modes,
            "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}.merge(split_binary_files(files)), true]
        when "downwardAPI"
          files, modes = downward_api_files(source, pod, pod_ip: pod_ip, host_ip: host_ip)
          [{"name" => name, "backend" => "downwardAPI", "files" => files, "modes" => modes, "pod" => pod,
            "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}, true]
        when "projected"
          sources, modes = projected_sources(source, pod, namespace, pod_ip: pod_ip, host_ip: host_ip)
          spec = {"name" => name, "backend" => "projected", "sources" => sources, "modes" => modes, "pod" => pod,
                  "podUid" => pod_uid(pod), "defaultMode" => Helpers.key(source, "defaultMode", DEFAULT_MODE)}
          if sources.any? { |projection| projection.is_a?(Hash) && projection.key?("serviceAccountToken") }
            rotator = @volume.respond_to?(:token_rotator_for) ? @volume.token_rotator_for(pod) : nil
            raise MissingDependency, "projected serviceAccountToken volume #{name.inspect} needs the node's TokenRequest client" if rotator.nil?

            spec["tokenRotator"] = rotator
          end
          [spec, true]
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
          # makeVolumeHandle: an inline (ephemeral) CSI volume is named
          # csi-<sha256(podUID + volume name)>, and is never attached.
          pod_uid = Helpers.key(Helpers.key(pod, "metadata", {}), "uid", "").to_s
          spec = csi_spec(source, namespace).merge(
            "volumeHandle" => Volume::KubernetesCSIAdapter.inline_volume_handle(pod_uid, name), "ephemeral" => true
          )
          [{"name" => name, "csi" => spec}, Helpers.key(source, "readOnly", false) == true]
        when "local"
          [{"name" => name, "backend" => "local", "path" => Helpers.key(source, "path")}, false]
        when "persistentVolumeClaim"
          claim_volume(name, Helpers.key(source, "claimName").to_s, namespace, readonly: Helpers.key(source, "readOnly", false) == true)
        when "ephemeral"
          pod_name = Helpers.key(Helpers.key(pod, "metadata", {}), "name", "").to_s
          claim_volume(name, "#{pod_name}-#{name}", namespace, readonly: false)
        end
      end

      def claim_name_for(entry, pod)
        if (claim = Helpers.key(entry, "persistentVolumeClaim", nil))
          Helpers.key(claim, "claimName").to_s
        elsif Helpers.key(entry, "ephemeral", nil)
          "#{Helpers.key(Helpers.key(pod, "metadata", {}), "name", "")}-#{Helpers.key(entry, "name")}"
        end
      end

      # NodeExpander.expandOnPlugin for one claim; nil when nothing is due.
      def expand_claim(pod, namespace, claim_name, mount)
        claim = read("persistentvolumeclaims", claim_name, namespace: namespace)
        return nil if claim.nil?

        pv_name = Helpers.key(Helpers.key(claim, "spec", {}), "volumeName", "").to_s
        return nil if pv_name.empty?

        pv = read("persistentvolumes", pv_name, namespace: nil)
        return nil if pv.nil? || Helpers.key(Helpers.key(pv, "spec", {}), "csi", nil).nil?

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
        if phase != "Bound" || pv_name.empty?
          raise MissingDependency, "persistentvolumeclaim \"#{claim_name}\" is not bound (phase #{phase.inspect})"
        end

        pv = read("persistentvolumes", pv_name, namespace: nil)
        raise MissingDependency, "persistentvolume \"#{pv_name}\" bound to claim \"#{claim_name}\" not found" if pv.nil?

        pv_spec = Helpers.key(pv, "spec", {})
        access_modes = Array(Helpers.key(pv_spec, "accessModes", []))
        base = {"name" => name, "accessModes" => access_modes, "capacity" => pv_spec.dig("capacity", "storage"),
                "volumeMode" => Helpers.key(pv_spec, "volumeMode", "Filesystem"),
                "persistentVolume" => pv_name, "claim" => "#{namespace}/#{claim_name}"}.compact
        spec = if (host = Helpers.key(pv_spec, "hostPath", nil))
                 base.merge("backend" => "hostPath", "path" => Helpers.key(host, "path"), "type" => Helpers.key(host, "type", ""))
               elsif (local = Helpers.key(pv_spec, "local", nil))
                 base.merge("backend" => "local", "path" => Helpers.key(local, "path"))
               elsif (csi = Helpers.key(pv_spec, "csi", nil))
                 # The PV's mountOptions reach NodeStage/NodePublish as mount flags.
                 mount_options = Array(Helpers.key(pv_spec, "mountOptions", []))
                 base.merge("csi" => csi_spec(csi, namespace, pv: true)).merge(mount_options.empty? ? {} : {"mountOptions" => mount_options})
               else
                 sources = pv_spec.keys - %w[accessModes capacity volumeMode storageClassName persistentVolumeReclaimPolicy
                                            claimRef nodeAffinity mountOptions]
                 raise Unsupported, "persistentvolume \"#{pv_name}\" uses unsupported source #{sources.first.inspect}"
               end
        readonly ||= access_modes == ["ReadOnlyMany"]
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
        Array(Helpers.key(Helpers.key(object, "spec", {}), "volumes", [])).filter_map do |volume|
          entry = Helpers.string_keys(volume)
          claim_name = claim_name_for(entry, object)
          next nil if claim_name.nil? || claim_name.empty?

          spec, _readonly = claim_volume(Helpers.key(entry, "name", "").to_s, claim_name, namespace, readonly: false)
          attachable_name(spec)
        rescue Error, StandardError
          nil
        end.uniq.sort
      end
      public :attachable_volume_names

      # The volume plugin of a Pod volume (its PV's for a claim).
      def plugin_name(entry, spec)
        kind = source_kind(entry)
        if %w[persistentVolumeClaim ephemeral].include?(kind)
          return "kubernetes.io/csi" if Helpers.key(spec, "csi", nil)

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

      # GetUniqueVolumeNameFromSpec for the attachable volumes kubelet
      # reports in use: a CSI PersistentVolume (inline ephemeral CSI volumes
      # are not attached).
      def attachable_name(spec)
        csi = Helpers.key(spec, "csi", nil)
        return nil unless csi.is_a?(Hash) && Helpers.key(spec, "persistentVolume", nil)

        "kubernetes.io/csi/#{Helpers.key(csi, "driver")}^#{Helpers.key(csi, "volumeHandle")}"
      end

      def csi_spec(source, namespace, pv: false)
        spec = {
          "driver" => Helpers.key(source, "driver"),
          "volumeHandle" => Helpers.key(source, "volumeHandle"),
          "fsType" => Helpers.key(source, "fsType", nil),
          "readOnly" => Helpers.key(source, "readOnly", false),
          "volumeAttributes" => Helpers.key(source, "volumeAttributes", {})
        }
        %w[nodePublishSecretRef nodeStageSecretRef controllerPublishSecretRef controllerExpandSecretRef].each do |key|
          reference = Helpers.key(source, key, nil)
          next if reference.nil?

          secret_namespace = Helpers.key(reference, "namespace", namespace)
          secret = read("secrets", Helpers.key(reference, "name"), namespace: secret_namespace)
          raise MissingDependency, "secret \"#{Helpers.key(reference, "name")}\" for CSI #{key} not found" if secret.nil?

          (spec["secrets"] ||= {})[key.sub("SecretRef", "")] = decode_secret_data(secret)
        end
        spec.compact
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
          if value.dup.force_encoding(Encoding::UTF_8).valid_encoding?
            text[path] = value
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
        if items.nil?
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

      def projected_sources(source, pod, namespace, pod_ip:, host_ip:)
        modes = {}
        sources = Array(Helpers.key(source, "sources", [])).map do |projection|
          entry = Helpers.string_keys(projection)
          if (config_map = Helpers.key(entry, "configMap", nil))
            files, item_modes = config_map_files(config_map, namespace, "projected configMap")
            modes.merge!(item_modes)
            files
          elsif (secret = Helpers.key(entry, "secret", nil))
            files, item_modes = secret_files(secret, namespace, "projected secret")
            modes.merge!(item_modes)
            files
          elsif (downward = Helpers.key(entry, "downwardAPI", nil))
            files, item_modes = downward_api_files(downward, pod, pod_ip: pod_ip, host_ip: host_ip)
            modes.merge!(item_modes)
            files
          elsif (token = Helpers.key(entry, "serviceAccountToken", nil))
            # The token itself is minted by the manager's rotator; only the
            # projection parameters travel.
            {"serviceAccountToken" => {"audience" => Helpers.key(token, "audience", nil),
                                       "expirationSeconds" => Helpers.key(token, "expirationSeconds", nil),
                                       "path" => Helpers.key(token, "path", "token")}.compact}
          elsif (bundle = Helpers.key(entry, "clusterTrustBundle", nil))
            cluster_trust_bundle_files(bundle)
          else
            raise Unsupported, "projected source #{entry.keys.inspect} is not supported"
          end
        end
        [sources, modes]
      end

      def cluster_trust_bundle_files(bundle)
        path = Helpers.key(bundle, "path").to_s
        validate_relative_path!(path, "projected clusterTrustBundle")
        optional = Helpers.key(bundle, "optional", false) == true
        bundles = if (name = Helpers.key(bundle, "name", nil))
                    object = read("clustertrustbundles", name, namespace: nil)
                    object.nil? ? [] : [object]
                  else
                    selector = Helpers.key(Helpers.key(bundle, "labelSelector", {}), "matchLabels", {}).to_h
                    signer = Helpers.key(bundle, "signerName", nil)
                    list("clustertrustbundles", namespace: nil).select do |object|
                      labels = object.dig("metadata", "labels") || {}
                      (signer.nil? || object.dig("spec", "signerName") == signer) &&
                        selector.all? { |key, value| labels[key] == value }
                    end
                  end
        if bundles.empty? && !optional && Helpers.key(bundle, "name", nil)
          raise MissingDependency, "clustertrustbundle \"#{Helpers.key(bundle, "name")}\" not found"
        end

        {path => bundles.map { |object| object.dig("spec", "trustBundle").to_s }.join("\n")}
      end

      def fs_group_for(pod, spec)
        context = Helpers.key(Helpers.key(pod, "spec", {}), "securityContext", {}) || {}
        value = Helpers.key(context, "fsGroup", nil)
        return nil if value.nil?
        # kubelet applies fsGroup to volumes that support ownership management;
        # hostPath and local volumes are excluded (SupportsOwnershipManagement).
        return nil if %w[hostPath local].include?(Helpers.key(spec, "backend", "").to_s)

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
