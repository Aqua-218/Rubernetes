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

module Rubernetes
  module Volume
    class VolumeStore
      def initialize(initial: {}, path: nil, fsync: false)
        @mutex = Monitor.new
        @path = path && File.expand_path(path.to_s)
        @fsync = fsync
        @files = @path && RecordFiles.new(path: @path, fsync: fsync)
        @values = load_values(initial)
      end

      def [](id)
        @mutex.synchronize { @values[id.to_s] }
      end

      def []=(id, value)
        @mutex.synchronize do
          key = id.to_s
          existed = @values.key?(key)
          previous = @values[key]
          @values[key] = value
          begin
            persist!(key)
          rescue StandardError
            existed ? @values[key] = previous : @values.delete(key)
            raise
          end
        end
      end

      def fetch(id, &fallback)
        @mutex.synchronize { @values.fetch(id.to_s, &fallback) }
      end

      def delete(id)
        @mutex.synchronize do
          key = id.to_s
          existed = @values.key?(key)
          value = @values.delete(key)
          begin
            forget!(key) if existed
          rescue StandardError
            @values[key] = value if existed
            raise
          end
          value
        end
      end

      def values
        @mutex.synchronize { @values.values.dup.freeze }
      end

      def each_value(&block)
        return enum_for(__method__) unless block
        values.each(&block)
      end

      private

      def load_values(initial)
        values = initial.dup
        return values unless @files

        legacy = @files.legacy?
        @files.load.each do |value|
          hash = value.transform_keys(&:to_s)
          id = hash.fetch("id")
          values[id] = VolumeRecord.new(id: hash.fetch("id", id), spec: hash.fetch("spec"), backend: hash.fetch("backend"),
                                        state: hash.fetch("state", "Declared"), generation: hash.fetch("generation", 0),
                                        attachments: hash.fetch("attachments", {}), stages: hash.fetch("stages", {}),
                                        publishes: hash.fetch("publishes", {}), operation: hash["operation"],
                                        capacity_bytes: hash["capacityBytes"], created_at: hash["createdAt"], updated_at: hash["updatedAt"])
        end
        @files.migrate!(values.transform_values { |value| value.respond_to?(:to_h) ? value.to_h : value }) if legacy
        values
      rescue JSON::ParserError, KeyError, TypeError => error
        raise JournalError, "volume store is corrupt: #{error.message}"
      end

      # Only the changed record is written (RecordFiles).
      def persist!(key)
        return true unless @files

        value = @values[key]
        @files.write(key, value.respond_to?(:to_h) ? value.to_h : value)
      rescue SystemCallError, IOError => error
        raise JournalError, "volume store persist failed: #{error.message}"
      end

      def forget!(key)
        return true unless @files

        @files.delete(key)
      rescue SystemCallError, IOError => error
        raise JournalError, "volume store persist failed: #{error.message}"
      end
    end

    module OperationSupport
      private

      # An Unknown volume still permits Cleanup, and every teardown operation
      # is one: the CSI teardown calls are all required to be idempotent and to
      # succeed on a volume that is already gone.  Fencing them is what makes a
      # Pod unremovable, so the fence is decided by what the operation is.
      CLEANUP_OPERATIONS = /\A(?:delete|unstage|unpublish|controller-unpublish|delete-snapshot)(?::|\z)/

      def cleanup_operation?(operation)
        CLEANUP_OPERATIONS.match?(operation.to_s)
      end

      def execute_operation(key:, operation:, token:, payload:)
        entry = nil
        effect_started = false
        durable_payload = nil
        @manager.with_volume_lock(key) do
          if @manager.respond_to?(:volume_store) && (record = @manager.volume_store[key.to_s])
            @manager.ensure_known!(record, action: cleanup_operation?(operation) ? "Cleanup" : "Mutate")
          end
          token = Types.identifier(token, "operation token")
          fingerprint = Types.digest(payload)
          durable_payload = @manager.operation_payload(payload)
          entry = @manager.operations.begin!(key: key, operation: operation, token: token,
                                             fingerprint: fingerprint, payload: durable_payload)
          # A teardown whose outcome is unknown must be RETRIED, not fenced.
          # That is the CSI contract for every teardown call and what the
          # kubelet volume reconciler does: it keeps calling UnmountVolume and
          # UnmountDevice until one succeeds (pkg/kubelet/volumemanager/
          # reconciler).  Fencing instead made the first ambiguous unstage
          # permanent -- the volume could never be released, so the Pod holding
          # it stayed Terminating in the API for ever.
          retryable = cleanup_operation?(operation)
          case entry.status
          when "succeeded"
            next Types.deep_copy(entry.result)
          when "pending", "effecting", "unknown"
            unless retryable
              raise OperationUnknown, "operation #{operation} for #{key} is #{entry.status}; recover before retrying"
            end
          when "new"
            # The ledger has just durably reserved this token for this payload.
            # Execute the effect exactly once and finalize the reservation below.
            nil
          when "failed"
            # "failed" is only ever recorded when the effect had NOT started (an
            # error at or after the effect boundary becomes "unknown"), so a retry
            # replays nothing.  kubelet retries a failed mount on every sync; a
            # fenced publish kept a Pod whose subPath target is created by an
            # earlier init container (GitLab's configure -> secrets.yml) failing
            # for ever with "previously failed".
            nil
          end

          effect_boundary = lambda do |state = :start|
            if %i[compensated rejected].include?(state)
              effect_started = false
            elsif !effect_started
              @manager.operations.effecting!(key: key, operation: operation, token: token)
              effect_started = true
            end
            true
          end
          result = yield(effect_boundary)
          @manager.operations.finish!(key: key, operation: operation, token: token,
                                      result: @manager.sanitize_for_persistence(result))
          result
        end
      rescue OperationUnknown => error
        if entry && entry.status != "unknown"
          persisted_error = @manager.persistence_error(error)
          @manager.operations.unknown!(key: key, operation: operation, token: token,
                                       error: persisted_error)
          @manager.mark_unknown(key, operation: operation, payload: durable_payload,
                                details: persisted_error.respond_to?(:details) ? persisted_error.details : nil)
        end
        raise
      rescue StandardError => error
        raise if error.is_a?(StateUnknownError)
        if entry && (effect_started || ambiguous_error?(error))
          persisted_error = @manager.persistence_error(error)
          @manager.operations.unknown!(key: key, operation: operation, token: token,
                                       error: persisted_error)
          @manager.mark_unknown(key, operation: operation, payload: durable_payload,
                                details: persisted_error.respond_to?(:details) ? persisted_error.details : nil)
          raise OperationUnknown.new("operation #{operation} for #{key} has an ambiguous result"), cause: error
        end
        @manager.operations.fail!(key: key, operation: operation, token: token,
                                  error: @manager.persistence_error(error)) if entry
        raise
      end

      def ambiguous_error?(error)
        return false if error.is_a?(StateUnknownError)
        return true if error.is_a?(OperationUnknown)
        return true if error.respond_to?(:ambiguous?) && error.ambiguous?

        return true if error.class.name.to_s.match?(/Unknown|Ambiguous|Timeout|EOF|ConnectionReset|BrokenPipe/)

        cause = error.respond_to?(:cause) ? error.cause : nil
        cause && cause != error ? ambiguous_error?(cause) : false
      end
    end

    class RemoteBackend < Backend
      TYPE = "csi"

      def initialize(csi:, secret_provider: nil, persistence_sanitizer: nil, error_sanitizer: nil, **kwargs)
        raise CSIUnavailable, "CSI adapter is not configured" unless csi

        super(**kwargs)
        @csi = csi
        @secret_provider = secret_provider
        @persistence_sanitizer = persistence_sanitizer
        @error_sanitizer = error_sanitizer
        backend_result = Types.key(spec, "backendResult", {})
        @driver_volume_id = Types.key(backend_result, "volumeId", Types.key(backend_result, "volume_id"))
      end

      attr_reader :driver_volume_id

      def provision(token:, effect_boundary: nil)
        request = Types.deep_copy(spec).merge("secrets" => secrets_for(:create_volume))
        result = sanitize_response(AdapterSupport.result_hash(
          invoke_remote_mutation(effect_boundary) { invoke_csi(:create_volume, request, token: token) }
        ))
        @driver_volume_id = Types.identifier(
          Types.key(result, "volumeId", Types.key(result, "volume_id")), "CSI driver volume id"
        )
        result
      end

      def remote?
        true
      end

      # csi_expander NodeExpand for a published volume (the kubelet's
      # ExpandInUseVolume): :unsupported without EXPAND_VOLUME.
      def kubelet_expand(target:, stage_path:, capacity_bytes:, token:)
        return nil unless kubelet_csi?
        return :unsupported unless @csi.respond_to?(:supports?) && @csi.supports?("EXPAND_VOLUME")

        ensure_path!(target)
        with_secure_csi_target(target, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          sanitize_response(AdapterSupport.result_hash(
            invoke_csi(:expand_node, remote_id, dispatch_path, token: token, capacity_bytes: capacity_bytes,
                                                                    volume_capability: csi_volume_capability,
                                                                    secrets: secrets_for(:node_expand), staging_path: stage_path)
          ))
        end
      end

      # csi metricsCsi: NodeGetVolumeStats on a published target, or
      # :unsupported without GET_VOLUME_STATS; nil for a plugin that is not
      # a kubelet node plugin.
      def kubelet_volume_stats(path)
        return nil unless kubelet_csi?
        return :unsupported unless @csi.respond_to?(:supports?) && @csi.supports?("GET_VOLUME_STATS")

        ensure_path!(path)
        with_secure_csi_target(path, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          sanitize_response(AdapterSupport.result_hash(invoke_csi(:stats, remote_id, path: dispatch_path)))
        end
      end

      # CSIDriver.spec.requiresRepublish: the kubelet calls NodePublishVolume
      # again periodically (fresh ServiceAccount tokens, rotated content).
      def requires_republish?
        @csi.respond_to?(:requires_republish?) && @csi.requires_republish? == true
      end

      # The periodic remount: NodePublishVolume on the existing target, with
      # the context rebuilt as at publish.
      def republish(stage_path:, target:, pod:, readonly: false, context: {}, token:)
        ensure_path!(stage_path)
        ensure_path!(target)
        remote_context = kubelet_csi_context(with_secrets(Types.deep_copy(context), :node_publish))
        remote_context["pod"] = Types.deep_copy(pod) if kubelet_csi? && pod.is_a?(Hash)
        target_directory = !Types.key(spec, "volumeMode", "Filesystem").to_s.casecmp?("Block")
        with_secure_csi_target(stage_path, directory: true, create: false, post_effect: :mounted) do |dispatch_stage, _stage_lease|
          with_secure_csi_target(target, directory: target_directory, create: false, post_effect: :mounted) do |dispatch_target, _lease|
            sanitize_response(AdapterSupport.result_hash(
              invoke_csi(:publish_node, remote_id, dispatch_stage, dispatch_target, token: token,
                                                                                    readonly: readonly || readonly?, context: remote_context)
            ))
          end
        end
      end

      # The kubelet CSI mounter's fsGroup decision for this volume: nil when
      # the adapter is not a kubelet node plugin (the stage-path pass
      # applies), otherwise :delegate, :kubelet or :none.
      def csi_fs_group_mode(fs_group, readonly:)
        return nil unless @csi.respond_to?(:fs_group_mode)

        @csi.fs_group_mode(fs_group: fs_group, fs_type: Types.key(spec, "fsType", "").to_s,
                           access_modes: Array(Types.key(spec, "accessModes", [])),
                           ephemeral: Types.key(spec, "ephemeral", false) == true, readonly: readonly || readonly?)
      end

      # ReadOnlyMany is a volume capability, not merely a caller hint.  Keep
      # it on the backend as well as in the ControllerPublish request so a
      # direct backend lifecycle call cannot accidentally issue a writable
      # NodePublishVolume/NodeStageVolume request.
      def readonly?
        Types.key(spec, "readOnly", Types.key(spec, "readonly", false)) == true ||
          Array(Types.key(spec, "accessModes", [])).map(&:to_s).include?("ReadOnlyMany")
      end

      def snapshot(token:, name: nil, effect_boundary: nil)
        secrets = secrets_for(:create_snapshot)
        sanitize_response(invoke_remote_mutation(effect_boundary) do
          invoke_csi(:create_snapshot, remote_id, token: token, name: name, secrets: secrets)
        end)
      end

      def delete(token:, effect_boundary: nil)
        secrets = secrets_for(:delete_volume)
        invoke_remote_mutation(effect_boundary) do
          invoke_csi(:delete_volume, remote_id, token: token, secrets: secrets)
        end
      end

      def attach(node:, context: {}, effect_boundary: nil)
        request_context = kubelet_csi_context(with_secrets(context, :controller_publish))
        sanitize_response(invoke_remote_mutation(effect_boundary) do
          invoke_csi(:publish, remote_id, node,
                     token: Types.key(context, "token", "attach-#{id}-#{node}"),
                     readonly: controller_readonly?(request_context), context: request_context)
        end)
      end

      def detach(node:, context: {}, effect_boundary: nil)
        request_context = with_secrets(context, :controller_unpublish)
        invoke_remote_mutation(effect_boundary) do
          invoke_csi(:unpublish, remote_id, node, token: Types.key(context, "token", "detach-#{id}-#{node}"),
                     context: request_context)
        end
      end

      def delete_snapshot(snapshot_id, token:, effect_boundary: nil)
        secrets = secrets_for(:delete_snapshot)
        invoke_remote_mutation(effect_boundary) do
          invoke_csi(:delete_snapshot, snapshot_id, token: token, secrets: secrets)
        end
      end

      def stage(path:, node:, readonly: false, context: {}, effect_boundary: nil)
        ensure_path!(path)
        request_context = kubelet_csi_context(with_secrets(context, :node_stage))
        token = Types.key(context, "token", "stage-#{id}-#{node}")
        with_secure_csi_target(
          path, directory: true, create: true, post_effect: :mounted,
          compensation: lambda do |dispatch_path, original_path|
            compensate_stage_mount!(dispatch_path, original_path, token: token)
          end
        ) do |dispatch_path, lease|
          response = invoke_remote_mutation(effect_boundary) do
            invoke_csi(:stage, remote_id, dispatch_path,
                       token: token,
                       readonly: readonly || readonly?, context: request_context)
          end
          normalize_remote_mount(response, path, stage: true,
                                  aliases: [dispatch_path], path_identity: lease&.identity)
        end
      end

      def unstage(path:, identity: nil, context: {}, effect_boundary: nil)
        ensure_path!(path)
        # A stage the plugin completed without a kernel mount has no mount
        # identity to verify; the target must nevertheless still be absent
        # from mountinfo, otherwise a foreign mount appeared under our path.
        if unmounted_stage_identity?(identity)
          if remote_mount_readback(path)
            raise MountIdentityError, "CSI stage #{path.inspect} was recorded unmounted but a mount now covers it"
          end
        else
          verify_mount_identity!(path, identity)
        end
        with_secure_csi_target(path, directory: true, create: false, post_effect: :removed) do |dispatch_path, _lease|
          invoke_remote_mutation(effect_boundary) do
            invoke_csi(:unstage, remote_id, dispatch_path, token: Types.key(context, "token", "unstage-#{id}"))
          end
          verify_remote_absent!(path, aliases: [dispatch_path]) if @require_real_readback
        end
        true
      end

      def publish(stage_path:, target:, node:, pod:, readonly: false, sub_path: nil, context: {}, effect_boundary: nil)
        ensure_path!(stage_path)
        ensure_path!(target)
        parent_handle = nil
        handle = nil
        remote_context = Types.deep_copy(context)
        if sub_path
          raise PathSecurityError, "subPath requires openat2 descriptor validation" unless @path_security

          parent_handle = open_stage_handle(stage_path)
          begin
            # A read-only volume is never modified to satisfy a subPath.
            handle = @path_security.validate_sub_path!(parent_handle, sub_path,
                                                       create: !(readonly || readonly?))
          ensure
            parent_handle.close unless handle && parent_handle.equal?(handle)
            parent_handle = nil
          end
          remote_context["subPath"] = handle.path.to_s if handle.respond_to?(:path)
          remote_context["subPathIdentity"] = handle.identity if handle.respond_to?(:identity)
        end
        remote_context = kubelet_csi_context(with_secrets(remote_context, :node_publish))
        # The kubelet's CSI mounter passes the Pod's identity and the
        # ServiceAccount tokens in the volume context.
        remote_context["pod"] = Types.deep_copy(pod) if kubelet_csi? && pod.is_a?(Hash)
        target_directory = !Types.key(spec, "volumeMode", "Filesystem").to_s.casecmp?("Block")
        with_secure_csi_target(stage_path, directory: true, create: false, post_effect: :mounted) do |dispatch_stage, _stage_lease|
          with_secure_csi_target(
            target, directory: target_directory, create: true, post_effect: :mounted,
            compensation: lambda do |dispatch_path, original_path|
              compensate_publish_mount!(dispatch_path, original_path,
                                         token: Types.key(context, "token", "publish-#{id}-#{target}"))
            end
          ) do |dispatch_target, target_lease|
            response = invoke_remote_mutation(effect_boundary) do
              invoke_csi(:publish_node, remote_id, dispatch_stage, dispatch_target,
                         token: Types.key(context, "token", "publish-#{id}-#{target}"),
                         readonly: readonly || readonly?, context: remote_context)
            end
            result = normalize_remote_mount(response, target, stage: false,
                                            aliases: [dispatch_target], path_identity: target_lease&.identity)
            result["node"] = node.to_s
            result["pod"] = pod_identifier(pod)
            result
          end
        end
      ensure
        handle&.close
      end

      def unpublish(target:, identity: nil, context: {}, effect_boundary: nil)
        ensure_path!(target)
        verify_mount_identity!(target, identity)
        with_secure_csi_target(target, directory: nil, create: false, post_effect: :removed) do |dispatch_target, _lease|
          invoke_remote_mutation(effect_boundary) do
            invoke_csi(:unpublish_node, remote_id, dispatch_target,
                       token: Types.key(context, "token", "unpublish-#{id}-#{target}"))
          end
          verify_remote_absent!(target, aliases: [dispatch_target]) if @require_real_readback
        end
        true
      end

      def stats(path:, capacity_bytes: nil)
        ensure_path!(path)
        value = with_secure_csi_target(path, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          invoke_csi(:stats, remote_id, path: dispatch_path)
        end
        hash = AdapterSupport.result_hash(value)
        Stats.new(volume_id: id, used_bytes: hash["usedBytes"] || 0, capacity_bytes: hash["capacityBytes"] || capacity_bytes || 0,
                  available_bytes: hash["availableBytes"])
      end

      def expand(capacity_bytes:, token:, node_paths: [], effect_boundary: nil)
        # ControllerExpandVolume can change remote state before NodeExpandVolume
        # runs. Acquire every node target first so a descriptor-less/raw-path
        # profile makes zero CSI calls and any parent/leaf replacement is
        # detected before the controller mutation crosses its effect boundary.
        ensure_descriptor_target_security!
        target_paths = Array(node_paths).map { |path| File.expand_path(ensure_path!(path).to_s) }.uniq
        secrets = secrets_for(:expand)
        with_target_leases(target_paths, post_effect: :mounted) do |leases|
          response = sanitize_response(invoke_remote_mutation(effect_boundary) do
            invoke_csi(:expand, remote_id, capacity_bytes, token: token, secrets: secrets,
                       volume_capability: csi_volume_capability)
          end)
          verify_target_leases!(leases, post_effect: :mounted)
          required = Types.key(response, "nodeExpansionRequired", Types.key(response, "node_expansion_required", false)) == true
          expanded_paths = []
          if required
            leases.each do |path, lease|
              begin
                # Same contract as with_secure_csi_target: the plugin acts on
                # the canonical path while the lease pins the inode.
                invoke_csi(:expand_node, remote_id, lease.original_path,
                           token: "#{token}:node:#{Types.digest(path)[0, 16]}",
                           capacity_bytes: capacity_bytes,
                           volume_capability: csi_volume_capability,
                           secrets: secrets_for(:node_expand))
                verify_target_leases!([[path, lease]], post_effect: :mounted)
                expanded_paths << path
              rescue OperationUnknown
                raise
              rescue StandardError => error
                raise OperationUnknown.new("CSI NodeExpandVolume failed after controller expansion: #{sanitize_error(error).message}"), cause: error
              end
            end
          end
          {
            "capacityBytes" => Types.key(response, "capacityBytes", capacity_bytes),
            "nodeExpansionRequired" => required,
            "nodeExpandedPaths" => expanded_paths
          }
        end
      end

      def expand_node(path:, capacity_bytes:, token:, effect_boundary: nil)
        ensure_path!(path)
        effect_boundary&.call
        response = perform_node_expand(path: path, capacity_bytes: capacity_bytes, token: token)
        sanitize_response(response)
      rescue StandardError => error
        raise OperationUnknown.new("CSI NodeExpandVolume result is unknown: #{sanitize_error(error).message}"), cause: error
      end

      private

      def remote_id
        return @driver_volume_id if Types.present?(@driver_volume_id)

        raise CSIUnavailable, "CSI driver volume id mapping is missing for local volume #{id}"
      end

      def csi_volume_capability
        Types.deep_copy(Types.key(spec, "volumeCapability", {
          "accessModes" => Array(Types.key(spec, "accessModes", ["ReadWriteOnce"])),
          "volumeMode" => Types.key(spec, "volumeMode", "Filesystem")
        }))
      end

      def with_secrets(context, purpose)
        Types.deep_copy(context).merge("secrets" => secrets_for(purpose))
      end

      def secrets_for(purpose)
        value = @secret_provider ? @secret_provider.call(purpose) : {}
        hash = value.respond_to?(:to_h) ? value.to_h : nil
        raise CSIUnavailable, "CSI secret resolver returned a non-map for #{purpose}" unless hash

        hash.each_with_object({}) do |(key, child), result|
          result[String(key)] = String(child)
        rescue TypeError
          raise CSIUnavailable, "CSI secret resolver returned a non-string value for #{purpose}"
        end
      end

      def invoke_remote_mutation(effect_boundary)
        effect_boundary&.call
        yield
      rescue CSIError => error
        effect_boundary&.call(:rejected) unless error.ambiguous?
        sanitized = sanitize_error(error)
        raise if sanitized.equal?(error)
        raise sanitized, cause: error
      rescue CSIUnavailable => error
        effect_boundary&.call(:rejected)
        sanitized = sanitize_error(error)
        raise if sanitized.equal?(error)
        raise sanitized, cause: error
      end

      # Keep compatibility with narrow injected test adapters while passing
      # every CSI context keyword to the real UDS client.
      def invoke_csi(method_name, *args, **kwargs)
        method = @csi.method(method_name)
        parameters = method.parameters
        return method.call(*args, **kwargs) if parameters.any? { |kind, _| kind == :keyrest }

        accepted = kwargs.select do |key, _|
          parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name.to_sym == key.to_sym }
        end
        method.call(*args, **accepted)
      rescue NoMethodError
        raise CSIUnavailable, "CSI adapter does not implement #{method_name}"
      end

      def normalize_remote_mount(value, target, stage:, aliases: [], path_identity: nil)
        response = sanitize_response(AdapterSupport.result_hash(value))
        observed = remote_mount_readback(target, aliases: aliases)
        if @require_real_readback
          if observed.nil? && stage && (stage_without_mount_declared? || response["stageSkipped"] == true)
            # CSI permits NodeStageVolume to complete without a kernel mount
            # (csi-driver-host-path, NFS-style drivers record the stage and
            # mount only at NodePublishVolume).  Because a missing readback is
            # otherwise the signature of a lost effect, this is accepted only
            # when the volume spec declares csi.stageWithoutMount for the
            # driver.  Nothing exists in the kernel to own, so the stage is
            # recorded explicitly as unmounted and never enters the mount
            # ledger; NodePublishVolume still requires an independent readback.
            return unmounted_stage_identity(response, target, path_identity: path_identity)
          end
          unless observed
            raise MountIdentityError, "CSI #{stage ? "stage" : "publish"} succeeded but #{target.inspect} is absent from independent mount readback"
          end
          normalized = normalize_mount(observed, target, stage: stage)
        else
          identity = response["mountIdentity"] || response["mount_identity"]
          response = AdapterSupport.result_hash(identity).merge(response) if identity.respond_to?(:to_h)
          normalized = normalize_mount(response, target, stage: stage)
        end
        response.each do |key, child|
          key = key.to_s
          # Never let a CSI response overwrite a kernel identity obtained from
          # mountinfo.  The plugin response is metadata, not readback proof.
          normalized[key] = Types.deep_copy(child) unless normalized.key?(key)
        end
        normalized["target"] = target
        normalized["stage"] = stage == true
        normalized["pathIdentity"] = Types.deep_copy(path_identity) if path_identity
        normalized
      end

      def unmounted_stage_identity(response, target, path_identity: nil)
        identity = {
          "volumeId" => id, "source" => "csi://#{remote_id}", "sourceIdentity" => "csi://#{remote_id}",
          "target" => target, "stage" => true, "mounted" => false, "readonly" => readonly?,
          "secret" => secret?, "filesystemUuid" => nil, "filesystemUuidAvailable" => false
        }
        response.each do |key, child|
          key = key.to_s
          identity[key] = Types.deep_copy(child) unless identity.key?(key)
        end
        identity["target"] = target
        identity["stage"] = true
        identity["mounted"] = false
        identity["pathIdentity"] = Types.deep_copy(path_identity) if path_identity
        identity
      end

      def remote_mount_readback(target, aliases: [])
        candidates = ([target] + Array(aliases)).map { |value| File.expand_path(value.to_s) }.uniq
        if @mount_adapter.respond_to?(:find_mount)
          candidates.each do |candidate|
            observed = @mount_adapter.find_mount(candidate)
            return observed if observed
          end
          return nil
        end
        return nil unless @mount_adapter.respond_to?(:list_mounts)

        Array(AdapterSupport.call(@mount_adapter, :list_mounts)).find do |entry|
          hash = entry.respond_to?(:to_h) ? entry.to_h : entry
          candidates.include?(File.expand_path((hash["target"] || hash[:target] || hash["mountpoint"] || hash[:mountpoint]).to_s))
        end
      end

      def verify_remote_absent!(target, aliases: [])
        return true unless remote_mount_readback(target, aliases: aliases)

        raise MountIdentityError, "CSI unmount succeeded but #{target.inspect} remains in independent mount readback"
      end

      def controller_readonly?(context)
        modes = Array(Types.key(context, "accessModes", Types.key(spec, "accessModes", []))).map(&:to_s)
        Types.key(spec, "readOnly", Types.key(spec, "readonly", false)) == true ||
          modes.include?("ReadOnlyMany") || readonly?
      end

      def sanitize_response(value)
        return AdapterSupport.result_hash(value) unless @persistence_sanitizer

        @persistence_sanitizer.call(AdapterSupport.result_hash(value))
      end

      def sanitize_error(error)
        @error_sanitizer ? @error_sanitizer.call(error) : error
      end

      def with_secure_csi_target(path, directory:, create:, post_effect: :unchanged, compensation: nil)
        ensure_descriptor_target_security!
        mounted = mounted_post_effect?(post_effect)
        lease = @path_security.acquire_target!(path, directory: directory, create: create)
        result = nil
        primary_error = nil
        verification_error = nil
        begin
          # CSI plugins receive the canonical pathname, exactly as kubelet
          # sends it.  A /proc/<pid>/fd/<n> alias breaks real drivers: the
          # mount-utils IsLikelyNotMountPoint heuristic compares st_dev of the
          # path and its parent, and /proc's device differs from every target,
          # so the plugin concludes "already mounted" and never mounts.  The
          # lease still pins the parent and leaf inodes; the post-effect
          # verification below binds the visible path and mountinfo entry to
          # those inodes and fences (OperationUnknown + compensation) when a
          # concurrent rename or symlink swap redirected the plugin.
          result = yield(lease.original_path, lease)
        rescue StandardError => error
          primary_error = error
        end

        begin
          observation = mounted ? mount_identity_for_target(path, result) : nil
          verify_target_lease!(lease, mounted: mounted, mount_identity: observation)
        rescue StandardError => error
          verification_error = error
        end

        compensation_error = nil
        if compensation && (primary_error || verification_error) && !ambiguous_remote_error?(primary_error)
          begin
            # Compensation must name the path the plugin acted on; the
            # descriptor alias is kept in the error details for operators.
            compensation.call(lease.original_path, lease.original_path)
          rescue StandardError => error
            compensation_error = error
          end
        end

        begin
          lease.close
        rescue StandardError => error
          verification_error ||= error
        end

        if compensation_error
          primary = verification_error || primary_error
          details = {
            "primaryError" => {"class" => primary.class.name, "message" => primary.message.to_s},
            "cleanupErrors" => [{"class" => compensation_error.class.name, "message" => compensation_error.message.to_s}],
            "leaseIdentity" => Types.deep_copy(lease.identity),
            "originalPath" => lease.original_path,
            "dispatchPath" => lease.dispatch_path
          }
          raise CleanupError.new(
            "CSI target compensation is ambiguous for #{path.inspect}: #{compensation_error.message}",
            details: details, cleanup_errors: [compensation_error]
          ), cause: primary
        end
        if verification_error
          raise OperationUnknown.new(
            "CSI target identity could not be verified: #{sanitize_error(verification_error).message}",
            details: {
              "leaseIdentity" => Types.deep_copy(lease.identity),
              "originalPath" => lease.original_path,
              "dispatchPath" => lease.dispatch_path
            }
          ), cause: verification_error
        end
        raise primary_error if primary_error

        result
      end

      def ensure_descriptor_target_security!
        return true if @path_security&.respond_to?(:descriptor_capable?) && @path_security.descriptor_capable?

        raise PathSecurityError, "CSI target dispatch requires an openat2 descriptor lease"
      end

      def with_target_leases(paths, post_effect: :unchanged)
        ensure_descriptor_target_security!
        mounted_post_effect?(post_effect)
        leases = []
        begin
          Array(paths).each do |path|
            leases << [path, @path_security.acquire_target!(path, directory: nil, create: false)]
          end
          yield leases
        ensure
          verify_and_close_target_leases(leases.map(&:last), post_effect: post_effect,
                                         mount_observer: ->(target) { mount_identity_for_target(target) })
        end
      end

      def verify_target_leases!(leases, post_effect: :unchanged)
        mounted = mounted_post_effect?(post_effect)
        Array(leases).each do |path, lease|
          observation = mounted ? mount_identity_for_target(path) : nil
          verify_target_lease!(lease, mounted: mounted, mount_identity: observation)
        end
        true
      rescue StandardError => error
        raise OperationUnknown.new("CSI target identity could not be verified: #{sanitize_error(error).message}"), cause: error
      end

      def verify_and_close_target_leases(leases, post_effect: :unchanged, mount_identity: nil, mount_observer: nil)
        mounted = mounted_post_effect?(post_effect)
        verification_error = nil
        Array(leases).each do |lease|
          begin
            observation = mount_identity || (mount_observer && mount_observer.call(lease.original_path))
            verify_target_lease!(lease, mounted: mounted, mount_identity: observation)
          rescue StandardError => error
            verification_error ||= error
          end
        end
        Array(leases).reverse_each(&:close)
        return true unless verification_error

        raise OperationUnknown.new("CSI target identity could not be verified: #{sanitize_error(verification_error).message}"),
              cause: verification_error
      end

      def verify_target_lease!(lease, mounted:, mount_identity: nil)
        return true unless lease && lease.respond_to?(:verify_original!)

        verifier = lease.method(:verify_original!)
        accepts_mount_identity = verifier.parameters.any? do |kind, name|
          kind == :keyrest || (%i[key keyreq].include?(kind) && name.to_sym == :mount_identity)
        end
        if accepts_mount_identity
          lease.verify_original!(mounted: mounted, mount_identity: mount_identity)
        else
          lease.verify_original!(mounted: mounted)
        end
      end

      def mounted_post_effect?(post_effect)
        mode = post_effect.to_sym
        return true if mode == :mounted
        return false if %i[unchanged removed].include?(mode)

        raise ValidationError, "unsupported CSI target post-effect verification mode #{post_effect.inspect}"
      rescue NoMethodError
        raise ValidationError, "CSI target post-effect verification mode must be a symbol"
      end

      def mount_identity_for_target(path, result = nil)
        return nil unless @mount_adapter.respond_to?(:descriptor_mount_binding?) &&
                          @mount_adapter.descriptor_mount_binding? == true

        if @mount_adapter.respond_to?(:find_mount)
          observed = @mount_adapter.find_mount(path)
          return observed if observed
        elsif @mount_adapter.respond_to?(:list_mounts)
          normalized = File.expand_path(path.to_s)
          observed = Array(AdapterSupport.call(@mount_adapter, :list_mounts)).find do |entry|
            hash = entry.respond_to?(:to_h) ? entry.to_h : entry
            candidate = hash && (hash["target"] || hash[:target] || hash["mountpoint"] || hash[:mountpoint])
            candidate && File.expand_path(candidate.to_s) == normalized
          end
          return observed if observed
        end

        hash = result.respond_to?(:to_h) ? result.to_h.transform_keys(&:to_s) : nil
        return nil unless hash && (hash["mountId"] || hash["mount_id"]) && (hash["target"] || hash["mountpoint"])

        hash
      end

      def compensate_stage_mount!(dispatch_path, original_path, token:)
        invoke_csi(:unstage, remote_id, dispatch_path, token: "#{token}:compensate")
        verify_remote_absent!(original_path, aliases: [dispatch_path]) if @require_real_readback
        true
      end

      def compensate_publish_mount!(dispatch_path, original_path, token:)
        invoke_csi(:unpublish_node, remote_id, dispatch_path, token: "#{token}:compensate")
        verify_remote_absent!(original_path, aliases: [dispatch_path]) if @require_real_readback
        true
      end

      def kubelet_csi?
        @csi.respond_to?(:pod_context?) && @csi.pod_context?
      end

      # What the kubelet sends a node plugin besides the manager's context:
      # the lifecycle mode, fsType and the PV's mountOptions.
      def kubelet_csi_context(context)
        return context unless kubelet_csi?

        context["ephemeral"] = Types.key(spec, "ephemeral", false) == true
        context["fsType"] = Types.key(spec, "fsType", "").to_s
        context["mountOptions"] = Array(Types.key(spec, "mountOptions", [])).map(&:to_s)
        context
      end

      def stage_without_mount_declared?
        return true if Types.key(spec, "stageWithoutMount", false) == true

        csi_spec = Types.key(spec, "csi", {})
        csi_spec = csi_spec.respond_to?(:to_h) ? csi_spec.to_h : {}
        Types.key(csi_spec, "stageWithoutMount", false) == true
      end

      def unmounted_stage_identity?(identity)
        hash = identity.respond_to?(:to_h) ? identity.to_h.transform_keys(&:to_s) : nil
        hash.is_a?(Hash) && hash["stage"] == true && hash.key?("mounted") && hash["mounted"] == false &&
          !Types.present?(hash["mountId"])
      end

      def ambiguous_remote_error?(error)
        return false unless error
        return true if error.respond_to?(:ambiguous?) && error.ambiguous?

        error.class.name.to_s.match?(/Unknown|Ambiguous|Timeout|EOF|ConnectionReset|BrokenPipe/)
      end

      def perform_node_expand(path:, capacity_bytes:, token:)
        ensure_path!(path)
        with_secure_csi_target(path, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          invoke_csi(:expand_node, remote_id, dispatch_path, token: token,
                     capacity_bytes: capacity_bytes,
                     volume_capability: csi_volume_capability,
                     secrets: secrets_for(:node_expand))
        end
      end
    end

    class Controller
      include OperationSupport

      def initialize(manager = nil, **options)
        @manager = manager || options.delete(:manager) || Manager.new(**options)
      end

      def identity
        @manager.identity
      end

      def capabilities
        @manager.capabilities
      end

      def create_volume(spec, token:)
        normalized = @manager.normalize_spec(spec)
        normalized = @manager.resolve_csi_content_sources(normalized)
        id = @manager.volume_id_for(normalized)
        @manager.remember_csi_secrets(id, normalized)
        execute_operation(key: id, operation: "create", token: token, payload: normalized) do |effect_boundary|
          raise ConflictError, "volume #{id} already exists" if @manager.volume_store[id]
          persisted_spec = @manager.persisted_spec(normalized)
          backend_spec = Types.key(normalized, "backend").to_s.casecmp?("csi") ? persisted_spec : normalized
          backend = @manager.build_backend(id, backend_spec)
          record = VolumeRecord.new(id: id, spec: persisted_spec, backend: backend.type, state: "Declared",
                                   capacity_bytes: Types.key(normalized, "capacityBytes", Types.key(normalized, "capacity")))
          @manager.volume_store[id] = record
          @manager.backends[id] = backend
          begin
            provisioned = if backend.is_a?(RemoteBackend)
                            backend.provision(token: token, effect_boundary: effect_boundary)
                          else
                            backend.provision
                          end
            @manager.record_backend_mount(id, provisioned)
            durable_result = @manager.sanitize_for_persistence(provisioned)
            durable_spec = persisted_spec.merge("backendResult" => durable_result)
            record = record.with(state: "Provisioned", generation: record.generation + 1,
                                 spec: durable_spec)
            @manager.volume_store[id] = record
            @manager.backends[id] = backend.is_a?(RemoteBackend) ? @manager.build_backend(id, durable_spec) : backend
            id
          rescue StandardError => error
            if backend.is_a?(RemoteBackend) && backend.driver_volume_id
              begin
                backend.delete(token: "create-compensate-#{token}")
                effect_boundary.call(:compensated)
                @manager.volume_store.delete(id)
                @manager.backends.delete(id)
              rescue StandardError
                @manager.mark_unknown(id, operation: "create", payload: @manager.operation_payload(normalized))
              end
            elsif backend.is_a?(RemoteBackend) && error.is_a?(CSIUnavailable) && !ambiguous_error?(error)
              # No plugin was reached (the kubelet's "driver not found in the
              # list of registered CSI drivers"): nothing exists to fence, and
              # the create is retried once the driver registers.
              @manager.volume_store.delete(id)
              @manager.backends.delete(id)
            elsif ambiguous_error?(error) || backend.is_a?(RemoteBackend)
              @manager.mark_unknown(id)
            else
              cleanup_failed = false
              begin
                backend.delete
              rescue StandardError
                cleanup_failed = true
              end
              if cleanup_failed
                @manager.mark_unknown(id)
              else
                @manager.volume_store.delete(id)
                @manager.backends.delete(id)
              end
            end
            raise
          end
        end
      end

      def delete_volume(id, token:)
        id = Types.identifier(id, "volume id")
        execute_operation(key: id, operation: "delete", token: token, payload: {"id" => id}) do |effect_boundary|
          record = @manager.fetch_record(id)
          raise ConflictError, "volume #{id} has active published consumers" unless record.publishes.empty?
          raise ConflictError, "volume #{id} has active attachments or stages" unless record.attachments.empty? && record.stages.empty?
          @manager.ensure_known!(record, action: "Cleanup")
          # An Unknown volume may still be torn down, but only when there is a
          # backend to tear it down WITH.  A record whose backend could not be
          # reconstructed after a restart has nothing to delete, and saying so
          # is the honest answer -- a bare `fetch` raised KeyError instead,
          # which told the caller nothing.
          backend = @manager.backends[id]
          unless backend
            raise StateUnknownError,
                  "volume #{id} is #{record.state} and its backend could not be reconstructed; recover before deleting"
          end
          raise ConflictError, "volume #{id} must be detached before delete" unless %w[Provisioned Detached Declared].include?(record.state)
          if backend.is_a?(RemoteBackend)
            backend.delete(token: token, effect_boundary: effect_boundary)
          else
            backend.delete
          end
          @manager.mount_ledger.remove_volume(id)
          @manager.volume_store.delete(id)
          @manager.backends.delete(id)
          @manager.forget_csi_secrets(id)
          true
        end
      end

      alias delete delete_volume

      # ControllerPublishVolume / ControllerUnpublishVolume semantics.
      def publish(id, node, token:)
        id = Types.identifier(id, "volume id")
        node = Types.identifier(node, "node")
        current = @manager.fetch_record(id)
        @manager.ensure_known!(current)
        if (existing = current.attachments[node])
          return Types.deep_copy(existing["backendResult"] || existing)
        end
        operation = "controller-publish:#{node}:#{current.generation}"
        execute_operation(key: id, operation: operation, token: token,
                          payload: {"id" => id, "node" => node, "generation" => current.generation}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record)
          enforce_attach_policy!(record, node: node, pod: nil)
          if (existing = record.attachments[node])
            return Types.deep_copy(existing["backendResult"] || existing)
          end
          backend = @manager.backends.fetch(id)
          context = attachment_context(record, node)
          result = if backend.is_a?(RemoteBackend)
                     AdapterSupport.result_hash(backend.attach(node: node, context: context,
                                                               effect_boundary: effect_boundary))
                   else
                     AdapterSupport.result_hash(backend.attach(node: node, context: context))
                   end
          durable_result = if backend.is_a?(RemoteBackend)
                             @manager.sanitize_for_persistence(result)
                           else
                             Types.deep_copy(result)
                           end
          attachments = Types.deep_copy(record.attachments)
          attachments[node] = {
            "node" => node, "pods" => [], "publishContext" => Types.deep_copy(durable_result["publishContext"] || {}),
            "volumeContext" => Types.deep_copy(context["volumeContext"] || {}),
            "accessModes" => Types.deep_copy(context["accessModes"] || []),
            "volumeMode" => context["volumeMode"].to_s,
            "backendResult" => durable_result
          }
          attachments[node]["pods"] = Array(attachments[node]["pods"]).uniq
          new_state = record.state == "Detached" ? "Attached" : record.state
          new_state = "Attached" if %w[Provisioned Declared].include?(new_state)
          record = record.with(state: new_state, attachments: attachments, generation: record.generation + 1)
          @manager.volume_store[id] = record
          durable_result || {"volumeId" => id, "node" => node}
        end
      end

      def unpublish(id, node, token:)
        id = Types.identifier(id, "volume id")
        node = Types.identifier(node, "node")
        current = @manager.fetch_record(id)
        @manager.ensure_known!(current, action: "Cleanup")
        return true unless current.attachments.key?(node)
        operation = "controller-unpublish:#{node}:#{current.generation}"
        execute_operation(key: id, operation: operation, token: token,
                          payload: {"id" => id, "node" => node, "generation" => current.generation}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record, action: "Cleanup")
          return true unless record.attachments.key?(node)
          raise ConflictError, "volume #{id} still has published consumers on #{node}" if record.publishes.values.any? { |entry| entry["node"].to_s == node }
          backend = @manager.backends.fetch(id)
          context = attachment_context(record, node, attachment: record.attachments[node])
          if backend.is_a?(RemoteBackend)
            backend.detach(node: node, context: context, effect_boundary: effect_boundary)
          else
            backend.detach(node: node, context: context)
          end
          attachments = Types.deep_copy(record.attachments)
          attachments.delete(node)
          state = attachments.empty? && record.stages.empty? ? "Detached" : record.state
          @manager.volume_store[id] = record.with(state: state, attachments: attachments, generation: record.generation + 1)
          true
        end
      end

      alias controller_publish publish
      alias controller_unpublish unpublish

      def create_snapshot(id, token:, name: nil)
        execute_operation(key: id.to_s, operation: "snapshot", token: token,
                          payload: {"id" => id.to_s, "name" => name}) do |effect_boundary|
          @manager.snapshot_manager.create(id, token: token, name: name, effect_boundary: effect_boundary).id
        end
      end

      alias snapshot create_snapshot

      def delete_snapshot(snapshot_id, token:)
        snapshot_id = Types.identifier(snapshot_id, "snapshot id")
        execute_operation(key: "snapshot-#{snapshot_id}", operation: "delete-snapshot", token: token,
                          payload: {"snapshotId" => snapshot_id}) do |effect_boundary|
          @manager.snapshot_manager.delete(snapshot_id, token: token, effect_boundary: effect_boundary)
        end
      rescue OperationUnknown => error
        @manager.snapshot_manager.mark_unknown(snapshot_id, reason: error)
        raise
      end

      def expand(id, capacity, token:)
        id = Types.identifier(id, "volume id")
        execute_operation(key: id, operation: "expand", token: token, payload: {"id" => id, "capacity" => capacity}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record)
          bytes = Types.parse_capacity(capacity)
          current = record.capacity_bytes || 0
          raise CapacityError, "volume expansion must increase capacity" unless bytes > current
          class_name = Types.key(record.spec, "storageClassName", Types.key(record.spec, "storageClass", "")).to_s
          storage_class = class_name.empty? ? nil : @manager.binder.find_storage_class(class_name)
          if storage_class && !storage_class.allow_volume_expansion
            raise UnsupportedError, "online expansion is disabled for storage class #{class_name.inspect}"
          end
          backend = @manager.backends.fetch(id)
          result = if backend.is_a?(RemoteBackend)
                     expansion = backend.expand(capacity_bytes: bytes, token: token,
                                                node_paths: @manager.expansion_paths(record),
                                                effect_boundary: effect_boundary)
                     record = @manager.record_expansion_result(record, expansion)
                     Types.key(expansion, "capacityBytes", bytes)
                   else
                     backend.expand(capacity_bytes: bytes)
                   end
          @manager.volume_store[id] = record.with(capacity_bytes: bytes, generation: record.generation + 1)
          result
        end
      end

      alias controller_expand expand

      def ensure_attach_policy(record, node:, pod: nil)
        enforce_attach_policy!(record, node: node, pod: pod)
      end

      private

      def attachment_context(record, node, attachment: nil)
        spec = record.spec
        backend_result = Types.key(spec, "backendResult", {})
        volume_context = Types.key(spec, "volumeContext", {}).to_h.merge(
          Types.key(backend_result, "volumeContext", Types.key(backend_result, "volume_context", {})).to_h
        )
        attachment ||= Types.key(record.attachments, node, {})
        {
          "volumeContext" => volume_context,
          "publishContext" => Types.deep_copy(Types.key(attachment, "publishContext", {})),
          "secrets" => Types.deep_copy(Types.key(spec, "secrets", {})),
          "accessModes" => Array(Types.key(spec, "accessModes", ["ReadWriteOnce"])),
          "volumeMode" => Types.key(spec, "volumeMode", "Filesystem").to_s,
          "volumeCapability" => Types.deep_copy(Types.key(spec, "volumeCapability", {})),
          "node" => node.to_s
        }
      end

      def node_context(record, node, context)
        attachment = record.attachments[node.to_s] || record.attachments[node]
        # Caller-supplied context may add a mount path/capability, but the
        # durable controller result and CreateVolume context always win.
        Types.deep_copy(context).merge(attachment_context(record, node, attachment: attachment))
      end

      def enforce_attach_policy!(record, node:, pod:)
        modes = Array(Types.key(record.spec, "accessModes", ["ReadWriteOnce"]))
        existing_nodes = record.attachments.keys
        if modes.include?("ReadWriteOncePod") && !existing_nodes.empty?
          raise MultiAttachError, "ReadWriteOncePod volume #{record.id} is already attached to another node" if existing_nodes.any? { |existing| existing.to_s != node.to_s }
        end
        if (modes & %w[ReadWriteOnce ReadWriteOncePod]).any? && existing_nodes.any? { |existing| existing.to_s != node.to_s }
          raise MultiAttachError, "volume #{record.id} with #{modes.join(", ")} cannot attach to multiple nodes"
        end
        return true unless pod
        if modes.include?("ReadWriteOncePod") && record.attachments.values.any? { |entry| Array(entry["pods"]).any? { |value| value != pod } }
          raise MultiAttachError, "ReadWriteOncePod volume #{record.id} is already used by another pod"
        end
      end
    end

    class Node
      include OperationSupport

      def initialize(manager = nil, **options)
        @manager = manager || options.delete(:manager) || Manager.new(**options)
      end

      # See Manager#forget_mount_target: clears a record left behind at a
      # fixed Pod path by an attempt that died.
      def forget_mount_target(target)
        @manager.forget_mount_target(target)
      end

      def stage(id, path, token:, readonly: false, node: nil, context: {})
        id = Types.identifier(id, "volume id")
        readonly = Types.bool(readonly)
        path = secure_path(path)
        execute_operation(key: id, operation: "stage:#{path}", token: token,
                          payload: {"id" => id, "path" => path, "readonly" => readonly, "node" => node}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record)
          record = ensure_attached(record, node)
          if node && !record.attachments.key?(node.to_s)
            raise ConflictError, "volume #{id} is not attached to node #{node}"
          end
          effective_node = node || attached_node(record)
          raise InvalidStateError, "volume #{id} must be Attached before staging (state #{record.state})" unless %w[Attached Staged].include?(record.state)
          if record.stages.key?(path)
            existing = record.stages.fetch(path)
            if node && existing["node"].to_s != node.to_s
              raise ConflictError, "volume #{id} is already staged on node #{existing["node"]}"
            end
            next existing
          end
          backend = @manager.backends.fetch(id)
          modes = Array(Types.key(record.spec, "accessModes", []))
          effective_readonly = readonly || modes.include?("ReadOnlyMany")
          effective_context = @manager.context_for_node(record, effective_node, context)
          result = if backend.is_a?(RemoteBackend)
                     backend.stage(path: path, node: effective_node, readonly: effective_readonly,
                                   context: effective_context, effect_boundary: effect_boundary)
                   else
                     backend.stage(path: path, node: effective_node, readonly: effective_readonly, context: effective_context)
                   end
          if backend.is_a?(RemoteBackend) && @manager.node_expansion_required?(record)
            backend.expand_node(path: path, capacity_bytes: record.capacity_bytes,
                                token: "#{token}:node-expand", effect_boundary: effect_boundary)
            record = @manager.record_node_expanded(record, path)
          end
          result["node"] = effective_node
          begin
            # A stage that the CSI plugin completed without a kernel mount
            # owns nothing in the mount table; only kernel identities enter
            # the ledger (spec 5.11.3).
            unless result["mounted"] == false && !Types.present?(result["mountId"])
              @manager.register_mount_identity(volume_id: id, identity: result, target: path,
                                               owner: "volume:#{id}", stage_path: path,
                                               generation: record.generation, secret: backend.secret?)
            end
            stages = Types.deep_copy(record.stages)
            stages[path] = result
            new_state = record.state == "Attached" ? "Staged" : record.state
            @manager.volume_store[id] = record.with(state: new_state, stages: stages, generation: record.generation + 1)
            result
          rescue StandardError => error
            cleanup_errors = collect_cleanup_errors do
              backend.unstage(path: path, identity: result, context: effective_context)
            end
            raise @manager.with_cleanup_errors(error, cleanup_errors) unless cleanup_errors.empty?

            raise error
          end
        end
      end

      alias node_stage stage

      # A backend that rewrote its files (token rotation, content refresh)
      # wrote them as root; the fsGroup ownership pass runs again so the Pod
      # keeps reading them (kubelet's SetVolumeOwnership on every remount).
      def reapply_fs_group(id, pod:, stage_path:, fs_group:, readonly: false)
        return true if fs_group.nil?

        backend = @manager.backends.fetch(Types.identifier(id, "volume id"))
        # The kubelet CSI mounter applies fsGroup only at SetUp.
        return true if backend.is_a?(RemoteBackend) && !backend.csi_fs_group_mode(fs_group, readonly: readonly).nil?

        apply_security!(backend, stage_path: stage_path, pod: pod, readonly: readonly, fs_group: fs_group,
                        selinux_label: nil, mount_propagation: nil, context: {})
        true
      end

      # Backends whose content the node itself writes into the volume
      # directory.  kubelet binds such a volume's per-Pod directory straight
      # into the container; nothing is mounted for it but the tmpfs a
      # Secret, downward API or projected volume lives on.
      DIRECT_TYPES = %w[configMap secret downwardAPI projected].freeze

      # The directory the runtime binds for a provisioned node-written
      # volume, used as it is: no stage and no publish bind.  Those two
      # mounts, their readbacks and their ledger records were most of what
      # starting a Pod with fifty ConfigMap volumes cost.  fsGroup ownership
      # is applied here, where publish applied it.
      def direct_path(id, pod:, fs_group: nil)
        id = Types.identifier(id, "volume id")
        if fs_group
          begin
            raise ValidationError, "fsGroup must be non-negative" if Integer(fs_group).negative?
          rescue ArgumentError, TypeError
            raise ValidationError, "fsGroup must be an integer"
          end
        end
        record = @manager.fetch_record(id)
        @manager.ensure_known!(record)
        raise InvalidStateError, "volume #{id} must be Provisioned to be used directly (state #{record.state})" unless record.state == "Provisioned"

        backend = @manager.backends.fetch(id)
        raise ValidationError, "#{backend.type} volume #{id} cannot be used without a publish" unless DIRECT_TYPES.include?(backend.type)

        path = backend.source_path
        apply_security!(backend, stage_path: path, pod: pod, readonly: true, fs_group: fs_group,
                        selinux_label: nil, mount_propagation: nil, context: {})
        path
      end

      def publish(id, pod, container_path, readonly:, token:, node: nil, sub_path: nil, fs_group: nil,
                  selinux_label: nil, mount_propagation: nil, context: {})
        id = Types.identifier(id, "volume id")
        readonly = Types.bool(readonly)
        if mount_propagation && !%w[None HostToContainer Bidirectional].include?(mount_propagation.to_s)
          raise ValidationError, "unsupported mountPropagation #{mount_propagation.inspect}"
        end
        if fs_group
          begin
            raise ValidationError, "fsGroup must be non-negative" if Integer(fs_group).negative?
          rescue ArgumentError, TypeError
            raise ValidationError, "fsGroup must be an integer"
          end
        end
        target = secure_path(container_path)
        pod_id = pod_identifier(pod)
        execute_operation(key: id, operation: "publish:#{pod_id}:#{target}", token: token,
                          payload: {"id" => id, "pod" => pod_id, "target" => target, "readonly" => readonly, "node" => node,
                                    "subPath" => sub_path, "fsGroup" => fs_group, "selinux" => selinux_label,
                                    "propagation" => mount_propagation}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record)
          raise InvalidStateError, "volume #{id} must be Staged before publishing (state #{record.state})" unless %w[Staged Published].include?(record.state)
          if Array(Types.key(record.spec, "accessModes", [])).include?("ReadOnlyMany") && !readonly
            raise SecurityError, "ReadOnlyMany volume #{id} cannot be published writable"
          end
          stage_path = stage_for(record, node)
          backend = @manager.backends.fetch(id)
          effective_node = node || attached_node(record)
          @manager.ensure_attach_policy!(record, node: effective_node, pod: pod_id)
          publish_key = "#{pod_id}\0#{target}"
          if record.publishes.key?(publish_key)
            existing = record.publishes.fetch(publish_key)
            raise SecurityError, "volume #{id} cannot change an existing read-only publish to writable" if existing["readonly"] == true && !readonly
            next existing
          end
          effective_context = @manager.context_for_node(record, effective_node, context)
          # A kubelet CSI node plugin: fsGroup goes to the driver
          # (VOLUME_MOUNT_GROUP) or is applied to the published target
          # afterwards, per the CSIDriver's fsGroupPolicy.
          csi_fs_group = backend.is_a?(RemoteBackend) ? backend.csi_fs_group_mode(fs_group, readonly: readonly) : nil
          effective_context = effective_context.merge("volumeMountGroup" => fs_group.to_s) if csi_fs_group == :delegate
          apply_security!(backend, stage_path: stage_path, pod: pod, readonly: readonly, fs_group: csi_fs_group ? nil : fs_group,
                          selinux_label: selinux_label, mount_propagation: mount_propagation, context: context)
          result = if backend.is_a?(RemoteBackend)
                     backend.publish(stage_path: stage_path, target: target, node: effective_node, pod: pod,
                                     readonly: readonly, sub_path: sub_path, context: effective_context,
                                     effect_boundary: effect_boundary)
                   else
                     backend.publish(stage_path: stage_path, target: target, node: effective_node, pod: pod,
                                     readonly: readonly, sub_path: sub_path, context: effective_context)
                   end
          if backend.is_a?(RemoteBackend) && @manager.node_expansion_required?(record)
            backend.expand_node(path: target, capacity_bytes: record.capacity_bytes,
                                token: "#{token}:node-expand", effect_boundary: effect_boundary)
            record = @manager.record_node_expanded(record, target)
          end
          begin
            if csi_fs_group == :kubelet
              apply_security!(backend, stage_path: target, pod: pod, readonly: readonly, fs_group: fs_group,
                              selinux_label: nil, mount_propagation: nil, context: context)
            end
            @manager.register_mount_identity(volume_id: id, identity: result, target: target,
                                             owner: "pod:#{pod_id}", stage_path: stage_path,
                                             generation: record.generation, secret: backend.secret?)
            publishes = Types.deep_copy(record.publishes)
            publishes[publish_key] = result.merge("pod" => pod_id, "target" => target)
            attachments = Types.deep_copy(record.attachments)
            node_key = effective_node
            attachments[node_key] ||= {"node" => node_key, "pods" => []}
            attachments[node_key]["pods"] = (Array(attachments[node_key]["pods"]) + [pod_id]).uniq
            @manager.volume_store[id] = record.with(state: "Published", publishes: publishes, attachments: attachments,
                                                    generation: record.generation + 1)
            result
          rescue StandardError => error
            cleanup_errors = collect_cleanup_errors do
              backend.unpublish(target: target, identity: result, context: context)
            end
            raise @manager.with_cleanup_errors(error, cleanup_errors) unless cleanup_errors.empty?

            raise error
          end
        end
      end

      alias node_publish publish

      def expand_in_use(id, pod, container_path, capacity_bytes:, token:)
        id = Types.identifier(id, "volume id")
        target = secure_path(container_path)
        pod_id = pod_identifier(pod)
        @manager.with_volume_lock(id) do
          record = @manager.fetch_record(id)
          next nil if record.state == "Unknown"

          backend = @manager.backends[id]
          next nil unless backend.is_a?(RemoteBackend)

          existing = record.publishes["#{pod_id}\0#{target}"]
          next nil unless existing

          stage = record.stages.values.find { |entry| existing["node"].to_s.empty? || entry["node"].to_s == existing["node"].to_s }
          result = backend.kubelet_expand(target: target, stage_path: stage && stage["target"],
                                          capacity_bytes: Integer(capacity_bytes), token: token)
          if result.is_a?(Hash)
            capacity = [Integer(result["capacityBytes"] || 0), Integer(capacity_bytes)].max
            @manager.volume_store[id] = record.with(capacity_bytes: capacity, generation: record.generation + 1) if capacity > record.capacity_bytes.to_i
          end
          result
        end
      end

      # csi_mounter remount for a driver with requiresRepublish.  NodePublish
      # is idempotent at the driver and the mount already exists, so this
      # goes around the operation ledger (a durable entry every sync would
      # grow the node's state without bound); the volume lock still orders it
      # against the volume's other operations.  Returns false when there is
      # nothing to republish.
      def republish(id, pod, container_path, token:)
        id = Types.identifier(id, "volume id")
        target = secure_path(container_path)
        pod_id = pod_identifier(pod)
        @manager.with_volume_lock(id) do
          record = @manager.fetch_record(id)
          next false if record.state == "Unknown"

          backend = @manager.backends[id]
          next false unless backend.is_a?(RemoteBackend) && backend.requires_republish?

          existing = record.publishes["#{pod_id}\0#{target}"]
          next false unless existing

          node = existing["node"]
          node = nil if node.to_s.empty?
          stage_path = stage_for(record, node)
          context = @manager.context_for_node(record, node || attached_node(record), {})
          backend.republish(stage_path: stage_path, target: target, pod: pod, readonly: existing["readonly"] == true,
                            context: context, token: token)
          true
        end
      end

      def unpublish(id, pod, container_path, token:)
        id = Types.identifier(id, "volume id")
        target = secure_path(container_path)
        pod_id = pod_identifier(pod)
        execute_operation(key: id, operation: "unpublish:#{pod_id}:#{target}", token: token,
                          payload: {"id" => id, "pod" => pod_id, "target" => target}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record, action: "Cleanup")
          key = "#{pod_id}\0#{target}"
          if record.publishes.empty? || !record.publishes.key?(key)
            true
          else
            entry = record.publishes.fetch(key)
            transitional = record.with(state: "Unpublishing", generation: record.generation + 1)
            @manager.volume_store[id] = transitional
            backend = @manager.backends.fetch(id)
            begin
              effective_context = @manager.context_for_node(record, entry["node"], {})
              if backend.is_a?(RemoteBackend)
                backend.unpublish(target: target, identity: entry, context: effective_context,
                                  effect_boundary: effect_boundary)
              else
                backend.unpublish(target: target, identity: entry, context: effective_context)
              end
            rescue StandardError => error
              @manager.mark_unknown(id) if ambiguous_error?(error)
              @manager.volume_store[id] = record unless ambiguous_error?(error)
              raise
            end
            @manager.mount_ledger.remove(identity: mount_identity(entry), expected: entry)
            publishes = Types.deep_copy(transitional.publishes)
            publishes.delete(key)
            attachments = Types.deep_copy(transitional.attachments)
            node_key = entry["node"].to_s
            if attachments[node_key]
              attachments[node_key]["pods"] = Array(attachments[node_key]["pods"]) - [pod_id]
              attachments.delete(node_key) if attachments[node_key]["pods"].empty? && transitional.stages.empty?
            end
            state = publishes.empty? ? "Staged" : "Published"
            @manager.volume_store[id] = transitional.with(state: state, publishes: publishes, attachments: attachments,
                                                           generation: transitional.generation + 1)
            true
          end
        end
      end

      alias node_unpublish unpublish

      def unstage(id, path, token:, node: nil, context: {})
        id = Types.identifier(id, "volume id")
        path = secure_path(path)
        execute_operation(key: id, operation: "unstage:#{path}", token: token,
                          payload: {"id" => id, "path" => path, "node" => node}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record, action: "Cleanup")
          raise ConflictError, "volume #{id} still has published consumers" unless record.publishes.empty?
          if !record.stages.key?(path)
            true
          else
            entry = record.stages.fetch(path)
            transitional = record.with(state: "Unstaged", generation: record.generation + 1)
            @manager.volume_store[id] = transitional
            begin
              backend = @manager.backends.fetch(id)
              effective_context = @manager.context_for_node(record, entry["node"], context)
              if backend.is_a?(RemoteBackend)
                backend.unstage(path: path, identity: entry, context: effective_context,
                                effect_boundary: effect_boundary)
              else
                backend.unstage(path: path, identity: entry, context: effective_context)
              end
            rescue StandardError => error
              @manager.mark_unknown(id) if ambiguous_error?(error)
              @manager.volume_store[id] = record unless ambiguous_error?(error)
              raise
            end
            @manager.mount_ledger.remove(identity: mount_identity(entry), expected: entry)
            stages = Types.deep_copy(transitional.stages)
            stages.delete(path)
            state = transitional.attachments.empty? ? "Detached" : "Attached"
            @manager.volume_store[id] = transitional.with(state: state, stages: stages, generation: transitional.generation + 1)
            true
          end
        end
      end

      alias node_unstage unstage

      def stats(id, path: nil)
        record = @manager.fetch_record(id)
        stats_path = path || (record.stages.empty? ? @manager.backends.fetch(id).source_path : stage_for(record, nil))
        @manager.backends.fetch(id).stats(path: stats_path, capacity_bytes: record.capacity_bytes)
      end

      alias node_get_volume_stats stats

      def recover(observed_mounts: nil, observed_devices: nil)
        @manager.recover(observed_mounts: observed_mounts, observed_devices: observed_devices)
      end

      # {attempted:, errors:} of the startup reconstruction (reconstruct_volume_operations_*).
      def reconstruction_stats
        @manager.respond_to?(:reconstruction_stats) ? @manager.reconstruction_stats : nil
      end

      private

      def collect_cleanup_errors
        result = yield
        return [] if result == true || result == 0

        [CleanupError.new(
          "mount cleanup did not report success (result=#{result.inspect})",
          details: {"cleanupErrors" => [{"class" => CleanupError.name,
                                          "message" => "adapter returned #{result.inspect}"}]},
          cleanup_errors: []
        )]
      rescue StandardError => error
        [error]
      end

      def secure_path(path)
        value = String(path)
        raise PathSecurityError, "volume path must be absolute" unless value.start_with?("/")
        raise PathSecurityError, "volume path contains NUL" if value.include?("\0")
        components = value.split("/")
        raise PathSecurityError, "volume path contains traversal" if components.include?("..") || components.include?(".") || components.drop(1).any?(&:empty?)
        @manager.path_security.validate_target!(value)
        value
      rescue TypeError
        raise PathSecurityError, "volume path must be a string"
      end

      def ensure_attached(record, node)
        return record unless node && record.attachments.key?(node.to_s)
        record
      end

      def attached_node(record)
        record.attachments.keys.first || raise(ConflictError, "volume #{record.id} is not controller-attached")
      end

      def stage_for(record, node)
        return record.stages.values.first["target"] if node.nil? && record.stages.length == 1
        value = record.stages.values.find { |entry| node.nil? || entry["node"].to_s == node.to_s }
        return value["target"] if value
        raise ConflictError, "volume #{record.id} has no stage path on node #{node}"
      end

      def mount_identity(entry)
        ledger = @manager.mount_ledger
        return ledger.identity_for(entry) if ledger.respond_to?(:identity_for)

        %w[mountId filesystemUuid deviceId target].map { |field| entry[field].to_s }.join("/")
      end

      def pod_identifier(pod)
        return Types.identifier(pod, "pod") unless pod.respond_to?(:to_h)
        metadata = Types.key(pod.to_h, "metadata", {})
        Types.identifier(Types.key(metadata, "uid", Types.key(metadata, "name", "pod")), "pod")
      end

      # PodSecurityContext.fsGroupChangePolicy: "Always" (the default) or
      # "OnRootMismatch", which skips the ownership walk when the volume root
      # already carries the desired group.
      def fs_group_change_policy(pod)
        return nil unless pod.respond_to?(:to_h) || pod.is_a?(Hash)

        value = Types.key(Types.key(Types.key(pod.respond_to?(:to_h) ? pod.to_h : pod, "spec", {}),
                                    "securityContext", {}), "fsGroupChangePolicy", nil)
        value&.to_s
      end

      def apply_security!(backend, stage_path:, pod:, readonly:, fs_group:, selinux_label:, mount_propagation:, context:)
        adapter = @manager.mount_adapter
        if fs_group && adapter.respond_to?(:apply_fs_group)
          AdapterSupport.call(adapter, :apply_fs_group, path: stage_path, fs_group: fs_group, pod: pod,
                              readonly: readonly, change_policy: fs_group_change_policy(pod))
        elsif fs_group && !adapter.respond_to?(:apply_fs_group)
          raise SecurityError, "fsGroup was requested but no injected adapter can apply it"
        end
        if selinux_label && adapter.respond_to?(:apply_selinux_label)
          AdapterSupport.call(adapter, :apply_selinux_label, path: stage_path, label: selinux_label)
        elsif selinux_label
          raise SecurityError, "SELinux label was requested but no injected adapter can apply it"
        end
        if mount_propagation && adapter.respond_to?(:apply_mount_propagation)
          AdapterSupport.call(adapter, :apply_mount_propagation, path: stage_path, propagation: mount_propagation)
        elsif mount_propagation
          raise SecurityError, "mountPropagation was requested but no injected adapter can apply it"
        end
        if backend.readonly? && !readonly
          raise SecurityError, "read-only volume cannot be published writable"
        end
        true
      end
    end

    class Manager
      CSI_RECOVERY_PAGE_LIMIT = 10_000

      attr_reader :volume_store, :backends, :operations, :mount_ledger, :controller, :node,
                  :binder, :snapshot_manager, :adapter, :mount_adapter, :device_adapter,
                  :path_security, :data_dir, :require_real_readback

      def initialize(data_dir: nil, root: nil, adapter: nil, mount_adapter: nil, path_security: nil,
                     resolver: nil, store: nil, operation_ledger: nil, mount_ledger: nil, csi: nil,
                     binder: nil, snapshot_store: nil, clock: -> { Time.now.utc }, fsync: false,
                     identity: nil, capabilities: nil, device_adapter: nil, require_real_readback: false,
                     secret_resolver: nil, token_provider: nil)
        @data_dir = File.expand_path((data_dir || root || File.join(Dir.tmpdir, "rubernetes-volumes")).to_s)
        @root = File.expand_path((root || File.join(@data_dir, "volumes")).to_s)
        FileUtils.mkdir_p(@root)
        if require_real_readback == true && mount_adapter.nil? && adapter.nil?
          raise MountIdentityError, "real mount readback requires an explicitly injected mount adapter"
        end
        if require_real_readback == true && [mount_adapter, adapter].compact.any? { |candidate| candidate.is_a?(FilesystemAdapter) }
          raise MountIdentityError, "real mount readback cannot use the in-memory FilesystemAdapter"
        end

        @token_provider = token_provider
        @mount_adapter = mount_adapter || adapter || FilesystemAdapter.new(root: @root, fsync: fsync)
        @adapter = adapter || @mount_adapter
        @device_adapter = device_adapter || @adapter
        native_mount_adapter = defined?(NativeMountAdapter) && @mount_adapter.is_a?(NativeMountAdapter)
        @require_real_readback = require_real_readback == true || native_mount_adapter
        @default_path_security = path_security.nil? && resolver.nil?
        @path_security = path_security || if resolver
                                           PathSecurity.new(root: @root, resolver: resolver)
                                         elsif csi
                                           # Public Manager construction is a
                                           # supported CSI entry point. Keep it
                                           # descriptor-safe just like the
                                           # production Assembler instead of
                                           # silently dispatching raw paths.
                                           openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
                                           PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
                                         else
                                           PathSecurity.new(root: "/", require_openat2: true)
                                         end
        @volume_store = store || VolumeStore.new(path: File.join(@data_dir, "volumes.json"), fsync: fsync)
        # What the durable state gave back at startup (kubelet's volume
        # reconstruction): records with mounts or attachments, and the ones
        # whose backend is unknown.
        restored = @volume_store.values
        @reconstruction_stats = {
          attempted: restored.count { |record| !record.publishes.to_h.empty? || !record.attachments.to_h.empty? },
          errors: restored.count { |record| record.state.to_s == "Unknown" }
        }.freeze
        @operations = operation_ledger || OperationLedger.new(path: File.join(@data_dir, "operations.json"), fsync: fsync, clock: clock)
        @mount_ledger = mount_ledger || MountIdentityLedger.new(path: File.join(@data_dir, "mounts.json"), fsync: fsync)
        if @mount_ledger.respond_to?(:live_check=) && @mount_ledger.live_check.nil? && @mount_adapter.respond_to?(:find_mount)
          @mount_ledger.live_check = lambda do |mount|
            observed = @mount_adapter.find_mount(mount.target)
            !observed.nil? && observed.fetch("mountId").to_s == mount.mount_id.to_s
          end
        end
        @backends = {}
        @volume_lock = Monitor.new
        @csi = csi
        @secret_resolver = secret_resolver
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
        @snapshot_manager = SnapshotManager.new(backend_lookup: method(:backend_for), record_lookup: method(:fetch_record),
                                                create_volume: method(:create_volume), restore_volume: method(:restore_snapshot_volume),
                                                clone_volume: method(:clone_volume), store: @snapshot_store, csi: csi, clock: clock,
                                                error_sanitizer: method(:persistence_error))
        @controller = Controller.new(self)
        @node = Node.new(self)
        recover_backends_from_store!
      end


      attr_reader :reconstruction_stats
      def identity
        @identity_value.is_a?(Identity) ? @identity_value : Identity.new(**@identity_value.to_h.transform_keys(&:to_sym))
      end

      # One lock per volume, not one for the node.  Every volume operation
      # persists three ledgers with fsync, and behind a single node-wide lock a
      # 100-Pod ReplicationController's kube-api-access volumes queued for
      # minutes (volume.ready median 65 s late in a round).  The ledgers and
      # the volume store synchronize themselves; the lock only orders the
      # operations of ONE volume.
      def with_volume_lock(key)
        lock = @volume_lock.synchronize { (@volume_locks ||= {})[key.to_s] ||= Monitor.new }
        lock.synchronize { yield }
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

      def mark_unknown(id, operation: nil, payload: nil, details: nil)
        record = volume_store[id.to_s]
        return nil unless record
        if record.state == "Unknown"
          return record unless operation && !Types.present?(Types.key(record.operation || {}, "name"))

          updated = record.with(operation: Types.deep_copy(record.operation || {}).merge(
            "name" => operation, "payload" => operation_payload(payload || {}),
            "details" => sanitize_for_persistence(details)
          ))
          volume_store[id] = updated
          return updated
        end

        updated = record.with(state: "Unknown", generation: record.generation + 1,
                              operation: {
                                "status" => "unknown", "reason" => "effect response was ambiguous",
                                "name" => operation, "payload" => operation_payload(payload || {}),
                                "previousState" => record.state,
                                "details" => sanitize_for_persistence(details)
                              })
        volume_store[id] = updated
        updated
      end

      def ensure_attach_policy!(record, node:, pod: nil)
        @controller.ensure_attach_policy(record, node: node, pod: pod)
      end

      # Build the complete CSI node context from durable CreateVolume and
      # per-node ControllerPublish results.  Node calls must not depend on a
      # caller replaying an ephemeral publishContext after restart.
      def context_for_node(record, node, context = {})
        spec = record.spec
        backend_result = Types.key(spec, "backendResult", {})
        volume_context = Types.key(spec, "volumeContext", {}).to_h.merge(
          Types.key(backend_result, "volumeContext", Types.key(backend_result, "volume_context", {})).to_h
        )
        attachment = record.attachments[node.to_s] || record.attachments[node] || {}
        Types.deep_copy(context).merge(
          "volumeContext" => volume_context,
          "publishContext" => Types.deep_copy(Types.key(attachment, "publishContext", {})),
          "secrets" => Types.deep_copy(Types.key(spec, "secrets", {})),
          "accessModes" => Array(Types.key(spec, "accessModes", ["ReadWriteOnce"])),
          "volumeMode" => Types.key(spec, "volumeMode", "Filesystem").to_s,
          "volumeCapability" => Types.deep_copy(Types.key(spec, "volumeCapability", {})),
          "node" => node.to_s
        )
      end

      def capabilities
        Types.deep_copy(@capabilities_value)
      end

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

      def stage(id, path, token:, **options)
        node.stage(id, path, token: token, **options)
      end

      def node_publish(id, pod, container_path, readonly:, token:, **options)
        node.publish(id, pod, container_path, readonly: readonly, token: token, **options)
      end

      def direct_path(id, pod:, fs_group: nil)
        node.direct_path(id, pod: pod, fs_group: fs_group)
      end

      def node_unpublish(id, pod, container_path, token:)
        node.unpublish(id, pod, container_path, token: token)
      end

      # The summary API's stats for a kubelet CSI volume published at +path+
      # (see RemoteBackend#kubelet_volume_stats).
      def csi_volume_stats(id, path)
        backend = backends[id.to_s]
        return nil unless backend.is_a?(RemoteBackend)

        backend.kubelet_volume_stats(path)
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

      def unstage(id, path, token:, **options)
        node.unstage(id, path, token: token, **options)
      end

      def stats(id, path: nil)
        node.stats(id, path: path)
      end

      def volume(id)
        fetch_record(id)
      end

      def list_volumes
        volume_store.values
      end

      def attach(id, node_name, token:)
        controller.publish(id, node_name, token: token)
      end

      def detach(id, node_name, token:)
        controller.unpublish(id, node_name, token: token)
      end

      def list_snapshots
        snapshot_manager.list
      end

      def expansion_paths(record)
        stages = record.stages.values.map { |entry| Types.key(entry, "target") }
        publishes = record.publishes.values.map { |entry| Types.key(entry, "target") }
        (stages + publishes).select { |path| Types.present?(path) }.map { |path| File.expand_path(path.to_s) }.uniq
      end

      def node_expansion_required?(record)
        backend_result = Types.key(record.spec, "backendResult", {})
        Types.key(backend_result, "nodeExpansionRequired", false) == true
      end

      def record_expansion_result(record, expansion)
        result = sanitize_for_persistence(AdapterSupport.result_hash(expansion))
        required = Types.key(result, "nodeExpansionRequired", false) == true
        expanded = Array(Types.key(result, "nodeExpandedPaths", []))
        backend_result = Types.deep_copy(Types.key(record.spec, "backendResult", {})).merge(result)
        backend_result["nodeExpansionRequired"] = required && expanded.empty?
        record.with(spec: record.spec.merge("backendResult" => backend_result))
      end

      def record_node_expanded(record, path)
        backend_result = Types.deep_copy(Types.key(record.spec, "backendResult", {}))
        paths = Array(Types.key(backend_result, "nodeExpandedPaths", [])) | [File.expand_path(path.to_s)]
        backend_result["nodeExpandedPaths"] = paths
        backend_result["nodeExpansionRequired"] = false
        record.with(spec: record.spec.merge("backendResult" => backend_result))
      end

      # Preserve the primary lifecycle error while making failed compensation
      # durable and explicitly ambiguous. Recovery must reconcile both the
      # original effect and every cleanup failure before allowing reuse.
      def with_cleanup_errors(error, cleanup_errors)
        failures = Array(cleanup_errors).compact
        return error if failures.empty?

        details = {
          "primaryError" => {"class" => error.class.name, "message" => error.message.to_s},
          "cleanupErrors" => failures.map do |failure|
            child = failure.respond_to?(:to_h) ? failure.to_h : nil
            {
              "class" => failure.class.name,
              "message" => failure.message.to_s,
              "details" => if failure.respond_to?(:details)
                             sanitize_for_persistence(failure.details)
                           else
                             child && child["details"]
                           end
            }.compact
          end
        }
        CleanupError.new(
          "#{error.message}; cleanup failed: #{failures.map(&:message).join("; ")}",
          operation: error.respond_to?(:operation) ? error.operation : nil,
          resource_id: error.respond_to?(:resource_id) ? error.resource_id : nil,
          details: details,
          cleanup_errors: failures
        )
      end

      # Persisted operation payloads are reconciliation hints, never a secret
      # transport. The original fingerprint still detects token misuse while
      # this redacted copy remains safe for disk and diagnostic collection.
      def operation_payload(payload)
        sanitize_for_persistence(payload || {})
      end

      def persistence_error(error)
        message = redact_secret_text(error.message.to_s)
        details = error.respond_to?(:details) ? sanitize_for_persistence(error.details) : nil
        return error if message == error.message.to_s && (!error.respond_to?(:details) || details == error.details)

        replacement = if error.is_a?(CSIError)
                        CSIError.new(message, ambiguous: error.ambiguous?, operation: error.operation,
                                    resource_id: error.resource_id, details: details)
                      elsif error.is_a?(Error)
                        error.class.new(message, operation: error.operation, resource_id: error.resource_id,
                                        details: details)
                      else
                        Error.new(message, details: details)
                      end
        replacement.set_backtrace(error.backtrace)
        replacement
      end

      def redact_secret_text(value)
        @secret_redactions.each_with_object(value.to_s.dup) do |secret, text|
          text.gsub!(secret, "[REDACTED]") unless secret.empty?
        end
      end

      def sanitize_for_persistence(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, child), result|
            text = key.to_s
            next if %w[secrets stringData token tokenRotator].include?(text) && !text.end_with?("Ref", "Reference")

            result[redact_secret_text(text)] = sanitize_for_persistence(child)
          end
        when Array
          value.map { |child| sanitize_for_persistence(child) }
        when String
          redact_secret_text(value)
        else
          Types.deep_copy(value)
        end
      end

      def remember_csi_secrets(id, spec)
        return true unless Types.key(spec, "backend").to_s.casecmp?("csi")

        secrets = Types.key(spec, "secrets")
        return true unless secrets
        raise ValidationError, "CSI secrets must be a map" unless secrets.respond_to?(:to_h)

        @volatile_csi_secrets[id.to_s] = secrets.to_h.each_with_object({}) do |(key, value), result|
          result[String(key)] = String(value)
        rescue TypeError
          raise ValidationError, "CSI secret keys and values must be strings"
        end.freeze
        @secret_redactions |= @volatile_csi_secrets.fetch(id.to_s).values
        true
      end

      def resolve_csi_content_sources(spec)
        copy = Types.deep_copy(spec)
        return copy unless Types.key(copy, "backend").to_s.casecmp?("csi")

        source_id = Types.key(copy, "cloneSourceId")
        return copy unless Types.present?(source_id) && volume_store[source_id.to_s]

        source = volume_store.fetch(source_id.to_s)
        driver_id = csi_driver_id(source)
        raise StateUnknownError, "CSI clone source #{source_id} has no durable driver volume id mapping" unless Types.present?(driver_id)

        copy["cloneSourceId"] = driver_id
        copy
      end

      def forget_csi_secrets(id)
        @volatile_csi_secrets.delete(id.to_s)
        true
      end

      def update_projection(id, data:, token:, binary_data: {}, sources: nil)
        run_manager_operation(id, "projection-update", token, {"data" => data, "binaryData" => binary_data, "sources" => sources}) do
          backend = backends.fetch(id.to_s)
          if sources && backend.respond_to?(:update)
            backend.update(sources: sources)
          elsif backend.respond_to?(:update)
            backend.update(data: data, binary_data: binary_data)
          else
            raise UnsupportedError, "volume #{id} does not support projection updates"
          end
        end
      end

      def rotate_token(id, now: @clock.call, token:)
        run_manager_operation(id, "token-rotate:#{token}", token, {"now" => now.to_s}) do
          backend = backends.fetch(id.to_s)
          raise UnsupportedError, "volume #{id} does not expose token rotation" unless backend.respond_to?(:rotate_token)
          backend.rotate_token(now: now)
        end
      end

      def restore_snapshot_volume(spec, snapshot:, token:)
        expected_digests = Types.key(snapshot.metadata, "contentSha256")
        # Integrity is checked before any volume exists so a corrupted
        # catalog never yields a half-restored, Provisioned volume.
        Backend.verify_content_integrity!(snapshot.content, expected_digests, volume_id: snapshot.id)
        id = create_volume(spec, token: token)
        backend = backends.fetch(id)
        # CSI restore is performed by CreateVolume(volume_content_source).  A
        # second generic restore would write local files beside a remote
        # volume and could report success without restoring the CSI object.
        return id if backend.is_a?(RemoteBackend)

        # The volume exists durably before its bytes do.  Fence it as Unknown
        # with a named restore operation until every file is written and
        # re-verified, so a crash mid-restore leaves a record that refuses
        # attach/publish instead of a Provisioned volume with partial content.
        record = fetch_record(id)
        volume_store[id] = record.with(state: "Unknown", generation: record.generation + 1,
                                       operation: {"status" => "restoring", "name" => "restore",
                                                   "payload" => {"snapshotId" => snapshot.id},
                                                   "previousState" => record.state,
                                                   "reason" => "snapshot content is being written"})
        restored = backend.restore(content: snapshot.content, content_sha256: expected_digests)
        written = backend.respond_to?(:snapshot) ? AdapterSupport.result_hash(backend.snapshot)["content"] : nil
        Backend.verify_content_integrity!(written, expected_digests, volume_id: id) unless written.nil?
        record = fetch_record(id)
        durable_spec = record.spec.merge(
          "backendResult" => Types.key(record.spec, "backendResult", {}).to_h.merge(
            "restoredFrom" => snapshot.id, "contentDigest" => AdapterSupport.result_hash(restored)["contentDigest"]
          )
        )
        volume_store[id] = record.with(state: "Provisioned", spec: durable_spec, operation: nil,
                                       generation: record.generation + 1)
        id
      rescue StandardError => error
        if id
          begin
            # An in-process failure is deterministic: unfence before the
            # compensating delete so it is not refused as Unknown.
            if (fenced = volume_store[id]) && fenced.state == "Unknown" &&
               Types.key(fenced.operation || {}, "name") == "restore"
              volume_store[id] = fenced.with(state: "Provisioned", operation: nil, generation: fenced.generation + 1)
            end
            delete_volume(id, token: "restore-compensate-#{token}")
          rescue StandardError => cleanup_error
            mark_unknown(id)
            safe_cleanup = persistence_error(cleanup_error)
            error = OperationUnknown.new(
              "snapshot restore cleanup is ambiguous for #{id}: #{safe_cleanup.message}"
            )
          end
        end
        sanitized = persistence_error(error)
        raise sanitized, cause: nil
      end

      def clone_volume(source_id:, spec:, token:)
        source = backends.fetch(source_id.to_s)
        id = create_volume(spec, token: token)
        destination = backends.fetch(id)
        # CSI clone is encoded in CreateVolume's content source.  Do not run
        # the local Backend#clone_from path for a remote destination.
        return id if destination.is_a?(RemoteBackend)

        destination.clone_from(source_backend: source)
        id
      rescue StandardError => error
        if id
          begin
            delete_volume(id, token: "clone-compensate-#{token}")
          rescue StandardError => cleanup_error
            mark_unknown(id)
            error = OperationUnknown.new("volume clone cleanup is ambiguous for #{id}: #{cleanup_error.message}")
          end
        end
        raise error
      end

      def recover(observed_mounts: nil, observed_devices: nil)
        observations = observed_mounts || (mount_adapter.respond_to?(:list_mounts) ? mount_adapter.list_mounts : [])
        reconciliation = mount_ledger.reconcile(observations)
        errors = []
        redaction_ready, redaction_errors = prime_csi_secret_redactions!
        errors.concat(redaction_errors)
        actions = []
        operations.pending_entries.each do |entry|
          operations.unknown!(key: entry.key, operation: entry.operation, token: entry.token,
                              error: OperationUnknown.new("operation was pending when the node restarted"))
          mark_unknown(entry.key, operation: entry.operation, payload: entry.payload) if volume_store[entry.key]
        end
        operations.unknown_entries.each do |entry|
          mark_unknown(entry.key, operation: entry.operation, payload: entry.payload) if volume_store[entry.key]
        end
        if observed_devices || device_adapter.respond_to?(:list_devices) || mount_adapter.respond_to?(:list_devices)
          device_source = device_adapter.respond_to?(:list_devices) ? device_adapter : mount_adapter
          devices = observed_devices || device_source.list_devices
          actions << {"kind" => "device-observe", "count" => Array(devices).length}
        end
        csi_volume_entries = nil
        if redaction_ready && @csi && @csi.respond_to?(:list_volumes)
          begin
            csi_volumes = list_csi_volumes
            csi_volume_entries = Array(AdapterSupport.result_hash(csi_volumes)["entries"] ||
                                       AdapterSupport.result_hash(csi_volumes)["volumes"] || csi_volumes)
            actions << {"kind" => "csi-list-volumes", "count" => csi_volume_entries.length}
          rescue StandardError => error
            errors << {"kind" => "csi-list-volumes", "error" => redact_secret_text(error.message.to_s)}
          end
        end
        snapshot_entries = nil
        if @snapshot_manager
          if redaction_ready
            begin
              snapshot_entries = list_csi_snapshots if @csi && @csi.respond_to?(:list_snapshots)
              snapshot_report = @snapshot_manager.reconcile(entries: snapshot_entries)
              actions << {"kind" => "snapshot-reconcile", "unknown" => Array(snapshot_report["unknown"]).length,
                          "observed" => Array(snapshot_report["observed"]).length,
                          "resolved" => Array(snapshot_report["resolved"]).length}
            rescue StandardError => error
              snapshot_report = @snapshot_manager.reconcile(error: error)
              errors << {"kind" => "snapshot-reconcile", "error" => redact_secret_text(error.message.to_s)}
              actions << {"kind" => "snapshot-reconcile", "unknown" => Array(snapshot_report["unknown"]).length,
                          "observed" => 0}
            end
          else
            snapshot_report = @snapshot_manager.reconcile(
              error: CSIUnavailable.new("CSI recovery secret redaction preflight failed")
            )
            actions << {"kind" => "snapshot-reconcile", "unknown" => Array(snapshot_report["unknown"]).length,
                        "observed" => 0}
          end
        end
        resolved = reconcile_unknown_operations(csi_volume_entries: csi_volume_entries,
                                                snapshot_entries: snapshot_entries,
                                                observations: observations, errors: errors)
        actions << {"kind" => "operation-resolve", "count" => resolved.length} unless resolved.empty?
        reconciled_missing = reconcile_missing_mounts(reconciliation["missing"], errors: errors)
        unless reconciled_missing.empty?
          actions << {"kind" => "missing-mount-reconcile", "count" => reconciled_missing.length,
                      "entries" => reconciled_missing}
        end
        unknown = operations.unknown_entries.map(&:to_h)
        snapshot_manager.list.each do |snapshot|
          next unless Types.key(snapshot.metadata, "state") == "Unknown"

          unknown << {"kind" => "snapshot", "id" => snapshot.id, "state" => "Unknown"}
        end
        actions << {"kind" => "observe", "count" => unknown.length} unless unknown.empty?
        RecoveryReport.new(owned: reconciliation["owned"], orphans: reconciliation["orphans"], missing: reconciliation["missing"],
                           identity_mismatches: reconciliation["identityMismatches"], unknown: unknown,
                           actions: actions, errors: errors)
      end

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

      def bind(pvc, **options)
        binder.bind(pvc, **options)
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

      def restore(snapshot_id, spec: {}, token:)
        snapshot_manager.restore(snapshot_id, spec: spec, token: token)
      end

      def clone(id, spec: {}, token:)
        snapshot_manager.clone(id, spec: spec, token: token)
      end

      def backend_for(id)
        return backends[id.to_s] if backends.key?(id.to_s)

        record = fetch_record(id)
        ensure_known!(record)
        begin
          backend = build_backend(id.to_s, record.spec)
          backends[id.to_s] = backend
          backend
        rescue StandardError => error
          mark_unknown(id)
          raise StateUnknownError,
                "volume #{id} backend reconstruction failed; recover before mutation: #{redact_secret_text(error.message.to_s)}"
        end
      end

      def fetch_record(id)
        volume_store.fetch(id) { raise NotFoundError, "volume #{id} does not exist" }
      end

      def volume_id_for(spec)
        supplied = Types.key(spec, "id", Types.key(spec, "volumeId"))
        return Types.identifier(supplied, "volume id") if supplied
        name = Types.key(spec, "name") || Types.key(Types.key(spec, "metadata", {}), "name")
        digest = Types.digest(spec)
        name && !name.to_s.empty? ? "vol-#{name}-#{digest[0, 16]}" : "vol-#{digest[0, 24]}"
      end

      def normalize_spec(value)
        hash = value.respond_to?(:to_h) ? Types.deep_copy(value.to_h) : {}
        raise ValidationError, "volume spec must be a map" unless value.respond_to?(:to_h)
        backend = detect_backend(hash)
        if csi_source_present?(hash) && backend && !backend.to_s.casecmp?("csi")
          raise ValidationError, "CSI volume source cannot be combined with backend #{backend.inspect}"
        end
        if backend
          nested = Types.key(hash, backend, {})
          if nested.respond_to?(:to_h) && !nested.is_a?(String)
            hash = nested.to_h.merge(hash.reject { |key, _| key.to_s.casecmp?(backend.to_s) })
          end
        end
        hash["backend"] = backend || Types.key(hash, "backend", "emptyDir").to_s
        hash["capacityBytes"] = Types.parse_capacity(Types.key(hash, "capacityBytes", Types.key(hash, "capacity", 1)))
        if Types.key(hash, "accessModes")
          hash["accessModes"] = Types.normalize_access_modes(Types.key(hash, "accessModes"))
        end
        hash
      end

      def persisted_spec(spec)
        copy = Types.deep_copy(spec)
        backend = Types.key(copy, "backend", "").to_s
        if backend.casecmp?("csi")
          had_secrets = Types.present?(Types.key(copy, "secrets"))
          copy = sanitize_for_persistence(copy)
          copy["csiSecrets"] = {"redacted" => true, "resolverRequiredAfterRestart" => true} if had_secrets
          return copy
        end
        secret = backend.casecmp?("secret") ||
                 (backend.casecmp?("projected") && secret_projection_present?(Types.key(copy, "sources", [])))
        return copy unless secret

        copy = redact_projected_secret_payload(copy, secret_context: backend.casecmp?("secret"))
        copy["secretProjection"] = {"redacted" => true}
        copy
      end

      SECRET_PROJECTION_SOURCE_KEYS = %w[secret serviceAccountToken service_account_token].freeze
      SECRET_PROJECTION_PAYLOAD_KEYS = %w[data binaryData binary_data stringData string_data token tokenRotator token_rotator].freeze

      def secret_projection_present?(value)
        case value
        when Hash
          value.any? do |key, child|
            SECRET_PROJECTION_SOURCE_KEYS.include?(key.to_s) || secret_projection_present?(child)
          end
        when Array
          value.any? { |child| secret_projection_present?(child) }
        else
          false
        end
      end

      def redact_projected_secret_payload(value, secret_context: false)
        case value
        when Hash
          value.each_with_object({}) do |(key, child), result|
            text = key.to_s
            nested_secret = secret_context || SECRET_PROJECTION_SOURCE_KEYS.include?(text)
            next if nested_secret && SECRET_PROJECTION_PAYLOAD_KEYS.include?(text)

            result[Types.deep_copy(key)] = redact_projected_secret_payload(child, secret_context: nested_secret)
          end
        when Array
          value.map { |child| redact_projected_secret_payload(child, secret_context: secret_context) }
        else
          Types.deep_copy(value)
        end
      end

      def record_backend_mount(id, provisioned)
        identity = provisioned && (provisioned["mountIdentity"] || provisioned[:mount_identity])
        return true unless identity
        hash = identity.respond_to?(:to_h) ? identity.to_h : identity
        register_mount_identity(
          volume_id: id,
          identity: hash,
          target: hash["target"] || hash[:target] || provisioned["source"],
          owner: "volume:#{id}",
          stage_path: provisioned["source"],
          generation: nil,
          secret: provisioned["backend"].to_s == "secret"
        )
      end

      # The kubelet's CSI plugin registry, used when no single CSI adapter
      # was configured.
      def csi_registry=(registry)
        return if @csi || registry.nil?

        @csi = registry
        # As at construction with csi:, CSI dispatch needs descriptor-safe
        # targets.
        if @default_path_security
          openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
          @path_security = PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
        end
        recover_unconfigured_csi_backends!
      end

      # Volumes whose backend could not be rebuilt only because no CSI
      # adapter existed at recovery get their backend and state back.
      def recover_unconfigured_csi_backends!
        volume_store.values.each do |record|
          operation = record.operation || {}
          next unless record.state == "Unknown" && Types.key(operation, "csiUnconfigured", false) == true

          with_volume_lock(record.id) do
            @backends[record.id] = build_backend(record.id, record.spec)
            previous = Types.key(operation, "previousState", "").to_s
            volume_store[record.id] = record.with(state: previous.empty? ? "Unknown" : previous, operation: nil,
                                                  generation: record.generation + 1)
          end
        rescue StandardError
          next
        end
      end

      def build_backend(id, spec)
        backend_name = Types.key(spec, "backend", "emptyDir").to_s
        if backend_name.casecmp?("csi")
          csi = @csi || csi_adapter_from_spec(spec)
          # A kubelet plugin registry resolves the node plugin registered
          # under the volume's driver name.
          registered = csi.respond_to?(:for_driver)
          csi = RegisteredCSIDriver.new(csi, Types.key(spec, "driver").to_s) if registered
          unless csi && csi.respond_to?(:create_volume)
            raise CSIUnavailable, "CSI adapter is not configured; initialize Manager with csi:"
          end
          # A registered plugin is looked up by the driver name itself.
          validate_csi_driver!(spec, csi) unless registered

          return RemoteBackend.new(id: id, spec: spec, adapter: @adapter, root: @root, path_security: @path_security,
                                   mount_adapter: @mount_adapter, device_adapter: @device_adapter,
                                   # A native node agent must independently
                                   # observe CSI effects in its own mount
                                   # namespace.  Test-profile adapters remain
                                   # explicitly non-native and may use their
                                   # injected lifecycle identities.
                                   require_real_readback: @require_real_readback, csi: csi,
                                   secret_provider: ->(purpose) { resolve_csi_secrets(id, spec, purpose: purpose) },
                                   persistence_sanitizer: method(:sanitize_for_persistence),
                                   error_sanitizer: method(:persistence_error))
        end
        klass = BUILTIN_BACKENDS[backend_name] || BUILTIN_BACKENDS[backend_name.downcase] || raise(UnsupportedError, "unsupported volume backend #{backend_name.inspect}")
        klass.new(id: id, spec: spec, adapter: @adapter, root: @root, path_security: @path_security,
                  mount_adapter: @mount_adapter, device_adapter: @device_adapter,
                  require_real_readback: @require_real_readback)
      end

      # Forgets any recorded mount at `target`.  The caller has established
      # that nothing is mounted there any more (an attempt that died left the
      # path behind); the record would otherwise block the next mount.
      def forget_mount_target(target)
        @mount_ledger.respond_to?(:remove_target) ? @mount_ledger.remove_target(target) : 0
      end

      # Keep the manager compatible with both the current ledger and the
      # stricter identity ledger used by native profiles. Optional identity
      # fields are passed only when the ledger advertises their keyword.
      def register_mount_identity(volume_id:, identity:, target:, owner:, stage_path:, generation:, secret:)
        hash = identity.respond_to?(:to_h) ? identity.to_h : identity
        arguments = {
          volume_id: volume_id,
          source: hash["source"] || hash[:source],
          target: target,
          mount_id: hash["mountId"] || hash[:mount_id],
          filesystem_uuid: hash.key?("filesystemUuid") ? hash["filesystemUuid"] : hash[:filesystem_uuid],
          device_id: hash["deviceId"] || hash[:device_id],
          owner: owner,
          stage_path: stage_path,
          generation: generation,
          secret: secret
        }
        keyword_names = @mount_ledger.method(:register).parameters.filter_map do |kind, name|
          name if %i[key keyreq].include?(kind)
        end
        bind = hash.key?("bind") ? hash["bind"] == true : hash[:bind] == true
        optional = {
          root: hash["root"] || hash[:root],
          source_identity: hash["sourceIdentity"] || hash[:source_identity] || hash["source"] || hash[:source],
          filesystem_uuid_available: hash.key?("filesystemUuidAvailable") ? hash["filesystemUuidAvailable"] : hash[:filesystem_uuid_available],
          filesystem: hash["filesystem"] || hash[:filesystem] || hash["fsType"] || hash[:fs_type],
          # A bind mount rides on another superblock; the ledger must not
          # treat its device as a second attachment of that block device.
          bind: bind
        }
        optional.each { |key, value| arguments[key] = value if keyword_names.include?(key) }
        @mount_ledger.register(**arguments)
      end

      attr_reader :root

      # The rotator that mints and refreshes a projected ServiceAccount token
      # for one Pod (TokenRequest through the node's API client); nil when
      # the manager has no token provider, in which case a projected
      # serviceAccountToken source cannot be served.
      def token_rotator_for(pod)
        return nil unless @token_provider

        provider = @token_provider.respond_to?(:for_pod) ? @token_provider.for_pod(pod.to_h) : @token_provider
        Projection::TokenRotator.new(provider: provider, clock: @clock)
      end

      private

      # Durable mount claims that the kernel no longer backs (the node came back
      # in a fresh mount namespace, or the mounts were torn down with it) are
      # retracted from the volume record so the lifecycle can be re-driven
      # from kernel truth: a publish/stage entry without a kernel mount is
      # dropped together with its ledger row, and a backend whose provisioned
      # source mount is gone may re-establish it (emptyDir Memory tmpfs).
      # Records fenced as Unknown are left for operation resolution.
      def reconcile_missing_mounts(missing, errors:)
        outcomes = []
        entries = Array(missing).map { |entry| entry.respond_to?(:to_h) ? entry.to_h.transform_keys(&:to_s) : entry }
        entries = entries.select { |entry| entry.is_a?(Hash) }
        # Publishes ride on stages, stages on the source: retract in that order.
        rank = ->(entry) { entry["owner"].to_s.start_with?("pod:") ? 0 : (entry["stagePath"].to_s == entry["target"].to_s ? 2 : 1) }
        entries.sort_by { |entry| rank.call(entry) }.each do |entry|
          volume_id = entry["volumeId"].to_s
          record = volume_store[volume_id]
          next unless record
          next if record.state == "Unknown"

          target = File.expand_path(entry["target"].to_s)
          outcome = retract_missing_mount(record, entry, target)
          outcomes << {"volumeId" => volume_id, "target" => target, "owner" => entry["owner"], "outcome" => outcome} if outcome
        rescue StandardError => error
          errors << {"kind" => "missing-mount-reconcile", "volumeId" => entry["volumeId"], "target" => entry["target"],
                     "error" => redact_secret_text(error.message.to_s)}
        end
        outcomes
      end

      def retract_missing_mount(record, entry, target)
        id = record.id
        publish_key, publish_entry = record.publishes.find { |_key, value| File.expand_path(value["target"].to_s) == target }
        if publish_key
          mount_ledger.remove(identity: entry)
          publishes = Types.deep_copy(record.publishes)
          publishes.delete(publish_key)
          attachments = Types.deep_copy(record.attachments)
          pod_id = publish_entry["pod"].to_s
          node_key = publish_entry["node"].to_s
          if attachments[node_key]
            attachments[node_key]["pods"] = Array(attachments[node_key]["pods"]) - [pod_id]
          end
          state = publishes.empty? ? "Staged" : "Published"
          volume_store[id] = record.with(state: state, publishes: publishes, attachments: attachments,
                                         generation: record.generation + 1)
          operations.retract!(key: id, operation: "publish:#{pod_id}:#{target}")
          return "publish-retracted"
        end
        if record.stages.key?(target)
          mount_ledger.remove(identity: entry)
          stages = Types.deep_copy(record.stages)
          stages.delete(target)
          state = if !record.publishes.empty?
                    record.state
                  elsif stages.empty?
                    record.attachments.empty? ? "Detached" : "Attached"
                  else
                    "Staged"
                  end
          volume_store[id] = record.with(state: state, stages: stages, generation: record.generation + 1)
          operations.retract!(key: id, operation: "stage:#{target}")
          return "stage-retracted"
        end
        backend = backends[id]
        source = backend.respond_to?(:source_path) ? File.expand_path(backend.source_path.to_s) : nil
        return nil unless backend && source == target && backend.respond_to?(:restore_source_mount!)

        restored = backend.restore_source_mount!
        return nil unless restored

        mount_ledger.remove(identity: entry)
        identity = sanitize_for_persistence(restored.respond_to?(:to_h) ? restored.to_h : restored)
        backend_result = Types.deep_copy(Types.key(record.spec, "backendResult", {}))
        backend_result["mountIdentity"] = identity
        record_backend_mount(id, backend_result)
        volume_store[id] = record.with(spec: record.spec.merge("backendResult" => backend_result),
                                       generation: record.generation + 1)
        "source-mount-restored"
      end

      def reconcile_unknown_operations(csi_volume_entries:, snapshot_entries:, observations:, errors:)
        volumes = index_csi_entries(csi_volume_entries, "volumeId")
        snapshots = index_csi_entries(
          snapshot_entries && AdapterSupport.result_hash(snapshot_entries)["entries"], "snapshotId"
        )
        mounts = Array(observations).each_with_object({}) do |entry, result|
          hash = entry.respond_to?(:to_h) ? entry.to_h.transform_keys(&:to_s) : entry
          target = hash && (hash["target"] || hash["mountpoint"])
          result[File.expand_path(target.to_s)] = hash if Types.present?(target)
        end
        resolved = []
        operations.unknown_entries.each do |entry|
          outcome = resolve_unknown_operation(entry, volumes: volumes, snapshots: snapshots, mounts: mounts,
                                               csi_observed: !csi_volume_entries.nil?,
                                               snapshots_observed: !snapshot_entries.nil?)
          resolved << {"key" => entry.key, "operation" => entry.operation, "outcome" => outcome} if outcome
        rescue StandardError => error
          errors << {"kind" => "operation-resolve", "key" => entry.key,
                     "operation" => entry.operation, "error" => redact_secret_text(error.message.to_s)}
        end
        resolved
      end

      def resolve_unknown_operation(entry, volumes:, snapshots:, mounts:, csi_observed:, snapshots_observed:)
        payload = entry.payload || {}
        operation = entry.operation
        record = volume_store[entry.key]
        case operation
        when "create"
          # A failed ListVolumes observation is not permission to replay a
          # mutating CSI RPC.  Keep the operation and record Unknown until a
          # later recovery pass has authoritative driver state.
          return nil unless record&.backend.to_s == "csi" && csi_observed

          backend = backends.fetch(record.id)
          driver_id = csi_driver_id(record)
          result = if driver_id && volumes.key?(driver_id)
                     volumes.fetch(driver_id)
                   else
                     backend.provision(token: entry.token)
                   end
          durable_result = sanitize_for_persistence(result)
          durable_spec = record.spec.merge("backendResult" => durable_result)
          volume_store[record.id] = record.with(state: "Provisioned", spec: durable_spec,
                                                 operation: nil, generation: record.generation + 1)
          backends[record.id] = build_backend(record.id, durable_spec)
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: record.id)
          "succeeded"
        when "delete"
          return nil unless record && csi_observed

          driver_id = csi_driver_id(record)
          if driver_id && !volumes.key?(driver_id)
            mount_ledger.remove_volume(record.id)
            volume_store.delete(record.id)
            backends.delete(record.id)
            forget_csi_secrets(record.id)
            operations.finish!(key: entry.key, operation: operation, token: entry.token, result: true)
            "succeeded"
          else
            resolve_operation_as_retryable(entry, record, "CSI volume still exists after DeleteVolume")
          end
        when /\Acontroller-publish:/
          return nil unless record && csi_observed
          node = Types.key(payload, "node") || operation.split(":", 3)[1]
          observed = volumes[csi_driver_id(record)]
          published_nodes = csi_published_nodes(observed)
          return resolve_operation_as_retryable(entry, record, "CSI volume is not published to #{node}") if published_nodes && !published_nodes.include?(node.to_s)

          backend = backends.fetch(record.id)
          context = context_for_node(record, node, {})
          result = sanitize_for_persistence(AdapterSupport.result_hash(backend.attach(node: node, context: context)))
          attachments = Types.deep_copy(record.attachments)
          attachments[node.to_s] = {
            "node" => node.to_s, "pods" => [],
            "publishContext" => Types.deep_copy(result["publishContext"] || {}),
            "volumeContext" => Types.deep_copy(context["volumeContext"] || {}),
            "accessModes" => Types.deep_copy(context["accessModes"] || []),
            "volumeMode" => context["volumeMode"].to_s,
            "backendResult" => sanitize_for_persistence(result)
          }
          volume_store[record.id] = record.with(state: "Attached", attachments: attachments,
                                                 operation: nil, generation: record.generation + 1)
          operations.finish!(key: entry.key, operation: operation, token: entry.token,
                             result: sanitize_for_persistence(result))
          "succeeded"
        when /\Acontroller-unpublish:/
          return nil unless record && csi_observed
          node = Types.key(payload, "node") || operation.split(":", 3)[1]
          observed = volumes[csi_driver_id(record)]
          published_nodes = csi_published_nodes(observed)
          backends.fetch(record.id).detach(node: node, context: context_for_node(record, node, {})) if published_nodes.nil? || published_nodes.include?(node.to_s)
          attachments = Types.deep_copy(record.attachments)
          attachments.delete(node.to_s)
          state = attachments.empty? && record.stages.empty? ? "Detached" : restored_state(record, "Attached")
          volume_store[record.id] = record.with(state: state, attachments: attachments,
                                                 operation: nil, generation: record.generation + 1)
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: true)
          "succeeded"
        when "expand"
          return nil unless record && csi_observed
          desired = Types.parse_capacity(Types.key(payload, "capacity"))
          expansion = backends.fetch(record.id).expand(capacity_bytes: desired, token: entry.token,
                                                       node_paths: expansion_paths(record))
          record = record_expansion_result(record, expansion)
          result = Types.key(expansion, "capacityBytes", desired)
          volume_store[record.id] = record.with(state: restored_state(record, "Provisioned"), capacity_bytes: desired,
                                                 operation: nil, generation: record.generation + 1)
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: result)
          "succeeded"
        when "snapshot"
          return nil unless record && snapshots_observed
          name = Types.key(payload, "name")
          existing = snapshot_manager.list.find do |snapshot|
            snapshot.source_id == record.id && (name.nil? || snapshot.name.to_s == name.to_s) && snapshots.key?(snapshot.id)
          end
          existing ||= snapshot_manager.create(record.id, token: entry.token, name: name)
          restore_known_record(record, default_state: "Provisioned")
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: existing.id)
          "succeeded"
        when "delete-snapshot"
          snapshot_id = Types.key(payload, "snapshotId") || entry.key.delete_prefix("snapshot-")
          return nil unless snapshots_observed
          if snapshots.key?(snapshot_id.to_s)
            snapshot = snapshot_manager.store[snapshot_id.to_s]
            return nil unless snapshot

            backends.fetch(snapshot.source_id).delete_snapshot(snapshot_id, token: entry.token)
            snapshot_manager.store.delete(snapshot_id.to_s)
            operations.finish!(key: entry.key, operation: operation, token: entry.token, result: true)
            "succeeded"
          else
            snapshot_manager.store.delete(snapshot_id.to_s)
            operations.finish!(key: entry.key, operation: operation, token: entry.token, result: true)
            "succeeded"
          end
        else
          # Mountinfo can describe the local effect, but a failed CSI
          # observation still cannot authorize follow-up NodeExpand or local
          # unfencing of a remote operation.
          return nil if record&.backend.to_s.casecmp?("csi") && !csi_observed

          resolve_unknown_node_operation(entry, record, payload, mounts)
        end
      end

      def resolve_unknown_node_operation(entry, record, payload, mounts)
        return nil unless record

        operation = entry.operation
        target = Types.key(payload, "path", Types.key(payload, "target"))
        target = File.expand_path(target.to_s) if Types.present?(target)
        observed = target && mounts[target]
        case operation
        when /\Astage:/
          return resolve_operation_as_retryable(entry, record, "stage mount is absent") unless observed
          return nil if unsafe_lease_observation?(entry)

          result = sanitize_for_persistence(observed).merge("target" => target, "node" => Types.key(payload, "node").to_s)
          if backends.fetch(record.id).is_a?(RemoteBackend) && node_expansion_required?(record)
            backends.fetch(record.id).expand_node(path: target, capacity_bytes: record.capacity_bytes,
                                                  token: "#{entry.token}:node-expand")
            record = record_node_expanded(record, target)
          end
          register_mount_identity(volume_id: record.id, identity: result, target: target,
                                  owner: "volume:#{record.id}", stage_path: target,
                                  generation: record.generation, secret: false)
          stages = Types.deep_copy(record.stages).merge(target => result)
          volume_store[record.id] = record.with(state: "Staged", stages: stages, operation: nil,
                                                 generation: record.generation + 1)
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: result)
          "succeeded"
        when /\Apublish:/
          return resolve_operation_as_retryable(entry, record, "published mount is absent") unless observed
          return nil if unsafe_lease_observation?(entry)

          pod = Types.key(payload, "pod").to_s
          result = sanitize_for_persistence(observed).merge("target" => target, "pod" => pod,
                                                            "node" => Types.key(payload, "node").to_s)
          if backends.fetch(record.id).is_a?(RemoteBackend) && node_expansion_required?(record)
            backends.fetch(record.id).expand_node(path: target, capacity_bytes: record.capacity_bytes,
                                                  token: "#{entry.token}:node-expand")
            record = record_node_expanded(record, target)
          end
          stage_path = record.stages.values.first && record.stages.values.first["target"]
          register_mount_identity(volume_id: record.id, identity: result, target: target,
                                  owner: "pod:#{pod}", stage_path: stage_path,
                                  generation: record.generation, secret: false)
          publishes = Types.deep_copy(record.publishes).merge("#{pod}\0#{target}" => result)
          volume_store[record.id] = record.with(state: "Published", publishes: publishes, operation: nil,
                                                 generation: record.generation + 1)
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: result)
          "succeeded"
        when /\Aunpublish:/
          return nil if observed

          pod = Types.key(payload, "pod").to_s
          publishes = Types.deep_copy(record.publishes)
          removed = publishes.delete("#{pod}\0#{target}")
          mount_ledger.remove(identity: mount_ledger.identity_for(removed), expected: removed) if removed
          state = publishes.empty? ? "Staged" : "Published"
          volume_store[record.id] = record.with(state: state, publishes: publishes, operation: nil,
                                                 generation: record.generation + 1)
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: true)
          "succeeded"
        when /\Aunstage:/
          return nil if observed

          stages = Types.deep_copy(record.stages)
          removed = stages.delete(target)
          mount_ledger.remove(identity: mount_ledger.identity_for(removed), expected: removed) if removed
          state = record.attachments.empty? ? "Detached" : "Attached"
          volume_store[record.id] = record.with(state: state, stages: stages, operation: nil,
                                                 generation: record.generation + 1)
          operations.finish!(key: entry.key, operation: operation, token: entry.token, result: true)
          "succeeded"
        end
      end

      # A post-effect lease verification failure can leave a real mount
      # reachable only through the old descriptor path. After restart that fd
      # no longer exists, so adopting a same-path observation would turn an
      # unproven rename/replacement into durable ownership. Keep the operation
      # fenced until an operator or a later authoritative observation resolves
      # it; an absent mount remains safe to classify as retryable above.
      def unsafe_lease_observation?(entry)
        details = entry.respond_to?(:error) ? entry.error : nil
        details = details.respond_to?(:to_h) ? details.to_h : {}
        nested = details["details"] || details[:details] || details
        nested.respond_to?(:to_h) &&
          Types.present?(nested["leaseIdentity"] || nested[:lease_identity])
      end

      def resolve_operation_as_retryable(entry, record, message)
        operations.fail!(key: entry.key, operation: entry.operation, token: entry.token,
                         error: ConflictError.new(message))
        restore_known_record(record, default_state: "Provisioned")
        "retryable"
      end

      def restore_known_record(record, default_state:)
        volume_store[record.id] = record.with(state: restored_state(record, default_state), operation: nil,
                                               generation: record.generation + 1)
      end

      def restored_state(record, default_state)
        Types.key(record.operation || {}, "previousState", default_state).to_s
      end

      def index_csi_entries(entries, id_key)
        Array(entries).each_with_object({}) do |entry, result|
          hash = entry.respond_to?(:to_h) ? entry.to_h.transform_keys(&:to_s) : {}
          id = Types.key(hash, id_key, Types.key(hash, "id"))
          result[id.to_s] = hash if Types.present?(id)
        end
      end

      def csi_driver_id(record)
        result = Types.key(record.spec, "backendResult", {})
        Types.key(result, "volumeId", Types.key(result, "volume_id"))&.to_s
      end

      def csi_published_nodes(observed)
        return nil unless observed
        status = Types.key(observed, "status")
        return nil unless status

        Array(Types.key(status, "publishedNodeIds", Types.key(status, "published_node_ids"))).map(&:to_s)
      end

      def run_manager_operation(id, operation, token, payload)
        key = Types.identifier(id, "volume id")
        token = Types.identifier(token, "operation token")
        entry = nil
        effect_applied = false
        with_volume_lock(key) do
          entry = operations.begin!(key: key, operation: operation, token: token, fingerprint: Types.digest(payload))
          return Types.deep_copy(entry.result) if entry.status == "succeeded"
          raise OperationUnknown, "operation #{operation} for #{key} is #{entry.status}" unless entry.status == "new"

          result = yield
          effect_applied = true
          operations.finish!(key: key, operation: operation, token: token, result: Types.deep_copy(result))
          result
        end
      rescue StandardError => error
        raise if error.is_a?(StateUnknownError)
        ambiguous = effect_applied || error.is_a?(OperationUnknown) ||
                    (!error.is_a?(StateUnknownError) && error.class.name.to_s.match?(/Timeout|Unknown|EOF|Connection/)) ||
                    (error.respond_to?(:ambiguous?) && error.ambiguous?)
        if entry && ambiguous
          operations.unknown!(key: key, operation: operation, token: token, error: error)
          mark_unknown(key)
        end
        operations.fail!(key: key, operation: operation, token: token, error: error) if entry && !ambiguous
        raise
      end

      def default_capabilities
        {"controller" => %w[CREATE_DELETE_VOLUME PUBLISH_UNPUBLISH_VOLUME CREATE_DELETE_SNAPSHOT EXPAND_VOLUME CLONE_VOLUME],
         "node" => %w[STAGE_UNSTAGE_VOLUME PUBLISH_UNPUBLISH_VOLUME GET_VOLUME_STATS EXPAND_VOLUME],
         "accessModes" => %w[ReadWriteOnce ReadOnlyMany ReadWriteMany ReadWriteOncePod]}
      end

      def detect_backend(hash)
        explicit = Types.key(hash, "backend")
        return explicit.to_s if explicit && !explicit.to_s.empty?
        typed = Types.key(hash, "type")
        return "csi" if typed && typed.to_s.casecmp?("csi")
        return typed.to_s if typed && (BUILTIN_BACKENDS.key?(typed.to_s) || BUILTIN_BACKENDS.key?(typed.to_s.downcase))
        return "csi" if csi_source_present?(hash)

        BUILTIN_BACKENDS.keys.find { |name| hash.key?(name) || hash.key?(name.to_sym) }
      end

      def csi_source_present?(hash)
        hash.respond_to?(:key?) && (hash.key?("csi") || hash.key?(:csi))
      end

      def csi_adapter_from_spec(spec)
        candidate = Types.key(spec, "csi")
        return nil if candidate.nil? || candidate.is_a?(Hash)

        candidate
      end

      # Populate the redaction registry before any recovery observation RPC.
      # A plugin is untrusted and may echo a secret in a ListVolumes or
      # pagination error, so a resolver failure must fence all CSI
      # observations rather than allowing a raw error to enter the report.
      def prime_csi_secret_redactions!
        failures = []
        volume_store.values.each do |record|
          next unless record.backend.to_s.casecmp?("csi")
          next unless csi_secret_reference_present?(record.spec)

          begin
            resolve_csi_secrets(record.id, record.spec, purpose: :recovery_redaction)
          rescue StandardError
            failures << {
              "kind" => "csi-secret-redaction",
              "volumeId" => record.id.to_s,
              "error" => "CSI recovery secret redaction preflight failed"
            }
          end
        end
        [failures.empty?, failures]
      end

      def csi_secret_reference_present?(spec)
        Types.present?(Types.key(spec, "secretRef", Types.key(spec, "secretsRef"))) ||
          Types.present?(Types.key(spec, "csiSecrets")) ||
          Types.present?(Types.key(spec, "secrets"))
      end

      def validate_csi_driver!(spec, csi)
        requested = Types.key(spec, "driver").to_s
        return true if requested.empty?
        unless csi.respond_to?(:identity)
          raise CSIUnavailable, "CSI adapter identity is unavailable; cannot verify requested driver #{requested.inspect}"
        end

        identity = csi.identity
        actual = if identity.respond_to?(:name)
                   identity.name.to_s
                 else
                   Types.key(identity.respond_to?(:to_h) ? identity.to_h : {}, "name").to_s
                 end
        raise CSIUnavailable, "CSI adapter returned an empty plugin identity" if actual.empty?
        return true if actual == requested

        raise CSIUnavailable, "CSI driver mismatch: volume requests #{requested.inspect}, configured plugin is #{actual.inspect}"
      end

      def resolve_csi_secrets(id, spec, purpose:)
        volatile = @volatile_csi_secrets[id.to_s]
        return Types.deep_copy(volatile) if volatile

        reference = Types.key(spec, "secretRef", Types.key(spec, "secretsRef"))
        required = Types.present?(reference) || Types.present?(Types.key(spec, "csiSecrets"))
        return {} unless required
        raise CSIUnavailable, "CSI secret resolver is not configured for volume #{id}" unless @secret_resolver

        method_name = @secret_resolver.respond_to?(:resolve) ? :resolve : :call
        raise CSIUnavailable, "CSI secret resolver must implement resolve or call" unless @secret_resolver.respond_to?(method_name)

        resolver_method = @secret_resolver.method(method_name)
        resolver_options = {volume_id: id.to_s, purpose: purpose.to_s}
        resolver_parameters = if method_name == :call && @secret_resolver.respond_to?(:parameters)
                                @secret_resolver.parameters
                              else
                                resolver_method.parameters
                              end
        value = if resolver_parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
                  resolver_method.call(Types.deep_copy(reference), **resolver_options)
                else
                  resolver_method.call(Types.deep_copy(reference), resolver_options)
                end
        hash = value.respond_to?(:to_h) ? value.to_h : nil
        raise CSIUnavailable, "CSI secret resolver returned a non-map for volume #{id}" unless hash

        resolved = hash.each_with_object({}) do |(key, child), result|
          result[String(key)] = String(child)
        rescue TypeError
          raise CSIUnavailable, "CSI secret resolver returned non-string data for volume #{id}"
        end
        @secret_redactions |= resolved.values
        resolved
      end

      def list_csi_snapshots
        entries = {}
        remote_records = volume_store.values.select { |record| record.backend.to_s.casecmp?("csi") }
        remote_records.each do |record|
          driver_id = csi_driver_id(record)
          next unless Types.present?(driver_id)

          kwargs = {
            source_volume_id: driver_id,
            secrets: resolve_csi_secrets(record.id, record.spec, purpose: :list_snapshots)
          }
          paginate_csi_observation(:list_snapshots, operation: "ListSnapshots", entry_keys: %w[entries snapshots],
                                                    id_key: "snapshotId", kwargs: kwargs).each do |entry|
            value = AdapterSupport.result_hash(entry)
            snapshot_id = Types.key(value, "snapshotId", Types.key(value, "snapshot_id"))
            source_volume_id = Types.key(value, "sourceVolumeId", Types.key(value, "source_volume_id"))
            unless source_volume_id.is_a?(String) && !source_volume_id.empty? && source_volume_id == driver_id.to_s
              raise CSIError,
                    "CSI ListSnapshots returned snapshot #{snapshot_id.inspect} for an unexpected source volume"
            end
            entries[snapshot_id.to_s] = sanitize_for_persistence(value) if Types.present?(snapshot_id)
          end
        end
        {"entries" => entries.values}
      end

      def list_csi_volumes
        entries = paginate_csi_observation(
          :list_volumes, operation: "ListVolumes", entry_keys: %w[entries volumes], id_key: "volumeId", kwargs: {}
        )
        {"entries" => entries}
      end

      def paginate_csi_observation(method_name, operation:, entry_keys:, id_key:, kwargs:)
        entries = []
        starting_token = nil
        seen_tokens = {}
        pages = 0
        loop do
          pages += 1
          if pages > CSI_RECOVERY_PAGE_LIMIT
            raise CSIError, "CSI #{operation} pagination exceeded the recovery bound"
          end

          page = invoke_csi_with_supported_keywords(method_name, kwargs.merge(starting_token: starting_token))
          unless page.is_a?(Array) || (!page.nil? && page.respond_to?(:to_h))
            raise CSIError, "CSI #{operation} returned a malformed pagination page"
          end

          hash = page.is_a?(Array) ? {} : AdapterSupport.result_hash(page)
          page_entries = page.is_a?(Array) ? page : entry_keys.lazy.map { |key| hash[key] }.find(&:itself)
          normalized_entries = if page_entries.nil?
                                 []
                               elsif page_entries.is_a?(Array)
                                 page_entries
                               elsif !page_entries.is_a?(Hash) && !page_entries.is_a?(String) && page_entries.respond_to?(:to_a)
                                 page_entries.to_a
                               else
                                 raise CSIError, "CSI #{operation} returned malformed entries"
                               end
          entries.concat(normalized_entries.map do |entry|
            normalize_csi_observation_entry(entry, id_key: id_key, operation: operation)
          end)
          next_token = hash["nextToken"] || hash["next_token"]
          break if next_token.nil? || next_token == ""
          raise CSIError, "CSI #{operation} returned a non-string pagination token" unless next_token.is_a?(String)

          token = next_token
          raise CSIError, "CSI #{operation} pagination repeated token" if seen_tokens.key?(token)

          seen_tokens[token] = true
          starting_token = token
        end
        entries
      end

      def normalize_csi_observation_entry(entry, id_key:, operation:)
        unless !entry.nil? && entry.respond_to?(:to_h)
          raise CSIError, "CSI #{operation} returned a malformed entry"
        end

        hash = AdapterSupport.result_hash(entry)
        nested_key = id_key == "volumeId" ? "volume" : "snapshot"
        if hash.key?(nested_key)
          nested = hash[nested_key]
          unless !nested.nil? && nested.respond_to?(:to_h)
            raise CSIError, "CSI #{operation} returned a malformed #{nested_key} entry"
          end
          hash = AdapterSupport.result_hash(nested).merge(hash.reject { |key, _| key == nested_key })
        end
        underscored_id_key = id_key.gsub(/([A-Z])/, '_\\1').downcase
        id = Types.key(hash, id_key, Types.key(hash, underscored_id_key, Types.key(hash, "id")))
        raise CSIError, "CSI #{operation} returned an entry without #{id_key}" unless Types.present?(id)

        hash
      end

      def invoke_csi_with_supported_keywords(method_name, kwargs)
        method = @csi.method(method_name)
        parameters = method.parameters
        accepted = if parameters.any? { |kind, _| kind == :keyrest }
                     kwargs
                   else
                     kwargs.select do |key, _|
                       parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name.to_sym == key.to_sym }
                     end
                   end
        method.call(**accepted)
      end

      def recover_backends_from_store!
        volume_store.each_value do |record|
          begin
            @backends[record.id] = build_backend(record.id, record.spec)
          rescue StandardError => error
            # A corrupt/incomplete record remains visible but is fenced.  The
            # old behavior swallowed the reconstruction failure, allowing a
            # later mutation to hit a missing backend and fail open as a
            # generic KeyError.
            previous_state = record.state
            mark_unknown(record.id)
            operation = {"status" => "unknown", "reason" => "backend reconstruction failed",
                         "error" => redact_secret_text(error.message.to_s), "previousState" => previous_state}
            # No CSI adapter yet: a kubelet plugin registry attached later
            # (csi_registry=) reconstructs the volume.
            operation["csiUnconfigured"] = true if error.is_a?(CSIUnavailable) && @csi.nil?
            volume_store[record.id] = volume_store[record.id].with(operation: operation)
          end
        end
      end

      def normalize_pod_volume(volume, pod)
        hash = volume.respond_to?(:to_h) ? Types.deep_copy(volume.to_h) : {}
        name = Types.key(hash, "name") || SecureRandom.hex(4)
        source = hash.reject { |key, _| key.to_s == "name" }
        source["name"] = name
        source["pod"] = pod.to_h
        source["podUid"] = pod_identifier(pod)
        # A projected serviceAccountToken source is refused outright without a
        # rotator; the node cannot mint tokens itself, so it carries one bound
        # to this pod that asks the TokenRequest API.
        if @token_provider && projected_service_account_token?(source)
          provider = @token_provider.respond_to?(:for_pod) ? @token_provider.for_pod(pod.to_h) : @token_provider
          source["tokenRotator"] = Projection::TokenRotator.new(provider: provider, clock: @clock)
        end
        source
      end

      def projected_service_account_token?(source)
        Array(Types.key(Types.key(source, "projected", {}), "sources", [])).any? do |entry|
          hash = entry.respond_to?(:to_h) ? entry.to_h : {}
          hash.key?("serviceAccountToken") || hash.key?(:serviceAccountToken)
        end
      end

      def pod_identifier(pod)
        metadata = Types.key(pod.to_h, "metadata", {})
        Types.key(metadata, "uid", Types.key(metadata, "name", "pod")).to_s
      end
    end
  end
end
