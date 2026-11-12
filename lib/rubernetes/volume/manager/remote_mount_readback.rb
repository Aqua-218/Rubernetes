# frozen_string_literal: true

# What RemoteBackend can prove about a CSI mount independently of the plugin's
# word: the mountinfo readback of a target, the identity recorded for a stage
# or publish, and the stage that legitimately has no kernel mount.
module Rubernetes
  module Volume
    class RemoteBackend < Backend
      module MountReadback
        private

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
              raise MountIdentityError,
                    "CSI #{stage ? "stage" : "publish"} succeeded but #{target.inspect} is absent from independent mount readback"
            end

            normalized = normalize_mount(observed, target, stage: stage)
          else
            identity = response["mountIdentity"] || response["mount_identity"]
            response = AdapterSupport.result_hash(identity).merge(response) if Capability.hash_like?(identity)
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
          if Capability.finds_mounts?(@mount_adapter)
            candidates.each do |candidate|
              observed = @mount_adapter.find_mount(candidate)
              return observed if observed
            end
            return nil
          end
          return nil unless Capability.lists_mounts?(@mount_adapter)

          Array(AdapterSupport.call(@mount_adapter, :list_mounts)).find do |entry|
            hash = Capability.hash_like?(entry) ? entry.to_h : entry
            candidates.include?(File.expand_path((hash["target"] || hash[:target] || hash["mountpoint"] || hash[:mountpoint]).to_s))
          end
        end

        def verify_remote_absent!(target, aliases: [])
          return true unless remote_mount_readback(target, aliases: aliases)

          raise MountIdentityError, "CSI unmount succeeded but #{target.inspect} remains in independent mount readback"
        end

        def mount_identity_for_target(path, result = nil)
          # Backend#descriptor_mount_binding?: only an adapter that binds mounts
          # to descriptors can vouch for a mountinfo entry.
          return nil unless descriptor_mount_binding?

          if Capability.finds_mounts?(@mount_adapter)
            observed = @mount_adapter.find_mount(path)
            return observed if observed
          elsif Capability.lists_mounts?(@mount_adapter)
            normalized = File.expand_path(path.to_s)
            observed = Array(AdapterSupport.call(@mount_adapter, :list_mounts)).find do |entry|
              hash = Capability.hash_like?(entry) ? entry.to_h : entry
              candidate = hash && (hash["target"] || hash[:target] || hash["mountpoint"] || hash[:mountpoint])
              candidate && File.expand_path(candidate.to_s) == normalized
            end
            return observed if observed
          end

          hash = Capability.hash_like?(result) ? result.to_h.transform_keys(&:to_s) : nil
          return nil unless hash && (hash["mountId"] || hash["mount_id"]) && (hash["target"] || hash["mountpoint"])

          hash
        end

        def stage_without_mount_declared?
          return true if Types.key(spec, "stageWithoutMount", false) == true

          csi_spec = Types.key(spec, "csi", {})
          csi_spec = Capability.hash_like?(csi_spec) ? csi_spec.to_h : {}
          Types.key(csi_spec, "stageWithoutMount", false) == true
        end

        def unmounted_stage_identity?(identity)
          hash = Capability.hash_like?(identity) ? identity.to_h.transform_keys(&:to_s) : nil
          hash.is_a?(Hash) && hash["stage"] == true && hash.key?("mounted") && hash["mounted"] == false &&
            !Types.present?(hash["mountId"])
        end
      end
    end
  end
end
