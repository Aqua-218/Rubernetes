# frozen_string_literal: true

module Rubernetes
  module Node
    class PodVolumes
      STATIC_STORAGE_SOURCES = {
        "nfs" => %w[server path readOnly],
        "iscsi" => %w[targetPortal portals iqn lun iscsiInterface initiatorName fsType readOnly chapAuthDiscovery chapAuthSession secretRef],
        "fc" => %w[targetWWNs lun wwids fsType readOnly]
      }.freeze

      # HostPath staging pins the authorized inode with a shallow bind. The
      # runtime needs the whole tree, using the original canonical path
      # that provisioning recorded in the volume store.
      def host_path_mount_source(volume)
        return unless real_mounts?

        record = @volume.volume(volume.fetch("id"))
        raise Error, "HostPath mount requires a provisioned source" unless record.backend == "hostPath"

        record.spec.fetch("backendResult").fetch("source")
      end

      private

      def used_volume_definitions(pod)
        spec = Helpers.key(pod, "spec", {}) || {}
        volumes = Array(Helpers.key(spec, "volumes", []))
        return volumes unless spec.key?("containers")

        names = %w[initContainers containers ephemeralContainers].flat_map do |group|
          Array(Helpers.key(spec, group, [])).flat_map do |container|
            entries = Array(Helpers.key(container, "volumeMounts", [])) + Array(Helpers.key(container, "volumeDevices", []))
            entries.map { |entry| Helpers.key(entry, "name", "").to_s }
          end
        end
        volumes.select { |volume| names.include?(Helpers.key(volume, "name", "").to_s) }
      end

      def validate_persistent_volume_mode!(pod, name, volume)
        return unless volume["persistentVolume"]

        mode = volume.fetch("volumeMode", "Filesystem")
        field = mode == "Block" ? "volumeMounts" : "volumeDevices"
        spec = Helpers.key(pod, "spec", {})
        used = %w[initContainers containers ephemeralContainers].any? do |group|
          Array(Helpers.key(spec, group, [])).any? do |container|
            Array(Helpers.key(container, field, [])).any? { |entry| Helpers.key(entry, "name") == name }
          end
        end
        raise Unsupported, "volume #{name} has volumeMode #{mode}, but is specified in #{field}" if used
      end

      def ephemeral_csi_volume(name, source, pod, namespace)
        pod_uid = Helpers.key(Helpers.key(pod, "metadata", {}), "uid", "").to_s
        spec = csi_spec(source, namespace).merge(
          "volumeHandle" => Volume::KubernetesCSIAdapter.inline_volume_handle(pod_uid, name), "ephemeral" => true
        )
        [{"name" => name, "csi" => spec}, Helpers.key(source, "readOnly", false) == true]
      end

      def migrated_inline_volume(entry, namespace)
        translated = Volume::CSIMigration.inline_spec(entry, namespace: namespace)
        source = translated.fetch("csi")
        spec = translated.merge("name" => entry.fetch("name"), "migratedInline" => true,
                                "csi" => csi_spec(source, namespace, pv: true))
        [spec, source["readOnly"] == true || translated["accessModes"] == ["ReadOnlyMany"]]
      end

      def static_storage_volume(base, kind, source, namespace, readonly:)
        spec = base.merge(Helpers.string_keys(source).slice(*STATIC_STORAGE_SOURCES.fetch(kind)), "backend" => kind)
        if kind == "iscsi" && (reference = Helpers.key(spec, "secretRef", nil))
          secret_namespace = Helpers.key(reference, "namespace").to_s
          secret_namespace = namespace if secret_namespace.empty? || !base.key?("persistentVolume")
          spec["secretRef"] = {"name" => Helpers.key(reference, "name"), "namespace" => secret_namespace}
        end
        readonly ||= spec["readOnly"] == true || Array(spec["mountOptions"]).any? { |option| option.to_s.split(",").map(&:strip).include?("ro") }
        [spec, readonly]
      end

      def iscsi_credentials(spec)
        return unless spec["backend"] == "iscsi" && (spec["chapAuthDiscovery"] == true || spec["chapAuthSession"] == true)

        reference = spec["secretRef"] || {}
        name = reference["name"].to_s
        namespace = reference["namespace"].to_s
        raise MissingDependency, "iSCSI CHAP authentication requires a Secret reference" if name.empty?

        secret = read("secrets", name, namespace: namespace)
        raise MissingDependency, "secret #{name.inspect} for iSCSI CHAP not found" unless secret

        decode_secret_data(secret)
      end

      # GetUniqueVolumeNameFromSpec for the attachable volumes kubelet
      # reports in use.
      def attachable_name(spec)
        case spec["backend"]
        when "iscsi" then return Volume::ISCSIBackend.unique_name(spec)
        when "fc" then return Volume::FibreChannelBackend.unique_name(spec)
        end

        csi = Helpers.key(spec, "csi", nil)
        return nil unless csi.is_a?(Hash) && (spec["persistentVolume"] || spec["migratedInline"])

        "kubernetes.io/csi/#{Helpers.key(csi, "driver")}^#{Helpers.key(csi, "volumeHandle")}"
      end

      def claim_name_for(entry, pod)
        if (claim = Helpers.key(entry, "persistentVolumeClaim", nil))
          Helpers.key(claim, "claimName").to_s
        elsif Helpers.key(entry, "ephemeral", nil)
          "#{Helpers.key(Helpers.key(pod, "metadata", {}), "name", "")}-#{Helpers.key(entry, "name")}"
        end
      end

      def csi_spec(source, namespace, pv: false)
        spec = {
          "driver" => Helpers.key(source, "driver"),
          "volumeHandle" => Helpers.key(source, "volumeHandle"),
          "fsType" => Helpers.key(source, "fsType", nil),
          "readOnly" => Helpers.key(source, "readOnly", false),
          "volumeAttributes" => Helpers.key(source, "volumeAttributes", {})
        }
        purposes = pv ? %w[nodeStage nodePublish nodeExpand] : %w[nodePublish]
        purposes.each do |purpose|
          reference = source["#{purpose}SecretRef"]
          next unless reference

          (spec["secretRefs"] ||= {})[purpose] = {
            "name" => reference.fetch("name"),
            "namespace" => pv ? reference.fetch("namespace", namespace) : namespace
          }
        end
        spec.compact
      end
    end
  end
end
