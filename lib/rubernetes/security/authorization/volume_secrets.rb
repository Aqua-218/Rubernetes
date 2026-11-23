# frozen_string_literal: true

module Rubernetes
  module Security
    module Authorization
      # pkg/api/v1/persistentvolume.VisitPVSecretNames, limited to references
      # a kubelet may read while serving the bound claim.
      module VolumeSecrets
        module_function

        def node_references(pv)
          spec = fields(fields(pv)["spec"])
          claim_namespace = fields(spec["claimRef"])["namespace"].to_s
          if (csi = spec["csi"])
            return %w[nodeStageSecretRef nodePublishSecretRef nodeExpandSecretRef].filter_map do |key|
              reference(fields(csi)[key])
            end
          end
          if spec["azureFile"]
            share = fields(spec["azureFile"])
            return [reference({"name" => share["secretName"], "namespace" => share["secretNamespace"]}, claim_namespace)].compact
          end

          kind = %w[cephfs cinder flexVolume rbd scaleIO iscsi storageos].find { |key| spec[key] }
          return [] unless kind

          namespace = %w[cinder storageos].include?(kind) ? "" : claim_namespace
          [reference(fields(spec[kind])["secretRef"], namespace)].compact
        end

        def reference(ref, fallback_namespace = "")
          ref = fields(ref)
          return if ref["name"].to_s.empty?

          namespace = ref["namespace"].to_s
          [:secrets, namespace.empty? ? fallback_namespace : namespace, ref["name"]]
        end

        def fields(hash) = hash.is_a?(Hash) ? hash.transform_keys(&:to_s) : {}
        private_class_method :reference, :fields
      end
    end
  end
end
