# frozen_string_literal: true

module Rubernetes
  # pkg/api/pod HasAPIObjectReference: the API resource a Pod depends on
  # (service account, secrets, config maps, claims, API-backed volumes), or
  # nil.  Static Pods (PreventStaticPodAPIReferences) and the mirror Pods a
  # node creates (NodeRestriction) may reference none.
  module PodAPIReferences
    module_function

    def find(pod)
      spec = pod["spec"] || {}
      return "serviceaccounts" unless spec["serviceAccountName"].to_s.empty?

      containers = Array(spec["containers"]) + Array(spec["initContainers"]) + Array(spec["ephemeralContainers"])
      secrets = !Array(spec["imagePullSecrets"]).empty?
      config_maps = false
      containers.each do |container|
        Array(container["envFrom"]).each do |source|
          secrets ||= source.key?("secretRef")
          config_maps ||= source.key?("configMapRef")
        end
        Array(container["env"]).each do |variable|
          from = variable["valueFrom"] || {}
          secrets ||= from.key?("secretKeyRef")
          config_maps ||= from.key?("configMapKeyRef")
        end
      end
      volumes = Array(spec["volumes"])
      projected = volumes.flat_map { |volume| Array(volume.dig("projected", "sources")) }
      # VisitPodSecretNames / VisitPodConfigmapNames see projected sources too.
      secrets ||= projected.any? { |source| source.key?("secret") } || volumes.any? do |volume|
        volume.key?("secret") || volume.dig("azureFile",
                                            "secretName") || %w[cephfs cinder flexVolume iscsi rbd scaleIO storageos csi].any? do |kind|
                                                               volume.dig(kind, "secretRef") || volume.dig(kind, "nodePublishSecretRef")
                                                             end
      end
      return "secrets" if secrets

      config_maps ||= volumes.any? { |volume| volume.key?("configMap") } || projected.any? { |source| source.key?("configMap") }
      return "configmaps" if config_maps
      return "resourceclaims" unless Array(spec["resourceClaims"]).empty?

      volumes.each do |volume|
        kind = (volume.keys - ["name"]).first.to_s
        case kind
        when "configMap" then return "configmaps (via configmap volumes)"
        when "secret" then return "secrets (via secret volumes)"
        when "csi" then return "csidrivers (via CSI volumes)"
        when "glusterfs" then return "endpoints (via glusterFS volumes)"
        when "persistentVolumeClaim" then return "persistentvolumeclaims"
        when "ephemeral" then return "persistentvolumeclaims (via ephemeral volumes)"
        when "azureFile" then return "secrets (via azureFile volumes)"
        when "projected"
          Array(volume.dig("projected", "sources")).each do |source|
            return "configmaps (via projected volumes)" if source.key?("configMap")
            return "secrets (via projected volumes)" if source.key?("secret")
            return "serviceaccounts (via projected volumes)" if source.key?("serviceAccountToken")
            return "clustertrustbundles" if source.key?("clusterTrustBundle")
            return "podcertificates" if source.key?("podCertificate")
          end
        end
      end
      nil
    end
  end
end
