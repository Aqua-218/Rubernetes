# frozen_string_literal: true

module Rubernetes
  module Node
    # The kubelet adds this admin-provided GID from each mounted, UID-bound PV
    # to the effective supplemental groups of the sandbox and its containers.
    module VolumeGroups
      ANNOTATION = "pv.beta.kubernetes.io/gid"

      module_function

      def for_claim(volume, claim)
        uid = claim.dig("metadata", "uid")
        return if uid.to_s.empty? || volume.dig("spec", "claimRef", "uid") != uid

        value = volume.dig("metadata", "annotations", ANNOTATION).to_s
        return unless value.match?(/\A[+-]?\d+\z/)

        gid = Integer(value, 10, exception: false)
        gid if gid&.between?(0, (1 << 32) - 2)
      end

      def apply(security_context, volume_handle)
        return security_context unless volume_handle.is_a?(Hash)

        mounts = volume_handle["mounts"]
        return security_context unless mounts.is_a?(Hash)

        groups = mounts.values.filter_map { |mount| mount["volumeGid"] if mount.is_a?(Hash) }
        return security_context if groups.empty?

        security_context.merge("supplementalGroups" => (Array(security_context["supplementalGroups"]) + groups).uniq)
      end
    end
  end
end
