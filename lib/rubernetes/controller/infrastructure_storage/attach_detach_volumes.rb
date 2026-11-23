# frozen_string_literal: true

require_relative "../../volume/csi_migration"

module Rubernetes
  module Controller
    # Indexes translated and native sources by the identity the CSI driver
    # attaches. An inline migrated source remains available after its Pod is
    # deleted because its complete spec is stored in the VolumeAttachment.
    class AttachDetachVolumes
      Volume = Data.define(:name, :spec, :source) do
        def csi = spec["csi"]

        def identity
          return unless csi.is_a?(Hash) && !csi["driver"].to_s.empty? && !csi["volumeHandle"].to_s.empty?

          [csi["driver"], csi["volumeHandle"]]
        end

        def unique_name = "kubernetes.io/csi/#{csi.fetch("driver")}^#{csi.fetch("volumeHandle")}"
      end

      def initialize(volumes, claims)
        @volumes = Array(volumes).to_h { |pv| [Support.name(pv), persistent(pv)] }
        @claims = Array(claims).to_h { |claim| [[Support.namespace(claim).to_s, Support.name(claim)], claim] }
      end

      def persistent(pv)
        name = Support.name(pv)
        spec = ::Rubernetes::Volume::CSIMigration.persistent_spec(pv)
        Volume.new(name: name, spec: spec, source: {"persistentVolumeName" => name})
      rescue ::Rubernetes::Volume::CSIMigration::Invalid
        nil
      end

      def pod_volume(pod, entry)
        if (claim_name = claim_name(pod, entry))
          claim = @claims[[Support.namespace(pod).to_s, claim_name]]
          return @volumes[Support.spec(claim || {})["volumeName"]]
        end

        spec = ::Rubernetes::Volume::CSIMigration.inline_spec(entry, namespace: Support.namespace(pod) || "default")
        source = spec ? {"inlineVolumeSpec" => spec} : nil
        Volume.new(name: Support.value(entry, "name", ""), spec: spec || entry, source: source)
      rescue ::Rubernetes::Volume::CSIMigration::Invalid
        nil
      end

      def attachment_volume(attachment)
        source = Support.spec(attachment)["source"] || {}
        return @volumes[source["persistentVolumeName"]] if source["persistentVolumeName"]

        spec = source["inlineVolumeSpec"]
        Volume.new(name: Support.name(attachment), spec: spec, source: source) if spec.is_a?(Hash)
      end

      private

      def claim_name(pod, entry)
        claim = entry.dig("persistentVolumeClaim", "claimName")
        return claim if claim

        "#{Support.name(pod)}-#{entry["name"]}" if entry["ephemeral"].is_a?(Hash)
      end
    end
  end
end
