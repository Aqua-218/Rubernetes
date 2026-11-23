# frozen_string_literal: true

module Rubernetes
  module Schema
    # pkg/api/persistentvolumeclaim/util.go's write preparation and read decorator.
    module PersistentVolumeClaimSources
      CROSS_NAMESPACE_GATE = "CrossNamespaceVolumeDataSource"
      REFERENCE_FIELDS = %w[apiGroup kind name].freeze

      module_function

      def prepare(claim, old, cross_namespace:)
        spec = claim["spec"]
        return claim unless spec.is_a?(Hash)

        old_spec = old && old["spec"]
        spec = spec.dup
        spec.delete("dataSourceRef") if !cross_namespace && namespaced?(spec["dataSourceRef"]) && old_spec&.fetch("dataSourceRef", nil).nil?
        if spec["dataSource"].is_a?(Hash) && spec["dataSourceRef"].nil? &&
           old_spec&.fetch("dataSource", nil).nil? && old_spec&.fetch("dataSourceRef", nil).nil? && !pvc_or_snapshot?(spec["dataSource"])
          spec.delete("dataSource")
        end
        normalize(claim.merge("spec" => spec))
      end

      def normalize(claim)
        spec = claim && claim["spec"]
        return claim unless spec.is_a?(Hash)

        source = spec["dataSource"]
        reference = spec["dataSourceRef"]
        if source.is_a?(Hash) && reference.nil?
          claim.merge("spec" => spec.merge("dataSourceRef" => source.slice(*REFERENCE_FIELDS)))
        elsif reference.is_a?(Hash) && source.nil? && !namespaced?(reference)
          claim.merge("spec" => spec.merge("dataSource" => reference.slice(*REFERENCE_FIELDS)))
        else
          claim
        end
      end

      def namespaced?(reference)
        reference.is_a?(Hash) && !reference["namespace"].to_s.empty?
      end

      def pvc_or_snapshot?(source)
        group = source["apiGroup"].to_s
        (source["kind"] == "PersistentVolumeClaim" && group.empty?) ||
          (source["kind"] == "VolumeSnapshot" && group == "snapshot.storage.k8s.io")
      end
      private_class_method :pvc_or_snapshot?
    end
  end
end
