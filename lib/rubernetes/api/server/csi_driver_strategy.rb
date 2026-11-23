# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The storage.k8s.io CSIDriver strategy defaults the opt-in when the
      # gate is enabled and drops new uses while it is disabled.
      module CSIDriverStrategy
        VOLUME_LIMIT_SCALING_GATE = "VolumeLimitScaling"
        PREVENT_MISSING_DRIVER = "preventPodSchedulingIfMissing"

        private

        def csi_driver_resource?(resource)
          resource.group == "storage.k8s.io" && resource.kind == "CSIDriver" && !resource.custom?
        end

        def default_volume_limit_scaling?(resource)
          csi_driver_resource?(resource) && feature_gate_enabled?(VOLUME_LIMIT_SCALING_GATE)
        end

        def default_volume_limit_scaling(resource, object)
          return object unless default_volume_limit_scaling?(resource) && object.is_a?(Hash)

          spec = object["spec"]
          return object unless spec.nil? || (spec.is_a?(Hash) && spec[PREVENT_MISSING_DRIVER].nil?)

          object.merge("spec" => (spec || {}).merge(PREVENT_MISSING_DRIVER => false))
        end

        def drop_disabled_volume_limit_scaling(resource, object, old)
          return object unless csi_driver_resource?(resource) && !feature_gate_enabled?(VOLUME_LIMIT_SCALING_GATE)
          return object unless object.is_a?(Hash) && object["spec"].is_a?(Hash) && object["spec"].key?(PREVENT_MISSING_DRIVER)
          return object unless old&.dig("spec", PREVENT_MISSING_DRIVER).nil?

          object.merge("spec" => object.fetch("spec").except(PREVENT_MISSING_DRIVER))
        end

        def update_csi_driver_generation(resource, object, old)
          return object unless old && default_volume_limit_scaling(resource, old)["spec"] != object["spec"]

          metadata = object.fetch("metadata", {})
          generation = old.dig("metadata", "generation").to_i + 1
          object.merge("metadata" => metadata.merge("generation" => generation))
        end
      end
    end
  end
end
