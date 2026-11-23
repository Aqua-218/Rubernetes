# frozen_string_literal: true

require_relative "types"

module Rubernetes
  module Controller
    module EndpointSliceObjects
      SERVICE_LABEL = "kubernetes.io/service-name"
      MANAGED_BY_LABEL = "endpointslice.kubernetes.io/managed-by"
      ENDPOINT_SLICE = ResourceDescriptor.parse("EndpointSlice")

      private

      def managed_slices_for(owner, slices)
        name = Support.name(owner)
        manager = self.class::MANAGED_BY
        Array(slices).select do |slice|
          labels = Support.labels(slice)
          labels[SERVICE_LABEL].to_s == name && labels[MANAGED_BY_LABEL].to_s == manager
        end.sort_by { |slice| [Support.value(slice, "addressType", "IPv4").to_s, Support.name(slice)] }
      end

      def build_slice(owner, name, labels, address_type, ports, endpoints)
        {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
         "metadata" => {"name" => name, "namespace" => Support.namespace(owner),
                        "labels" => labels.merge(SERVICE_LABEL => Support.name(owner), MANAGED_BY_LABEL => self.class::MANAGED_BY),
                        "ownerReferences" => [Support.owner_reference(owner)]},
         "addressType" => address_type, "ports" => ports, "endpoints" => endpoints}
      end

      def preserve_slice_metadata(current, candidate)
        candidate.merge("metadata" => Support.metadata(current).merge(candidate.fetch("metadata")),
                        "addressType" => Support.value(current, "addressType", candidate.fetch("addressType")))
      end
    end
  end
end
