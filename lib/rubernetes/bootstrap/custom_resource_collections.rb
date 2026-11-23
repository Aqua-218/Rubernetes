# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class CustomResourceDescriptor < Controller::ResourceDescriptor
      def collection_path(namespace = nil)
        base = "/apis/#{api_version}"
        base += "/namespaces/#{namespace}" if namespaced? && namespace
        "#{base}/#{resource}"
      end

      def delete_options(options, object)
        uid = object && Controller::Support.uid(object)
        return options if uid.to_s.empty?

        supplied = options || {}
        preconditions = {"uid" => uid}.merge(supplied["preconditions"] || {})
        supplied.merge("preconditions" => preconditions)
      end
    end

    # Garbage collection and ResourceQuota use one served version per
    # established custom resource so they count each persisted object once.
    module CustomResourceCollections
      CRD = Controller::ResourceDescriptor.parse("CustomResourceDefinition", group: "apiextensions.k8s.io",
                                                                             version: "v1", resource: "customresourcedefinitions", scope: :cluster)

      def custom_resource_collections
        custom_resource_descriptors.each_with_object({}) do |descriptor, collections|
          items = custom_resource_items(descriptor)
          collections[descriptor] = items if items
        end
      end

      def custom_resource_descriptors
        list(CRD, fresh: true).filter_map do |definition|
          spec = definition["spec"] || {}
          established = Array(definition.dig("status", "conditions")).any? do |condition|
            condition["type"] == "Established" && condition["status"] == "True"
          end
          next unless established

          served = Array(spec["versions"]).select { |version| version["served"] }
          preferred = served.find { |version| version["storage"] } || served.first
          next unless preferred

          names = definition.dig("status", "acceptedNames") || spec.fetch("names")
          CustomResourceDescriptor.new(group: spec.fetch("group"), version: preferred.fetch("name"),
                                       kind: names.fetch("kind"), resource: names.fetch("plural"),
                                       scope: spec["scope"] == "Cluster" ? :cluster : :namespaced, allow_unknown: true)
        end
      end

      def custom_resource_items(descriptor, namespace: nil)
        response = client.get(descriptor.collection_path(namespace))
        KubernetesResourceSource.restore_item_type_meta(Array(response.fetch("items")), envelope: response, descriptor: descriptor)
      rescue Client::APIError => error
        # An established CRD can be deleted between discovery and listing.
        raise unless error.status == 404

        nil
      end
    end
  end
end
