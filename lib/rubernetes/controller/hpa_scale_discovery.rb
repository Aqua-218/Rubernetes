# frozen_string_literal: true

require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "../client/errors"

module Rubernetes
  module Controller
    # HPA scale targets can be served by a CRD registered after the controller
    # started. Resolve its plural and scope through the exact served version.
    module HPAScaleDiscovery
      DNS_LABEL = /\A[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\z/

      module_function

      def resolve(client, reference)
        return unless client

        api_version = Support.value(reference, "apiVersion") || Support.value(reference, "api_version")
        group, version = ResourceDescriptor.split_api_version(api_version)
        return unless !group.empty? && group.split(".", -1).all? { |label| DNS_LABEL.match?(label) } && DNS_LABEL.match?(version)

        kind = Support.value(reference, "kind").to_s
        resources = Array(client.get("/apis/#{group}/#{version}")["resources"]).grep(Hash)
        entry = resources.find { |resource| resource["kind"] == kind && DNS_LABEL.match?(resource["name"].to_s) }
        return unless entry && resources.any? { |resource| resource["name"] == "#{entry.fetch("name")}/scale" }

        scope = entry["namespaced"] ? :namespaced : :cluster
        ResourceDescriptor.new(group: group, version: version, kind: kind, resource: entry.fetch("name"), scope: scope, allow_unknown: true)
      rescue Client::APIError => error
        return if error.status == 404

        raise UnknownGVKError, "HPA could not discover scale in #{api_version}: #{error.message}"
      end
    end
  end
end
