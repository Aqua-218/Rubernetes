# frozen_string_literal: true

require_relative "../static_manifest_source"

module Rubernetes
  module Security
    module Admission
      module Plugins
        # The API and filesystem use separate policy/binding namespaces. Static
        # configurations dispatch first, and they alone can validate API writes
        # to admission configuration objects.
        module ManifestBackedAdmission
          private

          def admission_configuration?(attributes)
            attributes.group == StaticManifestSource::GROUP && StaticManifestSource::RESOURCES.include?(attributes.resource)
          end

          def manifest_snapshot
            @config["manifest_source"]&.snapshot || {}
          end

          def api_configurations(resource)
            @context.list(resource, nil, group: StaticManifestSource::GROUP).sort_by { |entry| entry.dig("metadata", "name").to_s }
          end

          def configurations(resource, attributes)
            static = manifest_snapshot.fetch(resource, []).map { |configuration| [configuration, "manifest/"] }
            return static if admission_configuration?(attributes)

            static + api_configurations(resource).map { |configuration| [configuration, ""] }
          end

          def policy_bindings(attributes, policy_resource, binding_resource)
            snapshot = manifest_snapshot
            sources = [[snapshot.fetch(policy_resource, []), snapshot.fetch(binding_resource, [])]]
            sources << [api_configurations(policy_resource), api_configurations(binding_resource)] unless admission_configuration?(attributes)
            sources.flat_map do |policies, bindings|
              by_policy = bindings.group_by { |binding| binding.dig("spec", "policyName") }
              policies.map { |policy| [policy, by_policy.fetch(policy.dig("metadata", "name"), [])] }
            end
          end
        end
      end
    end
  end
end
