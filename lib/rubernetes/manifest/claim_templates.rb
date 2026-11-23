# frozen_string_literal: true

require_relative "../schema/kubernetes_validator/storage"
require_relative "../schema/quantity"

module Rubernetes
  module Manifest
    module Workload
      # Container mounts use the template's name. The controller supplies the
      # actual per-replica volume when it creates the Pod.
      ClaimTemplateReference = Data.define(:name, :workload, :claim)

      module ClaimTemplates
        CLAIM = "io.k8s.api.core.v1.PersistentVolumeClaim"
        ACCESS_MODES = Rubernetes::Schema::KubernetesValidator::SUPPORTED_ACCESS_MODES

        def volume_claim_template(name, **metadata, &block)
          name = String(name).dup.freeze
          unless Rubernetes::Schema::KubernetesValidator.dns1123_label_messages(name).empty?
            raise Error, "invalid StatefulSet claim template name #{name.inspect}"
          end

          path = "spec.volumeClaimTemplates.#{name}"
          entry = @schema.object(CLAIM, {"metadata" => metadata.merge("name" => name)}, path)
          builder = ObjectBuilder.new(object: entry, schema_name: CLAIM, schema: @schema, helpers: @helpers, path: path)
          builder.instance_exec(&block) if block
          builder.finish
          (entry["metadata"] ||= {})["name"] = name
          ((@workload["spec"] ||= {})["volumeClaimTemplates"] ||= []) << entry
          declared_at = caller(1, 1)
          at_finish { validate_claim_template(entry, path, declared_at) }
          ClaimTemplateReference.new(name, @workload, entry)
        end

        private

        def validate_claim_template(entry, path, declared_at)
          name, namespace = entry.fetch("metadata").values_at("name", "namespace")
          templates = Array(@workload.dig("spec", "volumeClaimTemplates")).compact
          if templates.count { |claim| claim.dig("metadata", "name") == name } > 1
            raise Error, "StatefulSet claim template #{name.inspect} was declared more than once", declared_at
          end

          parent_namespace = @workload.dig("metadata", "namespace")
          if !namespace.to_s.empty? && namespace != parent_namespace
            raise Error, "#{path} must inherit the StatefulSet namespace #{parent_namespace.inspect}", declared_at
          end

          spec = entry.fetch("spec", nil)
          return unless spec

          validate_claim_access_modes(spec["accessModes"], path, declared_at)
          mode = spec["volumeMode"]
          raise Error, "#{path} volumeMode must be Block or Filesystem", declared_at if mode && !%w[Block Filesystem].include?(mode)

          %w[requests limits].each do |field|
            resources = spec.dig("resources", field)
            next if resources.nil? || !resources.key?("storage")

            resources["storage"] = normalized_claim_storage(resources["storage"], "#{path}.spec.resources.#{field}.storage", field, declared_at)
          end
        end

        def validate_claim_access_modes(modes, path, declared_at)
          return if modes.nil?

          raise Error, "#{path} accessModes must use #{ACCESS_MODES.join(", ")}", declared_at if modes.empty? || (modes - ACCESS_MODES).any?
          return unless modes.include?("ReadWriteOncePod") && modes.uniq.length > 1

          raise Error, "#{path} cannot combine ReadWriteOncePod with other access modes", declared_at
        end

        def normalized_claim_storage(value, path, field, declared_at)
          quantity = Rubernetes::Schema::Quantity.from_json(value)
          raise Error, "#{path} must be greater than zero", declared_at if field == "requests" && quantity.sign <= 0

          quantity.to_s
        rescue Rubernetes::Schema::Quantity::ParseError => error
          raise Error, "#{path} has invalid quantity #{value.inspect} (#{error.message})", declared_at
        end
      end
    end
  end
end
