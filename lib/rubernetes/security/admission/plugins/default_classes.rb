# frozen_string_literal: true

module Rubernetes
  module Security
    module Admission
      module Plugins
        module DefaultClassSelection
          include Helpers

          # DefaultIngressClass and DefaultStorageClass both prefer the newest
          # API creation time, then the lexically first name on a tie.
          def newest_default_class(classes)
            classes.min_by do |klass|
              meta = metadata(klass)
              timestamp = meta["creationTimestamp"]
              [timestamp ? -Time.iso8601(timestamp).to_i : 0, meta["name"].to_s]
            end
          end
        end

        class DefaultStorageClass < Plugin
          include DefaultClassSelection

          def admit(attributes)
            return unless resource?(attributes, "", "persistentvolumeclaims") && attributes.object && attributes.operation == "CREATE"

            claim_spec = attributes.object["spec"] ||= {}
            annotations = metadata(attributes.object)["annotations"] || {}
            return if !claim_spec["storageClassName"].nil? || annotations.key?("volume.beta.kubernetes.io/storage-class")

            defaults = @context.list("storageclasses", nil, group: "storage.k8s.io").select do |klass|
              annotations = metadata(klass)["annotations"] || {}
              %w[storageclass.kubernetes.io/is-default-class storageclass.beta.kubernetes.io/is-default-class].any? { |key| annotations[key] == "true" }
            end
            return if defaults.empty?

            chosen = newest_default_class(defaults)
            claim_spec["storageClassName"] = chosen.dig("metadata", "name")
          end
        end
        Registry.register("DefaultStorageClass") do |context, config|
          DefaultStorageClass.new("DefaultStorageClass", context: context, config: config)
        end

        class DefaultIngressClass < Plugin
          include DefaultClassSelection

          def admit(attributes)
            return unless resource?(attributes, "networking.k8s.io", "ingresses") && attributes.object && attributes.operation == "CREATE"

            ingress_spec = attributes.object["spec"] ||= {}
            return if !ingress_spec["ingressClassName"].nil? || metadata(attributes.object).dig("annotations", "kubernetes.io/ingress.class")

            defaults = @context.list("ingressclasses", nil, group: "networking.k8s.io").select do |klass|
              klass.dig("metadata", "annotations", "ingressclass.kubernetes.io/is-default-class") == "true"
            end
            return if defaults.empty?

            chosen = newest_default_class(defaults)
            ingress_spec["ingressClassName"] = chosen.dig("metadata", "name")
          end
        end
        Registry.register("DefaultIngressClass") do |context, config|
          DefaultIngressClass.new("DefaultIngressClass", context: context, config: config)
        end
      end
    end
  end
end
