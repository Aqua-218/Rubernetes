# frozen_string_literal: true

module Rubernetes
  module Volume
    module CSIMigration
      module Topology
        ZONE_KEYS = {
          "awsElasticBlockStore" => "topology.ebs.csi.aws.com/zone",
          "gcePersistentDisk" => "topology.gke.io/zone",
          "cinder" => "topology.cinder.csi.openstack.org/zone",
          "vsphereVolume" => "topology.csi.vmware.com/zone"
        }.freeze
        DOMAINS = %w[topology.kubernetes.io failure-domain.beta.kubernetes.io].freeze

        module_function

        def translate(spec, kind, labels)
          zone_key = ZONE_KEYS[kind]
          return spec unless zone_key

          affinity = spec["nodeAffinity"] || {}
          required = affinity["required"] || {}
          original = Array(required["nodeSelectorTerms"])
          keys = original.flat_map { |term| Array(term["matchExpressions"]).map { |expr| expr["key"] } }
          domain = DOMAINS.find { |prefix| keys.include?("#{prefix}/zone") } ||
                   DOMAINS.find { |prefix| labels.key?("#{prefix}/zone") } || DOMAINS.first
          vsphere = kind == "vsphereVolume"
          zone = labels["#{domain}/zone"].to_s
          terms = rewrite(original, "#{domain}/zone", zone_key, vsphere ? [zone] : zone.split("__"))
          if vsphere
            terms = rewrite(terms, "#{domain}/region", "topology.csi.vmware.com/region", [labels["#{domain}/region"].to_s])
          elsif domain != DOMAINS.first
            terms = rewrite(terms, "#{domain}/region", "#{DOMAINS.first}/region", [])
          end
          return spec if terms == original

          spec.merge("nodeAffinity" => affinity.merge("required" => required.merge("nodeSelectorTerms" => terms)))
        end

        def rewrite(terms, old_key, new_key, labels)
          existing = terms.any? do |term|
            Array(term["matchExpressions"]).any? { |expr| expr["key"] == old_key && !Array(expr["values"]).empty? }
          end
          values = labels.map(&:strip).reject(&:empty?).uniq.sort
          return terms unless existing || !values.empty?

          (terms.empty? ? [{}] : terms).map do |term|
            expressions = Array(term["matchExpressions"])
            changed = if existing
                        expressions.map { |expr| expr["key"] == old_key ? expr.merge("key" => new_key) : expr }
                      else
                        expressions + [{"key" => new_key, "operator" => "In", "values" => values}]
                      end
            changed == expressions ? term : term.merge("matchExpressions" => changed)
          end
        end
        private_class_method :rewrite
      end
    end
  end
end
