# frozen_string_literal: true

require_relative "../resource_reader"
require_relative "../../api/status"
require_relative "../../api/selectors"
require_relative "../../pem"

module Rubernetes
  module Node
    class PodVolumes
      TRUST_BUNDLE_ORDER_SEED = Random.new_seed
      TRUST_BUNDLE_SELECTOR_LIMIT = 100 * 1024
      TRUST_BUNDLE_SELECTOR_OPERATORS = {
        "In" => :in, "NotIn" => :not_in, "Exists" => :exists, "DoesNotExist" => :not_exists
      }.freeze

      private

      def cluster_trust_bundle_files(bundle)
        path = Helpers.key(bundle, "path").to_s
        validate_relative_path!(path, "projected clusterTrustBundle")
        unless @cluster_trust_bundle_projection && @reader
          raise Unsupported, "projected clusterTrustBundle needs the ClusterTrustBundleProjection feature gate and the node's API client"
        end

        optional = Helpers.key(bundle, "optional", false) == true
        name = Helpers.key(bundle, "name", nil)
        signer = Helpers.key(bundle, "signerName", nil)
        bundles = if name
                    object = read("clustertrustbundles", name, namespace: nil)
                    raise MissingDependency, "ClusterTrustBundle #{name.inspect} not found" unless object || optional

                    [object].compact
                  elsif signer
                    selector = Helpers.key(bundle, "labelSelector", nil)
                    requirements = cluster_trust_bundle_requirements(selector) unless selector.nil?
                    matching = list("clustertrustbundles", namespace: nil).select do |object|
                      next false if requirements.nil? || object.dig("spec", "signerName") != signer

                      labels = object.dig("metadata", "labels") || {}
                      requirements.all? { |item| item.matches?(labels[item.key], present: labels.key?(item.key)) }
                    end
                    raise MissingDependency, "combination of signerName and labelSelector matched zero ClusterTrustBundles" if matching.empty? && !optional

                    matching
                  else
                    raise Error, "ClusterTrustBundle projection requires either name or signerName to be set"
                  end

        {path => normalized_trust_anchors(bundles)}
      rescue ResourceReader::Unavailable, Client::Error => error
        raise MissingDependency, "while reading ClusterTrustBundles: #{error.message}"
      end

      def cluster_trust_bundle_requirements(selector)
        terms = []
        requirements = Helpers.key(selector, "matchLabels", nil).to_h.map do |key, value|
          terms << "#{key}=#{value}"
          API::Selector::Requirement.new(key: key, operator: :equals, values: [value])
        end
        Array(Helpers.key(selector, "matchExpressions", nil)).each do |expression|
          key = Helpers.key(expression, "key")
          operator = Helpers.key(expression, "operator")
          values = Array(Helpers.key(expression, "values", nil))
          terms << case operator
                   when "In", "NotIn" then "#{key} #{operator.downcase} (#{values.join(",")})"
                   when "Exists" then key.to_s
                   when "DoesNotExist" then "!#{key}"
                   else raise Error, "invalid ClusterTrustBundle label selector operator #{operator.inspect}"
                   end
          requirements << API::Selector::Requirement.new(key: key, operator: TRUST_BUNDLE_SELECTOR_OPERATORS.fetch(operator), values: values)
        end
        raise Error, "ClusterTrustBundle label selector exceeds #{TRUST_BUNDLE_SELECTOR_LIMIT} bytes" if terms.join(",").bytesize > TRUST_BUNDLE_SELECTOR_LIMIT

        requirements
      end

      def normalized_trust_anchors(bundles)
        anchors = bundles.flat_map do |object|
          PEM.blocks(object.dig("spec", "trustBundle")).map(&:bytes)
        end

        # Vary the order across kubelet runs while keeping projected bytes stable during a sync.
        anchors.uniq.sort.shuffle(random: Random.new(TRUST_BUNDLE_ORDER_SEED)).map { |anchor| PEM.certificate(anchor) }.join
      end
    end
  end
end
