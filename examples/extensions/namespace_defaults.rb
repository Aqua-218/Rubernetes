# frozen_string_literal: true

# Every new namespace starts with the same guard rails.
#
#   rubectl extension apply examples/extensions/namespace_defaults.rb

SYSTEM = %w[default kube-system kube-public kube-node-lease].freeze

controller "namespace-defaults", watch: "namespaces" do |namespace, api|
  name = namespace.dig("metadata", "name")
  next if SYSTEM.include?(name) || namespace.dig("metadata", "deletionTimestamp")

  api.apply({"apiVersion" => "v1", "kind" => "LimitRange", "metadata" => {"name" => "defaults", "namespace" => name},
             "spec" => {"limits" => [{"type" => "Container", "defaultRequest" => {"cpu" => "50m", "memory" => "64Mi"},
                                      "default" => {"cpu" => "500m", "memory" => "256Mi"}}]}})
  api.apply({"apiVersion" => "v1", "kind" => "ResourceQuota", "metadata" => {"name" => "defaults", "namespace" => name},
             "spec" => {"hard" => {"pods" => "50"}}})
end

# And nobody removes them by accident.
validate "limitranges", "resourcequotas", on: :delete do |request|
  next unless request.name == "defaults"

  request.reject("the namespace defaults are managed by the namespace-defaults extension; delete the extension first")
end
