# frozen_string_literal: true

# Deployments pick up a changed ConfigMap.
#
# Kubernetes does not restart Pods when a ConfigMap they read changes; the
# usual answers are a hand-maintained checksum annotation or a separately
# deployed reloader.  Here it is one controller: when a ConfigMap changes,
# every Deployment in its namespace that mounts or reads it gets the
# ConfigMap's version written into its Pod template, which rolls it.
#
#   rubectl extension apply examples/extensions/restart_on_config_change.rb

def uses?(deployment, configmap)
  spec = deployment.dig("spec", "template", "spec") || {}
  volumes = (spec["volumes"] || []).map { |volume| volume.dig("configMap", "name") }
  containers = (spec["containers"] || []).flat_map do |container|
    (container["envFrom"] || []).map { |source| source.dig("configMapRef", "name") } +
      (container["env"] || []).map { |variable| variable.dig("valueFrom", "configMapKeyRef", "name") }
  end
  (volumes + containers).include?(configmap)
end

controller "restart-on-config-change", watch: "configmaps" do |configmap, api, event|
  next unless event == :modified

  namespace = configmap.dig("metadata", "namespace")
  name = configmap.dig("metadata", "name")
  api.list("deployments.apps", namespace: namespace).each do |deployment|
    next unless uses?(deployment, name)

    version = {"config.rubernetes.io/#{name}" => configmap.dig("metadata", "resourceVersion")}
    api.patch("deployments.apps", deployment.dig("metadata", "name"),
              {"spec" => {"template" => {"metadata" => {"annotations" => version}}}}, namespace: namespace)
    api.log("rolled a Deployment for a changed ConfigMap", deployment: deployment.dig("metadata", "name"), configmap: name)
  end
end
