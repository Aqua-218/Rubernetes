# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      USER_NAMESPACES_HOST_NETWORK_GATE = "UserNamespacesHostNetworkSupport"
      POD_CONTAINER_GROUPS = %w[containers initContainers ephemeralContainers].freeze

      module_function

      def pod_user_namespace_errors(root, old, kind, options)
        base = if kind == "Pod" then []
               elsif kind == "PodTemplate" then ["template"]
               else POD_TEMPLATE_PATHS[kind]
               end
        return [] unless base

        path = base + ["spec"]
        spec = dig_path(root, path)
        return [] unless fetch(spec, "hostUsers") == false

        old_spec = old && dig_path(old, path)
        host_network_allowed = options.include?(USER_NAMESPACES_HOST_NETWORK_GATE) ||
                               (fetch(old_spec, "hostUsers") == false && fetch(old_spec, "hostNetwork") == true)
        errors = []
        detail = "when `hostUsers` is false"
        errors << issue(path + ["hostNetwork"], :forbidden, detail) if fetch(spec, "hostNetwork") == true && !host_network_allowed
        errors << issue(path + ["HostPID"], :forbidden, detail) if fetch(spec, "hostPID") == true
        errors << issue(path + ["HostIPC"], :forbidden, detail) if fetch(spec, "hostIPC") == true
        return errors if existing_userns_volume_devices?(old_spec)

        POD_CONTAINER_GROUPS.each do |group|
          Array(fetch(spec, group)).each_with_index do |container, index|
            next if Array(fetch(container, "volumeDevices")).empty?

            errors << issue(path + [group, index.to_s, "volumeDevices"], :forbidden, detail)
          end
        end
        errors
      end

      def existing_userns_volume_devices?(spec)
        return false unless fetch(spec, "hostUsers") == false

        POD_CONTAINER_GROUPS.any? do |group|
          Array(fetch(spec, group)).any? { |container| !Array(fetch(container, "volumeDevices")).empty? }
        end
      end
    end
  end
end
