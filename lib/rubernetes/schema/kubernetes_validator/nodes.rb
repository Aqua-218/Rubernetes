# frozen_string_literal: true

module Rubernetes
  module Schema
    # Node: taints, the kubelet config source, and the fields ValidateNodeUpdate
    # freezes once set.
    module KubernetesValidator
      module_function

      def node_errors(root, operation)
        issues = []
        if %i[create update].include?(operation)
          walk(root) do |value, path|
            next unless value.is_a?(Array) && path.last.to_s == "taints"

            value.each_with_index do |taint, index|
              next unless taint.is_a?(Hash)

              effect = fetch(taint, "effect")
              next if %w[NoExecute NoSchedule PreferNoSchedule].include?(effect.to_s)

              count = operation == :update ? 2 : 1
              count.times do
                issues << issue(["metadata", "taints", index.to_s, "effect"], :unsupported,
                                "supported values: \"NoSchedule\", \"PreferNoSchedule\", \"NoExecute\"")
              end
            end
          end
        end
        return issues unless operation == :update

        spec = fetch(root, "spec")
        if spec.is_a?(Hash)
          config_source = fetch(spec, "configSource")
          if config_source.is_a?(Hash)
            refs = %w[configMap] # v1.36.2 NodeConfigSource has one union arm
            present = refs.count { |name| fetch(config_source, name).is_a?(Hash) }
            if present != 1
              issues << issue(%w[spec configSource], :invalid,
                              "exactly one reference subfield must be non-nil")
            end
          end
        end

        status = fetch(root, "status")
        config = fetch(status, "config") if status.is_a?(Hash)
        return issues unless config.is_a?(Hash)

        %w[active assigned lastKnownGood].each do |slot|
          slot_value = fetch(config, slot)
          config_map = fetch(slot_value, "configMap") if slot_value.is_a?(Hash)
          next unless config_map.is_a?(Hash)

          base = ["status", "config", slot, "configMap"]
          required(config_map, "resourceVersion", base, issues)
          required(config_map, "uid", base, issues)
        end
        issues
      end

      # ValidateNodeUpdate: podCIDR and providerID may only go from unset to a
      # value, never from one value to another
      # (pkg/apis/core/validation/validation.go:7374,7386).  Nothing enforced
      # it, so a client could repoint a live Node's pod network.
      def node_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        new_spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless new_spec.is_a?(Hash) && old_spec.is_a?(Hash)

        issues = []
        old_cidrs = Array(fetch(old_spec, "podCIDRs") || [fetch(old_spec, "podCIDR")].compact).map(&:to_s)
        new_cidrs = Array(fetch(new_spec, "podCIDRs") || [fetch(new_spec, "podCIDR")].compact).map(&:to_s)
        unless old_cidrs.empty? || old_cidrs == new_cidrs
          issues << issue(%w[spec podCIDRs], :forbidden,
                          "node updates may not change podCIDR except from \"\" to valid")
        end
        old_provider = fetch(old_spec, "providerID").to_s
        new_provider = fetch(new_spec, "providerID").to_s
        unless old_provider.empty? || old_provider == new_provider
          issues << issue(%w[spec providerID], :forbidden,
                          "node updates may not change providerID except from \"\" to valid")
        end
        issues
      end
    end
  end
end
