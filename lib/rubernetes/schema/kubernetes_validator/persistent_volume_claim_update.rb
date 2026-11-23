# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      PVC_STORAGE_CLASS_ANNOTATION = "volume.beta.kubernetes.io/storage-class"

      def pvc_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        spec = deep_copy_value(fetch(root, "spec") || {})
        previous = deep_copy_value(fetch(old, "spec") || {})
        return [] unless spec.is_a?(Hash) && previous.is_a?(Hash)

        issues = pvc_storage_class_transition(root, old, spec, previous)
        transition_issues = pvc_resize_errors(spec, previous, fetch(old, "status"))
        mode = spec["volumeMode"]
        transition_issues << valued_issue(%w[volumeMode], mode, "field is immutable") unless mode == previous["volumeMode"]
        transition_issues.concat(pvc_attributes_class_errors(spec, previous, fetch(old, "status")))

        # The controller assigns the volume name exactly once during binding.
        previous["volumeName"] = spec["volumeName"] if previous["volumeName"].to_s.empty?
        if fetch(fetch(root, "status"), "phase") == "Bound"
          requests = fetch(spec["resources"], "requests")
          requests["storage"] = value_at_path(previous, %w[resources requests storage]) if requests.is_a?(Hash)
          spec["volumeAttributesClassName"] = previous["volumeAttributesClassName"]
        end
        unless pvc_comparable_spec(spec) == pvc_comparable_spec(previous)
          issues << issue(%w[spec], :forbidden, "spec is immutable after creation except resources.requests and volumeAttributesClassName for bound claims")
        end
        issues.concat(transition_issues)
      end

      def pvc_storage_class_transition(root, old, spec, previous)
        key = PVC_STORAGE_CLASS_ANNOTATION
        was = value_at_path(old, ["metadata", "annotations", key])
        now = value_at_path(root, ["metadata", "annotations", key])
        name = spec["storageClassName"]
        assign = previous["storageClassName"].nil? && !name.nil? && (was.nil? || was == name)
        spec.delete("storageClassName") if assign
        return [] if now.to_s == was.to_s || (assign && now.nil?)

        [valued_issue(["metadata", "annotations", key], now.to_s, "field is immutable")]
      end

      def pvc_comparable_spec(spec)
        %w[limits requests].each do |key|
          resources = fetch(spec["resources"], key)
          resources.transform_values! { |value| limit_quantity(value) || value } if resources.is_a?(Hash)
        end
        comparable = semantic_value(spec) || {}
        # These are pointers to structs. A present, empty selector still
        # differs from an omitted selector even when all its lists are empty.
        %w[selector dataSource dataSourceRef].each do |field|
          comparable[field] ||= {} if spec[field].is_a?(Hash)
        end
        comparable
      end

      def pvc_resize_errors(spec, previous, old_status)
        path = %w[resources requests storage]
        requested = limit_quantity(value_at_path(spec, path))
        was = limit_quantity(value_at_path(previous, path))
        capacity = limit_quantity(value_at_path(old_status, %w[capacity storage])) || 0
        # A failed expansion can be retried at a smaller size above the actual capacity.
        return [] unless requested && was && requested < was && requested <= capacity

        [issue(["spec", *path], :forbidden, "field can not be less than status.capacity")]
      end

      def pvc_attributes_class_errors(spec, previous, old_status)
        name = spec["volumeAttributesClassName"]
        return [] if name == previous["volumeAttributesClassName"] || fetch(old_status, "currentVolumeAttributesClassName").nil?
        return [] unless name.nil? || name == ""

        value = name.nil? ? "nil" : "empty string"
        [issue(%w[spec volumeAttributesClassName], :forbidden, "update to #{value} is forbidden when status.currentVolumeAttributesClassName is not nil")]
      end
    end
  end
end
