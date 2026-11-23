# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      PVC_RESIZE_STATUSES = %w[
        ControllerResizeInProgress ControllerResizeInfeasible NodeResizeInProgress NodeResizeInfeasible NodeResizePending
      ].freeze

      # ValidatePersistentVolumeClaimStatusUpdate uses the stored spec. In
      # particular, validation of a status write does not revalidate the claim.
      def pvc_status_update_errors(root)
        issues = []
        required(fetch(root, "metadata"), "resourceVersion", [], issues)
        issues << issue(%w[Spec accessModes], :required, "") if Array(value_at_path(root, %w[spec accessModes])).empty?
        %w[capacity allocatedResourceStatuses allocatedResources].each do |field|
          entries = value_at_path(root, ["status", field])
          next unless entries.is_a?(Hash)

          path = ["status", field]
          entries.each do |key, value|
            name = key.to_s
            if field == "capacity"
              issues.concat(pvc_capacity_errors(value, path + ["[#{name}]"]))
              next
            end

            keys = pvc_allocated_key_errors(name, path)
            issues.concat(keys)
            if field == "allocatedResourceStatuses"
              issues << pvc_unsupported_value(name, path, PVC_RESIZE_STATUSES) unless PVC_RESIZE_STATUSES.include?(value)
            elsif keys.empty?
              issues.concat(pvc_capacity_errors(value, path + ["[#{name}]"], allocated: true))
            end
          end
        end
        issues
      end

      def pvc_allocated_key_errors(name, path)
        messages = qualified_name_messages(name)
        return messages.map { |message| valued_issue(path, name, message) } unless messages.empty?
        return [] if name == "storage" || !native_resource?(name)

        [pvc_unsupported_value(name, path, ["storage"])]
      end

      def pvc_unsupported_value(name, path, supported)
        ValidationIssue.new(path: path, code: :unsupported, kubernetes_type: "Unsupported value", value: name, message: unsupported_detail(supported))
      end

      def pvc_capacity_errors(value, path, allocated: false)
        quantity = Quantity.from_json(value)
        # resource.Quantity.Value rounds away from zero and returns an int64.
        integer = quantity.negative? ? quantity.value.floor : quantity.value.ceil
        signed = ((integer + (1 << 63)) % (1 << 64)) - (1 << 63)
        return [valued_issue(path, signed, "must be a valid resource quantity")] if signed.negative?
        return [valued_issue(path, quantity.to_s, IS_NEGATIVE_ERROR_MSG)] if allocated && quantity.negative?

        []
      rescue Quantity::ParseError
        [] # Quantity decoding reports its own error.
      end
    end
  end
end
