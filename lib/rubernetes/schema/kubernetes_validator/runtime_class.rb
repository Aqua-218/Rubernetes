# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      # pkg/registry/node/runtimeclass: update reruns the create checks and
      # then adds the immutable-field check.
      def runtime_class_handler_errors(root, old, operation)
        handler = fetch(root, "handler").to_s
        errors = if handler.empty?
                   [issue(%w[handler], :required, "")]
                 else
                   invalid_messages(%w[handler], dns1123_label_messages(handler))
                 end
        errors << issue(%w[handler], :invalid, "field is immutable") if operation == :update && old && handler != fetch(old, "handler").to_s
        errors
      end
    end
  end
end
