# frozen_string_literal: true

module Rubernetes
  module Runtime
    # RuntimeClass objects the control plane installs at bootstrap
    # (spec/node/runtime.md 5.8.1): the node's runtime handlers and the fixed
    # Pod overhead of the microVM backends.  Kept free of runtime code so the
    # API server can install them without loading the Firecracker backend.
    module MicroVMRuntimeClasses
      OVERHEAD = {"cpu" => "50m", "memory" => "128Mi"}.freeze
      HANDLERS = {
        "microvm" => "rubernetes-firecracker",
        "microvm-restricted" => "rubernetes-firecracker-restricted"
      }.freeze

      module_function

      def documents
        HANDLERS.map do |name, handler|
          {"apiVersion" => "node.k8s.io/v1", "kind" => "RuntimeClass", "metadata" => {"name" => name},
           "handler" => handler, "overhead" => {"podFixed" => OVERHEAD.dup}}
        end
      end

      # RuntimeClass name -> handler, including the default native class.
      def handler_table(extra = {})
        {"rubernetes-native" => "rubernetes-native"}.merge(HANDLERS).merge(extra.to_h.transform_keys(&:to_s).transform_values(&:to_s))
      end
    end
  end
end
