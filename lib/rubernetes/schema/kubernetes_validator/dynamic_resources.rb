# frozen_string_literal: true

module Rubernetes
  module Schema
    # resource.k8s.io kinds other than the claim spec: ResourceSlice,
    # DeviceClass, DeviceTaintRule and ResourcePoolStatusRequest.
    module KubernetesValidator
      module_function

      SUPPORTED_RESOURCE_SLICE_PLACEMENT = %w[nodeName nodeSelector allNodes perDeviceNodeSelection].freeze

      def resource_slice_errors(root, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        required(spec, "driver", ["spec"], issues)
        resource_slice_pool_errors(spec, issues)
        devices = fetch(spec, "devices")
        if devices.is_a?(Array)
          devices.each_with_index do |device, index|
            resource_slice_device_errors(device, ["spec", "devices", index.to_s], operation, issues) if device.is_a?(Hash)
          end
        end
        resource_slice_node_selector_errors(spec, issues)
        resource_slice_placement_errors(spec, issues)
        issues
      end

      def resource_slice_pool_errors(spec, issues)
        pool = fetch(spec, "pool")
        # ResourceSlice's Go validator dereferences the value-typed Pool
        # struct even when the wire fixture has no pool object.  It reports
        # the child fields (not an OpenAPI `spec.pool` parent) and treats the
        # zero count as a range error.
        pool = {} unless pool.is_a?(Hash)
        required(pool, "name", %w[spec pool], issues)
        count = fetch(pool, "resourceSliceCount")
        issues << issue(%w[spec pool resourceSliceCount], :invalid, "must be greater than zero") if !count.is_a?(Numeric) || count <= 0
      end

      def resource_slice_device_errors(device, path, operation, issues)
        name = fetch(device, "name")
        issues << issue(path + ["name"], :invalid, DNS1123_LABEL_MSG) unless name.is_a?(String) && name.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/)
        # v1/v1beta2 expose the device fields directly; v1beta1 nests them
        # under Device.Basic.
        advanced_device = fetch(device, "basic")
        advanced_device = device unless advanced_device.is_a?(Hash)
        resource_slice_taint_errors(advanced_device, path, issues) unless operation == :update
        resource_slice_attribute_errors(advanced_device, path, issues)
        resource_slice_capacity_errors(device, advanced_device, path, issues)
      end

      def resource_slice_taint_errors(advanced_device, path, issues)
        taints = fetch(advanced_device, "taints")
        return unless taints.is_a?(Array)

        taints.each_with_index do |taint, taint_index|
          next unless taint.is_a?(Hash)

          effect = fetch(taint, "effect")
          next if %w[NoExecute NoSchedule None].include?(effect.to_s)

          issues << issue(path + ["taints", taint_index.to_s, "effect"], :unsupported,
                          "supported values: \"NoExecute\", \"NoSchedule\", \"None\"")
        end
      end

      def resource_slice_attribute_errors(advanced_device, path, issues)
        attributes = fetch(advanced_device, "attributes")
        return unless attributes.is_a?(Hash)

        attributes.each do |name, attribute|
          next unless attribute.is_a?(Hash)

          value_fields = %w[bool int string version boolValue intValue stringValue versionValue]
          next if value_fields.any? { |field| !fetch(attribute, field).nil? }

          issues << issue(path + ["attributes", "[#{name}]"], :invalid,
                          "exactly one value must be specified")
        end
      end

      # v1/v1beta2 expose capacity directly; v1beta1 nests it under
      # Device.Basic.  A request policy is only valid for a device that
      # explicitly opts into multiple allocations.  The generated
      # schema's value-required errors are replaced by this strategy
      # union error when the policy is present.
      def resource_slice_capacity_errors(device, capacity_device, path, issues)
        capacities = fetch(capacity_device, "capacity")
        return unless capacities.is_a?(Hash)

        capacities.each do |name, capacity|
          next unless capacity.is_a?(Hash)

          policy = fetch(capacity, "requestPolicy")
          next unless policy.is_a?(Hash)
          next if fetch(device, "allowMultipleAllocations") == true || fetch(capacity_device, "allowMultipleAllocations") == true

          issues << issue(path + ["capacity", "[#{name}]", "requestPolicy"], :forbidden,
                          "allowMultipleAllocations must be true")
        end
      end

      def resource_slice_node_selector_errors(spec, issues)
        node_selector = fetch(spec, "nodeSelector")
        terms = node_selector.is_a?(Hash) ? fetch(node_selector, "nodeSelectorTerms") : nil
        return unless terms.is_a?(Array)

        terms.each_with_index do |term, term_index|
          next unless term.is_a?(Hash)

          expressions = fetch(term, "matchExpressions")
          next unless expressions.is_a?(Array)

          expressions.each_with_index do |expression, expression_index|
            next unless expression.is_a?(Hash)

            expression_path = ["spec", "nodeSelector", "nodeSelectorTerms", term_index.to_s,
                               "matchExpressions", expression_index.to_s]
            operator = fetch(expression, "operator")
            if blank?(operator)
              required(expression, "operator", expression_path, issues)
            elsif !%w[In NotIn Exists DoesNotExist Gt Lt].include?(operator.to_s)
              issues << issue(expression_path + ["operator"], :invalid,
                              "not a valid selector operator")
            end
          end
        end
      end

      def resource_slice_placement_errors(spec, issues)
        present = SUPPORTED_RESOURCE_SLICE_PLACEMENT.reject { |name| fetch(spec, name).nil? }
        if present.empty?
          issues << issue(%w[spec], :required,
                          "exactly one of `nodeName`, `nodeSelector`, `allNodes`, `perDeviceNodeSelection` is required")
        elsif present.length > 1
          issues << issue(%w[spec], :invalid,
                          "exactly one of `nodeName`, `nodeSelector`, `allNodes`, `perDeviceNodeSelection` is required, but multiple fields are set")
        end
      end

      def device_class_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        selectors = fetch(spec, "selectors")
        if selectors.is_a?(Array)
          selectors.each_with_index do |selector, index|
            next unless selector.is_a?(Hash)

            cel = fetch(selector, "cel")
            if cel.is_a?(Hash)
              expression = fetch(cel, "expression")
              if blank?(expression)
                required(cel, "expression", ["spec", "selectors", index.to_s, "cel"], issues)
              elsif !%w[bool dyn].include?(cel_result_type(expression.to_s))
                issues << issue(["spec", "selectors", index.to_s, "cel", "expression"], :invalid,
                                "must evaluate to bool or the unknown type, not #{cel_result_type(expression.to_s)}")
              end
            else
              issues << issue(["spec", "selectors", index.to_s, "cel"], :required, "")
            end
          end
        end
        configs = fetch(spec, "config")
        if configs.is_a?(Array)
          configs.each_with_index do |config, index|
            next unless config.is_a?(Hash)
            next if fetch(config, "opaque").is_a?(Hash)

            issues << issue(["spec", "config", index.to_s, "opaque"], :required, "")
          end
        end
        issues
      end

      # Static CEL result type ("bool", "int", "dyn", ...) from the project's
      # CEL parser; a syntax error is reported as "error" so the caller
      # rejects the expression the way the apiserver's compile step does.
      def cel_compile_error(expression)
        require "rubernetes/security/cel" unless defined?(Rubernetes::Security::CEL::Types)
        Rubernetes::Security::CEL::Types.result_type(expression)
        "expression does not compile"
      rescue Rubernetes::Security::CEL::Error, NotImplementedError => error
        error.message
      end

      def cel_result_type(expression)
        require "rubernetes/security/cel" unless defined?(Rubernetes::Security::CEL::Types)
        Rubernetes::Security::CEL::Types.result_type(expression).to_s
      rescue Rubernetes::Security::CEL::Error, NotImplementedError
        # An expression CEL itself cannot compile really does have the error
        # type; anything else (a load failure, a bug in the checker) must not
        # masquerade as one, or every expression is rejected.
        "error"
      end

      def device_taint_rule_errors(root, old = nil)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        old_spec = old.is_a?(Hash) ? fetch(old, "spec") : nil
        old_taint = old_spec.is_a?(Hash) ? fetch(old_spec, "taint") : nil
        issues = []
        selector = fetch(spec, "deviceSelector")
        if selector.is_a?(Hash)
          driver = fetch(selector, "driver")
          issues.concat(invalid_messages(%w[spec deviceSelector driver], dns1123_subdomain_messages(driver))) unless driver.nil?
          pool = fetch(selector, "pool")
          issues.concat(pool_name_errors(pool, %w[spec deviceSelector pool])) unless pool.nil?
          device = fetch(selector, "device")
          issues.concat(invalid_messages(%w[spec deviceSelector device], dns1123_label_messages(device))) unless device.nil?
        end
        taint = fetch(spec, "taint")
        taint = {} unless taint.is_a?(Hash)
        issues.concat(invalid_messages(%w[spec taint key], qualified_name_messages(fetch(taint, "key").to_s)))
        value = fetch(taint, "value").to_s
        issues.concat(invalid_messages(%w[spec taint value], label_value_messages(value))) unless value.empty?
        effect = fetch(taint, "effect").to_s
        if !old_taint.is_a?(Hash) || fetch(old_taint, "effect").to_s != effect
          if effect.empty?
            issues << issue(%w[spec taint effect], :required, "")
          elsif !%w[NoExecute NoSchedule None].include?(effect)
            issues << issue(%w[spec taint effect], :unsupported, unsupported_detail(%w[NoExecute NoSchedule None]))
          end
        end
        issues
      end

      def pool_name_errors(name, path)
        name = name.to_s
        return [issue(path, :required, "")] if name.empty?
        return [issue(path, :too_long, "may not be more than 253 bytes")] if name.length > 253

        name.split("/", -1).flat_map { |part| invalid_messages(path, dns1123_subdomain_messages(part)) }
      end

      # staging/src/k8s.io/api/resource/v1alpha3/types.go ResourcePoolStatusRequestSpec (declarative)
      def resource_pool_status_request_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        driver = fetch(spec, "driver").to_s
        if driver.empty?
          issues << issue(%w[spec driver], :required, "")
        else
          issues.concat(invalid_messages(%w[spec driver], dns1123_subdomain_messages(driver)))
        end
        pool = fetch(spec, "poolName")
        issues.concat(pool_name_errors(pool, %w[spec poolName])) unless pool.nil?
        limit = fetch(spec, "limit")
        if limit.is_a?(Integer)
          issues << issue(%w[spec limit], :invalid, "must be greater than or equal to 1") if limit < 1
          issues << issue(%w[spec limit], :invalid, "must be less than or equal to 1000") if limit > 1000
        end
        count = fetch(spec, "poolCount")
        issues << issue(%w[spec poolCount], :invalid, "must be greater than or equal to 0") if count.is_a?(Integer) && count.negative?
        issues
      end

      private_class_method :resource_slice_pool_errors, :resource_slice_device_errors, :resource_slice_taint_errors, :resource_slice_attribute_errors,
                           :resource_slice_capacity_errors, :resource_slice_node_selector_errors, :resource_slice_placement_errors
    end
  end
end
