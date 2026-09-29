# frozen_string_literal: true

require_relative "../../resource_helpers"

module Rubernetes
  module Schema
    # pkg/apis/core/validation (v1.36.2): container and pod-level resource
    # requirements (validateResourceRequirements, validatePodResources,
    # validatePodResourceConsistency) and the ephemeral container field
    # allow-list.  None of these were enforced: a container could request
    # more than its limit, name "cpus", ask for -1 memory, and an ephemeral
    # container could carry probes and resources the node never honours.
    module KubernetesValidator
      module_function

      STANDARD_CONTAINER_RESOURCES = %w[cpu memory ephemeral-storage].freeze
      STANDARD_RESOURCES = %w[
        cpu memory ephemeral-storage requests.cpu requests.memory requests.ephemeral-storage limits.cpu limits.memory
        limits.ephemeral-storage pods resourcequotas services replicationcontrollers secrets configmaps
        persistentvolumeclaims storage requests.storage services.nodeports services.loadbalancers
      ].freeze
      INTEGER_RESOURCES = %w[
        pods resourcequotas services replicationcontrollers secrets configmaps persistentvolumeclaims
        services.nodeports services.loadbalancers
      ].freeze
      QOS_COMPUTE_RESOURCES = %w[cpu memory].freeze
      IS_NOT_INTEGER_ERROR_MSG = "must be an integer"
      # EphemeralContainerCommon fields in declaration order; true = allowed.
      EPHEMERAL_CONTAINER_FIELDS = {
        "name" => true, "image" => true, "command" => true, "args" => true, "workingDir" => true, "ports" => false,
        "envFrom" => true, "env" => true, "resources" => false, "resizePolicy" => false, "restartPolicy" => false,
        "restartPolicyRules" => false, "volumeMounts" => true, "volumeDevices" => true, "livenessProbe" => false,
        "readinessProbe" => false, "startupProbe" => false, "lifecycle" => false, "terminationMessagePath" => true,
        "terminationMessagePolicy" => true, "imagePullPolicy" => true, "securityContext" => true, "stdin" => true,
        "stdinOnce" => true, "tty" => true
      }.freeze

      def pod_resources_errors(root)
        issues = []
        walk(root) do |value, path|
          next unless value.is_a?(Hash) && value["containers"].is_a?(Array)
          next if path.include?("status")

          %w[containers initContainers].each do |field|
            Array(value[field]).each_with_index do |container, index|
              resources = container.is_a?(Hash) ? container["resources"] : nil
              next unless resources.is_a?(Hash)

              issues.concat(resource_requirements_errors(resources, path + [field, index.to_s, "resources"], pod_level: false))
            end
          end
          Array(value["ephemeralContainers"]).each_with_index do |container, index|
            issues.concat(ephemeral_container_field_errors(container, path + ["ephemeralContainers", index.to_s])) if container.is_a?(Hash)
          end
          issues.concat(pod_level_resources_errors(value, path)) if value["resources"].is_a?(Hash)
        end
        issues
      end

      # validatePodResources (the claims rule lives in resource_claim_reference_errors).
      def pod_level_resources_errors(spec, path)
        resources_path = path + ["resources"]
        os = spec["os"].is_a?(Hash) ? spec["os"]["name"].to_s : ""
        return [issue(resources_path, :forbidden, "may not be set for a windows pod")] if os == "windows"

        issues = resource_requirements_errors(spec["resources"], resources_path, pod_level: true)
        issues.concat(pod_resource_consistency_errors(spec, resources_path))
        issues
      end

      # validatePodResourceConsistency: pod-level requests cover the
      # containers' aggregate, a pod-level hugepage limit covers the
      # containers' aggregate, and no container limit exceeds the pod's.
      def pod_resource_consistency_errors(spec, path)
        helpers = Rubernetes::ResourceHelpers
        pod = {"spec" => spec}
        pod_requests = helpers.resource_list(spec["resources"]["requests"])
        pod_limits = helpers.resource_list(spec["resources"]["limits"])
        issues = []
        helpers.aggregate_container_requests(pod).sort.each do |name, aggregate|
          requested = pod_requests[name]
          next if requested.nil? || aggregate.value <= requested.value

          issues << valued_issue(path + ["requests", "[#{name}]"], requested.to_s,
                                 "must be greater than or equal to aggregate container requests of #{aggregate}")
        end
        helpers.aggregate_container_limits(pod).sort.each do |name, aggregate|
          next unless name.start_with?(helpers::HUGE_PAGES_PREFIX)

          limit = pod_limits[name]
          next if limit.nil? || aggregate.value <= limit.value

          issues << valued_issue(path + ["limits", "[#{name}]"], limit.to_s,
                                 "must be greater than or equal to aggregate container limits of #{aggregate}")
        end
        Array(spec["containers"]).each_with_index do |container, index|
          next unless container.is_a?(Hash)

          helpers.resource_list(container.dig("resources", "limits")).sort.each do |name, limit|
            pod_limit = pod_limits[name]
            next if pod_limit.nil? || limit.value <= pod_limit.value

            # Upstream builds this path from the pod-level resources path.
            issues << valued_issue(path + ["containers", index.to_s, "[#{name}]", "limits"], limit.to_s,
                                   "must be less than or equal to pod limits of #{pod_limit}")
          end
        end
        issues
      end

      # validateResourceRequirements (Go iterates a map; names are sorted here
      # so the error order is stable).
      def resource_requirements_errors(requirements, path, pod_level:)
        limits = requirements["limits"].is_a?(Hash) ? requirements["limits"] : {}
        requests = requirements["requests"].is_a?(Hash) ? requirements["requests"] : {}
        issues = []
        limit_cpu_or_memory = request_cpu_or_memory = limit_huge = request_huge = false
        parsed_limits = {}
        limits.keys.sort.each do |name|
          field_path = path + ["limits", "[#{name}]"]
          issues.concat(requirement_resource_name_errors(name, field_path, pod_level: pod_level))
          quantity, quantity_issues = requirement_quantity(name, limits[name], field_path)
          issues.concat(quantity_issues)
          parsed_limits[name] = quantity if quantity
          if name.start_with?("hugepages-")
            limit_huge = true
            issues.concat(huge_page_value_errors(name, quantity, field_path))
          end
          limit_cpu_or_memory = true if QOS_COMPUTE_RESOURCES.include?(name)
        end
        requests.keys.sort.each do |name|
          field_path = path + ["requests", "[#{name}]"]
          issues.concat(requirement_resource_name_errors(name, field_path, pod_level: pod_level))
          quantity, quantity_issues = requirement_quantity(name, requests[name], field_path)
          issues.concat(quantity_issues)
          limit = parsed_limits[name]
          if limits.key?(name)
            if quantity && limit
              if quantity.value != limit.value && !overcommit_allowed?(name)
                issues << valued_issue(path + ["requests"], quantity.to_s, "must be equal to #{name} limit of #{limit}")
              elsif quantity.value > limit.value
                issues << valued_issue(path + ["requests"], quantity.to_s, "must be less than or equal to #{name} limit of #{limit}")
              end
            end
          elsif !overcommit_allowed?(name)
            issues << issue(path + ["limits"], :required, "Limit must be set for non overcommitable resources")
          end
          if name.start_with?("hugepages-")
            request_huge = true
            issues.concat(huge_page_value_errors(name, quantity, field_path))
          end
          request_cpu_or_memory = true if QOS_COMPUTE_RESOURCES.include?(name)
        end
        if !limit_cpu_or_memory && !request_cpu_or_memory && (request_huge || limit_huge)
          issues << issue(path, :forbidden, "HugePages require cpu or memory")
        end
        issues
      end

      def requirement_quantity(name, raw, path)
        quantity = Quantity.from_json(raw)
        issues = []
        issues << valued_issue(path, quantity.to_s, IS_NEGATIVE_ERROR_MSG) if quantity.negative?
        if integer_resource?(name) && (quantity.milli_value % 1000) != 0
          issues << valued_issue(path, quantity.to_s, IS_NOT_INTEGER_ERROR_MSG)
        end
        [quantity, issues]
      rescue Quantity::ParseError
        # The schema layer reports an unparsable quantity.
        [nil, []]
      end

      # validateContainerResourceName / validatePodResourceName.
      def requirement_resource_name_errors(name, path, pod_level:)
        messages = qualified_name_messages(name)
        return messages.map { |message| valued_issue(path, name, message) } unless messages.empty?

        # validateResourceName, whose error the container check appends to.
        unqualified = !name.include?("/")
        issues = []
        if unqualified && !(STANDARD_RESOURCES.include?(name) || quota_huge_page?(name))
          issues << valued_issue(path, name, "must be a standard resource type or fully qualified")
          return issues if pod_level
        end

        if pod_level
          return [] if Rubernetes::ResourceHelpers.supported_pod_level_resource?(name)

          return [ValidationIssue.new(path: path, code: :unsupported, value: name, kubernetes_type: "Unsupported value",
                                      message: "supported values: \"cpu\", \"hugepages-\", \"memory\"")]
        end
        if unqualified
          return issues if STANDARD_CONTAINER_RESOURCES.include?(name) || name.start_with?("hugepages-")

          issues + [valued_issue(path, name, "must be a standard resource for containers")]
        elsif !native_resource?(name) && !extended_resource?(name)
          [valued_issue(path, name, "doesn't follow extended resource name standard")]
        else
          []
        end
      end

      def huge_page_value_errors(name, quantity, path)
        return [] if quantity.nil?

        page = Quantity.parse(name.delete_prefix("hugepages-"))
        divisible = page.value.positive? && (page.milli_value % 1000).zero? && (quantity.value.ceil % page.value.ceil).zero?
        divisible ? [] : [valued_issue(path, quantity.to_s, "#{quantity} is not positive integer multiple of #{name}")]
      rescue Quantity::ParseError
        [valued_issue(path, quantity.to_s, "#{quantity} is not positive integer multiple of #{name}")]
      end

      def quota_huge_page?(name) = name.start_with?("hugepages-", "requests.hugepages-")
      def native_resource?(name) = !name.include?("/") || name.include?("kubernetes.io/")
      def overcommit_allowed?(name) = native_resource?(name) && !name.start_with?("hugepages-")
      def integer_resource?(name) = INTEGER_RESOURCES.include?(name) || extended_resource?(name)

      def extended_resource?(name)
        return false if native_resource?(name) || name.start_with?("requests.")

        qualified_name_messages("requests.#{name}").empty?
      end

      # validateFieldAllowList(EphemeralContainerCommon, ...) plus the subPath rule.
      def ephemeral_container_field_errors(container, path)
        issues = EPHEMERAL_CONTAINER_FIELDS.filter_map do |field, allowed|
          next if allowed || !field_set?(container[field])

          issue(path + [field], :forbidden, "cannot be set for an Ephemeral Container")
        end
        Array(container["volumeMounts"]).each_with_index do |mount, index|
          next unless mount.is_a?(Hash)

          %w[subPath subPathExpr].each do |field|
            next if mount[field].to_s.empty?

            issues << issue(path + ["volumeMounts", index.to_s, field], :forbidden, "cannot be set for an Ephemeral Container")
          end
        end
        issues
      end

      # The Go zero value: an absent field, or an object with nothing in it.
      def field_set?(value)
        case value
        when nil then false
        when Hash then value.values.any? { |child| field_set?(child) }
        when Array then !value.empty?
        when String then !value.empty?
        when false then false
        else true
        end
      end

      def valued_issue(path, value, message)
        ValidationIssue.new(path: path, code: :invalid, message: message, value: value, kubernetes_type: "Invalid value")
      end
    end
  end
end
