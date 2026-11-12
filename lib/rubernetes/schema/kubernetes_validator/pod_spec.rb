# frozen_string_literal: true

module Rubernetes
  module Schema
    # PodSpec rules that apply wherever a Pod template is embedded (Pod, the
    # workload controllers, Job, CronJob, PodTemplate): probe handlers, OS,
    # restart policy, security profiles, container images, downward API field
    # selectors, and the Pod's own container and resource-claim names.
    module KubernetesValidator
      module_function

      PROBE_HANDLERS = %w[exec httpGet tcpSocket grpc sleep].freeze
      PROBE_HANDLER_DETAIL = "may not specify more than 1 handler type"
      SUPPORTED_APPARMOR = %w[Localhost RuntimeDefault Unconfined].freeze
      SUPPORTED_SECCOMP = %w[Localhost RuntimeDefault Unconfined].freeze
      SUPPORTED_OS = %w[linux windows].freeze

      def probe_errors(root)
        issues = []
        walk(root) do |value, path|
          next if path.include?("status")
          next unless value.is_a?(Hash)
          # Probe handlers in status are observed state, not PodSpec input;
          # normal resource create/update strategies do not validate them.
          next if path.include?("status")

          present = PROBE_HANDLERS.reject { |name| fetch(value, name).nil? }
          next if present.empty?

          if present.length > 1
            # Kubernetes treats the first populated handler in the API
            # struct's stable order as the selected handler and reports the
            # remaining populated handlers as forbidden.
            present.drop(1).each do |name|
              issues << issue(path + [name], :forbidden, PROBE_HANDLER_DETAIL)
            end
          end
          # Validate the selected handler only.  The upstream validator emits
          # a single Forbidden error for every later handler and does not
          # descend into those handlers.  Descending unconditionally makes a
          # zero-value probe report spurious port/command errors alongside the
          # expected one-of errors.
          exec = fetch(value, "exec")
          if present.first == "exec" && exec.is_a?(Hash) &&
             (!exec.key?("command") || blank_array?(fetch(exec, "command")))
            issues << issue(path + %w[exec command], :required, "")
          end
          http = fetch(value, "httpGet")
          if present.first == "httpGet" && http.is_a?(Hash)
            port = fetch(http, "port")
            if port.nil? || (port.is_a?(Integer) && !(1..65_535).cover?(port))
              issues << issue(path + %w[httpGet port], :invalid, "must be between 1 and 65535, inclusive")
            elsif port.is_a?(String) && port.match?(/\A\d+\z/)
              issues << issue(path + %w[httpGet port], :invalid, "must contain at least one letter (a-z)")
            end
          end
        end
        issues
      end

      def common_pod_errors(root, operation = :create, old = nil)
        issues = []
        walk(root) do |value, path|
          next unless value.is_a?(Hash)

          # Status is validated by status strategies (when one exists), not
          # by the main PodSpec validator.  The generated fixture graph can
          # materialize status.containerStatuses with empty fields; applying
          # PodSpec requiredness there creates false REST errors.
          in_status = path.include?("status")
          os = fetch(value, "os")
          os = fetch(os, "name") if os.is_a?(Hash)
          issues << issue(path + ["os"], :unsupported, "supported values: \"linux\", \"windows\"") if !in_status && !os.nil? && !SUPPORTED_OS.include?(os.to_s)
          restart = fetch(value, "restartPolicy")
          if !in_status && !path.include?("resizePolicy") && !restart.nil? &&
             !%w[Always OnFailure Never].include?(restart.to_s)
            issues << issue(path + ["restartPolicy"], :required, "valid values: \"OnFailure\", \"Never\"")
          end
          %w[appArmorProfile seccompProfile].each do |profile|
            next if in_status

            nested = fetch(fetch(value, "securityContext"), profile)
            next unless nested.is_a?(Hash)

            type = fetch(nested, "type")
            next if SUPPORTED_APPARMOR.include?(type.to_s) || SUPPORTED_SECCOMP.include?(type.to_s)

            issues << issue(path + %w[securityContext] + [profile, "type"], :unsupported,
                            "supported values: \"Localhost\", \"RuntimeDefault\", \"Unconfined\"")
          end
          # GenericWorkload is disabled in the pinned apiserver defaults.
          # PrepareForCreate drops this field, while PrepareForUpdate keeps it
          # when the old object already used the field.  Mirror that
          # operation-sensitive retention instead of treating every
          # materialized zero-value pointer as user input.
          scheduling_group = fetch(value, "schedulingGroup")
          if !in_status && scheduling_group.is_a?(Hash) &&
             operation == :update && value_at_path(old, path + ["schedulingGroup"]).is_a?(Hash) &&
             blank?(fetch(scheduling_group, "podGroupName"))
            issues << issue(path + %w[schedulingGroup podGroupName], :invalid,
                            "must specify one of: `podGroupName`")
          end
          containers = fetch(value, "containers")
          if !in_status && containers.is_a?(Array)
            containers.each_with_index do |container, index|
              next unless container.is_a?(Hash)

              required(container, "image", path + ["containers", index.to_s], issues)
            end
          end
        end
        issues
      end

      # validateObjectFieldSelector: a downward API fieldPath is either a
      # plain label from the set allowed in that position, or a subscripted
      # `metadata.labels['k']` / `metadata.annotations['k']` whose subscript
      # is a qualified name.  Environment variables and downwardAPI volume
      # items allow different plain labels (a volume may project the whole
      # label or annotation map; an environment variable may not).
      ENV_FIELD_PATHS = %w[metadata.name metadata.namespace metadata.uid spec.nodeName spec.serviceAccountName
                           status.hostIP status.hostIPs status.podIP status.podIPs].freeze
      VOLUME_FIELD_PATHS = %w[metadata.name metadata.namespace metadata.uid metadata.labels metadata.annotations].freeze
      SUBSCRIPTED_FIELD_PATH = /\A(?<path>[^\[]+)\['(?<subscript>.*)'\]\z/

      def object_field_selector_issues(value, path)
        issues = []
        field_path = fetch(value, "fieldPath")
        return issues unless field_path.is_a?(String) && !field_path.empty?

        if (match = SUBSCRIPTED_FIELD_PATH.match(field_path))
          base = match[:path]
          subscript = match[:subscript]
          case base
          when "metadata.annotations"
            issues.concat(qualified_name_messages(subscript.downcase).map { |message| issue(path, :invalid, message) })
          when "metadata.labels"
            issues.concat(qualified_name_messages(subscript).map { |message| issue(path, :invalid, message) })
          else
            issues << issue(path, :invalid, "does not support subscript")
          end
          return issues
        end

        allowed = downward_api_volume_context?(path) ? VOLUME_FIELD_PATHS : ENV_FIELD_PATHS
        unless allowed.include?(field_path)
          issues << issue(path + ["fieldPath"], :unsupported,
                          "supported values: #{allowed.sort.map { |entry| JSON.generate(entry) }.join(", ")}")
        end
        issues
      end

      def downward_api_volume_context?(path)
        path.any? { |segment| segment.to_s == "downwardAPI" } ||
          (path.any? { |segment| segment.to_s == "volumes" } && path.none? { |segment| segment.to_s == "env" })
      end

      # pkg/apis/core/validation ValidatePodCreate (ephemeral containers are a
      # subresource) and validateContainers (names are unique across the
      # container lists).
      def pod_container_set_errors(root, _operation)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        # The create-time ephemeralContainers Forbidden is reported by the
        # PodSpec walk in pod_nested_errors.
        seen = {}
        %w[initContainers containers ephemeralContainers].each do |list|
          Array(fetch(spec, list)).each_with_index do |container, index|
            next unless container.is_a?(Hash)

            name = fetch(container, "name").to_s
            next if name.empty?

            issues << issue(["spec", list, index.to_s, "name"], :duplicate, "") if seen[name]
            seen[name] = true
          end
        end
        issues
      end

      # pkg/apis/core/validation validateResourceClaimNames / pod-level resources:
      # container resources.claims must name entries of spec.resourceClaims;
      # pod-level resources may not carry claims.
      def resource_claim_reference_errors(root, claims, path)
        issues = []
        pod_level = path == %w[spec resources claims]
        issues << issue(path, :forbidden, "claims may not be set for Resources at pod-level") if pod_level
        spec = fetch(root, "spec")
        names = if spec.is_a?(Hash)
                  Array(fetch(spec, "resourceClaims")).filter_map do |entry|
                    entry.is_a?(Hash) ? fetch(entry, "name").to_s : nil
                  end
                else
                  []
                end
        claims.each_with_index do |entry, index|
          name = entry.is_a?(Hash) ? fetch(entry, "name").to_s : ""
          next if !pod_level && names.include?(name)

          detail = names.empty? ? "must be one of the names in pod.spec.resourceClaims which is empty" : "must be one of the names in pod.spec.resourceClaims"
          issues << issue(path + [index.to_s], :not_found, detail)
        end
        issues
      end
    end
  end
end
