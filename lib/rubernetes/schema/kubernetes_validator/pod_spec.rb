# frozen_string_literal: true

require_relative "../probe_timing"

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
      RECURSIVE_READ_ONLY_MODES = %w[Disabled Enabled IfPossible].freeze
      HOSTNAME_OVERRIDE_GATE = "HostnameOverride"

      def pod_hostname_override_errors(root, kind)
        base = kind == "Pod" ? [] : POD_TEMPLATE_PATHS[kind]
        return [] unless base

        spec_path = base + ["spec"]
        spec = dig_path(root, spec_path)
        hostname = fetch(spec, "hostnameOverride")
        return [] unless hostname.is_a?(String)

        path = spec_path + ["hostnameOverride"]
        errors = %w[setHostnameAsFQDN hostNetwork].filter_map do |field|
          issue(path, :forbidden, "may not be specified when #{field} is true") if fetch(spec, field) == true
        end
        errors << issue(path, :too_long, "may not be more than 64 bytes") if hostname.bytesize > 64
        errors.concat(invalid_messages(path, dns1123_subdomain_messages(hostname)))
      end

      def probe_errors(root, kind)
        issues = []
        base = kind == "Pod" ? [] : POD_TEMPLATE_PATHS[kind]
        spec_path = base + ["spec"] if base
        walk(root) do |value, path|
          next unless value.is_a?(Hash) && !path.include?("status")

          if path == spec_path
            pod_spec_probe_errors(value, path, issues)
          elsif !pod_container_probe_path?(path, spec_path)
            probe_handler_errors(value, path, issues)
          end
        end
        issues
      end

      def pod_container_probe_path?(path, spec_path)
        spec_path && ProbeTiming::FIELDS.include?(path.last) && %w[containers initContainers].include?(path[-3]) &&
          path.length == spec_path.length + 3 && path.take(spec_path.length) == spec_path
      end

      # Follow the order of ValidateContainers and ValidateInitContainers.
      def pod_spec_probe_errors(spec, path, issues)
        %w[containers initContainers].each do |field|
          Array(fetch(spec, field)).each_with_index do |container, index|
            allowed = field != "initContainers" || fetch(container, "restartPolicy") == "Always"
            ProbeTiming::FIELDS.each do |name|
              probe = fetch(container, name)
              next unless probe.is_a?(Hash)

              probe_path = path + [field, index, name]
              if allowed
                probe_handler_errors(probe, probe_path, issues, required: true)
                ProbeTiming.errors(probe, probe_path).each do |error|
                  issues << ValidationIssue.new(path: error.path, code: :invalid, value: error.value, message: error.message)
                end
              else
                issues << issue(probe_path, :forbidden, ProbeTiming::INIT_CONTAINER_DETAIL)
              end
            end
          end
        end
      end

      def probe_handler_errors(value, path, issues, required: false)
        present = PROBE_HANDLERS.reject { |name| fetch(value, name).nil? }
        if present.empty?
          issues << issue(path, :required, "must specify a handler type") if required
          return
        end

        # The first populated handler is selected in the API struct's order.
        # Do not descend into handlers that are rejected by this one-of check.
        present.drop(1).each { |name| issues << issue(path + [name], :forbidden, PROBE_HANDLER_DETAIL) }
        exec = fetch(value, "exec")
        if present.first == "exec" && exec.is_a?(Hash) &&
           (!exec.key?("command") || blank_array?(fetch(exec, "command")))
          issues << issue(path + %w[exec command], :required, "")
        end
        http = fetch(value, "httpGet")
        return unless present.first == "httpGet" && http.is_a?(Hash)

        port = fetch(http, "port")
        if port.nil? || (port.is_a?(Integer) && !(1..65_535).cover?(port))
          issues << issue(path + %w[httpGet port], :invalid, "must be between 1 and 65535, inclusive")
        elsif port.is_a?(String) && port.match?(/\A\d+\z/)
          issues << issue(path + %w[httpGet port], :invalid, "must contain at least one letter (a-z)")
        end
      end

      def common_pod_errors(root, operation = :create, old = nil)
        issues = []
        walk(root) do |value, path|
          if path.last == "volumeMounts" && %w[containers initContainers ephemeralContainers].include?(path[-3]) &&
             value.is_a?(Array) && !path.include?("status")
            recursive_mount_errors(value, path + ["recursiveReadOnly"], issues)
          end
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

      # validateMountRecursiveReadOnly: the issue belongs to the mount list.
      def recursive_mount_errors(mounts, path, issues)
        mounts.each do |mount|
          mode = fetch(mount, "recursiveReadOnly")
          next if mode.nil? || mode == "Disabled"

          unless RECURSIVE_READ_ONLY_MODES.include?(mode)
            issues << ValidationIssue.new(path: path, code: :unsupported, value: mode, kubernetes_type: "Unsupported value",
                                          message: unsupported_detail(RECURSIVE_READ_ONLY_MODES))
            next
          end
          issues << issue(path, :forbidden, "may only be specified when readOnly is true") unless fetch(mount, "readOnly") == true
          propagation = fetch(mount, "mountPropagation")
          next if propagation.nil? || propagation == "None"

          issues << issue(path, :forbidden, "may only be specified when mountPropagation is None or not specified")
        end
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
