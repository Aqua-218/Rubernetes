# frozen_string_literal: true

module Rubernetes
  module Schema
    # Rules for the value-typed helper structs inside a Pod's spec (env
    # sources, lifecycle handlers, volume sources, tolerations, ...), applied
    # to a Pod object only.
    #
    # pod_nested_errors walks the Pod three times -- objects, then lists,
    # then service account token projections -- because that is the order in
    # which the errors are reported.  Each rule appends to the walk's issue
    # list, so a Pod without mistakes allocates nothing per visited node.
    module KubernetesValidator
      module_function

      # What a nested rule needs to know about the Pod it belongs to.
      PodScope = Data.define(:root, :operation, :volume_names)

      RESOURCE_FIELD_REF_RESOURCES = %w[limits.cpu limits.ephemeral-storage limits.memory requests.cpu requests.ephemeral-storage requests.memory].freeze
      POD_CERTIFICATE_KEY_TYPES = %w[RSA3072 RSA4096 ECDSAP256 ECDSAP384 ECDSAP521 ED25519].freeze

      # The core Pod validator owns a large family of value-typed helper
      # structs.  OpenAPI captures their shape but not the one-of/reference
      # rules enforced by ValidatePodSpec.  Walk the materialized Pod graph
      # once and apply those reusable rules by field family.
      def pod_nested_errors(root, operation = :create)
        issues = []
        spec = fetch(root, "spec")
        pod = PodScope.new(root: root, operation: operation, volume_names: pod_volume_names(spec))
        walk(root) do |value, path|
          next if path.include?("status")
          next unless value.is_a?(Hash)
          next if path.last.to_s == "tcpSocket" && unselected_probe_handler?(root, path)

          pod_struct_errors(value, path, pod, issues)
          pod_restart_rules_policy_errors(value, path, issues)
          pod_claim_template_errors(value, path, issues) if path.last.to_s == "volumeClaimTemplate"
        end

        # Array-valued PodSpec fields carry rules at the array's parent path.
        # `walk` yields arrays as well as objects so these checks preserve the
        # Kubernetes field.Index paths and error multiplicity.
        walk(root) do |value, path|
          next if path.include?("status")
          next unless value.is_a?(Array)

          pod_list_errors(value, path, pod, issues)
        end

        pod_service_account_token_errors(root, spec, issues)
        issues
      end

      def pod_volume_names(spec)
        return [] unless spec.is_a?(Hash) && fetch(spec, "volumes").is_a?(Array)

        fetch(spec, "volumes").filter_map do |volume|
          fetch(volume, "name") if volume.is_a?(Hash)
        end.map(&:to_s)
      end

      # Probe/LifecycleHandler one-of validation selects the first
      # populated handler and does not descend into later handlers.
      # Value-typed Pod fixtures materialize all handler structs, so a
      # tcpSocket sibling under an exec/httpGet probe is not user input
      # and must not produce a synthetic port error.  A direct
      # TCPSocketAction fixture has tcpSocket as the selected handler.
      def unselected_probe_handler?(root, path)
        handler_parent = value_at_path(root, path[0...-1])
        return false unless handler_parent.is_a?(Hash)

        selected = PROBE_HANDLERS.find { |name| !fetch(handler_parent, name).nil? }
        !(selected.nil? || selected == "tcpSocket")
      end

      # The rule of one object, chosen by the field that holds it.
      def pod_struct_errors(value, path, pod, issues)
        case path.last.to_s
        when "configMapRef", "secretRef" then pod_local_reference_errors(value, path, issues)
        when "configMapKeyRef", "secretKeyRef" then pod_key_selector_errors(value, path, issues)
        when "fileKeyRef" then pod_file_key_errors(value, path, pod, issues)
        when "resourceFieldRef" then pod_resource_field_errors(value, path, issues)
        when "fieldRef" then issues.concat(object_field_selector_issues(value, path))
        when "valueFrom" then pod_env_value_source_errors(value, path, issues)
        when "envFrom" then pod_env_from_source_errors(value, path, issues)
        when "postStart", "preStop", "livenessProbe", "readinessProbe", "startupProbe"
          issues << issue(path, :required, "must specify a handler type") if value.empty?
        when "tcpSocket" then pod_tcp_socket_errors(value, path, issues)
        when "iscsi" then pod_iscsi_errors(value, path, issues)
        when "image" then required(value, "reference", path, issues)
        when "scaleIO", "storageos" then required(value, "volumeName", path, issues)
        when "configMap" then required(value, "name", path, issues)
        when "secret" then pod_secret_source_errors(value, path, issues)
        when "downwardAPI" then pod_downward_api_errors(value, path, issues)
        when "ephemeral" then required(value, "volumeClaimTemplate", path, issues)
        when "podCertificate" then (pod_certificate_projection_errors(value, path, issues) if pod.operation == :update)
        when "clusterTrustBundle" then (pod_trust_bundle_projection_errors(value, path, issues) if pod.operation == :update)
        end
      end

      # ---- env and envFrom sources ------------------------------------------

      def pod_local_reference_errors(value, path, issues)
        # ScaleIO's secretRef is an optional LocalObjectReference.
        # Empty value-typed references are accepted by ValidatePodSpec.
        return if path.last.to_s == "secretRef" && path.include?("scaleIO") && value.empty?

        required(value, "name", path, issues)
      end

      def pod_key_selector_errors(value, path, issues)
        name = fetch(value, "name")
        return if name.is_a?(String) && name.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/)

        issues << issue(path + ["name"], :invalid, DNS1123_SUBDOMAIN_MSG)
      end

      def pod_file_key_errors(value, path, pod, issues)
        volume_name = fetch(value, "volumeName")
        issues << issue(path + ["volumeName"], :not_found, "") unless pod.volume_names.include?(volume_name.to_s)
      end

      def pod_resource_field_errors(value, path, issues)
        resource = fetch(value, "resource")
        return if RESOURCE_FIELD_REF_RESOURCES.include?(resource.to_s)

        issues << issue(path + ["resource"], :unsupported,
                        "supported values: #{RESOURCE_FIELD_REF_RESOURCES.map { |entry| JSON.generate(entry) }.join(", ")}")
      end

      def pod_env_value_source_errors(value, path, issues)
        alternatives = %w[fieldRef resourceFieldRef configMapKeyRef secretKeyRef fileKeyRef]
        return if alternatives.any? { |name| fetch(value, name).is_a?(Hash) }

        issues << issue(path, :invalid,
                        "must specify one of: `fieldRef`, `resourceFieldRef`, `configMapKeyRef`, `secretKeyRef` or `fileKeyRef`")
      end

      def pod_env_from_source_errors(value, path, issues)
        return if %w[configMapRef secretRef].any? { |name| fetch(value, name).is_a?(Hash) }

        issues << issue(path, :invalid, "must specify one of: `configMapRef` or `secretRef`")
      end

      # ---- probe and lifecycle handlers -------------------------------------

      def pod_tcp_socket_errors(value, path, issues)
        port = fetch(value, "port")
        # A zero-value IntOrString port is represented by an omitted
        # field in the request.  ValidateProbe reports the parent
        # handler's structural error, not a synthetic child error, until
        # a concrete numeric port was supplied.
        issues << issue(path + ["port"], :invalid, "must contain at least one letter (a-z)") if !port.nil? && port.is_a?(String) && port.match?(/\A\d+\z/)
      end

      # ---- volume sources ---------------------------------------------------

      def pod_iscsi_errors(value, path, issues)
        iqn = fetch(value, "iqn")
        return if iqn.is_a?(String) && iqn.match?(/\A(?:iqn|eui|naa)/)

        issues << issue(path + ["iqn"], :invalid, "must be valid format starting with iqn, eui, or naa")
      end

      def pod_secret_source_errors(value, path, issues)
        # ScaleIO's secretRef is an optional LocalObjectReference.  The
        # zero-value reference is accepted by ValidatePodSpec; it is not
        # the SecretVolumeSource/SecretProjection secretName field.
        return if path.include?("scaleIO") && value.empty?

        if value.key?("secretName") || !path.include?("projected")
          required(value, "secretName", path, issues)
        else
          required(value, "name", path, issues)
        end
      end

      def pod_downward_api_errors(value, path, issues)
        # ValidatePodSpec reports the one-of error on a downwardAPI
        # volume source only when it contains an item.  A zero-value
        # DownwardAPIVolumeSource/Projection is accepted, and projected
        # sources have their own per-item checks.
        items = fetch(value, "items")
        return unless !path.include?("projected") && items.is_a?(Array) && !items.empty?

        invalid_item = items.any? do |item|
          item.is_a?(Hash) && %w[fieldRef resourceFieldRef].none? { |name| fetch(item, name).is_a?(Hash) }
        end
        issues << issue(path, :required, "one of fieldRef and resourceFieldRef is required") if invalid_item
      end

      # Update only: a created Pod's projection is validated by the schema.
      def pod_certificate_projection_errors(value, path, issues)
        paths = %w[credentialBundlePath keyPath certificateChainPath]
        unless paths.any? { |name| !blank?(fetch(value, name)) }
          issues << issue(path, :required, "specify at least one of credentialBundlePath, keyPath, and certificateChainPath")
        end
        key_type = fetch(value, "keyType")
        unless POD_CERTIFICATE_KEY_TYPES.include?(key_type.to_s)
          issues << issue(path + ["keyType"], :unsupported,
                          "supported values: #{POD_CERTIFICATE_KEY_TYPES.map { |entry| JSON.generate(entry) }.join(", ")}")
        end
        signer = fetch(value, "signerName")
        return if signer.is_a?(String) && signer.match?(%r{\A[a-z0-9.-]+/[a-z0-9][a-z0-9.-]*\z})

        issues << issue(path + ["signerName"], :invalid,
                        "must be a fully qualified domain and path of the form 'example.com/signer-name'")
      end

      def pod_trust_bundle_projection_errors(value, path, issues)
        return unless blank?(fetch(value, "name")) && blank?(fetch(value, "signerName"))

        issues << issue(path, :required, "either name or signerName must be specified")
      end

      # Empty PVC templates in an ephemeral volume are validated as PVC
      # specs by the core Pod validator.
      def pod_claim_template_errors(value, path, issues)
        pvc_spec = fetch(value, "spec")
        pvc_spec = {} unless pvc_spec.is_a?(Hash)
        modes = fetch(pvc_spec, "accessModes")
        unless modes.is_a?(Array) && !modes.empty?
          issues << issue(path + %w[spec accessModes], :required,
                          "at least 1 access mode is required")
        end
        resources = fetch(pvc_spec, "resources")
        requests = resources.is_a?(Hash) ? fetch(resources, "requests") : nil
        issues << issue(path + %w[spec resources [storage]], :required, "") unless requests.is_a?(Hash) && provided?(fetch(requests, "storage"))
      end

      # ---- containers -------------------------------------------------------

      # A restart rule requires an explicit container restart policy.
      def pod_restart_rules_policy_errors(value, path, issues)
        rules = fetch(value, "restartPolicyRules")
        return unless rules.is_a?(Array) && !rules.empty? && blank?(fetch(value, "restartPolicy"))

        issues << issue(path + ["restartPolicy"], :required,
                        "must specify restartPolicy when restart rules are used")
      end

      # The rule of one list, chosen by the field that holds it.
      def pod_list_errors(list, path, pod, issues)
        case path.last.to_s
        when "resizePolicy" then pod_resize_policy_errors(list, path, issues)
        when "restartPolicyRules" then pod_restart_rule_errors(list, path, issues)
        when "volumeMounts", "volumeDevices" then pod_volume_reference_errors(list, path, pod, issues)
        when "envFrom" then pod_env_from_list_errors(list, path, issues)
        when "hostAliases" then pod_host_alias_errors(list, path, issues)
        when "tolerations" then pod_toleration_errors(list, path, pod, issues)
        when "topologySpreadConstraints" then pod_topology_spread_errors(list, path, issues)
        when "options" then pod_dns_option_errors(list, path, issues)
        when "resourceClaims" then pod_resource_claim_source_errors(list, path, issues)
        when "claims" then (issues.concat(resource_claim_reference_errors(pod.root, list, path)) if path[-2] == "resources")
        when "ephemeralContainers" then pod_ephemeral_container_errors(list, path, pod, issues)
        end
      end

      def pod_resize_policy_errors(list, path, issues)
        list.each do |policy|
          next unless policy.is_a?(Hash)

          resource = fetch(policy, "resourceName")
          restart = fetch(policy, "restartPolicy")
          issues << issue(path, :unsupported, "supported values: \"cpu\", \"memory\"") unless %w[cpu memory].include?(resource.to_s)
          unless %w[NotRequired RestartContainer].include?(restart.to_s)
            issues << issue(path, :unsupported, "supported values: \"NotRequired\", \"RestartContainer\"")
          end
        end
      end

      def pod_restart_rule_errors(list, path, issues)
        list.each_with_index do |rule, index|
          next unless rule.is_a?(Hash)

          rule_path = path + [index.to_s]
          action = fetch(rule, "action")
          unless %w[Restart RestartAllContainers].include?(action.to_s)
            issues << issue(rule_path + ["action"], :unsupported,
                            "supported values: \"Restart\", \"RestartAllContainers\"")
          end
          exit_codes = fetch(rule, "exitCodes")
          if exit_codes.is_a?(Hash)
            operator = fetch(exit_codes, "operator")
            unless %w[In NotIn].include?(operator.to_s)
              issues << issue(rule_path + %w[exitCodes operator], :unsupported,
                              "supported values: \"In\", \"NotIn\"")
            end
          else
            issues << issue(rule_path + ["exitCodes"], :required, "must be specified")
          end
        end
      end

      def pod_volume_reference_errors(list, path, pod, issues)
        list.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          name = fetch(entry, "name")
          issues << issue(path + [index.to_s, "name"], :not_found, "") unless pod.volume_names.include?(name.to_s)
        end
      end

      # EnvFromSource is a list element, but the one-of validation is
      # attached to the list field (not to configMapRef/secretRef).
      def pod_env_from_list_errors(list, path, issues)
        list.each do |entry|
          next unless entry.is_a?(Hash)

          pod_env_from_source_errors(entry, path, issues)
        end
      end

      # ---- pod-level lists --------------------------------------------------

      def pod_host_alias_errors(list, path, issues)
        list.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          issues.concat(ip_field_issues(path + [index.to_s, "ip"], fetch(entry, "ip")))
        end
      end

      def pod_toleration_errors(list, path, pod, issues)
        list.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          next unless blank?(fetch(entry, "key")) && fetch(entry, "operator").to_s != "Exists"

          count = pod.operation == :update ? 2 : 1
          count.times do
            issues << issue(path + [index.to_s, "operator"], :invalid,
                            "operator must be Exists when `key` is empty, which means \"match all values and all keys\"")
          end
        end
      end

      def pod_topology_spread_errors(list, path, issues)
        list.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          unless %w[DoNotSchedule ScheduleAnyway].include?(fetch(entry, "whenUnsatisfiable").to_s)
            issues << issue(path + [index.to_s, "whenUnsatisfiable"], :unsupported,
                            "supported values: \"DoNotSchedule\", \"ScheduleAnyway\"")
          end
        end
      end

      def pod_dns_option_errors(list, path, issues)
        list.each_with_index do |entry, index|
          issues << issue(path + [index.to_s], :required, "must not be empty") if entry.is_a?(Hash) && entry.empty?
        end
      end

      def pod_resource_claim_source_errors(list, path, issues)
        list.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          names = %w[resourceClaimName resourceClaimTemplateName]
          unless names.any? { |name| !blank?(fetch(entry, name)) }
            issues << issue(path + [index.to_s], :invalid,
                            "must specify one of: `resourceClaimName`, `resourceClaimTemplateName`")
          end
        end
      end

      def pod_ephemeral_container_errors(list, path, pod, issues)
        issues << issue(path, :forbidden, "cannot be set on create") if pod.operation == :create
        list.each_with_index do |entry, index|
          required(entry, "image", path + [index.to_s], issues) if entry.is_a?(Hash)
        end
      end

      # ServiceAccountTokenProjection is forbidden unless the containing Pod
      # names a service account.
      def pod_service_account_token_errors(root, spec, issues)
        service_account_name = spec.is_a?(Hash) ? fetch(spec, "serviceAccountName") : nil
        return unless blank?(service_account_name)

        walk(root) do |value, path|
          next unless value.is_a?(Hash) && path.last.to_s == "serviceAccountToken"

          issues << issue(path, :forbidden, "must not be specified when serviceAccountName is not set")
        end
      end

      private_class_method :pod_volume_names, :unselected_probe_handler?, :pod_struct_errors, :pod_local_reference_errors,
                           :pod_key_selector_errors, :pod_file_key_errors, :pod_resource_field_errors, :pod_env_value_source_errors,
                           :pod_env_from_source_errors, :pod_tcp_socket_errors, :pod_iscsi_errors, :pod_secret_source_errors,
                           :pod_downward_api_errors, :pod_certificate_projection_errors, :pod_trust_bundle_projection_errors,
                           :pod_claim_template_errors, :pod_restart_rules_policy_errors, :pod_list_errors, :pod_resize_policy_errors,
                           :pod_restart_rule_errors, :pod_volume_reference_errors, :pod_env_from_list_errors, :pod_host_alias_errors,
                           :pod_toleration_errors, :pod_topology_spread_errors, :pod_dns_option_errors,
                           :pod_resource_claim_source_errors, :pod_ephemeral_container_errors, :pod_service_account_token_errors
    end
  end
end
