# frozen_string_literal: true

module Rubernetes
  module Schema
    # Kubernetes v1.36.2 ValidateProjectedVolumeSource and ValidateProjectionSources.
    module KubernetesValidator
      module_function

      PROJECTION_TYPES = %w[secret configMap downwardAPI serviceAccountToken clusterTrustBundle podCertificate].freeze
      PROJECTION_FEATURE_GATES = {
        "clusterTrustBundle" => "ClusterTrustBundleProjection",
        "podCertificate" => "PodCertificateRequest"
      }.freeze
      PROJECTION_FILE_MODE_DETAIL = "must be a number between 0 and 0777 (octal), both inclusive"
      PROJECTION_CERTIFICATE_KEY_TYPES = %w[RSA3072 RSA4096 ECDSAP256 ECDSAP384 ECDSAP521 ED25519].freeze
      PROJECTION_CERTIFICATE_PATHS = %w[credentialBundlePath keyPath certificateChainPath].freeze
      CONVERTIBLE_DOWNWARD_FIELDS = (ENV_FIELD_PATHS + VOLUME_FIELD_PATHS +
                                    %w[spec.restartPolicy spec.schedulerName status.phase]).uniq.freeze

      def projected_volumes(spec)
        volumes = fetch(spec, "volumes")
        return enum_for(__method__, spec) unless block_given?
        return unless volumes.is_a?(Array)

        volumes.each_with_index do |volume, index|
          projection = fetch(volume, "projected")
          yield projection, index if projection.is_a?(Hash)
        end
      end

      def projection_sources(projection)
        sources = fetch(projection, "sources")
        sources.is_a?(Array) ? sources : []
      end

      def validates_pod_projections?(kind, subresource)
        if kind == "Pod"
          [nil, "", "ephemeralcontainers", "resize"].include?(subresource)
        else
          subresource.to_s.empty? && POD_TEMPLATE_PATHS.key?(kind)
        end
      end

      def projection_strategy_required_field?(kind, field)
        template = kind == "Pod" ? [] : POD_TEMPLATE_PATHS[kind]
        return false unless template

        # The strategy owns requiredness below sources, including the
        # unindexed downwardAPI item paths and unselected fields.
        base = template + %w[spec volumes]
        field.first(base.length) == base && (field[base.length + 1, 2] == %w[projected sources] || field[base.length + 1] == "downwardAPI")
      end

      def stateful_set_rechecked_template_errors(root, old, definition, spread, declarative_options)
        return [] unless old.is_a?(Hash) && definition

        issues = pod_projection_errors(root, old, "StatefulSet") + spread
        return issues if issues.empty?

        # ValidateStatefulSetUpdate tolerates legacy invalid templates, service
        # names, and claim templates. Recheck the stored spec only when the
        # new Pod template would otherwise produce an update error.
        previous_errors = definition.validator.errors(old, operation: :create, old: old, unknown_fields: :preserve, declarative_options: declarative_options)
        legacy = previous_errors.any? do |existing|
          existing.path.first == "spec" && !%w[serviceName volumeClaimTemplates].include?(existing.path[1])
        end
        legacy ? [] : issues
      end

      def pod_projection_errors(root, old, kind)
        base = kind == "Pod" ? [] : POD_TEMPLATE_PATHS[kind]
        return [] unless base

        spec_path = base + ["spec"]
        allow_nonlocal_token_path = projected_volumes(dig_path(old, spec_path)).any? do |projection, _|
          projection_sources(projection).any? do |source|
            !projection_path_messages(fetch(fetch(source, "serviceAccountToken"), "path")).empty?
          end
        end

        issues = []
        spec = dig_path(root, spec_path)
        spec = stateful_set_projection_spec(root, spec) if kind == "StatefulSet"
        Array(fetch(spec, "volumes")).each_with_index do |volume, index|
          path = spec_path + ["volumes", index.to_s]
          if (downward = fetch(volume, "downwardAPI")).is_a?(Hash)
            source_path = path + ["downwardAPI"]
            projection_file_mode_errors(downward, "defaultMode", source_path, issues)
            Array(fetch(downward, "items")).each { |item| projection_downward_item_errors(item, source_path, issues) }
          end
          next unless (projection = fetch(volume, "projected")).is_a?(Hash)

          source_path = path + ["projected"]
          projection_file_mode_errors(projection, "defaultMode", source_path, issues)
          projection_source_errors(projection, source_path, allow_nonlocal_token_path, issues)
        end
        downward_environment_errors(spec, spec_path, issues)
        issues
      end

      def stateful_set_projection_spec(root, spec)
        templates = dig_path(root, %w[spec volumeClaimTemplates])
        return spec unless spec.is_a?(Hash) && templates.is_a?(Array) && !templates.empty?

        names = templates.map { |template| dig_path(template, %w[metadata name]).to_s }.uniq
        # Apps validation replaces same-name volumes with claim volumes and
        # validates the template with those claims at the start of the list.
        volumes = fetch(spec, "volumes")
        return spec unless volumes.is_a?(Array)

        volumes = volumes.reject { |volume| names.include?(fetch(volume, "name").to_s) }
        spec.merge("volumes" => Array.new(names.size) + volumes)
      end

      def projection_source_errors(projection, path, allow_nonlocal_token_path, issues)
        seen = {}
        projection_sources(projection).each_with_index do |source, index|
          source_path = path + ["sources", index.to_s]
          types = PROJECTION_TYPES.select { |type| fetch(source, type).is_a?(Hash) }
          types.each do |type|
            value = fetch(source, type)
            field_path = source_path + [type]
            case type
            when "secret", "configMap"
              required(value, "name", field_path, issues)
              projection_items_errors(value, type, field_path, path, seen, issues)
            when "downwardAPI"
              projection_items_errors(value, type, field_path, path, seen, issues)
            when "serviceAccountToken"
              # Token projections use separate path validation.
              projection_token_errors(value, field_path, path, allow_nonlocal_token_path, issues)
            when "clusterTrustBundle"
              projection_trust_bundle_errors(value, field_path, issues)
              record_projection_path(seen, path, fetch(value, "path").to_s, fetch(value, "path").to_s, issues)
            when "podCertificate"
              projection_certificate_errors(value, field_path, path, seen, issues)
            end
          end
          issues << issue(source_path, :forbidden, "may not specify more than 1 volume type per source") if types.length > 1
        end
      end

      def projection_items_errors(source, type, field_path, projection_path, seen, issues)
        items = fetch(source, "items")
        return unless items.is_a?(Array)

        items.each_with_index do |item, index|
          next unless item.nil? || item.is_a?(Hash)

          item_path = fetch(item, "path")
          if type == "downwardAPI"
            projection_downward_item_errors(item, field_path, issues)
            duplicate_value = item_path
          else
            item_field = field_path + ["items", index.to_s]
            required(item, "key", item_field, issues)
            required(item, "path", item_field, issues)
            validate_projection_path(item_path, item_field + ["path"], issues)
            projection_file_mode_errors(item, "mode", item_field, issues)
            duplicate_value = fetch(source, "name").to_s
          end
          record_projection_path(seen, projection_path, item_path, duplicate_value, issues) if item_path.is_a?(String) && !item_path.empty?
        end
      end

      def projection_downward_item_errors(item, path, issues)
        required(item, "path", path, issues)
        validate_projection_path(fetch(item, "path"), path + ["path"], issues)
        field_ref = fetch(item, "fieldRef")
        resource_ref = fetch(item, "resourceFieldRef")
        if field_ref.is_a?(Hash)
          projection_field_selector_errors(field_ref, path + ["fieldRef"], issues)
          issues << valued_issue(path, "resource", "fieldRef and resourceFieldRef can not be specified simultaneously") if resource_ref.is_a?(Hash)
        elsif resource_ref.is_a?(Hash)
          projection_resource_selector_errors(resource_ref, path + ["resourceFieldRef"], issues)
        else
          issues << issue(path, :required, "one of fieldRef and resourceFieldRef is required")
        end
        projection_file_mode_errors(item, "mode", path, issues)
      end

      def downward_environment_errors(spec, spec_path, issues)
        %w[containers initContainers ephemeralContainers].each do |list|
          Array(fetch(spec, list)).each_with_index do |container, index|
            Array(fetch(container, "env")).each_with_index do |entry, position|
              source = fetch(entry, "valueFrom")
              next unless source.is_a?(Hash)

              path = spec_path + [list, index.to_s, "env", position.to_s, "valueFrom"]
              field = fetch(source, "fieldRef")
              resource = fetch(source, "resourceFieldRef")
              projection_field_selector_errors(field, path + ["fieldRef"], issues, allowed: ENV_FIELD_PATHS) if field.is_a?(Hash)
              projection_resource_selector_errors(resource, path + ["resourceFieldRef"], issues, volume: false) if resource.is_a?(Hash)
            end
          end
        end
      end

      def projection_field_selector_errors(selector, path, issues, allowed: VOLUME_FIELD_PATHS)
        field = fetch(selector, "fieldPath").to_s
        field_path = path + ["fieldPath"]
        return issues << issue(field_path, :required, "") if field.empty?

        version = fetch(selector, "apiVersion")
        parts = field.delete_suffix("']").split("['", 2) if field.end_with?("']")
        label, subscript = parts if parts&.length == 2 && !parts.first.empty?
        detail = if !blank?(version) && version != "v1"
                   "unsupported pod version: #{version}"
                 elsif subscript && !%w[metadata.labels metadata.annotations].include?(label)
                   "field label does not support subscript: #{field}"
                 elsif !subscript && field != "spec.host" && !CONVERTIBLE_DOWNWARD_FIELDS.include?(field)
                   "field label not supported: #{field}"
                 end
        return issues << valued_issue(field_path, field, "error converting fieldPath: #{detail}") if detail

        if subscript
          subscript = subscript.downcase if label == "metadata.annotations"
          qualified_name_messages(subscript).each do |message|
            issues << valued_issue(path, subscript, message)
          end
        else
          field = "spec.nodeName" if field == "spec.host"
          unless allowed.include?(field)
            issues << ValidationIssue.new(path: field_path, code: :unsupported, value: field, kubernetes_type: "Unsupported value",
                                          message: unsupported_detail(allowed.sort))
          end
        end
      end

      def projection_resource_selector_errors(selector, path, issues, volume: true)
        resource = fetch(selector, "resource").to_s
        if volume && blank?(fetch(selector, "containerName"))
          issues << issue(path + ["containerName"], :required, "")
        elsif resource.empty?
          issues << issue(path + ["resource"], :required, "")
        elsif !ResourceHelpers.downward_resource_field?(resource)
          issues << ValidationIssue.new(path: path + ["resource"], code: :unsupported, value: resource,
                                        kubernetes_type: "Unsupported value", message: unsupported_detail(RESOURCE_FIELD_REF_RESOURCES.sort))
        end
        divisor = fetch(selector, "divisor")
        return if divisor.nil? || !ResourceHelpers.downward_resource_field?(resource)

        error = ResourceHelpers.downward_divisor_error(resource, Quantity.from_json(divisor))
        issues << valued_issue(path + ["divisor"], resource, error) if error
      rescue Quantity::ParseError
        # The typed decoder reports malformed quantities before strategy validation.
      end

      def projection_token_errors(token, path, projection_path, allow_nonlocal_token_path, issues)
        seconds = fetch(token, "expirationSeconds")
        if seconds.is_a?(Integer)
          if seconds < 600
            issues << valued_issue(path + ["expirationSeconds"], seconds, "may not specify a duration less than 10 minutes")
          elsif seconds > (1 << 32)
            issues << valued_issue(path + ["expirationSeconds"], seconds, "may not specify a duration larger than 2^32 seconds")
          end
        end
        token_path = fetch(token, "path")
        required(token, "path", projection_path, issues)
        validate_projection_path(token_path, projection_path + ["path"], issues) unless allow_nonlocal_token_path
      end

      def projection_trust_bundle_errors(bundle, path, issues)
        name = fetch(bundle, "name")
        signer = fetch(bundle, "signerName")
        selector = fetch(bundle, "labelSelector")
        if !name.nil? && !signer.nil?
          value = {"Name" => name, "SignerName" => signer, "LabelSelector" => selector,
                   "Optional" => fetch(bundle, "optional"), "Path" => fetch(bundle, "path").to_s}
          issues << valued_issue(path, value, "only one of name and signerName may be used")
        elsif !name.nil?
          required(bundle, "name", path, issues, "must be a valid object name")
          # A colon separates the signer prefix from the DNS subdomain suffix.
          signer_prefix, separator, suffix = name.to_s.rpartition(":")
          messages = if !separator.empty? && signer_prefix.empty?
                       ['ClusterTrustBundle without signer name must not have ":" in its name']
                     else
                       dns1123_subdomain_messages(suffix)
                     end
          messages.each { |message| issues << valued_issue(path + ["name"], name, "not a valid clustertrustbundlename: #{message}") }
          issues << valued_issue(path + ["labelSelector"], selector, "labelSelector must be unset if name is specified") if selector.is_a?(Hash)
        elsif !signer.nil?
          required(bundle, "signerName", path, issues, "must be a valid signer name")
          issues.concat(signer_name_errors(signer, path + ["signerName"]))
          projection_label_selector_errors(selector, path + ["labelSelector"], issues)
        else
          issues << issue(path, :required, "either name or signerName must be specified")
        end
        required(bundle, "path", path, issues)
        validate_projection_path(fetch(bundle, "path"), path + ["path"], issues)
      end

      def projection_label_selector_errors(selector, path, issues)
        return unless selector.is_a?(Hash)

        labels = fetch(selector, "matchLabels")
        if labels.is_a?(Hash)
          labels.each do |key, value|
            label_path = path + ["matchLabels"]
            qualified_name_messages(key).each { |message| issues << valued_issue(label_path, key, message) }
            label_value_messages(value).each { |message| issues << valued_issue(label_path, value, message) }
          end
        end

        expressions = fetch(selector, "matchExpressions")
        return unless expressions.is_a?(Array)

        expressions.each_with_index do |expression, index|
          next unless expression.nil? || expression.is_a?(Hash)

          expression_path = path + ["matchExpressions", index.to_s]
          operator = fetch(expression, "operator").to_s
          values = fetch(expression, "values")
          values = [] unless values.is_a?(Array)
          values_path = expression_path + ["values"]
          case operator
          when "In", "NotIn"
            issues << issue(values_path, :required, "must be specified when `operator` is 'In' or 'NotIn'") if values.empty?
          when "Exists", "DoesNotExist"
            issues << issue(values_path, :forbidden, "may not be specified when `operator` is 'Exists' or 'DoesNotExist'") unless values.empty?
          else
            issues << valued_issue(expression_path + ["operator"], operator, "not a valid selector operator")
          end
          key = fetch(expression, "key").to_s
          qualified_name_messages(key).each { |message| issues << valued_issue(expression_path + ["key"], key, message) }
          values.each_with_index do |value, value_index|
            label_value_messages(value).each do |message|
              issues << valued_issue(values_path + [value_index.to_s], value, message)
            end
          end
        end
      end

      def projection_certificate_errors(certificate, path, projection_path, seen, issues)
        signer = fetch(certificate, "signerName").to_s
        issues.concat(signer_name_errors(signer, path + ["signerName"]))
        projection_certificate_annotation_errors(fetch(certificate, "userAnnotations"), path + ["userAnnotations"], issues)
        key_type = fetch(certificate, "keyType").to_s
        unless PROJECTION_CERTIFICATE_KEY_TYPES.include?(key_type)
          issues << ValidationIssue.new(path: path + ["keyType"], code: :unsupported, value: key_type, kubernetes_type: "Unsupported value",
                                        message: unsupported_detail(PROJECTION_CERTIFICATE_KEY_TYPES))
        end
        expiration = fetch(certificate, "maxExpirationSeconds")
        if expiration.is_a?(Integer)
          host = signer.split("/", 2).first
          maximum = host == "kubernetes.io" || host&.end_with?(".kubernetes.io") ? 86_400 : 91 * 86_400
          if expiration < 3600
            issues << valued_issue(path + ["maxExpirationSeconds"], expiration, "if provided, maxExpirationSeconds must be >= 3600")
          elsif expiration > maximum
            issues << valued_issue(path + ["maxExpirationSeconds"], expiration, "if provided, maxExpirationSeconds must be <= #{maximum}")
          end
        end
        paths = PROJECTION_CERTIFICATE_PATHS.reject { |field| blank?(fetch(certificate, field)) }
        issues << issue(path, :required, "specify at least one of credentialBundlePath, keyPath, and certificateChainPath") if paths.empty?
        paths.each do |field|
          value = fetch(certificate, field)
          next unless value.is_a?(String)

          validate_projection_path(value, path + [field], issues)
          record_projection_path(seen, projection_path, value, value, issues)
        end
      end

      def projection_certificate_annotation_errors(annotations, path, issues)
        return unless annotations.is_a?(Hash)

        size = 0
        annotations.each do |key, value|
          size += key.to_s.bytesize + value.to_s.bytesize
          annotation = key.to_s.downcase
          if annotation.empty?
            issues << issue(path, :required, "")
            next
          end
          messages = qualified_name_messages(annotation)
          messages << 'must be a domain-prefixed key (such as "acme.io/foo")' if messages.empty? && !annotation.include?("/")
          messages.each { |message| issues << valued_issue(path, annotation, message) }
        end
        issues << issue(path, :too_long, "may not be more than 262144 bytes") if size > 262_144
      end

      def projection_file_mode_errors(object, field, path, issues)
        mode = fetch(object, field)
        return unless mode.is_a?(Integer) && !(0..0o777).cover?(mode)

        issues << valued_issue(path + [field], mode, PROJECTION_FILE_MODE_DETAIL)
      end

      def validate_projection_path(value, path, issues)
        projection_path_messages(value).each { |message| issues << valued_issue(path, value, message) }
      end

      def projection_path_messages(value)
        return [] unless value.is_a?(String)

        messages = []
        messages << "must be a relative path" if value.start_with?("/")
        messages << "must not contain '..'" if value.split("/").include?("..")
        messages << "must not start with '..'" if value.start_with?("..") && !value.start_with?("../")
        messages
      end

      def record_projection_path(seen, field, value, duplicate_value, issues)
        issues << valued_issue(field, duplicate_value, "conflicting duplicate paths") if seen.key?(value)
        seen[value] = true
      end

      private_class_method :stateful_set_rechecked_template_errors, :pod_projection_errors, :stateful_set_projection_spec,
                           :projection_source_errors, :projection_items_errors, :projection_downward_item_errors, :projection_field_selector_errors,
                           :downward_environment_errors, :projection_resource_selector_errors, :projection_token_errors, :projection_trust_bundle_errors,
                           :projection_label_selector_errors, :projection_certificate_errors, :projection_certificate_annotation_errors,
                           :projection_file_mode_errors, :validate_projection_path, :projection_path_messages, :record_projection_path
    end
  end
end
