# frozen_string_literal: true

module Rubernetes
  module Schema
    # apiextensions CustomResourceDefinition: group, scope, versions, names,
    # subresources, printer columns and conversion.
    module KubernetesValidator
      module_function

      # A CustomResourceDefinition without its OpenAPI schemas
      # (spec.validation.openAPIV3Schema, spec.versions[*].schema), for the
      # walkers that look for embedded Pod templates.  Other kinds pass as is.
      def schema_free_root(root, kind)
        return root unless kind == "CustomResourceDefinition" && root.is_a?(Hash)

        spec = fetch(root, "spec")
        return root unless spec.is_a?(Hash)

        spec = spec.dup
        spec.delete("validation")
        spec.delete(:validation)
        versions = fetch(spec, "versions")
        if versions.is_a?(Array)
          stripped = versions.map do |version|
            next version unless version.is_a?(Hash)

            version = version.dup
            version.delete("schema")
            version.delete(:schema)
            version
          end
          spec.key?(:versions) ? spec[:versions] = stripped : spec["versions"] = stripped
        end
        root = root.dup
        root.key?(:spec) ? root[:spec] = spec : root["spec"] = spec
        root
      end

      def custom_resource_definition_errors(root, operation = :create)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        if operation == :update
          # ValidateCustomResourceDefinitionUpdate validates the retained
          # status names and stored versions of the stored object.
          status = fetch(root, "status")
          status = {} unless status.is_a?(Hash)
          accepted = fetch(status, "acceptedNames")
          issues.concat(crd_names_errors(accepted, %w[status acceptedNames])) if accepted.is_a?(Hash)
        end
        crd_group_errors(fetch(spec, "group").to_s, issues)
        scope = fetch(spec, "scope").to_s
        if scope.empty?
          issues << issue(%w[spec scope], :required, "")
        elsif !%w[Cluster Namespaced].include?(scope)
          issues << issue(%w[spec scope], :unsupported, unsupported_detail(%w[Cluster Namespaced]))
        end
        versions = fetch(spec, "versions")
        versions = [] unless versions.is_a?(Array)
        crd_versions_errors(versions, issues)
        names = fetch(spec, "names")
        names = {} unless names.is_a?(Hash)
        %w[plural singular kind listKind].each do |field|
          issues << issue(["spec", "names", field], :required, "") if fetch(names, field).to_s.empty?
        end
        issues.concat(crd_names_errors(names, %w[spec names]))
        issues.concat(crd_conversion_errors(fetch(spec, "conversion"), %w[spec conversion]))
        # PrepareForCreate derives status.storedVersions from the storage
        # version; ValidateCustomResourceDefinitionStoredVersions then runs.
        stored = versions.select { |version| version.is_a?(Hash) && fetch(version, "storage") == true }
        issues << issue(%w[status storedVersions], :invalid, "must have at least one stored version") if stored.empty?
        issues
      end

      def crd_group_errors(group, issues)
        return issues << issue(%w[spec group], :required, "") if group.empty?

        messages = dns1123_subdomain_messages(group)
        if !messages.empty?
          issues << issue(%w[spec group], :invalid, messages.join(","))
        elsif group.split(".").length < 2
          issues << issue(%w[spec group], :invalid, "should be a domain with at least one dot")
        end
      end

      # Each version, then the two rules about the list as a whole: version
      # names are unique and exactly one version is the storage version.
      def crd_versions_errors(versions, issues)
        versions.each_with_index do |version, index|
          crd_version_errors(version, index, issues) if version.is_a?(Hash)
        end
        served = versions.grep(Hash)
        names = served.map { |version| fetch(version, "name").to_s }
        issues << issue(%w[spec versions], :invalid, "must contain unique version names") unless names.uniq.length == names.length
        return if served.count { |version| fetch(version, "storage") == true } == 1

        issues << issue(%w[spec versions], :invalid, "must have exactly one version marked as storage version")
      end

      def crd_version_errors(version, index, issues)
        path = ["spec", "versions", index.to_s]
        name = fetch(version, "name").to_s
        messages = dns1035_label_messages(name)
        unless messages.empty?
          issues << issue(path + ["name"], :invalid, messages.join(","))
          # The v1 conversion mirrors the first version name into the
          # internal spec.version field, which is validated as well.
          issues << issue(%w[spec version], :invalid, messages.join(",")) if index.zero? && !name.empty?
        end
        schema = fetch(version, "schema")
        issues << issue(path + %w[schema openAPIV3Schema], :required, "") if !schema.is_a?(Hash) || !fetch(schema, "openAPIV3Schema").is_a?(Hash)
        issues.concat(crd_subresources_errors(fetch(version, "subresources"), path + ["subresources"]))
        Array(fetch(version, "additionalPrinterColumns")).each_with_index do |column, column_index|
          next unless column.is_a?(Hash)

          issues.concat(crd_column_errors(column, path + ["additionalPrinterColumns", column_index.to_s]))
        end
      end

      def crd_names_errors(names, path)
        issues = []
        %w[plural singular].each do |field|
          value = fetch(names, field).to_s
          next if value.empty?

          messages = dns1035_label_messages(value)
          issues << issue(path + [field], :invalid, messages.join(",")) unless messages.empty?
        end
        %w[kind listKind].each do |field|
          value = fetch(names, field).to_s
          next if value.empty?

          messages = dns1035_label_messages(value.downcase)
          unless messages.empty?
            issues << issue(path + [field], :invalid,
                            "may have mixed case, but should otherwise match: #{messages.join(",")}")
          end
        end
        Array(fetch(names, "shortNames")).each_with_index do |short, index|
          messages = dns1035_label_messages(short)
          issues << issue(path + ["shortNames", index.to_s], :invalid, messages.join(",")) unless messages.empty?
        end
        kind = fetch(names, "kind").to_s
        issues << issue(path + ["listKind"], :invalid, "kind and listKind may not be the same") if !kind.empty? && kind == fetch(names,
                                                                                                                                 "listKind").to_s
        Array(fetch(names, "categories")).each_with_index do |category, index|
          messages = dns1035_label_messages(category)
          issues << issue(path + ["categories", index.to_s], :invalid, messages.join(",")) unless messages.empty?
        end
        issues
      end

      def crd_subresources_errors(subresources, path)
        return [] unless subresources.is_a?(Hash)

        scale = fetch(subresources, "scale")
        return [] unless scale.is_a?(Hash)

        issues = []
        {"specReplicasPath" => ".spec", "statusReplicasPath" => ".status"}.each do |field, prefix|
          value = fetch(scale, field).to_s
          if value.empty?
            issues << issue(path + ["scale.#{field}"], :required, "")
          elsif !value.match?(/\A\.[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*\z/)
            issues << issue(path + ["scale.#{field}"], :invalid, "must be a simple json path starting with .")
          elsif !value.start_with?("#{prefix}.")
            issues << issue(path + ["scale.#{field}"], :invalid, "should be a json path under #{prefix}")
          end
        end
        issues
      end

      def crd_column_errors(column, path)
        issues = []
        issues << issue(path + ["name"], :required, "") if fetch(column, "name").to_s.empty?
        types = %w[boolean date integer number string]
        type = fetch(column, "type").to_s
        if type.empty?
          issues << issue(path + ["type"], :required, "must be one of #{types.join(",")}")
        elsif !types.include?(type)
          issues << issue(path + ["type"], :invalid, "must be one of #{types.join(",")}")
        end
        formats = %w[byte date date-time double float int32 int64 password]
        format = fetch(column, "format").to_s
        issues << issue(path + ["format"], :invalid, "must be one of #{formats.join(",")}") if !format.empty? && !formats.include?(format)
        issues << issue(path + ["JSONPath"], :required, "") if fetch(column, "jsonPath").to_s.empty?
        issues
      end

      def crd_conversion_errors(conversion, path)
        return [] unless conversion.is_a?(Hash)

        issues = []
        strategy = fetch(conversion, "strategy").to_s
        webhook = fetch(conversion, "webhook")
        webhook = {} unless webhook.is_a?(Hash)
        client = fetch(webhook, "clientConfig")
        review_versions = Array(fetch(webhook, "conversionReviewVersions"))
        case strategy
        when "None"
          if client.is_a?(Hash)
            issues << issue(path + ["webhookClientConfig"], :forbidden,
                            "should not be set when strategy is not set to Webhook")
          end
          unless review_versions.empty?
            issues << issue(path + ["conversionReviewVersions"], :forbidden,
                            "should not be set when strategy is not set to Webhook")
          end
        when "Webhook"
          if client.is_a?(Hash)
            url = fetch(client, "url")
            service = fetch(client, "service")
            if blank?(url) == !service.is_a?(Hash) ? false : (blank?(url) && !service.is_a?(Hash)) || (!blank?(url) && service.is_a?(Hash))
              issues << issue(path + ["webhookClientConfig"], :required,
                              "exactly one of url or service is required")
            end
          else
            issues << issue(path + ["webhookClientConfig"], :required, "required when strategy is set to Webhook")
          end
          if review_versions.empty?
            issues << issue(path + ["conversionReviewVersions"], :required, "")
          elsif (review_versions & %w[v1 v1beta1]).empty?
            issues << issue(path + ["conversionReviewVersions"], :invalid, "must include at least one of v1, v1beta1")
          end
        else
          issues << issue(path + ["strategy"], :unsupported, unsupported_detail(%w[None Webhook])) unless strategy.empty?
          issues << issue(path + ["strategy"], :required, "") if strategy.empty?
        end
        issues
      end

      private_class_method :crd_group_errors, :crd_versions_errors, :crd_version_errors
    end
  end
end
