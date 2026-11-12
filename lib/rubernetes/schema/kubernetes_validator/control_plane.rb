# frozen_string_literal: true

module Rubernetes
  module Schema
    # Kinds the control plane keeps about itself: APIService, StorageVersion,
    # StorageVersionMigration and LeaseCandidate.
    module KubernetesValidator
      module_function

      def api_service_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        group = fetch(spec, "group")
        version = fetch(spec, "version")
        if blank?(group) && version.to_s != "v1"
          issues << issue(%w[spec group], :required,
                          "only v1 may have an empty group and it better be legacy kube")
        end
        issues << issue(%w[spec version], :invalid, DNS1035_LABEL_MSG) unless version.is_a?(String) && version.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)
        group_priority = fetch(spec, "groupPriorityMinimum")
        if !group_priority.is_a?(Numeric) || group_priority <= 0 || group_priority > 20_000
          issues << issue(%w[spec groupPriorityMinimum], :invalid, "must be positive and less than 20000")
        end
        version_priority = fetch(spec, "versionPriority")
        if !version_priority.is_a?(Numeric) || version_priority <= 0 || version_priority > 1000
          issues << issue(%w[spec versionPriority], :invalid, "must be positive and less than 1000")
        end
        service = fetch(spec, "service")
        if service.is_a?(Hash)
          required(service, "name", %w[spec service], issues)
          required(service, "namespace", %w[spec service], issues)
        end
        issues
      end

      def storage_version_errors(root)
        status = fetch(root, "status")
        return [] unless status.is_a?(Hash)

        issues = []
        entries = Array(fetch(status, "storageVersions"))
        seen = {}
        entries.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          base = ["status", "storageVersions", index.to_s]
          server = fetch(entry, "apiServerID").to_s
          if seen[server]
            issues << issue(base + ["apiServerID"], :duplicate, "")
          else
            seen[server] = true
          end
          server_storage_version_errors(entry, server, base, issues)
        end
        common_encoding_version_errors(status, entries, issues)
        storage_version_condition_errors(status, issues)
        issues
      end

      # One API server's entry: its ID, and that it can decode what it
      # encodes and serves.
      def server_storage_version_errors(entry, server, base, issues)
        issues.concat(invalid_messages(base + ["apiServerID"], dns1123_subdomain_messages(server)))
        encoding = fetch(entry, "encodingVersion").to_s
        messages = api_version_messages(encoding)
        issues << issue(base + ["encodingVersion"], :invalid, messages.join(",")) unless messages.empty?
        decodable = Array(fetch(entry, "decodableVersions"))
        decodable.each_with_index do |version, version_index|
          messages = api_version_messages(version)
          issues << issue(base + ["decodableVersions", version_index.to_s], :invalid, messages.join(",")) unless messages.empty?
        end
        unless decodable.include?(encoding)
          issues << issue(base + ["decodableVersions"], :invalid,
                          "decodableVersions must include encodingVersion #{encoding}")
        end
        Array(fetch(entry, "servedVersions")).each_with_index do |version, version_index|
          messages = api_version_messages(version)
          issues << issue(base + ["servedVersions", version_index.to_s], :invalid, messages.join(",")) unless messages.empty?
          unless decodable.include?(version)
            issues << issue(base + ["servedVersions", version_index.to_s], :invalid,
                            "individual served version : #{version} must be included in decodableVersions : #{decodable.inspect.tr(",", "")}")
          end
        end
      end

      # status.commonEncodingVersion is set exactly when every server
      # reports the same encoding version.
      def common_encoding_version_errors(status, entries, issues)
        encodings = entries.grep(Hash).map { |entry| fetch(entry, "encodingVersion").to_s }
        actual_common = encodings.empty? || encodings.uniq.length != 1 ? nil : encodings.first
        common = fetch(status, "commonEncodingVersion")
        if actual_common.nil? && !common.nil?
          issues << issue(%w[status commonEncodingVersion], :invalid,
                          "should be nil if servers do not agree on the same encoding version, or if there is no server reporting the supported versions yet")
        elsif !actual_common.nil? && common.nil?
          issues << issue(%w[status commonEncodingVersion], :invalid, "the common encoding version is #{actual_common}")
        elsif !actual_common.nil? && !common.nil? && actual_common != common.to_s
          issues << issue(%w[status commonEncodingVersion], :invalid, "the actual common encoding version is #{actual_common}")
        end
      end

      def storage_version_condition_errors(status, issues)
        seen_types = {}
        Array(fetch(status, "conditions")).each_with_index do |condition, index|
          next unless condition.is_a?(Hash)

          base = ["status", "conditions", index.to_s]
          type = fetch(condition, "type").to_s
          if seen_types.key?(type)
            issues << issue(base + ["type"], :invalid,
                            "the type of the condition is not unique, it also appears in conditions[#{seen_types[type]}]")
          end
          seen_types[type] = index
          issues.concat(invalid_messages(base + ["type"], qualified_name_messages(type)))
          issues.concat(invalid_messages(base + ["status"], qualified_name_messages(fetch(condition, "status").to_s)))
          issues << issue(base + ["reason"], :required, "") if fetch(condition, "reason").to_s.empty?
          issues << issue(base + ["message"], :required, "") if fetch(condition, "message").to_s.empty?
        end
      end

      def api_version_messages(value)
        value = value.to_s
        parts = value.split("/", -1)
        messages = []
        case parts.length
        when 1
          version = parts[0]
        when 2
          group, version = parts
          if group.empty?
            messages << "group part: must be non-empty"
          else
            messages.concat(dns1123_subdomain_messages(group).map { |message| "group part: #{message}" })
          end
        else
          return ["an apiVersion is a DNS-1035 label, which must consist of lower case alphanumeric characters or '-', start with an alphabetic character, " \
                  "and end with an alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?') with " \
                  "an optional DNS subdomain prefix and '/' (e.g. 'example.com/MyVersion')"]
        end
        if version.empty?
          messages << "version part: must be non-empty"
        else
          messages.concat(dns1035_label_messages(version).map { |message| "version part: #{message}" })
        end
        messages
      end

      def storage_version_migration_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        resource = fetch(spec, "resource")
        resource = {} unless resource.is_a?(Hash)
        value = fetch(resource, "resource")
        return [issue(%w[spec resource resource], :required, "resource is required to be set")] if blank?(value)
        return [] if value.is_a?(String) && value.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)

        [issue(%w[spec resource resource], :invalid, DNS1035_LABEL_MSG)]
      end

      def lease_candidate_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        binary_version = fetch(spec, "binaryVersion")
        if !blank?(binary_version) && !binary_version.to_s.match?(/\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z/)
          issues << issue(%w[spec binaryVersion], :invalid, "must be a valid semantic version")
        end
        strategy = fetch(spec, "strategy")
        value = strategy.is_a?(Hash) ? fetch(strategy, "strategy") : strategy
        if !blank?(value) && value.to_s != "OldestEmulationVersion"
          issues << issue(%w[spec strategy strategy], :unsupported,
                          "supported values: \"OldestEmulationVersion\"")
        end
        issues
      end

      private_class_method :server_storage_version_errors, :common_encoding_version_errors, :storage_version_condition_errors
    end
  end
end
