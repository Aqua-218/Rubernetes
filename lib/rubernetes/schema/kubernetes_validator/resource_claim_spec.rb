# frozen_string_literal: true

require_relative "../../dra/legacy_device_request"
require_relative "../declarative_rules"

module Rubernetes
  module Schema
    # resource.k8s.io ResourceClaim and ResourceClaimTemplate specs
    # (pkg/apis/resource/validation validateDeviceClaim).
    module KubernetesValidator
      module_function

      def resource_claim_errors(root, spec_path)
        spec = spec_path.reduce(root) { |current, segment| current.is_a?(Hash) ? fetch(current, segment) : nil }
        return [] unless spec.is_a?(Hash)

        devices = fetch(spec, "devices")
        return [] unless devices.is_a?(Hash)

        path = spec_path + ["devices"]
        requests = Array(fetch(devices, "requests"))
        request_names = dra_request_names(requests)
        issues = dra_request_list_errors(requests, path + ["requests"])
        issues.concat(dra_constraint_list_errors(Array(fetch(devices, "constraints")), path + ["constraints"], request_names))
        issues.concat(dra_config_list_errors(Array(fetch(devices, "config")), path + ["config"], request_names))
        issues
      end

      # request name => the names of its firstAvailable subrequests: what a
      # constraint or a config may refer to.
      def dra_request_names(requests)
        requests.each_with_object({}) do |request, names|
          next unless request.is_a?(Hash)

          subrequests = Array(fetch(request, "firstAvailable")).grep(Hash)
          names[fetch(request, "name").to_s] = subrequests.map { |sub| fetch(sub, "name").to_s }
        end
      end

      def dra_request_list_errors(requests, path)
        issues = []
        issues << issue(path, :too_many, "must have at most 32 items") if requests.length > 32
        seen = {}
        requests.each_with_index do |request, index|
          next unless request.is_a?(Hash)

          base = path + [index.to_s]
          name = fetch(request, "name").to_s
          issues.concat(dra_request_name_errors(name, base + ["name"]))
          issues << issue(base + ["name"], :duplicate, "") if seen[name]
          seen[name] = true
          issues.concat(dra_request_choice_errors(request, base))
        end
        issues
      end

      # A request is either one exact request or a list of alternatives.
      def dra_request_choice_errors(request, base)
        first_available = fetch(request, "firstAvailable")
        exactly = dra_exact_request(request)
        has_first = first_available.is_a?(Array) && !first_available.empty?
        has_exactly = exactly.is_a?(Hash)
        if !has_first && !has_exactly
          [issue(base, :required, "exactly one of `exactly` or `firstAvailable` is required")]
        elsif has_first && has_exactly
          [issue(base, :invalid, "exactly one of `exactly` or `firstAvailable` is required, but multiple fields are set")]
        elsif has_first
          dra_subrequest_list_errors(first_available, base + ["firstAvailable"])
        else
          dra_device_request_body_errors(exactly, base + ["exactly"])
        end
      end

      def dra_exact_request(request)
        exactly = fetch(request, "exactly")
        return exactly unless exactly.nil?

        # v1beta1 carries the exact request fields inline on the request;
        # conversion materializes Exactly when any of them is set.
        inline = request.transform_keys(&:to_s).slice(*DRA::LegacyDeviceRequest::FIELDS)
        inline if DRA::LegacyDeviceRequest.fields_set?(inline)
      end

      def dra_subrequest_list_errors(first_available, path)
        issues = []
        issues << issue(path, :too_many, "must have at most 8 items") if first_available.length > 8
        seen = {}
        first_available.each_with_index do |sub, sub_index|
          next unless sub.is_a?(Hash)

          sub_base = path + [sub_index.to_s]
          sub_name = fetch(sub, "name").to_s
          issues.concat(dra_request_name_errors(sub_name, sub_base + ["name"]))
          issues << issue(sub_base + ["name"], :duplicate, "") if seen[sub_name]
          seen[sub_name] = true
          issues.concat(dra_device_request_body_errors(sub, sub_base))
        end
        issues
      end

      def dra_constraint_list_errors(constraints, path, request_names)
        issues = []
        issues << issue(path, :too_many, "must have at most 32 items") if constraints.length > 32
        constraints.each_with_index do |constraint, index|
          next unless constraint.is_a?(Hash)

          base = path + [index.to_s]
          issues.concat(dra_request_reference_errors(fetch(constraint, "requests"), base + ["requests"], request_names))
          match = fetch(constraint, "matchAttribute")
          distinct = fetch(constraint, "distinctAttribute")
          if !match.nil?
            issues.concat(dra_fully_qualified_name_errors(match, base + ["matchAttribute"]))
          elsif !distinct.nil?
            issues.concat(dra_fully_qualified_name_errors(distinct, base + ["distinctAttribute"]))
          else
            issues << issue(base, :required,
                            "exactly one of \"matchAttribute\" or \"distinctAttribute\" is required, but multiple fields are set")
          end
        end
        issues
      end

      def dra_config_list_errors(configs, path, request_names)
        issues = []
        issues << issue(path, :too_many, "must have at most 32 items") if configs.length > 32
        configs.each_with_index do |config, index|
          next unless config.is_a?(Hash)

          base = path + [index.to_s]
          issues.concat(dra_request_reference_errors(fetch(config, "requests"), base + ["requests"], request_names))
          issues.concat(dra_device_configuration_errors(config, base))
        end
        issues
      end

      def dra_request_name_errors(name, path)
        return [issue(path, :required, "")] if name.empty?

        invalid_messages(path, dns1123_label_messages(name))
      end

      def dra_fully_qualified_name_errors(name, path)
        name = name.to_s
        parts = name.split("/", -1)
        return [issue(path, :invalid, "a fully qualified name must be a domain and a name separated by a slash")] unless parts.length == 2

        domain, identifier = parts
        issues = invalid_messages(path, dns1123_subdomain_messages(domain))
        issues << issue(path, :too_long, "may not be more than 32 bytes") if identifier.bytesize > 32
        issues << issue(path, :invalid, DeclarativeRules::C_IDENTIFIER_MESSAGE) unless identifier.match?(DeclarativeRules::C_IDENTIFIER)
        issues
      end

      def dra_request_reference_errors(references, path, request_names)
        return [] unless references.is_a?(Array)

        issues = []
        issues << issue(path, :too_many, "must have at most 32 items") if references.length > 32
        seen = {}
        references.each_with_index do |reference, index|
          reference = reference.to_s
          base = path + [index.to_s]
          segments = reference.split("/", -1)
          if segments.length > 2
            issues << issue(base, :invalid,
                            "must be the name of a request in the claim or the name of a request and a subrequest separated by '/'")
            next
          end
          segments.each { |segment| issues.concat(dra_request_name_errors(segment, base)) }
          known = request_names.key?(segments[0]) &&
                  (segments.length == 1 || request_names.fetch(segments[0]).include?(segments[1]))
          unless known
            issues << issue(base, :invalid,
                            "must be the name of a request in the claim or the name of a request and a subrequest separated by '/'")
          end
          issues << issue(base, :duplicate, "") if seen[reference]
          seen[reference] = true
        end
        issues
      end

      def dra_device_request_body_errors(request, path)
        issues = []
        class_name = fetch(request, "deviceClassName").to_s
        if class_name.empty?
          issues << issue(path + ["deviceClassName"], :required, "")
        else
          issues.concat(invalid_messages(path + ["deviceClassName"], dns1123_subdomain_messages(class_name)))
        end
        Array(fetch(request, "selectors")).each_with_index do |selector, index|
          next unless selector.is_a?(Hash)

          base = path + ["selectors", index.to_s]
          cel = fetch(selector, "cel")
          if cel.is_a?(Hash)
            issues << issue(base + %w[cel expression], :required, "") if fetch(cel, "expression").to_s.empty?
          else
            issues << issue(base + ["cel"], :required, "")
          end
        end
        issues.concat(dra_allocation_mode_errors(request, path))
        Array(fetch(request, "tolerations")).each_with_index do |toleration, index|
          next unless toleration.is_a?(Hash)

          issues.concat(dra_toleration_errors(toleration, path + ["tolerations", index.to_s]))
        end
        issues
      end

      def dra_allocation_mode_errors(request, path)
        mode = fetch(request, "allocationMode")
        count = fetch(request, "count")
        count = 0 if count.nil?
        case mode.to_s
        when "", "ExactCount"
          # SetDefaults_DeviceRequest defaults allocationMode to ExactCount and count to 1.
          return [] unless mode.to_s == "ExactCount" && count.is_a?(Integer) && count <= 0

          [issue(path + ["count"], :invalid, "must be greater than zero")]
        when "All"
          return [] unless count.is_a?(Integer) && count != 0

          [issue(path + ["count"], :invalid, "must not be specified when allocationMode is 'All'")]
        else
          [issue(path + ["allocationMode"], :unsupported, unsupported_detail(%w[All ExactCount]))]
        end
      end

      def dra_toleration_errors(toleration, base)
        issues = []
        key = fetch(toleration, "key").to_s
        issues.concat(invalid_messages(base + ["key"], qualified_name_messages(key))) unless key.empty?
        value = fetch(toleration, "value").to_s
        case fetch(toleration, "operator").to_s
        when "Exists"
          issues << issue(base + ["value"], :invalid, "must be empty for operator `Exists`") unless value.empty?
        when "Equal"
          issues.concat(invalid_messages(base + ["value"], label_value_messages(value)))
        when ""
          issues << issue(base + ["operator"], :required, "")
        else
          issues << issue(base + ["operator"], :unsupported, unsupported_detail(%w[Equal Exists]))
        end
        effect = fetch(toleration, "effect").to_s
        unless effect.empty? || %w[NoExecute NoSchedule None].include?(effect)
          issues << issue(base + ["effect"], :unsupported, unsupported_detail(%w[NoExecute NoSchedule None]))
        end
        issues
      end

      def dra_device_configuration_errors(config, path)
        opaque = fetch(config, "opaque")
        return [issue(path + ["opaque"], :required, "")] unless opaque.is_a?(Hash)

        issues = []
        driver = fetch(opaque, "driver").to_s
        if driver.empty?
          issues << issue(path + %w[opaque driver], :required, "")
        else
          issues.concat(invalid_messages(path + %w[opaque driver], dns1123_subdomain_messages(driver)))
        end
        issues << issue(path + %w[opaque parameters], :required, "") if fetch(opaque, "parameters").nil?
        issues
      end

      private_class_method :dra_request_names, :dra_request_list_errors, :dra_request_choice_errors, :dra_exact_request, :dra_subrequest_list_errors,
                           :dra_constraint_list_errors, :dra_config_list_errors, :dra_allocation_mode_errors, :dra_toleration_errors
    end
  end
end
