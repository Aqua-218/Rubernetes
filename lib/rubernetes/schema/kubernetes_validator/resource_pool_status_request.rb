# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      POOL_STATUS_SCHEMA = "io.k8s.api.resource.v1alpha3.ResourcePoolStatusRequest"

      # The current status is cleared by the create strategy. Updates to a
      # completed request's status also go through the handwritten checks.
      def resource_pool_status_request_errors(root, old, operation, subresource)
        if old.is_a?(Hash) && (previous = fetch(old, "spec")).is_a?(Hash) && fetch(previous, "limit").nil?
          # Requests stored before this default was applied have the same
          # effective limit as a request explicitly specifying 100.
          old = old.merge("spec" => previous.merge("limit" => 100))
          spec = fetch(root, "spec")
          root = root.merge("spec" => spec.merge("limit" => 100)) if spec.is_a?(Hash) && fetch(spec, "limit").nil?
        end

        issues = []
        if subresource.to_s == "status"
          status = fetch(root, "status")
          previous = fetch(old, "status")
          if previous.is_a?(Hash)
            issues << issue(%w[status], :invalid, "field is immutable") if status != previous
          elsif status.is_a?(Hash)
            issues.concat(meta_conditions_errors(Array(fetch(status, "conditions")), %w[status conditions]))
          end
        elsif operation == :create
          root = root.except("status")
        end

        findings = DeclarativeRules.new(operation: operation).evaluate(POOL_STATUS_SCHEMA, root, old)
        issues.concat(findings.filter_map { |finding| finding.issue unless finding.stage })
      end

      def pool_status_driver_errors(driver, path)
        return [issue(path, :required, "")] if driver.to_s.empty?
        return [] unless driver.is_a?(String)

        issues = []
        issues << issue(path, :invalid, "must be no more than 253 characters") if driver.bytesize > 253
        unless /\A[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?(\.[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?)*\z/.match?(driver)
          issues << issue(path, :invalid,
                          "an RFC 1123 subdomain must consist of alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character")
        end
        issues
      end

      def declared_pool_name_errors(name, path)
        issues = []
        issues << issue(path, :too_long, "may not be more than 253 bytes") if name.bytesize > 253
        segments = name.empty? ? [""] : name.split("/", -1)
        segments.each_with_index do |segment, index|
          messages = segment.empty? ? ["must not be empty"] : dns1123_subdomain_messages(segment)
          issues.concat(invalid_messages(path, messages.map { |message| "segment #{index}: #{message}" }))
        end
        issues
      end
    end
  end
end
