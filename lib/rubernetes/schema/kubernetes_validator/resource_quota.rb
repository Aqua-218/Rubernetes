# frozen_string_literal: true

module Rubernetes
  module Schema
    # pkg/apis/core/validation (v1.36.2) ValidateResourceQuota,
    # ValidateResourceQuotaUpdate and ValidateResourceQuotaStatusUpdate.  Only
    # the scope selector's operator and scope name were checked, so a quota
    # could be stored that names no real resource ("foo"), a negative or a
    # fractional count ("pods: 1.5", "example.com/gpu: 500m"), a BestEffort
    # scope over cpu the evaluator can never charge, or change its scopes
    # in place.  Map keys are visited sorted (Go iterates the map).
    module KubernetesValidator
      module_function

      STANDARD_QUOTA_RESOURCES = %w[
        cpu memory ephemeral-storage requests.cpu requests.memory requests.storage requests.ephemeral-storage
        limits.cpu limits.memory limits.ephemeral-storage pods resourcequotas services replicationcontrollers secrets
        persistentvolumeclaims configmaps services.nodeports services.loadbalancers
      ].freeze
      STANDARD_RESOURCE_QUOTA_SCOPES = %w[
        Terminating NotTerminating BestEffort NotBestEffort PriorityClass VolumeAttributesClass CrossNamespacePodAffinity
      ].freeze
      POD_OBJECT_COUNT_QUOTA_RESOURCES = %w[pods].freeze
      POD_COMPUTE_QUOTA_RESOURCES = %w[cpu memory limits.cpu limits.memory requests.cpu requests.memory].freeze
      PVC_QUOTA_RESOURCES = %w[persistentvolumeclaims requests.storage].freeze
      EXISTS_ONLY_SCOPES = %w[BestEffort NotBestEffort Terminating NotTerminating CrossNamespacePodAffinity].freeze
      CONFLICTING_SCOPES = [%w[BestEffort NotBestEffort], %w[Terminating NotTerminating]].freeze
      # A nil Go slice as the bad value: rendered "null" (a nil issue value
      # would render whatever sits at the issue's path instead).
      NIL_SLICE = Object.new.tap { |value| def value.to_json(*) = "null" }.freeze

      def resource_quota_errors(root, operation = :create, old = nil, subresource = nil)
        return resource_quota_status_errors(root) if subresource.to_s == "status"

        spec = fetch(root, "spec")
        issues = spec.is_a?(Hash) ? resource_quota_spec_errors(spec) : []
        if operation == :update
          old_scopes = Array(fetch(fetch(old, "spec"), "scopes")).map(&:to_s).uniq.sort
          new_scopes = spec.is_a?(Hash) ? Array(fetch(spec, "scopes")) : []
          unless old_scopes == new_scopes.map(&:to_s).uniq.sort
            issues << valued_issue(%w[spec scopes], new_scopes, "field is immutable")
          end
        else
          issues.concat(resource_quota_status_errors(root))
        end
        issues
      end

      def resource_quota_status_errors(root)
        status = fetch(root, "status")
        return [] unless status.is_a?(Hash)

        %w[hard used].flat_map { |name| quota_resource_list_errors(fetch(status, name), ["status", name]) }
      end

      # ValidateResourceQuotaSpec.
      def resource_quota_spec_errors(spec)
        hard = fetch(spec, "hard")
        issues = quota_resource_list_errors(hard, %w[spec hard])
        names = hard.is_a?(Hash) ? hard.keys.map(&:to_s).sort : []
        issues.concat(resource_quota_scopes_errors(spec, names))
        selector = fetch(spec, "scopeSelector")
        issues.concat(scope_selector_errors(spec, selector, names)) if selector.is_a?(Hash)
        issues
      end

      def quota_resource_list_errors(list, path)
        return [] unless list.is_a?(Hash)

        list.keys.map(&:to_s).sort.flat_map do |name|
          resource_path = path + ["[#{name}]"]
          quota_resource_name_errors(name, resource_path) + requirement_quantity(name, list[name], resource_path).last
        end
      end

      # ValidateResourceQuotaResourceName over validateResourceName.
      def quota_resource_name_errors(name, path)
        messages = qualified_name_messages(name)
        return messages.map { |message| valued_issue(path, name, message) } unless messages.empty?
        return [] if name.include?("/")

        issues = []
        unless STANDARD_RESOURCES.include?(name) || quota_huge_page?(name)
          issues << valued_issue(path, name, "must be a standard resource type or fully qualified")
        end
        unless STANDARD_QUOTA_RESOURCES.include?(name) || quota_huge_page?(name)
          issues << valued_issue(path, name, "must be a standard resource for quota")
        end
        issues
      end

      # helper.IsResourceQuotaScopeValidForResource.
      def quota_scope_valid_for_resource?(scope, name)
        case scope
        when "Terminating", "NotTerminating", "NotBestEffort", "PriorityClass", "CrossNamespacePodAffinity"
          POD_OBJECT_COUNT_QUOTA_RESOURCES.include?(name) || POD_COMPUTE_QUOTA_RESOURCES.include?(name)
        when "BestEffort" then POD_OBJECT_COUNT_QUOTA_RESOURCES.include?(name)
        when "VolumeAttributesClass" then PVC_QUOTA_RESOURCES.include?(name)
        else true
        end
      end

      def standard_quota_resource?(name) = STANDARD_QUOTA_RESOURCES.include?(name) || quota_huge_page?(name)

      # validateResourceQuotaScopes.
      def resource_quota_scopes_errors(spec, names)
        scopes = fetch(spec, "scopes")
        return [] unless scopes.is_a?(Array) && !scopes.empty?

        issues = []
        scopes.each do |scope|
          issues << valued_issue(%w[spec scopes], scopes, "unsupported scope") unless STANDARD_RESOURCE_QUOTA_SCOPES.include?(scope.to_s)
          names.each do |name|
            if standard_quota_resource?(name) && !quota_scope_valid_for_resource?(scope.to_s, name)
              issues << valued_issue(%w[spec scopes], scopes, "unsupported scope applied to resource")
            end
          end
        end
        present = scopes.map(&:to_s)
        CONFLICTING_SCOPES.each do |pair|
          issues << valued_issue(%w[spec scopes], scopes, "conflicting scopes") if (pair - present).empty?
        end
        issues
      end

      # validateScopedResourceSelectorRequirement.  The internal
      # ScopeSelector carries no JSON tags, so upstream prints its Go field
      # names.
      def scope_selector_errors(spec, selector, names)
        expressions = fetch(selector, "matchExpressions")
        return [] unless expressions.is_a?(Array)

        base = %w[spec scopeSelector matchExpressions]
        issues = []
        seen = []
        expressions.each do |expression|
          next unless expression.is_a?(Hash)

          operator = fetch(expression, "operator")
          scope_name = fetch(expression, "scopeName")
          values = fetch(expression, "values")
          if blank?(scope_name)
            required(expression, "scopeName", base, issues)
          elsif !STANDARD_RESOURCE_QUOTA_SCOPES.include?(scope_name.to_s)
            issues << valued_issue(base + ["scopeName"], scope_name.to_s, "unsupported scope")
          end
          names.each do |name|
            if standard_quota_resource?(name) && !quota_scope_valid_for_resource?(scope_name.to_s, name)
              issues << valued_issue(base, go_scope_selector(selector), "unsupported scope applied to resource")
            end
          end
          if EXISTS_ONLY_SCOPES.include?(scope_name.to_s) && operator.to_s != "Exists" && !blank?(operator)
            issues << valued_issue(base + ["operator"], operator.to_s,
                                   "must be 'Exists' when scope is any of ResourceQuotaScopeTerminating, ResourceQuotaScopeNotTerminating, " \
                                   "ResourceQuotaScopeBestEffort, ResourceQuotaScopeNotBestEffort or ResourceQuotaScopeCrossNamespacePodAffinity")
          end
          case operator.to_s
          when "In", "NotIn"
            if !values.is_a?(Array) || values.empty?
              issues << issue(base + ["values"], :required, "must be at least one value when `operator` is 'In' or 'NotIn' for scope selector")
            end
          when "Exists", "DoesNotExist"
            if values.is_a?(Array) && !values.empty?
              issues << valued_issue(base + ["values"], values,
                                     "must be no value when `operator` is 'Exist' or 'DoesNotExist' for scope selector")
            end
          when ""
            required(expression, "operator", base, issues)
          else
            issues << valued_issue(base + ["operator"], operator.to_s, "not a valid selector operator")
          end
          seen << scope_name.to_s
        end
        scopes = fetch(spec, "scopes")
        CONFLICTING_SCOPES.each do |pair|
          issues << valued_issue(base, scopes.is_a?(Array) && !scopes.empty? ? scopes : NIL_SLICE, "conflicting scopes") if (pair - seen).empty?
        end
        issues
      end

      def go_scope_selector(selector)
        {"MatchExpressions" => Array(fetch(selector, "matchExpressions")).select { |item| item.is_a?(Hash) }.map do |expression|
          values = fetch(expression, "values")
          {"ScopeName" => fetch(expression, "scopeName").to_s, "Operator" => fetch(expression, "operator").to_s,
           "Values" => values.is_a?(Array) && !values.empty? ? values : nil}
        end}
      end
    end
  end
end
