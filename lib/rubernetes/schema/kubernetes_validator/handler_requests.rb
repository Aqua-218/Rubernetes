# frozen_string_literal: true

module Rubernetes
  module Schema
    # Request bodies validated inside a REST handler rather than by a
    # registry strategy: TokenRequest, the SubjectAccessReview family, Scale,
    # Binding and metav1.DeleteOptions.
    module KubernetesValidator
      module_function

      DELETE_PROPAGATION_POLICIES = %w[Foreground Background Orphan].freeze

      def handler_request_errors(root, kind)
        case kind
        when "TokenRequest" then token_request_errors(root)
        when "SubjectAccessReview" then subject_access_review_errors(root, self_review: false, local: false)
        when "SelfSubjectAccessReview" then subject_access_review_errors(root, self_review: true, local: false)
        when "LocalSubjectAccessReview" then subject_access_review_errors(root, self_review: false, local: true)
        when "Scale" then scale_errors(root)
        when "Binding" then binding_errors(root)
        else []
        end
      end

      # pkg/apis/authentication/validation ValidateTokenRequest.  The token
      # REST handler receives the request after the versioned decoder applied
      # SetDefaults_TokenRequestSpec (expirationSeconds 3600 when absent).
      def token_request_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        seconds = fetch(spec, "expirationSeconds")
        seconds = 3600 if seconds.nil?
        issues = []
        return issues unless seconds.is_a?(Integer)

        issues << issue(%w[spec expirationSeconds], :invalid, "may not specify a duration less than 10 minutes") if seconds < 600
        issues << issue(%w[spec expirationSeconds], :invalid, "may not specify a duration larger than 2^32 seconds") if seconds > (1 << 32)
        issues
      end

      # pkg/apis/authorization/validation ValidateSubjectAccessReviewSpec /
      # ValidateSelfSubjectAccessReviewSpec / ValidateLocalSubjectAccessReview
      def subject_access_review_errors(root, self_review:, local:)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        resource = fetch(spec, "resourceAttributes")
        non_resource = fetch(spec, "nonResourceAttributes")
        issues = []
        if resource.is_a?(Hash) && non_resource.is_a?(Hash)
          issues << issue(%w[spec nonResourceAttributes], :invalid, "cannot be specified in combination with resourceAttributes")
        end
        if !resource.is_a?(Hash) && !non_resource.is_a?(Hash)
          issues << issue(%w[spec resourceAttributes], :invalid,
                          "exactly one of nonResourceAttributes or resourceAttributes must be specified")
        end
        if !self_review && blank?(fetch(spec, "user")) && Array(fetch(spec, "groups")).empty?
          issues << issue(%w[spec user], :invalid, "at least one of user or group must be specified")
        end
        issues.concat(resource_attributes_errors(resource))
        metadata = fetch(root, "metadata")
        metadata = {} unless metadata.is_a?(Hash)
        if local
          issues << issue(%w[spec nonResourceAttributes], :invalid, "disallowed on this kind of request") if non_resource.is_a?(Hash)
          extra = metadata.reject { |key, value| %w[namespace managedFields].include?(key.to_s) || unset_value?(value) }
          issues << issue(%w[metadata], :invalid, "must be empty except for namespace") unless extra.empty?
          if resource.is_a?(Hash) && fetch(resource, "namespace").to_s != fetch(metadata, "namespace").to_s
            issues << issue(%w[spec resourceAttributes namespace], :invalid, "must match metadata.namespace")
          end
        else
          # ValidateSubjectAccessReview / ValidateSelfSubjectAccessReview:
          # ObjectMeta must be the zero value.
          issues << issue(%w[metadata], :invalid, "must be empty") unless metadata.all? { |_key, value| unset_value?(value) }
        end
        issues
      end

      def resource_attributes_errors(resource)
        return [] unless resource.is_a?(Hash)

        issues = []
        {"fieldSelector" => :field, "labelSelector" => :label}.each do |name, flavor|
          selector = fetch(resource, name)
          next unless selector.is_a?(Hash)

          path = ["spec.resourceAttributes", name]
          raw = fetch(selector, "rawSelector").to_s
          requirements = Array(fetch(selector, "requirements"))
          if !raw.empty? && !requirements.empty?
            issues << issue(path + ["rawSelector"], :invalid,
                            "may not specified at the same time as requirements")
          end
          if raw.empty? && requirements.empty?
            issues << issue(path + ["requirements"], :required,
                            "when #{path.join(".")} is specified, requirements or rawSelector is required")
          end
          requirements.each_with_index do |requirement, index|
            next unless requirement.is_a?(Hash)

            requirement_path = path + ["requirements", index.to_s]
            issues << issue(requirement_path + ["key"], :required, "must be specified") if blank?(fetch(requirement, "key"))
            operator = fetch(requirement, "operator").to_s
            values = Array(fetch(requirement, "values"))
            case operator
            when "In", "NotIn"
              if values.empty?
                issues << issue(requirement_path + ["values"], :required,
                                "must be specified when `operator` is 'In' or 'NotIn'")
              end
            when "Exists", "DoesNotExist"
              unless values.empty?
                issues << issue(requirement_path + ["values"], :forbidden,
                                "may not be specified when `operator` is 'Exists' or 'DoesNotExist'")
              end
            end
            if flavor == :label && !blank?(fetch(requirement, "key"))
              issues.concat(label_key_errors(fetch(requirement, "key").to_s, requirement_path + ["key"]))
            end
          end
        end
        issues
      end

      # pkg/apis/autoscaling/validation ValidateScale
      def scale_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        replicas = fetch(spec, "replicas")
        return [] unless replicas.is_a?(Integer) && replicas.negative?

        [issue(%w[spec replicas], :invalid, IS_NEGATIVE_ERROR_MSG)]
      end

      # pkg/apis/core/validation ValidatePodBinding
      def binding_errors(root)
        target = fetch(root, "target")
        target = {} unless target.is_a?(Hash)
        issues = []
        kind = fetch(target, "kind").to_s
        issues << issue(%w[target kind], :unsupported, "supported values: \"Node\", \"<empty>\"") unless kind.empty? || kind == "Node"
        issues << issue(%w[target name], :required, "") if blank?(fetch(target, "name"))
        issues
      end

      # staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/validation ValidateDeleteOptions
      def delete_options_errors(root)
        issues = []
        orphan = fetch(root, "orphanDependents")
        policy = fetch(root, "propagationPolicy")
        issues << issue(%w[propagationPolicy], :invalid, "orphanDependents and deletionPropagation cannot be both set") if !orphan.nil? && !policy.nil?
        if !policy.nil? && !DELETE_PROPAGATION_POLICIES.include?(policy.to_s)
          issues << issue(%w[propagationPolicy], :unsupported, "supported values: \"Foreground\", \"Background\", \"Orphan\", \"nil\"")
        end
        dry_run = Array(fetch(root, "dryRun"))
        issues << issue(%w[dryRun], :unsupported, "supported values: \"All\"") unless dry_run.all? { |value| value.to_s == "All" }
        if fetch(root, "ignoreStoreReadErrorWithClusterBreakingPotential") == true
          path = %w[ignoreStoreReadErrorWithClusterBreakingPotential]
          issues << issue(path, :invalid, "cannot be set together with .dryRun") unless dry_run.empty?
          issues << issue(path, :invalid, "cannot be set together with .propagationPolicy") unless policy.nil?
          issues << issue(path, :invalid, "cannot be set together with .orphanDependents") unless orphan.nil?
          issues << issue(path, :invalid, "cannot be set together with .gracePeriodSeconds") unless fetch(root, "gracePeriodSeconds").nil?
        end
        issues
      end
    end
  end
end
