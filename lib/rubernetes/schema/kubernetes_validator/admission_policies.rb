# frozen_string_literal: true

module Rubernetes
  module Schema
    # ValidatingAdmissionPolicy and MutatingAdmissionPolicy specs: match
    # constraints, match conditions, variables, validations, audit annotations
    # and mutations (pkg/apis/admissionregistration/validation).  The CEL
    # compilation itself lives in admission_policy_cel.rb.
    module KubernetesValidator
      module_function

      ADMISSION_MATCH_RESOURCE_OPERATIONS = %w[* CONNECT CREATE DELETE UPDATE].freeze
      ADMISSION_MUTATING_OPERATIONS = %w[* CONNECT CREATE UPDATE].freeze

      # compiler: the policy's CEL compiler (getCompiler -- with variable
      # composition when the policy has variables).
      def admission_policy_common_errors(spec, compiler = policy_compiler(spec))
        issues = []
        policy = fetch(spec, "failurePolicy")
        issues << issue(%w[spec failurePolicy], :unsupported, unsupported_detail(%w[Fail Ignore])) if !policy.nil? && !%w[Fail
                                                                                                                          Ignore].include?(policy.to_s)
        param_kind = fetch(spec, "paramKind")
        issues.concat(param_kind_errors(param_kind, %w[spec paramKind])) if param_kind.is_a?(Hash)
        constraints = fetch(spec, "matchConstraints")
        if constraints.is_a?(Hash)
          issues.concat(match_resources_errors(constraints, %w[spec matchConstraints]))
          issues << issue(%w[spec matchConstraints resourceRules], :required, "") if Array(fetch(constraints, "resourceRules")).empty?
        else
          issues << issue(%w[spec matchConstraints], :required, "")
        end
        has_params = param_kind.is_a?(Hash)
        issues.concat(match_conditions_errors(fetch(spec, "matchConditions"), %w[spec matchConditions], has_params: has_params))
        issues.concat(variables_errors(fetch(spec, "variables"), %w[spec variables], compiler: compiler, has_params: has_params))
        issues
      end

      def policy_compiler(spec) = policy_expression_compiler(composition: Array(fetch(spec, "variables")).any?)

      def param_kind_errors(kind_ref, path)
        issues = []
        api_version = fetch(kind_ref, "apiVersion").to_s
        if api_version.empty?
          issues << issue(path + ["apiVersion"], :required, "")
        else
          parts = api_version.split("/", -1)
          if parts.length > 2
            issues << issue(path + ["apiVersion"], :invalid, "unexpected GroupVersion string: #{api_version}")
          else
            group = parts.length == 2 ? parts[0] : ""
            version = parts.last
            unless group.empty?
              messages = dns1123_subdomain_messages(group)
              issues << issue(path + ["apiVersion"], :invalid, messages.join(",")) unless messages.empty?
            end
            if version.empty?
              issues << issue(path + ["apiVersion"], :invalid, "version must be specified")
            else
              messages = dns1035_label_messages(version)
              issues << issue(path + ["apiVersion"], :invalid, messages.join(",")) unless messages.empty?
            end
          end
        end
        kind = fetch(kind_ref, "kind").to_s
        if kind.empty?
          issues << issue(path + ["kind"], :required, "")
        else
          messages = dns1035_label_messages(kind.downcase)
          unless messages.empty?
            issues << issue(path + ["kind"], :invalid,
                            "may have mixed case, but should otherwise match: #{messages.join(",")}")
          end
        end
        issues
      end

      # validateMatchResources; nil selectors and matchPolicy are defaulted
      # by the versioned scheme before the strategy runs.
      def match_resources_errors(match, path, operations: ADMISSION_MATCH_RESOURCE_OPERATIONS)
        return [] unless match.is_a?(Hash)

        issues = []
        policy = fetch(match, "matchPolicy")
        issues << issue(path + ["matchPolicy"], :unsupported, unsupported_detail(%w[Equivalent Exact])) if !policy.nil? && !%w[Equivalent
                                                                                                                               Exact].include?(policy.to_s)
        issues.concat(label_selector_errors(fetch(match, "namespaceSelector"), path + ["namespaceSelector"]))
        issues.concat(label_selector_errors(fetch(match, "objectSelector"), path + ["objectSelector"]))
        %w[resourceRules excludeResourceRules].each do |collection|
          Array(fetch(match, collection)).each_with_index do |rule, index|
            next unless rule.is_a?(Hash)

            issues.concat(admission_rule_errors(rule, path + [collection, index.to_s], operations: operations))
          end
        end
        issues
      end

      def admission_rule_errors(rule, path, operations:)
        issues = []
        names = Array(fetch(rule, "resourceNames"))
        seen = {}
        names.each_with_index do |name, index|
          issues.concat(invalid_messages(path + ["resourceNames", index.to_s], path_segment_name_messages(name)))
          if seen[name]
            issues << issue(path + ["resourceNames", index.to_s], :duplicate, "")
          else
            seen[name] = true
          end
        end
        ops = Array(fetch(rule, "operations"))
        issues << issue(path + ["operations"], :required, "") if ops.empty?
        if ops.length > 1 && ops.include?("*")
          issues << issue(path + ["operations"], :invalid,
                          "if '*' is present, must not specify other operations")
        end
        ops.each_with_index do |op, index|
          unless operations.include?(op.to_s)
            issues << issue(path + ["operations", index.to_s], :unsupported,
                            unsupported_detail(operations))
          end
        end
        groups = Array(fetch(rule, "apiGroups"))
        issues << issue(path + ["apiGroups"], :required, "") if groups.empty?
        if groups.length > 1 && groups.include?("*")
          issues << issue(path + ["apiGroups"], :invalid,
                          "if '*' is present, must not specify other API groups")
        end
        versions = Array(fetch(rule, "apiVersions"))
        issues << issue(path + ["apiVersions"], :required, "") if versions.empty?
        if versions.length > 1 && versions.include?("*")
          issues << issue(path + ["apiVersions"], :invalid,
                          "if '*' is present, must not specify other API versions")
        end
        versions.each_with_index do |version, index|
          issues << issue(path + ["apiVersions", index.to_s], :required, "") if version.to_s.empty?
        end
        resources = Array(fetch(rule, "resources"))
        issues << issue(path + ["resources"], :required, "") if resources.empty?
        resources.each_with_index do |resource, index|
          issues << issue(path + ["resources", index.to_s], :required, "") if resource.to_s.empty?
        end
        if resources.length > 1 && resources.include?("*")
          issues << issue(path + ["resources"], :invalid,
                          "if '*' is present, must not specify other resources")
        end
        scope = fetch(rule, "scope")
        issues << issue(path + ["scope"], :unsupported, unsupported_detail(%w[* Cluster Namespaced])) if !scope.nil? && !%w[* Cluster
                                                                                                                            Namespaced].include?(scope.to_s)
        issues
      end

      def mutating_operations_errors(match, path)
        return [] unless match.is_a?(Hash)

        issues = []
        Array(fetch(match, "resourceRules")).each do |rule|
          next unless rule.is_a?(Hash)

          Array(fetch(rule, "operations")).each do |op|
            next if ADMISSION_MUTATING_OPERATIONS.include?(op.to_s)

            issues << issue(path + %w[resourceRules operations], :unsupported, unsupported_detail(ADMISSION_MUTATING_OPERATIONS))
          end
        end
        issues
      end

      # validateMatchConditions; has_params: allowParamsInMatchConditions
      # (a policy with a paramKind).  The trimmed expression is compiled by
      # the strict stateless compiler.
      def match_conditions_errors(conditions, path, has_params: false)
        return [] unless conditions.is_a?(Array)

        issues = []
        issues << issue(path, :too_many, "must have at most 64 items") if conditions.length > 64
        seen = {}
        conditions.each_with_index do |condition, index|
          next unless condition.is_a?(Hash)

          base = path + [index.to_s]
          trimmed = fetch(condition, "expression").to_s.strip
          if trimmed.empty?
            issues << issue(base + ["expression"], :required, "")
          else
            compile_issue = cel_compile_issue(base + ["expression"], trimmed, compiler: policy_expression_compiler, return_types: cel_return_types(:bool),
                                                                              has_params: has_params, has_authorizer: true)
            issues << compile_issue if compile_issue
          end
          name = fetch(condition, "name").to_s
          if name.empty?
            issues << issue(base + ["name"], :required, "")
          else
            issues.concat(invalid_messages(base + ["name"], qualified_name_messages(name)))
            if seen[name]
              issues << issue(base + ["name"], :duplicate, "")
            else
              seen[name] = true
            end
          end
        end
        issues
      end

      CEL_RESERVED_WORDS = %w[true false null in as break const continue else for function if import let loop package namespace return
                              var void while].freeze

      # validateVariable: each variable compiled into the policy's
      # composition compiler (later expressions see its type).
      def variables_errors(variables, path, compiler: nil, has_params: false)
        return [] unless variables.is_a?(Array)

        issues = []
        variables.each_with_index do |variable, index|
          next unless variable.is_a?(Hash)

          base = path + [index.to_s]
          raw_name = fetch(variable, "name").to_s
          name = raw_name.strip
          if name.empty?
            issues << issue(base + ["name"], :required, "name is not specified")
          elsif !raw_name.match?(/\A[_a-zA-Z][_a-zA-Z0-9]*\z/) || CEL_RESERVED_WORDS.include?(raw_name)
            issues << issue(base + ["name"], :invalid, "must be a valid CEL identifier")
          end
          expression = fetch(variable, "expression").to_s
          if expression.strip.empty?
            issues << issue(base + ["expression"], :required, "expression is not specified")
          elsif compiler
            compile_issue = cel_result_issue(base + ["expression"],
                                             compiler.compile_variable(raw_name, expression, has_params: has_params), expression)
            issues << compile_issue if compile_issue
          end
        end
        issues
      end

      # pkg/apis/admissionregistration/validation validateValidatingAdmissionPolicySpec
      def validating_admission_policy_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        metadata = fetch(root, "metadata")
        metadata = {} unless metadata.is_a?(Hash)
        compiler = policy_compiler(spec)
        issues = admission_policy_common_errors(spec, compiler)
        validations = fetch(spec, "validations")
        validations = [] unless validations.is_a?(Array)
        annotations = fetch(spec, "auditAnnotations")
        annotations = [] unless annotations.is_a?(Array)
        if validations.empty? && annotations.empty?
          issues << issue(%w[spec validations], :required, "validations or auditAnnotations must contain at least one item")
          issues << issue(%w[spec auditAnnotations], :required, "validations or auditAnnotations must contain at least one item")
          return issues
        end
        has_params = fetch(spec, "paramKind").is_a?(Hash)
        validations.each_with_index do |validation, index|
          next unless validation.is_a?(Hash)

          policy_validation_errors(validation, ["spec", "validations", index.to_s], compiler, has_params, issues)
        end
        audit_annotation_errors(annotations, fetch(metadata, "name"), compiler, has_params, issues)
        issues
      end

      # validateValidation: the expression, its message and reason.
      def policy_validation_errors(validation, base, compiler, has_params, issues)
        expression = fetch(validation, "expression").to_s
        if expression.strip.empty?
          issues << issue(base + ["expression"], :required, "expression is not specified")
        else
          compile_issue = cel_compile_issue(base + ["expression"], expression, compiler: compiler, return_types: cel_return_types(:bool),
                                                                               has_params: has_params, has_authorizer: true)
          issues << compile_issue if compile_issue
        end
        message_expression = fetch(validation, "messageExpression").to_s
        if !message_expression.empty? && message_expression.strip.empty?
          issues << issue(base + ["messageExpression"], :required, "must be non-empty if specified")
        elsif !message_expression.strip.empty?
          compile_issue = cel_compile_issue(base + ["messageExpression"], message_expression, compiler: compiler,
                                                                                              return_types: cel_return_types(:string),
                                                                                              has_params: has_params, has_authorizer: false)
          issues << compile_issue if compile_issue
        end
        message = fetch(validation, "message").to_s
        if !message.empty? && message.strip.empty?
          issues << issue(base + ["message"], :required, "message must be non-empty if specified")
        elsif message.strip.match?(/[\r\n]/)
          issues << issue(base + ["message"], :invalid, "message must not contain line breaks")
        end
        reason = fetch(validation, "reason")
        return if reason.nil? || %w[Forbidden Invalid RequestEntityTooLarge].include?(reason.to_s)

        issues << issue(base + ["reason"], :unsupported, unsupported_detail(%w[Forbidden Invalid RequestEntityTooLarge]))
      end

      # validateAuditAnnotation: at most 20, each with a unique key that is
      # a qualified name once prefixed with the policy's name, and a value
      # expression that compiles.
      def audit_annotation_errors(annotations, policy_name, compiler, has_params, issues)
        issues << issue(%w[spec auditAnnotations], :invalid, "must not have more than 20 auditAnnotations") if annotations.length > 20
        seen = {}
        annotations.each_with_index do |annotation, index|
          next unless annotation.is_a?(Hash)

          base = ["spec", "auditAnnotations", index.to_s]
          key = fetch(annotation, "key").to_s
          if blank?(policy_name)
            issues << issue(base + ["key"], :invalid, "requires metadata.name be non-empty")
          else
            issues.concat(invalid_messages(base + ["key"], qualified_name_messages("#{policy_name}/#{key}")))
          end
          expression = fetch(annotation, "valueExpression").to_s
          if expression.strip.empty?
            issues << issue(base + ["valueExpression"], :required, "valueExpression is not specified")
          elsif expression.strip.bytesize > 5120
            issues << issue(base + ["valueExpression"], :required, "must not exceed 5120 bytes in length")
          else
            compile_issue = cel_compile_issue(base + ["valueExpression"], expression.strip, value: expression, compiler: compiler,
                                                                                            return_types: cel_return_types(:string_or_null),
                                                                                            has_params: has_params, has_authorizer: true)
            issues << compile_issue if compile_issue
          end
          issues << issue(base + ["key"], :duplicate, "") if seen[key]
          seen[key] = true
        end
      end

      # pkg/apis/admissionregistration/validation validateMutatingAdmissionPolicySpec
      def mutating_admission_policy_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        # createCompiler(true): a MutatingAdmissionPolicy always composes.
        compiler = policy_expression_compiler(composition: true)
        issues = admission_policy_common_errors(spec, compiler)
        issues.concat(mutating_operations_errors(fetch(spec, "matchConstraints"), %w[spec matchConstraints]))
        has_params = fetch(spec, "paramKind").is_a?(Hash)
        mutations = fetch(spec, "mutations")
        if !mutations.is_a?(Array) || mutations.empty?
          issues << issue(%w[spec mutations], :required, "mutations must contain at least one item")
        else
          mutations.each_with_index do |mutation, index|
            next unless mutation.is_a?(Hash)

            policy_mutation_errors(mutation, ["spec", "mutations", index.to_s], compiler, has_params, issues)
          end
        end
        reinvocation = fetch(spec, "reinvocationPolicy").to_s
        if reinvocation.empty?
          issues << issue(%w[spec reinvocationPolicy], :required, "")
        elsif !%w[IfNeeded Never].include?(reinvocation)
          issues << issue(%w[spec reinvocationPolicy], :unsupported, unsupported_detail(%w[IfNeeded Never]))
        end
        issues
      end

      # A mutation carries exactly the patch its patchType names.
      def policy_mutation_errors(mutation, base, compiler, has_params, issues)
        json_patch = fetch(mutation, "jsonPatch")
        apply_configuration = fetch(mutation, "applyConfiguration")
        case fetch(mutation, "patchType").to_s
        when ""
          issues << issue(base + ["patchType"], :required, "")
        when "JSONPatch"
          if json_patch.is_a?(Hash)
            issues.concat(mutation_expression_errors(json_patch, base + %w[jsonPatch expression], compiler, :json_patches, has_params))
          else
            issues << issue(base + ["jsonPatch"], :required, "must be specified when patchType is JSONPatch")
          end
          if apply_configuration.is_a?(Hash)
            issues << issue(base + ["applyConfiguration"], :invalid,
                            "must not be specified when patchType is JSONPatch")
          end
        when "ApplyConfiguration"
          if apply_configuration.is_a?(Hash)
            issues.concat(mutation_expression_errors(apply_configuration, base + %w[applyConfiguration expression], compiler, :object,
                                                     has_params))
          else
            issues << issue(base + ["applyConfiguration"], :required, "must be specified when patchType is ApplyConfiguration")
          end
          if json_patch.is_a?(Hash)
            issues << issue(base + ["jsonPatch"], :invalid,
                            "must not be specified when patchType is ApplyConfiguration")
          end
        else
          issues << issue(base + ["patchType"], :unsupported, unsupported_detail(%w[ApplyConfiguration JSONPatch]))
        end
      end

      private_class_method :policy_validation_errors, :audit_annotation_errors, :policy_mutation_errors
    end
  end
end
