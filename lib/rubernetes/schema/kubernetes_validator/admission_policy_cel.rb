# frozen_string_literal: true

module Rubernetes
  module Schema
    # The CEL compilation pkg/apis/admissionregistration/validation runs over
    # a policy's (and a webhook's) expressions on create and update
    # (validateCELCondition / convertCELErrorToValidationError, v1.36.2): an
    # expression that does not compile, or compiles to a type its field does
    # not allow, is Invalid with the compiler's detail.
    module KubernetesValidator
      module_function

      def policy_expression_compiler(composition: false)
        require_relative "../../security/admission/policy_expression_compiler"
        Security::Admission::PolicyExpressionCompiler.new(composition: composition)
      end

      # The issue for one expression, or nil.  value: what field.Invalid
      # prints (the expression as the accessor carries it).
      def cel_compile_issue(path, expression, compiler:, return_types:, has_params:, has_authorizer:, value: expression)
        result = compiler.compile(expression, return_types: return_types, has_params: has_params, has_authorizer: has_authorizer)
        cel_result_issue(path, result, value)
      end

      # convertCELErrorToValidationError: Invalid with the expression, or an
      # internal error (program instantiation).
      def cel_result_issue(path, result, value)
        return nil if result.nil?

        kind, detail = result
        return ValidationIssue.new(path: path, code: :internal, message: detail, kubernetes_type: "Internal error") if kind == :internal

        ValidationIssue.new(path: path, code: :invalid, value: value, message: detail, kubernetes_type: "Invalid value")
      end

      def cel_return_types(kind)
        compiler = Security::Admission::PolicyExpressionCompiler
        {bool: compiler::BOOL, string: compiler::STRING, string_or_null: compiler::STRING_OR_NULL, object: compiler::OBJECT,
         json_patches: compiler::JSON_PATCHES}.fetch(kind)
      end

      # validateApplyConfiguration / validateJSONPatch: the trimmed
      # expression, with the patch types, printed as trimmed.
      def mutation_expression_errors(mutation, path, compiler, return_kind, has_params)
        trimmed = fetch(mutation, "expression").to_s.strip
        return [issue(path, :required, "")] if trimmed.empty?

        result = compiler.compile(trimmed, return_types: cel_return_types(return_kind), has_params: has_params, has_authorizer: true,
                                           patch_types: true)
        [cel_result_issue(path, result, trimmed)].compact
      end
    end
  end
end
