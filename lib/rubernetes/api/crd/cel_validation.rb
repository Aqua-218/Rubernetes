# frozen_string_literal: true

require_relative "../../security/admission/policy_type_checker"
require_relative "../object_validation"
require_relative "cel_cost"
require_relative "cel_field_path"

module Rubernetes
  module API
    module CRD
      # apiextensions validates and estimates CEL expressions when a CRD is
      # written, before storing the definition or publishing its versions.
      module CELValidation
        Checker = Security::Admission::PolicyTypeChecker
        Types = Security::CEL::Check
        EXPRESSION_LIMIT = 10_000_000
        SCHEMA_LIMIT = 100_000_000
        REASONS = %w[FieldValueDuplicate FieldValueForbidden FieldValueInvalid FieldValueRequired].freeze

        module_function

        def errors(object, old: nil)
          prior = Array(old&.dig("spec", "versions")).to_h { |version| [version["name"], version.dig("schema", "openAPIV3Schema")] }
          Array(object.dig("spec", "versions")).each_with_index.flat_map do |version, index|
            schema = version.dig("schema", "openAPIV3Schema")
            next [] if schema.nil? || schema == prior[version["name"]]

            path = "spec.versions[#{index}].schema.openAPIV3Schema"
            causes = []
            total = validate_schema(schema, path, causes, root: true)
            if total > SCHEMA_LIMIT
              causes << cost_error(path, "x-kubernetes-validations estimated rule cost total for entire OpenAPIv3 schema", total,
                                   SCHEMA_LIMIT)
            end
            causes
          end
        end

        def validate_schema(schema, path, causes, cardinality: 1, root: false, type_schema: schema, uncorrelatable: nil)
          return 0 unless schema.is_a?(Hash)

          total = Array(schema["x-kubernetes-validations"]).each_with_index.sum do |rule, index|
            next 0 unless rule.is_a?(Hash)

            compile_rule(rule, type_schema, "#{path}.x-kubernetes-validations[#{index}]", causes, cardinality, root, uncorrelatable)
          end
          (schema["properties"] || {}).each do |name, child|
            total += validate_schema(child, "#{path}.properties[#{name}]", causes,
                                     cardinality: cardinality, uncorrelatable: uncorrelatable)
          end
          %w[items additionalProperties].each do |field|
            child = schema[field]
            next unless child.is_a?(Hash)

            ancestor = uncorrelatable || (path if field == "items" && schema["x-kubernetes-list-type"] != "map")
            limit = schema[field == "items" ? "maxItems" : "maxProperties"]
            child_cardinality = cardinality * [limit, 0].max if cardinality && limit
            total += validate_schema(child, "#{path}.#{field}", causes, cardinality: child_cardinality, uncorrelatable: ancestor)
          end
          Array(schema["allOf"]).each_with_index do |child, index|
            total += validate_schema(child, "#{path}.allOf[#{index}]", causes, cardinality: cardinality,
                                                                               root: root, type_schema: type_schema, uncorrelatable: uncorrelatable)
          end
          total
        end

        def compile_rule(rule, schema, path, causes, cardinality, root, uncorrelatable)
          invalid = rule_errors(rule, schema, path)
          unless invalid.empty?
            causes.concat(invalid)
            return 0
          end

          resource = root || schema["x-kubernetes-embedded-resource"] == true
          declaration = Checker::SchemaTypes.schema_decl_type(schema, resource)&.assign_name("rubernetes.crd.self")
          type = declaration ? declaration.cel_type : Types::DYN
          old_self_type = rule["optionalOldSelf"] == true ? Types::Type.optional(type) : type
          structs = declaration ? declaration.object_types.transform_values { |decl| decl.fields.transform_values(&:cel_type) } : {}
          environment = base_environment.with(idents: {"self" => type, "oldSelf" => old_self_type}, structs: structs)
          rule_cardinality = cardinality || (CELCost::MAX_REQUEST_BYTES / (1 + CELCost.min_json_size(schema)))
          rule_cost = validate_expression(rule["rule"], environment, Types::BOOL, path, causes, schema, rule_cardinality, "rule") do |ast|
            error = transition_error(rule, ast, path, uncorrelatable)
            causes << error if error
          end
          rule_cost + validate_expression(rule["messageExpression"], environment, Types::STRING, path, causes, schema, 1, "messageExpression")
        end

        def transition_error(rule, ast, path, uncorrelatable)
          Types::Validators.descendants(ast) do |node, _ancestors|
            next unless node.kind == :ident && node.name == "oldSelf"
            return nil unless uncorrelatable

            detail = "oldSelf cannot be used on the uncorrelatable portion of the schema within #{uncorrelatable}"
            return ObjectValidation::Cause.new(field: "#{path}.rule", reason: "FieldValueInvalid", message: "Invalid value: #{detail}")
          end
          return unless rule.key?("optionalOldSelf") && !rule["optionalOldSelf"].nil?

          ObjectValidation::Cause.new(field: "#{path}.optionalOldSelf", reason: "FieldValueInvalid",
                                      message: "Invalid value: may not be set if oldSelf is not used in rule")
        end

        def rule_errors(rule, schema, path)
          source = rule["rule"].to_s.strip
          message = rule["message"].to_s.strip
          expression = rule["messageExpression"].to_s
          field_path = rule["fieldPath"].to_s
          cause = lambda do |field, reason, detail|
            ObjectValidation::Cause.new(field: "#{path}.#{field}", reason: reason, message: detail)
          end
          errors = []
          if source.empty?
            errors << cause.call("rule", "FieldValueRequired", "Required value: rule is not specified")
          elsif !rule["message"].to_s.empty? && message.empty?
            errors << cause.call("message", "FieldValueInvalid", "Invalid value: must be non-empty if specified")
          elsif message.match?(/[\r\n]/)
            errors << cause.call("message", "FieldValueInvalid", "Invalid value: must not contain line breaks")
          elsif source.match?(/[\r\n]/) && message.empty?
            errors << cause.call("message", "FieldValueRequired", "Required value: message must be specified if rule contains line breaks")
          end
          if !expression.empty? && expression.strip.empty?
            errors << cause.call("messageExpression", "FieldValueRequired", "Required value: messageExpression must be non-empty if specified")
          end
          if rule["reason"] && !REASONS.include?(rule["reason"])
            errors << cause.call("reason", "FieldValueNotSupported", "Unsupported value: #{rule["reason"].inspect}")
          end
          if !field_path.empty? && (field_path.match?(/[\r\n]/) || !CELFieldPath.segments(field_path, schema))
            errors << cause.call("fieldPath", "FieldValueInvalid", "Invalid value: must be a valid path")
          end
          errors
        end

        def base_environment
          @base_environment ||= begin
            env = Checker::Declarations.environment
            (env.ident_names & %w[authorizer request namespaceObject]).reduce(env) { |clean, name| clean.without_ident(name) }
          end
        end

        def validate_expression(expression, environment, expected, path, causes, schema, cardinality, label)
          return 0 unless expression.is_a?(String) && !expression.empty?

          path = "#{path}.#{label}"
          type, issues, ast = Checker.compile(environment, expression)
          unless issues.empty? && expected.exact?(type)
            subject = label == "rule" ? "cel expression" : label
            message = issues.empty? ? "#{subject} must evaluate to a #{expected}" : "#{label} compilation failed: #{issues}"
            causes << ObjectValidation::Cause.new(field: path, reason: "FieldValueInvalid", message: "Invalid value: #{message}")
            return 0
          end

          yield ast if block_given?
          cost = CELCost.cost(ast, {"self" => schema, "oldSelf" => schema}) * cardinality
          causes << cost_error(path, "estimated #{label} cost", cost, EXPRESSION_LIMIT) if cost > EXPRESSION_LIMIT
          cost
        end

        def cost_error(path, name, cost, limit)
          ratio = cost.to_f / limit
          factor = if ratio > 100 then "more than 100x"
                   elsif ratio < 1.5 then format("%fx", ratio)
                   else format("%.1fx", ratio)
                   end
          detail = "#{name} exceeds budget by factor of #{factor} " \
                   "(try simplifying the rule, or adding maxItems, maxProperties, and maxLength where arrays, maps, and strings are declared)"
          ObjectValidation::Cause.new(field: path, reason: "FieldValueForbidden", message: "Forbidden: #{detail}")
        end
      end
    end
  end
end
