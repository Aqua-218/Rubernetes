# frozen_string_literal: true

require_relative "../../security/cel/evaluator"
require_relative "cel_field_path"
require_relative "cel_values"

module Rubernetes
  module API
    module CRD
      # Evaluate schema rules against values correlated across resource
      # revisions, sharing the request's CEL budget throughout the schema.
      module CELRuntime
        RUNTIME_CEL_BUDGET = 10_000_000
        MAX_CEL_MESSAGE_BYTES = 5 * 1024
        ERROR_TYPE_TEXT = {"FieldValueInvalid" => "Invalid value", "FieldValueForbidden" => "Forbidden", "FieldValueRequired" => "Required value",
                           "FieldValueDuplicate" => "Duplicate value"}.freeze

        private

        # x-kubernetes-validations: each rule sees `self` (and `oldSelf` on
        # update); a false result yields the rule's message / messageExpression.
        # Validator.validate: each visit of a node that has a validator is one
        # evaluation, its time including the nodes below it.
        def validate_cel(value, schema, path, causes, budget:, correlation: nil, ancestor_unchanged: false, root: false)
          return if budget.stopped?

          options = {correlation: correlation, ancestor_unchanged: ancestor_unchanged, root: root, budget: budget}
          return validate_cel_node(value, schema, path, causes, **options) unless CRD.metrics && @validator_nodes.key?(schema)

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            validate_cel_node(value, schema, path, causes, **options)
          ensure
            observe_cel("apiserver_cel_evaluation_duration_seconds", started)
          end
        end

        def validate_cel_node(value, schema, path, causes, correlation:, ancestor_unchanged:, root:, budget:)
          return unless schema.is_a?(Hash) && !value.nil?

          unchanged = correlation ? correlation.unchanged? : ancestor_unchanged
          validate_cel_rules(value, schema, path, causes, old_value: correlation&.old_value, unchanged: unchanged, root: root, budget: budget)
          return if budget.stopped?

          case value
          when Hash
            validate_cel_properties(value, schema, path, causes, correlation: correlation, unchanged: unchanged, root: root, budget: budget)
          when Array
            return unless schema["items"].is_a?(Hash)

            value.each_with_index do |item, index|
              validate_cel(item, schema["items"], path + ["[#{index}]"], causes,
                           correlation: correlation&.child(index), ancestor_unchanged: unchanged, budget: budget)
            end
          end
        end

        def validate_cel_properties(value, schema, path, causes, correlation:, unchanged:, root:, budget:)
          properties = schema["properties"] || {}
          additional = schema["additionalProperties"]
          value.each do |key, child|
            next if root && %w[apiVersion kind metadata].include?(key)

            known_property = properties.key?(key)
            child_schema = known_property ? properties[key] : additional
            child_path = path + [known_property ? key : "[#{key}]"]
            validate_cel(child, child_schema, child_path, causes,
                         correlation: correlation&.child(key), ancestor_unchanged: unchanged, budget: budget)
          end
        end

        def validate_cel_rules(value, schema, path, causes, old_value:, unchanged:, root:, budget:)
          rules = Array(schema["x-kubernetes-validations"])
          return if rules.empty?

          current = CELValues.wrap(value, schema, resource: root)
          previous = CELValues.wrap(old_value, schema, resource: root)
          rules.each do |rule|
            transition = uses_old_self?(rule["rule"])
            optional = rule["optionalOldSelf"] == true
            next if transition && old_value.nil? && !optional

            variables = {"self" => current}
            if optional
              optional_value = Security::CEL::Values::Optional
              variables["oldSelf"] = old_value.nil? ? optional_value.none : optional_value.of(previous)
            elsif !old_value.nil?
              variables["oldSelf"] = previous
            end
            result = begin
              evaluate_cel(rule["rule"], variables, budget)
            rescue Security::CEL::Evaluator::CostLimitExceeded => error
              add_cel_budget_error(causes, path, schema, error, rule["rule"], budget, "rule")
              break
            rescue StandardError => error
              add(causes, path, "Invalid value: #{go_quote(schema["type"].to_s)}: #{error.message} evaluating rule: #{rule["rule"]}",
                  "FieldValueInvalid")
              next
            end
            next if result == true || (unchanged && !transition)

            message = rule["message"].to_s.strip
            field = rule["fieldPath"].to_s
            error_path = field.empty? ? path : path + (CELFieldPath.segments(field, schema) || [])
            if rule["messageExpression"].is_a?(String) && !rule["messageExpression"].empty?
              message = begin
                evaluated = evaluate_cel(rule["messageExpression"], variables, budget)
                cel_message(evaluated) || message
              rescue Security::CEL::Evaluator::CostLimitExceeded => error
                add_cel_budget_error(causes, error_path, schema, error, rule["messageExpression"], budget, "messageExpression")
                break
              rescue StandardError
                message
              end
            end
            detail = message.empty? ? "failed rule: #{rule["rule"].to_s.strip}" : message
            reason = rule["reason"] || "FieldValueInvalid"
            add(causes, error_path, "#{ERROR_TYPE_TEXT.fetch(reason, "Invalid value")}: #{detail}", reason)
          end
        end

        def cel_message(value)
          return unless value.is_a?(String)

          message = value.strip
          return if message.empty? || message.bytesize > MAX_CEL_MESSAGE_BYTES || message.include?("\n")

          message
        end

        def evaluate_cel(expression, variables, budget)
          return @cel.evaluate(expression, variables, budget) if @cel.is_a?(Security::CEL::Evaluator)

          @cel.evaluate(expression, variables)
        end

        def add_cel_budget_error(causes, path, schema, error, expression, budget, subject)
          budget.stop!
          detail = if error.aggregate?
                     "validation failed due to running out of cost budget, no further validation rules will be run"
                   else
                     "no further validation rules will be run due to call cost exceeds limit for #{subject}: #{expression}"
                   end
          add(causes, path, "Invalid value: #{go_quote(schema["type"].to_s)}: #{detail}", "FieldValueInvalid")
        end

        def uses_old_self?(expression)
          return false unless expression.to_s.include?("oldSelf")

          tokens = Security::CEL::Lexer.new(expression).tokens
          tokens.each_with_index.any? do |token, index|
            token.type == :identifier && token.value == "oldSelf" && (index.zero? || !%w[. .?].include?(tokens[index - 1].value))
          end
        rescue Security::CEL::SyntaxError
          false
        end
      end
    end
  end
end
