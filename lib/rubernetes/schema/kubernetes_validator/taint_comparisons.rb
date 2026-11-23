# frozen_string_literal: true

require_relative "../../taint_toleration"

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      TOLERATIONS_ANNOTATION = "scheduler.alpha.kubernetes.io/tolerations"

      def taint_comparison_errors(root, old, kind, options)
        if kind == "RuntimeClass"
          path = %w[scheduling tolerations]
          return comparison_entry_errors(dig_path(root, path), path, false)
        end

        base = kind == "Pod" ? [] : POD_TEMPLATE_PATHS[kind]
        return [] unless base

        path = base + %w[spec tolerations]
        enabled = options.include?(TaintToleration::GATE) ||
                  (old && Array(dig_path(old, path)).any? { |entry| entry.is_a?(Hash) && %w[Gt Lt].include?(fetch(entry, "operator")) })
        annotation = dig_path(root, base + ["metadata", "annotations", TOLERATIONS_ANNOTATION])
        annotated = annotation_comparison_errors(annotation, base, enabled)
        annotated.concat(comparison_entry_errors(dig_path(root, path), path, enabled))
      end

      def annotation_comparison_errors(text, base, enabled)
        return [] unless text.is_a?(String) && !text.empty?

        path = (base.empty? ? %w[metadata annotations] : base + ["annotations"])
        entries = JSON.parse(text)
        return [] if entries.nil?
        unless entries.is_a?(Array)
          return [ValidationIssue.new(path: path, code: :invalid, message: "expected a JSON array of tolerations", value: TOLERATIONS_ANNOTATION)]
        end

        comparison_entry_errors(entries, path + [TOLERATIONS_ANNOTATION], enabled)
      rescue JSON::ParserError => error
        [ValidationIssue.new(path: path, code: :invalid, message: error.message, value: TOLERATIONS_ANNOTATION)]
      end

      def comparison_entry_errors(entries, path, enabled)
        return [] unless entries.is_a?(Array)

        entries.each_with_index.flat_map do |entry, index|
          next [] unless entry.is_a?(Hash)

          operator = fetch(entry, "operator")
          next [] unless %w[Gt Lt].include?(operator)

          if enabled
            numeric_toleration_errors(fetch(entry, "value").to_s, path + [index.to_s, "value"])
          else
            [ValidationIssue.new(path: path + [index.to_s, "operator"], code: :unsupported, value: operator,
                                 kubernetes_type: "Unsupported value", message: 'supported values: "Equal", "Exists", "Lt", "Gt"')]
          end
        end
      end

      def numeric_toleration_errors(value, path)
        return [] if TaintToleration.integer(value)

        errors = []
        unless TaintToleration::DECIMAL.match?(value)
          message = value.empty? ? "must not be empty" : "must be a valid decimal integer in canonical form"
          errors << ValidationIssue.new(path: path, code: :invalid, value: value, message: message)
        end
        reason = if !/\A[+-]?[0-9]+\z/.match?(value)
                   "invalid syntax"
                 elsif value.sub(/\A[+-]?0*/, "").size > 19 || !TaintToleration::INT64.cover?(value.to_i)
                   "value out of range"
                 end
        errors << ValidationIssue.new(path: path, code: :invalid, value: value, message: "strconv.ParseInt: parsing #{value.inspect}: #{reason}") if reason
        errors
      end
    end
  end
end
