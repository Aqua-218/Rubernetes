# frozen_string_literal: true

require_relative "../../label_requirement"

require_relative "../../schema/job_selector"

module Rubernetes
  module Storage
    # Bridges selector objects owned by API::StoreAdapter without coupling the
    # storage layer to API constants. Its stable signature keeps continue
    # tokens bound to the exact label/field query across requests.
    class ExternalSelectorPredicate
      attr_reader :selector_signature, :shard

      def initialize(selector, kind: :combined, shard: nil)
        @selector = selector
        @kind = kind.to_sym
        @shard = shard
        @selector_signature = MemoryStoreSupport.immutable_copy(signature_for(selector, @kind))
        freeze
      end

      def filters_attributes?
        !@selector.empty?
      end

      def call(object, &)
        candidate = @kind == :label ? labels_from(object) : object
        @selector.matches?(candidate, &)
      end

      private

      def labels_from(object)
        metadata = object.is_a?(Hash) ? object.fetch("metadata", {}) : {}
        labels = metadata.fetch("labels", {})
        labels = Schema::JobSelector.inherited_labels(object) || labels if Schema::JobSelector.object?(object)
        labels = labels.is_a?(Hash) ? MemoryStoreSupport.deep_dup(labels) : {}
        labels["metadata.name"] = metadata["name"] if metadata.key?("name")
        labels
      end

      # API::Selectors pairs a label and a field selector; API::Selector is
      # one list of requirements.
      def signature_for(selector, kind)
        if Shape.selector_pair?(selector)
          signature = {
            "kind" => kind.to_s,
            "label" => requirements_for(selector.label),
            "field" => requirements_for(selector.field)
          }
          signature["shard"] = shard.to_s if shard
          signature
        else
          {"kind" => kind.to_s, "requirements" => requirements_for(selector)}
        end
      end

      def requirements_for(selector)
        selector.requirements.map do |requirement|
          {"key" => requirement.key.to_s, "operator" => requirement.operator.to_s, "values" => Array(requirement.values).map(&:to_s)}
        end
      end
    end

    # Label and field selectors parsed once per list or watch.
    class Selector
      Clause = Data.define(:path, :operator, :values, :kind)

      attr_reader :signature, :shard

      def initialize(label_selector:, field_selector:)
        label_clauses = parse(label_selector, :label)
        field_clauses = parse(field_selector, :field)
        @shard = label_selector.shard if label_selector.is_a?(ExternalSelectorPredicate)
        @clauses = label_clauses + field_clauses
        @filters_attributes = @clauses.any? do |clause|
          predicate = clause.values.first
          !predicate.is_a?(ExternalSelectorPredicate) || predicate.filters_attributes?
        end
        @signature = MemoryStoreSupport.digest(
          labels: label_clauses.map(&:to_h),
          fields: field_clauses.map(&:to_h)
        ).freeze
        freeze
      end

      def matches?(object, &)
        @clauses.all? { |clause| match_clause(clause, object, &) }
      end

      def empty?
        @clauses.empty?
      end

      def filters_attributes? = @filters_attributes

      private

      def parse(selector, kind)
        return [] if selector.nil? || selector == "" || selector == {}
        return [Clause.new(path: "", operator: :callable, values: [selector], kind: kind)] if Shape.callable?(selector)

        return selector.map { |path, expected| parse_hash_clause(path, expected, kind) } if selector.is_a?(Hash)

        expressions = if selector.is_a?(Array)
                        selector
                      else
                        LabelRequirement.split(String(selector)) { raise ArgumentError, "unbalanced selector parentheses" }
                      end
        expressions.map { |expression| parse_expression(expression, kind) }
      rescue ArgumentError => error
        field = kind == :label ? "labelSelector" : "fieldSelector"
        raise InvalidSelector.new(error.message, field: field)
      end

      def parse_hash_clause(path, expected, kind)
        name = String(path).strip

        if name.start_with?("!")
          validate_selector_key!(name[1..].to_s)
          return Clause.new(path: name[1..], operator: :not_exists, values: [], kind: kind) if expected == true || expected.nil?

          raise ArgumentError, "absence selector cannot have a value: #{name}"
        end
        validate_selector_key!(name)

        case expected
        when Array
          Clause.new(path: name, operator: :in, values: expected.map { |value| String(value) }, kind: kind)
        when nil
          Clause.new(path: name, operator: :exists, values: [], kind: kind)
        else
          Clause.new(path: name, operator: :equal, values: [String(expected)], kind: kind)
        end
      end

      def parse_expression(expression, kind)
        text = String(expression).strip
        raise ArgumentError, "selector expression must not be empty" if text.empty?

        if text.start_with?("!") && !text.include?("=")
          path = text[1..].strip
          validate_selector_key!(path)

          return Clause.new(path: path, operator: :not_exists, values: [], kind: kind)
        end

        if (match = text.match(/\A(.+?)\s+(notin|in)\s*\((.*)\)\z/i))
          path = match[1].strip
          validate_selector_key!(path)
          values = match[3].split(",").map(&:strip).reject(&:empty?)
          raise ArgumentError, "set selector must contain a value" if values.empty?

          operator = match[2].downcase == "in" ? :in : :not_in
          return Clause.new(path: path, operator: operator, values: values, kind: kind)
        end

        if (match = text.match(/\A(.+?)\s*(!=|==|=)\s*(.*)\z/))
          path = match[1].strip
          validate_selector_key!(path)
          value = match[3].strip
          raise ArgumentError, "selector value must not be empty" if value.empty?

          operator = match[2] == "!=" ? :not_equal : :equal
          return Clause.new(path: path, operator: operator, values: [value], kind: kind)
        end

        validate_selector_key!(text)
        Clause.new(path: text, operator: :exists, values: [], kind: kind)
      end

      def validate_selector_key!(value)
        raise ArgumentError, "selector key must not be empty" if value.empty?
        return value unless value.match?(/[=!,()\s]/)

        raise ArgumentError, "selector key #{value.inspect} is invalid"
      end

      def label_value(object, path)
        labels = object.dig("metadata", "labels")
        labels = Schema::JobSelector.inherited_labels(object) || labels if Schema::JobSelector.object?(object)
        return nil unless labels.is_a?(Hash)

        labels[path]
      end

      def field_value(object, path)
        normalized_path = path.to_s
        normalized_path = "metadata.#{normalized_path}" if %w[name namespace uid resourceVersion].include?(normalized_path)
        normalized_path.split(".").reduce(object) do |value, segment|
          value.is_a?(Hash) ? value[segment] : nil
        end
      end

      def match_clause(clause, object, &)
        return clause.values.first.call(object, &) if clause.operator == :callable

        value = clause.kind == :label ? label_value(object, clause.path) : field_value(object, clause.path)
        LabelRequirement.matches?(clause.operator, value.nil? ? nil : String(value), clause.values, present: !value.nil?)
      end
    end
  end
end
