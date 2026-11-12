# frozen_string_literal: true

module Rubernetes
  module Storage
    # Bridges selector objects owned by API::StoreAdapter without coupling the
    # storage layer to API constants. Its stable signature keeps continue
    # tokens bound to the exact label/field query across requests.
    class ExternalSelectorPredicate
      attr_reader :selector_signature

      def initialize(selector, kind: :combined)
        @selector = selector
        @kind = kind.to_sym
        @selector_signature = MemoryStoreSupport.immutable_copy(signature_for(selector, @kind))
        freeze
      end

      def call(object)
        candidate = @kind == :label ? labels_from(object) : object
        @selector.matches?(candidate)
      end

      private

      def labels_from(object)
        metadata = object.is_a?(Hash) ? object.fetch("metadata", {}) : {}
        labels = metadata.fetch("labels", {})
        labels = labels.is_a?(Hash) ? MemoryStoreSupport.deep_dup(labels) : {}
        labels["metadata.name"] = metadata["name"] if metadata.key?("name")
        labels
      end

      # API::Selectors pairs a label and a field selector; API::Selector is
      # one list of requirements.
      def signature_for(selector, kind)
        if Shape.selector_pair?(selector)
          {
            "kind" => kind.to_s,
            "label" => requirements_for(selector.label),
            "field" => requirements_for(selector.field)
          }
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

      attr_reader :signature

      def initialize(label_selector:, field_selector:)
        @label_clauses = parse(label_selector, :label)
        @field_clauses = parse(field_selector, :field)
        @signature = MemoryStoreSupport.digest(
          labels: @label_clauses.map(&:to_h),
          fields: @field_clauses.map(&:to_h)
        ).freeze
        freeze
      end

      def matches?(object)
        @label_clauses.all? { |clause| match_clause(clause, label_value(object, clause.path), object) } &&
          @field_clauses.all? { |clause| match_clause(clause, field_value(object, clause.path), object) }
      end

      def empty?
        @label_clauses.empty? && @field_clauses.empty?
      end

      private

      def parse(selector, kind)
        return [] if selector.nil? || selector == "" || selector == {}
        return [Clause.new(path: "", operator: :callable, values: [selector], kind: kind)] if Shape.callable?(selector)

        if selector.is_a?(Hash)
          return selector.flat_map do |path, expected|
            parse_hash_clause(path, expected, kind)
          end
        end

        expressions = selector.is_a?(Array) ? selector : split_expressions(String(selector))
        expressions.flat_map { |expression| parse_expression(expression, kind) }
      rescue ArgumentError => error
        field = kind == :label ? "labelSelector" : "fieldSelector"
        raise InvalidSelector.new(error.message, field: field)
      end

      def parse_hash_clause(path, expected, kind)
        name = String(path).strip

        if name.start_with?("!")
          validate_selector_key!(name[1..].to_s)
          return [Clause.new(path: name[1..], operator: :not_exists, values: [], kind: kind)] if expected == true || expected.nil?

          raise ArgumentError, "absence selector cannot have a value: #{name}"
        end
        validate_selector_key!(name)

        case expected
        when Array
          [Clause.new(path: name, operator: :in, values: expected.map { |value| String(value) }, kind: kind)]
        when nil
          [Clause.new(path: name, operator: :exists, values: [], kind: kind)]
        else
          [Clause.new(path: name, operator: :equal, values: [String(expected)], kind: kind)]
        end
      end

      def parse_expression(expression, kind)
        text = String(expression).strip
        raise ArgumentError, "selector expression must not be empty" if text.empty?

        if text.start_with?("!") && !text.include?("=")
          path = text[1..].strip
          validate_selector_key!(path)

          return [Clause.new(path: path, operator: :not_exists, values: [], kind: kind)]
        end

        if (match = text.match(/\A(.+?)\s+(notin|in)\s*\((.*)\)\z/i))
          path = match[1].strip
          validate_selector_key!(path)
          values = split_values(match[3])
          raise ArgumentError, "set selector must contain a value" if values.empty?

          operator = match[2].downcase == "in" ? :in : :not_in
          return [Clause.new(path: path, operator: operator, values: values, kind: kind)]
        end

        if (match = text.match(/\A(.+?)\s*(!=|==|=)\s*(.*)\z/))
          path = match[1].strip
          validate_selector_key!(path)
          value = match[3].strip
          raise ArgumentError, "selector key must not be empty" if path.empty?
          raise ArgumentError, "selector value must not be empty" if value.empty?

          operator = match[2] == "!=" ? :not_equal : :equal
          return [Clause.new(path: path, operator: operator, values: [value], kind: kind)]
        end

        validate_selector_key!(text)
        [Clause.new(path: text, operator: :exists, values: [], kind: kind)]
      end

      def validate_selector_key!(value)
        raise ArgumentError, "selector key must not be empty" if value.empty?
        return value unless value.match?(/[=!,()\s]/)

        raise ArgumentError, "selector key #{value.inspect} is invalid"
      end

      def split_expressions(selector)
        expressions = []
        start = 0
        depth = 0
        selector.each_char.with_index do |char, index|
          depth += 1 if char == "("
          depth -= 1 if char == ")"
          raise ArgumentError, "unbalanced selector parentheses" if depth.negative?

          if char == "," && depth.zero?
            expressions << selector[start...index]
            start = index + 1
          end
        end
        raise ArgumentError, "unbalanced selector parentheses" unless depth.zero?

        expressions << selector[start..]
        expressions
      end

      def split_values(values)
        values.split(",").map(&:strip).reject(&:empty?)
      end

      def label_value(object, path)
        labels = object.dig("metadata", "labels")
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

      def match_clause(clause, value, object)
        return clause.values.first.call(object) if clause.operator == :callable

        present = !value.nil?
        string_value = value.nil? ? nil : String(value)
        case clause.operator
        when :exists
          present
        when :not_exists
          !present
        when :equal
          present && string_value == clause.values.first
        when :not_equal
          !present || string_value != clause.values.first
        when :in
          present && clause.values.include?(string_value)
        when :not_in
          !present || !clause.values.include?(string_value)
        else
          false
        end
      end
    end
  end
end
