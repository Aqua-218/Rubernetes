# frozen_string_literal: true

module Rubernetes
  # Set membership for label and field selectors. A missing label and a
  # present, empty label have distinct meanings even when both stringify to "".
  module LabelRequirement
    module_function

    # Commas inside a set belong to the same requirement. Callers decide
    # whether empty terms are legal and report errors in their own API form.
    def split(text)
      return text.split(",", -1).map!(&:strip) unless text.include?("(") || text.include?(")")

      terms = []
      term = +""
      depth = 0
      text.each_char do |char|
        depth += 1 if char == "("
        depth -= 1 if char == ")"
        yield :closing if depth.negative?

        if char == "," && depth.zero?
          terms << term.strip
          term = +""
        else
          term << char
        end
      end
      yield :opening unless depth.zero?
      terms << term.strip
    end

    def matches?(operator, actual, values, present:)
      case operator
      when :equal, :equals then present && actual == values.first
      when :not_equal, :not_equals then !present || actual != values.first
      when :in, "In" then present && values.include?(actual)
      when :not_in, "NotIn" then !present || !values.include?(actual)
      when :exists, "Exists" then present
      when :not_exists, "DoesNotExist" then !present
      else false
      end
    end
  end
end
