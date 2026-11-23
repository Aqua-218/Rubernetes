# frozen_string_literal: true

module Rubernetes
  # core/v1.Toleration.ToleratesTaint, shared by scheduling and eviction.
  module TaintToleration
    GATE = "TaintTolerationComparisonOperators"
    INT64 = (-(2**63)..((2**63) - 1))
    DECIMAL = /\A(?:0|-?[1-9][0-9]*)\z/

    module_function

    def integer(value)
      return unless value.bytesize <= 20 && DECIMAL.match?(value)

      parsed = value.to_i
      parsed if INT64.cover?(parsed)
    end

    def matches?(toleration, taint, comparisons: false)
      return false unless toleration.is_a?(Hash) && taint.is_a?(Hash)

      %w[key effect].each do |field|
        expected = (toleration[field] || toleration[field.to_sym]).to_s
        return false unless expected.empty? || expected == (taint[field] || taint[field.to_sym]).to_s
      end
      value = (toleration["value"] || toleration[:value]).to_s
      actual = (taint["value"] || taint[:value]).to_s
      case (toleration["operator"] || toleration[:operator]).to_s
      when "", "Equal" then actual == value
      when "Exists" then true
      when "Gt", "Lt"
        return false unless comparisons

        threshold = integer(value)
        observed = integer(actual)
        return false unless threshold && observed

        (toleration["operator"] || toleration[:operator]) == "Gt" ? observed > threshold : observed < threshold
      else false
      end
    end
  end
end
