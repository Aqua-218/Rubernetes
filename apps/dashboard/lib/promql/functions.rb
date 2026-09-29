# frozen_string_literal: true

module Promql
  # Function table: name -> [argument types, variadic?, return type].
  # Types: :scalar, :vector, :matrix, :string.  Evaluation lives in Engine.
  module Functions
    TABLE = {
      "abs" => [[:vector], false, :vector],
      "absent" => [[:vector], false, :vector],
      "absent_over_time" => [[:matrix], false, :vector],
      "acos" => [[:vector], false, :vector],
      "acosh" => [[:vector], false, :vector],
      "asin" => [[:vector], false, :vector],
      "asinh" => [[:vector], false, :vector],
      "atan" => [[:vector], false, :vector],
      "atanh" => [[:vector], false, :vector],
      "avg_over_time" => [[:matrix], false, :vector],
      "ceil" => [[:vector], false, :vector],
      "changes" => [[:matrix], false, :vector],
      "clamp" => [[:vector, :scalar, :scalar], false, :vector],
      "clamp_max" => [[:vector, :scalar], false, :vector],
      "clamp_min" => [[:vector, :scalar], false, :vector],
      "cos" => [[:vector], false, :vector],
      "cosh" => [[:vector], false, :vector],
      "count_over_time" => [[:matrix], false, :vector],
      "days_in_month" => [[:vector], true, :vector],
      "day_of_month" => [[:vector], true, :vector],
      "day_of_week" => [[:vector], true, :vector],
      "day_of_year" => [[:vector], true, :vector],
      "deg" => [[:vector], false, :vector],
      "delta" => [[:matrix], false, :vector],
      "deriv" => [[:matrix], false, :vector],
      "double_exponential_smoothing" => [[:matrix, :scalar, :scalar], false, :vector],
      "exp" => [[:vector], false, :vector],
      "floor" => [[:vector], false, :vector],
      "histogram_quantile" => [[:scalar, :vector], false, :vector],
      "holt_winters" => [[:matrix, :scalar, :scalar], false, :vector],
      "hour" => [[:vector], true, :vector],
      "idelta" => [[:matrix], false, :vector],
      "increase" => [[:matrix], false, :vector],
      "irate" => [[:matrix], false, :vector],
      "label_join" => [[:vector, :string, :string, :string], true, :vector],
      "label_replace" => [[:vector, :string, :string, :string, :string], false, :vector],
      "last_over_time" => [[:matrix], false, :vector],
      "ln" => [[:vector], false, :vector],
      "log10" => [[:vector], false, :vector],
      "log2" => [[:vector], false, :vector],
      "mad_over_time" => [[:matrix], false, :vector],
      "max_over_time" => [[:matrix], false, :vector],
      "min_over_time" => [[:matrix], false, :vector],
      "minute" => [[:vector], true, :vector],
      "month" => [[:vector], true, :vector],
      "pi" => [[], false, :scalar],
      "predict_linear" => [[:matrix, :scalar], false, :vector],
      "present_over_time" => [[:matrix], false, :vector],
      "quantile_over_time" => [[:scalar, :matrix], false, :vector],
      "rad" => [[:vector], false, :vector],
      "rate" => [[:matrix], false, :vector],
      "resets" => [[:matrix], false, :vector],
      "round" => [[:vector, :scalar], true, :vector],
      "scalar" => [[:vector], false, :scalar],
      "sgn" => [[:vector], false, :vector],
      "sin" => [[:vector], false, :vector],
      "sinh" => [[:vector], false, :vector],
      "sort" => [[:vector], false, :vector],
      "sort_by_label" => [[:vector, :string], true, :vector],
      "sort_by_label_desc" => [[:vector, :string], true, :vector],
      "sort_desc" => [[:vector], false, :vector],
      "sqrt" => [[:vector], false, :vector],
      "stddev_over_time" => [[:matrix], false, :vector],
      "stdvar_over_time" => [[:matrix], false, :vector],
      "sum_over_time" => [[:matrix], false, :vector],
      "tan" => [[:vector], false, :vector],
      "tanh" => [[:vector], false, :vector],
      "time" => [[], false, :scalar],
      "timestamp" => [[:vector], false, :vector],
      "vector" => [[:scalar], false, :vector],
      "year" => [[:vector], true, :vector]
    }.freeze

    # Functions whose first argument defaults to vector(time()) when omitted.
    TIME_FUNCTIONS = %w[days_in_month day_of_month day_of_week day_of_year hour minute month year].freeze

    module_function

    def known?(name) = TABLE.key?(name)

    def return_type(name) = TABLE.fetch(name)[2]

    def check_arity!(name, args)
      types, variadic, = TABLE.fetch(name)
      required = types.length
      required -= 1 if variadic && (TIME_FUNCTIONS.include?(name) || name == "round")
      if args.length < required || (!variadic && args.length > types.length)
        expected = variadic ? "at least #{required}" : types.length.to_s
        raise ParseError, "expected #{expected} argument(s) in call to #{name.inspect}, got #{args.length}"
      end
      if name == "label_join" && args.length < 3
        raise ParseError, "expected at least 3 argument(s) in call to \"label_join\", got #{args.length}"
      end
    end

    def check_types!(call)
      types, variadic, = TABLE.fetch(call.func)
      call.args.each_with_index do |arg, index|
        expected = types[index] || (variadic ? types.last : nil)
        next if expected.nil?

        actual = arg.type
        actual = :scalar if actual == :scalar
        next if actual == expected
        # A number literal is also acceptable where a scalar is expected; a
        # subquery yields a matrix.
        raise ParseError, "expected type #{expected} in call to function #{call.func.inspect}, got #{actual} for argument #{index + 1}"
      end
    end
  end
end
