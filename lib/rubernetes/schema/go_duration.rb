# frozen_string_literal: true

module Rubernetes
  module Schema
    # time.Duration text form used by metav1.Duration JSON ("1h0m0s", "1.5ms").
    # Kubernetes protobuf carries the same value as int64 nanoseconds, so both
    # directions live here rather than in a codec-specific helper.
    module GoDuration
      class ParseError < ArgumentError; end

      NANOSECOND = 1
      MICROSECOND = 1_000
      MILLISECOND = 1_000_000
      SECOND = 1_000_000_000
      MINUTE = 60 * SECOND
      HOUR = 60 * MINUTE
      UNITS = {
        "ns" => NANOSECOND, "us" => MICROSECOND, "µs" => MICROSECOND, "μs" => MICROSECOND,
        "ms" => MILLISECOND, "s" => SECOND, "m" => MINUTE, "h" => HOUR
      }.freeze
      TOKEN = /\A([0-9]*)(?:\.([0-9]*))?(ns|us|µs|μs|ms|s|m|h)/.freeze

      module_function

      # time.Duration.String()
      def format(nanoseconds)
        total = Integer(nanoseconds)
        negative = total.negative?
        remaining = total.abs
        result =
          if remaining < SECOND
            return "0s" if remaining.zero?

            if remaining < MICROSECOND
              "#{remaining}ns"
            elsif remaining < MILLISECOND
              "#{fraction(remaining, 3)}µs"
            else
              "#{fraction(remaining, 6)}ms"
            end
          else
            seconds_text = fraction(remaining, 9)
            whole_seconds = remaining / SECOND
            if whole_seconds < 60
              "#{seconds_text}s"
            else
              seconds_only = fraction(remaining - (whole_seconds - (whole_seconds % 60)) * SECOND, 9)
              minutes = whole_seconds / 60
              text = "#{seconds_only}s"
              text = "#{minutes % 60}m#{text}"
              text = "#{minutes / 60}h#{text}" if minutes >= 60
              text
            end
          end
        negative ? "-#{result}" : result
      end

      # time.ParseDuration: a signed sequence of decimal numbers with units.
      def parse(text)
        raise ParseError, "time: invalid duration #{text.inspect}" unless text.is_a?(String)

        remaining = text.dup
        negative = false
        if remaining.start_with?("-", "+")
          negative = remaining.start_with?("-")
          remaining = remaining[1..]
        end
        return 0 if remaining == "0"
        raise ParseError, "time: invalid duration #{text.inspect}" if remaining.empty?

        total = 0r
        until remaining.empty?
          match = TOKEN.match(remaining)
          if match.nil?
            if remaining.match?(/\A[0-9.]+\z/)
              raise ParseError, "time: missing unit in duration #{text.inspect}"
            end

            raise ParseError, "time: invalid duration #{text.inspect}"
          end
          whole = match[1]
          fraction_digits = match[2]
          raise ParseError, "time: invalid duration #{text.inspect}" if whole.empty? && (fraction_digits.nil? || fraction_digits.empty?)

          value = Rational(whole.empty? ? 0 : Integer(whole, 10), 1)
          value += Rational(Integer(fraction_digits, 10), 10**fraction_digits.length) unless fraction_digits.nil? || fraction_digits.empty?
          total += value * UNITS.fetch(match[3])
          remaining = remaining[match[0].length..]
        end
        nanoseconds = total.floor
        raise ParseError, "time: invalid duration #{text.inspect}" if nanoseconds > (1 << 63) - 1

        negative ? -nanoseconds : nanoseconds
      end

      # fmtFrac + fmtInt: integer part followed by a fraction with trailing
      # zeros removed.
      def fraction(nanoseconds, precision)
        divisor = 10**precision
        whole = nanoseconds / divisor
        remainder = nanoseconds % divisor
        return whole.to_s if remainder.zero?

        digits = remainder.to_s.rjust(precision, "0").sub(/0+\z/, "")
        "#{whole}.#{digits}"
      end
      private_class_method :fraction
    end
  end
end
