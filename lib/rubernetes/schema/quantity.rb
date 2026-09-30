# frozen_string_literal: true

module Rubernetes
  module Schema
    # Port of k8s.io/apimachinery/pkg/api/resource.Quantity parsing and
    # canonical rendering (v1.36.2).
    #
    # Kubernetes keeps the caller's spelling for "already canonical" inputs and
    # rewrites everything else (for example 0.5 -> 500m, 1024Mi -> 1Gi).  The
    # API differential observes those rewrites in stored objects, so the rules
    # are reproduced exactly instead of approximated with a generic formatter.
    class Quantity
      class ParseError < ArgumentError; end

      SPLIT_RE_STRING = "^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$"
      FORMAT_WRONG_MESSAGE = "quantities must match the regular expression '#{SPLIT_RE_STRING}'".freeze
      NUMERIC_MESSAGE = "unable to parse numeric part of quantity"
      SUFFIX_MESSAGE = "unable to parse quantity's suffix"
      NANO = -9
      MAX_INT64 = (1 << 63) - 1
      MAX_INT64_FACTORS = 18
      DECIMAL_SUFFIXES = {
        "n" => -9, "u" => -6, "m" => -3, "" => 0, "k" => 3, "M" => 6, "G" => 9, "T" => 12, "P" => 15, "E" => 18
      }.freeze
      DECIMAL_SUFFIX_BY_EXPONENT = DECIMAL_SUFFIXES.invert.freeze
      BINARY_SUFFIXES = {"Ki" => 10, "Mi" => 20, "Gi" => 30, "Ti" => 40, "Pi" => 50, "Ei" => 60}.freeze
      BINARY_SUFFIX_BY_EXPONENT = BINARY_SUFFIXES.invert.freeze
      FORMATS = %i[decimal_si binary_si decimal_exponent].freeze
      SUFFIX_CHARACTERS = "eEinumkKMGTP"

      include Comparable

      attr_reader :value, :format

      # Parses a JSON value (String or Numeric) the way Quantity.UnmarshalJSON
      # does: numbers are re-read from their textual form.
      def self.from_json(value)
        case value
        when Quantity then value
        when String then parse(value.strip)
        when Integer then parse(value.to_s)
        when Float
          raise ParseError, FORMAT_WRONG_MESSAGE unless value.finite?

          parse(value == value.floor && value.abs < 1e15 ? value.to_i.to_s : value.to_s)
        else
          raise ParseError, FORMAT_WRONG_MESSAGE
        end
      end

      def self.parse(string)
        raise ParseError, FORMAT_WRONG_MESSAGE unless string.is_a?(String)
        raise ParseError, FORMAT_WRONG_MESSAGE if string.empty?
        return new(0r, :decimal_si, original: "0") if string == "0"

        positive, num, denom, suffix = split(string)
        base, exponent, format = interpret_suffix(suffix)
        digits = num + denom
        scale = -denom.length
        scale += exponent if base == 10
        magnitude = Integer(digits, 10)
        rational = Rational(magnitude, 1) * (10r**scale)
        rational *= (2r**exponent) if base == 2
        rational = -rational unless positive
        original = keep_original?(positive, num, denom, base, exponent, format, magnitude, digits) ? string : nil
        if original.nil?
          rational = round_to_nano(rational)
          if format == :binary_si
            rational = Rational(MAX_INT64, 1) if rational > MAX_INT64
            format = :decimal_si if rational > 0 && rational < 1
          end
        end
        new(rational, format, original: original)
      end

      def initialize(value, format = :decimal_si, original: nil)
        raise ArgumentError, "quantity value must be Rational" unless value.is_a?(Rational)
        raise ArgumentError, "unknown quantity format #{format.inspect}" unless FORMATS.include?(format)

        @value = value
        @format = format
        @original = original&.dup&.freeze
        freeze
      end

      def zero?
        @value.zero?
      end

      def sign
        @value <=> 0
      end

      def negative?
        @value.negative?
      end

      # Milli-value like Quantity.MilliValue (rounded up to the next milli).
      def milli_value
        (@value * 1000).ceil
      end

      def integer?
        @value.denominator == 1
      end

      def <=>(other)
        other = self.class.from_json(other) unless other.is_a?(Quantity)
        @value <=> other.value
      end

      def ==(other)
        other.is_a?(Quantity) && (@value <=> other.value).zero?
      end
      alias eql? ==

      def hash
        @value.hash
      end

      def to_s
        @original || canonical
      end

      def to_json(*)
        to_s.to_json(*)
      end

      def inspect
        "#<Rubernetes::Schema::Quantity #{self}>"
      end

      # Quantity.CanonicalizeBytes: number and suffix of the canonical form.
      def canonical
        return "0" if zero?

        format = @format
        rounded = nil
        if format == :binary_si
          if @value > -1024 && @value < 1024
            format = :decimal_si
          else
            rounded = round_away_from_zero(@value)
            format = :decimal_si unless rounded == @value
          end
        end
        case format
        when :decimal_si, :decimal_exponent
          number, exponent = canonical_decimal
          suffix = if format == :decimal_si
                     DECIMAL_SUFFIX_BY_EXPONENT.fetch(exponent, "")
                   else
                     exponent.zero? ? "" : "e#{exponent}"
                   end
          "#{number}#{suffix}"
        else
          amount, times = remove_factors(rounded.to_i, 1024)
          "#{amount}#{BINARY_SUFFIX_BY_EXPONENT.fetch(times * 10, "")}"
        end
      end

      private

      # Renders coefficient x 10^exponent with the exponent snapped to a
      # multiple of three, mirroring int64Amount/infDecAmount.AsCanonicalBytes.
      def canonical_decimal
        coefficient, exponent = decimal_parts(@value)
        coefficient, times = remove_factors(coefficient, 10)
        exponent += times
        until (exponent % 3).zero?
          coefficient *= 10
          exponent -= 1
        end
        [coefficient.to_s, exponent]
      end

      # Exact decimal expansion: every parsed quantity is either an integer or
      # was rounded to nano precision, so the denominator divides 10^9.
      def decimal_parts(rational)
        exponent = 0
        scaled = rational
        until scaled.denominator == 1
          scaled *= 10
          exponent -= 1
          raise ArgumentError, "quantity #{rational} has no finite decimal expansion" if exponent < -30
        end
        [scaled.numerator, exponent]
      end

      def remove_factors(value, base)
        times = 0
        negative = value.negative?
        result = negative ? -value : value
        while result >= base && (result % base).zero?
          times += 1
          result /= base
        end
        [negative ? -result : result, times]
      end

      def round_away_from_zero(rational)
        rational.negative? ? Rational(rational.floor, 1) : Rational(rational.ceil, 1)
      end

      class << self
        private

        # parseQuantityString: sign, integer digits, fraction digits, suffix.
        def split(string)
          bytes = string
          pos = 0
          finish = bytes.length
          positive = true
          case bytes[0]
          when "-"
            positive = false
            pos += 1
          when "+"
            pos += 1
          end
          index = pos
          while index < finish && bytes[index] == "0"
            pos += 1
            index += 1
          end
          return [positive, "0", "", ""] if pos >= finish

          num_start = pos
          pos += 1 while pos < finish && digit?(bytes[pos])
          num = bytes[num_start...pos]
          num = "0" if num.empty?
          return [positive, num, "", ""] if pos >= finish

          denom = ""
          if bytes[pos] == "."
            pos += 1
            denom_start = pos
            pos += 1 while pos < finish && digit?(bytes[pos])
            denom = bytes[denom_start...pos]
            return [positive, num, denom, ""] if pos >= finish
          end
          suffix_start = pos
          pos += 1 while pos < finish && SUFFIX_CHARACTERS.include?(bytes[pos])
          return [positive, num, denom, bytes[suffix_start...finish]] if pos >= finish

          pos += 1 if %w[- +].include?(bytes[pos])
          pos += 1 while pos < finish && digit?(bytes[pos])
          raise ParseError, FORMAT_WRONG_MESSAGE unless pos >= finish

          [positive, num, denom, bytes[suffix_start...finish]]
        end

        def digit?(character)
          !character.nil? && character >= "0" && character <= "9"
        end

        def interpret_suffix(suffix)
          return [10, DECIMAL_SUFFIXES.fetch(suffix), :decimal_si] if DECIMAL_SUFFIXES.key?(suffix)
          return [2, BINARY_SUFFIXES.fetch(suffix), :binary_si] if BINARY_SUFFIXES.key?(suffix)

          if suffix.length > 1 && %w[e E].include?(suffix[0])
            exponent = Integer(suffix[1..], 10, exception: false)
            raise ParseError, SUFFIX_MESSAGE if exponent.nil?

            return [10, exponent, :decimal_exponent]
          end
          raise ParseError, SUFFIX_MESSAGE
        end

        # ParseQuantity keeps the caller's spelling only on its int64 fast
        # path and only when that spelling is already canonical.
        def keep_original?(_positive, num, denom, base, exponent, format, magnitude, digits)
          precision = if format == :binary_si
                        exponent >= 0 && denom.empty? ? 15 - num.length - (exponent * 3 / 10) - 1 : -1
                      else
                        MAX_INT64_FACTORS - digits.length
                      end
          return false if precision.negative?

          scale = -denom.length
          scale += exponent if base == 10
          return false if scale < NANO
          return false if magnitude > MAX_INT64

          mantissa = base == 2 ? (1 << exponent) : 1
          result = magnitude * mantissa
          return false if result > MAX_INT64

          if format == :binary_si
            (exponent % 10).zero? && (magnitude & 0x07) != 0
          else
            (scale % 3).zero? && !digits.end_with?("000") && digits[0] != "0"
          end
        end

        # inf.Dec rounding to nano precision, away from zero.
        def round_to_nano(rational)
          scaled = rational * (10**9)
          return rational if scaled.denominator == 1

          rounded = rational.negative? ? scaled.floor : scaled.ceil
          Rational(rounded, 10**9)
        end
      end
    end
  end
end
