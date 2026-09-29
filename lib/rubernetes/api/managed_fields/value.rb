# frozen_string_literal: true

module Rubernetes
  module API
    module ManagedFields
      # sigs.k8s.io/structured-merge-diff/v6/value for plain Ruby values
      # (Hash with String keys, Array, String, Integer, Float, true/false,
      # nil for JSON null).  A field that is absent is ABSENT, never nil.
      module Value
        ABSENT = Object.new.tap do |absent|
          def absent.inspect = "ABSENT"
          absent.freeze
        end

        module_function

        def absent?(value) = value.equal?(ABSENT)
        def numeric?(value) = value.is_a?(Integer) || value.is_a?(Float)
        def scalar?(value) = numeric?(value) || value.is_a?(String) || value == true || value == false

        # Integral floats compare and hash as integers, as value.Equals
        # compares an int with a float numerically.
        def normalize(value)
          value.is_a?(Float) && value.finite? && value == value.floor && value.abs < 2**63 ? value.to_i : value
        end

        def rank(value)
          case value
          when Integer, Float then 0
          when String then 1
          when true, false then 2
          when Array then 3
          when Hash then 4
          else 5
          end
        end

        # value.Compare: numbers < strings < booleans < lists < maps < null.
        def compare(lhs, rhs)
          left = rank(lhs)
          right = rank(rhs)
          return left <=> right unless left == right

          case left
          when 0 then lhs <=> rhs
          when 1 then lhs <=> rhs
          when 2 then lhs == rhs ? 0 : (lhs ? 1 : -1)
          when 3 then compare_lists(lhs, rhs)
          when 4 then compare_maps(lhs, rhs)
          else 0
          end
        end

        def compare_lists(lhs, rhs)
          lhs.each_with_index do |item, index|
            return 1 if index >= rhs.length

            result = compare(item, rhs[index])
            return result unless result.zero?
          end
          lhs.length < rhs.length ? -1 : 0
        end

        # MapCompareUsing with LexicalKeyOrder.
        def compare_maps(lhs, rhs)
          return 0 if lhs.empty? && rhs.empty?

          keys = (lhs.keys | rhs.keys).sort
          keys.each_with_index do |key, index|
            return -1 if index == lhs.length
            return 1 if index == rhs.length
            return 1 unless lhs.key?(key)
            return -1 unless rhs.key?(key)

            result = compare(lhs[key], rhs[key])
            return result unless result.zero?
          end
          0
        end

        # value.Equals.
        def equal?(lhs, rhs)
          if lhs.is_a?(Float) || rhs.is_a?(Float)
            return numeric?(lhs) && numeric?(rhs) && lhs.to_f == rhs.to_f
          end

          case lhs
          when Integer then rhs.is_a?(Integer) && lhs == rhs
          when String then rhs.is_a?(String) && lhs == rhs
          when true, false then (rhs == true || rhs == false) && lhs == rhs
          when Array
            rhs.is_a?(Array) && lhs.length == rhs.length && lhs.each_index.all? { |index| equal?(lhs[index], rhs[index]) }
          when Hash
            rhs.is_a?(Hash) && lhs.length == rhs.length &&
              lhs.all? { |key, item| rhs.key?(key) && equal?(item, rhs[key]) }
          when nil then rhs.nil?
          else lhs == rhs
          end
        end

        # value.ToString, as a path is rendered in a conflict message.
        def to_string(value)
          case value
          when nil then "null"
          when Float then format_float(value)
          when Integer then value.to_s
          when String then go_quote(value)
          when true, false then value.to_s
          when Array then "[#{value.map { |item| to_string(item) }.join(",")}]"
          when Hash then value.map { |key, item| "#{key}=#{to_string(item)}" }.join
          else "{{undefined}}"
          end
        end

        # fmt's %q.
        def go_quote(string)
          out = +'"'
          string.each_char do |char|
            out << case char
                   when '"' then '\\"'
                   when "\\" then "\\\\"
                   when "\n" then "\\n"
                   when "\t" then "\\t"
                   when "\r" then "\\r"
                   when "\a" then "\\a"
                   when "\b" then "\\b"
                   when "\f" then "\\f"
                   when "\v" then "\\v"
                   else
                     code = char.ord
                     code < 0x20 || code == 0x7f ? format("\\x%02x", code) : char
                   end
          end
          out << '"'
        end

        # %v of a float64: strconv.FormatFloat(f, 'g', -1, 64).
        def format_float(value)
          return value.to_s if value.nan? || value.infinite?

          digits, exponent = shortest(value)
          return exponential(digits, exponent, value.negative?) if exponent < -4 || exponent >= 21

          fixed(digits, exponent, value.negative?)
        end

        # The shortest round-trip digits and the decimal exponent of the
        # first digit (value = 0.d1d2... * 10**(exponent + 1)).
        def shortest(value)
          return [["0"], 0] if value.zero?

          candidate = value.abs.to_s
          if candidate.include?("e")
            mantissa, exponent = candidate.split("e")
          else
            integer, fraction = candidate.split(".")
            fraction = fraction.to_s.sub(/0+\z/, "")
            if integer == "0"
              leading = fraction[/\A0*/].length
              return [fraction[leading..].chars, -(leading + 1)]
            end
            return [(integer + fraction).sub(/0+\z/, "").then { |d| d.empty? ? "0" : d }.chars, integer.length - 1]
          end
          digits = mantissa.delete(".").sub(/0+\z/, "")
          [(digits.empty? ? "0" : digits).chars, exponent.to_i]
        end

        def exponential(digits, exponent, negative)
          mantissa = digits.first + (digits.length > 1 ? ".#{digits.drop(1).join}" : "")
          sign = exponent.negative? ? "-" : "+"
          "#{negative ? "-" : ""}#{mantissa}e#{sign}#{exponent.abs.to_s.rjust(2, "0")}"
        end

        def fixed(digits, exponent, negative)
          text = if exponent.negative?
                   "0.#{"0" * (-exponent - 1)}#{digits.join}"
                 elsif digits.length > exponent + 1
                   "#{digits[0..exponent].join}.#{digits[(exponent + 1)..].join}"
                 else
                   digits.join + ("0" * (exponent + 1 - digits.length))
                 end
          "#{negative ? "-" : ""}#{text}"
        end

        # encoding/json (and jsoniter ConfigCompatibleWithStandardLibrary)
        # output for a key or value path element.
        def to_json(value)
          case value
          when nil then "null"
          when true then "true"
          when false then "false"
          when Integer then value.to_s
          when Float then json_float(value)
          when String then json_string(value)
          when Array then "[#{value.map { |item| to_json(item) }.join(",")}]"
          when Hash then "{#{value.keys.sort.map { |key| "#{json_string(key.to_s)}:#{to_json(value[key])}" }.join(",")}}"
          else json_string(value.to_s)
          end
        end

        # encoding/json floatEncoder: 'f' unless the exponent is extreme,
        # then 'e' with a two-digit exponent.
        def json_float(value)
          digits, exponent = shortest(value)
          absolute = value.abs
          return fixed(digits, exponent, value.negative?) unless absolute != 0 && (absolute < 1e-6 || absolute >= 1e21)

          exponential(digits, exponent, value.negative?)
        end

        HTML_ESCAPES = {"<" => "\\u003c", ">" => "\\u003e", "&" => "\\u0026",
                        " " => "\\u2028", " " => "\\u2029"}.freeze

        def json_string(string)
          out = +'"'
          string.each_char do |char|
            out << case char
                   when '"' then '\\"'
                   when "\\" then "\\\\"
                   when "\n" then "\\n"
                   when "\r" then "\\r"
                   when "\t" then "\\t"
                   else
                     escaped = HTML_ESCAPES[char]
                     if escaped
                       escaped
                     elsif char.ord < 0x20
                       format("\\u%04x", char.ord)
                     else
                       char
                     end
                   end
          end
          out << '"'
        end
      end
    end
  end
end
