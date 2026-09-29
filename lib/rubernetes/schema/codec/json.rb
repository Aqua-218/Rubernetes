# frozen_string_literal: true

module Rubernetes
  module Schema
    class Codec
      # JSON parser/generator with duplicate-key detection and deterministic
      # canonical generation.  JSON.parse is retained for its battle-tested
      # lexical handling; the object_class hook lets us reject duplicate keys
      # after JSON escape sequences have been decoded.
      module JSONCodec
        class DuplicateCheckingHash < Hash
          def []=(key, value)
            if key?(key)
              raise Codec::DuplicateKeyError, "duplicate JSON object key #{key.inspect}"
            end

            super
          end
        end

        module_function

        def load(input, strict: true, max_bytes: Codec::DEFAULT_MAX_BYTES, max_depth: Codec::DEFAULT_MAX_DEPTH)
          Codec.validate_body!(input, max_bytes)
          input = input.dup.force_encoding(Encoding::UTF_8)
          validate_utf8!(input)
          object_class = strict ? DuplicateCheckingHash : Hash
          value = ::JSON.parse(
            input,
            object_class: object_class,
            array_class: Array,
            allow_nan: false,
            max_nesting: [max_depth + 1, 1].max
          )
          Codec.validate_depth!(value, max_depth)
          value
        rescue Codec::Error
          raise
        rescue ::JSON::NestingError => error
          raise Codec::LimitError.new("JSON nesting exceeds #{max_depth} levels"), cause: error
        rescue ::JSON::ParserError, EncodingError => error
          raise Codec::ParseError.new("invalid JSON: #{error.message}"), cause: error
        end

        def dump(object, canonical: false, max_bytes: Codec::DEFAULT_MAX_BYTES, max_depth: Codec::DEFAULT_MAX_DEPTH)
          normalized = Codec.normalize_value(object, max_depth: max_depth)
          Codec.validate_depth!(normalized, max_depth)
          output = if canonical
                     canonical_encode(normalized, max_depth: max_depth)
                   else
                     ::JSON.generate(normalized, allow_nan: false)
                   end
          output = output.encode(Encoding::UTF_8)
          Codec.validate_output!(output, max_bytes)
        rescue Codec::Error
          raise
        rescue ::JSON::GeneratorError, EncodingError, TypeError => error
          raise Codec::EncodeError.new("cannot encode JSON: #{error.message}"), cause: error
        end

        alias parse load
        alias generate dump

        def canonical_encode(value, max_depth:, depth: 0, stack: {})
          raise Codec::LimitError, "codec nesting exceeds #{max_depth} levels" if depth > max_depth

          case value
          when NilClass
            "null"
          when TrueClass
            "true"
          when FalseClass
            "false"
          when Integer
            value.to_s
          when Float
            canonical_float(value)
          when String
            validate_utf8!(value)
            ::JSON.generate(value)
          when Array
            detect_stack_cycle!(value, stack)
            begin
              "[#{value.map { |child| canonical_encode(child, max_depth: max_depth, depth: depth + 1, stack: stack) }.join(",")}]"
            ensure
              stack.delete(value.object_id)
            end
          when Hash
            detect_stack_cycle!(value, stack)
            begin
              entries = value.map do |key, child|
                normalized_key = Codec.normalize_key(key)
                validate_utf8!(normalized_key)
                [normalized_key, child]
              end
              duplicate_keys = entries.group_by(&:first).select { |_key, pair| pair.length > 1 }.keys
              unless duplicate_keys.empty?
                raise Codec::DuplicateKeyError, "object contains duplicate key #{duplicate_keys.first.inspect}"
              end
              entries.sort_by! { |key, _child| key.encode(Encoding::UTF_8).bytes }
              body = entries.map do |key, child|
                "#{::JSON.generate(key)}:#{canonical_encode(child, max_depth: max_depth, depth: depth + 1, stack: stack)}"
              end.join(",")
              "{#{body}}"
            ensure
              stack.delete(value.object_id)
            end
          else
            raise Codec::UnsupportedTypeError, "unsupported canonical JSON value #{value.class}"
          end
        end

        alias canonical canonical_encode
        module_function :parse, :generate, :canonical

        def canonical_float(value)
          raise Codec::EncodeError, "JSON does not support non-finite Float values" unless value.finite?
          return "0" if value.zero?

          text = value.to_s.downcase
          mantissa, exponent_text = text.split("e", 2)
          exponent = exponent_text ? Integer(exponent_text) : 0
          sign = mantissa.start_with?("-") ? "-" : ""
          mantissa = mantissa.delete_prefix("-")
          decimal_position = mantissa.index(".") || mantissa.length
          digits = mantissa.delete(".")
          scientific_exponent = exponent + decimal_position - 1
          leading_zeroes = digits.index(/[^0]/) || digits.length
          digits = digits[leading_zeroes..] || "0"
          scientific_exponent -= leading_zeroes
          digits = digits.sub(/0+\z/, "")
          digits = "0" if digits.empty?

          absolute = value.abs
          if absolute >= 1e-6 && absolute < 1e21
            decimal_position = scientific_exponent + 1
            if decimal_position <= 0
              "#{sign}0.#{"0" * -decimal_position}#{digits}"
            elsif decimal_position >= digits.length
              "#{sign}#{digits}#{"0" * (decimal_position - digits.length)}"
            else
              "#{sign}#{digits[0, decimal_position]}.#{digits[decimal_position..]}"
            end
          else
            mantissa = digits.length == 1 ? digits : "#{digits[0]}.#{digits[1..]}"
            exponent_sign = scientific_exponent.negative? ? "-" : "+"
            "#{sign}#{mantissa}e#{exponent_sign}#{scientific_exponent.abs}"
          end
        end

        def detect_stack_cycle!(value, stack)
          object_id = value.object_id
          raise Codec::UnsupportedTypeError, "cyclic canonical JSON value graph is not supported" if stack.key?(object_id)

          stack[object_id] = true
        end

        def validate_utf8!(value)
          return value if value.valid_encoding? && (value.encoding == Encoding::UTF_8 || value.ascii_only?)

          raise Codec::ParseError, "JSON input and strings must be valid UTF-8"
        end
      end

      JSON = JSONCodec unless const_defined?(:JSON, false)
      Json = JSONCodec unless const_defined?(:Json, false)
    end
  end
end
