# frozen_string_literal: true

require "time"
require_relative "ast"
require_relative "validators"

module Rubernetes
  module Security
    module CEL
      module Check
        # interpreter/decorators.go decOptimize (cel.OptOptimize, on in the
        # Kubernetes base environment): when a program is planned, a type
        # conversion (bool bytes double duration dyn int string timestamp
        # type uint) of a constant -- a literal, a type name, a list or map of
        # constants, an already folded conversion -- is evaluated; an error
        # there fails program instantiation.  The conversions follow the
        # ConvertToType methods of common/types.
        module ConstantFolding
          CONVERSIONS = %w[bool bytes double duration dyn int string timestamp type uint].freeze
          MAX_INT = (2**63) - 1
          MIN_INT = -(2**63)
          MIN_UNIX = -62_135_596_800
          MAX_UNIX = 253_402_300_799
          TYPE_NAMES = {Integer => "int", Values::UInt => "uint", Float => "double", String => "string", Values::Bytes => "bytes",
                        TrueClass => "bool", FalseClass => "bool", NilClass => "null_type"}.freeze

          class Failure < StandardError
          end
          Duration = Struct.new(:nanos)
          Timestamp = Struct.new(:seconds, :nanos)
          TypeValue = Struct.new(:name)
          NOT_CONSTANT = Object.new.freeze

          module_function

          # The first folding error in planning order (bottom-up), or nil.
          # type_idents: identifier names that resolve to type values;
          # accepts: conversion name -> the argument type names its
          # overloads take (:any for a type parameter).
          def error(root, type_idents, accepts)
            @accepts = accepts
            fold(root, type_idents)
            nil
          rescue Failure => failure
            failure.message
          end

          def fold(node, type_idents)
            case node.kind
            when :literal then node.value
            when :ident then type_idents.include?(node.name) ? TypeValue.new(node.name) : NOT_CONSTANT
            when :list
              values = node.elements.map { |element| fold(element, type_idents) }
              values.any? { |value| value.equal?(NOT_CONSTANT) } || node.optional_indices.any? ? NOT_CONSTANT : values
            when :map
              pairs = node.entries.map { |entry| [fold(entry.key, type_idents), fold(entry.value, type_idents)] }
              pairs.flatten(1).any? { |value| value.equal?(NOT_CONSTANT) } || node.entries.any?(&:optional) ? NOT_CONSTANT : pairs
            when :call
              fold(node.target, type_idents) if node.member?
              args = node.args.map { |arg| fold(arg, type_idents) }
              return NOT_CONSTANT unless !node.member? && CONVERSIONS.include?(node.name) && args.length == 1 && !args[0].equal?(NOT_CONSTANT)

              convert(node.name, args[0])
            when :select then fold(node.operand, type_idents)
                              NOT_CONSTANT
            when :comprehension
              %i[iter_range accu_init loop_condition loop_step result].each { |part| fold(node.public_send(part), type_idents) }
              NOT_CONSTANT
            when :struct
              node.fields.each { |field| fold(field.value, type_idents) }
              NOT_CONSTANT
            else NOT_CONSTANT
            end
          end

          def type_name(value)
            case value
            when Duration then "google.protobuf.Duration"
            when Timestamp then "google.protobuf.Timestamp"
            when TypeValue then "type"
            when Array then value.all? { |item| item.is_a?(Array) && item.length == 2 } && !value.empty? ? "map" : "list"
            else TYPE_NAMES.fetch(value.class, "dyn")
            end
          end

          def conversion_error(from, to)
            raise Failure, "type conversion error from '#{from}' to '#{to}'"
          end

          TARGETS = {"int" => "int", "uint" => "uint", "double" => "double", "string" => "string", "bytes" => "bytes", "bool" => "bool",
                     "duration" => "google.protobuf.Duration", "timestamp" => "google.protobuf.Timestamp"}.freeze

          def convert(function, value)
            accepted = @accepts.fetch(function, [])
            # The dispatcher picks the overload by the argument's runtime type.
            unless accepted.include?(:any) || accepted.include?(type_name(value))
              raise Failure,
                    "no such overload: #{function}(#{type_name(value)})"
            end
            return value if function == "dyn"
            return TypeValue.new(type_name(value)) if function == "type"

            target = TARGETS.fetch(function)
            case value
            when Integer then from_int(value, function, target)
            when Values::UInt then from_uint(value.value, function, target)
            when Float then from_double(value, function, target)
            when String then from_string(value, function, target)
            when Values::Bytes
              return value if function == "bytes"
              return conversion_error("bytes", target) unless function == "string"

              text = value.value.dup.force_encoding(Encoding::UTF_8)
              raise Failure, "invalid UTF-8 in bytes, cannot convert to string" unless text.valid_encoding?

              text
            when true, false
              return value if function == "bool"
              return value.to_s if function == "string"

              conversion_error("bool", target)
            when Duration
              case function
              when "duration" then value
              when "int" then value.nanos
              when "string" then "#{go_float_f(value.nanos / 1e9)}s"
              else conversion_error("google.protobuf.Duration", target)
              end
            when Timestamp
              case function
              when "timestamp" then value
              when "int" then value.seconds
              when "string"
                rendered = Time.at(value.seconds, value.nanos, :nanosecond).utc.iso8601(value.nanos.zero? ? 0 : 9)
                rendered.sub(/\.?0+Z\z/) { |m| m.start_with?(".") ? "Z" : m }
              else conversion_error("google.protobuf.Timestamp", target)
              end
            else conversion_error(type_name(value), target)
            end
          end

          def from_int(value, function, target)
            case function
            when "int" then value
            when "uint" then value.negative? ? raise(Failure, "unsigned integer overflow") : Values::UInt.new(value)
            when "double" then value.to_f
            when "string" then value.to_s
            when "timestamp"
              raise Failure, "timestamp overflow" unless value.between?(MIN_UNIX, MAX_UNIX)

              Timestamp.new(value, 0)
            else conversion_error("int", target)
            end
          end

          def from_uint(value, function, target)
            case function
            when "int" then value > MAX_INT ? raise(Failure, "integer overflow") : value
            when "uint" then Values::UInt.new(value)
            when "double" then value.to_f
            when "string" then value.to_s
            else conversion_error("uint", target)
            end
          end

          def from_double(value, function, target)
            case function
            when "int"
              if value.nan? || value.infinite? || value <= -9_223_372_036_854_775_809.0 || value >= 9_223_372_036_854_775_808.0
                raise Failure,
                      "integer overflow"
              end

              value.truncate
            when "uint"
              if value.nan? || value.infinite? || value.negative? || value >= 18_446_744_073_709_551_616.0
                raise Failure,
                      "unsigned integer overflow"
              end

              Values::UInt.new(value.truncate)
            when "double" then value
            when "string" then go_float_g(value)
            else conversion_error("double", target)
            end
          end

          def from_string(value, function, target)
            case function
            when "int"
              parsed = value.match?(/\A[+-]?\d+\z/) ? Integer(value.delete_prefix("+"), 10) : nil
              return parsed if parsed && parsed.between?(MIN_INT, MAX_INT)
            when "uint"
              parsed = value.match?(/\A\+?\d+\z/) ? Integer(value.delete_prefix("+"), 10) : nil
              return Values::UInt.new(parsed) if parsed && parsed < 2**64
            when "double"
              parsed = go_parse_float(value)
              return parsed unless parsed.nil?
            when "bool"
              return true if %w[1 t T TRUE true True].include?(value)
              return false if %w[0 f F FALSE false False].include?(value)
            when "bytes" then return Values::Bytes.new(value.b)
            when "string" then return value
            when "duration"
              return Duration.new(parse_duration(value)) if Validators.valid_duration?(value)
            when "timestamp"
              if value.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})\z/)
                raise Failure, "timestamp overflow" if parse_timestamp_seconds(value).then { |s| s && !s.between?(MIN_UNIX, MAX_UNIX) }
                return Timestamp.new(parse_timestamp_seconds(value), 0) if Validators.valid_timestamp?(value)
              end
            end
            conversion_error("string", target)
          end

          def parse_timestamp_seconds(value)
            Time.iso8601(value).to_i
          rescue ArgumentError
            nil
          end

          UNITS = {"ns" => 1, "us" => 1_000, "µs" => 1_000, "μs" => 1_000, "ms" => 1_000_000, "s" => 1_000_000_000, "m" => 60_000_000_000,
                   "h" => 3_600_000_000_000}.freeze

          def parse_duration(value)
            sign = value.start_with?("-") ? -1 : 1
            text = value.sub(/\A[+-]/, "")
            return 0 if text == "0"

            total = 0r
            text.scan(/([0-9]*(?:\.[0-9]*)?)([^0-9.]+)/) do |number, unit|
              total += Rational(number.empty? ? "0" : number) * UNITS.fetch(unit)
            end
            sign * total.truncate
          end

          # strconv.ParseFloat (decimal forms, inf, nan).
          def go_parse_float(value)
            case value.downcase.delete_prefix("+")
            when "inf", "infinity" then return value.start_with?("-") ? -Float::INFINITY : Float::INFINITY
            when "-inf", "-infinity" then return -Float::INFINITY
            when "nan" then return Float::NAN
            end
            return nil unless value.match?(/\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/)

            Float(value)
          end

          # strconv.FormatFloat(f, 'g', -1, 64) as fmt "%g" prints it.
          def go_float_g(value)
            return "NaN" if value.nan?
            return value.positive? ? "+Inf" : "-Inf" if value.infinite?
            return (1.0 / value).negative? ? "-0" : "0" if value.zero?

            digits, exponent = shortest(value.abs)
            exp = exponent - 1
            sign = value.negative? ? "-" : ""
            # shortest precision: %e when exp < -4 or exp >= 6.
            if exp < -4 || exp >= 6
              mantissa = digits.length > 1 ? "#{digits[0]}.#{digits[1..]}" : digits
              "#{sign}#{mantissa}e#{exp.negative? ? "-" : "+"}#{exp.abs.to_s.rjust(2, "0")}"
            elsif exponent <= 0
              "#{sign}0.#{"0" * -exponent}#{digits}"
            elsif exponent >= digits.length
              "#{sign}#{digits}#{"0" * (exponent - digits.length)}"
            else
              "#{sign}#{digits[0...exponent]}.#{digits[exponent..]}"
            end
          end

          # Shortest round-trip digits and decimal exponent (0.d1d2... x 10^exp).
          def shortest(value)
            mantissa, exponent = format("%.17e", value).split("e")
            17.downto(1) do |count|
              candidate = format("%.#{count - 1}e", value)
              next unless Float(candidate) == value

              mantissa, exponent = candidate.split("e")
            end
            digits = mantissa.delete(".").sub(/0+\z/, "")
            digits = "0" if digits.empty?
            [digits, exponent.to_i + 1]
          end

          # strconv.FormatFloat(f, 'f', -1, 64).
          def go_float_f(value)
            return "0" if value.zero?

            digits, exponent = shortest(value.abs)
            sign = value.negative? ? "-" : ""
            if exponent <= 0
              "#{sign}0.#{"0" * -exponent}#{digits}"
            elsif exponent >= digits.length
              "#{sign}#{digits}#{"0" * (exponent - digits.length)}"
            else
              "#{sign}#{digits[0...exponent]}.#{digits[exponent..]}"
            end
          end
        end
      end
    end
  end
end
