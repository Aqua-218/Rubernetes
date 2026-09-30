# frozen_string_literal: true

require "time"

module Rubernetes
  module Security
    module CEL
      # CEL value types that Ruby does not distinguish natively.
      module Values
        INT64_MIN = -(2**63)
        INT64_MAX = (2**63) - 1
        UINT64_MAX = (2**64) - 1

        # A constructed message (`Object{...}`, `Object.spec{...}`): a field
        # map that remembers the type name it was built as, which the
        # MutatingAdmissionPolicy ApplyConfiguration checks against the field
        # path (dynamic.ObjectVal).
        class ObjectVal < Hash
          attr_reader :type_name

          def initialize(type_name)
            super()
            @type_name = type_name.to_s
          end

          # CheckTypeNamesMatchFieldPathNames: every nested object's type name
          # is its field path from the root type.
          def type_name_errors
            ObjectVal.type_check(self, [type_name])
          end

          def self.type_check(value, path)
            errors = []
            if value.is_a?(ObjectVal)
              expected = path.join(".")
              if value.type_name != expected
                errors << %(unexpected type name "#{value.type_name}", expected "#{expected}", which matches field name path from root Object type)
              end
              value.each { |key, field| errors.concat(type_check(field, path + [key.to_s])) }
            elsif value.is_a?(Array)
              value.each { |item| errors.concat(type_check(item, path)) }
            elsif value.is_a?(Hash)
              value.each_value { |item| errors.concat(type_check(item, path)) }
            end
            errors
          end
        end

        class UInt
          attr_reader :value

          def initialize(value)
            raise EvaluationError, "uint out of range" unless value.is_a?(Integer) && value.between?(0, UINT64_MAX)

            @value = value
          end

          def ==(other) = other.is_a?(UInt) && other.value == @value
          alias eql? ==
          def hash = [:uint, @value].hash
          def to_s = @value.to_s
          def to_i = @value
        end

        class Bytes
          attr_reader :value

          def initialize(value)
            @value = value.b
          end

          def ==(other) = other.is_a?(Bytes) && other.value == @value
          alias eql? ==
          def hash = [:bytes, @value].hash
          def to_s = @value
        end

        class Duration
          attr_reader :seconds

          def initialize(seconds)
            @seconds = seconds.to_r
          end

          def ==(other) = other.is_a?(Duration) && other.seconds == @seconds
          alias eql? ==
          def hash = [:duration, @seconds].hash
          def <=>(other) = @seconds <=> other.seconds
          include Comparable

          def to_s
            format_duration(@seconds)
          end

          def self.parse(text)
            unless text.is_a?(String) && text.match?(/\A-?(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+\z/)
              raise EvaluationError,
                    "invalid duration #{text.inspect}"
            end

            sign = text.start_with?("-") ? -1 : 1
            total = 0r
            text.delete_prefix("-").scan(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/) do |number, unit|
              factor = {"ns" => 1r / 1_000_000_000, "us" => 1r / 1_000_000, "µs" => 1r / 1_000_000, "ms" => 1r / 1000, "s" => 1r,
                        "m" => 60r, "h" => 3600r}.fetch(unit)
              total += number.to_r * factor
            end
            new(sign * total)
          end

          private

          def format_duration(seconds)
            return "#{seconds.to_i}s" if seconds == seconds.to_i

            "#{seconds.to_f}s"
          end
        end

        class Timestamp
          attr_reader :time

          def initialize(time)
            @time = time.utc
          end

          def ==(other) = other.is_a?(Timestamp) && other.time == @time
          alias eql? ==
          def hash = [:timestamp, @time].hash
          def <=>(other) = @time <=> other.time
          include Comparable

          def to_s = @time.iso8601(9).sub(/\.?0+Z\z/, "Z")

          def self.parse(text)
            new(Time.iso8601(text))
          rescue ArgumentError
            raise EvaluationError, "invalid timestamp #{text.inspect}"
          end
        end

        class TypeValue
          attr_reader :name

          def initialize(name)
            @name = name
          end

          def ==(other) = other.is_a?(TypeValue) && other.name == @name
          alias eql? ==
          def hash = [:type, @name].hash
          def to_s = @name
        end

        class Optional
          attr_reader :value

          def initialize(value, present)
            @value = value
            @present = present
          end

          def self.of(value) = new(value, true)
          def self.none = new(nil, false)
          def present? = @present
          def ==(other) = other.is_a?(Optional) && other.present? == @present && (!@present || other.value == @value)
          alias eql? ==
          def hash = [:optional, @present, @value].hash
        end

        module_function

        def type_of(value)
          case value
          when nil then "null_type"
          when true, false then "bool"
          when Integer then "int"
          when UInt then "uint"
          when Float then "double"
          when String then "string"
          when Bytes then "bytes"
          when Array then "list"
          when Hash then "map"
          when Duration then "google.protobuf.Duration"
          when Timestamp then "google.protobuf.Timestamp"
          when TypeValue then "type"
          when Optional then "optional_type"
          else
            return value.class.name.split("::").last.downcase if value.respond_to?(:cel_receiver?) && value.cel_receiver?

            raise EvaluationError, "unsupported value #{value.class}"
          end
        end

        def check_int!(value)
          raise EvaluationError, "integer overflow" unless value.between?(INT64_MIN, INT64_MAX)

          value
        end
      end
    end
  end
end
