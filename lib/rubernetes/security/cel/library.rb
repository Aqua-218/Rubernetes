# frozen_string_literal: true

require "ipaddr"
require "uri"
require "base64"

require_relative "values"

module Rubernetes
  module Security
    module CEL
      # Standard CEL functions plus the Kubernetes extension libraries
      # (k8s.io/apiserver/pkg/cel/library: lists, regex, urls, ip, cidr,
      # quantity, format, semver, sets, authz, jsonpatch-free subset).
      class Library
        include Values

        NAMESPACES = {
          "optional.none" => -> { Optional.none },
          "optional.of" => nil
        }.freeze

        def initialize(authorizer: nil)
          @authorizer = authorizer
        end

        GLOBAL_QUALIFIED = %w[optional.of optional.none sets.contains sets.equivalent sets.intersects].freeze

        def global_function?(name)
          GLOBAL_QUALIFIED.include?(name)
        end

        def namespace_value?(name)
          name == "optional.none"
        end

        def namespace_value(name)
          Optional.none if name == "optional.none"
        end

        # ---------------------------------------------------------------- operators

        def binary(operator, left, right, context)
          case operator
          when "==" then equal?(left, right)
          when "!=" then !equal?(left, right)
          when "<", "<=", ">", ">="
            result = compare(left, right)
            case operator
            when "<" then result.negative?
            when "<=" then !result.positive?
            when ">" then result.positive?
            when ">=" then !result.negative?
            end
          when "in"
            case right
            when Array then right.any? { |item| equal?(item, left) }
            when Hash then right.key?(left)
            else raise TypeMismatch, "in requires a list or map"
            end
          when "+" then add(left, right, context)
          when "-" then subtract(left, right)
          when "*" then multiply(left, right)
          when "/" then divide(left, right)
          when "%" then modulo(left, right)
          else raise EvaluationError, "unknown operator #{operator}"
          end
        end

        def equal?(left, right)
          return left == right if left.class == right.class
          return numeric_equal?(left, right) if numeric?(left) && numeric?(right)
          return left.zip(right).all? { |a, b| equal?(a, b) } if left.is_a?(Array) && right.is_a?(Array) && left.length == right.length
          return left.all? { |key, value| right.key?(key) && equal?(value, right[key]) } if left.is_a?(Hash) && right.is_a?(Hash) && left.length == right.length

          false
        end

        def numeric?(value) = value.is_a?(Integer) || value.is_a?(Float) || value.is_a?(UInt)
        def numeric_value(value) = value.is_a?(UInt) ? value.value : value

        def numeric_equal?(left, right)
          numeric_value(left) == numeric_value(right)
        end

        def compare(left, right)
          return numeric_value(left) <=> numeric_value(right) if numeric?(left) && numeric?(right)
          return left.compareTo(right) if left.respond_to?(:compareTo) && right.instance_of?(left.class)

          case left
          when String then raise TypeMismatch, "cannot compare string with #{type_of(right)}" unless right.is_a?(String)
          when Bytes then raise TypeMismatch, "cannot compare bytes" unless right.is_a?(Bytes)

                          return left.value <=> right.value
          when TrueClass, FalseClass then raise TypeMismatch, "cannot compare bool" unless [true, false].include?(right)

                                          return (left ? 1 : 0) <=> (right ? 1 : 0)
          when Duration, Timestamp then unless right.instance_of?(left.class)
                                          raise TypeMismatch,
                                                "cannot compare #{type_of(left)} with #{type_of(right)}"
                                        end
          else raise TypeMismatch, "cannot compare #{type_of(left)}"
          end
          left <=> right
        end

        def add(left, right, context)
          case left
          when Integer then raise TypeMismatch, "int + #{type_of(right)}" unless right.is_a?(Integer)

                            check_int!(left + right)
          when UInt then raise TypeMismatch, "uint + #{type_of(right)}" unless right.is_a?(UInt)

                         UInt.new(left.value + right.value)
          when Float then raise TypeMismatch, "double + #{type_of(right)}" unless right.is_a?(Float)

                          left + right
          when String then raise TypeMismatch, "string + #{type_of(right)}" unless right.is_a?(String)

                           left + right
          when Bytes then raise TypeMismatch, "bytes + #{type_of(right)}" unless right.is_a?(Bytes)

                          Bytes.new(left.value + right.value)
          when Array
            raise TypeMismatch, "list + #{type_of(right)}" unless right.is_a?(Array)

            context.charge(left.length + right.length)
            left + right
          when Duration
            case right
            when Duration then Duration.new(left.seconds + right.seconds)
            when Timestamp then Timestamp.new(right.time + left.seconds)
            else raise TypeMismatch, "duration + #{type_of(right)}"
            end
          when Timestamp
            raise TypeMismatch, "timestamp + #{type_of(right)}" unless right.is_a?(Duration)

            Timestamp.new(left.time + right.seconds)
          else raise TypeMismatch, "no + overload for #{type_of(left)}"
          end
        end

        def subtract(left, right)
          case left
          when Integer then raise TypeMismatch, "int - #{type_of(right)}" unless right.is_a?(Integer)

                            check_int!(left - right)
          when UInt then raise TypeMismatch, "uint - #{type_of(right)}" unless right.is_a?(UInt)

                         UInt.new(left.value - right.value)
          when Float then raise TypeMismatch, "double - #{type_of(right)}" unless right.is_a?(Float)

                          left - right
          when Duration then raise TypeMismatch, "duration - #{type_of(right)}" unless right.is_a?(Duration)

                             Duration.new(left.seconds - right.seconds)
          when Timestamp
            case right
            when Timestamp then Duration.new(left.time.to_r - right.time.to_r)
            when Duration then Timestamp.new(left.time - right.seconds)
            else raise TypeMismatch, "timestamp - #{type_of(right)}"
            end
          else raise TypeMismatch, "no - overload for #{type_of(left)}"
          end
        end

        def multiply(left, right)
          case left
          when Integer then raise TypeMismatch, "int * #{type_of(right)}" unless right.is_a?(Integer)

                            check_int!(left * right)
          when UInt then raise TypeMismatch, "uint * #{type_of(right)}" unless right.is_a?(UInt)

                         UInt.new(left.value * right.value)
          when Float then raise TypeMismatch, "double * #{type_of(right)}" unless right.is_a?(Float)

                          left * right
          else raise TypeMismatch, "no * overload for #{type_of(left)}"
          end
        end

        def divide(left, right)
          case left
          when Integer
            raise TypeMismatch, "int / #{type_of(right)}" unless right.is_a?(Integer)
            raise EvaluationError, "division by zero" if right.zero?

            check_int!(left.abs / right.abs * (left.negative? ^ right.negative? ? -1 : 1))
          when UInt
            raise TypeMismatch, "uint / #{type_of(right)}" unless right.is_a?(UInt)
            raise EvaluationError, "division by zero" if right.value.zero?

            UInt.new(left.value / right.value)
          when Float then raise TypeMismatch, "double / #{type_of(right)}" unless right.is_a?(Float)

                          left / right
          else raise TypeMismatch, "no / overload for #{type_of(left)}"
          end
        end

        def modulo(left, right)
          case left
          when Integer
            raise TypeMismatch, "int % #{type_of(right)}" unless right.is_a?(Integer)
            raise EvaluationError, "modulus by zero" if right.zero?

            left.remainder(right)
          when UInt
            raise TypeMismatch, "uint % #{type_of(right)}" unless right.is_a?(UInt)
            raise EvaluationError, "modulus by zero" if right.value.zero?

            UInt.new(left.value % right.value)
          else raise TypeMismatch, "no % overload for #{type_of(left)}"
          end
        end

        # ---------------------------------------------------------------- functions

        def call(function, target, arguments, context, has_target: false)
          if has_target
            member_call(function, target, arguments, context)
          else
            global_call(function, arguments, context)
          end
        end

        def global_call(function, arguments, _context)
          case function
          when "size" then size(arguments.fetch(0))
          when "int" then to_int(arguments.fetch(0))
          when "uint" then to_uint(arguments.fetch(0))
          when "double" then to_double(arguments.fetch(0))
          when "string" then to_string(arguments.fetch(0))
          when "bool" then to_bool(arguments.fetch(0))
          when "bytes" then arguments.fetch(0).is_a?(String) ? Bytes.new(arguments.fetch(0)) : arguments.fetch(0)
          when "dyn" then arguments.fetch(0)
          when "type" then TypeValue.new(type_of(arguments.fetch(0)))
          when "duration" then arguments.fetch(0).is_a?(Duration) ? arguments.fetch(0) : Duration.parse(arguments.fetch(0))
          when "timestamp" then arguments.fetch(0).is_a?(Timestamp) ? arguments.fetch(0) : Timestamp.parse(arguments.fetch(0))
          when "matches" then matches?(arguments.fetch(0), arguments.fetch(1))
          when "quantity" then Quantity.new(arguments.fetch(0))
          when "isQuantity" then Quantity.valid?(arguments.fetch(0))
          when "ip" then IP.parse(arguments.fetch(0))
          when "isIP" then IP.valid?(arguments.fetch(0))
          when "cidr" then CIDR.parse(arguments.fetch(0))
          when "isCIDR" then CIDR.valid?(arguments.fetch(0))
          when "url" then URL.parse(arguments.fetch(0))
          when "isURL" then URL.valid?(arguments.fetch(0))
          when "semver" then SemVer.parse(arguments.fetch(0), normalize: arguments.fetch(1, false))
          when "isSemver" then SemVer.valid?(arguments.fetch(0), normalize: arguments.fetch(1, false))
          when "optional.of" then Optional.of(arguments.fetch(0))
          when "optional.none" then Optional.none
          when "sets.contains" then sets_contains(arguments.fetch(0), arguments.fetch(1))
          when "sets.equivalent" then sets_contains(arguments.fetch(0),
                                                    arguments.fetch(1)) && sets_contains(arguments.fetch(1), arguments.fetch(0))
          when "sets.intersects" then arguments.fetch(0).any? { |item| arguments.fetch(1).any? { |other| equal?(item, other) } }
          when "authorizer" then Authorizer.new(@authorizer, nil, nil)
          else
            raise EvaluationError, "undeclared function '#{function}'"
          end
        end

        def member_call(function, target, arguments, context)
          return target.public_send(function, *arguments) if target.respond_to?(:cel_receiver?) && target.cel_receiver?

          if target.is_a?(Optional)
            case function
            when "hasValue" then return target.present?
            when "value"
              raise EvaluationError, "optional.none() dereference" unless target.present?

              return target.value
            when "orValue" then return target.present? ? target.value : arguments.fetch(0)
            when "or" then return target.present? ? target : arguments.fetch(0)
            end
          end
          case function
          when "size" then size(target)
          when "contains"
            case target
            when String then target.include?(string_argument(arguments, 0))
            when Array then target.any? { |item| equal?(item, arguments.fetch(0)) }
            else raise TypeMismatch, "contains on #{type_of(target)}"
            end
          when "startsWith" then string_target(target).start_with?(string_argument(arguments, 0))
          when "endsWith" then string_target(target).end_with?(string_argument(arguments, 0))
          when "matches" then matches?(string_target(target), string_argument(arguments, 0))
          when "lowerAscii" then string_target(target).gsub(/[A-Z]/, &:downcase)
          when "upperAscii" then string_target(target).gsub(/[a-z]/, &:upcase)
          when "trim" then string_target(target).strip
          when "replace"
            text = string_target(target)
            limit = arguments[2]
            if limit.nil? || limit.to_i.negative?
              text.gsub(string_argument(arguments, 0),
                        string_argument(arguments,
                                        1))
            else
              replace_limited(text, string_argument(arguments, 0),
                              string_argument(arguments, 1), limit.to_i)
            end
          when "split"
            text = string_target(target)
            limit = arguments[1]
            limit.nil? ? text.split(string_argument(arguments, 0), -1) : text.split(string_argument(arguments, 0), limit.to_i)

          when "join"
            raise TypeMismatch, "join on non-list" unless target.is_a?(Array)

            target.join(arguments.empty? ? "" : string_argument(arguments, 0))
          when "substring"
            text = string_target(target)
            start = arguments.fetch(0).to_i
            finish = arguments[1].nil? ? text.length : arguments[1].to_i
            raise EvaluationError, "substring range out of bounds" if start.negative? || finish > text.length || start > finish

            text[start...finish]
          when "indexOf" then index_of(string_target(target), string_argument(arguments, 0), arguments[1].to_i)
          when "lastIndexOf" then last_index_of(string_target(target), string_argument(arguments, 0), arguments[1]&.to_i)
          when "charAt"
            text = string_target(target)
            index = arguments.fetch(0).to_i
            raise EvaluationError, "charAt index out of range" unless index.between?(0, text.length)

            index == text.length ? "" : text[index]
          when "reverse"
            case target
            when String then target.reverse
            when Array then target.reverse
            else raise TypeMismatch, "reverse on #{type_of(target)}"
            end
          when "format" then Format.format(string_target(target), arguments.fetch(0))
          when "find"
            match = Regex.compile(string_argument(arguments, 0)).match(string_target(target))
            match ? match[0] : ""
          when "findAll"
            regex = Regex.compile(string_argument(arguments, 0))
            limit = arguments[1]&.to_i
            all = string_target(target).scan(regex).map { |item| item.is_a?(Array) ? item.first : item }
            limit.nil? || limit.negative? ? all : all.first(limit)
          when "isSorted" then list_target(target).each_cons(2).all? { |a, b| !compare(a, b).positive? }
          when "sum"
            list = list_target(target)
            list.empty? ? 0 : list.reduce { |a, b| add(a, b, context) }
          when "min" then list_target(target).min { |a, b| compare(a, b) } || raise(EvaluationError, "min of empty list")
          when "max" then list_target(target).max { |a, b| compare(a, b) } || raise(EvaluationError, "max of empty list")
          when "slice"
            list = list_target(target)
            start = arguments.fetch(0).to_i
            finish = arguments.fetch(1).to_i
            raise EvaluationError, "slice range out of bounds" if start.negative? || finish > list.length || start > finish

            list[start...finish]
          when "flatten"
            depth = arguments.empty? ? 1 : arguments.fetch(0).to_i
            list_target(target).flatten(depth)
          when "distinct" then list_target(target).uniq { |item| item }
          when "all", "exists", "exists_one", "map", "filter"
            raise EvaluationError, "#{function} is a macro and needs a variable"
          when "getDate", "getDayOfMonth", "getDayOfWeek", "getDayOfYear", "getFullYear", "getHours", "getMilliseconds", "getMinutes", "getMonth", "getSeconds"
            time_accessor(function, target, arguments)
          when "cel_receiver?" then false
          else
            raise EvaluationError, "undeclared function '#{function}' on #{type_of(target)}"
          end
        end

        # ---------------------------------------------------------------- helpers

        def size(value)
          case value
          when String then value.length
          when Bytes then value.value.bytesize
          when Array, Hash then value.length
          else raise TypeMismatch, "size on #{type_of(value)}"
          end
        end

        def to_int(value)
          case value
          when Integer then value
          when UInt then check_int!(value.value)
          when Float
            raise EvaluationError, "double out of int range" if value.nan? || value.infinite? || value >= 2**63 || value < -(2**63)

            value.truncate
          when String
            # strconv.ParseInt; any failure is cel-go's conversion error.
            parsed = value.match?(/\A[+-]?\d+\z/) ? Integer(value.delete_prefix("+"), 10) : nil
            raise EvaluationError, "type conversion error from 'string' to 'int'" if parsed.nil? || parsed >= 2**63 || parsed < -(2**63)

            parsed
          when Timestamp then value.time.to_i
          when Duration then value.seconds.to_i
          else raise TypeMismatch, "cannot convert #{type_of(value)} to int"
          end
        end

        def to_uint(value)
          case value
          when UInt then value
          when Integer then UInt.new(value)
          when Float
            raise EvaluationError, "double out of uint range" if value.nan? || value.negative? || value >= 2**64

            UInt.new(value.truncate)
          when String
            raise EvaluationError, "type conversion error from 'string' to 'uint'" unless value.match?(/\A\d+\z/) && Integer(value,
                                                                                                                             10) < 2**64

            UInt.new(Integer(value, 10))
          else raise TypeMismatch, "cannot convert #{type_of(value)} to uint"
          end
        end

        def to_double(value)
          case value
          when Float then value
          when Integer then value.to_f
          when UInt then value.value.to_f
          when String
            Float(value)
          else raise TypeMismatch, "cannot convert #{type_of(value)} to double"
          end
        rescue ArgumentError
          raise EvaluationError, "type conversion error from 'string' to 'double'"
        end

        def to_string(value)
          case value
          when String then value
          when Integer, UInt then value.to_s
          when Float then value.to_s
          when TrueClass, FalseClass then value.to_s
          when Bytes then value.value.dup.force_encoding(Encoding::UTF_8).tap do |s|
            raise EvaluationError, "invalid UTF-8 in bytes" unless s.valid_encoding?
          end
          when Duration, Timestamp, Quantity, IP, CIDR, URL, SemVer then value.to_s
          else raise TypeMismatch, "cannot convert #{type_of(value)} to string"
          end
        end

        def to_bool(value)
          case value
          when TrueClass, FalseClass then value
          when String
            return true if %w[true True TRUE t T 1].include?(value)
            return false if %w[false False FALSE f F 0].include?(value)

            raise EvaluationError, "type conversion error from 'string' to 'bool'"
          else raise TypeMismatch, "cannot convert #{type_of(value)} to bool"
          end
        end

        def matches?(text, pattern)
          raise TypeMismatch, "matches requires strings" unless text.is_a?(String) && pattern.is_a?(String)

          Regex.compile(pattern).match?(text)
        end

        def string_target(value)
          raise TypeMismatch, "expected string receiver, got #{type_of(value)}" unless value.is_a?(String)

          value
        end

        def list_target(value)
          raise TypeMismatch, "expected list receiver, got #{type_of(value)}" unless value.is_a?(Array)

          value
        end

        def string_argument(arguments, index)
          value = arguments.fetch(index) { raise EvaluationError, "missing argument #{index}" }
          raise TypeMismatch, "expected string argument, got #{type_of(value)}" unless value.is_a?(String)

          value
        end

        def replace_limited(text, from, to, limit)
          result = text.dup
          count = 0
          position = 0
          while count < limit && (index = result.index(from, position))
            result[index, from.length] = to
            position = index + to.length
            count += 1
            break if from.empty?
          end
          result
        end

        def index_of(text, needle, offset)
          raise EvaluationError, "indexOf offset out of range" if offset.negative? || offset > text.length

          text.index(needle, offset) || -1
        end

        def last_index_of(text, needle, offset)
          offset = text.length if offset.nil?
          raise EvaluationError, "lastIndexOf offset out of range" if offset.negative? || offset > text.length

          text.rindex(needle, offset) || -1
        end

        def sets_contains(list, other)
          other.all? { |item| list.any? { |candidate| equal?(candidate, item) } }
        end

        def time_accessor(function, target, arguments)
          raise TypeMismatch, "#{function} on #{type_of(target)}" unless target.is_a?(Timestamp) || target.is_a?(Duration)

          if target.is_a?(Duration)
            seconds = target.seconds
            return case function
                   when "getHours" then (seconds / 3600).to_i
                   when "getMinutes" then (seconds / 60).to_i
                   when "getSeconds" then seconds.to_i
                   when "getMilliseconds" then ((seconds * 1000).to_i % 1000)
                   else raise EvaluationError, "#{function} is not defined on duration"
                   end
          end
          time = target.time
          zone = arguments.first
          time = shift_zone(time, zone) if zone
          case function
          when "getDate", "getDayOfMonth" then function == "getDate" ? time.day : time.day - 1
          when "getDayOfWeek" then time.wday
          when "getDayOfYear" then time.yday - 1
          when "getFullYear" then time.year
          when "getHours" then time.hour
          when "getMilliseconds" then time.nsec / 1_000_000
          when "getMinutes" then time.min
          when "getMonth" then time.month - 1
          when "getSeconds" then time.sec
          end
        end

        def shift_zone(time, zone)
          raise EvaluationError, "unsupported time zone #{zone.inspect}" unless zone.match?(/\A[+-]\d{2}:\d{2}\z/)

          sign = zone.start_with?("-") ? -1 : 1
          hours, minutes = zone[1..].split(":").map(&:to_i)
          time.getlocal(sign * ((hours * 3600) + (minutes * 60)))
        end

        # ---------------------------------------------------------------- extension types

        # RE2-compatible subset: Ruby Onigmo accepts RE2 syntax used in policies;
        # lookarounds and backreferences are rejected as RE2 would.
        module Regex
          module_function

          def compile(pattern)
            raise EvaluationError, "regex uses unsupported construct" if pattern.match?(/\(\?[=!<]|\\[1-9]/)

            Regexp.new(pattern)
          rescue RegexpError => error
            raise EvaluationError, "invalid regex #{pattern.inspect}: #{error.message}"
          end
        end

        class Quantity
          SUFFIXES = {"" => 1r, "n" => 1r / (10**9), "u" => 1r / (10**6), "m" => 1r / 1000, "k" => 1000r, "M" => 10**6r, "G" => 10**9r, "T" => 10**12r,
                      "P" => 10**15r, "E" => 10**18r, "Ki" => 1024r, "Mi" => 1024r**2, "Gi" => 1024r**3, "Ti" => 1024r**4, "Pi" => 1024r**5,
                      "Ei" => 1024r**6}.freeze
          attr_reader :value, :text

          def self.valid?(text)
            new(text)
            true
          rescue EvaluationError
            false
          end

          def initialize(text)
            raise TypeMismatch, "quantity requires a string" unless text.is_a?(String)

            match = text.strip.match(/\A([+-]?[0-9]*\.?[0-9]+)(?:[eE]([+-]?\d+))?([a-zA-Z]*)\z/)
            raise EvaluationError, "invalid quantity #{text.inspect}" unless match && SUFFIXES.key?(match[3])

            @text = text
            @value = match[1].to_r * (match[2] ? 10r**match[2].to_i : 1) * SUFFIXES.fetch(match[3])
          end

          def cel_receiver? = true
          def isInteger = @value.denominator == 1
          def asInteger = raise_unless_integer!
          def asApproximateFloat = @value.to_f
          def sign = @value <=> 0
          def isGreaterThan(other) = @value > other.value
          def isLessThan(other) = @value < other.value
          def compareTo(other) = @value <=> other.value
          def add(other) = Quantity.from_value(@value + (other.is_a?(Quantity) ? other.value : other))
          def sub(other) = Quantity.from_value(@value - (other.is_a?(Quantity) ? other.value : other))
          def to_s = @text
          def ==(other) = other.is_a?(Quantity) && other.value == @value

          def self.from_value(value)
            quantity = allocate
            quantity.instance_variable_set(:@value, value)
            quantity.instance_variable_set(:@text, value.denominator == 1 ? value.to_i.to_s : "#{(value * 1000).to_i}m")
            quantity
          end

          private

          def raise_unless_integer!
            raise EvaluationError, "quantity is not an integer" unless isInteger

            @value.to_i
          end
        end

        class IP
          attr_reader :address

          def self.valid?(text)
            text.is_a?(String) && !text.include?("/") && IPAddr.new(text) && true
          rescue StandardError
            false
          end

          def self.parse(text)
            raise EvaluationError, "invalid IP address #{text.inspect}" unless valid?(text)

            new(IPAddr.new(text), text)
          end

          # `text` is the source form when the value was parsed from a string;
          # isCanonical compares it with the canonical rendering, as cel-go does.
          def initialize(address, text = nil)
            @address = address
            @text = text
          end

          def cel_receiver? = true
          def family = @address.ipv4? ? 4 : 6
          def isCanonical = @text.nil? || @text == @address.to_s
          def isUnspecified = @address.to_i.zero?
          def isLoopback = @address.loopback?

          def isLinkLocalMulticast
            @address.ipv4? ? IPAddr.new("224.0.0.0/24").include?(@address) : IPAddr.new("ff02::/16").include?(@address)
          end

          def isLinkLocalUnicast = @address.link_local?

          def isGlobalUnicast
            multicast = @address.ipv4? ? IPAddr.new("224.0.0.0/4").include?(@address) : IPAddr.new("ff00::/8").include?(@address)
            !(isLoopback || isUnspecified || @address.link_local? || multicast)
          end

          def to_s = @address.to_s
          def ==(other) = other.is_a?(IP) && other.address == @address
        end

        class CIDR
          attr_reader :range, :text

          def self.valid?(text)
            text.is_a?(String) && text.include?("/") && IPAddr.new(text) && true
          rescue StandardError
            false
          end

          def self.parse(text)
            raise EvaluationError, "invalid CIDR #{text.inspect}" unless valid?(text)

            new(text)
          end

          def initialize(text)
            @text = text
            @range = IPAddr.new(text)
          end

          def cel_receiver? = true
          def containsIP(value) = @range.include?(value.is_a?(IP) ? value.address : IPAddr.new(value))
          def containsCIDR(value) = @range.include?(value.is_a?(CIDR) ? value.range : IPAddr.new(value))
          def ip = IP.new(@range)
          def masked = CIDR.new("#{@range}/#{@range.prefix}")
          def prefixLength = @range.prefix
          def to_s = @text
          def ==(other) = other.is_a?(CIDR) && other.range == @range && other.range.prefix == @range.prefix
        end

        class URL
          attr_reader :uri

          def self.valid?(text)
            text.is_a?(String) && URI.parse(text) && true
          rescue URI::InvalidURIError
            false
          end

          def self.parse(text)
            raise EvaluationError, "invalid URL #{text.inspect}" unless valid?(text)

            new(URI.parse(text))
          end

          def initialize(uri) = @uri = uri
          def cel_receiver? = true
          def getScheme = @uri.scheme.to_s
          def getHost = @uri.port && @uri.port != @uri.default_port ? "#{@uri.host}:#{@uri.port}" : @uri.host.to_s
          def getHostname = @uri.host.to_s
          def getPort = @uri.port && @uri.port != @uri.default_port ? @uri.port.to_s : ""
          def getEscapedPath = @uri.path.to_s
          def getQuery = URI.decode_www_form(@uri.query.to_s).group_by(&:first).transform_values { |pairs| pairs.map(&:last) }
          def to_s = @uri.to_s
          def ==(other) = other.is_a?(URL) && other.uri == @uri
        end

        # github.com/blang/semver/v4 as the Kubernetes CEL semver library
        # uses it: strict Parse (Major.Minor.Patch, no leading zeroes, no "v"),
        # SemVer 2.0 precedence including prerelease identifiers, build
        # metadata ignored for comparison and equality; normalize (strip "v",
        # fill missing minor/patch, drop leading zeroes) on request.
        class SemVer
          include Comparable

          NUMBERS = /\A[0-9]*\z/
          ALPHANUM = /\A[0-9A-Za-z-]*\z/

          def self.valid?(text, normalize: false)
            parse(text, normalize: normalize)
            true
          rescue EvaluationError, TypeMismatch
            false
          end

          def self.parse(text, normalize: false)
            raise TypeMismatch, "semver requires a string" unless text.is_a?(String)

            source = normalize == true ? normalized(text) : text
            new(source, text)
          end

          # normalizeAndParse's rewrite.
          def self.normalized(text)
            parts = text.delete_prefix("v").split(".", 3)
            parts = parts.map do |part|
              next part unless part.length > 1

              trimmed = part.sub(/\A0+/, "")
              trimmed.empty? || !trimmed[0].match?(/[0-9]/) ? "0#{trimmed}" : trimmed
            end
            if parts.length < 3
              raise EvaluationError, "short version cannot contain PreRelease/Build meta data" if parts.last.to_s.match?(/[+-]/)

              parts << "0" while parts.length < 3
            end
            parts.join(".")
          end

          def initialize(source, text = source)
            raise EvaluationError, "Version string empty" if source.empty?

            parts = source.split(".", 3)
            raise EvaluationError, "No Major.Minor.Patch elements found" unless parts.length == 3

            @major = number(parts[0], "major")
            @minor = number(parts[1], "minor")
            patch = parts[2]
            build = nil
            if (index = patch.index("+"))
              build = patch[(index + 1)..].split(".", -1)
              patch = patch[0...index]
            end
            prerelease = nil
            if (index = patch.index("-"))
              prerelease = patch[(index + 1)..].split(".", -1)
              patch = patch[0...index]
            end
            @patch = number(patch, "patch")
            @prerelease_ids = Array(prerelease).map { |identifier| prerelease_id(identifier) }
            Array(build).each do |identifier|
              raise EvaluationError, "Build meta data is empty" if identifier.empty?
              unless ALPHANUM.match?(identifier)
                raise EvaluationError,
                      "Invalid character(s) found in build meta data #{identifier.inspect}"
              end
            end
            @prerelease = prerelease&.join(".")
            @build = build&.join(".")
            @text = text
          end

          def cel_receiver? = true
          def isGreaterThan(other) = (self <=> other).positive?
          def isLessThan(other) = (self <=> other).negative?
          def compareTo(other) = self <=> other
          attr_reader :major, :minor, :patch, :prerelease, :build, :prerelease_ids

          def <=>(other)
            return nil unless other.is_a?(SemVer)

            core = [major, minor, patch] <=> [other.major, other.minor, other.patch]
            return core unless core.zero?

            mine = prerelease_ids
            theirs = other.prerelease_ids
            return 0 if mine.empty? && theirs.empty?
            return 1 if mine.empty?
            return -1 if theirs.empty?

            mine.zip(theirs).each do |left, right|
              break if right.nil?

              comparison = compare_identifier(left, right)
              return comparison unless comparison.zero?
            end
            mine.length <=> theirs.length
          end

          def to_s = @text
          def ==(other) = other.is_a?(SemVer) && (self <=> other).zero?
          alias eql? ==
          def hash = [major, minor, patch, prerelease_ids].hash

          private

          def number(text, label)
            raise EvaluationError, "Invalid character(s) found in #{label} number #{text.inspect}" unless NUMBERS.match?(text)
            if text.length > 1 && text.start_with?("0")
              raise EvaluationError,
                    "#{label.capitalize} number must not contain leading zeroes #{text.inspect}"
            end
            raise EvaluationError, "strconv.ParseUint: parsing #{text.inspect}: invalid syntax" if text.empty?

            Integer(text, 10)
          end

          def prerelease_id(text)
            raise EvaluationError, "Prerelease is empty" if text.empty?

            if NUMBERS.match?(text)
              raise EvaluationError, "Numeric PreRelease version must not contain leading zeroes #{text.inspect}" if text.length > 1 && text.start_with?("0")

              return Integer(text, 10)
            end
            raise EvaluationError, "Invalid character(s) found in prerelease #{text.inspect}" unless ALPHANUM.match?(text)

            text
          end

          # PRVersion.Compare: numeric < alphanumeric, numbers numerically,
          # strings lexically.
          def compare_identifier(left, right)
            return -1 if left.is_a?(Integer) && !right.is_a?(Integer)
            return 1 if !left.is_a?(Integer) && right.is_a?(Integer)

            left <=> right
          end
        end

        # strings.format subset: %s %d %f %e %x %X %o %b
        module Format
          module_function

          def format(template, arguments)
            raise TypeMismatch, "format requires a list" unless arguments.is_a?(Array)

            index = -1
            template.gsub(/%(?:\.(\d+))?([sdfexXob%])/) do
              precision = Regexp.last_match(1)
              verb = Regexp.last_match(2)
              next "%" if verb == "%"

              index += 1
              raise EvaluationError, "format: not enough arguments" if index >= arguments.length

              value = arguments[index]
              case verb
              when "s" then stringify(value)
              when "d" then Integer(value.is_a?(Values::UInt) ? value.value : value).to_s
              when "f" then Kernel.format("%.#{precision || 6}f", value.to_f)
              when "e" then Kernel.format("%.#{precision || 6}e", value.to_f)
              when "x" then Integer(value.is_a?(Values::UInt) ? value.value : value).to_s(16)
              when "X" then Integer(value.is_a?(Values::UInt) ? value.value : value).to_s(16).upcase
              when "o" then Integer(value.is_a?(Values::UInt) ? value.value : value).to_s(8)
              when "b" then Integer(value.is_a?(Values::UInt) ? value.value : value).to_s(2)
              end
            end
          end

          def stringify(value)
            case value
            when String then value
            when Array then "[#{value.map { |item| stringify(item) }.join(", ")}]"
            when Hash then "{#{value.map { |key, item| "#{stringify(key)}: #{stringify(item)}" }.join(", ")}}"
            when nil then "null"
            else value.to_s
            end
          end
        end

        # authorizer library (k8s.io/apiserver/pkg/cel/library/authz.go).
        class Authorizer
          def initialize(backend, user, request_resource)
            @backend = backend
            @user = user
            @request_resource = request_resource
            @group = ""
            @resource = nil
            @subresource = ""
            @namespace = ""
            @name = ""
            @path = nil
            @field_selector = nil
            @label_selector = nil
          end

          def cel_receiver? = true

          def group(name) = dup.tap { |a| a.instance_variable_set(:@group, name) }
          def resource(name) = dup.tap { |a| a.instance_variable_set(:@resource, name) }
          def subresource(name) = dup.tap { |a| a.instance_variable_set(:@subresource, name) }
          def namespace(name) = dup.tap { |a| a.instance_variable_set(:@namespace, name) }
          def name(value) = dup.tap { |a| a.instance_variable_set(:@name, value) }
          def path(value) = dup.tap { |a| a.instance_variable_set(:@path, value) }

          def serviceAccount(namespace, name)
            dup.tap { |a| a.instance_variable_set(:@user, UserInfo.service_account(namespace: namespace, name: name)) }
          end

          def fieldSelector(value) = dup.tap { |a| a.instance_variable_set(:@field_selector, value) }
          def labelSelector(value) = dup.tap { |a| a.instance_variable_set(:@label_selector, value) }

          def check(verb)
            raise EvaluationError, "authorizer is not available" if @backend.nil? || @user.nil?

            attributes = if @path
                           Authorization::Attributes.new(user: @user, verb: verb, path: @path, resource_request: false)
                         else
                           Authorization::Attributes.new(user: @user, verb: verb, api_group: @group, resource: @resource.to_s, subresource: @subresource,
                                                         namespace: @namespace, name: @name, resource_request: true,
                                                         field_selector: @field_selector, label_selector: @label_selector)
                         end
            Decision.new(@backend.authorize(attributes))
          end

          def errored = false
          def error = ""

          class Decision
            def initialize(decision) = @decision = decision
            def cel_receiver? = true
            def allowed = @decision.allowed?
            def denied = @decision.denied?
            def reason = @decision.reason.to_s
            def errored = false
            def error = ""
          end
        end
      end
    end
  end
end
