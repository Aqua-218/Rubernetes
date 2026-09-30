# frozen_string_literal: true

require "date"
require_relative "checker"

module Rubernetes
  module Security
    module CEL
      module Check
        # cel/validator.go and ext/formatting.go: the AST validators of the
        # Kubernetes base environment, run over a checked expression without
        # errors (duration, timestamp and regex literals, homogeneous aggregate
        # literals, string.format calls).
        module Validators
          HOMOGENEOUS_EXEMPT = %w[format].freeze

          module_function

          def run(names, root, types, references, issues)
            names.each do |name|
              case name
              when "cel.validator.duration" then literal_arguments(root, "duration") { |value| valid_duration?(value) }
                .each { |node| issues.report(node.offset, "invalid duration argument") }
              when "cel.validator.timestamp" then literal_arguments(root, "timestamp") { |value| valid_timestamp?(value) }
                .each { |node| issues.report(node.offset, "invalid timestamp argument") }
              when "cel.validator.matches" then literal_arguments(root, "matches") { |value| valid_regex?(value) }
                .each { |node| issues.report(node.offset, "invalid matches argument") }
              when "cel.validator.homogeneous_literals" then homogeneous(root, types, issues)
              when "cel.validator.string_format" then string_format(root, types, references, issues)
              end
            end
          end

          # ast.MatchDescendants: post-order, with the ancestors of each node.
          def descendants(node, ancestors = [], &)
            return if node.nil?

            path = ancestors + [node]
            case node.kind
            when :call
              descendants(node.target, path, &) if node.member?
              node.args.each { |arg| descendants(arg, path, &) }
            when :comprehension
              %i[iter_range accu_init loop_condition loop_step result].each { |part| descendants(node.public_send(part), path, &) }
            when :list then node.elements.each { |element| descendants(element, path, &) }
            when :map
              node.entries.each do |entry|
                descendants(entry.key, path, &)
                descendants(entry.value, path, &)
              end
            when :struct then node.fields.each { |field| descendants(field.value, path, &) }
            when :select then descendants(node.operand, path, &)
            end
            yield node, ancestors
          end

          # formatValidator: the first argument of every call of the function,
          # when it is a literal the check refuses.
          def literal_arguments(root, function)
            bad = []
            descendants(root) do |node, _ancestors|
              next unless node.kind == :call && node.name == function && !node.args.empty?

              argument = node.args[0]
              next unless argument.kind == :literal

              bad << argument unless yield(argument.value)
            end
            bad
          end

          DURATION_UNITS = {"ns" => 1, "us" => 1_000, "µs" => 1_000, "μs" => 1_000, "ms" => 1_000_000, "s" => 1_000_000_000,
                            "m" => 60_000_000_000, "h" => 3_600_000_000_000}.freeze

          # duration(<literal>): evaluated -- a string goes through
          # time.ParseDuration (an int64 of nanoseconds); the int64_to_duration
          # overload is declared but fails when evaluated, so an int is refused.
          def valid_duration?(value)
            return false unless value.is_a?(String)

            text = value.dup
            text = text[1..] if text.start_with?("-", "+")
            return true if text == "0"
            return false if text.empty?

            total = 0r
            until text.empty?
              match = text.match(/\A([0-9]*)(?:\.([0-9]*))?/)
              whole = match[1]
              fraction = match[2]
              return false if whole.empty? && (fraction.nil? || fraction.empty?)

              text = text[match[0].length..]
              unit = text[/\A[^0-9.]+/]
              return false if unit.nil? || !DURATION_UNITS.key?(unit)

              text = text[unit.length..]
              number = Rational(whole.empty? ? 0 : whole.to_i) + (fraction.to_s.empty? ? 0 : Rational(fraction.to_i, 10**fraction.length))
              total += number * DURATION_UNITS[unit]
              return false if total > 2**63
            end
            total <= (value.start_with?("-") ? 2**63 : (2**63) - 1)
          end

          # timestamp(<string>): time.Parse(time.RFC3339, ...) within
          # 0001-01-01T00:00:00Z..9999-12-31T23:59:59Z.
          def valid_timestamp?(value)
            return value.between?(-62_135_596_800, 253_402_300_799) if value.is_a?(Integer)
            return false unless value.is_a?(String)

            match = value.match(/\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-](\d{2}):(\d{2}))\z/)
            return false unless match

            year, month, day, hour, minute, second = match[1..6].map(&:to_i)
            return false unless Date.valid_date?(year, month, day) && hour < 24 && minute < 60 && second < 60
            return false if match[9] && (match[9].to_i >= 24 || match[10].to_i >= 60)

            offset = if match[8] == "Z"
                       0
                     else
                       ((match[9].to_i * 3600) + (match[10].to_i * 60)) * (match[8].start_with?("-") ? -1 : 1)
                     end
            seconds = Time.utc(year, month, day, hour, minute, second).to_i - offset
            seconds.between?(-62_135_596_800, 253_402_300_799)
          rescue ArgumentError
            false
          end

          # regexp.Compile (RE2): Onigmo syntax minus what RE2 refuses.
          def valid_regex?(value)
            return false unless value.is_a?(String)
            return false if value.match?(/\(\?(?:[=!>]|<[=!])|\\[1-9]|\\[ZhHRGKXgk]|[*+?}]\+/)

            Regexp.new(value)
            true
          rescue RegexpError
            false
          end

          def exempt?(ancestors) = ancestors.any? { |ancestor| ancestor.kind == :call && HOMOGENEOUS_EXEMPT.include?(ancestor.name) }

          def homogeneous(root, types, issues)
            lists = []
            maps = []
            descendants(root) do |node, ancestors|
              lists << [node, ancestors] if node.kind == :list
              maps << [node, ancestors] if node.kind == :map
            end
            lists.each do |node, ancestors|
              next if exempt?(ancestors)

              element_type = nil
              node.elements.each_with_index do |element, index|
                type = types[element]
                type = type.params[0] if node.optional_indices.include?(index)
                if element_type.nil?
                  element_type = type
                  next
                end
                next if element_type.equivalent?(type)

                issues.report(element.offset, "expected type '#{element_type}' but found '#{type}'")
                break
              end
            end
            maps.each do |node, ancestors|
              next if exempt?(ancestors)

              key_type = value_type = nil
              node.entries.each do |entry|
                key = types[entry.key]
                value = types[entry.value]
                value = value.params[0] if entry.optional
                if key_type.nil? && value_type.nil?
                  key_type = key
                  value_type = value
                  next
                end
                issues.report(entry.key.offset, "expected type '#{key_type}' but found '#{key}'") unless key_type.equivalent?(key)
                issues.report(entry.value.offset, "expected type '#{value_type}' but found '#{value}'") unless value_type.equivalent?(value)
              end
            end
          end

          FormatError = Struct.new(:node, :message)

          # stringFormatValidator (ext.Strings v1-v3): a literal format string
          # applied to a list literal is parsed and each clause checked against
          # its argument's type.
          def string_format(root, types, references, issues)
            calls = []
            descendants(root) do |node, _ancestors|
              next unless node.kind == :call && node.member? && node.name == "format"

              ids = references[node]
              next if ids && !ids.empty? && !ids.include?("string_format")
              next unless node.target.kind == :literal && node.target.value.is_a?(String)
              next unless node.args.length == 1 && node.args[0].kind == :list

              calls << node
            end
            calls.each do |call|
              arguments = call.args[0].elements
              requested = 0
              error = parse_format(call.target.value.b, arguments, types) { requested += 1 }
              if error
                issues.report((error.node || call).offset, error.message)
                next
              end
              if arguments.length > requested
                issues.report(call.offset, "too many arguments supplied to string.format (expected #{requested}, got #{arguments.length})")
              end
            end
          end

          # parseFormatString with the stringFormatChecker callbacks.
          def parse_format(text, arguments, types)
            index = 0
            argument_index = 0
            while index < text.bytesize
              if text.getbyte(index) != 0x25
                index += 1
                next
              end
              if index + 1 < text.bytesize && text.getbyte(index + 1) == 0x25
                index += 2
                next
              end
              yield
              return FormatError.new(nil, "unexpected end of string") if index + 1 >= text.bytesize
              return FormatError.new(nil, "index #{argument_index} out of range") if argument_index >= arguments.length

              read, error = format_clause(text.byteslice((index + 1)..), arguments[argument_index], types)
              return error if error

              index += 1 + read
              argument_index += 1
            end
            nil
          end

          def format_clause(text, argument, types)
            index = 0
            if text.getbyte(0) == 0x2e
              index = 1
              loop do
                if index >= text.bytesize
                  return [nil,
                          FormatError.new(nil,
                                          "could not parse formatting clause: error while parsing precision: could not find end of precision specifier")]
                end
                break unless text.getbyte(index).between?(0x30, 0x39)

                index += 1
              end
              if index == 1
                return [nil, FormatError.new(nil, "could not parse formatting clause: error while parsing precision: " \
                                                  "error while converting precision to integer: strconv.Atoi: parsing \"\": invalid syntax")]
              end
            end
            # rune(formatStr[i]): the byte as a code point.
            clause = text.getbyte(index).chr(Encoding::ISO_8859_1).encode(Encoding::UTF_8)
            index += 1
            valid, bad, message = case clause
                                  when "s" then verify_string(argument, types)
                                  when "d" then [kind_in?(types[argument], :int, :uint), argument,
                                                 "decimal clause can only be used on integers"]
                                  when "f" then [kind_in?(types[argument], :double, :string), argument,
                                                 "fixed-point clause can only be used on doubles"]
                                  when "e" then [kind_in?(types[argument], :double, :string), argument,
                                                 "scientific clause can only be used on doubles"]
                                  when "b" then [kind_in?(types[argument], :int, :uint, :bool), argument,
                                                 "only integers and bools can be formatted as binary"]
                                  when "x", "X" then [kind_in?(types[argument], :int, :uint, :string, :bytes), argument,
                                                      "only integers, byte buffers, and strings can be formatted as hex"]
                                  when "o" then [kind_in?(types[argument], :int, :uint), argument,
                                                 "octal clause can only be used on integers"]
                                  else
                                    return [nil,
                                            FormatError.new(nil,
                                                            "could not parse formatting clause: unrecognized formatting clause \"#{clause}\"")]
                                  end
            return [index, nil] if valid

            message ||= "string clause can only be used on strings, bools, bytes, ints, doubles, maps, lists, types, durations, and timestamps"
            [nil, FormatError.new(bad, "error during formatting: #{message}, was given #{types[bad].name}")]
          end

          def kind_in?(type, *kinds) = type.dyn? || kinds.include?(type.kind)

          STRING_KINDS = %i[list map int uint double bool string timestamp bytes duration type null].freeze

          def verify_string(node, types)
            return [false, node, nil] unless kind_in?(types[node], *STRING_KINDS)

            case node.kind
            when :list
              node.elements.each do |element|
                valid, bad, = verify_string(element, types)
                return [false, bad, nil] unless valid
              end
            when :map
              node.entries.each do |entry|
                [entry.key, entry.value].each do |part|
                  valid, bad, = verify_string(part, types)
                  return [false, bad, nil] unless valid
                end
              end
            end
            [true, node, nil]
          end
        end
      end
    end
  end
end
