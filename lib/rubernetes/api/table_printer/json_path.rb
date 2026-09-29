# frozen_string_literal: true

require "json"

module Rubernetes
  module API
    module TablePrinter
      # Port of k8s.io/client-go/util/jsonpath (v1.36.2) over decoded JSON
      # (Hash, Array, String, Integer, Float, true/false, nil), as the
      # apiextensions table convertor evaluates additionalPrinterColumns
      # against unstructured content.
      #
      # Go iterates maps in random order; wildcards and recursive descent over
      # a map here follow insertion order instead.  A String is a sequence of
      # bytes to reflection, so a wildcard over one yields GoUint8 values.
      class JSONPath
        # Go's walk functions return a partial value alongside the error;
        # the filter "exists" operator inspects it.
        class Error < StandardError
          attr_reader :partial

          def initialize(message = nil, partial = [])
            super(message)
            @partial = partial
          end
        end

        GoUint8 = Struct.new(:value)

        # Parse tree nodes (node.go).
        ListNode = Struct.new(:nodes)
        TextNode = Struct.new(:text)
        FieldNode = Struct.new(:value)
        ParamsEntry = Struct.new(:value, :known, :derived)
        ArrayNode = Struct.new(:params)
        FilterNode = Struct.new(:left, :right, :operator)
        IntNode = Struct.new(:value)
        FloatNode = Struct.new(:value)
        BoolNode = Struct.new(:value)
        WildcardNode = Class.new
        RecursiveNode = Class.new
        UnionNode = Struct.new(:nodes)
        IdentifierNode = Struct.new(:name)

        EOF = :eof
        LEFT_DELIM = "{"
        RIGHT_DELIM = "}"
        DICT_KEY = /\A'([^']*)'\z/
        SLICE_OPERATOR = /\A(-?[0-9]*)(:-?[0-9]*)?(:-?[0-9]*)?\z/
        FILTER = /\A([^!<>=]+)([!<>=]+)(.+?)\z/m
        MAX_INT = (1 << 63) - 1
        MIN_INT = -(1 << 63)

        # Parser (parser.go).
        class Parser
          attr_reader :root

          def self.parse(text)
            parser = new
            parser.parse(text)
            parser
          end

          # parseAction: the text wrapped in delimiters, its first list.
          def self.parse_action(text)
            parse("#{LEFT_DELIM}#{text}#{RIGHT_DELIM}").root.nodes.first
          end

          def parse(text)
            @input = text.chars
            @root = ListNode.new([])
            @pos = 0
            @start = 0
            @width = 0
            parse_text(@root)
            self
          end

          private

          def rest = @input[@pos..].join
          def rest_start?(prefix) = @input[@pos, prefix.length] == prefix.chars

          def consume
            value = @input[@start...@pos].join
            @start = @pos
            value
          end

          def next_char
            if @pos >= @input.length
              @width = 0
              return EOF
            end
            @width = 1
            @pos += 1
            @input[@pos - 1]
          end

          def peek
            char = next_char
            backup
            char
          end

          def backup
            @pos -= @width
          end

          def parse_text(current)
            loop do
              if rest_start?(LEFT_DELIM)
                current.nodes << TextNode.new(consume) if @pos > @start
                return parse_left_delim(current)
              end
              break if next_char == EOF
            end
            current.nodes << TextNode.new(consume) if @pos > @start
          end

          def parse_left_delim(current)
            @pos += LEFT_DELIM.length
            consume
            node = ListNode.new([])
            current.nodes << node
            parse_inside_action(node)
          end

          def parse_inside_action(current)
            loop do
              return parse_right_delim if rest_start?(RIGHT_DELIM)
              return parse_filter(current) if rest_start?("[?(")
              return parse_recursive(current) if rest_start?("..")

              char = next_char
              if char == EOF || end_of_line?(char)
                raise Error, "unclosed action"
              elsif char == " " || char == "@" || char == "$"
                consume
              elsif char == "["
                return parse_array(current)
              elsif char == '"' || char == "'"
                return parse_quote(current, char)
              elsif char == "."
                return parse_field(current)
              elsif char == "+" || char == "-" || digit?(char)
                backup
                return parse_number(current)
              elsif alphanumeric?(char)
                backup
                return parse_identifier(current)
              else
                raise Error, format("unrecognized character in action: U+%04X %s", char.ord, char.inspect)
              end
            end
          end

          def parse_right_delim
            @pos += RIGHT_DELIM.length
            consume
            parse_text(@root)
          end

          def parse_identifier(current)
            loop do
              char = next_char
              if terminator?(char)
                backup
                break
              end
            end
            value = consume
            current.nodes << (%w[true false].include?(value) ? BoolNode.new(value == "true") : IdentifierNode.new(value))
            parse_inside_action(current)
          end

          def parse_recursive(current)
            raise Error, "invalid multiple recursive descent" if current.nodes.last.is_a?(RecursiveNode)

            @pos += 2
            consume
            current.nodes << RecursiveNode.new
            return parse_field(current) if alphanumeric?(peek)

            parse_inside_action(current)
          end

          def parse_number(current)
            char = peek
            next_char if ["+", "-"].include?(char)
            loop do
              char = next_char
              next if char == "." || digit?(char)

              backup
              break
            end
            value = consume
            if (integer = go_atoi(value))
              current.nodes << IntNode.new(integer)
            elsif (float = go_parse_float(value))
              current.nodes << FloatNode.new(float)
            else
              raise Error, "cannot parse number #{value}"
            end
            parse_inside_action(current)
          end

          def go_atoi(text)
            return nil unless text.match?(/\A[+-]?[0-9]+\z/)

            value = Integer(text, 10)
            value.between?(MIN_INT, MAX_INT) ? value : nil
          end

          def go_parse_float(text)
            return nil unless text.match?(/\A[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)\z/)

            Float(text.sub(/\.\z/, ".0").sub(/\A([+-]?)\./) { "#{Regexp.last_match(1)}0." })
          rescue ArgumentError
            nil
          end

          def parse_array(current)
            loop do
              char = next_char
              raise Error, "unterminated array" if char == EOF || char == "\n"
              break if char == "]"
            end
            text = consume[1...-1]
            text = ":" if text == "*"
            parts = text.split(",", -1)
            if parts.length > 1
              union = parts.map { |part| Parser.parse_action("[#{part.gsub(/\A +| +\z/, "")}]") }
              current.nodes << UnionNode.new(union)
              return parse_inside_action(current)
            end
            if (match = DICT_KEY.match(text))
              Parser.parse_action(".#{match[1]}").nodes.each { |node| current.nodes << node }
              return parse_inside_action(current)
            end
            match = SLICE_OPERATOR.match(text)
            raise Error, "invalid array index #{text}" unless match

            values = [match[1].to_s, match[2].to_s, match[3].to_s]
            params = Array.new(3) { ParamsEntry.new(0, false, false) }
            3.times do |index|
              value = values[index]
              if !value.empty?
                value = value[1..] if index.positive?
                if index.positive? && value.empty?
                  params[index].known = false
                else
                  number = go_atoi(value)
                  raise Error, "array index #{value} is not a number" if number.nil?

                  params[index].known = true
                  params[index].value = number
                end
              elsif index == 1
                params[1].known = true
                params[1].value = params[0].value + 1
                params[1].derived = true
              end
            end
            current.nodes << ArrayNode.new(params)
            parse_inside_action(current)
          end

          def parse_filter(current)
            @pos += 3
            consume
            opened = false
            closed = false
            pair = nil
            loop do
              char = next_char
              raise Error, "unterminated filter" if char == EOF || char == "\n"

              if ['"', "'"].include?(char)
                unless opened
                  opened = true
                  pair = char
                  next
                end
                closed = true if @input[@pos - 2] != "\\" && char == pair
              elsif char == ")"
                break if opened == closed
              end
            end
            raise Error, "unclosed array expect ]" unless next_char == "]"

            text = consume[0...-2]
            if (match = FILTER.match(text))
              current.nodes << FilterNode.new(Parser.parse_action(match[1]), Parser.parse_action(match[3]), match[2])
            else
              current.nodes << FilterNode.new(Parser.parse_action(text), ListNode.new([]), "exists")
            end
            parse_inside_action(current)
          end

          def parse_quote(current, quote)
            loop do
              char = next_char
              raise Error, "unterminated quoted string" if char == EOF || char == "\n"
              break if char == quote && @input[@pos - 2] != "\\"
            end
            value = consume
            current.nodes << TextNode.new(JSONPath.unquote_extend(value))
            parse_inside_action(current)
          end

          def parse_field(current)
            consume
            loop do
              char = next_char
              if char == "\\"
                next_char
              elsif terminator?(char)
                backup
                break
              end
            end
            value = consume
            current.nodes << (value == "*" ? WildcardNode.new : FieldNode.new(value.delete("\\")))
            parse_inside_action(current)
          end

          def terminator?(char)
            return true if char == EOF || char == " " || char == "\t" || end_of_line?(char)

            [".", ",", "[", "]", "$", "@", "{", "}"].include?(char)
          end

          def end_of_line?(char) = ["\r", "\n"].include?(char)
          def digit?(char) = char != EOF && char.match?(/\A\p{Nd}\z/)
          def alphanumeric?(char) = char != EOF && (char == "_" || char.match?(/\A[\p{L}\p{Nd}]\z/))
        end

        # UnquoteExtend over strconv.UnquoteChar.
        def self.unquote_extend(text)
          raise Error, "invalid syntax" if text.length < 2

          quote = text[0]
          raise Error, "invalid syntax" unless quote == text[-1] && ['"', "'"].include?(quote)

          body = text[1...-1]
          return body unless body.include?("\\") || body.include?(quote)

          bytes = +"".b
          index = 0
          while index < body.length
            char = body[index]
            raise Error, "invalid syntax" if char == quote
            if char != "\\"
              bytes << char.b
              index += 1
              next
            end
            escape = body[index + 1]
            raise Error, "invalid syntax" if escape.nil?

            index += 2
            case escape
            when "a" then bytes << "\a"
            when "b" then bytes << "\b"
            when "f" then bytes << "\f"
            when "n" then bytes << "\n"
            when "r" then bytes << "\r"
            when "t" then bytes << "\t"
            when "v" then bytes << "\v"
            when "\\" then bytes << "\\"
            when "'", '"'
              raise Error, "invalid syntax" unless escape == quote

              bytes << escape
            when "x", "u", "U"
              length = {"x" => 2, "u" => 4, "U" => 8}.fetch(escape)
              digits = body[index, length].to_s
              raise Error, "invalid syntax" unless digits.length == length && digits.match?(/\A\h+\z/)

              index += length
              value = digits.to_i(16)
              if escape == "x"
                bytes << value.chr
              else
                raise Error, "invalid syntax" if value > 0x10FFFF || value.between?(0xD800, 0xDFFF)

                bytes << [value].pack("U").b
              end
            when "0".."7"
              digits = body[index - 1, 3].to_s
              raise Error, "invalid syntax" unless digits.match?(/\A[0-7]{3}\z/)

              value = digits.to_i(8)
              raise Error, "invalid syntax" if value > 255

              index += 2
              bytes << value.chr
            else
              raise Error, "invalid syntax"
            end
          end
          bytes.force_encoding(Encoding::UTF_8)
        end

        def self.parse(text, allow_missing_keys: false)
          new(Parser.parse(text), allow_missing_keys: allow_missing_keys)
        end

        def initialize(parser, allow_missing_keys: false)
          @parser = parser
          @allow_missing_keys = allow_missing_keys
          @begin_range = 0
          @in_range = 0
          @end_range = 0
          @last_end_node = nil
        end

        # FindResults: one result list per top-level node.
        def find_results(data)
          current = [data]
          nodes = @parser.root.nodes
          full = []
          index = 0
          while index < nodes.length
            node = nodes[index]
            results = walk(current, node)
            if @end_range.positive? && @end_range <= @in_range
              @end_range -= 1
              @last_end_node = node
              break
            end
            if @begin_range.positive?
              @begin_range -= 1
              @in_range += 1
              if results.empty?
                @parser.root.nodes = nodes[(index + 1)..]
                find_results(nil)
              else
                results.each do |value|
                  @parser.root.nodes = nodes[(index + 1)..]
                  full.concat(find_results(value))
                end
              end
              @in_range -= 1
              ((index + 1)...nodes.length).each do |position|
                if nodes[position].equal?(@last_end_node)
                  index = position
                  break
                end
              end
              index += 1
              next
            end
            full << results
            index += 1
          end
          full
        end

        # PrintResults (without EnableJSONOutput).
        def print_results(results)
          results.each_with_index.map do |value, index|
            text = value.is_a?(Hash) || value.is_a?(Array) ? JSONPath.go_json(value) : JSONPath.go_print(value)
            index == results.length - 1 ? text : "#{text} "
          end.join
        end

        # fmt.Fprint of a printable value.
        def self.go_print(value)
          case value
          when nil then "<no value>"
          when GoUint8 then value.value.to_s
          when Float then go_float(value, :g)
          else value.to_s
          end
        end

        # encoding/json Marshal: sorted keys, HTML-safe escaping.
        def self.go_json(value)
          case value
          when Hash
            "{#{value.keys.sort_by(&:to_s).map { |key| "#{go_json_string(key.to_s)}:#{go_json(value[key])}" }.join(",")}}"
          when Array then "[#{value.map { |item| go_json(item) }.join(",")}]"
          when String then go_json_string(value)
          when GoUint8 then value.value.to_s
          when Float then go_float(value, :json)
          when nil then "null"
          else value.to_s
          end
        end

        def self.go_json_string(text)
          escaped = text.to_s.each_char.map do |char|
            case char
            when '"' then '\\"'
            when "\\" then "\\\\"
            when "\n" then "\\n"
            when "\r" then "\\r"
            when "\t" then "\\t"
            when "<", ">", "&", " ", " " then format("\\u%04x", char.ord)
            else char.ord < 0x20 ? format("\\u%04x", char.ord) : char
            end
          end.join
          "\"#{escaped}\""
        end

        # strconv.FormatFloat(f, 'g', -1, 64) for fmt %v, or encoding/json's
        # float rendering.
        def self.go_float(value, style)
          return (value.positive? ? "+Inf" : "-Inf") if value.infinite?
          return "NaN" if value.nan?
          return (value.to_s.start_with?("-") ? "-0" : "0") if value.zero?

          sign = value.negative? ? "-" : ""
          digits, exponent = shortest_digits(value.abs)
          point = exponent + 1
          scientific = if style == :json
                         value.abs < 1e-6 || value.abs >= 1e21
                       else
                         exponent < -4 || exponent >= 6
                       end
          if scientific
            mantissa = digits.length > 1 ? "#{digits[0]}.#{digits[1..]}" : digits
            # strconv writes at least two exponent digits; encoding/json then
            # shortens a negative one ("e-07" -> "e-7").
            exp_text = format("%02d", exponent.abs)
            exp_text = exponent.abs.to_s if style == :json && exponent.negative?
            "#{sign}#{mantissa}e#{exponent.negative? ? "-" : "+"}#{exp_text}"
          elsif point <= 0
            "#{sign}0.#{"0" * -point}#{digits}"
          elsif point >= digits.length
            "#{sign}#{digits}#{"0" * (point - digits.length)}"
          else
            "#{sign}#{digits[0...point]}.#{digits[point..]}"
          end
        end

        # The shortest round-trip digits and decimal exponent of a positive
        # float (Ruby's Float#to_s is shortest round-trip too).
        def self.shortest_digits(value)
          text = value.to_s
          mantissa, exponent = text.split("e")
          exponent = exponent.to_i
          whole, fraction = mantissa.split(".")
          fraction = "" if fraction == "0"
          digits = "#{whole}#{fraction}"
          exponent += whole.length - 1
          stripped = digits.sub(/\A0+/, "")
          exponent -= digits.length - stripped.length
          [stripped.sub(/0+\z/, "").then { |text_digits| text_digits.empty? ? "0" : text_digits }, exponent]
        end

        private

        def walk(values, node)
          case node
          when ListNode then eval_list(values, node)
          when TextNode then [node.text]
          when FieldNode then eval_field(values, node)
          when ArrayNode then eval_array(values, node)
          when FilterNode then eval_filter(values, node)
          when IntNode, FloatNode, BoolNode then values.map { node.value }
          when WildcardNode then eval_wildcard(values)
          when RecursiveNode then eval_recursive(values)
          when UnionNode
            node.nodes.flat_map do |list|
              eval_list(values, list)
            rescue Error => error
              raise Error.new(error.message, values)
            end
          when IdentifierNode then eval_identifier(values, node)
          else raise Error, "unexpected Node #{node.inspect}"
          end
        end

        def eval_list(values, node)
          node.nodes.reduce(values) { |current, child| walk(current, child) }
        end

        def eval_identifier(values, node)
          case node.name
          when "range"
            @begin_range += 1
            values
          when "end"
            raise Error, "not in range, nothing to end" unless @in_range.positive?

            @end_range += 1
            []
          else
            raise Error.new("unrecognized identifier #{node.name}", values)
          end
        end

        def eval_array(values, node)
          result = []
          values.each do |value|
            next if value.nil?
            raise Error.new("#{type_name(value)} is not array or slice", values) unless value.is_a?(Array)

            start, finish, step = node.params.map(&:dup)
            start.value = 0 unless start.known
            start.value += value.length if start.value.negative?
            finish.value = value.length unless finish.known
            finish.value += value.length if finish.value.negative? || (finish.value.zero? && finish.derived)
            length = value.length
            return result if finish.value == start.value

            if start.value >= length || start.value.negative?
              raise Error.new("array index out of bounds: index #{start.value}, length #{length}", values)
            end
            if finish.value > length || finish.value.negative?
              raise Error.new("array index out of bounds: index #{finish.value - 1}, length #{length}", values)
            end
            if start.value > finish.value
              raise Error.new("starting index #{start.value} is greater than ending index #{finish.value}", values)
            end

            slice = value[start.value...finish.value]
            stride = 1
            if step.known
              raise Error.new("step must be > 0", values) unless step.value.positive?

              stride = step.value
            end
            (0...slice.length).step(stride) { |index| result << slice[index] }
          end
          result
        end

        def eval_field(values, node)
          results = []
          return results if values.empty?

          values.each do |value|
            next if value.nil?
            next unless value.is_a?(Hash)

            results << value[node.value] if value.key?(node.value)
          end
          raise Error, "#{node.value} is not found" if results.empty? && !@allow_missing_keys

          results
        end

        def children(value)
          case value
          when Hash then value.values
          when Array then value
          when String then value.bytes.map { |byte| GoUint8.new(byte) }
          else []
          end
        end

        def eval_wildcard(values)
          values.reject(&:nil?).flat_map { |value| children(value) }
        end

        def eval_recursive(values)
          result = []
          values.each do |value|
            next if value.nil?

            nested = children(value)
            next if nested.empty?

            result << value
            result.concat(eval_recursive(nested))
          end
          result
        end

        def eval_filter(values, node)
          results = []
          values.each do |value|
            raise Error.new("#{value.inspect} is not array or slice and cannot be filtered", values) unless value.is_a?(Array)

            value.each do |element|
              lefts = begin
                eval_list([element], node.left)
              rescue Error => error
                raise Error.new(error.message, values) unless node.operator == "exists"

                error.partial
              end
              if node.operator == "exists"
                results << element unless lefts.empty?
                next
              end
              next if lefts.empty?
              raise Error.new("can only compare one element at a time", values) if lefts.length > 1

              rights = begin
                eval_list([element], node.right)
              rescue Error => error
                raise Error.new(error.message, values)
              end
              next if rights.empty?
              raise Error.new("can only compare one element at a time", values) if rights.length > 1

              passed = begin
                compare(node.operator, lefts.first, rights.first)
              rescue Error => error
                raise Error.new(error.message, results)
              end
              results << element if passed
            end
          end
          results
        end

        def basic_kind(value)
          case value
          when true, false then :bool
          when Integer then :int
          when GoUint8 then :uint
          when Float then :float
          when String then :string
          else raise Error, "invalid type for comparison"
          end
        end

        def scalar(value) = value.is_a?(GoUint8) ? value.value : value

        def equal?(left, right)
          left_kind = basic_kind(left)
          right_kind = basic_kind(right)
          if left_kind != right_kind
            raise Error, "incompatible types for comparison" unless [left_kind, right_kind].sort == %i[int uint]

            return scalar(left) == scalar(right)
          end
          scalar(left) == scalar(right)
        end

        def less?(left, right)
          left_kind = basic_kind(left)
          right_kind = basic_kind(right)
          if left_kind != right_kind
            raise Error, "incompatible types for comparison" unless [left_kind, right_kind].sort == %i[int uint]

            return scalar(left) < scalar(right)
          end
          raise Error, "invalid type for comparison" if left_kind == :bool

          scalar(left) < scalar(right)
        end

        def compare(operator, left, right)
          case operator
          when "<" then less?(left, right)
          when ">" then !(less?(left, right) || equal?(left, right))
          when "==" then equal?(left, right)
          when "!=" then !equal?(left, right)
          when "<=" then less?(left, right) || equal?(left, right)
          when ">=" then !less?(left, right)
          else raise Error, "unrecognized filter operator #{operator}"
          end
        end

        def type_name(value)
          case value
          when Hash then "map[string]interface {}"
          when String then "string"
          when Integer then "int64"
          when Float then "float64"
          when true, false then "bool"
          else value.class.name
          end
        end
      end
    end
  end
end
