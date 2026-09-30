# frozen_string_literal: true

require_relative "../lexer"
require_relative "../values"

module Rubernetes
  module Security
    module CEL
      module Check
        # A parsed expression node: cel-go's ast.Expr kinds, each with the
        # source offset cel-go's parser gives its id.
        class Node
          attr_reader :kind, :offset
          attr_accessor :value, :name, :target, :args, :operand, :test_only, :elements, :optional_indices, :entries,
                        :fields, :iter_var, :iter_var2, :iter_range, :accu_var, :accu_init, :loop_condition, :loop_step, :result

          def initialize(kind, offset, **attributes)
            @kind = kind
            @offset = offset
            attributes.each { |key, value| instance_variable_set("@#{key}", value) }
          end

          def member? = !@target.nil?
        end

        # A map entry or struct field initializer ([key or name, value,
        # optional]) with the offset of its ':'.
        Entry = Struct.new(:key, :value, :optional, :offset)

        class ParseError < StandardError; end

        # The expression text and its line table (common.Source).
        class Source
          attr_reader :text, :lines

          def initialize(text)
            @text = text.to_s
            @lines = @text.split("\n", -1)
            @starts = [0]
            @text.each_char.with_index { |char, index| @starts << (index + 1) if char == "\n" }
          end

          # [line (1-based), column (0-based, code points)].
          def location(offset)
            line = @starts.rindex { |start| start <= offset } || 0
            [line + 1, offset - @starts[line]]
          end

          def snippet(line) = line.between?(1, @lines.length) ? @lines[line - 1] : nil
        end

        # parser.go / helper.go / macro.go: the AST cel-go builds for an
        # expression -- operators as calls, && and || balanced, a sign fused
        # into a numeric literal, macros expanded -- with each node at the
        # offset of the token cel-go takes its id from.
        class Parser
          ACCUMULATOR = "__result__"
          UNUSED_ITER_VAR = "#unused"
          RELATIONS = {"==" => "_==_", "!=" => "_!=_", "<" => "_<_", "<=" => "_<=_", ">" => "_>_", ">=" => "_>=_", "in" => "@in"}.freeze
          ADDITIVE = {"+" => "_+_", "-" => "_-_"}.freeze
          MULTIPLICATIVE = {"*" => "_*_", "/" => "_/_", "%" => "_%_"}.freeze

          # A macro whose arguments are malformed: reported at the offending
          # argument (or the call), parsing goes on (parser.expandMacro).
          class MacroError < StandardError
            attr_reader :offset

            def initialize(message, offset)
              @offset = offset
              super(message)
            end
          end

          # [offset, message] of every macro misuse.
          attr_reader :errors

          # macros: [[function, arg count, receiver style], ...] of the environment.
          def initialize(text, macros:)
            @tokens = Lexer.new(text).tokens
            @index = 0
            @macros = macros
            @errors = []
          end

          def parse
            expression = parse_expr
            raise ParseError, "unexpected token #{peek.value.inspect}" unless peek.type == :eof

            expression
          end

          private

          def peek(offset = 0) = @tokens[@index + offset]

          def advance
            token = @tokens[@index]
            @index += 1
            token
          end

          def operator?(value, offset = 0)
            token = peek(offset)
            token.type == :operator && token.value == value
          end

          def accept(value)
            operator?(value) ? advance : nil
          end

          def expect(value)
            accept(value) || raise(ParseError, "expected #{value.inspect}")
          end

          def call(offset, function, *args, target: nil) = Node.new(:call, offset, name: function, target: target, args: args)
          def literal(offset, value) = Node.new(:literal, offset, value: value)
          def ident(offset, name) = Node.new(:ident, offset, name: name)

          def parse_expr
            condition = parse_or
            question = accept("?")
            return condition unless question

            consequent = parse_or
            expect(":")
            alternative = parse_expr
            call(question.position, "_?_:_", condition, consequent, alternative)
          end

          def parse_or = parse_logic("||", "_||_") { parse_and }
          def parse_and = parse_logic("&&", "_&&_") { parse_relation }

          # logicManager with balancing: terms joined into a balanced tree.
          def parse_logic(operator, function)
            terms = [yield]
            ops = []
            while (token = accept(operator))
              ops << token.position
              terms << yield
            end
            return terms.first if ops.empty?

            balanced(function, terms, ops, 0, ops.length - 1)
          end

          def balanced(function, terms, ops, lo, hi)
            mid = (lo + hi + 1) / 2
            left = mid == lo ? terms[mid] : balanced(function, terms, ops, lo, mid - 1)
            right = mid == hi ? terms[mid + 1] : balanced(function, terms, ops, mid + 1, hi)
            call(ops[mid], function, left, right)
          end

          def parse_relation
            left = parse_additive
            while (function = RELATIONS[relation_operator])
              token = advance
              left = global_call_or_macro(token.position, function, left, parse_additive)
            end
            left
          end

          def relation_operator
            token = peek
            token.type == :operator ? token.value : nil
          end

          def parse_additive
            left = parse_multiplicative
            while peek.type == :operator && (function = ADDITIVE[peek.value])
              token = advance
              left = global_call_or_macro(token.position, function, left, parse_multiplicative)
            end
            left
          end

          def parse_multiplicative
            left = parse_unary
            while peek.type == :operator && (function = MULTIPLICATIVE[peek.value])
              token = advance
              left = global_call_or_macro(token.position, function, left, parse_unary)
            end
            left
          end

          # LogicalNot / Negate: an even run of operators cancels out; a single
          # '-' before a number is the literal's sign (MemberExpr wins).
          def parse_unary
            if operator?("!")
              first = peek.position
              count = 0
              count += 1 while accept("!")
              operand = parse_member
              return count.even? ? operand : global_call_or_macro(first, "!_", operand)
            end
            if operator?("-")
              return parse_member if %i[int double].include?(peek(1).type) && !operator?("-", 1)

              first = peek.position
              count = 0
              count += 1 while accept("-")
              operand = parse_member
              return count.even? ? operand : global_call_or_macro(first, "-_", operand)
            end
            parse_member
          end

          def parse_member
            expression = parse_primary
            loop do
              if (token = accept(".") || accept(".?"))
                name_token = advance
                raise ParseError, "expected field name" unless %i[identifier reserved].include?(name_token.type)

                if token.value == ".?"
                  expression = call(token.position, "_?._", expression, literal(name_token.position, name_token.value))
                elsif (open = accept("("))
                  arguments = parse_arguments
                  expression = receiver_call_or_macro(open.position, name_token.value, expression, arguments)
                else
                  expression = Node.new(:select, token.position, operand: expression, name: name_token.value, test_only: false)
                end
              elsif (token = accept("[") || accept("[?"))
                index = parse_expr
                expect("]")
                expression = global_call_or_macro(token.position, token.value == "[?" ? "_[?_]" : "_[_]", expression, index)
              elsif operator?("{") && (path = message_path(expression))
                expression = parse_message(path)
              else
                break
              end
            end
            expression
          end

          def message_path(expression)
            case expression.kind
            when :ident then [expression.name]
            when :select
              parent = message_path(expression.operand)
              parent && (parent + [expression.name])
            end
          end

          def parse_arguments
            arguments = []
            unless operator?(")")
              loop do
                arguments << parse_expr
                break unless accept(",")
              end
            end
            expect(")")
            arguments
          end

          def parse_primary
            token = peek
            case token.type
            when :int, :double
              advance
              literal(token.position, token.value)
            when :operator
              case token.value
              when "-"
                # A signed numeric literal: the literal starts at the sign.
                advance
                number = advance
                literal(token.position, -number.value)
              when "(" then advance
                            expression = parse_expr
                            expect(")")
                            expression
              when "[", "[?" then parse_list
              when "{" then parse_map
              when "."
                advance
                name_token = advance
                raise ParseError, "expected identifier" unless name_token.type == :identifier

                primary_identifier(name_token, ".")
              else raise ParseError, "unexpected token #{token.value.inspect}"
              end
            when :uint then advance
                            literal(token.position, Values::UInt.new(token.value))
            when :string then advance
                              literal(token.position, token.value)
            when :bytes then advance
                             literal(token.position, Values::Bytes.new(token.value))
            when :bool then advance
                            literal(token.position, token.value)
            when :null then advance
                            literal(token.position, nil)
            when :identifier then advance
                                  primary_identifier(token, "")
            else raise ParseError, "unexpected #{token.type}"
            end
          end

          def primary_identifier(token, prefix)
            name = prefix + token.value
            if (open = accept("("))
              return global_call_or_macro(open.position, name, *parse_arguments)
            end

            ident(token.position, name)
          end

          # The lexer reads "[?" as one token: a list whose first element is
          # optional.
          def parse_list
            open = advance
            elements = []
            optional_indices = []
            first_optional = open.value == "[?"
            unless operator?("]") && !first_optional
              loop do
                optional_indices << elements.length if accept("?") || first_optional
                first_optional = false
                elements << parse_expr
                break unless accept(",")
                break if operator?("]")
              end
            end
            expect("]")
            Node.new(:list, open.position, elements: elements, optional_indices: optional_indices)
          end

          def parse_map
            open = advance
            entries = []
            unless operator?("}")
              loop do
                optional = !accept("?").nil?
                key = parse_expr
                colon = expect(":")
                entries << Entry.new(key, parse_expr, optional, colon.position)
                break unless accept(",")
                break if operator?("}")
              end
            end
            expect("}")
            Node.new(:map, open.position, entries: entries)
          end

          def parse_message(path)
            open = expect("{")
            fields = []
            unless operator?("}")
              loop do
                optional = !accept("?").nil?
                name_token = advance
                raise ParseError, "expected field name" unless %i[identifier reserved].include?(name_token.type)

                colon = expect(":")
                fields << Entry.new(name_token.value, parse_expr, optional, colon.position)
                break unless accept(",")
                break if operator?("}")
              end
            end
            expect("}")
            Node.new(:struct, open.position, name: path.join("."), fields: fields)
          end

          def global_call_or_macro(offset, function, *args)
            expand_macro_or_error(offset, function, nil, args) || call(offset, function, *args)
          end

          def receiver_call_or_macro(offset, function, target, args)
            expand_macro_or_error(offset, function, target, args) || call(offset, function, *args, target: target)
          end

          def expand_macro_or_error(offset, function, target, args)
            expand_macro(offset, function, target, args)
          rescue MacroError => error
            @errors << [error.offset || offset, error.message]
            Node.new(:error, offset)
          end

          def macro?(function, count, receiver) = @macros.include?([function, count, receiver])

          # macro.go, ext/comprehensions.go, ext/lists.go, cel/library.go:
          # every generated node sits at the macro call's offset.
          def expand_macro(at, function, target, args)
            receiver = !target.nil?
            return nil unless macro?(function, args.length, receiver)

            case [function, receiver]
            when ["has", false]
              raise MacroError.new("invalid argument to has() macro", args[0].offset) unless args[0].kind == :select

              Node.new(:select, at, operand: args[0].operand, name: args[0].name, test_only: true)
            when ["all", true], ["exists", true], ["exists_one", true], ["existsOne", true]
              quantifier = function == "existsOne" ? "exists_one" : function
              args.length == 3 ? two_var_quantifier(at, quantifier, target, args) : quantifier(at, quantifier, target, args)
            when ["map", true] then make_map(at, target, args)
            when ["filter", true] then make_filter(at, target, args)
            when ["optMap", true], ["optFlatMap", true] then opt_map(at, function, target, args)
            when ["transformList", true] then transform(at, :list, target, args)
            when ["transformMap", true] then transform(at, :map, target, args)
            when ["transformMapEntry", true] then transform(at, :entry, target, args)
            when ["sortBy", true] then sort_by(at, target, args)
            end
          end

          def iter_var!(node, message = "argument must be a simple name")
            raise MacroError.new(message, node.offset) unless node.kind == :ident
            raise MacroError.new("iteration variable overwrites accumulator variable", node.offset) if node.name == ACCUMULATOR

            node.name
          end

          def accu(at) = ident(at, ACCUMULATOR)

          def comprehension(at, range, var, init, condition, step, result, var2: nil)
            Node.new(:comprehension, at, iter_range: range, iter_var: var, iter_var2: var2, accu_var: ACCUMULATOR, accu_init: init,
                                         loop_condition: condition, loop_step: step, result: result)
          end

          def quantifier_parts(at, kind, predicate)
            case kind
            when "all"
              [literal(at, true), call(at, "@not_strictly_false", accu(at)), call(at, "_&&_", accu(at), predicate), accu(at)]
            when "exists"
              [literal(at, false), call(at, "@not_strictly_false", call(at, "!_", accu(at))), call(at, "_||_", accu(at), predicate),
               accu(at)]
            else
              [literal(at, 0), literal(at, true),
               call(at, "_?_:_", predicate, call(at, "_+_", accu(at), literal(at, 1)), accu(at)),
               call(at, "_==_", accu(at), literal(at, 1))]
            end
          end

          def quantifier(at, kind, target, args)
            var = iter_var!(args[0])
            init, condition, step, result = quantifier_parts(at, kind, args[1])
            comprehension(at, target, var, init, condition, step, result)
          end

          def two_var_iter_vars!(args)
            first = iter_var!(args[0], "argument must be a simple name")
            second = iter_var!(args[1], "argument must be a simple name")
            raise MacroError.new("duplicate variable name: #{first}", args[1].offset) if first == second

            [first, second]
          end

          def two_var_quantifier(at, kind, target, args)
            first, second = two_var_iter_vars!(args)
            init, condition, step, result = quantifier_parts(at, kind, args[2])
            comprehension(at, target, first, init, condition, step, result, var2: second)
          end

          def make_map(at, target, args)
            var = iter_var!(args[0], "argument is not an identifier")
            filter, fn = args.length == 3 ? [args[1], args[2]] : [nil, args[1]]
            step = call(at, "_+_", accu(at), Node.new(:list, at, elements: [fn], optional_indices: []))
            step = call(at, "_?_:_", filter, step, accu(at)) if filter
            comprehension(at, target, var, Node.new(:list, at, elements: [], optional_indices: []), literal(at, true), step, accu(at))
          end

          def make_filter(at, target, args)
            var = iter_var!(args[0], "argument is not an identifier")
            step = call(at, "_+_", accu(at), Node.new(:list, at, elements: [args[0]], optional_indices: []))
            step = call(at, "_?_:_", args[1], step, accu(at))
            comprehension(at, target, var, Node.new(:list, at, elements: [], optional_indices: []), literal(at, true), step, accu(at))
          end

          def opt_map(at, function, target, args)
            raise MacroError.new("#{function}() variable name must be a simple identifier", args[0].offset) unless args[0].kind == :ident

            var = args[0].name
            loop = Node.new(:comprehension, at, iter_range: Node.new(:list, at, elements: [], optional_indices: []), iter_var: UNUSED_ITER_VAR,
                                                accu_var: var, accu_init: call(at, "value", target: copy(target)), loop_condition: literal(at, false),
                                                loop_step: ident(at, var), result: args[1])
            present = function == "optMap" ? call(at, "optional.of", loop) : loop
            call(at, "_?_:_", call(at, "hasValue", target: target), present, call(at, "optional.none"))
          end

          def transform(at, kind, target, args)
            first, second = two_var_iter_vars!(args)
            filter, fn = args.length == 4 ? [args[2], args[3]] : [nil, args[2]]
            step = case kind
                   when :list then call(at, "_+_", accu(at), Node.new(:list, at, elements: [fn], optional_indices: []))
                   when :map then call(at, "cel.@mapInsert", accu(at), ident(at, first), fn)
                   else call(at, "cel.@mapInsert", accu(at), fn)
                   end
            step = call(at, "_?_:_", filter, step, accu(at)) if filter
            init = kind == :list ? Node.new(:list, at, elements: [], optional_indices: []) : Node.new(:map, at, entries: [])
            comprehension(at, target, first, init, literal(at, true), step, accu(at), var2: second)
          end

          def sort_by(at, target, args)
            unless %i[list select ident comprehension call].include?(target.kind)
              raise MacroError.new("sortBy can only be applied to a list, identifier, comprehension, call or select expression",
                                   target.offset)
            end

            input = ident(at, "@__sortBy_input__")
            keys = make_map(at, copy(input), args)
            sorted = call(at, "@sortByAssociatedKeys", keys, target: copy(input))
            Node.new(:comprehension, at, iter_range: Node.new(:list, at, elements: [], optional_indices: []), iter_var: UNUSED_ITER_VAR,
                                         accu_var: input.name, accu_init: target, loop_condition: literal(at, false), loop_step: input, result: sorted)
          end

          # exprHelper.Copy: the same tree, fresh nodes at the same offsets.
          def copy(node)
            return nil if node.nil?

            attributes = {}
            node.instance_variables.each do |variable|
              next if %i[@kind @offset].include?(variable)

              value = node.instance_variable_get(variable)
              attributes[variable.to_s.delete_prefix("@").to_sym] = copy_value(value)
            end
            Node.new(node.kind, node.offset, **attributes)
          end

          def copy_value(value)
            case value
            when Node then copy(value)
            when Entry then Entry.new(copy_value(value.key), copy_value(value.value), value.optional, value.offset)
            when Array then value.map { |item| copy_value(item) }
            else value
            end
          end
        end
      end
    end
  end
end
