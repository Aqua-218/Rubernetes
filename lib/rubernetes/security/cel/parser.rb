# frozen_string_literal: true

require_relative "lexer"

module Rubernetes
  module Security
    module CEL
      # AST nodes are arrays: [:literal, value], [:ident, name], [:select, target, field, optional],
      # [:index, target, index, optional], [:call, function, target_or_nil, args],
      # [:list, items], [:map, [[key, value], ...]], [:struct, type, fields], [:unary, op, expr],
      # [:binary, op, left, right], [:conditional, cond, then, else],
      # [:comprehension, iter_var, iter_range, accu_var, accu_init, loop_condition, loop_step, result]
      class Parser
        MACROS = %w[has all exists exists_one map filter].freeze

        def initialize(source)
          @tokens = Lexer.new(source).tokens
          @index = 0
          @depth = 0
        end

        def parse
          expression = parse_conditional
          raise SyntaxError, "unexpected token #{peek.value.inspect} at #{peek.position}" unless peek.type == :eof

          expression
        end

        private

        def peek(offset = 0)
          @tokens[@index + offset]
        end

        def advance
          token = @tokens[@index]
          @index += 1
          token
        end

        def accept(value)
          return nil unless peek.type == :operator && peek.value == value

          advance
        end

        def expect(value)
          token = accept(value)
          raise SyntaxError, "expected #{value.inspect} but found #{peek.value.inspect} at #{peek.position}" unless token

          token
        end

        def nested
          @depth += 1
          raise SyntaxError, "expression nesting exceeds 32 levels" if @depth > 32

          yield
        ensure
          @depth -= 1
        end

        def parse_conditional
          condition = parse_or
          return condition unless accept("?")

          nested do
            consequent = parse_conditional
            expect(":")
            alternative = parse_conditional
            [:conditional, condition, consequent, alternative]
          end
        end

        def parse_or
          left = parse_and
          left = [:binary, "||", left, parse_and] while accept("||")
          left
        end

        def parse_and
          left = parse_relation
          left = [:binary, "&&", left, parse_relation] while accept("&&")
          left
        end

        def parse_relation
          left = parse_additive
          loop do
            operator = %w[== != < <= > >= in].find { |candidate| accept(candidate) }
            break unless operator

            left = [:binary, operator, left, parse_additive]
          end
          left
        end

        def parse_additive
          left = parse_multiplicative
          loop do
            operator = %w[+ -].find { |candidate| accept(candidate) }
            break unless operator

            left = [:binary, operator, left, parse_multiplicative]
          end
          left
        end

        def parse_multiplicative
          left = parse_unary
          loop do
            operator = %w[* / %].find { |candidate| accept(candidate) }
            break unless operator

            left = [:binary, operator, left, parse_unary]
          end
          left
        end

        def parse_unary
          if accept("!")
            count = 1
            count += 1 while accept("!")
            operand = parse_member
            return count.odd? ? [:unary, "!", operand] : operand
          end
          if accept("-")
            count = 1
            count += 1 while accept("-")
            operand = parse_member
            return count.odd? ? [:unary, "-", operand] : operand
          end
          parse_member
        end

        def parse_member
          expression = parse_primary
          loop do
            if accept(".") || (optional = accept(".?"))
              optional_select = !optional.nil?
              name_token = advance
              # Reserved words are legal as field and method names after a dot
              # (Kubernetes' authorizer.namespace(...) relies on this).
              raise SyntaxError, "expected field name at #{name_token.position}" unless %i[identifier reserved].include?(name_token.type)

              if accept("(")
                arguments = parse_arguments
                if name_token.value == "bind" && expression == [:ident, "cel"]
                  # ext.Bindings: cel.bind(var, init, expr) evaluates +expr+
                  # with +var+ bound to +init+.
                  unless arguments.length == 3 && arguments.first.first == :ident
                    raise SyntaxError, "cel.bind() requires an identifier and 2 expressions"
                  end

                  expression = [:bind, arguments[0][1], arguments[1], arguments[2]]
                elsif MACROS.include?(name_token.value)
                  expression = expand_macro(name_token.value, expression, arguments)
                else
                  expression = [:call, name_token.value, expression, arguments]
                end
              else
                expression = [:select, expression, name_token.value, optional_select]
              end
              optional = nil
            elsif accept("[") || (optional = accept("[?"))
              optional_index = !optional.nil?
              index = nested { parse_conditional }
              expect("]")
              expression = [:index, expression, index, optional_index]
              optional = nil
            elsif peek.type == :operator && peek.value == "{" && (path = struct_type_path(expression))
              expression = parse_struct(path)
            else
              break
            end
          end
          expression
        end

        def parse_arguments
          arguments = []
          unless peek.type == :operator && peek.value == ")"
            loop do
              arguments << nested { parse_conditional }
              break unless accept(",")
            end
          end
          expect(")")
          arguments
        end

        def parse_primary
          token = peek
          case token.type
          when :int then advance; [:literal, token.value]
          when :uint then advance; [:literal, Values::UInt.new(token.value)]
          when :double then advance; [:literal, token.value]
          when :string then advance; [:literal, token.value]
          when :bytes then advance; [:literal, Values::Bytes.new(token.value)]
          when :bool then advance; [:literal, token.value]
          when :null then advance; [:literal, nil]
          when :reserved
            raise SyntaxError, "reserved identifier #{token.value} at #{token.position}"
          when :identifier
            advance
            name = token.value
            if accept("(")
              arguments = parse_arguments
              if name == "has"
                raise SyntaxError, "has() requires a field selection" unless arguments.length == 1 && arguments.first.first == :select

                return [:has, arguments.first[1], arguments.first[2]]
              end
              return [:call, name, nil, arguments]
            end
            [:ident, name]
          when :operator
            case token.value
            when "("
              advance
              expression = nested { parse_conditional }
              expect(")")
              expression
            when "["
              advance
              items = []
              unless peek.type == :operator && peek.value == "]"
                loop do
                  items << nested { parse_conditional }
                  break unless accept(",")
                  break if peek.type == :operator && peek.value == "]"
                end
              end
              expect("]")
              [:list, items]
            when "{"
              advance
              entries = []
              unless peek.type == :operator && peek.value == "}"
                loop do
                  key = nested { parse_conditional }
                  expect(":")
                  value = nested { parse_conditional }
                  entries << [key, value]
                  break unless accept(",")
                  break if peek.type == :operator && peek.value == "}"
                end
              end
              expect("}")
              [:map, entries]
            when "."
              advance
              name_token = advance
              raise SyntaxError, "expected identifier after leading dot" unless name_token.type == :identifier

              [:ident, name_token.value]
            else
              raise SyntaxError, "unexpected token #{token.value.inspect} at #{token.position}"
            end
          else
            raise SyntaxError, "unexpected end of expression"
          end
        end

        # `Name{field: value, ...}` and `Name.Sub{...}`: CEL message
        # construction.  Kubernetes' MutatingAdmissionPolicy builds its apply
        # configurations this way (`Object{spec: Object.spec{replicas: 1}}`);
        # the type path is kept for the checker, the value is the field map.
        def struct_type_path(expression)
          case expression.first
          when :ident then [expression[1]]
          when :ident_path then expression[1]
          when :select
            return nil if expression[3]

            parent = struct_type_path(expression[1])
            parent && parent + [expression[2]]
          end
        end

        def parse_struct(path)
          expect("{")
          fields = []
          unless peek.type == :operator && peek.value == "}"
            loop do
              name_token = advance
              raise SyntaxError, "expected field name at #{name_token.position}" unless %i[identifier reserved].include?(name_token.type)

              expect(":")
              fields << [name_token.value, nested { parse_conditional }]
              break unless accept(",")
              break if peek.type == :operator && peek.value == "}"
            end
          end
          expect("}")
          [:struct, path.join("."), fields]
        end

        # Macro expansion into comprehensions (langdef.md "Macros").
        def expand_macro(name, target, arguments)
          case name
          when "all", "exists", "exists_one", "map", "filter"
            raise SyntaxError, "#{name}() requires a variable" if arguments.empty? || arguments.first.first != :ident

            variable = arguments.first[1]
            case name
            when "all"
              raise SyntaxError, "all() takes 2 arguments" unless arguments.length == 2
              [:comprehension, variable, target, "__result__", [:literal, true], [:ident, "__result__"],
               [:binary, "&&", [:ident, "__result__"], arguments[1]], [:ident, "__result__"]]
            when "exists"
              raise SyntaxError, "exists() takes 2 arguments" unless arguments.length == 2
              [:comprehension, variable, target, "__result__", [:literal, false], [:unary, "!", [:ident, "__result__"]],
               [:binary, "||", [:ident, "__result__"], arguments[1]], [:ident, "__result__"]]
            when "exists_one"
              raise SyntaxError, "exists_one() takes 2 arguments" unless arguments.length == 2
              [:comprehension, variable, target, "__result__", [:literal, 0], [:literal, true],
               [:conditional, arguments[1], [:binary, "+", [:ident, "__result__"], [:literal, 1]], [:ident, "__result__"]],
               [:binary, "==", [:ident, "__result__"], [:literal, 1]]]
            when "map"
              if arguments.length == 2
                [:comprehension, variable, target, "__result__", [:list, []], [:literal, true],
                 [:binary, "+", [:ident, "__result__"], [:list, [arguments[1]]]], [:ident, "__result__"]]
              elsif arguments.length == 3
                [:comprehension, variable, target, "__result__", [:list, []], [:literal, true],
                 [:conditional, arguments[1], [:binary, "+", [:ident, "__result__"], [:list, [arguments[2]]]], [:ident, "__result__"]], [:ident, "__result__"]]
              else
                raise SyntaxError, "map() takes 2 or 3 arguments"
              end
            when "filter"
              raise SyntaxError, "filter() takes 2 arguments" unless arguments.length == 2
              [:comprehension, variable, target, "__result__", [:list, []], [:literal, true],
               [:conditional, arguments[1], [:binary, "+", [:ident, "__result__"], [:list, [[:ident, variable]]]], [:ident, "__result__"]], [:ident, "__result__"]]
            end
          else
            [:call, name, target, arguments]
          end
        end
      end
    end
  end
end
