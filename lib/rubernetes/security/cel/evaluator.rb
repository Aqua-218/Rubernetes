# frozen_string_literal: true

require_relative "parser"
require_relative "values"
require_relative "library"

module Rubernetes
  module Security
    module CEL
      # Tree-walking CEL evaluator with the Kubernetes extension libraries.
      # Errors follow CEL semantics: missing keys, division by zero and type
      # mismatches raise; logical operators absorb errors on the other branch
      # (commutative &&/||); comprehensions are bounded by a cost budget so a
      # policy can never spin the API server.
      class Evaluator
        DEFAULT_COST_LIMIT = 1_000_000

        Program = Struct.new(:ast, :source)

        def initialize(cost_limit: DEFAULT_COST_LIMIT, library: Library.new)
          @cost_limit = cost_limit
          @library = library
          @cache = {}
          @mutex = Mutex.new
        end

        def compile(source)
          @mutex.synchronize { @cache[source] ||= Program.new(Parser.new(source).parse, source) }
        end

        def evaluate(source, variables = {})
          run(compile(source), variables)
        end

        def run(program, variables)
          context = Context.new(variables: variables, library: @library, cost_limit: @cost_limit)
          context.evaluate(program.ast)
        end

        class Context
          attr_reader :library

          def initialize(variables:, library:, cost_limit:)
            @scopes = [normalize_variables(variables)]
            @library = library
            @cost_limit = cost_limit
            @cost = 0
          end

          def charge(amount = 1)
            @cost += amount
            raise EvaluationError, "expression cost exceeds the limit (#{@cost_limit})" if @cost > @cost_limit
          end

          def lookup(name)
            @scopes.reverse_each { |scope| return scope[name] if scope.key?(name) }
            raise EvaluationError, "undeclared reference to '#{name}'"
          end

          def declared?(name)
            @scopes.any? { |scope| scope.key?(name) }
          end

          def with(bindings)
            @scopes.push(bindings)
            yield
          ensure
            @scopes.pop
          end

          def evaluate(node)
            charge
            case node.first
            when :literal then node[1]
            when :ident then lookup(node[1])
            when :select then eval_select(node)
            when :has then eval_has(node)
            when :index then eval_index(node)
            when :list then node[1].map { |item| evaluate(item) }
            when :struct
              node[2].each_with_object(Values::ObjectVal.new(node[1])) do |(field, value_node), hash|
                raise EvaluationError, "duplicate field #{field.inspect} in #{node[1]}" if hash.key?(field)

                hash[field] = evaluate(value_node)
              end
            when :map
              node[1].each_with_object({}) do |(key_node, value_node), hash|
                key = evaluate(key_node)
                unless [Integer, Values::UInt, TrueClass, FalseClass, String].any? { |type| key.is_a?(type) }
                  raise EvaluationError, "map key must be int, uint, bool or string"
                end
                raise EvaluationError, "duplicate map key #{key.inspect}" if hash.key?(key)

                hash[key] = evaluate(value_node)
              end
            when :unary then eval_unary(node)
            when :binary then eval_binary(node)
            when :conditional
              condition = evaluate(node[1])
              raise TypeMismatch, "conditional requires a bool" unless [true, false].include?(condition)

              condition ? evaluate(node[2]) : evaluate(node[3])
            when :call then eval_call(node)
            when :comprehension then eval_comprehension(node)
            when :bind then with({node[1] => evaluate(node[2])}) { evaluate(node[3]) }
            else raise EvaluationError, "unknown node #{node.first}"
            end
          end

          private

          def normalize_variables(variables)
            variables.each_with_object({}) { |(key, value), hash| hash[key.to_s] = value }
          end

          def eval_select(node)
            _, target_node, field, optional = node
            if target_node.first == :ident && !declared?(target_node[1])
              # Qualified identifiers like optional.none or a.b for a namespaced variable.
              qualified = "#{target_node[1]}.#{field}"
              return lookup(qualified) if declared?(qualified)
              return @library.namespace_value(qualified) if @library.namespace_value?(qualified)
            end
            target = evaluate(target_node)
            if target.is_a?(Values::Optional)
              return target unless target.present?

              target = target.value
              optional = true
            end
            case target
            when Hash
              if target.key?(field)
                value = target[field]
                optional ? Values::Optional.of(value) : value
              elsif !target.default.nil?
                # A map with a default value (DRA's device.attributes and
                # device.capacity): an unknown key finds the default.
                optional ? Values::Optional.of(target.default) : target.default
              elsif optional
                Values::Optional.none
              else
                raise EvaluationError, "no such key: #{field}"
              end
            else
              raise EvaluationError, "no such attribute: #{field} on #{Values.type_of(target)}"
            end
          end

          def eval_has(node)
            _, target_node, field = node
            target = eval(target_node)
            target = target.present? ? target.value : nil if target.is_a?(Values::Optional)
            raise EvaluationError, "has() applied to non-map #{Values.type_of(target)}" unless target.is_a?(Hash) || target.nil?

            target.is_a?(Hash) && target.key?(field)
          end

          def eval_index(node)
            _, target_node, index_node, optional = node
            target = eval(target_node)
            if target.is_a?(Values::Optional)
              return target unless target.present?

              target = target.value
              optional = true
            end
            index = eval(index_node)
            case target
            when Array
              raise TypeMismatch, "list index must be int" unless index.is_a?(Integer) || index.is_a?(Values::UInt)

              position = index.to_i
              if position.between?(0, target.length - 1)
                optional ? Values::Optional.of(target[position]) : target[position]
              elsif optional
                Values::Optional.none
              else
                raise EvaluationError, "index out of bounds: #{position}"
              end
            when Hash
              if target.key?(index)
                optional ? Values::Optional.of(target[index]) : target[index]
              elsif !target.default.nil?
                optional ? Values::Optional.of(target.default) : target.default
              elsif optional
                Values::Optional.none
              else
                # cel-go: fmt "%v" of the key -- a string unquoted.
                raise EvaluationError, "no such key: #{index}"
              end
            else
              raise TypeMismatch, "cannot index #{Values.type_of(target)}"
            end
          end

          def eval_unary(node)
            _, operator, operand_node = node
            operand = eval(operand_node)
            case operator
            when "!"
              raise TypeMismatch, "! requires a bool" unless [true, false].include?(operand)

              !operand
            when "-"
              case operand
              when Integer then Values.check_int!(-operand)
              when Float then -operand
              else raise TypeMismatch, "unary - requires int or double"
              end
            end
          end

          def eval_binary(node)
            _, operator, left_node, right_node = node
            case operator
            when "&&"
              left = safe(left_node)
              right = safe(right_node)
              return false if left == false || right == false
              raise left if left.is_a?(Exception)
              raise right if right.is_a?(Exception)
              raise TypeMismatch, "&& requires bools" unless left == true && right == true

              true
            when "||"
              left = safe(left_node)
              right = safe(right_node)
              return true if left == true || right == true
              raise left if left.is_a?(Exception)
              raise right if right.is_a?(Exception)
              raise TypeMismatch, "|| requires bools" unless left == false && right == false

              false
            else
              @library.binary(operator, eval(left_node), eval(right_node), self)
            end
          end

          def safe(node)
            eval(node)
          rescue EvaluationError => error
            error
          end

          def eval_call(node)
            _, function, target_node, argument_nodes = node
            if target_node.nil?
              arguments = argument_nodes.map { |argument| eval(argument) }
              return @library.call(function, nil, arguments, self)
            end
            # Namespaced global functions (sets.contains, optional.of) look like
            # member calls on an undeclared identifier.
            if target_node.first == :ident && !declared?(target_node[1]) && @library.global_function?("#{target_node[1]}.#{function}")
              arguments = argument_nodes.map { |argument| eval(argument) }
              return @library.call("#{target_node[1]}.#{function}", nil, arguments, self)
            end
            target = eval(target_node)
            arguments = argument_nodes.map { |argument| eval(argument) }
            @library.call(function, target, arguments, self, has_target: true)
          end

          def eval_comprehension(node)
            _, iter_var, range_node, accu_var, init_node, condition_node, step_node, result_node = node
            range = eval(range_node)
            items = case range
                    when Array then range
                    when Hash then range.keys
                    else raise TypeMismatch, "comprehension range must be a list or map"
                    end
            accumulator = eval(init_node)
            items.each do |item|
              charge(2)
              with(iter_var => item, accu_var => accumulator) do
                condition = eval(condition_node)
                break unless condition == true

                accumulator = eval(step_node)
              end
            end
            with(accu_var => accumulator) { eval(result_node) }
          end
        end
      end
    end
  end
end
