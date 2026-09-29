# frozen_string_literal: true

require_relative "parser"
require_relative "values"

module Rubernetes
  module Security
    module CEL
      # Static result-type inference for a CEL expression, as far as the
      # untyped variable environment of admission match conditions allows:
      # literals, operators and the standard functions have known result
      # types, variables and selections are +:dyn+.  This is what the
      # apiserver's compile step checks when it requires a bool result
      # ("must evaluate to bool"): a +:dyn+ result is accepted, any other
      # non-bool type is rejected.
      module Types
        BOOL_FUNCTIONS = %w[contains startsWith endsWith matches exists exists_one all has isSorted isURL isIP isCIDR isQuantity
                            isSemver isFormat containsIP containsCIDR isSubnet].freeze
        INT_FUNCTIONS = %w[size int indexOf lastIndexOf getSeconds getHours getMinutes getMilliseconds getDayOfMonth getDayOfWeek
                           getDayOfYear getFullYear getMonth toInt].freeze
        STRING_FUNCTIONS = %w[string lowerAscii upperAscii trim replace substring join format quote reverse charAt strings.quote].freeze
        LIST_FUNCTIONS = %w[map filter split sum min max flatten slice sort sets.intersects].freeze

        module_function

        def result_type(source)
          infer(Parser.new(source).parse)
        end

        def bool_or_dyn?(source)
          %i[bool dyn].include?(result_type(source))
        end

        def infer(node)
          return :dyn unless node.is_a?(Array)

          case node.first
          when :literal then literal_type(node[1])
          when :binary
            operator = node[1]
            left = infer(node[2])
            right = infer(node[3])
            case operator
            when "==", "!=", "<", "<=", ">", ">=", "in", "||", "&&" then :bool
            when "+"
              return :string if left == :string && right == :string
              return :list if left == :list && right == :list

              numeric(left, right)
            else numeric(left, right)
            end
          when :unary then node[1] == "!" ? :bool : infer(node[2])
          when :conditional
            consequent = infer(node[2])
            alternative = infer(node[3])
            consequent == alternative ? consequent : :dyn
          when :has then :bool
          when :bind then infer(node[3])
          when :list then :list
          when :map, :struct then :map
          when :call
            name = node[1].to_s
            return :bool if BOOL_FUNCTIONS.include?(name)
            return :int if INT_FUNCTIONS.include?(name)
            return :string if STRING_FUNCTIONS.include?(name)
            return :list if LIST_FUNCTIONS.include?(name)
            return :double if name == "double"
            return :uint if name == "uint"
            return :bool if name == "bool"

            :dyn
          else :dyn
          end
        end

        def literal_type(value)
          case value
          when true, false then :bool
          when nil then :null
          when Integer then :int
          when Float then :double
          when String then :string
          else
            return :uint if defined?(Values::UInt) && value.is_a?(Values::UInt)
            return :bytes if defined?(Values::Bytes) && value.is_a?(Values::Bytes)

            :dyn
          end
        end

        def numeric(left, right)
          return left if left == right && %i[int uint double].include?(left)
          return :dyn if left == :dyn || right == :dyn

          :dyn
        end
      end
    end
  end
end
