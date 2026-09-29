# frozen_string_literal: true

require "thread"

require_relative "../security/cel"

module Rubernetes
  module DRA
    # k8s.io/dynamic-resource-allocation/cel (v1.36.2): device selector
    # expressions over
    #
    #   device.driver                     string
    #   device.allowMultipleAllocations   bool (with DRAConsumableCapacity)
    #   device.attributes[domain][id]     int / bool / string / semver
    #   device.capacity[domain][id]       quantity
    #
    # on the Kubernetes CEL libraries (quantity, semver, ...) plus ext.Bindings
    # (cel.bind).  Attribute and capacity names without a domain belong to
    # the device's driver; an unknown domain finds an empty map, so
    # device.attributes["other.example.com"].x is "no such key", not a
    # missing-domain error.  An expression must be bool or of unknown type;
    # that and the device fields are checked when it is compiled, as the
    # typed upstream environment does.
    class CEL
      SecurityCEL = Security::CEL
      # resourceapi.CELSelectorExpressionMaxCost.
      MAX_COST = 1_000_000

      class Error < StandardError; end

      Result = Data.define(:expression, :program, :error, :output_type) do
        def error? = !error.nil?
      end

      DEVICE_FIELDS = {"driver" => :string, "attributes" => :attributes, "capacity" => :capacity}.freeze

      def initialize(consumable_capacity: true, max_entries: 10)
        @consumable_capacity = consumable_capacity
        @evaluator = SecurityCEL::Evaluator.new(cost_limit: MAX_COST)
        @cache = {}
        @order = []
        @max_entries = max_entries
        @mutex = Mutex.new
      end

      # Cache.GetOrCompile: successful compilations are kept (LRU).
      def get_or_compile(expression)
        @mutex.synchronize do
          if (cached = @cache[expression])
            @order.delete(expression)
            @order << expression
            return cached
          end
        end
        result = compile(expression)
        return result if result.error?

        @mutex.synchronize do
          @cache[expression] = result
          @order << expression
          @cache.delete(@order.shift) while @order.length > @max_entries
        end
        result
      end

      def compile(expression)
        program = @evaluator.compile(expression)
        type = infer(program.ast, {})
        unless %i[bool dyn].include?(type)
          return failure(expression, "compilation failed: ERROR: <input>:1:1: must evaluate to bool or the unknown type, " \
                                     "not #{type_name(type)}")
        end

        Result.new(expression: expression, program: program, error: nil, output_type: type)
      rescue SecurityCEL::SyntaxError => error
        failure(expression, "compilation failed: ERROR: <input>:1:1: Syntax error: #{error.message}")
      rescue CompileError => error
        failure(expression, "compilation failed: ERROR: <input>:1:1: #{error.message}")
      end

      # CompilationResult.DeviceMatches: true/false, or raises Error with the
      # runtime error.
      def device_matches(result, driver:, attributes: {}, capacity: {}, allow_multiple_allocations: nil)
        variables = {"device" => device_value(driver, attributes, capacity, allow_multiple_allocations)}
        value = @evaluator.run(result.program, variables)
        unless value == true || value == false
          raise Error, "CEL result of type #{SecurityCEL::Values.type_of(value)} could not be converted to bool: " \
                       "unsupported type conversion from '#{SecurityCEL::Values.type_of(value)}' to bool"
        end

        value
      rescue SecurityCEL::EvaluationError, SecurityCEL::TypeMismatch => error
        raise Error, error.message
      end

      private

      class CompileError < StandardError; end

      def failure(expression, message)
        Result.new(expression: expression, program: nil, error: message, output_type: nil)
      end

      def device_value(driver, attributes, capacity, allow_multiple_allocations)
        attribute_map = Hash.new({}.freeze)
        (attributes || {}).each do |name, attribute|
          domain, id = qualified_name(name.to_s, driver)
          (attribute_map[domain] = attribute_map.fetch(domain, {}).dup)[id] = attribute_value(name, attribute)
        end
        capacity_map = Hash.new({}.freeze)
        (capacity || {}).each do |name, entry|
          domain, id = qualified_name(name.to_s, driver)
          value = entry.is_a?(Hash) ? entry["value"] : entry
          (capacity_map[domain] = capacity_map.fetch(domain, {}).dup)[id] = SecurityCEL::Library::Quantity.new(value.to_s)
        end
        device = {"driver" => driver.to_s, "attributes" => attribute_map, "capacity" => capacity_map}
        device["allowMultipleAllocations"] = allow_multiple_allocations == true if @consumable_capacity
        device
      end

      # getAttributeValue.
      def attribute_value(name, attribute)
        attribute ||= {}
        return Integer(attribute["int"]) if attribute.key?("int")
        return attribute["bool"] == true if attribute.key?("bool")
        return attribute["string"].to_s if attribute.key?("string")
        if attribute.key?("version")
          begin
            return SecurityCEL::Library::SemVer.parse(attribute["version"].to_s)
          rescue SecurityCEL::EvaluationError => error
            raise Error, "attribute #{name}: parse semantic version: #{error.message}"
          end
        end
        raise Error, "attribute #{name}: unsupported attribute value"
      end

      # parseQualifiedName.
      def qualified_name(name, default_domain)
        index = name.index("/")
        index ? [name[0...index], name[(index + 1)..]] : [default_domain.to_s, name]
      end

      # --------------------------------------------------- compile checks

      # Result types over the typed device variable; everything the
      # untyped inference cannot know is :dyn.
      def infer(node, scope)
        return :dyn unless node.is_a?(Array)

        case node.first
        when :ident
          name = node[1]
          return scope[name] if scope.key?(name)
          return :device if name == "device"

          raise CompileError, "undeclared reference to '#{name}' (in container '')"
        when :select
          target = infer(node[1], scope)
          field = node[2]
          case target
          when :device
            type = device_field(field)
            raise CompileError, "undefined field '#{field}'" unless type

            type
          when :attributes then :attribute_domain
          when :capacity then :capacity_domain
          when :attribute_domain then :dyn
          when :capacity_domain then :quantity
          else :dyn
          end
        when :index
          target = infer(node[1], scope)
          infer(node[2], scope)
          case target
          when :attributes then :attribute_domain
          when :capacity then :capacity_domain
          when :attribute_domain then :dyn
          when :capacity_domain then :quantity
          else :dyn
          end
        when :has
          infer(node[1], scope)
          :bool
        when :bind
          bound = infer(node[2], scope)
          infer(node[3], scope.merge(node[1] => bound))
        when :comprehension
          _, iter_var, range, accu_var, init, condition, step, result = node
          infer(range, scope)
          inner = scope.merge(iter_var => :dyn, accu_var => :dyn)
          infer(init, scope)
          [condition, step].each { |child| infer(child, inner) }
          infer(result, scope.merge(accu_var => :dyn))
        when :call
          name = node[1].to_s
          target = node[2]
          infer(target, scope) if target
          Array(node[3]).each { |argument| infer(argument, scope) }
          return :int if %w[compareTo].include?(name)
          return :quantity if name == "quantity" || (%w[add sub].include?(name) && target && infer(target, scope) == :quantity)
          return :semver if name == "semver"

          SecurityCEL::Types.infer(node)
        when :binary
          infer(node[2], scope)
          infer(node[3], scope)
          SecurityCEL::Types.infer([:binary, node[1], typed_literal(node[2], scope), typed_literal(node[3], scope)])
        when :unary
          inner = infer(node[2], scope)
          node[1] == "!" ? :bool : inner
        when :conditional
          infer(node[1], scope)
          consequent = infer(node[2], scope)
          alternative = infer(node[3], scope)
          consequent == alternative ? consequent : :dyn
        when :list
          Array(node[1]).each { |item| infer(item, scope) }
          :list
        when :map, :struct
          :map
        else
          SecurityCEL::Types.infer(node)
        end
      end

      def device_field(field)
        return :bool if field == "allowMultipleAllocations" && @consumable_capacity

        DEVICE_FIELDS[field]
      end

      # Stand-in literals so the generic inference sees the operand types.
      def typed_literal(node, scope)
        case infer(node, scope)
        when :string then [:literal, ""]
        when :int then [:literal, 0]
        when :bool then [:literal, true]
        else node
        end
      end

      def type_name(type)
        {string: "string", int: "int", uint: "uint", double: "double", list: "list(dyn)", map: "map(dyn, dyn)",
         bytes: "bytes", null: "null_type", quantity: "kubernetes.Quantity", semver: "kubernetes.Semver",
         attributes: "map(string, map(string, any))", capacity: "map(string, map(string, kubernetes.Quantity))",
         attribute_domain: "map(string, any)", capacity_domain: "map(string, kubernetes.Quantity)",
         device: "kubernetes.DRADevice"}.fetch(type, type.to_s)
      end
    end
  end
end
