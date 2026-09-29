# frozen_string_literal: true

require_relative "types"
require_relative "ast"

module Rubernetes
  module Security
    module CEL
      module Check
        Overload = Struct.new(:id, :member, :args, :result, :type_params)

        # The declarations a check runs against (checker/env.go): functions
        # with their overloads in declaration order, identifiers (variables,
        # type names), and the struct types with their fields (nil: a known
        # type without selectable fields).
        class Environment
          attr_reader :functions, :macros

          def initialize(functions:, idents:, structs:, macros:, object_fields: nil, json_patch_fields: nil)
            @functions = functions
            @idents = idents
            @structs = structs
            @macros = macros
            @object_fields = object_fields
            @json_patch_fields = json_patch_fields
          end

          # common.ResolverTypeProvider over mutation.DynamicTypeResolver:
          # "Object" and "Object.<path>" (every field dyn) and "JSONPatch".
          def with_patch_types(object_fields, json_patch_fields, functions)
            Environment.new(functions: @functions.merge(functions), idents: @idents, structs: @structs, macros: @macros,
                            object_fields: object_fields, json_patch_fields: json_patch_fields)
          end

          def dynamic_struct(name)
            return nil unless @object_fields
            return @json_patch_fields if name == "JSONPatch"

            @object_fields if name == "Object" || name.start_with?("Object.")
          end

          def with(idents: {}, structs: {})
            Environment.new(functions: @functions, idents: @idents.merge(idents), structs: @structs.merge(structs), macros: @macros,
                            object_fields: @object_fields, json_patch_fields: @json_patch_fields)
          end

          def without_ident(name)
            Environment.new(functions: @functions, idents: @idents.except(name), structs: @structs, macros: @macros,
                            object_fields: @object_fields, json_patch_fields: @json_patch_fields)
          end

          def ident(name) = @idents[name]
          def ident_names = @idents.keys
          def struct?(name) = !dynamic_struct(name).nil? || @structs.key?(name)
          def struct_fields(name) = dynamic_struct(name) || @structs[name]
          def function(name) = @functions[name]
        end

        # One reported issue: message and source offset (common.Error).
        Issue = Struct.new(:offset, :message)

        # common.Errors: issues sorted (stably) by location and rendered with
        # the source line and a caret.
        class Issues
          MAX_ERRORS = 100

          attr_reader :list

          def initialize(source)
            @source = source
            @list = []
            @count = 0
          end

          def report(offset, message)
            @count += 1
            @list << Issue.new(offset, message) if @count <= MAX_ERRORS
          end

          def empty? = @list.empty?

          def to_s
            sorted = @list.each_with_index.sort_by { |issue, index| [*@source.location(issue.offset), index] }.map(&:first)
            rendered = sorted.map { |issue| display(issue) }
            rendered << "#{@count - MAX_ERRORS} more errors were truncated" if @count > MAX_ERRORS
            rendered.join("\n")
          end

          def display(issue)
            line, column = @source.location(issue.offset)
            out = +"ERROR: <input>:#{line}:#{column + 1}: #{issue.message}"
            snippet = @source.snippet(line)
            return out if snippet.nil? || snippet.bytesize > 16_384

            snippet = snippet.tr("\t", " ")
            out << "\n | " << snippet << "\n | "
            chars = snippet.chars
            column.times do |index|
              break if index >= chars.length

              out << (chars[index].bytesize > 1 ? "．" : ".")
            end
            out << (chars[column] && chars[column].bytesize > 1 ? "＾" : "^")
            out
          end
        end

        # checker/checker.go.
        class Checker
          RESERVED = %w[true false null in as break const continue else for function if import let loop package namespace return
                        var void while].freeze

          attr_reader :types, :references

          def initialize(env)
            @env = env
            @references = {}.compare_by_identity
            @scopes = []
            @types = {}.compare_by_identity
            @mappings = Mapping.new
            @free_type_vars = 0
          end

          def check(root, issues)
            @issues = issues
            visit(root)
            @types.each_key { |node| @types[node] = Types.substitute(@mappings, @types[node], true) }
            @types
          end

          private

          def visit(node)
            return if node.nil?

            case node.kind
            when :literal then set_type(node, literal_type(node.value))
            when :ident then check_ident(node)
            when :select then check_select(node)
            when :call then check_call(node)
            when :list then check_list(node)
            when :map then check_map(node)
            when :struct then check_struct(node)
            when :comprehension then check_comprehension(node)
            end
          end

          def literal_type(value)
            case value
            when true, false then BOOL
            when Integer then INT
            when Float then DOUBLE
            when String then STRING
            when nil then NULL
            when Values::UInt then UINT
            when Values::Bytes then BYTES
            else DYN
            end
          end

          def error(node_or_offset, message)
            @issues.report(node_or_offset.is_a?(Integer) ? node_or_offset : node_or_offset.offset, message)
          end

          def container_name = ""

          # Env.LookupIdent: the innermost scope first, then the environment's
          # variables, struct types and type identifiers.
          def lookup_ident(name)
            name = name.delete_prefix(".")
            @scopes.reverse_each { |scope| return scope[name] if scope.key?(name) }
            @env.ident(name) || (@env.struct?(name) ? Type.type_type(Type.struct(name)) : nil)
          end

          def check_ident(node)
            if (type = lookup_ident(node.name))
              set_type(node, type)
              return
            end
            set_type(node, ERROR)
            error(node, "undeclared reference to '#{node.name}' (in container '#{container_name}')")
          end

          # containers.ToQualifiedName.
          def qualified_name(node)
            case node.kind
            when :ident then node.name
            when :select
              return nil if node.test_only

              parent = qualified_name(node.operand)
              parent && "#{parent}.#{node.name}"
            end
          end

          def check_select(node)
            if (name = qualified_name(node)) && (type = lookup_ident(name))
              set_type(node, type)
              return
            end
            result = check_select_field(node, node.operand, node.name, false)
            result = BOOL if node.test_only
            set_type(node, Types.substitute(@mappings, result, false))
          end

          def check_opt_select(node)
            operand, field = node.args
            unless field.kind == :literal && field.value.is_a?(String)
              error(field, "unsupported optional field selection: #{field}")
              return
            end
            result = check_select_field(node, operand, field.value, true)
            set_type(node, Types.substitute(@mappings, result, false))
          end

          def check_select_field(node, operand, field, optional)
            visit(operand)
            operand_type = Types.substitute(@mappings, type_of(operand), false)
            target, is_optional = Types.unwrap_optional(operand_type)
            result = case target.kind
                     when :map then target.params[1]
                     when :struct then lookup_field_type(node, target.name, field) || ERROR
                     when :type_param
                       assignable?(DYN, target)
                       DYN
                     else
                       error(node, "type '#{target}' does not support field selection") unless target.dyn_or_error?
                       DYN
                     end
            is_optional || optional ? Type.optional(result) : result
          end

          def lookup_field_type(node, struct_name, field)
            unless @env.struct?(struct_name)
              error(node, "unexpected failed resolution of '#{struct_name}'")
              return nil
            end
            fields = @env.struct_fields(struct_name)
            return fields[field] if fields&.key?(field)
            # DeclTypeProvider with RecognizeKeywordAsFieldName: a reserved
            # word is looked up in its escaped form.
            return fields["__#{field}__"] if fields && RESERVED.include?(field) && fields.key?("__#{field}__")

            error(node, "undefined field '#{field}'")
            nil
          end

          def check_call(node)
            if node.name == "_?._"
              check_opt_select(node)
              return
            end
            node.args.each { |arg| visit(arg) }
            unless node.member?
              function = @env.function(node.name.delete_prefix("."))
              if function.nil?
                error(node, "undeclared reference to '#{node.name}' (in container '#{container_name}')")
                set_type(node, ERROR)
                return
              end
              resolve_overload_or_error(node, node.name, function, nil)
              return
            end
            if (prefix = qualified_name(node.target)) && (function = @env.function("#{prefix}.#{node.name}"))
              resolve_overload_or_error(node, "#{prefix}.#{node.name}", function, nil)
              return
            end
            visit(node.target)
            if (function = @env.function(node.name))
              resolve_overload_or_error(node, node.name, function, node.target)
              return
            end
            set_type(node, ERROR)
            error(node, "undeclared reference to '#{node.name}' (in container '#{container_name}')")
          end

          def resolve_overload_or_error(node, name, overloads, target)
            result = resolve_overload(node, name, overloads, target)
            set_type(node, result || ERROR)
          end

          def resolve_overload(node, name, overloads, target)
            reference = nil
            arg_types = []
            arg_types << type_of(target) if target
            node.args.each { |arg| arg_types << type_of(arg) }
            result = nil
            overloads.each do |overload|
              next if target.nil? == overload.member

              if %w[_&&_ _||_].include?(name)
                reference = [overload.id]
                failed = false
                arg_types.each_with_index do |arg_type, index|
                  next if assignable?(arg_type, BOOL)

                  error(node.args[index], "expected type '#{BOOL}' but found '#{arg_type}'")
                  failed = true
                end
                return nil if failed

                @references[node] = reference
                return BOOL
              end
              overload_type = Type.function(overload.result, *overload.args)
              unless overload.type_params.empty?
                substitutions = Mapping.new
                overload.type_params.each { |param| substitutions.add(Type.type_param(param), new_type_var) }
                overload_type = Types.substitute(substitutions, overload_type, false)
              end
              next unless assignable_list?(arg_types, overload_type.params[1..])

              (reference ||= []) << overload.id
              fn_result = Types.substitute(@mappings, overload_type.params[0], false)
              if result.nil?
                result = fn_result
              elsif !result.dyn? && !fn_result.exact?(result)
                result = DYN
              end
            end
            if result
              @references[node] = reference
              return result
            end

            substituted = arg_types.map { |type| Types.substitute(@mappings, type, true) }
            error(node, "found no matching overload for '#{name}' applied to '#{Check.format_function(nil, substituted, !target.nil?)}'")
            nil
          end

          def check_list(node)
            elems_type = nil
            node.elements.each_with_index do |element, index|
              visit(element)
              elem_type = type_of(element)
              if node.optional_indices.include?(index)
                elem_type, is_optional = Types.unwrap_optional(elem_type)
                error(element, "expected type '#{Type.optional(elem_type)}' but found '#{elem_type}'") if !is_optional && !elem_type.dyn?
              end
              elems_type = join_types(element, elems_type, elem_type)
            end
            set_type(node, Type.list(elems_type || new_type_var))
          end

          def check_map(node)
            key_type = nil
            value_type = nil
            node.entries.each do |entry|
              visit(entry.key)
              key_type = join_types(entry.key, key_type, type_of(entry.key))
              visit(entry.value)
              value = type_of(entry.value)
              if entry.optional
                value, is_optional = Types.unwrap_optional(value)
                error(entry.value, "expected type '#{Type.optional(value)}' but found '#{value}'") if !is_optional && !value.dyn?
              end
              value_type = join_types(entry.value, value_type, value)
            end
            if key_type.nil?
              key_type = new_type_var
              value_type = new_type_var
            end
            set_type(node, Type.map(key_type, value_type))
          end

          def check_struct(node)
            ident = lookup_ident(node.name)
            if ident.nil?
              error(node, "undeclared reference to '#{node.name}' (in container '#{container_name}')")
              set_type(node, ERROR)
              return
            end
            result = ERROR
            type_name = node.name.delete_prefix(".")
            if ident.kind != :error
              if ident.kind != :type
                error(node, "'#{ident.declared_name}' is not a type")
              else
                result = ident.params[0]
                if result.kind == :struct
                  type_name = result.name
                else
                  error(node, "'#{result.declared_name}' is not a message type")
                  result = ERROR
                end
              end
            end
            set_type(node, result)
            node.fields.each do |field|
              visit(field.value)
              field_type = lookup_field_type(field.offset, type_name, field.key) || ERROR
              value_type = type_of(field.value)
              if field.optional
                value_type, is_optional = Types.unwrap_optional(value_type)
                error(field.value, "expected type '#{Type.optional(value_type)}' but found '#{value_type}'") if !is_optional && !value_type.dyn?
              end
              next if assignable?(field_type, value_type)

              error(field.offset, "expected type of field '#{field.key}' is '#{field_type}' but provided type is '#{value_type}'")
            end
          end

          def check_comprehension(node)
            visit(node.iter_range)
            visit(node.accu_init)
            range_type = Types.substitute(@mappings, type_of(node.iter_range), false)
            accu_type = type_of(node.accu_init)
            @scopes.push({node.accu_var => accu_type})
            var_type, var2_type = case range_type.kind
                                  when :list then node.iter_var2 ? [INT, range_type.params[0]] : [range_type.params[0], nil]
                                  when :map then [range_type.params[0], node.iter_var2 && range_type.params[1]]
                                  when :dyn, :error, :type_param
                                    assignable?(DYN, range_type)
                                    [DYN, node.iter_var2 && DYN]
                                  else
                                    error(node.iter_range, "expression of type '#{range_type}' cannot be range of a comprehension (must be list, map, or dynamic)")
                                    [ERROR, node.iter_var2 && ERROR]
                                  end
            scope = {node.iter_var => var_type}
            scope[node.iter_var2] = var2_type if node.iter_var2
            @scopes.push(scope)
            visit(node.loop_condition)
            assert_type(node.loop_condition, BOOL)
            visit(node.loop_step)
            assert_type(node.loop_step, accu_type)
            @scopes.pop
            visit(node.result)
            @scopes.pop
            set_type(node, Types.substitute(@mappings, type_of(node.result), false))
          end

          # joinTypes with dyn aggregate literal element types (cel-go's
          # default): mixed elements make the literal dyn; the homogeneous
          # literal validator reports them afterwards.
          def join_types(_node, previous, current)
            return current if previous.nil?
            return Types.most_general(previous, current) if assignable?(previous, current)

            DYN
          end

          def new_type_var
            name = "_var#{@free_type_vars}"
            @free_type_vars += 1
            Type.type_param(name)
          end

          def assignable?(t1, t2)
            mapping = Types.assignable(@mappings, t1, t2)
            return false unless mapping

            @mappings = mapping
            true
          end

          def assignable_list?(l1, l2)
            mapping = Types.assignable_list(@mappings, l1, l2)
            return false unless mapping

            @mappings = mapping
            true
          end

          def set_type(node, type)
            if (old = @types[node]) && !old.exact?(type)
              error(node, "incompatible type already exists for expression: old:#{old}, new:#{type}")
              return
            end
            @types[node] = type
          end

          def type_of(node) = @types[node]

          def assert_type(node, type)
            return if assignable?(type, type_of(node))

            error(node, "expected type '#{type}' but found '#{type_of(node)}'")
          end
        end
      end
    end
  end
end
