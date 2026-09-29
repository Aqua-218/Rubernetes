# frozen_string_literal: true

module Rubernetes
  module Security
    module CEL
      # Static CEL type checking, a port of github.com/google/cel-go's parser
      # AST (ids, locations, macro expansions), checker, AST validators and
      # issue formatting (cel-go as vendored by Kubernetes v1.36.2).  The
      # evaluator keeps its own parser; this package exists so type-checking
      # warnings (ValidatingAdmissionPolicy status.typeChecking) read exactly
      # as upstream's.
      module Check
        # common/types.Type: kind, runtime type name, parameters, and whether
        # null is assignable (a wrapper type).
        class Type
          attr_reader :kind, :name, :params

          def initialize(kind, name, params = [], nullable: false)
            @kind = kind
            @name = name
            @params = params.freeze
            @nullable = nullable
            freeze
          end

          def nullable? = @nullable

          def self.primitive(kind, name) = new(kind, name)
          def self.list(elem) = new(:list, "list", [elem])
          def self.map(key, value) = new(:map, "map", [key, value])
          def self.type_param(name) = new(:type_param, name)
          def self.opaque(name, *params) = new(:opaque, name, params)
          def self.struct(name) = new(:struct, name)
          def self.optional(elem) = opaque("optional_type", elem)
          def self.type_type(param = nil) = new(:type, "type", param ? [param] : [])
          def self.function(result, *args) = opaque("function", result, *args)

          def dyn_like? = %i[dyn any type_param].include?(kind)
          def dyn? = kind == :dyn
          def error? = kind == :error
          def dyn_or_error? = dyn? || error?

          # DeclaredTypeName.
          def declared_name
            return "wrapper(#{name})" if kind != :null && !dyn_like? && assignable_from?(NULL)

            name
          end

          # isTypeInternal.
          def same?(other, check_param_name)
            return true if equal?(other)
            return false unless other && kind == other.kind && params.length == other.params.length
            return false if (check_param_name || kind != :type_param) && name != other.name

            params.each_with_index.all? { |param, index| param.same?(other.params[index], check_param_name) }
          end

          def exact?(other) = same?(other, true)
          def equivalent?(other) = same?(other, false)

          # IsAssignableType (a nullable type also accepts null).
          def assignable_from?(from)
            return NULL.assignable_from?(from) || without_nullable.assignable_from?(from) if nullable?
            return true if equal?(from) || dyn_like?
            return false if kind != from.kind || name != from.name || params.length != from.params.length

            params.each_with_index.all? { |param, index| param.assignable_from?(from.params[index]) }
          end

          def without_nullable = Type.new(kind, name, params)

          # FormatCELType.
          def to_s
            case kind
            when :any then "any"
            when :duration then "duration"
            when :error then "!error!"
            when :null then "null"
            when :timestamp then "timestamp"
            when :type_param then name
            when :unspecified then ""
            else
              if kind == :opaque && name == "function"
                return Check.format_function(params[0], params[1..], false)
              end
              return declared_name if params.empty?

              "#{name}(#{params.map(&:to_s).join(", ")})"
            end
          end

          def inspect = "#<CEL::Check::Type #{self}>"
        end

        DYN = Type.primitive(:dyn, "dyn")
        ANY = Type.primitive(:any, "google.protobuf.Any")
        BOOL = Type.primitive(:bool, "bool")
        BYTES = Type.primitive(:bytes, "bytes")
        DOUBLE = Type.primitive(:double, "double")
        DURATION = Type.primitive(:duration, "google.protobuf.Duration")
        ERROR = Type.primitive(:error, "*error*")
        INT = Type.primitive(:int, "int")
        NULL = Type.primitive(:null, "null_type")
        STRING = Type.primitive(:string, "string")
        TIMESTAMP = Type.primitive(:timestamp, "google.protobuf.Timestamp")
        UINT = Type.primitive(:uint, "uint")
        TYPE = Type.type_type

        KINDS = {"dyn" => :dyn, "any" => :any, "bool" => :bool, "bytes" => :bytes, "double" => :double, "duration" => :duration,
                 "error" => :error, "int" => :int, "list" => :list, "map" => :map, "null" => :null, "opaque" => :opaque,
                 "string" => :string, "struct" => :struct, "timestamp" => :timestamp, "type" => :type,
                 "type_param" => :type_param, "uint" => :uint, "unspecified" => :unspecified}.freeze

        module_function

        # A type as tools/schema/import_cel_declarations.rb serialized it.
        def type_from_json(json)
          return nil if json.nil? || json["kind"] == "nil"

          kind = KINDS.fetch(json["kind"])
          params = Array(json["params"]).map { |param| type_from_json(param) }
          Type.new(kind, json["name"].to_s, params, nullable: json["nullable"] == true)
        end

        # formatFunctionDeclType.
        def format_function(result, args, instance)
          out = +""
          if instance
            out << args.first.to_s << "."
            args = args[1..]
          end
          out << "(" << args.map(&:to_s).join(", ") << ")"
          rendered = result.to_s
          out << " -> " << rendered unless rendered.empty?
          out
        end

        # checker/mapping.go: type parameter substitutions keyed by the
        # formatted type.
        class Mapping
          def initialize(entries = {})
            @entries = entries
          end

          def add(from, to) = @entries[from.to_s] = to
          def find(from) = @entries[from.to_s]
          def copy = Mapping.new(@entries.dup)
        end

        # checker/types.go.
        module Types
          module_function

          def optional?(type) = type.kind == :opaque && type.name == "optional_type"

          def unwrap_optional(type)
            optional?(type) ? [type.params[0], true] : [type, false]
          end

          def equal_or_less_specific?(t1, t2)
            return true if t1.dyn? || t1.kind == :type_param
            return false if t2.dyn? || t2.kind == :type_param
            return false if t1.kind != t2.kind

            case t1.kind
            when :opaque
              return false if t1.name != t2.name || t1.params.length != t2.params.length

              t1.params.each_with_index.all? { |param, index| equal_or_less_specific?(param, t2.params[index]) }
            when :list then equal_or_less_specific?(t1.params[0], t2.params[0])
            when :map then equal_or_less_specific?(t1.params[0], t2.params[0]) && equal_or_less_specific?(t1.params[1], t2.params[1])
            when :type then true
            else t1.exact?(t2)
            end
          end

          def internal_assignable?(m, t1, t2)
            if t2.kind == :type_param
              valid, has_sub = valid_substitution?(m, t1, t2)
              return true if valid
              return false if has_sub
            end
            return valid_substitution?(m, t2, t1).first if t1.kind == :type_param
            return true if t1.dyn_or_error? || t2.dyn_or_error?
            return assignable_null?(t2) if t1.kind == :null
            return assignable_null?(t1) if t2.kind == :null

            case t1.kind
            when :bool, :bytes, :double, :int, :string, :uint, :any, :duration, :timestamp, :struct
              t2.assignable_from?(t1)
            when :type then t2.kind == :type
            when :opaque, :list, :map
              t1.kind == t2.kind && t1.name == t2.name && internal_assignable_list?(m, t1.params, t2.params)
            else false
            end
          end

          def valid_substitution?(m, t1, t2)
            return [true, true] if t1.kind == t2.kind && t1.exact?(t2)

            if (t2_sub = m.find(t2))
              return [true, true] if t1.kind == t2_sub.kind && t1.exact?(t2_sub)

              if internal_assignable?(m, t1, t2_sub)
                t2_new = most_general(t1, t2_sub)
                m.add(t2, t2_new) if not_referenced_in?(m, t2, t2_new)
                return [true, true]
              end
              return [false, true]
            end
            if not_referenced_in?(m, t2, t1)
              m.add(t2, t1)
              return [true, false]
            end
            [false, false]
          end

          def internal_assignable_list?(m, l1, l2)
            return false if l1.length != l2.length

            l1.each_with_index.all? { |t1, index| internal_assignable?(m, t1, l2[index]) }
          end

          def assignable_null?(type)
            %i[opaque struct any duration timestamp].include?(type.kind) || type.assignable_from?(NULL)
          end

          def assignable(m, t1, t2)
            copy = m.copy
            internal_assignable?(copy, t1, t2) ? copy : nil
          end

          def assignable_list(m, l1, l2)
            copy = m.copy
            internal_assignable_list?(copy, l1, l2) ? copy : nil
          end

          def most_general(t1, t2) = equal_or_less_specific?(t1, t2) ? t1 : t2

          def not_referenced_in?(m, type, within)
            return false if type.exact?(within)

            case within.kind
            when :type_param
              sub = m.find(within)
              sub.nil? || not_referenced_in?(m, type, sub)
            when :opaque, :list, :map, :type
              within.params.all? { |param| not_referenced_in?(m, type, param) }
            else true
            end
          end

          def substitute(m, type, type_param_to_dyn)
            if (sub = m.find(type))
              return substitute(m, sub, type_param_to_dyn)
            end
            return DYN if type_param_to_dyn && type.kind == :type_param

            case type.kind
            when :opaque then Type.opaque(type.name, *type.params.map { |param| substitute(m, param, type_param_to_dyn) })
            when :list then Type.list(substitute(m, type.params[0], type_param_to_dyn))
            when :map then Type.map(substitute(m, type.params[0], type_param_to_dyn), substitute(m, type.params[1], type_param_to_dyn))
            when :type
              type.params.empty? ? type : Type.type_type(substitute(m, type.params[0], type_param_to_dyn))
            else type
            end
          end
        end
      end
    end
  end
end
