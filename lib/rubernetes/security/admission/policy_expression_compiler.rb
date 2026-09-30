# frozen_string_literal: true

require_relative "policy_type_checker"
require_relative "../cel/check/constant_folding"

module Rubernetes
  module Security
    module Admission
      # plugin/cel Compiler.CompileCELExpression (v1.36.2) as
      # pkg/apis/admissionregistration/validation runs it when a policy or a
      # webhook configuration is created or updated: the expression compiled
      # in the base environment with object/oldObject/params as dyn,
      # request/namespaceObject typed, authorizer and params declared only
      # when the accessor has them, and -- for a policy with variables -- the
      # composition's kubernetes.variables; the result type must be one the
      # accessor allows.
      class PolicyExpressionCompiler
        C = CEL::Check
        BOOL = [C::BOOL].freeze
        STRING = [C::STRING].freeze
        STRING_OR_NULL = [C::STRING, C::NULL].freeze
        ANY = [C::ANY, C::DYN].freeze
        OBJECT = [C::Type.struct("Object")].freeze
        JSON_PATCHES = [C::Type.list(C::Type.struct("JSONPatch"))].freeze

        # mutation.DynamicTypeResolver: every field of Object and of
        # Object.<path> is dyn.
        class AnyFields
          def key?(_name) = true
          def [](_name) = C::DYN
        end

        # mutation.JSONPatchType's fields.
        JSON_PATCH_FIELDS = {"op" => C::STRING, "path" => C::STRING, "from" => C::STRING, "value" => C::DYN}.freeze
        # library.JSONPatch.
        ESCAPE_KEY = [C::Overload.new("string_jsonpatch_escapeKey_string", false, [C::STRING], C::STRING, [])].freeze

        # A composition compiler (createCompiler(true)) keeps the variables it
        # compiled; a stateless one (no variables) declares none.
        def initialize(composition: false)
          @composition = composition
          @variables = composition ? {} : nil
        end

        # [:invalid or :internal, detail] (field.Invalid / field.InternalError),
        # or nil when the expression compiles to an allowed type and its
        # program can be planned.
        def compile(expression, return_types:, has_params:, has_authorizer:, patch_types: false)
          output, issues, root = compile_with_issues(expression, has_params: has_params, has_authorizer: has_authorizer,
                                                                 patch_types: patch_types)
          @last_output = nil
          return [:invalid, "compilation failed: #{issues}"] unless issues.empty?

          unless return_types.any? { |type| output.exact?(type) || C::ANY.exact?(type) }
            detail = if return_types.length == 1
                       "must evaluate to #{type_string(return_types[0])} but got #{type_string(output)}"
                     else
                       "must evaluate to one of [#{return_types.map { |type| type_string(type) }.join(" ")}] but got #{type_string(output)}"
                     end
            return [:invalid, detail]
          end
          folding = C::ConstantFolding.error(root, type_idents, conversion_overloads)
          return [:internal, "program instantiation failed: #{folding}"] if folding

          @last_output = output
          nil
        end

        # CompileAndStoreVariable: the variable's type joins
        # kubernetes.variables (dyn when it does not compile or plan).
        def compile_variable(name, expression, has_params:)
          result = compile(expression, return_types: ANY, has_params: has_params, has_authorizer: true)
          @variables[name] = PolicyTypeChecker.variable_type(@last_output) if @variables
          result
        end

        # The argument types each conversion's overloads take.
        def conversion_overloads
          @conversion_overloads ||= C::ConstantFolding::CONVERSIONS.to_h do |name|
            accepted = Array(PolicyTypeChecker::Declarations.environment.function(name)).filter_map do |overload|
              next if overload.member || overload.args.length != 1

              arg = overload.args[0]
              arg.kind == :type_param || arg.dyn? ? :any : arg.name
            end
            [name, accepted]
          end
        end

        # Identifiers the planner resolves to constant type values.
        def type_idents
          @type_idents ||= PolicyTypeChecker::Declarations.environment.ident_names.select do |name|
            PolicyTypeChecker::Declarations.environment.ident(name).kind == :type
          end.to_set
        end

        private

        # *cel.Type.String().
        def type_string(type)
          return "<#{type.name}>" if type.kind == :type_param
          return type.declared_name if type.params.empty?

          "#{type.declared_name}(#{type.params.map { |param| type_string(param) }.join(", ")})"
        end

        def compile_with_issues(expression, has_params:, has_authorizer:, patch_types: false)
          PolicyTypeChecker.compile(environment(has_params: has_params, has_authorizer: has_authorizer, patch_types: patch_types),
                                    expression)
        end

        # createEnvForOpts: object/oldObject dyn, params dyn with a
        # paramKind, authorizer and resourceAuthorizer with an authorizer,
        # the patch types (HasPatchTypes) for a mutation.  The request
        # resource check is the qualified identifier authorizer.requestResource.
        def environment(has_params:, has_authorizer:, patch_types: false)
          base = PolicyTypeChecker::Declarations.environment
          idents = {"object" => C::DYN, "oldObject" => C::DYN}
          idents["params"] = C::DYN if has_params
          idents["authorizer.requestResource"] = C::Type.struct("kubernetes.authorization.ResourceCheck") if has_authorizer
          structs = {}
          if @variables
            idents["variables"] = C::Type.struct("kubernetes.variables")
            structs["kubernetes.variables"] = @variables.dup
          end
          env = base.with(idents: idents, structs: structs)
          env = env.without_ident("authorizer").without_ident("authorizer.requestResource") unless has_authorizer
          env = env.without_ident("variables") unless @variables
          env = env.with_patch_types(AnyFields.new, JSON_PATCH_FIELDS, "jsonpatch.escapeKey" => ESCAPE_KEY) if patch_types
          env
        end
      end
    end
  end
end
