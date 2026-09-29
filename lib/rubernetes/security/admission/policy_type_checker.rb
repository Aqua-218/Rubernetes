# frozen_string_literal: true

require "json"
require "set"
require_relative "../cel/check/validators"

module Rubernetes
  module Security
    module Admission
      # ValidatingAdmissionPolicy type checking
      # (k8s.io/apiserver/pkg/admission/plugin/policy/validating/typechecking.go,
      # v1.36.2): each validation expression and messageExpression is compiled
      # against the schema of every kind the policy's resource rules match
      # (at most 10), with object/oldObject/params typed from OpenAPI, and the
      # CEL issues become status.typeChecking.expressionWarnings.
      class PolicyTypeChecker
        MAX_TYPES_TO_CHECK = 10
        DEFAULTS = File.expand_path("../../../../schema/kubernetes/v1.36.2-defaults", __dir__)
        C = CEL::Check
        CEL_RESERVED = %w[true false null in as break const continue else for function if import let loop package namespace return
                          var void while].freeze

        # The declarations corpus (tools/schema/import_cel_type_checking.rb).
        module Declarations
          module_function

          def document
            @document ||= JSON.parse(File.read(File.join(DEFAULTS, "cel_declarations.json")))
          end

          def environment
            @environment ||= begin
              # A declaration-disabled function (a deprecated alias) exists only
              # at runtime; the checker does not see it.
              functions = document.fetch("functions").reject { |function| function["disabled"] }.to_h do |function|
                overloads = function.fetch("overloads").map do |overload|
                  C::Overload.new(overload["id"], overload["member"] == true, Array(overload["args"]).map { |arg| C.type_from_json(arg) },
                                  C.type_from_json(overload["result"]), Array(overload["type_params"]))
                end
                [function["name"], overloads]
              end
              idents = document.fetch("variables").reject { |name, _| %w[object oldObject params variables].include?(name) }
                               .transform_values { |type| C.type_from_json(type) }
              document.fetch("type_idents").each { |name, type| idents[name] ||= C::Type.type_type(C.type_from_json(type)) }
              structs = document.fetch("structs").transform_values do |fields|
                fields.to_h { |field| [field["name"], C.type_from_json(field["type"])] }
              end
              macros = document.fetch("macros").map { |macro| [macro["function"], macro["args"], macro["receiver"]] }
              C::Environment.new(functions: functions, idents: idents, structs: structs, macros: macros)
            end
          end

          def validators = document.fetch("validators")

          def definitions
            @definitions ||= JSON.parse(File.read(File.join(DEFAULTS, "cel_type_definitions.json")))
          end

          # DefinitionsSchemaResolver's GVK -> definition name.
          def gvk_refs
            @gvk_refs ||= definitions.fetch("gvks").each_with_object({}) do |(name, gvks), out|
              gvks.each { |gvk| out[[gvk["group"], gvk["version"], gvk["kind"]]] = name }
            end
          end
        end

        # apiservercel.DeclType: an object (fields), list, map or simple type.
        DeclType = Struct.new(:kind, :name, :fields, :key, :elem, :cel) do
          def object? = kind == :object
          def list? = kind == :list
          def map? = kind == :map

          # CelType.
          def cel_type
            case kind
            when :object then C::Type.struct(name)
            when :list then C::Type.list(elem.cel_type)
            when :map then C::Type.map(key.cel_type, elem.cel_type)
            else cel
            end
          end

          # MaybeAssignTypeName.
          def assign_name(name)
            if object?
              updated = self.name == "object"
              name = self.name unless updated
              new_fields = fields.to_h do |field_name, field|
                renamed = field.assign_name("#{name}.#{field_name}")
                updated ||= !renamed.equal?(field)
                [field_name, renamed]
              end
              return self unless updated

              return DeclType.new(:object, name, new_fields, nil, nil, nil)
            end
            if map? || list?
              renamed = elem.assign_name("#{name}.#{map? ? "@elem" : "@idx"}")
              return self if renamed.equal?(elem)

              return DeclType.new(kind, self.name, nil, key, renamed, nil)
            end
            self
          end

          # FieldTypeMap: every object type of the tree by name.
          def object_types(into = {})
            case kind
            when :object
              into[name] = self
              fields.each_value { |field| field.object_types(into) }
            when :list, :map then elem.object_types(into)
            end
            into
          end
        end

        SIMPLE = {"boolean" => C::BOOL, "number" => C::DOUBLE, "integer" => C::INT}.freeze
        STRING_FORMATS = {"byte" => C::BYTES, "duration" => C::DURATION, "date" => C::TIMESTAMP, "date-time" => C::TIMESTAMP}.freeze

        Warning = Struct.new(:field_ref, :warning) do
          def to_h = {"fieldRef" => field_ref, "warning" => warning}
        end

        # rest_mapper: (group, version, resource) -> [[group, version, kind], ...]
        # (raises or returns [] when unknown).  discovery_schema:
        # [group, version, kind] -> OpenAPI v3 components document of that
        # group version (ClientDiscoveryResolver), or nil.
        def initialize(rest_mapper:, discovery_document: nil, type_name_suffix: -> { Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond) % 1_000_000_000 })
          @rest_mapper = rest_mapper
          @discovery_document = discovery_document
          @type_name_suffix = type_name_suffix
        end

        # kube-controller-manager's wiring: the REST mapper from API
        # discovery, CRD schemas from the served /openapi/v3 documents
        # (ClientDiscoveryResolver); both cached briefly.
        def self.for_client(client, ttl: 30, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          cache = {}
          fetch = lambda do |path|
            entry = cache[path]
            return entry[1] if entry && clock.call - entry[0] < ttl

            value = begin
              response = client.raw("GET", path)
              body = response.respond_to?(:body) ? response.body : response
              body.is_a?(String) ? JSON.parse(body) : body
            rescue StandardError
              nil
            end
            cache[path] = [clock.call, value]
            value
          end
          group_version_path = ->(group, version) { group.empty? ? "api/#{version}" : "apis/#{group}/#{version}" }
          mapper = lambda do |group, version, resource|
            list = fetch.call("/#{group_version_path.call(group, version)}")
            entry = Array(list.is_a?(Hash) ? list["resources"] : nil).find { |candidate| candidate["name"] == resource }
            entry ? [[group, version, entry["kind"].to_s]] : []
          end
          document = ->(gvk) { fetch.call("/openapi/v3/#{group_version_path.call(gvk[0], gvk[1])}") }
          new(rest_mapper: mapper, discovery_document: document)
        end

        # The controller's entry point (TypeChecker.Check as a callable).
        def call(policy) = check(policy)&.map(&:to_h) || []

        # TypeChecker.Check: the warnings, nil when there are none.
        def check(policy)
          context = create_context(policy)
          warnings = []
          Array(policy.dig("spec", "validations")).each_with_index do |validation, index|
            results = check_expression(context, validation["expression"].to_s)
            warnings << Warning.new("spec.validations[#{index}].expression", render(results)) unless results.empty?
            next if validation["messageExpression"].to_s.empty?

            results = check_expression(context, validation["messageExpression"].to_s)
            warnings << Warning.new("spec.validations[#{index}].messageExpression", render(results)) unless results.empty?
          end
          warnings.empty? ? nil : warnings
        end

        Context = Struct.new(:gvks, :decl_types, :param_gvk, :param_decl_type, :variables)

        def create_context(policy)
          gvks = []
          decl_types = []
          types_to_check(policy).each do |gvk|
            found, decl_type = decl_type_for(gvk)
            next unless found

            gvks << gvk
            decl_types << decl_type
          end
          param_gvk = params_gvk(policy)
          param_decl_type = param_gvk ? decl_type_for(param_gvk).last : nil
          Context.new(gvks, decl_types, param_gvk, param_decl_type, Array(policy.dig("spec", "variables")))
        end

        # CheckExpression: one result per checked kind that has issues.
        def check_expression(context, expression)
          context.gvks.each_with_index.filter_map do |gvk, index|
            env = environment(context, context.decl_types[index])
            issues = compile(env, expression).last
            issues.empty? ? nil : [gvk, issues]
          end
        end

        # TypeCheckingResults.String.
        def render(results)
          results.map { |gvk, issues| "#{gvk_string(gvk)}: #{issues}\n" }.join("\n")
        end

        # schema.GroupVersionKind.String: "<group>/<version>, Kind=<kind>"
        # (the core group prints as "/v1").
        def gvk_string(gvk)
          group, version, kind = gvk
          "#{group}/#{version}, Kind=#{kind}"
        end

        # The type-checking environment for one kind: object/oldObject (and
        # params) typed, and variables compiled in order into
        # kubernetes.variables.
        def environment(context, object_type)
          base = Declarations.environment
          idents = {}
          structs = {}
          object_cel = object_type ? object_type.cel_type : C::DYN
          structs.merge!(object_type.object_types.transform_values { |decl| decl_fields(decl) }) if object_type
          idents["object"] = object_cel
          idents["oldObject"] = object_cel
          if context.param_gvk
            param_type = context.param_decl_type
            structs.merge!(param_type.object_types.transform_values { |decl| decl_fields(decl) }) if param_type
            idents["params"] = param_type ? param_type.cel_type : C::DYN
          end
          variables = {}
          idents["variables"] = C::Type.struct("kubernetes.variables")
          structs["kubernetes.variables"] = variables
          env = base.with(idents: idents, structs: structs)
          context.variables.each do |variable|
            output, = compile(env, variable["expression"].to_s)
            variables[variable["name"].to_s] = variable_type(output)
          end
          env
        end

        def decl_fields(decl) = decl.fields.transform_values(&:cel_type)

        def compile(env, expression) = self.class.compile(env, expression).first(2)
        def variable_type(type) = self.class.variable_type(type)

        # env.Compile: parse, check, then (without errors) the validators.
        # Returns [output type or nil, issues, the checked AST root].
        def self.compile(env, expression)
          source = C::Source.new(expression)
          issues = C::Issues.new(source)
          begin
            parser = C::Parser.new(expression, macros: env.macros)
            root = parser.parse
          rescue C::ParseError, CEL::SyntaxError => error
            issues.report(0, "Syntax error: #{error.message}")
            return [nil, issues]
          end
          unless parser.errors.empty?
            parser.errors.each { |offset, message| issues.report(offset, message) }
            return [nil, issues]
          end
          checker = C::Checker.new(env)
          types = checker.check(root, issues)
          return [nil, issues] unless issues.empty?

          C::Validators.run(Declarations.validators, root, types, checker.references, issues)
          issues.empty? ? [types[root], issues, root] : [nil, issues]
        end

        # convertCelTypeToDeclType, back as a CEL type.
        def self.variable_type(type)
          return C::DYN if type.nil? || type.nullable?

          case type.kind
          when :any, :bool, :bytes, :double, :duration, :int, :null, :string, :timestamp, :uint then type
          when :list then C::Type.list(variable_type(type.params[0]))
          when :map then C::Type.map(variable_type(type.params[0]), variable_type(type.params[1]))
          else C::DYN
          end
        end

        # typesToCheck.
        def types_to_check(policy)
          rules = Array(policy.dig("spec", "matchConstraints", "resourceRules"))
          return [] if rules.empty?

          gvks = []
          rules.each do |rule|
            groups = Array(rule["apiGroups"])
            versions = Array(rule["apiVersions"])
            next if groups.empty? || groups.any? { |group| group.include?("*") }
            next if versions.empty? || versions.any? { |version| version.include?("*") }

            resources = Array(rule["resources"]).reject { |resource| resource.match?(%r{[*/]}) }
            next if resources.empty?

            count = 0
            groups.sort.each do |group|
              versions.sort.each do |version|
                resources.sort.each do |resource|
                  Array(safe_kinds_for(group, version, resource)).each do |gvk|
                    next if gvk.nil? || gvk.all?(&:empty?)

                    gvks << gvk unless gvks.include?(gvk)
                    count += 1
                    return sort_gvks(gvks) if count == MAX_TYPES_TO_CHECK
                  end
                end
              end
            end
          end
          sort_gvks(gvks)
        end

        def safe_kinds_for(group, version, resource)
          @rest_mapper.call(group, version, resource)
        rescue StandardError
          []
        end

        def sort_gvks(gvks) = gvks.sort

        # paramsGVK: schema.ParseGroupVersion of the apiVersion (an invalid
        # one gives the empty GVK: no params).
        def params_gvk(policy)
          kind = policy.dig("spec", "paramKind")
          return nil unless kind.is_a?(Hash)

          api_version = kind["apiVersion"].to_s
          parts = api_version.split("/", -1)
          group, version = case parts.length
                           when 0, 1 then ["", api_version]
                           when 2 then parts
                           else return nil
                           end
          return nil if api_version == "/"

          gvk = [group, version, kind["kind"].to_s]
          gvk.all?(&:empty?) ? nil : gvk
        end

        # declType: [resolved, the schema as a DeclType named
        # <Kind><nanoseconds> (generateUniqueTypeName) or nil].
        def decl_type_for(gvk)
          schema = resolve_schema(gvk)
          return [false, nil] if schema.nil?

          decl = schema_decl_type(schema, true)
          [true, decl&.assign_name("#{gvk[2]}#{@type_name_suffix.call}")]
        end

        def resolve_schema(gvk)
          if (ref = Declarations.gvk_refs[gvk])
            definitions = Declarations.definitions.fetch("definitions")
            return populate_refs(definitions[ref], Set[ref]) { |name| definitions[name] }
          end
          document = @discovery_document&.call(gvk)
          return nil unless document.is_a?(Hash)

          schemas = document.dig("components", "schemas") || {}
          ref, = schemas.find do |_name, schema|
            Array(schema.is_a?(Hash) ? schema["x-kubernetes-group-version-kind"] : nil).any? do |candidate|
              [candidate["group"].to_s, candidate["version"].to_s, candidate["kind"].to_s] == gvk
            end
          end
          return nil unless ref

          populate_refs(schemas[ref], Set[ref]) { |name| schemas[name.delete_prefix("#/components/schemas/")] }
        rescue KeyError
          nil
        end

        # PopulateRefs: $ref (directly or inside allOf) replaced by the
        # referenced schema; a cycle becomes {type: object}.
        def populate_refs(schema, visited, &lookup)
          raise KeyError, "missing schema" if schema.nil?

          result = schema
          ref = ref_of(schema)
          if ref
            return {"type" => "object"} if visited.include?(ref)

            visited << ref
            begin
              resolved = lookup.call(ref)
              raise KeyError, "cannot resolve #{ref}" if resolved.nil?

              return expand_children(resolved, visited, &lookup)
            ensure
              visited.delete(ref)
            end
          end
          expand_children(result, visited, &lookup)
        end

        def expand_children(schema, visited, &lookup)
          result = schema.dup
          if schema["properties"].is_a?(Hash)
            result["properties"] = schema["properties"].transform_values { |property| populate_refs(property, visited, &lookup) }
          end
          if schema["additionalProperties"].is_a?(Hash)
            result["additionalProperties"] = populate_refs(schema["additionalProperties"], visited, &lookup)
          end
          result["items"] = populate_refs(schema["items"], visited, &lookup) if schema["items"].is_a?(Hash)
          result
        end

        def ref_of(schema)
          return schema["$ref"] if schema["$ref"].is_a?(String) && !schema["$ref"].empty?

          Array(schema["allOf"]).each do |item|
            ref = item.is_a?(Hash) ? ref_of(item) : nil
            return ref if ref
          end
          nil
        end

        def schema_type(schema)
          type = schema["type"]
          type.is_a?(Array) ? type.first.to_s : type.to_s
        end

        def extension?(schema, key) = schema[key] == true

        def int_or_string?(schema) = schema["format"] == "int-or-string" || extension?(schema, "x-kubernetes-int-or-string")

        # SchemaDeclType.
        def schema_decl_type(schema, resource_root)
          return nil unless schema.is_a?(Hash)
          return DeclType.new(:simple, "dyn", nil, nil, nil, C::DYN) if int_or_string?(schema)

          schema = with_type_and_object_meta(schema) if resource_root
          case schema_type(schema)
          when "array"
            items = schema["items"]
            return nil unless items.is_a?(Hash)

            elem = schema_decl_type(items, extension?(items, "x-kubernetes-embedded-resource"))
            elem && DeclType.new(:list, "list", nil, nil, elem, nil)
          when "object"
            additional = schema["additionalProperties"]
            if additional.is_a?(Hash)
              elem = schema_decl_type(additional, extension?(additional, "x-kubernetes-embedded-resource"))
              return elem && DeclType.new(:map, "map", nil, DeclType.new(:simple, "string", nil, nil, nil, C::STRING), elem, nil)
            end
            fields = {}
            (schema["properties"] || {}).each do |name, property|
              type = schema_decl_type(property, property.is_a?(Hash) && extension?(property, "x-kubernetes-embedded-resource"))
              next if type.nil?

              escaped = escape(name)
              fields[escaped] = type if escaped
            end
            DeclType.new(:object, "object", fields, nil, nil, nil)
          when "string"
            DeclType.new(:simple, "string", nil, nil, nil, STRING_FORMATS.fetch(schema["format"].to_s, C::STRING))
          else
            simple = SIMPLE[schema_type(schema)]
            simple && DeclType.new(:simple, schema_type(schema), nil, nil, nil, simple)
          end
        end

        def with_type_and_object_meta(schema)
          properties = schema["properties"]
          if properties.is_a?(Hash) && string_typed?(properties["kind"]) && string_typed?(properties["apiVersion"]) &&
             properties["metadata"].is_a?(Hash) && schema_type(properties["metadata"]) == "object" &&
             properties.dig("metadata", "properties").is_a?(Hash) &&
             string_typed?(properties.dig("metadata", "properties", "name")) &&
             string_typed?(properties.dig("metadata", "properties", "generateName"))
            return schema
          end

          string = {"type" => "string"}
          schema.merge("properties" => (properties || {}).merge(
            "kind" => string, "apiVersion" => string,
            "metadata" => {"type" => "object", "properties" => {"name" => string, "generateName" => string}}
          ))
        end

        def string_typed?(schema) = schema.is_a?(Hash) && Array(schema["type"]).include?("string")

        # apiservercel.Escape.
        def escape(name)
          return nil if name.empty? || name[0].match?(/[0-9]/)
          return "__#{name}__" if CEL_RESERVED.include?(name)
          return nil unless name.match?(%r{\A[A-Za-z0-9_./-]*\z})
          return name unless name.match?(%r{[/.-]|__})

          name.gsub(%r{__|[-./]}) do |match|
            {"__" => "__underscores__", "." => "__dot__", "-" => "__dash__", "/" => "__slash__"}.fetch(match)
          end
        end
      end
    end
  end
end
