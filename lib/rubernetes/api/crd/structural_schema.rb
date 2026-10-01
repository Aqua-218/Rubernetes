# frozen_string_literal: true

require "json"
require "time"

module Rubernetes
  module API
    module CRD
      class << self
        # The API server's registry for the apiextensions-apiserver series
        # (CEL compilation and evaluation, conversion webhooks) -- process-wide,
        # like upstream's package-level metrics.
        attr_accessor :metrics
      end

      # CustomResourceDefinition structural schema
      # (apiextensions.k8s.io/v1, k8s.io/apiextensions-apiserver/pkg/apiserver/schema):
      # structural validation of the schema itself, defaulting, pruning of
      # unknown fields, OpenAPI v3 validation of custom resources, list-type
      # and map-key semantics, int-or-string, embedded resources, and the
      # x-kubernetes-validations CEL rules.
      class StructuralSchema
        class Invalid < StandardError
          attr_reader :causes

          def initialize(causes)
            @causes = causes
            super(causes.map { |cause| "#{cause["field"]}: #{cause["message"]}" }.join(", "))
          end
        end

        class NotStructural < StandardError; end

        TYPES = %w[object array string integer number boolean].freeze
        KNOWN_KEYS = %w[
          type properties required items additionalProperties default enum pattern minLength maxLength minimum maximum
          exclusiveMinimum exclusiveMaximum minItems maxItems uniqueItems minProperties maxProperties multipleOf format
          description title nullable allOf anyOf oneOf not example externalDocs
          x-kubernetes-preserve-unknown-fields x-kubernetes-embedded-resource x-kubernetes-int-or-string
          x-kubernetes-list-type x-kubernetes-list-map-keys x-kubernetes-map-type x-kubernetes-validations
        ].freeze

        attr_reader :schema, :cel

        def initialize(schema, cel: nil)
          @schema = schema || {}
          @cel = cel
          validate_structural!(@schema, [])
          @validator_nodes = {}.compare_by_identity
          build_validators(@schema) if @cel && validations?(@schema)
        end

        # cel.NewValidator: one validator per schema node on the spine of the
        # rules (items, properties, additionalProperties, allOf), each
        # compiling its own x-kubernetes-validations -- the compilation every
        # node pays is observed, rules or not.  A node keeps a validator when
        # it has rules or a descendant does; only those are evaluated.
        def build_validators(schema)
          return false unless schema.is_a?(Hash)

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          rules = Array(schema["x-kubernetes-validations"])
          rules.each do |rule|
            @cel.compile(rule["rule"]) if rule["rule"].is_a?(String)
            @cel.compile(rule["messageExpression"]) if rule["messageExpression"].is_a?(String)
          rescue StandardError
            nil
          end
          observe_cel("apiserver_cel_compilation_duration_seconds", started)
          children = []
          children << schema["items"] if schema["items"].is_a?(Hash)
          children.concat((schema["properties"] || {}).values)
          children << schema["additionalProperties"] if schema["additionalProperties"].is_a?(Hash)
          children.concat(Array(schema["allOf"]))
          nested = children.map { |child| build_validators(child) }.any?
          return false unless !rules.empty? || nested

          @validator_nodes[schema] = true
        end

        def observe_cel(name, started)
          metrics = CRD.metrics
          metrics&.observe(name, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        rescue StandardError
          nil
        end

        # ---------------------------------------------------------------- structural rules

        def validate_structural!(schema, path)
          return if schema.nil?
          raise NotStructural, "#{join(path)}: schema must be an object" unless schema.is_a?(Hash)

          unknown = schema.keys - KNOWN_KEYS
          raise NotStructural, "#{join(path)}: unknown schema keys #{unknown.join(", ")}" unless unknown.empty?

          type = schema["type"]
          preserve = schema["x-kubernetes-preserve-unknown-fields"] == true
          int_or_string = schema["x-kubernetes-int-or-string"] == true
          if type.nil? && !preserve && !int_or_string && !path.empty?
            raise NotStructural, "#{join(path)}: must have a type (or x-kubernetes-preserve-unknown-fields / x-kubernetes-int-or-string)"
          end
          raise NotStructural, "#{join(path)}: type #{type.inspect} is not allowed" if type && !TYPES.include?(type)
          raise NotStructural, "root schema must be an object" if path.empty? && type != "object"

          %w[allOf anyOf oneOf].each do |combinator|
            Array(schema[combinator]).each_with_index do |branch, index|
              if branch.is_a?(Hash) && branch.key?("type")
                raise NotStructural,
                      "#{join(path + ["#{combinator}[#{index}]"])}: must not set type"
              end
              if branch.is_a?(Hash) && branch.key?("default")
                raise NotStructural,
                      "#{join(path + ["#{combinator}[#{index}]"])}: must not set default"
              end
            end
          end
          if path == ["metadata"] && schema["properties"] && (schema["properties"].keys - %w[
            name generateName
          ]).any?
            raise NotStructural,
                  "#{join(path)}: metadata may only specify name and generateName"
          end

          (schema["properties"] || {}).each { |name, child| validate_structural!(child, path + [name]) }
          validate_structural!(schema["items"], path + ["items"]) if schema["items"].is_a?(Hash)
          if schema["additionalProperties"].is_a?(Hash)
            raise NotStructural, "#{join(path)}: additionalProperties and properties are mutually exclusive" if schema["properties"]

            validate_structural!(schema["additionalProperties"], path + ["additionalProperties"])
          end
          if schema["x-kubernetes-list-type"] == "map"
            keys = Array(schema["x-kubernetes-list-map-keys"])
            raise NotStructural, "#{join(path)}: list-type map requires x-kubernetes-list-map-keys" if keys.empty?

            item_properties = schema.dig("items", "properties") || {}
            keys.each do |key|
              raise NotStructural, "#{join(path)}: map key #{key} must be a defined item property" unless item_properties.key?(key)
            end
          end
          Array(schema["x-kubernetes-validations"]).each_with_index do |rule, index|
            unless rule.is_a?(Hash) && rule["rule"].is_a?(String)
              raise NotStructural,
                    "#{join(path)}: x-kubernetes-validations[#{index}] needs a rule"
            end
          end
        end

        # ---------------------------------------------------------------- defaulting

        def apply_defaults(object)
          default_value(deep_copy(object), @schema)
        end

        def default_value(value, schema)
          return value if schema.nil? || !schema.is_a?(Hash)

          value = deep_copy(schema["default"]) if value.nil? && schema.key?("default")
          case value
          when Hash
            (schema["properties"] || {}).each do |name, child|
              if value.key?(name)
                value[name] = default_value(value[name], child)
              elsif child.is_a?(Hash) && child.key?("default")
                value[name] = deep_copy(child["default"])
                value[name] = default_value(value[name], child)
              end
            end
            value.each_key { |key| value[key] = default_value(value[key], schema["additionalProperties"]) } if schema["additionalProperties"].is_a?(Hash)
          when Array
            value.map! { |item| default_value(item, schema["items"]) } if schema["items"].is_a?(Hash)
          end
          value
        end

        # ---------------------------------------------------------------- pruning

        # Remove fields not declared in the schema (unless preserved).
        def prune(object)
          prune_value(deep_copy(object), @schema, root: true)
        end

        def prune_value(value, schema, root: false)
          return value if schema.nil? || !schema.is_a?(Hash)

          # An embedded resource still has its ObjectMeta pruned, even when the
          # schema preserves everything else about it: metadata is a known
          # Kubernetes type, not part of the free-form content.
          if schema["x-kubernetes-preserve-unknown-fields"] == true && !schema["properties"] &&
             !schema["items"] && !schema["additionalProperties"]
            if schema["x-kubernetes-embedded-resource"] == true && value.is_a?(Hash) && value["metadata"].is_a?(Hash)
              value["metadata"] = prune_metadata(value["metadata"])
            end
            return value
          end

          case value
          when Hash
            properties = schema["properties"] || {}
            preserve = schema["x-kubernetes-preserve-unknown-fields"] == true
            embedded = schema["x-kubernetes-embedded-resource"] == true
            value.keys.each do |key|
              if root && %w[apiVersion kind metadata].include?(key)
                value[key] = prune_metadata(value[key]) if key == "metadata"
                next
              end
              if embedded && %w[apiVersion kind metadata].include?(key)
                value[key] = prune_metadata(value[key]) if key == "metadata"
                next
              end
              if properties.key?(key)
                value[key] = prune_value(value[key], properties[key])
              elsif schema["additionalProperties"].is_a?(Hash)
                value[key] = prune_value(value[key], schema["additionalProperties"])
              elsif schema["additionalProperties"] == true || preserve
                next
              else
                value.delete(key)
              end
            end
          when Array
            value.map! { |item| prune_value(item, schema["items"]) } if schema["items"].is_a?(Hash)
          end
          value
        end

        # The fields pruning would drop, as JSON paths.  Server-side field
        # validation reports exactly these: apiextensions-apiserver prunes a
        # custom resource against its structural schema and, when
        # fieldValidation asks, reports what it removed instead of removing it
        # silently.  Without this a CR could carry any field at all past a
        # Strict request.
        def unknown_field_paths(object)
          paths = []
          collect_unknown(object, @schema, [], paths, root: true)
          paths
        end

        def collect_unknown(value, schema, path, paths, root: false)
          return unless schema.is_a?(Hash)

          if schema["x-kubernetes-preserve-unknown-fields"] == true && !schema["properties"] &&
             !schema["items"] && !schema["additionalProperties"] && !root
            collect_unknown_metadata(value["metadata"], path + ["metadata"], paths) if schema["x-kubernetes-embedded-resource"] == true && value.is_a?(Hash)
            return
          end

          case value
          when Hash
            properties = schema["properties"] || {}
            preserve = schema["x-kubernetes-preserve-unknown-fields"] == true
            embedded = schema["x-kubernetes-embedded-resource"] == true
            value.each do |key, item|
              if (root || embedded) && %w[apiVersion kind metadata].include?(key)
                collect_unknown_metadata(item, path + [key], paths) if key == "metadata"
                next
              end
              if properties.key?(key)
                collect_unknown(item, properties[key], path + [key], paths)
              elsif schema["additionalProperties"].is_a?(Hash)
                collect_unknown(item, schema["additionalProperties"], path + [key], paths)
              elsif schema["additionalProperties"] == true || preserve
                next
              else
                paths << (path + [key])
              end
            end
          when Array
            return unless schema["items"].is_a?(Hash)

            value.each_with_index { |item, index| collect_unknown(item, schema["items"], path + [index], paths) }
          end
        end

        # ObjectMeta is pruned to the known fields at the root and inside every
        # embedded resource, so an unknown metadata field is reported in both.
        def collect_unknown_metadata(metadata, path, paths)
          return unless metadata.is_a?(Hash)

          metadata.each_key do |key|
            paths << (path + [key]) unless METADATA_FIELDS.include?(key)
          end
        end

        # ObjectMeta is pruned against the known metadata fields.
        METADATA_FIELDS = %w[name generateName namespace selfLink uid resourceVersion generation creationTimestamp deletionTimestamp
                             deletionGracePeriodSeconds labels annotations ownerReferences finalizers managedFields].freeze

        def prune_metadata(metadata)
          return metadata unless metadata.is_a?(Hash)

          metadata.select { |key, _| METADATA_FIELDS.include?(key) }
        end

        # ---------------------------------------------------------------- validation

        # Validation mirrors apiextensions-apiserver: kube-openapi schema
        # validation first (messages rendered exactly like
        # field.Error.ErrorBody with the "<path> in body ..." detail), then
        # list-type checks, then CEL rules.  CEL is skipped, with the upstream
        # "<nil>" cause, when a blocking error (required, unsupported, too
        # long, too many, wrong type) is present.
        BLOCKING_REASONS = %w[FieldValueNotSupported FieldValueRequired FieldValueTooLong FieldValueTooMany FieldValueTypeInvalid].freeze
        BLOCKED_MESSAGE = "some validation rules were not checked because the object was invalid; correct the existing errors to complete validation"

        def validate(object, old: nil, variables: {})
          causes = []
          validate_value(object, @schema, [], causes, root: true)
          ratchet!(causes, object, old) if old
          if @cel && validations?(@schema)
            if causes.any? { |cause| BLOCKING_REASONS.include?(cause["reason"]) }
              causes << {"field" => "<nil>", "message" => "Invalid value: null: #{BLOCKED_MESSAGE}", "reason" => "FieldValueInvalid"}
            else
              validate_cel(object, @schema, [], causes, old_value: old, root: true)
            end
          end
          raise Invalid, causes unless causes.empty?

          true
        end

        # CRDValidationRatcheting: on an update, a structural error inside a
        # subtree that is unchanged from the stored object is not the
        # caller's doing and is dropped (it was accepted when stored).  Lists
        # correlate by index.  apiextensions_apiserver_validation_ratcheting_seconds
        # is the time the old/new comparison takes.
        def ratchet!(causes, object, old)
          return if causes.empty?

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          unchanged = []
          collect_unchanged(object, old, [], unchanged)
          unless unchanged.empty?
            causes.reject! do |cause|
              field = cause["field"].to_s
              unchanged.any? { |prefix| field == prefix || field.start_with?("#{prefix}.", "#{prefix}[") }
            end
          end
        ensure
          observe_ratcheting(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) if started
        end

        def collect_unchanged(value, old, path, unchanged)
          if value == old
            unchanged << join(path) unless path.empty?
            return
          end
          case value
          when Hash
            return unless old.is_a?(Hash)

            value.each { |key, child| collect_unchanged(child, old[key], path + [key.to_s], unchanged) if old.key?(key) }
          when Array
            return unless old.is_a?(Array)

            value.each_with_index do |child, index|
              collect_unchanged(child, old[index], path + ["[#{index}]"], unchanged) if index < old.length
            end
          end
        end

        def observe_ratcheting(seconds)
          return unless defined?(Rubernetes::Observability::Metrics)

          registry = Rubernetes::Observability::Metrics.global
          name = "apiextensions_apiserver_validation_ratcheting_seconds"
          registry.register(name, type: :histogram) unless registry.registered?(name)
          registry.observe(name, seconds)
        rescue StandardError
          nil
        end

        def validations?(schema)
          return false unless schema.is_a?(Hash)
          return true unless Array(schema["x-kubernetes-validations"]).empty?

          (schema["properties"] || {}).values.any? { |child| validations?(child) } ||
            validations?(schema["items"]) || validations?(schema["additionalProperties"]) ||
            %w[allOf anyOf oneOf].any? { |combinator| Array(schema[combinator]).any? { |child| validations?(child) } } ||
            validations?(schema["not"])
        end

        def validate_value(value, schema, path, causes, root: false)
          return if schema.nil?

          if schema["x-kubernetes-int-or-string"] == true
            return type_invalid(causes, path, value, "integer,string") unless value.is_a?(Integer) || value.is_a?(String)
          elsif value.nil?
            return if schema["nullable"] == true
            return type_invalid(causes, path, value, schema["type"]) if schema["type"] && !schema.key?("default")

            return
          end
          type = schema["type"]
          return type_invalid(causes, path, value, type) if type && !type_matches?(type, value)

          if schema["enum"] && schema["enum"].none?(value)
            supported = schema["enum"].map { |allowed| allowed.is_a?(String) ? go_quote(allowed) : go_quote(JSON.generate(allowed)) }
            add(causes, path, "Unsupported value: #{render_value(value)}: supported values: #{supported.join(", ")}",
                "FieldValueNotSupported")
          end
          case value
          when String
            if schema["minLength"] && value.length < schema["minLength"]
              invalid(causes, path, value,
                      "should be at least #{schema["minLength"]} chars long")
            end
            if schema["maxLength"] && value.length > schema["maxLength"]
              add(causes, path, "Too long: may not be more than #{schema["maxLength"]} #{schema["maxLength"] == 1 ? "byte" : "bytes"}",
                  "FieldValueTooLong")
            end
            if schema["pattern"]
              begin
                invalid(causes, path, value, "should match '#{schema["pattern"]}'") unless Regexp.new(schema["pattern"]).match?(value)
              rescue RegexpError
                invalid(causes, path, value, "should match '#{schema["pattern"]}'")
              end
            end
            validate_format(value, schema["format"], path, causes) if schema["format"]
          when Integer, Float
            if schema["minimum"] && (schema["exclusiveMinimum"] ? value <= schema["minimum"] : value < schema["minimum"])
              invalid(causes, path, value,
                      "should be greater than #{"or equal to " unless schema["exclusiveMinimum"]}#{go_number(schema["minimum"])}")
            end
            if schema["maximum"] && (schema["exclusiveMaximum"] ? value >= schema["maximum"] : value > schema["maximum"])
              invalid(causes, path, value,
                      "should be less than #{"or equal to " unless schema["exclusiveMaximum"]}#{go_number(schema["maximum"])}")
            end
            if schema["multipleOf"] && (value % schema["multipleOf"]) != 0
              invalid(causes, path, value,
                      "should be a multiple of #{go_number(schema["multipleOf"])}")
            end
          when Array
            if schema["minItems"] && value.length < schema["minItems"]
              invalid(causes, path, value,
                      "should have at least #{schema["minItems"]} items")
            end
            too_many(causes, path, value.length, schema["maxItems"]) if schema["maxItems"] && value.length > schema["maxItems"]
            invalid(causes, path, value, "shouldn't contain duplicates") if schema["uniqueItems"] && value.uniq.length != value.length
            validate_list_type(value, schema, path, causes)
            if schema["items"].is_a?(Hash)
              value.each_with_index do |item, index|
                validate_value(item, schema["items"], path + ["[#{index}]"], causes)
              end
            end
          when Hash
            properties = schema["properties"] || {}
            Array(schema["required"]).each do |name|
              add(causes, path + [name], "Required value", "FieldValueRequired") unless value.key?(name) && !value[name].nil?
            end
            if schema["minProperties"] && value.length < schema["minProperties"]
              invalid(causes, path, value,
                      "should have at least #{schema["minProperties"]} properties")
            end
            if schema["maxProperties"] && value.length > schema["maxProperties"]
              too_many(causes, path, value.length,
                       schema["maxProperties"])
            end
            value.each do |key, child|
              next if root && %w[apiVersion kind metadata].include?(key)
              next if schema["x-kubernetes-embedded-resource"] == true && %w[apiVersion kind metadata].include?(key)

              if properties.key?(key)
                validate_value(child, properties[key], path + [key], causes)
              elsif schema["additionalProperties"].is_a?(Hash)
                validate_value(child, schema["additionalProperties"], path + [key], causes)
              end
            end
            validate_embedded_resource(value, path, causes) if schema["x-kubernetes-embedded-resource"] == true
          end
          %w[allOf anyOf oneOf].each do |combinator|
            branches = Array(schema[combinator])
            next if branches.empty?

            results = branches.map do |branch|
              branch_causes = []
              validate_value(value, branch.merge("type" => type), path, branch_causes)
              branch_causes.empty?
            end
            case combinator
            when "allOf" then invalid(causes, path, value, "must validate all the schemas (allOf)") unless results.all?
            when "anyOf" then invalid(causes, path, value, "must validate at least one schema (anyOf)") unless results.any?
            when "oneOf" then invalid(causes, path, value, "must validate one and only one schema (oneOf)") unless results.count(true) == 1
            end
          end
          return unless schema["not"]

          not_causes = []
          validate_value(value, schema["not"].merge("type" => type), path, not_causes)
          invalid(causes, path, value, "must not validate the schema (not)") if not_causes.empty?
        end

        def type_matches?(type, value)
          case type
          when nil then true
          when "object" then value.is_a?(Hash)
          when "array" then value.is_a?(Array)
          when "string" then value.is_a?(String)
          when "integer" then value.is_a?(Integer)
          when "number" then value.is_a?(Integer) || value.is_a?(Float)
          when "boolean" then [true, false].include?(value)
          else false
          end
        end

        def validate_format(value, format, path, causes)
          ok = case format
               when "date-time" then begin
                 Time.iso8601(value) && true
               rescue StandardError
                 false
               end
               when "date" then value.match?(/\A\d{4}-\d{2}-\d{2}\z/)
               when "email" then value.match?(/\A[^@\s]+@[^@\s]+\z/)
               when "ipv4" then value.match?(/\A(?:\d{1,3}\.){3}\d{1,3}\z/)
               when "ipv6" then value.include?(":")
               when "uri" then value.match?(/\A[a-zA-Z][a-zA-Z0-9+.-]*:/)
               when "uuid" then value.match?(/\A[0-9a-fA-F-]{36}\z/)
               else true
               end
          type_invalid(causes, path, value, format) unless ok
        end

        def validate_list_type(value, schema, path, causes)
          case schema["x-kubernetes-list-type"]
          when "set"
            # listtype.validateListSetsAndMapsArray: the later duplicate is reported at its index.
            seen = []
            value.each_with_index do |item, index|
              add(causes, path + ["[#{index}]"], "Duplicate value: #{render_value(item)}", "FieldValueDuplicate") if seen.include?(item)
              seen << item
            end
          when "map"
            keys = Array(schema["x-kubernetes-list-map-keys"])
            seen = {}
            value.each_with_index do |item, index|
              next unless item.is_a?(Hash)

              key = keys.map { |name| item[name] }
              if seen.key?(key)
                rendered = keys.each_with_object({}) { |name, hash| hash[name] = item[name] if item.key?(name) }
                add(causes, path + ["[#{index}]"], "Duplicate value: #{JSON.generate(rendered)}", "FieldValueDuplicate")
              end
              seen[key] = true
            end
          end
        end

        def validate_embedded_resource(value, path, causes)
          unless value["apiVersion"].is_a?(String) && !value["apiVersion"].empty?
            add(causes, path + ["apiVersion"], "Required value",
                "FieldValueRequired")
          end
          add(causes, path + ["kind"], "Required value", "FieldValueRequired") unless value["kind"].is_a?(String) && !value["kind"].empty?
        end

        # x-kubernetes-validations: each rule sees `self` (and `oldSelf` on
        # update); a false result yields the rule's message / messageExpression.
        # Validator.validate: each visit of a node that has a validator is one
        # evaluation, its time including the nodes below it.
        def validate_cel(value, schema, path, causes, old_value: nil, root: false)
          return validate_cel_node(value, schema, path, causes, old_value: old_value, root: root) unless CRD.metrics && @validator_nodes.key?(schema)

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            validate_cel_node(value, schema, path, causes, old_value: old_value, root: root)
          ensure
            observe_cel("apiserver_cel_evaluation_duration_seconds", started)
          end
        end

        def validate_cel_node(value, schema, path, causes, old_value: nil, root: false)
          return if schema.nil? || !schema.is_a?(Hash)

          Array(schema["x-kubernetes-validations"]).each do |rule|
            next if value.nil?
            next if rule["optionalOldSelf"] != true && rule["rule"].include?("oldSelf") && old_value.nil?

            variables = {"self" => value}
            variables["oldSelf"] = old_value unless old_value.nil?
            result = begin
              @cel.evaluate(rule["rule"], variables)
            rescue StandardError => error
              add(causes, path, "Invalid value: #{go_quote(schema["type"].to_s)}: #{error.message} evaluating rule: #{rule["rule"]}",
                  "FieldValueInvalid")
              next
            end
            next if result == true

            message = rule["message"]
            if rule["messageExpression"]
              message = begin
                @cel.evaluate(rule["messageExpression"], variables)
              rescue StandardError
                message
              end
            end
            detail = message.to_s.empty? ? "failed rule: #{rule["rule"]}" : message.to_s
            reason = rule["reason"] || "FieldValueInvalid"
            add(causes, path, "#{ERROR_TYPE_TEXT.fetch(reason, "Invalid value")}: #{detail}", reason)
          end
          case value
          when Hash
            (schema["properties"] || {}).each do |name, child|
              next unless value.key?(name)
              next if root && %w[apiVersion kind metadata].include?(name)

              validate_cel(value[name], child, path + [name], causes, old_value: old_value.is_a?(Hash) ? old_value[name] : nil)
            end
            if schema["additionalProperties"].is_a?(Hash)
              value.each do |key, child|
                validate_cel(child, schema["additionalProperties"], path + [key], causes,
                             old_value: old_value.is_a?(Hash) ? old_value[key] : nil)
              end
            end
          when Array
            if schema["items"].is_a?(Hash)
              value.each_with_index do |item, index|
                validate_cel(item, schema["items"], path + ["[#{index}]"], causes)
              end
            end
          end
        end

        private

        ERROR_TYPE_TEXT = {"FieldValueInvalid" => "Invalid value", "FieldValueForbidden" => "Forbidden", "FieldValueRequired" => "Required value",
                           "FieldValueDuplicate" => "Duplicate value", "FieldValueNotSupported" => "Unsupported value"}.freeze

        def add(causes, path, message, reason)
          causes << {"field" => join(path), "message" => message, "reason" => reason}
        end

        # field.Invalid(path, value, "<path> in body <detail>")
        def invalid(causes, path, value, detail)
          add(causes, path, "Invalid value: #{render_value(value)}: #{join(path)} in body #{detail}", "FieldValueInvalid")
        end

        # field.TypeInvalid(path, value, "<path> in body must be of type <type>: <go type>")
        def type_invalid(causes, path, value, type)
          add(causes, path,
              "Invalid value: #{render_value(value)}: #{join(path)} in body must be of type #{type}: " \
              "#{go_quote(json_type_name(value))}", "FieldValueTypeInvalid")
        end

        def too_many(causes, path, actual, maximum)
          add(causes, path, "Too many: #{actual}: must have at most #{maximum} #{maximum == 1 ? "item" : "items"}", "FieldValueTooMany")
        end

        # field.Error.ErrorBody value rendering: simple types with %v, strings
        # with %q, everything else JSON-encoded.
        def render_value(value)
          case value
          when nil then "null"
          when String then go_quote(value)
          when Integer, true, false then value.to_s
          when Float then go_number(value)
          else JSON.generate(value)
          end
        end

        def go_number(value)
          return value.to_s unless value.is_a?(Float)

          value == value.floor && value.abs < 1e21 ? value.to_i.to_s : value.to_s
        end

        # strconv.Quote: double-quoted with Go escapes.
        def go_quote(value)
          escaped = value.to_s.each_char.map do |char|
            case char
            when '"' then '\\"'
            when "\\" then "\\\\"
            when "\n" then "\\n"
            when "\t" then "\\t"
            when "\r" then "\\r"
            else
              if char.ord < 0x20 || char.ord == 0x7f
                format("\\x%02x", char.ord)
              else
                char
              end
            end
          end.join
          "\"#{escaped}\""
        end

        def json_type_name(value)
          case value
          when nil then "null"
          when String then "string"
          when Integer then "number"
          when Float then "number"
          when true, false then "boolean"
          when Array then "array"
          when Hash then "object"
          else value.class.name.to_s.downcase
          end
        end

        def join(path)
          path.empty? ? "<root>" : path.join(".").gsub(".[", "[")
        end

        def deep_copy(value)
          case value
          when Hash then value.each_with_object({}) { |(key, child), hash| hash[key] = deep_copy(child) }
          when Array then value.map { |child| deep_copy(child) }
          else value
          end
        end
      end
    end
  end
end
