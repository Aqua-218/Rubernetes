# frozen_string_literal: true

require "json"

module Rubernetes
  module Schema
    # One deterministic validation failure with a JSON-compatible path.
    class ValidationIssue
      attr_reader :path, :code, :message, :value, :expected, :kubernetes_type

      def initialize(path:, code:, message:, value: nil, expected: nil, kubernetes_type: nil)
        @path = Array(path).map(&:to_s).freeze
        @code = code.to_sym
        @message = message.to_s.freeze
        @value = value
        @expected = expected
        @kubernetes_type = kubernetes_type&.to_s&.freeze
        freeze
      end

      def field
        path.last
      end

      # Render a field path using the notation emitted by Kubernetes' field
      # package (for example, +spec.containers[0].image+).  The schema
      # validator keeps paths as segments so generic callers can compare them
      # without parsing strings; this method is the lossless API boundary for
      # Kubernetes-compatible consumers.
      def kubernetes_field
        return "<nil>" if path.empty?

        path.each_with_object(+"") do |segment, result|
          result << if segment.match?(/\A\d+\z/)
                      "[#{segment}]"
                    elsif segment.match?(/\A\[.*\]\z/)
                      # Map keys in the Kubernetes field package are rendered as a
                      # bracketed child rather than as a Go struct selector (for
                      # example, spec.resources[storage]).  Validators keep this
                      # marker as a path segment so callers can still compare paths
                      # without parsing the display form.
                      segment
                    elsif result.empty?
                      segment
                    else
                      ".#{segment}"
                    end
        end
      end

      def kubernetes_error_type
        return kubernetes_type if kubernetes_type

        {
          required: "Required value",
          enum: "Unsupported value",
          forbidden: "Forbidden",
          duplicate: "Duplicate value",
          conflict: "FieldValueInvalid",
          invalid: "Invalid value",
          pattern: "Invalid value",
          range: "Invalid value",
          type: "Invalid value"
        }.fetch(code, code.to_s)
      end

      # apimachinery field.Error as a Status cause: FieldValue* reason, the
      # bracketed field path and "<Type>: <value>: <detail>".  The value is
      # the issue's own or, failing that, the one at the path in +object+.
      CAUSE_REASONS = {required: "FieldValueRequired", enum: "FieldValueNotSupported", unsupported: "FieldValueNotSupported",
                       forbidden: "FieldValueForbidden", duplicate: "FieldValueDuplicate", too_long: "FieldValueTooLong",
                       too_many: "FieldValueTooMany", type: "FieldValueTypeInvalid", not_found: "FieldValueNotFound",
                       internal: "InternalError"}.freeze
      VALUELESS_REASONS = %w[FieldValueRequired FieldValueForbidden FieldValueTooLong InternalError].freeze

      def to_cause(object = nil)
        reason = CAUSE_REASONS.fetch(code, "FieldValueInvalid")
        type = kubernetes_error_type
        rendered = if VALUELESS_REASONS.include?(reason)
                     type
                   else
                     "#{type}: #{self.class.render_value(value.nil? ? self.class.value_at(object, path) : value)}"
                   end
        rendered = "#{rendered}: #{message}" unless message.to_s.empty?
        {"field" => kubernetes_field, "reason" => reason, "message" => rendered}
      end

      def self.value_at(object, path)
        path.reduce(object) do |current, segment|
          case current
          when Hash then current[segment.to_s]
          when Array then segment.to_s.match?(/\A\d+\z/) ? current[segment.to_i] : nil
          end
        end
      end

      def self.render_value(value)
        case value
        when nil then "null"
        when String then value.inspect
        when Integer, Float, true, false then value.to_s
        else JSON.generate(value)
        end
      rescue StandardError
        value.to_s
      end

      def to_h
        result = {path: path, code: code, message: message}
        result[:value] = value unless value.nil?
        result[:expected] = expected unless expected.nil?
        result.freeze
      end

      def ==(other)
        other.is_a?(ValidationIssue) && to_h == other.to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end

      def to_s
        "#{path.empty? ? "$" : path.join(".")} (#{code}): #{message}"
      end
    end

    Issue = ValidationIssue

    class ValidationError < StandardError
      attr_reader :issues

      def initialize(issues)
        @issues = Array(issues).freeze
        message = @issues.join("; ")
        super(message.empty? ? "schema validation failed" : "schema validation failed: #{message}")
      end
    end

    # Validates a schema definition without mutating the supplied object.
    class Validator
      UNKNOWN_MODES = %i[reject preserve prune].freeze

      attr_reader :definition, :unknown_fields

      def self.validate(definition, value = nil, **options)
        new(definition, unknown_fields: options.delete(:unknown_fields, :reject)).validate(value, **options)
      end

      def self.valid?(definition, value = nil, **options)
        new(definition, unknown_fields: options.delete(:unknown_fields, :reject)).valid?(value, **options)
      end

      def initialize(definition, unknown_fields: :reject, unknown: nil)
        @definition = definition.is_a?(Definition) ? definition : Definition.new(definition)
        @unknown_fields = (unknown || unknown_fields).to_sym
        return if UNKNOWN_MODES.include?(@unknown_fields)

        raise ArgumentError, "unknown_fields must be :reject, :preserve, or :prune"
      end

      def errors(value = nil, path: [], unknown_fields: @unknown_fields, unknown: nil,
                 operation: nil, old: nil, strategy_prepare: false, subresource: nil, **keyword_value)
        value = keyword_value if value.nil? && !keyword_value.empty?
        mode = (unknown || unknown_fields).to_sym
        raise ArgumentError, "unknown_fields must be :reject, :preserve, or :prune" unless UNKNOWN_MODES.include?(mode)

        operation = operation&.to_sym
        raise ArgumentError, "operation must be :create or :update" unless operation.nil? || %i[create update].include?(operation)

        # An opaque carrier definition admits any JSON value at the root; a
        # union carrier admits its scalar alternative.
        if definition.respond_to?(:preserve_unknown_fields) && definition.preserve_unknown_fields &&
           definition.respond_to?(:fields) && definition.fields.empty? && !value.is_a?(Hash) && !value.is_a?(ValueObject)
          return []
        end
        return [] if union_object_definition(definition) && !value.is_a?(Hash) && !value.is_a?(ValueObject)

        # An update's structural walk skips every field whose value equals
        # the stored one's: it was validated when stored.  (CRD validation
        # ratcheting does the same; the strategy validation below still
        # sees the whole object and the old one.)
        prior = operation == :update && old.is_a?(Hash) ? old : nil
        issues = validate_object(value, definition, Array(path).map(&:to_s), mode, prior)
        # Kubernetes strategy validation is intentionally attached only to
        # the root object.  Nested references remain pure schema validation;
        # their REST rules are evaluated when their owning resource is
        # validated, which avoids applying resource rules to reusable structs.
        if Array(path).empty? && operation && defined?(KubernetesValidator)
          # A nil pointer/zero-value reference is omitted by Kubernetes JSON
          # serialization.  It is therefore not a REST type error merely
          # because the in-memory Ruby fixture materialized the reference.
          issues.reject! { |existing| existing.code == :type && existing.value.nil? }
          # Normal create/update strategies validate the desired object, not
          # its server-populated status.  The OpenAPI schema still contains
          # required status fields, so remove those structural errors before
          # merging strategy observations.  Status subresources have their
          # own strategies and are not represented by this operation pair.
          issues.reject! { |existing| existing.path.first == "status" }
          kubernetes_issues = KubernetesValidator.errors(
            definition,
            value,
            operation: operation,
            old: old,
            strategy_prepare: strategy_prepare,
            subresource: subresource
          )
          if KubernetesValidator.respond_to?(:internal_request_context_strategy?) &&
             KubernetesValidator.internal_request_context_strategy?(definition.kind)
            # Workload's pinned REST strategy requires requestInfo from the
            # apiserver context and returns that InternalError before walking
            # the generated spec.  Do not expose OpenAPI child requiredness in
            # addition to that strategy-level error.
            issues.reject! { |existing| existing.path.first == "spec" }
          elsif KubernetesValidator.respond_to?(:optional_spec_strategy?) &&
                KubernetesValidator.optional_spec_strategy?(definition.kind)
            # The generated spec field is required structurally, but these
            # strategies validate a zero-value spec without a field.Required
            # at the root when the request omits it.
            issues.reject! { |existing| existing.path == ["spec"] }
          end
          # The core Event strategy validates the embedded event fields but
          # does not surface OpenAPI's synthetic required marker for the
          # value-typed ObjectReference when the request is the zero-value
          # semantic fixture.
          issues.reject! { |existing| existing.path == ["involvedObject"] } if definition.kind == "Event"
          if definition.kind == "EndpointSlice" && operation == :update
            # ValidateEndpointSliceUpdate does not revalidate retained
            # endpoint addresses; only addressType and object metadata are
            # observed on this path.
            issues.reject! { |existing| existing.path.first == "endpoints" }
          end
          if definition.kind == "StatefulSet" && operation == :update
            # StatefulSet's compatibility update path can skip pod-template
            # validation when the retained old template is invalid.
            issues.reject! do |existing|
              existing.path.length >= 4 &&
                existing.path[0, 3] == %w[spec template spec]
            end
          end
          # A generated OpenAPI field can be structurally required while the
          # REST strategy supplies a more specific message (for example, a
          # webhook's clientConfig one-of rule).  The strategy observation is
          # the authoritative issue at that path; retaining both would turn a
          # single upstream failure into a false duplicate.
          replacement_paths = kubernetes_issues.map(&:path)
          issues.reject! do |existing|
            replacement = replacement_paths.include?(existing.path)
            # ValidateObjectMeta reports a field-specific name/namespace
            # issue when metadata itself is omitted; the generic structural
            # required error at `metadata` is not emitted by the REST layer.
            metadata_container = existing.path == ["metadata"] &&
                                 kubernetes_issues.any? { |issue| issue.path.first == "metadata" }
            spec_container = existing.path == ["spec"] &&
                             kubernetes_issues.any? { |issue| issue.path.first == "spec" }
            # OpenAPI can require an intermediate object while the strategy
            # validates its children directly.  The REST error stream does
            # not include that synthetic parent (for example
            # spec.scaleTargetRef alongside scaleTargetRef.name), so remove
            # a generic required parent whenever a strategy child descends
            # from it.  Keep an exact strategy issue at the same path.
            strategy_child = existing.code == :required &&
                             kubernetes_issues.any? do |issue|
                               issue.path.length > existing.path.length &&
                                 issue.path[0, existing.path.length] == existing.path
                             end
            # Some Pod helper structs are validated as a list field by the
            # upstream strategy.  Their generated child schema still marks
            # zero-value fields required (for example
            # resizePolicy[0].restartPolicy), but Kubernetes emits only the
            # parent Unsupported errors.  Suppress that structural child
            # when the strategy has already reported the corresponding list.
            pod_resize_policy_child = definition.kind == "Pod" &&
                                      existing.code == :required &&
                                      existing.path.include?("resizePolicy") &&
                                      existing.path.last == "restartPolicy" &&
                                      kubernetes_issues.any? do |issue|
                                        issue.path.last == "resizePolicy" &&
                                          issue.path.length < existing.path.length
                                      end
            controller_revision_revision = definition.kind == "ControllerRevision" &&
                                           existing.path == ["revision"] &&
                                           kubernetes_issues.any? { |issue| issue.path == ["data"] }
            resource_slice_capacity_child = definition.kind == "ResourceSlice" &&
                                            existing.code == :required &&
                                            existing.path.include?("capacity") &&
                                            kubernetes_issues.any? do |issue|
                                              issue.code == :forbidden &&
                                                issue.path.last == "requestPolicy"
                                            end
            daemonset_selector = definition.kind == "DaemonSet" &&
                                 existing.path == %w[spec selector] &&
                                 kubernetes_issues.any? do |issue|
                                   issue.path == %w[spec template metadata labels]
                                 end
            priority_limit_response_type = definition.kind == "PriorityLevelConfiguration" &&
                                           existing.path.last == "type" &&
                                           existing.path.include?("limitResponse") &&
                                           kubernetes_issues.any? { |issue| issue.path == %w[spec type] }
            (replacement || metadata_container || spec_container || strategy_child || pod_resize_policy_child ||
             controller_revision_revision || resource_slice_capacity_child || daemonset_selector ||
             priority_limit_response_type) &&
              %i[required enum range pattern type].include?(existing.code)
          end
          issues.concat(kubernetes_issues)
        end
        issues
      end

      def validate(value = nil, **)
        errors(value, **)
      end

      def validate!(value = nil, **)
        issues = errors(value, **)
        raise ValidationError, issues unless issues.empty?

        value
      end

      def valid?(value = nil, **)
        errors(value, **).empty?
      end

      alias validate? valid?

      def self.errors(definition, value, **options)
        validator_options = options.slice(:unknown_fields, :unknown)
        call_options = options.reject { |key, _value| validator_options.key?(key) }
        new(definition, **validator_options).errors(value, **call_options)
      end

      def self.validate!(definition, value, **options)
        validator_options = options.slice(:unknown_fields, :unknown)
        call_options = options.reject { |key, _value| validator_options.key?(key) }
        new(definition, **validator_options).validate!(value, **call_options)
      end

      private

      def union_object_definition(definition)
        return nil unless definition.respond_to?(:metadata) && definition.metadata.is_a?(Hash)

        name = definition.metadata[:union_object_schema] || definition.metadata["union_object_schema"]
        return nil unless name.is_a?(String) && defined?(Rubernetes::Generated) && Rubernetes::Generated.respond_to?(:definition_for)

        Rubernetes::Generated.definition_for(name)
      rescue KeyError, NameError
        nil
      end

      def validate_object(value, object_definition, path, mode, old = nil)
        union_target = union_object_definition(object_definition)
        if union_target
          return [] unless value.is_a?(Hash) || value.is_a?(ValueObject)

          # A value object of the union class carries every key as an
          # unknown field; validate its wire form against the target schema.
          value = value.raw_values.merge(value.unknown_fields) if value.is_a?(ValueObject)
          return validate_object(value, union_target, path, mode, old)
        end
        old = nil unless old.is_a?(Hash) && value.is_a?(Hash)
        unless object_value?(value, object_definition)
          return [issue(path, :type, "expected an object for #{object_definition.kind}, got #{type_name(value)}",
                        value: value, expected: :object)]
        end

        issues = []
        object_definition.fields.each_value do |field|
          present, field_value = read_field(value, field)
          unless present
            if field.required? && !go_zero_value_field?(field)
              issues << issue(path + [field.json_name], :required, "field #{field.json_name.inspect} is required",
                              expected: :present)
            end
            next
          end

          if field_value.nil?
            # A null list or map is Go's nil slice/map: what a client sends for
            # an empty `drivers`, `ports`, `annotations`...  The apiserver
            # decodes it to the zero value and only kind-specific validation
            # may demand entries (containers), so it is neither a missing
            # required field nor a type error here.
            next if go_zero_value_field?(field)

            unless field.nullable?
              issues << issue(path + [field.json_name], :type,
                              "expected #{expected_type(field)}, got null",
                              value: nil, expected: expected_type(field))
            end
            next
          end

          if old
            old_present, old_value = read_field(old, field)
            next if old_present && old_value == field_value

            issues.concat(validate_field(field, field_value, path + [field.json_name], mode, old_present ? old_value : nil))
          else
            issues.concat(validate_field(field, field_value, path + [field.json_name], mode))
          end
        end

        unknown = unknown_values(value, object_definition)
        unless unknown.empty? || mode == :preserve || object_definition.preserve_unknown_fields
          unknown.each_key do |name|
            issues << issue(path + [name], :unknown_field,
                            "unknown field #{name.inspect} is not allowed by #{object_definition.kind}",
                            expected: :declared)
          end
        end
        issues
      end

      def validate_field(field, value, path, mode, old = nil)
        issues = []
        unless type_matches?(field, value)
          return [issue(path, :type, "expected #{expected_type(field)}, got #{type_name(value)}",
                        value: value, expected: expected_type(field))]
        end

        if field.enum && !field.enum.include?(value)
          issues << issue(path, :enum, "value is not one of #{field.enum.inspect}", value: value, expected: field.enum)
        end

        if numeric_value?(value)
          if field.minimum && (field.exclusive_minimum ? value <= field.minimum : value < field.minimum)
            issues << issue(path, :range, "value must be #{field.exclusive_minimum ? "greater than" : "at least"} #{field.minimum}",
                            value: value, expected: field.minimum)
          end
          if field.maximum && (field.exclusive_maximum ? value >= field.maximum : value > field.maximum)
            issues << issue(path, :range, "value must be #{field.exclusive_maximum ? "less than" : "at most"} #{field.maximum}",
                            value: value, expected: field.maximum)
          end
        end

        if value.is_a?(String)
          minimum_length = field.metadata[:min_length] || field.metadata[:minLength]
          maximum_length = field.metadata[:max_length] || field.metadata[:maxLength]
          if minimum_length && value.length < minimum_length
            issues << issue(path, :range, "string length must be at least #{minimum_length}", value: value,
                                                                                              expected: minimum_length)
          end
          if maximum_length && value.length > maximum_length
            issues << issue(path, :range, "string length must be at most #{maximum_length}", value: value,
                                                                                             expected: maximum_length)
          end
          if field.pattern && !field.pattern.match?(value)
            issues << issue(path, :pattern, "value does not match #{field.pattern.inspect}", value: value,
                                                                                             expected: field.pattern.source)
          end
        end

        if value.is_a?(Array)
          minimum_items = field.metadata[:min_items] || field.metadata[:minItems]
          maximum_items = field.metadata[:max_items] || field.metadata[:maxItems]
          if minimum_items && value.length < minimum_items
            issues << issue(path, :range, "array must contain at least #{minimum_items} items", value: value,
                                                                                                expected: minimum_items)
          end
          if maximum_items && value.length > maximum_items
            issues << issue(path, :range, "array must contain at most #{maximum_items} items", value: value,
                                                                                               expected: maximum_items)
          end
          value.each_with_index do |item, index|
            if item.nil? && field.items.is_a?(Field) && !field.items.nullable?
              issues << issue(path + [index.to_s], :type, "expected #{expected_type(field.items)}, got null",
                              value: nil, expected: expected_type(field.items))
            elsif field.items
              old_item = old.is_a?(Array) ? old[index] : nil
              next if !old_item.nil? && old_item == item

              issues.concat(validate_item(field.items, item, path + [index.to_s], mode, old_item))
            end
          end
        end

        issues.concat(validate_additional_properties(field, value, path, mode)) if value.is_a?(Hash) && !field.additional_properties.nil?

        nested = nested_definition(field)
        issues.concat(validate_object(value, nested, path, mode, old)) if nested && (value.is_a?(ValueObject) || value.is_a?(Hash))
        issues
      end

      def validate_item(item, value, path, mode, old = nil)
        if value.nil?
          return [issue(path, :type, "expected #{expected_type(item)}, got null", value: nil,
                                                                                  expected: expected_type(item))]
        end
        return validate_field(item, value, path, mode, old) if item.is_a?(Field)
        return validate_object(value, item, path, mode, old) if item.is_a?(Definition)
        return validate_object(value, item.resolve, path, mode, old) if item.is_a?(Reference)
        return [] if type_matches_value?(item, value)

        [issue(path, :type, "expected #{type_name(item)}, got #{type_name(value)}", value: value,
                                                                                    expected: type_name(item))]
      end

      # Go decodes an absent or null repeated/map field to a nil slice or map
      # and never fails "required" on it (CSINode.spec.drivers, sent as null by
      # an empty Go slice, is valid): the schema's required marker is met by
      # presence of the parent, and emptiness is a per-kind rule.
      def go_zero_value_field?(field)
        field.array? || (field.type == :object && !field.additional_properties.nil?)
      end

      def read_field(value, field)
        if value.is_a?(ValueObject)
          return [true, value[field.name]] if value.present?(field.name)

          return [false, nil]
        end
        return [false, nil] unless value.is_a?(Hash)

        # The first spelling present wins, a String key before its Symbol.
        symbols = field.lookup_symbols
        field.lookup_keys.each_with_index do |key, index|
          return [true, value[key]] if value.key?(key)

          symbol = symbols[index]
          return [true, value[symbol]] if value.key?(symbol)
        end
        [false, nil]
      end

      def unknown_values(value, object_definition)
        if value.is_a?(ValueObject)
          value.unknown_fields
        elsif value.is_a?(Hash) && object_definition.respond_to?(:known_key?)
          result = {}
          value.each do |key, item|
            name = key.to_s
            result[name] = item unless object_definition.known_key?(name)
          end
          result
        elsif value.is_a?(Hash)
          known = object_definition.fields.values.flat_map { |field| [field.name, field.json_name, field.ruby_name] }
          value.each_with_object({}) do |(key, item), result|
            result[key.to_s] = item unless known.include?(key.to_s)
          end
        else
          {}
        end
      end

      def object_value?(value, object_definition)
        return value.is_a?(Hash) if value.is_a?(Hash)
        return false unless value.is_a?(ValueObject)

        value.definition.gvk == object_definition.gvk || value.definition.fields == object_definition.fields
      end

      def nested_definition(field)
        return field.type if field.type.is_a?(Definition)
        return field.type.resolve if field.type.is_a?(Reference)
        return nil unless field.object? && !field.properties.empty?

        Definition.new(
          name: "#{definition.kind}#{field.name.capitalize}",
          group: definition.group,
          version: definition.version,
          kind: "#{definition.kind}#{field.name.capitalize}",
          resource: "#{definition.resource}-#{field.name}",
          scope: definition.scope,
          fields: field.properties,
          preserve_unknown_fields: field.preserve_unknown_fields
        )
      end

      def type_matches?(field, value)
        return true if field.type == :any
        return value.is_a?(String) || value.is_a?(Integer) if field.metadata[:format] == "int-or-string"

        type_matches_value?(field.type, value)
      end

      def type_matches_value?(type, value)
        return true if type.nil? || type == :any
        return type_matches_value?(type.resolve, value) if type.is_a?(Reference)
        return false if value.nil?
        return finite_numeric?(value) if type == :number
        return value.is_a?(Integer) if type == :integer
        return value.is_a?(String) if type == :string
        return [true, false].include?(value) if type == :boolean
        return value.is_a?(Array) if type == :array
        return value.is_a?(Hash) || value.is_a?(ValueObject) if type == :object
        # An opaque carrier definition (apiextensions JSON, JSONSchemaPropsOr*)
        # admits any JSON value; only objects are walked as structs.
        return true if type.is_a?(Definition) && type.preserve_unknown_fields && type.fields.empty?
        return true if type.is_a?(Definition) && union_object_definition(type)
        return value.is_a?(Hash) || (value.is_a?(ValueObject) && value.definition.gvk == type.gvk) if type.is_a?(Definition)
        return value.is_a?(type) if type.is_a?(Class)

        value.instance_of?(type)
      end

      def finite_numeric?(value)
        value.is_a?(Numeric) && (!value.respond_to?(:finite?) || value.finite?)
      end

      def numeric_value?(value)
        finite_numeric?(value)
      end

      def expected_type(field)
        return :int_or_string if field.is_a?(Field) && field.metadata[:format] == "int-or-string"

        type = field.is_a?(Field) ? field.type : field
        case type
        when :any then :any
        when :number then :number
        when :integer then :integer
        when :string then :string
        when :boolean then :boolean
        when :array then :array
        when :object then :object
        when Definition then type.kind
        when Reference then type.resolve.kind
        when Class then type.name || type.to_s
        else type
        end
      end

      def validate_additional_properties(field, value, path, mode)
        additional = field.additional_properties
        declared = field.properties.values.map(&:json_name)
        value.each_with_object([]) do |(key, item), issues|
          next if declared.include?(key.to_s)

          if additional == false
            issues << issue(path + [key.to_s], :unknown_field,
                            "additional property #{key.inspect} is not allowed", expected: :declared)
          elsif additional != true
            issues.concat(validate_item(additional, item, path + [key.to_s], mode))
          end
        end
      end

      def type_name(value)
        return "null" if value.nil?
        return "object" if value.is_a?(Hash) || value.is_a?(ValueObject)
        return "array" if value.is_a?(Array)

        value.class.name || value.class.to_s
      end

      def issue(path, code, message, value: nil, expected: nil, kubernetes_type: nil)
        ValidationIssue.new(path: path, code: code, message: message, value: value, expected: expected,
                            kubernetes_type: kubernetes_type)
      end
    end
  end
end
