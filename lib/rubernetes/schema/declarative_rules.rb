# frozen_string_literal: true

require "json"
require_relative "definition"

module Rubernetes
  module Schema
    # Executes rules imported from the versioned validation-gen Go output.
    # Unsupported instructions are reported per reachable type before an
    # evaluator can be selected for a REST strategy.
    class DeclarativeRules
      SOURCE = File.expand_path("../../../generated/schema/declarative_validation.json", __dir__)
      ZERO_VALUES = {"string" => "", "integer" => 0, "boolean" => false, "object" => {}}.freeze
      FORMATS = {
        "ShortName" => ["k8s-short-name", :dns1123_label_messages],
        "LongName" => ["k8s-long-name", :dns1123_subdomain_messages],
        "PathSegmentName" => ["k8s-path-segment-name", :path_segment_name_messages],
        "LabelKey" => ["k8s-label-key", :qualified_name_messages]
      }.freeze
      UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
      C_IDENTIFIER = /\A[A-Za-z_][A-Za-z0-9_]*\z/
      C_IDENTIFIER_MESSAGE = "a valid C identifier must start with alphabetic character or '_', followed by a string of " \
                             "alphanumeric characters or '_' (e.g. 'my_name',  or 'MY_NAME', regex used for validation is '[A-Za-z_][A-Za-z0-9_]*')"

      Finding = Data.define(:issue, :origin, :stage) do
        def identity = [issue.code, issue.path, origin]
      end
      Cursor = Data.define(:value, :previous, :path)

      def self.types
        @types ||= DeepFreeze.call(JSON.parse(File.read(SOURCE)).fetch("types"))
      end

      def self.outstanding(schema)
        @outstanding ||= {}
        @outstanding[schema] ||= begin
          seen = {}
          visit = lambda do |program|
            program.flat_map do |instruction|
              case instruction.fetch("op")
              when "unsupported" then [instruction.fetch("name")]
              when "type"
                name = instruction.fetch("name")
                next [] if seen[name]

                seen[name] = true
                child = types[name]
                child ? visit.call(child) : ["unresolved type #{name}"]
              else
                visit.call(instruction.fetch("body", []))
              end
            end
          end
          visit.call(types.fetch(schema, [{"op" => "unsupported", "name" => "type has no generated validator"}])).uniq.sort.freeze
        end
      end

      def initialize(operation:, options: [])
        @updating = operation == :update
        @options = options
        @findings = []
      end

      def evaluate(schema, object, previous = nil)
        gaps = self.class.outstanding(schema)
        raise ArgumentError, "unsupported declarative validation for #{schema}: #{gaps.join(", ")}" unless gaps.empty?

        @findings = []
        run(self.class.types.fetch(schema), Cursor.new(object, previous, []))
        @findings
      end

      private

      def run(program, cursor)
        guard_failed = false
        program.each do |instruction|
          break if instruction["op"] == "stop_if_guard_failed" && guard_failed

          failed = perform(instruction, cursor)
          guard_failed ||= failed && instruction["guard"]
        end
        guard_failed
      end

      def perform(instruction, cursor)
        name = instruction["name"]
        case instruction["op"]
        when "field", "subfield" then run_field(instruction, cursor)
        when "embedded" then run_embedded(instruction, cursor)
        when "discriminated" then run_discriminated(instruction, cursor)
        when "cohort" then run(instruction.fetch("body"), cursor)
        when "type" then run(self.class.types.fetch(name), cursor)
        when "option"
          return false unless @options.include?(name) == instruction.fetch("arguments").first

          child = instruction.fetch("body").first
          child = child.merge("stage" => instruction["stage"]) if instruction["stage"]
          perform(child, cursor)
        when "list" then run_list(instruction, cursor)
        when "map" then run_map(instruction, cursor)
        when "rule" then run_rule(instruction, cursor)
        when "stop_if_guard_failed" then false
        else raise ArgumentError, "unknown declarative instruction #{instruction.fetch("op")}"
        end
      end

      def run_field(instruction, cursor)
        field = instruction.fetch("name")
        value = KubernetesValidator.fetch(cursor.value, field)
        previous = KubernetesValidator.fetch(cursor.previous, field)
        type = instruction["value_type"]
        if ZERO_VALUES.key?(type)
          value = ZERO_VALUES.fetch(type) if value.nil?
          previous = ZERO_VALUES.fetch(type) if previous.nil? && cursor.previous.is_a?(Hash)
        end
        if @updating && cursor.previous.is_a?(Hash) && instruction["ratchet"]
          same_value = type == "pointer" ? value == previous : equivalent?(value, previous)
          return false if same_value
        end

        body = instruction.fetch("body", [])
        body = body.map { |rule| rule.merge("stage" => instruction["stage"]) } if instruction["stage"]
        child = Cursor.new(value, previous, cursor.path + [field])
        return perform(body.first, child) if instruction["op"] == "subfield"

        run(body, child)
      end

      def run_embedded(instruction, cursor)
        fields = instruction.fetch("arguments").first
        value = cursor.value.is_a?(Hash) ? cursor.value.slice(*fields) : {}
        previous = cursor.previous.slice(*fields) if cursor.previous.is_a?(Hash)
        return false if @updating && previous == value

        path = cursor.path.empty? ? [instruction.fetch("name")] : cursor.path
        run(instruction.fetch("body"), Cursor.new(value, previous, path))
      end

      def run_discriminated(instruction, cursor)
        field = instruction.fetch("name")
        discriminator = instruction.fetch("arguments").first
        variant = KubernetesValidator.fetch(cursor.value, discriminator).to_s
        value = KubernetesValidator.fetch(cursor.value, field)
        previous = KubernetesValidator.fetch(cursor.previous, field)
        return false if @updating && cursor.previous && variant == KubernetesValidator.fetch(cursor.previous, discriminator).to_s && value == previous

        fallback, *variants = instruction.fetch("body")
        branch = variants.find { |entry| entry.fetch("name") == variant } || fallback
        run(branch.fetch("body", []), Cursor.new(value, previous, cursor.path + [field]))
      end

      def run_list(instruction, cursor)
        return false unless cursor.value.is_a?(Array)

        keys = instruction.fetch("arguments").first
        key = ->(item) { list_key(item, keys) }
        by_key = {}
        cursor.previous.each { |item| by_key[key.call(item)] ||= item } if @updating && !keys.empty? && cursor.previous.is_a?(Array)
        seen = {}
        cursor.value.each_with_index do |item, index|
          child_path = cursor.path + [index.to_s]
          item_key = key.call(item)
          if instruction["name"] == "Unique"
            finding(instruction, child_path, :duplicate, "", value: item) if seen[item_key]
            seen[item_key] = true
          else
            previous = by_key[item_key]
            next if previous && equivalent?(item, previous)

            run(instruction.fetch("body"), Cursor.new(item, previous, child_path))
          end
        end
        false
      end

      def list_key(item, keys)
        return item if keys.empty?

        keys.map do |field|
          value = KubernetesValidator.fetch(item, field.fetch("name"))
          value.nil? && field.key?("zero") ? ZERO_VALUES.fetch(field.fetch("zero")) : value
        end
      end

      def run_map(instruction, cursor)
        return false unless cursor.value.is_a?(Hash)

        previous = cursor.previous.is_a?(Hash) ? cursor.previous : {}
        child = instruction.fetch("body").first
        child = child.merge("stage" => instruction["stage"]) if instruction["stage"]
        cursor.value.keys.sort.each do |key|
          if instruction["name"] == "EachMapKey"
            next if @updating && previous.key?(key)

            perform(child, Cursor.new(key, nil, cursor.path))
          else
            value = cursor.value[key]
            next if @updating && previous.key?(key) && equivalent?(value, previous[key])

            perform(child, Cursor.new(value, previous[key], cursor.path + ["[#{key}]"]))
          end
        end
        false
      end

      def run_rule(instruction, cursor)
        name = instruction.fetch("name")
        value = cursor.value
        case name
        when "OptionalValue", "OptionalPointer", "OptionalSlice", "OptionalMap"
          absent?(name.delete_prefix("Optional"), value)
        when "RequiredValue", "RequiredPointer", "RequiredSlice", "RequiredMap"
          finding(instruction, cursor.path, :required, "") if absent?(name.delete_prefix("Required"), value)
        when "ForbiddenValue", "ForbiddenPointer"
          finding(instruction, cursor.path, :forbidden, "") unless absent?(name.delete_prefix("Forbidden"), value)
        when "Immutable"
          finding(instruction, cursor.path, :invalid, "field is immutable", origin: "immutable", use_object_value: false) if @updating
        when "NoModifyPointer"
          if @updating && !cursor.previous.nil? && !value.nil?
            finding(instruction, cursor.path, :invalid, "field cannot be modified once set", origin: "update", use_object_value: false)
          end
        when "Minimum", "Maximum", "MaxItems", "MaxBytes", "MaxLength"
          check_limit(instruction, cursor)
        when "Enum"
          allowed = instruction.fetch("arguments").sort
          finding(instruction, cursor.path, :unsupported, KubernetesValidator.unsupported_detail(allowed)) if value.is_a?(String) && !allowed.include?(value)
        when "Union", "ZeroOrOneOfUnion" then check_union(instruction, cursor)
        else
          check_format(instruction, cursor)
        end
      end

      def absent?(type, value)
        case type
        when "Pointer" then value.nil?
        when "Value" then value.nil? || value == "" || value == false || value == 0
        else value.nil? || ((value.is_a?(Array) || value.is_a?(Hash)) && value.empty?)
        end
      end

      def check_limit(instruction, cursor)
        limit = instruction.fetch("arguments").first
        value = cursor.value
        case instruction.fetch("name")
        when "Minimum"
          finding(instruction, cursor.path, :invalid, "must be greater than or equal to #{limit}", origin: "minimum") if value.is_a?(Integer) && value < limit
        when "Maximum"
          finding(instruction, cursor.path, :invalid, "must be less than or equal to #{limit}", origin: "maximum") if value.is_a?(Integer) && value > limit
        when "MaxItems"
          if value.is_a?(Array) && value.length > limit
            finding(instruction, cursor.path, :too_many, "must have at most #{limit} items", value: value.length, origin: "maxItems")
          end
        when "MaxBytes"
          if value.is_a?(String) && value.bytesize > limit
            finding(instruction, cursor.path, :too_long, "may not be more than #{limit} bytes", origin: "maxBytes")
          end
        when "MaxLength"
          if value.is_a?(String) && value.length > limit
            finding(instruction, cursor.path, :too_long, "may not be more than #{limit} characters", origin: "maxLength")
          end
        end
      end

      def check_union(instruction, cursor)
        members = instruction.fetch("arguments")
        names = members.map { |member| member.is_a?(Hash) ? member.fetch("name") : member }
        chosen = union_members(members, names, cursor.value)
        return false if @updating && cursor.previous && chosen == union_members(members, names, cursor.previous)

        fields = names.map { |field| "`#{field}`" }.join(", ")
        if instruction["name"] == "ZeroOrOneOfUnion"
          if chosen.length > 1
            finding(instruction, cursor.path, :invalid, "must specify at most one of: #{names.join(", ")}",
                    value: "{#{chosen.join(", ")}}", origin: "zeroOrOneOf")
          end
        elsif chosen.empty?
          finding(instruction, cursor.path, :invalid, "must specify one of: #{fields}", value: "", origin: "union")
        elsif chosen.length > 1
          finding(instruction, cursor.path, :invalid, "must specify exactly one of: #{fields}",
                  value: "{#{chosen.map { |field| "`#{field}`" }.join(", ")}}", origin: "union")
        end
      end

      def union_members(members, names, object)
        members.zip(names).filter_map do |member, name|
          present = if member.is_a?(Hash) && member.fetch("test") == "contains"
                      object.is_a?(Array) && object.any? { |item| KubernetesValidator.fetch(item, member.fetch("field")) == member.fetch("value") }
                    else
                      value = KubernetesValidator.fetch(object, name)
                      !value.nil? && (!member.is_a?(Hash) || !value.empty?)
                    end
          name if present
        end
      end

      def check_format(instruction, cursor)
        return false unless cursor.value.is_a?(String)

        name = instruction.fetch("name")
        if name == "ResourcePoolName"
          issues = KubernetesValidator.declared_pool_name_errors(cursor.value, cursor.path)
          issues.each { |issue| @findings << Finding.new(issue, "format=k8s-resource-pool-name", instruction["stage"]) }
          return !issues.empty?
        end
        if name == "LongNameCaseless"
          issues = KubernetesValidator.pool_status_driver_errors(cursor.value, cursor.path)
          issues.each { |issue| @findings << Finding.new(issue, "format=k8s-long-name-caseless", instruction["stage"]) }
          return !issues.empty?
        end
        return check_resource_format(instruction, cursor) if %w[ExtendedResourceName ResourceFullyQualifiedName UUID].include?(name)

        format, helper = FORMATS.fetch(name)
        messages = KubernetesValidator.public_send(helper, cursor.value.b)
        messages.each { |message| finding(instruction, cursor.path, :invalid, message, origin: "format=#{format}") }
        !messages.empty?
      end

      def check_resource_format(instruction, cursor)
        value = cursor.value
        format, messages = case instruction.fetch("name")
                           when "UUID"
                             ["uuid", value.match?(UUID) ? [] : ["must be a lowercase UUID in 8-4-4-4-12 format"]]
                           when "ExtendedResourceName"
                             ["extended-resource-name", extended_resource_name_messages(value)]
                           when "ResourceFullyQualifiedName"
                             return check_fully_qualified_resource_name(instruction, cursor)
                           end
        messages.each { |message| finding(instruction, cursor.path, :invalid, message, origin: "format=k8s-#{format}") }
        !messages.empty?
      end

      def extended_resource_name_messages(value)
        messages = []
        if !value.include?("/")
          messages << "a name must be a domain-prefixed path, such as 'example.com/my-prop'"
        elsif value.include?("kubernetes.io/")
          messages << 'must not have "kubernetes.io/" domain'
        end
        messages << 'must not have "requests." prefix' if value.start_with?("requests.")
        messages.concat(KubernetesValidator.qualified_name_messages("requests.#{value}".b))
      end

      def check_fully_qualified_resource_name(instruction, cursor)
        origin = "format=k8s-resource-fully-qualified-name"
        value = cursor.value
        prefix, name, extra = value.split("/", -1)
        return false if extra

        start = @findings.length
        if name
          if prefix.empty?
            finding(instruction, cursor.path, :invalid, "prefix must not be empty", value: prefix, origin: origin)
          else
            finding(instruction, cursor.path, :too_long, "may not be more than 63 bytes", value: prefix, origin: origin) if prefix.bytesize > 63
            KubernetesValidator.dns1123_subdomain_messages(prefix.b).each do |message|
              finding(instruction, cursor.path, :invalid, "prefix: #{message}", value: prefix, origin: origin)
            end
          end
          return finding(instruction, cursor.path, :invalid, "name must not be empty", value: name, origin: origin) if name.empty?
        end

        identifier = name || value
        finding(instruction, cursor.path, :too_long, "may not be more than 32 bytes", value: identifier, origin: origin) if identifier.bytesize > 32
        finding(instruction, cursor.path, :invalid, C_IDENTIFIER_MESSAGE, value: identifier, origin: origin) unless identifier.match?(C_IDENTIFIER)
        finding(instruction, cursor.path, :invalid, "a fully qualified name must be a domain and a name separated by a slash", origin: origin) unless name
        @findings.length != start
      end

      def equivalent?(left, right)
        return true if left == right
        return true if left.nil? && [[], {}].include?(right)

        right.nil? && [[], {}].include?(left)
      end

      def finding(instruction, path, code, message, origin: nil, value: nil, use_object_value: true)
        kind = {too_many: "Too many", too_long: "Too long", unsupported: "Unsupported value"}.fetch(code, nil)
        issue = ValidationIssue.new(path: path, code: code, message: message, value: value, kubernetes_type: kind,
                                    use_object_value: use_object_value)
        @findings << Finding.new(issue, origin, instruction["stage"])
        true
      end
    end
  end
end
