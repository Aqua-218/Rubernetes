# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The options of a write: fieldManager, force and dryRun validation, and the
      # ?fieldValidation= directive with its strict-decoding violations.
      module WriteOptions
        private

        # cleanFieldValidation.
        def metric_field_validation(request)
          values = Array(request.query_values("fieldValidation"))
          return "" if values.empty?
          return "invalid" unless values.length == 1 && ["", *FIELD_VALIDATION_DIRECTIVES].include?(values.first.to_s)

          values.first.to_s
        end

        # Kubernetes `?fieldValidation=` handling.  The directive defaults to Warn
        # (apiserver rest.go fieldValidation); Ignore drops unknown and duplicate
        # fields silently, Warn drops them and reports one warning per violation,
        # Strict fails the request with a BadRequest naming every violation.
        # Unknown fields are dropped from the stored object in every mode.
        FIELD_VALIDATION_DIRECTIVES = %w[Ignore Warn Strict].freeze

        FIELD_MANAGER_MAX_LENGTH = 128

        GO_BOOLS = %w[1 t T TRUE true True 0 f F FALSE false False].freeze

        # metav1 validation ValidateCreateOptions / ValidateUpdateOptions /
        # ValidatePatchOptions: fieldManager (required for an apply, at most
        # 128 bytes, printable), force only on an apply, dryRun "All",
        # fieldValidation Ignore/Warn/Strict -- an Invalid <Kind>.meta.k8s.io.
        def validate_write_options!(request, kind, patch_type: nil)
          force = query(request, "force")
          if !force.nil? && !GO_BOOLS.include?(force.to_s)
            raise Status::BadRequest.new("strconv.ParseBool: parsing #{ManagedFields::Value.go_quote(force.to_s)}: invalid syntax")
          end

          causes = []
          manager = query(request, "fieldManager").to_s
          if %i[apply apply_cbor].include?(patch_type)
            if manager.empty?
              causes << {"reason" => "FieldValueRequired", "message" => "Required value: is required for apply patch",
                         "field" => "fieldManager"}
            end
          elsif patch_type && !force.nil?
            causes << {"reason" => "FieldValueForbidden", "message" => "Forbidden: may not be specified for non-apply patch",
                       "field" => "force"}
          end
          if manager.bytesize > FIELD_MANAGER_MAX_LENGTH
            causes << {"reason" => "FieldValueTooLong", "message" => "Too long: may not be more than #{FIELD_MANAGER_MAX_LENGTH} bytes",
                       "field" => "fieldManager"}
          end
          byte = 0
          manager.each_char do |char|
            unless go_printable?(char)
              causes << {"reason" => "FieldValueInvalid", "field" => "fieldManager",
                         "message" => "Invalid value: #{ManagedFields::Value.go_quote(manager)}: invalid character " \
                                      "U+#{format("%04X", char.ord)} (at position #{byte})"}
            end
            byte += char.bytesize
          end
          dry_run_cause = invalid_dry_run(Array(request.query_values("dryRun")))
          causes << dry_run_cause if dry_run_cause
          directive = query(request, "fieldValidation")
          unless directive.nil? || directive.to_s.empty? || FIELD_VALIDATION_DIRECTIVES.include?(directive.to_s)
            causes << {"reason" => "FieldValueNotSupported", "field" => "fieldValidation",
                       "message" => "Unsupported value: #{ManagedFields::Value.go_quote(directive.to_s)}: supported values: \"\", \"Ignore\", \"Strict\", " \
                                    "\"Warn\""}
          end
          invalid_write_options!(kind, causes)
        end

        def invalid_dry_run(values)
          return if values.all?("All")

          {"reason" => "FieldValueNotSupported", "field" => "dryRun",
           "message" => %(Unsupported value: #{JSON.generate(values)}: supported values: "All")}
        end

        def invalid_write_options!(kind, causes)
          return if causes.empty?

          rendered = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }
          summary = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
          raise Status::Invalid.new("#{kind}.meta.k8s.io \"\" is invalid: #{summary}",
                                    details: {"group" => "meta.k8s.io", "kind" => kind, "causes" => causes})
        end

        # unicode.IsPrint: letters, marks, numbers, punctuation, symbols and
        # the ASCII space.
        def go_printable?(char)
          char == " " || char.match?(/[\p{L}\p{M}\p{N}\p{P}\p{S}]/)
        end

        def field_validation_directive(request)
          directive = query(request, "fieldValidation").to_s
          return "Warn" if directive.empty?
          unless FIELD_VALIDATION_DIRECTIVES.include?(directive)
            raise Status::BadRequest.new(
              "fieldValidation: Invalid value: #{directive.inspect}: must be one of #{FIELD_VALIDATION_DIRECTIVES.join(", ")}"
            )
          end

          directive
        end

        # `unknown field "spec.foo"` / `duplicate field "metadata.name"`, matching
        # sigs.k8s.io/json strictError.Error().
        def strict_field_violations(resource, object, duplicates: [], yaml_errors: [], check_types: false)
          # sigs.k8s.io/json reports strict errors in the order the decoder met
          # them, and the body a client sends declares its unknown field before
          # it repeats a known one -- which is the order conformance matches on
          # ("unknown field \"spec.unknownField\", duplicate field
          # \"spec.replicas\"").
          schema = resource&.schema
          # A custom resource is validated against its CRD's structural schema,
          # which knows exactly which fields it would prune.  Without this a
          # Strict request could smuggle any field at all into a CR.
          violations = schema_unknown_fields(schema, object).map { |path| "unknown field #{render_object_path(path).inspect}" }
          reporter = schema_issue_reporter(schema)
          if reporter
            # A validator that cannot walk the object reports no unknown fields.
            issues = best_effort { reporter.errors(object, unknown_fields: :reject) } || []
            yield reporter.wire_type_error(issues) if check_types && reporter.is_a?(Schema::Validator)
            Array(issues).each do |issue|
              next unless issue.code == :unknown_field

              violations << "unknown field #{issue.path.join(".").inspect}"
            end
          end
          # The YAML decoder runs before the typed decoder, so its errors come
          # first: "strict decoding error: yaml: unmarshal errors:\n  line 5:
          # key \"other\" already set in map, unknown field \"unknown\"".
          Array(yaml_errors) + violations + duplicates.map { |path| "duplicate field #{path.inspect}" }
        end

        # "spec.ports[0].unknown" -- the strict decoder's rendering.  The apply
        # type converter prints the same path with a leading dot.
        def render_object_path(path)
          Array(path).each_with_object(+"") do |segment, rendered|
            if segment.is_a?(Integer)
              rendered << "[#{segment}]"
            else
              rendered << "." unless rendered.empty?
              rendered << segment.to_s
            end
          end
        end

        def enforce_field_validation(resource, object, request, duplicates: [], apply: false, document: nil,
                                     yaml_errors: nil)
          directive = field_validation_directive(request)
          yaml_errors = request_duplicate_yaml_errors(request) if yaml_errors.nil?
          violations = strict_field_violations(resource, document.nil? ? object : document,
                                               duplicates: duplicates, yaml_errors: yaml_errors, check_types: !apply) do |error|
            refuse_undecodable_write!(resource, request, error) if error
          end
          return :prune if violations.empty?

          case directive
          when "Strict"
            raise Status::BadRequest.new(apply_validation_message(resource, violations)) if apply

            kind = resource.kind.to_s
            version = resource.version.to_s
            raise Status::BadRequest.new(
              "#{kind} in version #{version.inspect} cannot be handled as a #{kind}: " \
              "strict decoding error: #{violations.join(", ")}"
            )
          when "Warn"
            violations.each do |violation|
              split_yaml_strict_error(violation).each { |warning| request_warnings(request) << warning }
            end
          end
          :prune
        end

        def refuse_undecodable_write!(resource, request, error)
          if request.method == "PATCH"
            # The merged object may include values the request did not supply.
            # Report the offending field and type without echoing the object.
            cause = {"reason" => "FieldValueInvalid", "message" => error, "field" => "patch"}
            raise Status::Invalid.new("patch: #{error}", details: {"causes" => [cause]})
          end

          kind = resource.kind
          raise Status::BadRequest.new("#{kind} in version #{resource.version.inspect} cannot be handled as a #{kind}: #{error}")
        end

        # Server-side apply reports an undeclared field through the typed
        # converter rather than the strict decoder, and clients match on its
        # wording (test/e2e/apimachinery/field_validation.go expects
        # ".unknownField: field not declared in schema").
        def apply_validation_message(resource, violations)
          kind = resource.kind.to_s
          api_version = resource.api_version.to_s
          details = violations.map do |violation|
            path = violation[/\Aunknown field "(.*)"\z/, 1]
            path ? ".#{path}: field not declared in schema" : violation
          end
          "failed to create typed patch object (#{api_version}, Kind=#{kind}): #{details.join("; ")}"
        end

        # dryRun accepts only the value "All" (metav1.DryRunAll).
        def dry_run?(request)
          values = Array(request.query_values("dryRun"))
          values = [query(request, "dryRun")].compact if values.empty?
          values.map(&:to_s).reject(&:empty?).any?("All")
        end

        # What the object would look like once stored, without storing it: the
        # server still fills in what it owns.
        def dry_run_view(object, namespace)
          result = deep_copy(object)
          result["metadata"] ||= {}
          result["metadata"]["namespace"] ||= namespace unless %i[cluster all].include?(namespace)
          result["metadata"]["uid"] ||= @uid_generator ? @uid_generator.call : SecureRandom.uuid
          result["metadata"]["creationTimestamp"] ||= @clock.call.utc.iso8601
          result
        end

        # managerOrUserAgent: the fieldManager option, else the user agent up
        # to its first "/", printable characters only and at most 128 bytes
        # ("" leaves the field manager to name it "unknown").
        def update_manager(request)
          explicit = query(request, "fieldManager")
          return explicit.to_s unless explicit.to_s.empty?

          prefix = request.header("user-agent").to_s.split("/", 2).first.to_s
          out = +""
          prefix.each_char do |char|
            next unless go_printable?(char)
            break if out.bytesize + char.bytesize > FIELD_MANAGER_MAX_LENGTH

            out << char
          end
          out
        end
      end
    end
  end
end
