# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Hands requests to the admission chain (mutating, validating, and the CONNECT
      # of a streaming subresource) and carries what admission produced back out:
      # Status rejections, audit annotations and Warning headers.
      module AdmissionGlue
        # Admission runs between decode and strategy validation (mutating) and
        # after validation (validating).  Rejections become 4xx Status objects.
        def admit_mutating(request, route, operation, object, old_object, namespace, **)
          if operation == "CREATE" && route.resource.custom? && @crd_manager&.terminating?("#{route.resource.resource}.#{route.resource.group}")
            name = metadata_value(object, "name")
            raise Status::Forbidden.new("#{route.resource.resource}.#{route.resource.group} #{name.inspect} is forbidden: " \
                                        "create not allowed while custom resource definition is terminating",
                                        details: resource_details(route, name: name))
          end
          object = default_service_account_for_admission(route, operation, object)
          chain = admission_chain
          return drop_disabled_volume_limit_scaling(route.resource, object, old_object) unless chain

          # Mutating plugins edit the object in place.  Schema application and the
          # store both hand back structures with frozen members, so the chain must
          # be given a mutable copy -- otherwise the first plugin that touches a
          # defaulted sub-object raises FrozenError and the request 500s.
          attributes = admission_attributes(request, route, operation, deep_copy(object), old_object, namespace, **)
          begin
            phase("admit") { chain.admit(attributes) }
          ensure
            record_admission_annotations(attributes)
          end
          attributes.warnings.each { |warning| request_warnings(request) << warning }
          drop_disabled_volume_limit_scaling(route.resource, attributes.object, old_object)
        rescue Security::Admission::Rejected => rejected
          raise admission_status(rejected, route)
        end

        # Apply the typed Pod default after the field manager. The admission
        # chain still sees that account for its usual service-account checks.
        def default_service_account_for_admission(route, operation, object)
          return object unless operation == "CREATE" && route.subresource.nil? && pod_resource?(route.resource)

          spec = object["spec"]
          return object unless spec.is_a?(Hash) && spec["serviceAccountName"].to_s.empty?
          return object unless schema_hash_defaulting(route.resource.schema).is_a?(Schema::Defaulting)

          defaulted = Schema::Defaulting.default_pod_service_account(spec, object.dig("metadata", "annotations"))
          defaulted.equal?(spec) ? object : object.merge("spec" => defaulted)
        end

        def admit_validating(request, route, operation, object, old_object, namespace, **)
          validate_static_admission_name!(request, route.resource, operation, object)
          chain = admission_chain
          return true unless chain

          attributes = admission_attributes(request, route, operation, object, old_object, namespace, **)
          begin
            phase("validate_admission") { chain.validate(attributes) }
          ensure
            record_admission_annotations(attributes)
          end
          attributes.warnings.each { |warning| request_warnings(request) << warning }
          true
        rescue Security::Admission::Rejected => rejected
          raise admission_status(rejected, route)
        end

        # The Binding and Eviction payloads have their own kind even though the
        # admission rule matches the Pod subresource that receives the write.
        def admitted_for_create_subresource(request, route, object, namespace, dry_run:)
          gvk = route.subresource == "eviction" ? %w[policy v1 Eviction] : ["", "v1", "Binding"]
          group, version, kind = gvk
          document = deep_copy(object)
          document["apiVersion"] = group.empty? ? version : "#{group}/#{version}"
          document["kind"] = kind
          options = {dry_run: dry_run, gvk: gvk}
          document = admit_mutating(request, route, "CREATE", document, nil, namespace, **options)
          admit_validating(request, route, "CREATE", document, nil, namespace, **options)
          document
        end

        def admission_create_options(request)
          options = {"apiVersion" => "meta.k8s.io/v1", "kind" => "CreateOptions"}
          %w[fieldManager fieldValidation].each do |key|
            value = query(request, key)
            options[key] = value unless value.to_s.empty?
          end
          dry_run = Array(request.query_values("dryRun"))
          options["dryRun"] = dry_run unless dry_run.empty?
          options
        end

        # pods/exec, pods/attach and pods/portforward are CREATE requests that go
        # through admission upstream: a webhook registered for the subresource is
        # handed the options object built from the query string and can deny the
        # connection.  Skipping admission let a denied attach open the stream and
        # hang until the client gave up -- "[sig-api-machinery] AdmissionWebhook
        # should be able to deny attaching pod" reported a kubectl timeout rather
        # than the webhook's message.
        STREAMING_ADMISSION_KINDS = {
          "exec" => "PodExecOptions", "attach" => "PodAttachOptions",
          "portforward" => "PodPortForwardOptions"
        }.freeze

        # Upstream hands these to admission as CONNECT (admission.Connect), not
        # CREATE: the e2e webhook for attach is registered for
        # Operations: [CONNECT], so a CREATE matched no rule and the attach went
        # ahead.  And kubectl 1.36 opens exec/attach over a WebSocket, which is a
        # GET, so admitting POST alone skipped every modern client.
        STREAMING_ADMISSION_METHODS = %w[GET POST].freeze

        def admit_streaming_subresource(request, route)
          kind = STREAMING_ADMISSION_KINDS[route.subresource.to_s]
          return if kind.nil? || !STREAMING_ADMISSION_METHODS.include?(request.method.to_s.upcase)

          options = streaming_options(request, kind)
          admit_mutating(request, route, :connect, options, nil, route.namespace, name: route.name)
          admit_validating(request, route, :connect, options, nil, route.namespace, name: route.name)
        end

        # The options a streaming request carries as query parameters are the
        # object admission sees (pkg/registry/core/pod/rest/subresources.go).
        def streaming_options(request, kind)
          options = {"kind" => kind, "apiVersion" => "v1"}
          if kind == "PodPortForwardOptions"
            ports = Array(request.query_values("ports")).flat_map { |value| value.to_s.split(",") }
            options["ports"] = ports.filter_map do |port|
              Integer(port, 10)
            rescue ArgumentError
              nil
            end
            return options
          end

          %w[stdin stdout stderr tty].each do |field|
            value = query(request, field)
            options[field] = truthy?(value) unless value.nil? || value.to_s.empty?
          end
          container = query(request, "container").to_s
          options["container"] = container unless container.empty?
          options["command"] = Array(request.query_values("command")).map(&:to_s) if kind == "PodExecOptions"
          options
        end

        def admission_chain
          @security&.admission
        end

        def validate_static_admission_name!(request, resource, operation, object)
          source = Security::Admission::StaticManifestSource
          return unless %w[CREATE UPDATE].include?(operation.to_s) && resource.group == source::GROUP && source::KINDS.include?(resource.kind)

          name = metadata_value(object, "name").to_s
          return unless name.end_with?(source::SUFFIX)

          if operation.to_s == "CREATE" && feature_gate_enabled?(source::GATE)
            cause = {"reason" => "FieldValueInvalid", "field" => "metadata.name", "message" => "Invalid value: #{name.inspect}: #{source::RESERVED_NAME}"}
            raise Status::Invalid.new("#{resource.kind}.#{resource.group} #{name.inspect} is invalid: metadata.name: #{cause.fetch("message")}",
                                      details: {"group" => resource.group, "kind" => resource.kind, "name" => name, "causes" => [cause]})
          end

          request_warnings(request) << "metadata.name: #{source::RESERVED_NAME}"
        end

        def admission_attributes(request, route, operation, object, old_object, namespace, name: nil, dry_run: dry_run?(request), gvk: nil)
          user = request.identity ? Security::UserInfo.from_h(request.identity) : Security::UserInfo.anonymous
          group, version, kind = gvk || [route.resource.group, route.resource.version, route.resource.kind]
          options = admission_create_options(request) if operation.to_s == "CREATE" && request.method == "POST"
          Security::Admission::Attributes.new(operation: operation, user: user, group: route.resource.group, version: route.resource.version,
                                              resource: route.resource.resource, kind: kind, kind_group: group, kind_version: version,
                                              subresource: route.subresource,
                                              namespace: namespace, name: name || route.name || metadata_value(object || old_object || {}, "name"),
                                              object: object, old_object: old_object, dry_run: dry_run, options: options,
                                              webhook_decoder: method(:decode_webhook_object))
        end

        def decode_webhook_object(gvk, object)
          group, version, kind = gvk
          resource = @registry.find_gvk(group: group, version: version, kind: kind)
          return object unless resource

          reporter = schema_issue_reporter(resource.schema)
          if reporter.is_a?(Schema::Validator)
            error = reporter.wire_type_error(reporter.errors(object, unknown_fields: :preserve))
            raise Status::InternalError.new(error) if error
          end
          deep_copy(apply_defaults_only(resource, object, unknown_fields: :prune, operation: :update))
        rescue Schema::DefaultingError, Status::BadRequest => error
          raise Status::InternalError.new(error.message)
        end

        def admission_status(rejected, route)
          details = (rejected.details || {}).merge(resource_details(route)) { |_key, left, _right| left }
          case rejected.code
          when 400 then Status::BadRequest.new(rejected.message, details: details)
          when 409 then Status::Conflict.new(rejected.message, details: details)
          when 422 then Status::Invalid.new(rejected.message, details: details)
          when 500 then Status::Error.new(message: rejected.message, code: 500, reason: "InternalError", details: details)
          when 503 then Status::ServiceUnavailable.new(rejected.message, details: details)
          else Status::Forbidden.new(rejected.message, details: details)
          end
        end

        # Annotations an admission plugin added (PodSecurity's enforce-policy
        # and audit-violations, a webhook's) go onto the request's audit
        # event, rejected requests included.
        def record_admission_annotations(attributes)
          audit = Thread.current[AUDIT_KEY]
          return unless audit

          attributes.annotations.each { |key, value| audit.annotate(key, value) }
        end

        def request_warnings(request)
          @request_warnings ||= Hash.new { |hash, key| hash[key] = [] }.compare_by_identity
          @request_warnings[request]
        end

        # Admission warnings reach the client as RFC 7234 Warning headers with
        # kube-apiserver's `299 - "text"` rendering.
        def with_warning_headers(request, response)
          warnings = @request_warnings&.delete(request)
          return response if warnings.nil? || warnings.empty?

          rendered = warnings.map { |warning| "299 - #{warning.to_s.gsub(/[\r\n]+/, " ").inspect}" }
          existing = response.header("warning")
          response.with_header("warning", [existing, *rendered].compact.join(", "))
        end
      end
    end
  end
end
